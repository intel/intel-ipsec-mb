;;
;; Copyright (c) 2026, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;

;; SNOW5G-NCA4 2-buffer Submit/Flush functions for AVX512

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/align_avx512.inc"
%include "include/snow5g_x2_vaes_avx512.inc"

extern nca_vclmul_avx512

%define NCA4_HQP_SIZE           48  ;; HQP: H(16) | Q(16) | P(16) = 48 bytes per lane

;; Callee-saved GP register aliases
%define p_state         r12
%define p_job_in_lane   r13

struc STACK_NCA4_WORK
_hqp_nca4:       resb    (NCA4_HQP_SIZE * 2)             ; HQP: 2 lanes x 48 bytes
_digest_nca4:    resb    (16 * 2)                        ; 2 x 16-byte digest output
_keystream_nca4: resy    1                               ; 32-byte keystream scratch
;; SNOW5G state: 2 lanes x (4 LFSRs + 3 FSMs) = 2 x (7 x 16B) bytes
_states_nca4:   resb    (112 * 2)
_gpr_save_nca4: resq     10
%ifndef LINUX
_xmm_save_nca4: reso     10
%endif
_rsp_save_nca4: resq     1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Per-lane POLYVAL authentication
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_POLYVAL_LANE 3
%define %%LANE      %1  ;; [in] lane index (0 or 1)
%define %%DATA_FLD  %2  ;; [in] state field for msg pointer (_snow5g_args_in or _snow5g_args_out)
%define %%CHECK_NULL %3 ;; [in] 1 = guard against NULL job, 0 = job guaranteed non-NULL

        mov     rax, [p_job_in_lane + %%LANE*8]
%if %%CHECK_NULL
        test    rax, rax
        jz      %%skip_polyval_ %+ %%LANE
%endif

        ;; nca_vclmul_avx512(digest, hqp, msg, msg_len, aad, aad_len)
        lea     arg1, [rsp + _digest_nca4 + %%LANE*16]
        lea     arg2, [rsp + _hqp_nca4 + NCA4_HQP_SIZE * %%LANE]
        mov     arg3, [p_state + %%DATA_FLD + %%LANE*8]
        mov     arg4, [rax + _msg_len_to_cipher_in_bytes]
%ifdef LINUX
        mov     arg5, [rax + _cbcmac_aad]
        mov     arg6, [rax + _cbcmac_aad_len]
%else
        mov     r10, [rax + _cbcmac_aad]
        mov     r11, [rax + _cbcmac_aad_len]
        sub     rsp, 48
        mov     [rsp + 32], r10
        mov     [rsp + 40], r11
%endif
        call    nca_vclmul_avx512
%ifndef LINUX
        add     rsp, 48
%endif

%if %%CHECK_NULL
%%skip_polyval_ %+ %%LANE:
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Per-lane tag output: masked store of digest to auth_tag_output
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_COPY_TAG 2
%define %%LANE      %1  ;; [in] lane index (0 or 1)
%define %%CHECK_NULL %2 ;; [in] 1 = guard against NULL job, 0 = job guaranteed non-NULL

        mov     rax, [p_job_in_lane + %%LANE*8]
%if %%CHECK_NULL
        test    rax, rax
        jz      %%skip_tag_ %+ %%LANE
%endif

        vmovdqu64 xmm0, [rsp + _digest_nca4 + %%LANE*16]
        mov     ecx, [rax + _auth_tag_output_len_in_bytes]
        mov     rdx, [rax + _auth_tag_output]
        mov     eax, -1
        bzhi    eax, eax, ecx           ;; ecx bytes → ecx low bits set
        kmovw   k1, eax
        vmovdqu8 [rdx]{k1}, xmm0

%if %%CHECK_NULL
%%skip_tag_ %+ %%LANE:
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 2-lane cipher: full 16-byte blocks + masked tail per lane.
;; Clobbers: rax, rbx, rbp, r8-r15, ymm0-ymm5, k1
;; STATE_IN_REGS=1 skips reload of FSM/LFSR YMMs (caller must have them live).
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_CIPHER_X2 1
%define %%STATE_IN_REGS %1      ;; [in] 1 = state already in YMM regs, skip load
%define %%rem0          r12
%define %%rem1          rbx
%define %%num_blocks    r13
%define %%len0          r14     ;; [in] lane 0 length in bytes, [clobbered] extra full blocks
%define %%longer_lane   r11
%define %%len1          r15     ;; [in] lane 1 length in bytes, [clobbered] byte offset

        mov     rax, %%len0
        or      rax, %%len1
        jz      %%cipher_done

        ;; Load src/dst pointers ONCE for all phases (constant across loop).
        ;; Read directly via p_state (r12) before %%rem0 alias overwrites it.
        mov     r8,  [p_state + _snow5g_args_in + 0]    ;; src lane 0
        mov     r9,  [p_state + _snow5g_args_out + 0]   ;; dst lane 0
        mov     r10, [p_state + _snow5g_args_in + 8]    ;; src lane 1
        mov     rbp, [p_state + _snow5g_args_out + 8]   ;; dst lane 1

        mov     DWORD(%%rem0), DWORD(%%len0)
        mov     DWORD(%%rem1), DWORD(%%len1)
        and     DWORD(%%rem0), 15
        and     DWORD(%%rem1), 15
        shr     DWORD(%%len0), 4
        shr     DWORD(%%len1), 4

        mov     DWORD(%%num_blocks), DWORD(%%len0)
        xor     DWORD(%%longer_lane), DWORD(%%longer_lane)
        cmp     DWORD(%%len0), DWORD(%%len1)
        cmova   DWORD(%%num_blocks), DWORD(%%len1)
        cmovb   DWORD(%%len0), DWORD(%%len1)
        setb    BYTE(%%longer_lane)
        sub     DWORD(%%len0), DWORD(%%num_blocks)
        xor     %%len1, %%len1          ;; repurpose %%len1 as byte offset into src/dst buffers
%define %%offset        %%len1

%if %%STATE_IN_REGS == 0
        lea     rax, [rsp + _states_nca4]
        STATE_LOAD_NCA4_X2 rax
%endif
        kxord   k1, k1, k1

        ;; Phase 1: both lanes, full blocks
        test    DWORD(%%num_blocks), DWORD(%%num_blocks)
        jz      %%phase1_done
align_loop
%%phase1:
        NCA4_CIPHER_LANE_PAIR FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _keystream_nca4, \
                TEMP1, TEMP2, r8, r9, r10, rbp, %%offset, k1, 2
        add     %%offset, 16
        dec     DWORD(%%num_blocks)
        jnz     %%phase1
align_label
%%phase1_done:

        ;; Phase 2: extra full blocks for the longer lane
        test    DWORD(%%len0), DWORD(%%len0)
        jz      %%phase2_done
        test    DWORD(%%longer_lane), DWORD(%%longer_lane)
        jnz     %%phase2_lane1
align_loop
%%phase2_lane0:
        NCA4_CIPHER_LANE_PAIR FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _keystream_nca4, \
                TEMP1, TEMP2, r8, r9, r10, rbp, %%offset, k1, 0
        add     %%offset, 16
        dec     DWORD(%%len0)
        jnz     %%phase2_lane0
        jmp     %%phase2_done
align_loop
%%phase2_lane1:
        NCA4_CIPHER_LANE_PAIR FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _keystream_nca4, \
                TEMP1, TEMP2, r8, r9, r10, rbp, %%offset, k1, 1
        add     %%offset, 16
        dec     DWORD(%%len0)
        jnz     %%phase2_lane1
align_label
%%phase2_done:

        ;; Tail: partial bytes via masked stores
        mov     DWORD(rax), DWORD(%%rem0)
        or      DWORD(rax), DWORD(%%rem1)
        jz      %%skip_tail

        vpaddw  TEMP1, LFSR_B_HDQ_L01, FSM_R1_L01
        vpxord  TEMP1, TEMP1, FSM_R2_L01

        lea     rax, [rel byte_len_to_mask_table_nca4]
        kmovw   k1, [rax + %%rem0*2]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [r8 + %%offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        vmovdqu8        [r9 + %%offset]{k1}, XWORD(TEMP2)

        vextracti32x4   XWORD(TEMP1), TEMP1, 1
        kmovw   k1, [rax + %%rem1*2]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [r10 + %%offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        vmovdqu8        [rbp + %%offset]{k1}, XWORD(TEMP2)
%undef %%offset

%%skip_tail:
        ;; Restore p_state/p_job_in_lane clobbered by cipher
        mov     p_state, [rsp + _gpr_save_nca4 + 8*8]
        lea     p_job_in_lane, [p_state + _snow5g_job_in_lane]
%%cipher_done:
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NCA4 2-lane AEAD core: HQP generation, POLYVAL, cipher, tag output
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_CORE 3
%define %%STATE         %1  ;; [in] GP reg: SNOW5G OOO state pointer
%define %%DIR           %2  ;; [in] 0=encrypt, 1=decrypt
%define %%LANE1_VALID   %3  ;; [in] 1=lane 1 has a job (submit), 0=lane 1 NULL (flush)

        mov     p_state, %%STATE
        lea     p_job_in_lane, [%%STATE + _snow5g_job_in_lane]

        ;; Generate HQP and SNOW5G cipher state for both lanes.
        ;; ENCRYPT: state YMMs stay live across cipher (no POLYVAL between);
        ;;          skip state-store in HQP and state-load in cipher.
        ;; DECRYPT: POLYVAL function call between HQP and cipher clobbers YMMs;
        ;;          must persist state through memory.
        lea     rax, [p_state + _snow5g_args_keys]
%if %%DIR == 0
        SNOW5G_GENERATE_HQP_X2 rax, {p_state + _snow5g_args_IV}, \
                {rsp + _hqp_nca4}, 0, _keystream_nca4, \
                FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP0, TEMP1, ymm4, ymm5, rcx, k1, k2
%else
        lea     rbx, [rsp + _states_nca4]
        SNOW5G_GENERATE_HQP_X2 rax, {p_state + _snow5g_args_IV}, \
                {rsp + _hqp_nca4}, rbx, _keystream_nca4, \
                FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP0, TEMP1, ymm4, ymm5, rcx, k1, k2
%endif

        ;; Collect cipher lengths into r14 (lane 0) and r15 (lane 1)
        ;; Lane 0 is always valid; lane 1 only when called from submit.
        mov     rax, [p_job_in_lane]
        mov     r14, [rax + _msg_len_to_cipher_in_bytes]
%if %%LANE1_VALID
        mov     rax, [p_job_in_lane + 8]
        mov     r15, [rax + _msg_len_to_cipher_in_bytes]
%else
        xor     r15d, r15d
%endif

%if %%DIR == 1
        ;; Decrypt: hash AAD + ciphertext (input) BEFORE cipher
%if %%LANE1_VALID
        NCA4_POLYVAL_LANE 0, _snow5g_args_in, 0
        NCA4_POLYVAL_LANE 1, _snow5g_args_in, 0
%else
        NCA4_POLYVAL_LANE 0, _snow5g_args_in, 0
        NCA4_POLYVAL_LANE 1, _snow5g_args_in, 1
%endif
%endif

        SNOW5G_NCA4_CIPHER_X2 (1 - %%DIR)

%if %%DIR == 0
        ;; Encrypt: hash AAD + ciphertext (output) AFTER cipher
%if %%LANE1_VALID
        NCA4_POLYVAL_LANE 0, _snow5g_args_out, 0
        NCA4_POLYVAL_LANE 1, _snow5g_args_out, 0
%else
        NCA4_POLYVAL_LANE 0, _snow5g_args_out, 0
        NCA4_POLYVAL_LANE 1, _snow5g_args_out, 1
%endif
%endif

        NCA4_COPY_TAG 0, 0
        NCA4_COPY_TAG 1, (1 - %%LANE1_VALID)

%ifdef SAFE_DATA
        vpxorq  zmm0, zmm0, zmm0
        vmovdqa64 [rsp + _hqp_nca4], zmm0
        vmovdqa32 [rsp + _hqp_nca4 + 64], ymm0
        vmovdqa64 [rsp + _digest_nca4], ymm0
%if %%DIR == 1
        ;; _states_nca4 only written on decrypt path
        vmovdqu64 [rsp + _states_nca4 + 64 * 0], zmm0
        vmovdqu64 [rsp + _states_nca4 + 64 * 1], zmm0
        vmovdqu64 [rsp + _states_nca4 + 64 * 2], zmm0
        vmovdqa32 [rsp + _states_nca4 + 64 * 3], ymm0
%endif
%endif

%endmacro

mksection .text
default rel

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%define arg6    r9
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    qword [rsp + 32]
%define arg6    qword [rsp + 40]
%endif

%define state   arg1
%define job     arg2
%define job_rax rax

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Saves register contents and creates stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_NCA4_WORK_size
        and     rsp, -64

        mov     [rsp + _gpr_save_nca4 + 8*0], rbx
        mov     [rsp + _gpr_save_nca4 + 8*1], rbp
        mov     [rsp + _gpr_save_nca4 + 8*2], r12
        mov     [rsp + _gpr_save_nca4 + 8*3], r13
        mov     [rsp + _gpr_save_nca4 + 8*4], r14
        mov     [rsp + _gpr_save_nca4 + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save_nca4 + 8*6], rsi
        mov     [rsp + _gpr_save_nca4 + 8*7], rdi
        ;; Save XMM6-15 (Windows callee-saved)
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 0], xmm6
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 1], xmm7
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 2], xmm8
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 3], xmm9
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 4], xmm10
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 5], xmm11
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 6], xmm12
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 7], xmm13
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 8], xmm14
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 9], xmm15
%endif
        mov     [rsp + _gpr_save_nca4 + 8*8], state
        mov     [rsp + _rsp_save_nca4], rax
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restores register contents and removes the stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_FUNC_END 0
%ifdef SAFE_DATA
        clear_all_zmms_asm
%else
        vzeroupper
%endif
        mov     rbx, [rsp + _gpr_save_nca4 + 8*0]
        mov     rbp, [rsp + _gpr_save_nca4 + 8*1]
        mov     r12, [rsp + _gpr_save_nca4 + 8*2]
        mov     r13, [rsp + _gpr_save_nca4 + 8*3]
        mov     r14, [rsp + _gpr_save_nca4 + 8*4]
        mov     r15, [rsp + _gpr_save_nca4 + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save_nca4 + 8*6]
        mov     rdi, [rsp + _gpr_save_nca4 + 8*7]
        vmovdqa xmm6,  [rsp + _xmm_save_nca4 + 16 * 0]
        vmovdqa xmm7,  [rsp + _xmm_save_nca4 + 16 * 1]
        vmovdqa xmm8,  [rsp + _xmm_save_nca4 + 16 * 2]
        vmovdqa xmm9,  [rsp + _xmm_save_nca4 + 16 * 3]
        vmovdqa xmm10, [rsp + _xmm_save_nca4 + 16 * 4]
        vmovdqa xmm11, [rsp + _xmm_save_nca4 + 16 * 5]
        vmovdqa xmm12, [rsp + _xmm_save_nca4 + 16 * 6]
        vmovdqa xmm13, [rsp + _xmm_save_nca4 + 16 * 7]
        vmovdqa xmm14, [rsp + _xmm_save_nca4 + 16 * 8]
        vmovdqa xmm15, [rsp + _xmm_save_nca4 + 16 * 9]
%endif
        mov     rsp, [rsp + _rsp_save_nca4]     ;; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Submits a job to the 2-buffer SNOW5G-NCA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SUBMIT_JOB_SNOW5G_NCA4_X2 1

%define %%lane           r8
%define %%tmp            r15
%define %%tmp2           xmm0

        SNOW5G_NCA4_FUNC_START

        ;; Lane index = current lanes in use (0 or 1)
        mov     %%lane, [state + _snow5g_lanes_in_use]
        add     qword [state + _snow5g_lanes_in_use], 1

        ;; Store job pointer in lane
        mov     [state + _snow5g_job_in_lane + %%lane*8], job

        ;; Copy job data into lane arrays
        mov     %%tmp, [job + _src]
        add     %%tmp, [job + _cipher_start_src_offset_in_bytes]
        mov     [state + _snow5g_args_in + %%lane*8], %%tmp

        mov     %%tmp, [job + _dst]
        mov     [state + _snow5g_args_out + %%lane*8], %%tmp

        mov     %%tmp, [job + _enc_keys]
        mov     [state + _snow5g_args_keys + %%lane*8], %%tmp

        ;; Copy IV to state array (16 bytes per lane)
        mov     %%tmp, [job + _iv]
        vmovdqu %%tmp2, [%%tmp]
        shl     %%lane, 4
        vmovdqu [state + _snow5g_args_IV + %%lane], %%tmp2

        ;; Check if all 2 lanes are full (%%lane != 0 after shl means old count was 1)
        test    %%lane, %%lane
        jz      %%return_null_submit

        ;; Both lanes full - process them
        SNOW5G_NCA4_CORE state, %1, 1

        ;; Complete both jobs and reset state
        mov     job_rax, [p_state + _snow5g_job_in_lane]
        mov     rbx, [p_state + _snow5g_job_in_lane + 8]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        or      dword [rbx + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane], 0
        mov     qword [p_state + _snow5g_job_in_lane + 8], 0
        mov     qword [p_state + _snow5g_lanes_in_use], 0
        jmp     %%exit_submit

align_label
%%return_null_submit:
        xor     job_rax, job_rax

align_label
%%exit_submit:
        SNOW5G_NCA4_FUNC_END
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Flushes completed jobs from the 2-buffer SNOW5G-NCA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro FLUSH_JOB_SNOW5G_NCA4_X2 1

%define %%tmp            r11
%define %%tmp2           xmm0

        SNOW5G_NCA4_FUNC_START

        ;; Check for empty
        cmp     qword [state + _snow5g_lanes_in_use], 0
        jz      %%return_null_flush

        ;; With 2 lanes, flush always has lane 0 valid, lane 1 null.
        ;; Fill lane 1 from lane 0.
        mov             %%tmp, [state + _snow5g_args_in]
        mov             [state + _snow5g_args_in + 8], %%tmp

        mov             %%tmp, [state + _snow5g_args_out]
        mov             [state + _snow5g_args_out + 8], %%tmp

        mov             %%tmp, [state + _snow5g_args_keys]
        mov             [state + _snow5g_args_keys + 8], %%tmp

        vmovdqa64       %%tmp2, [state + _snow5g_args_IV]
        vmovdqa64       [state + _snow5g_args_IV + 16], %%tmp2

        SNOW5G_NCA4_CORE state, %1, 0

        ;; Complete lane 0 job and reset state
        mov     job_rax, [p_state + _snow5g_job_in_lane]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane], 0
        mov     qword [p_state + _snow5g_lanes_in_use], 0

        jmp     %%exit_flush

align_label
%%return_null_flush:
        xor     job_rax, job_rax

align_label
%%exit_flush:
        SNOW5G_NCA4_FUNC_END
%endmacro

;; submit_job_snow5g_nca4_enc_vaes_avx512(state, job) - encrypt queue
MKGLOBAL(submit_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_enc_vaes_avx512:
        SUBMIT_JOB_SNOW5G_NCA4_X2 0
        ret

;; flush_job_snow5g_nca4_enc_vaes_avx512(state) - encrypt queue
MKGLOBAL(flush_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_enc_vaes_avx512:
        FLUSH_JOB_SNOW5G_NCA4_X2 0
        ret

;; submit_job_snow5g_nca4_dec_vaes_avx512(state, job) - decrypt queue
MKGLOBAL(submit_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_dec_vaes_avx512:
        SUBMIT_JOB_SNOW5G_NCA4_X2 1
        ret

;; flush_job_snow5g_nca4_dec_vaes_avx512(state) - decrypt queue
MKGLOBAL(flush_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_dec_vaes_avx512:
        FLUSH_JOB_SNOW5G_NCA4_X2 1
        ret

mksection stack-noexec
