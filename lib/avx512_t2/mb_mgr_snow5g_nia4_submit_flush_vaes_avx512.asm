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

;; SNOW5G-NIA4 2-buffer Submit/Flush functions for AVX512

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/constants.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/align_avx512.inc"
%include "include/snow5g_x2_vaes_avx512.inc"

extern nia_vclmul_avx512

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


;; HQP field layout: H(16) | Q(16) | P(16) = 48 bytes per lane
%define NIA4_HQP_STRIDE         48

struc STACK_NIA4
;; NIA4 auth working data (used by SNOW5G_NIA4_AUTH_X2 / PROCESS_NIA4_LANE)
_hqp_nia4:      resb    (NIA4_HQP_STRIDE * 2)   ; HQP: 2 lanes x 48 bytes (H+Q+P)
_keystream_nia4: resy   1                        ; 32-byte keystream scratch
_digest_nia4:   reso    1                        ; 16-byte POLYVAL digest
;; Function frame (used by mb_mgr SNOW5G_NIA4_FUNC_START/END)
_gpr_save_nia4: resq    8                        ; callee-saved GP regs
_state_save_nia4: resq   1                        ; state (arg1) save
_job_save_nia4: resq     1                        ; job (arg2) save
%ifndef LINUX
_xmm_save_nia4: reso    10                       ; XMM6-15 save area (Windows only)
%endif
_rsp_save_nia4: resq    1                        ; original RSP before alignment
_idx_save_nia4: resq    1                        ; lane index saved across AUTH_X2 call
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Per-lane POLYVAL authentication: build HashKey table, call polyval bulk hash,
;; digest XOR with length, single-block GHASH_MUL finalization, and tag output.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PROCESS_NIA4_LANE 4
%define %%STATE     %1  ;; [in] GP reg: SNOW5G OOO state pointer
%define %%LANE      %2  ;; [in] lane index (0 or 1)
%define %%DIGEST    %3  ;; [clobbered] temporary XMM
%define %%KMASK     %4  ;; [clobbered] temporary mask K-register

%define %%GP1       arg1        ; temporary GP
%define %%GP2       arg2        ; temporary GP

        lea     arg1, [rsp + _digest_nia4]              ;; digest out
        lea     arg2, [rsp + _hqp_nia4 + NIA4_HQP_STRIDE * %%LANE]      ;; HQP
        mov     arg3, [%%STATE + _snow5g_args_in + %%LANE*8]            ;; msg
        mov     DWORD(arg4), [%%STATE + _snow5g_lens_dqw + %%LANE*4]    ;; msg_len
        call    nia_vclmul_avx512

        ;; Reload state pointer (r11 clobbered by nia_vclmul_avx512 call)
        mov     %%STATE, [rsp + _state_save_nia4]

        ;; Copy tag to output — masked store for partial tag lengths
        vmovdqu64 %%DIGEST, [rsp + _digest_nia4]
        mov       %%GP1, [%%STATE + _snow5g_job_in_lane + %%LANE*8]     ;; job pointer
        mov       DWORD(%%GP1), [%%GP1 + _auth_tag_output_len_in_bytes]
        mov       DWORD(%%GP2), -1
        bzhi      DWORD(%%GP2), DWORD(%%GP2), DWORD(%%GP1) ;; mask = low tag_len bits
        kmovw     %%KMASK, DWORD(%%GP2)
        mov       %%GP1, [%%STATE + _snow5g_args_out + %%LANE*8]        ;; output tag pointer
        vmovdqu8  [%%GP1]{%%KMASK}, %%DIGEST
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NIA4 authentication for 2 lanes
;; Clobbered callee-saved GPRs: rbp, r12, r13, r14, r15
;; Clobbered SIMD/opmask: all volatile (contains function calls)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NIA4_AUTH_X2 1
%define %%STATE     %1   ;; [in] GP reg: SNOW5G OOO state pointer

        lea     rax, [%%STATE + _snow5g_args_keys]
        SNOW5G_GENERATE_HQP_X2 rax, {%%STATE + _snow5g_args_IV}, \
                {rsp + _hqp_nia4}, 0, _keystream_nia4, \
                FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP0, TEMP1, ymm4, ymm5, rcx, k1, k2

        ;; Reload state pointer (r11 clobbered by SNOW5G_GENERATE_HQP_X2)
        mov     %%STATE, [rsp + _state_save_nia4]

        mov     rax, [%%STATE + _snow5g_job_in_lane + 0*8]
        test    rax, rax
        jz      .check_lane1

        PROCESS_NIA4_LANE %%STATE, 0, xmm0, k1

align_label
.check_lane1:
        mov     rax, [%%STATE + _snow5g_job_in_lane + 1*8]
        test    rax, rax
        jz      .auth_done

        PROCESS_NIA4_LANE %%STATE, 1, xmm0, k1

align_label
.auth_done:

%ifdef SAFE_DATA
        vpxorq  xmm0, xmm0, xmm0
        vmovdqa64 [rsp + _hqp_nia4], zmm0
        vmovdqa32 [rsp + _hqp_nia4 + 64], ymm0
        vmovdqa32 [rsp + _keystream_nia4], ymm0
%endif

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Saves register contents and creates stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NIA4_FUNC_START 1
%define %%SAVE_JOB      %1  ;; [in] 1 to save job pointer (submit), 0 to skip (flush)

        mov     rax, rsp
        sub     rsp, STACK_NIA4_size
        and     rsp, -64

        mov     [rsp + _gpr_save_nia4 + 8*0], rbx
        mov     [rsp + _gpr_save_nia4 + 8*1], rbp
        mov     [rsp + _gpr_save_nia4 + 8*2], r12
        mov     [rsp + _gpr_save_nia4 + 8*3], r13
        mov     [rsp + _gpr_save_nia4 + 8*4], r14
        mov     [rsp + _gpr_save_nia4 + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save_nia4 + 8*6], rsi
        mov     [rsp + _gpr_save_nia4 + 8*7], rdi
        ;; Save XMM6-15 (Windows callee-saved)
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 0], xmm6
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 1], xmm7
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 2], xmm8
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 3], xmm9
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 4], xmm10
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 5], xmm11
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 6], xmm12
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 7], xmm13
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 8], xmm14
        vmovdqa [rsp + _xmm_save_nia4 + 16 * 9], xmm15
%endif
        mov     [rsp + _state_save_nia4], state
%if %%SAVE_JOB
        mov     [rsp + _job_save_nia4], job
%endif
        mov     [rsp + _rsp_save_nia4], rax
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restores register contents and removes the stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NIA4_FUNC_END 0
%ifdef SAFE_DATA
        clear_all_zmms_asm
%else
        vzeroupper
%endif
        mov     rbx, [rsp + _gpr_save_nia4 + 8*0]
        mov     rbp, [rsp + _gpr_save_nia4 + 8*1]
        mov     r12, [rsp + _gpr_save_nia4 + 8*2]
        mov     r13, [rsp + _gpr_save_nia4 + 8*3]
        mov     r14, [rsp + _gpr_save_nia4 + 8*4]
        mov     r15, [rsp + _gpr_save_nia4 + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save_nia4 + 8*6]
        mov     rdi, [rsp + _gpr_save_nia4 + 8*7]
        ;; Restore XMM6-15 (Windows callee-saved)
        vmovdqa xmm6,  [rsp + _xmm_save_nia4 + 16 * 0]
        vmovdqa xmm7,  [rsp + _xmm_save_nia4 + 16 * 1]
        vmovdqa xmm8,  [rsp + _xmm_save_nia4 + 16 * 2]
        vmovdqa xmm9,  [rsp + _xmm_save_nia4 + 16 * 3]
        vmovdqa xmm10, [rsp + _xmm_save_nia4 + 16 * 4]
        vmovdqa xmm11, [rsp + _xmm_save_nia4 + 16 * 5]
        vmovdqa xmm12, [rsp + _xmm_save_nia4 + 16 * 6]
        vmovdqa xmm13, [rsp + _xmm_save_nia4 + 16 * 7]
        vmovdqa xmm14, [rsp + _xmm_save_nia4 + 16 * 8]
        vmovdqa xmm15, [rsp + _xmm_save_nia4 + 16 * 9]
%endif
        mov     rsp, [rsp + _rsp_save_nia4]     ;; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Completes a job and returns it in job_rax
;; Clobbers: %%TMP, unused_lanes
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro COMPLETE_JOB 2
%define %%IDX           %1  ;; [in] lane index of completed job
%define %%TMP           %2  ;; [clobbered] temporary GPR

        sub     qword [state + _snow5g_lanes_in_use], 1
        mov     job_rax, [state + _snow5g_job_in_lane + %%IDX*8]
        mov     unused_lanes, [state + _snow5g_unused_lanes]
        mov     qword [state + _snow5g_job_in_lane + %%IDX*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        mov     dword [state + _snow5g_lens_dqw + %%IDX*4], 0xFFFFFFFF
        shl     unused_lanes, 4
        or      unused_lanes, %%IDX
        mov     [state + _snow5g_unused_lanes], unused_lanes

        ;; Update unused lane bitmask: INIT_MASK |= (1 << IDX)
        xor     DWORD(%%TMP), DWORD(%%TMP)
        bts     DWORD(%%TMP), DWORD(%%IDX)
        or      [state + _snow5g_INIT_MASK], WORD(%%TMP)
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Submits a job to the 2-buffer SNOW5G-NIA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

MKGLOBAL(submit_job_snow5g_nia4_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nia4_vaes_avx512:
        endbranch64

%define len              rbp
%define idx              rbp

%define lane             r8
%define unused_lanes     rbx
%define tmp              r15
%define tmp2             r13

        SNOW5G_NIA4_FUNC_START 1

        mov     unused_lanes, [state + _snow5g_unused_lanes]
        mov     lane, unused_lanes
        and     lane, 0x1
        shr     unused_lanes, 4
        mov     [state + _snow5g_unused_lanes], unused_lanes
        add     qword [state + _snow5g_lanes_in_use], 1

        mov     [state + _snow5g_job_in_lane + lane*8], job

        xor     DWORD(tmp), DWORD(tmp)
        bts     DWORD(tmp), DWORD(lane)
        not     DWORD(tmp)
        and     [state + _snow5g_INIT_MASK], WORD(tmp)

        mov     tmp, [job + _src]
        add     tmp, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _snow5g_args_in + lane*8], tmp

        ;; Store key pointer
        mov     tmp, [job + _nia_key]
        mov     [state + _snow5g_args_keys + lane*8], tmp

        ;; Copy IV to state array (16 bytes per lane)
        mov     tmp, [job + _nia_iv]
        mov     tmp2, lane
        shl     tmp2, 4
        vmovdqu xmm0, [tmp]
        vmovdqu [state + _snow5g_args_IV + tmp2], xmm0

        ;; Store output tag pointer
        mov     tmp, [job + _auth_tag_output]
        mov     [state + _snow5g_args_out + lane*8], tmp

        ;; Insert len into proper lane (bytes)
        mov     len, [job + _msg_len_to_hash_in_bytes]

        mov     [state + _snow5g_lens_dqw + lane*4], DWORD(len)

        cmp     qword [state + _snow5g_lanes_in_use], 2
        jne     .return_null_submit_nia4

        ;; Check if the other lane has len=0 (already completed in previous batch)
        mov             DWORD(idx), DWORD(lane)
        xor             DWORD(idx), 1
        cmp             dword [state + _snow5g_lens_dqw + idx*4], 0
        je              .len_is_0_submit_nia4

        ;; Find minimum length lane
        mov             DWORD(tmp), [state + _snow5g_lens_dqw]
        mov             DWORD(tmp2), [state + _snow5g_lens_dqw + 4]
        xor             DWORD(idx), DWORD(idx)
        cmp             DWORD(tmp2), DWORD(tmp)
        cmovb           DWORD(tmp), DWORD(tmp2)
        adc             DWORD(idx), 0

        test            DWORD(tmp), DWORD(tmp)
        jz              .len_is_0_submit_nia4

        mov     [rsp + _idx_save_nia4], idx
        mov     r11, state
        SNOW5G_NIA4_AUTH_X2 r11

        mov     state, [rsp + _state_save_nia4]
        mov     job,   [rsp + _job_save_nia4]
        mov     idx,   [rsp + _idx_save_nia4]

        ; Clear lane lengths after processing
        mov     qword [state + _snow5g_lens_dqw], 0

align_label
.len_is_0_submit_nia4:
        COMPLETE_JOB idx, tmp
        jmp     .exit_submit

align_label
.return_null_submit_nia4:
        xor     job_rax, job_rax

align_label
.exit_submit:
        SNOW5G_NIA4_FUNC_END
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Flushes completed jobs from the 2-buffer SNOW5G-NIA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(flush_job_snow5g_nia4_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nia4_vaes_avx512:
        endbranch64

%define unused_lanes     rbx
%define tmp1             rbx

%define tmp2             r13
%define tmp              rbp
%define tmp3             r8
%define tmp4             r15
%define idx              r14

        SNOW5G_NIA4_FUNC_START 0

        cmp     qword [state + _snow5g_lanes_in_use], 0
        jz      .return_null_flush_nia4

        ;; One lane active: find unused lane and set its length to max
        mov     DWORD(tmp3), [state + _snow5g_unused_lanes]
        and     DWORD(tmp3), 0x1
        mov     dword [state + _snow5g_lens_dqw + tmp3*4], 0xFFFFFFFF

        mov     DWORD(idx), DWORD(tmp3)
        xor     DWORD(idx), 1

        cmp     dword [state + _snow5g_lens_dqw + idx*4], 0
        je      .len_is_0_flush_nia4

        ;; Copy active lane's args to unused lane for NIA4_X2
        mov     tmp4, [state + _snow5g_args_in + idx*8]
        mov     [state + _snow5g_args_in + tmp3*8], tmp4

        mov     tmp4, [state + _snow5g_args_keys + idx*8]
        mov     [state + _snow5g_args_keys + tmp3*8], tmp4

        mov     DWORD(tmp), DWORD(idx)
        shl     DWORD(tmp), 4
        vmovdqu xmm0, [state + _snow5g_args_IV + tmp]
        mov     DWORD(tmp), DWORD(tmp3)
        shl     DWORD(tmp), 4
        vmovdqu [state + _snow5g_args_IV + tmp], xmm0
        mov     [rsp + _idx_save_nia4], idx
        mov     r11, state
        SNOW5G_NIA4_AUTH_X2 r11

        mov     state, [rsp + _state_save_nia4]
        mov     idx,   [rsp + _idx_save_nia4]

        ; Clear lane lengths after processing
        mov     qword [state + _snow5g_lens_dqw], 0

align_label
.len_is_0_flush_nia4:
        COMPLETE_JOB idx, tmp3
        jmp     .exit_flush

align_label
.return_null_flush_nia4:
        xor     job_rax, job_rax

align_label
.exit_flush:
        SNOW5G_NIA4_FUNC_END
        ret

mksection stack-noexec
