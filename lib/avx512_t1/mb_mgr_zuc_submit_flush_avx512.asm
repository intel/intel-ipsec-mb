;;
;; Copyright (c) 2020-2024, Intel Corporation
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

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/constants.inc"
%include "include/reg_sizes.inc"
%include "include/const.inc"
%include "include/clear_regs.inc"
%include "include/align_avx512.inc"

%ifndef SUBMIT_JOB_ZUC128_EEA3
%define SUBMIT_JOB_ZUC128_EEA3 submit_job_zuc_eea3_no_gfni_avx512
%define FLUSH_JOB_ZUC128_EEA3 flush_job_zuc_eea3_no_gfni_avx512
%define SUBMIT_JOB_ZUC128_EIA3 submit_job_zuc_eia3_no_gfni_avx512
%define FLUSH_JOB_ZUC128_EIA3 flush_job_zuc_eia3_no_gfni_avx512
%define ZUC128_INIT_16     asm_ZucInitialization_16_avx512
%define ZUC_KEYGEN4B_16    asm_ZucGenKeystream4B_16_avx512
%define ZUC_CIPHER         asm_ZucCipher_16_avx512
%define ZUC_REMAINDER_16   asm_Eia3RemainderAVX512_16
%define ZUC_KEYGEN_SKIP8_16 asm_ZucGenKeystream_16_skip8_avx512
%define ZUC_KEYGEN64B_SKIP8_16 asm_ZucGenKeystream64B_16_skip8_avx512
%define ZUC_KEYGEN_16      asm_ZucGenKeystream_16_avx512
%define ZUC_KEYGEN64B_16   asm_ZucGenKeystream64B_16_avx512
%define ZUC_ROUND64B       asm_Eia3Round64BAVX512_16
%define ZUC_EIA3_N64B      asm_Eia3_Nx64B_AVX512_16
%endif

mksection .rodata
default rel

index_to_mask:
dw      0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080
dw      0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000

extern asm_ZucInitialization_16_avx512
extern asm_ZucInitialization_16_gfni_avx512
extern asm_ZucCipher_16_avx512
extern asm_ZucCipher_16_gfni_avx512
extern asm_Eia3RemainderAVX512_16
extern asm_Eia3RemainderAVX512_16_VPCLMUL
extern asm_ZucGenKeystream_16_skip8_avx512
extern asm_ZucGenKeystream_16_skip8_gfni_avx512
extern asm_ZucGenKeystream64B_16_skip8_avx512
extern asm_ZucGenKeystream64B_16_skip8_gfni_avx512
extern asm_ZucGenKeystream_16_avx512
extern asm_ZucGenKeystream_16_gfni_avx512
extern asm_ZucGenKeystream64B_16_avx512
extern asm_ZucGenKeystream64B_16_gfni_avx512
extern asm_Eia3Round64BAVX512_16
extern asm_Eia3Round64B_16_VPCLMUL
extern asm_Eia3_Nx64B_AVX512_16
extern asm_Eia3_Nx64B_AVX512_16_VPCLMUL

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%define arg6    r9
%define arg7    qword [rsp]
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    qword [rsp + 32]
%define arg6    qword [rsp + 40]
%define arg7    qword [rsp + 48]
%endif

%define state   arg1
%define job     arg2

%define job_rax          rax

; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    10
_rsp_save:      resq    1
endstruc

%define OFS_R1  (16*(4*16))
%define OFS_R2  (OFS_R1 + (4*16))

mksection .text

%define APPEND(a,b) a %+ b

%macro SUBMIT_JOB_ZUC_EEA3 0

; idx needs to be in rbp
%define len              rbp
%define idx              rbp

%define lane             r8
%define unused_lanes     rbx
%define tmp              r12
%define tmp2             r13
%define tmp3             r14
%define min_len          r14

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _gpr_save + 8*9], job
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     lane, unused_lanes
        and     lane, 0xF ;; just a nibble
        shr     unused_lanes, 4
        mov     tmp, [job + _iv]
        shl     lane, 5
        ; Read first 16 bytes of IV
        vmovdqu xmm0, [tmp]
        vmovdqa [state + _zuc_args_IV + lane], xmm0
        shr     lane, 5
        mov     [state + _zuc_unused_lanes], unused_lanes
        add     qword [state + _zuc_lanes_in_use], 1

        mov     [state + _zuc_job_in_lane + lane*8], job
        ; New job that needs init (update bit in zuc_init_not_done bitmask)
        lea     tmp2, [rel index_to_mask]
        movzx   DWORD(tmp), word [tmp2 + lane*2]
        kmovw   k1, DWORD(tmp)
        or      [state + _zuc_init_not_done], WORD(tmp)
        not     DWORD(tmp)
        and     [state + _zuc_unused_lane_bitmask], WORD(tmp)

        mov     tmp, [job + _src]
        add     tmp, [job + _cipher_start_src_offset_in_bytes]
        mov     [state + _zuc_args_in + lane*8], tmp
        mov     tmp, [job + _enc_keys]
        mov     [state + _zuc_args_keys + lane*8], tmp
        mov     tmp, [job + _dst]
        mov     [state + _zuc_args_out + lane*8], tmp

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_cipher_in_bytes]

        ;; Update lane len
        vmovdqa64       ymm0, [state + _zuc_lens]
        vpbroadcastw    ymm1, WORD(len)
        vmovdqu16       ymm0{k1}, ymm1
        vmovdqa64       [state + _zuc_lens], ymm0

        ;; Find min length for lanes 0-7
        vphminposuw     xmm2, xmm0

        xor     job_rax, job_rax
        cmp     qword [state + _zuc_lanes_in_use], 16
        jne     %%return_submit_eea3

        ; Find min length for lanes 8-15
        vpextrw         DWORD(min_len), xmm2, 0   ; min value
        vpextrw         DWORD(idx), xmm2, 1   ; min index
        vextracti128    xmm1, ymm0, 1
        vphminposuw     xmm2, xmm1
        vpextrw         DWORD(tmp), xmm2, 0       ; min value
        cmp             DWORD(min_len), DWORD(tmp)
        jle             %%use_min
        vpextrw         DWORD(idx), xmm2, 1   ; min index
        add             DWORD(idx), 8               ; but index +8
        mov             min_len, tmp                    ; min len
align_label
%%use_min:
        or              min_len, min_len
        je              %%len_is_0_submit_eea3

        ; Move state into r11, as register for state will be used
        ; to pass parameter to next function
        mov     r11, state

        lea     arg1, [r11 + _zuc_args_keys]
        lea     arg2, [r11 + _zuc_args_IV]
        lea     arg3, [r11 + _zuc_state]
        movzx   DWORD(arg4), word [r11 + _zuc_init_not_done]

        call    ZUC128_INIT_16

        mov     r11, [rsp + _gpr_save + 8*8]

        mov     word [r11 + _zuc_init_not_done], 0 ; Init done for all lanes

        RESERVE_STACK_SPACE 5

        lea     arg1, [r11 + _zuc_state]
        lea     arg2, [r11 + _zuc_args_in]
        lea     arg3, [r11 + _zuc_args_out]
        lea     arg4, [r11 + _zuc_lens]
        mov     arg5, min_len

        call    ZUC_CIPHER

        RESTORE_STACK_SPACE 5

        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

align_label
%%len_is_0_submit_eea3:
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub     qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes
        lea     tmp2, [rel index_to_mask]
        movzx   DWORD(tmp), word [tmp2 + idx*2]
        or      [state + _zuc_unused_lane_bitmask], WORD(tmp)

        ; Clear ZUC state of lane that is returned
%ifdef SAFE_DATA
        vpxorq          zmm0, zmm0
        kmovw           k1, [tmp2 + idx*2]
%assign i 0
%rep (16 + 6)
        vmovdqa32       [state + _zuc_state]{k1}, zmm0
%assign i (i + 1)
%endrep
%endif

align_label
%%return_submit_eea3:
%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif
        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

%macro FLUSH_JOB_ZUC_EEA3 0

%define unused_lanes     rbx
%define tmp1             rbx

%define tmp2             rax

; idx needs to be in rbp (will be maintained after function calls)
%define tmp              rbp
%define idx              rbp

%define tmp3             r8
%define tmp4             r9
%define tmp5             r10
%define null_jobs_mask   r13 ; Will be maintained after function calls
%define min_len          r14 ; Will be maintained after function calls

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _rsp_save], rax  ; original SP

        ; check for empty
        xor     job_rax, job_rax
        cmp     qword [state + _zuc_lanes_in_use], 0
        jz      %%return_flush_eea3

        ; Find lanes with NULL jobs
        vpxorq          zmm0, zmm0
        vmovdqu64       zmm1, [state + _zuc_job_in_lane]
        vmovdqu64       zmm2, [state + _zuc_job_in_lane + (8*8)]
        vpcmpq          k1, zmm1, zmm0, 0 ; EQ ; mask of null jobs (L8)
        vpcmpq          k2, zmm2, zmm0, 0 ; EQ ; mask of null jobs (H8)
        kshiftlw        k3, k2, 8
        korw            k3, k3, k1 ; mask of NULL jobs for all lanes
        kmovw           DWORD(null_jobs_mask), k3
        ;; - Update lengths of NULL lanes to 0xFFFF, to find minimum
        vmovdqa         ymm0, [state + _zuc_lens]
        mov             WORD(tmp3), 0xffff
        vpbroadcastw    ymm1, WORD(tmp3)
        vmovdqu16       ymm0{k3}, ymm1
        vmovdqa64       [state + _zuc_lens], ymm0

        ; Find if a job has been finished (length is zero)
        vpxor           ymm1, ymm1
        vpcmpw          k4, ymm0, ymm1, 0
        kmovw           DWORD(tmp), k4
        bsf             DWORD(idx), DWORD(tmp)
        jnz             %%len_is_0_flush_eea3

        ;; Find min length for lanes 0-7
        vphminposuw     xmm2, xmm0

        ; extract min length of lanes 0-7
        vpextrw         DWORD(min_len), xmm2, 0   ; min value
        vpextrw         DWORD(idx), xmm2, 1   ; min index

        ;; Update lens and find min for lanes 8-15
        vextracti128    xmm1, ymm0, 1
        vphminposuw     xmm2, xmm1
        vpextrw         DWORD(tmp3), xmm2, 0       ; min value
        cmp             DWORD(min_len), DWORD(tmp3)
        jle             %%use_min_flush
        vpextrw         DWORD(idx), xmm2, 1   ; min index
        add             DWORD(idx), 8               ; but index +8
        mov             min_len, tmp3                    ; min len
align_label
%%use_min_flush:

        ; Move state into r12, as register for state will be used
        ; to pass parameter to next function
        mov     r12, state

        ;; copy good lane data (with minimum length) into NULL lanes
        ;; - k1(L8)/k2(H8)/k3 - masks of NULL jobs
        ;; - idx index of job with minimum length

        ;; - in pointer
        mov             tmp3, [state + _zuc_args_in + idx*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_in + (0*PTR_SZ)]{k1}, zmm1
        vmovdqu64       [state + _zuc_args_in + (8*PTR_SZ)]{k2}, zmm1
        ;; - out pointer
        mov             tmp3, [state + _zuc_args_out + idx*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_out + (0*PTR_SZ)]{k1}, zmm1
        vmovdqu64       [state + _zuc_args_out + (8*PTR_SZ)]{k2}, zmm1
        ;; - key pointer
        mov             tmp3, [state + _zuc_args_keys + idx*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_keys + (0*PTR_SZ)]{k1}, zmm1
        vmovdqu64       [state + _zuc_args_keys + (8*PTR_SZ)]{k2}, zmm1

        cmp     word [r12 + _zuc_init_not_done], 0
        je      %%skip_init_flush

        lea     arg1, [r12 + _zuc_args_keys]
        lea     arg2, [r12 + _zuc_args_IV]
        lea     arg3, [r12 + _zuc_state]
        movzx   DWORD(arg4), word [r12 + _zuc_init_not_done]

        call    ZUC128_INIT_16
        mov     word [r12 + _zuc_init_not_done], 0

align_label
%%skip_init_flush:
        ;; Copy state from valid lane into NULL job masks
        kmovq   k1, null_jobs_mask

        ;; Copy LFSR registers
%assign off 0
%rep 16
        mov     DWORD(tmp4), [r12 + _zuc_state + off + idx*4]
        vpbroadcastd    zmm0, DWORD(tmp4)
        vmovdqa32 [r12 + _zuc_state + off]{k1}, zmm0
%assign off (off + 64)
%endrep
        ;; Copy R1-2
        mov   DWORD(tmp4), [r12 + _zuc_state + OFS_R1 + idx*4]
        vpbroadcastd    zmm0, DWORD(tmp4)
        vmovdqa32 [r12 + _zuc_state + OFS_R1]{k1}, zmm0
        mov   DWORD(tmp4), [r12 + _zuc_state + OFS_R2 + idx*4]
        vpbroadcastd    zmm0, DWORD(tmp4)
        vmovdqa32 [r12 + _zuc_state + OFS_R2]{k1}, zmm0

        RESERVE_STACK_SPACE 5

        lea     arg1, [r12 + _zuc_state]
        lea     arg2, [r12 + _zuc_args_in]
        lea     arg3, [r12 + _zuc_args_out]
        lea     arg4, [r12 + _zuc_lens]
        mov     arg5, min_len

        call    ZUC_CIPHER

        RESTORE_STACK_SPACE 5

        mov     state, [rsp + _gpr_save + 8*8]

        ; Prepare bitmask to clear ZUC state with lane
        ; that is returned and NULL lanes
%ifdef SAFE_DATA
        lea     tmp2, [rel index_to_mask]
        movzx   DWORD(tmp1), word [tmp2 + idx*2]
        movzx   DWORD(tmp3), word [state + _zuc_unused_lane_bitmask]
        or      tmp3, tmp1 ;; bitmask with NULL lanes and job to return
        kmovq   k1, tmp3

        jmp     %%skip_flush_clear_state
%endif
align_label
%%len_is_0_flush_eea3:
%ifdef SAFE_DATA
        ; Prepare bitmask to clear ZUC state with lane that is returned
        lea     tmp3, [rel index_to_mask]
        kmovw   k1, [tmp3 + idx*2]

align_label
%%skip_flush_clear_state:
%endif
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub     qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

        lea     tmp4, [rel index_to_mask]
        movzx   DWORD(tmp3), word [tmp4 + idx*2]
        or      [state + _zuc_unused_lane_bitmask], WORD(tmp3)
        ; Clear ZUC state using k1 bitmask set above
%ifdef SAFE_DATA
        vpxorq          zmm0, zmm0
%assign i 0
%rep (16 + 6)
        vmovdqa32       [state + _zuc_state]{k1}, zmm0
%assign i (i + 1)
%endrep
%endif

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif

align_label
%%return_flush_eea3:

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

; JOB* SUBMIT_JOB_ZUC128_EEA3(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_ZUC128_EEA3,function,internal)
align_function
SUBMIT_JOB_ZUC128_EEA3:
        SUBMIT_JOB_ZUC_EEA3
        ret



; JOB* FLUSH_JOB_ZUC128_EEA3(MB_MGR_ZUC_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_ZUC128_EEA3,function,internal)
align_function
FLUSH_JOB_ZUC128_EEA3:
        FLUSH_JOB_ZUC_EEA3
        ret



%macro ZUC_EIA3_16_BUFFER 4
%define %%OOO           %1 ; [in] Pointer to ZUC OOO manager
%define %%L             %2 ; [clobbered] Temporary GP register (dword)
%define %%REMAIN_BITS   %3 ; [clobbered] Temporary GP register (dword)
%define %%TMP           %4 ; [clobbered] Temporary GP register

        ; Find minimum length
        vmovdqa xmm0, [%%OOO + _zuc_lens]
        vphminposuw xmm0, xmm0
        vmovdqa xmm1, [%%OOO + _zuc_lens + 16]
        vphminposuw xmm1, xmm1
        vpextrw %%REMAIN_BITS, xmm0, 0
        vpextrw DWORD(%%TMP), xmm1, 0
        cmp     DWORD(%%TMP), %%REMAIN_BITS
        cmovbe  %%REMAIN_BITS, DWORD(%%TMP)

        ; Get number of KS 32-bit words to generate ([length/32] + tag_size))
        lea     %%L, [%%REMAIN_BITS + 31 + 2*(8*4)]

        shr     %%L, 5

        cmp     %%L, 16
        jae     %%_above_eq_16

        ; Generate L KS words (less than 16), except for old buffers, which only need L-2,
        ; since 2 words are reused from previous iteration
        RESERVE_STACK_SPACE 5

        lea     arg1, [%%OOO + _zuc_state]
        lea     arg2, [%%OOO + _zuc_args_KS]
        xor     arg3, arg3 ; offset = 0
        movzx   DWORD(arg4), word [%%OOO + _zuc_init_not_done]

%ifdef LINUX
        mov     DWORD(arg5), %%L
%else
        mov     [rsp + 32], %%L
%endif

        call    ZUC_KEYGEN_SKIP8_16

        RESTORE_STACK_SPACE 5

        jmp     %%_exit

align_label
%%_above_eq_16:
        ; Generate 16 KS words, except for old buffers. which only need 14 (16 - 2),
        ; since 2 words are reused from previous iteration
        lea     arg1, [%%OOO + _zuc_state]
        lea     arg2, [%%OOO + _zuc_args_KS]
        xor     arg3, arg3 ; offset = 0
        movzx   DWORD(arg4), word [%%OOO + _zuc_init_not_done]

        call    ZUC_KEYGEN64B_SKIP8_16
        sub     %%L, 16

align_loop
%%_loop:
        cmp     %%REMAIN_BITS, 64*8
        jbe     %%_exit_loop

        cmp     %%L, 16
        jae     %%_above_eq_16_loop

        ; Generate last KS words needed
        lea     arg1, [%%OOO + _zuc_state]
        lea     arg2, [%%OOO + _zuc_args_KS]
        mov     arg3, 64 ; offset = 64
        mov     DWORD(arg4), %%L

        call    ZUC_KEYGEN_16

        RESERVE_STACK_SPACE 4

        ; Digest 64 bytes of data
        lea     arg1, [%%OOO + _zuc_args_digest]
        lea     arg2, [%%OOO + _zuc_args_KS]
        lea     arg3, [%%OOO + _zuc_args_in]
        lea     arg4, [%%OOO + _zuc_lens]

        call    ZUC_ROUND64B

        RESTORE_STACK_SPACE 4

        sub     %%REMAIN_BITS, 64*8
        jmp     %%_exit

align_label
%%_above_eq_16_loop:

        ; Generate next 16 KS words and digest 64 bytes of data
        RESERVE_STACK_SPACE 6

        mov     DWORD(%%TMP), %%L
        shr     DWORD(%%TMP), 4 ; Number of rounds of 64 bytes

        ;; Calculate number of remaining bits after function call
        mov     eax, 64*8
        mul     %%TMP
        sub     %%REMAIN_BITS, eax
        lea     arg1, [%%OOO + _zuc_state]
        lea     arg2, [%%OOO + _zuc_args_KS]
        lea     arg3, [%%OOO + _zuc_args_digest]
        lea     arg4, [%%OOO + _zuc_args_in]
%ifdef LINUX
        mov     arg6, %%TMP
        lea     arg5, [%%OOO + _zuc_lens]
%else
        mov     [rsp + 40], %%TMP
        lea     %%TMP, [%%OOO + _zuc_lens]
        mov     [rsp + 32], %%TMP
%endif

        call    ZUC_EIA3_N64B

        RESTORE_STACK_SPACE 6

        and     %%L, 0xf ; Remaining words of KS left to generate

        jmp     %%_loop

align_label
%%_exit_loop:
        or      %%L, %%L
        jz      %%_exit
        lea     arg1, [%%OOO + _zuc_state]
        lea     arg2, [%%OOO + _zuc_args_KS]
        mov     arg3, 64 ; offset = 64
        mov     DWORD(arg4), %%L

        ; Generate final KS words
        call    ZUC_KEYGEN_16

align_label
%%_exit:
        RESERVE_STACK_SPACE 5

        ; Digest final bytes of data and generate tag for finished buffers
        lea     arg1, [%%OOO + _zuc_args_digest]
        lea     arg2, [%%OOO + _zuc_args_KS]
        lea     arg3, [%%OOO + _zuc_args_in]
        lea     arg4, [%%OOO + _zuc_lens]
%ifdef LINUX
        mov     DWORD(arg5), %%REMAIN_BITS
%else
        mov     [rsp + 32], %%REMAIN_BITS
%endif

        call    ZUC_REMAINDER_16
        RESTORE_STACK_SPACE 5

        mov     word [%%OOO + _zuc_init_not_done], 0
%endmacro

%macro SUBMIT_JOB_ZUC_EIA3 0

; idx needs to be in rbp
%define len              rbp
%define idx              rbp

%define lane             r8
%define unused_lanes     rbx
%define tmp              r15
%define tmp2             r13
%define tmp3             r14
%define min_len          r14

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _gpr_save + 8*9], job
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     lane, unused_lanes
        and     lane, 0xF           ;; just a nibble
        shr     unused_lanes, 4
        mov     tmp, [job + _zuc_eia3_iv]
        shl     lane, 5
        ; Read first 16 bytes of IV
        vmovdqu xmm0, [tmp]
        vmovdqa [state + _zuc_args_IV + lane], xmm0
        shr     lane, 5
        mov     [state + _zuc_unused_lanes], unused_lanes
        add     qword [state + _zuc_lanes_in_use], 1

        mov     [state + _zuc_job_in_lane + lane*8], job
        ; New job that needs init (update bit in zuc_init_not_done bitmask)
        lea     tmp2, [rel index_to_mask]
        movzx   DWORD(tmp), word [tmp2 + lane*2]
        or      [state + _zuc_init_not_done], WORD(tmp)
        kmovq   k1, tmp
        not     tmp
        and     [state + _zuc_unused_lane_bitmask], WORD(tmp)
        ; Reset temporary digest for the lane
        mov     dword [state + _zuc_args_digest + lane*4], 0
        mov     tmp, [job + _src]
        add     tmp, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _zuc_args_in + lane*8], tmp
        mov     tmp, [job + _zuc_eia3_key]
        mov     [state + _zuc_args_keys + lane*8], tmp

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_hash_in_bits]

        ;; Update lane len
        vmovdqa64       ymm0, [state + _zuc_lens]
        vpbroadcastw    ymm1, WORD(len)
        vmovdqu16       ymm0{k1}, ymm1
        vmovdqa64       [state + _zuc_lens], ymm0

        xor     job_rax, job_rax
        cmp     qword [state + _zuc_lanes_in_use], 16
        jne     %%return_submit_eia3

        ;; Find min length for lanes 0-7
        vphminposuw     xmm2, xmm0

        ; Find min length for lanes 8-15
        vpextrw         DWORD(min_len), xmm2, 0   ; min value
        vpextrw         DWORD(idx), xmm2, 1   ; min index
        vextracti128    xmm1, ymm0, 1
        vphminposuw     xmm2, xmm1
        vpextrw         DWORD(tmp), xmm2, 0       ; min value
        cmp             DWORD(min_len), DWORD(tmp)
        jle             %%use_min_eia3
        vpextrw         DWORD(idx), xmm2, 1   ; min index
        add             DWORD(idx), 8               ; but index +8
        mov             min_len, tmp                    ; min len
align_label
%%use_min_eia3:
        or              min_len, min_len
        jz              %%len_is_0_submit_eia3

        ; Move state into r12, as register for state will be used
        ; to pass parameter to next function
        mov     r12, state

        lea     arg1, [r12 + _zuc_args_keys]
        lea     arg2, [r12 + _zuc_args_IV]
        lea     arg3, [r12 + _zuc_state]
        movzx   DWORD(arg4), word [r12 + _zuc_init_not_done]

        call    ZUC128_INIT_16

        ZUC_EIA3_16_BUFFER r12, DWORD(tmp), DWORD(tmp2), tmp3

        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

align_label
%%len_is_0_submit_eia3:
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub     qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        ; Copy digest to auth tag output
        mov     r11, [job_rax + _auth_tag_output]
        mov     r10d, [state + _zuc_args_digest + idx*4]
        mov     [r11], r10d
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes
        lea     tmp2, [rel index_to_mask]
        movzx   DWORD(tmp), word [tmp2 + idx*2]
        or      [state + _zuc_unused_lane_bitmask], WORD(tmp)

        ; Clear ZUC state of lane that is returned
%ifdef SAFE_DATA
        vpxorq          zmm0, zmm0
        kmovw           k1, [tmp2 + idx*2]
%assign i 0
%rep (16 + 6)
        vmovdqa32       [state + _zuc_state]{k1}, zmm0
%assign i (i + 1)
%endrep
%endif

align_label
%%return_submit_eia3:
%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

%macro FLUSH_JOB_ZUC_EIA3 0

%define unused_lanes     rbx
%define tmp1             rbx

%define tmp2             r13

%define tmp              rbp

%define tmp3             r8
%define tmp4             r15
%define idx              r14 ; Will be maintained after function calls
%define min_len          r15

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _rsp_save], rax  ; original SP

        ; check for empty
        xor     job_rax, job_rax
        cmp     qword [state + _zuc_lanes_in_use], 0
        jz      %%return_flush_eia3

        ; find a lane with a null job
        vpxorq          zmm0, zmm0
        vmovdqu64       zmm1, [state + _zuc_job_in_lane]
        vmovdqu64       zmm2, [state + _zuc_job_in_lane + (8*8)]
        vpcmpq          k1, zmm1, zmm0, 0 ; EQ ; mask of null jobs (L8)
        vpcmpq          k2, zmm2, zmm0, 0 ; EQ ; mask of null jobs (H8)
        kshiftlw        k3, k2, 8
        korw            k3, k3, k1 ; mask of NULL jobs for all lanes
        ;; - Update lengths of NULL lanes to 0xFFFF, to find minimum
        vmovdqa         ymm0, [state + _zuc_lens]
        mov             WORD(tmp3), 0xffff
        vpbroadcastw    ymm1, WORD(tmp3)
        vmovdqu16       ymm0{k3}, ymm1
        vmovdqa64       [state + _zuc_lens], ymm0

        ; Find if a job has been finished (length is zero)
        vpxor           ymm1, ymm1
        vpcmpw          k4, ymm0, ymm1, 0
        kmovw           DWORD(tmp), k4
        bsf             DWORD(idx), DWORD(tmp)
        jnz             %%len_is_0_flush_eia3

        ;; Find min length for lanes 0-7
        vphminposuw     xmm2, xmm0

        ; extract min length of lanes 0-7
        vpextrw         DWORD(min_len), xmm2, 0   ; min value
        vpextrw         DWORD(idx), xmm2, 1   ; min index

        ;; Update lens and find min for lanes 8-15
        vextracti128    xmm1, ymm0, 1
        vphminposuw     xmm2, xmm1
        vpextrw         DWORD(tmp3), xmm2, 0       ; min value
        cmp             DWORD(min_len), DWORD(tmp3)
        jle             %%use_min_flush_eia3
        vpextrw         DWORD(idx), xmm2, 1   ; min index
        add             DWORD(idx), 8               ; but index +8
        mov             min_len, tmp3                    ; min len
align_label
%%use_min_flush_eia3:

        ;; copy good lane data into NULL lanes
        ;; - k1(L8)/k2(H8)/k3 - masks of NULL jobs
        ;; - idx - index of 1st non-null job

        ;; - in pointer
        mov             tmp3, [state + _zuc_args_in + idx*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_in + (0*PTR_SZ)]{k1}, zmm1
        vmovdqu64       [state + _zuc_args_in + (8*PTR_SZ)]{k2}, zmm1
        ;; - key pointer
        mov             tmp3, [state + _zuc_args_keys + idx*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_keys + (0*PTR_SZ)]{k1}, zmm1
        vmovdqu64       [state + _zuc_args_keys + (8*PTR_SZ)]{k2}, zmm1

        ; Move state into r12, as register for state will be used
        ; to pass parameter to next function
        mov     r12, state

        cmp     word [r12 + _zuc_init_not_done], 0
        je      %%skip_init_flush_eia3

        lea     arg1, [r12 + _zuc_args_keys]
        lea     arg2, [r12 + _zuc_args_IV]
        lea     arg3, [r12 + _zuc_state]
        movzx   DWORD(arg4), word [r12 + _zuc_init_not_done]

        call    ZUC128_INIT_16

align_label
%%skip_init_flush_eia3:
        ZUC_EIA3_16_BUFFER r12, DWORD(tmp), DWORD(tmp2), tmp4

        mov     state, [rsp + _gpr_save + 8*8]

        ; Prepare bitmask to clear ZUC state with lane
        ; that is returned and NULL lanes
%ifdef SAFE_DATA
        lea     tmp2, [rel index_to_mask]
        movzx   DWORD(tmp1), word [tmp2 + idx*2]
        movzx   DWORD(tmp3), word [state + _zuc_unused_lane_bitmask]
        or      tmp3, tmp1 ;; bitmask with NULL lanes and job to return
        kmovq   k1, tmp3

        jmp     %%skip_flush_clear_state_eia3
%endif
align_label
%%len_is_0_flush_eia3:
%ifdef SAFE_DATA
        ; Prepare bitmask to clear ZUC state with lane that is returned
        lea     tmp3, [rel index_to_mask]
        kmovw   k1, [tmp3 + idx*2]

align_label
%%skip_flush_clear_state_eia3:
%endif
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub     qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        ; Copy digest to auth tag output
        mov     r11, [job_rax + _auth_tag_output]
        mov     r10d, [state + _zuc_args_digest + idx*4]
        mov     [r11], r10d
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

        lea     tmp4, [rel index_to_mask]
        movzx   DWORD(tmp3), word [tmp4 + idx*2]
        or      [state + _zuc_unused_lane_bitmask], WORD(tmp3)
        ; Clear ZUC state using k1 bitmask set above
%ifdef SAFE_DATA
        vpxorq          zmm0, zmm0
%assign i 0
%rep (16 + 6)
        vmovdqa32       [state + _zuc_state]{k1}, zmm0
%assign i (i + 1)
%endrep
%endif

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif

align_label
%%return_flush_eia3:
        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

; JOB* SUBMIT_JOB_ZUC128_EIA3(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_ZUC128_EIA3,function,internal)
align_function
SUBMIT_JOB_ZUC128_EIA3:
        SUBMIT_JOB_ZUC_EIA3
        ret


; JOB* FLUSH_JOB_ZUC128_EIA3(MB_MGR_ZUC_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_ZUC128_EIA3,function,internal)
align_function
FLUSH_JOB_ZUC128_EIA3:
        FLUSH_JOB_ZUC_EIA3
        ret


mksection stack-noexec
