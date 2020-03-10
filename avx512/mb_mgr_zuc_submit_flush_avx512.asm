;;
;; Copyright (c) 2020, Intel Corporation
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

%include "include/os.asm"
%include "imb_job.asm"
%include "mb_mgr_datastruct.asm"
%include "constants.asm"

%include "include/reg_sizes.asm"
%include "include/const.inc"

%ifndef SUBMIT_JOB_ZUC_EEA3
%define SUBMIT_JOB_ZUC_EEA3 submit_job_zuc_eea3_no_gfni_avx512
%define FLUSH_JOB_ZUC_EEA3 flush_job_zuc_eea3_no_gfni_avx512
%define SUBMIT_JOB_ZUC_EIA3 submit_job_zuc_eia3_no_gfni_avx512
%define FLUSH_JOB_ZUC_EIA3 flush_job_zuc_eia3_no_gfni_avx512
%define ZUC_EEA3_16_BUFFER zuc_eea3_16_buffer_job_no_gfni_avx512
%define ZUC_EIA3_16_BUFFER zuc_eia3_16_buffer_job_no_gfni_avx512
%endif

section .data
default rel

extern zuc_eea3_16_buffer_job_no_gfni_avx512
extern zuc_eia3_16_buffer_job_no_gfni_avx512
extern zuc_eea3_16_buffer_job_gfni_avx512
extern zuc_eia3_16_buffer_job_gfni_avx512

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
%define arg5    [rsp + 32]
%define arg6    [rsp + 40]
%endif

%define state   arg1
%define job     arg2

%define job_rax          rax

; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    10
_rsp_save:      resq    1
endstruc

section .text

%define APPEND(a,b) a %+ b

; JOB* SUBMIT_JOB_ZUC_EEA3(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_ZUC_EEA3,function,internal)
SUBMIT_JOB_ZUC_EEA3:

; idx needs to be in rbp
%define len              rbp
%define idx              rbp
%define tmp              rbp

%define lane             r8
%define unused_lanes     rbx
%define len2             r13

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
        mov     [state + _zuc_args_IV + lane*8], tmp
        mov     [state + _zuc_unused_lanes], unused_lanes
        add	qword [state + _zuc_lanes_in_use], 1

        mov     [state + _zuc_job_in_lane + lane*8], job
        mov     tmp, [job + _src]
        add     tmp, [job + _cipher_start_src_offset_in_bytes]
        mov     [state + _zuc_args_in + lane*8], tmp
        mov     tmp, [job + _enc_keys]
        mov     [state + _zuc_args_keys + lane*8], tmp
        mov     tmp, [job + _dst]
        mov     [state + _zuc_args_out + lane*8], tmp

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_cipher_in_bytes]

        ;; TODO: Optimize to avoid store-to-load-fwd issues
        mov     [state + _zuc_lens + lane * 2], WORD(len)

        cmp     qword [state + _zuc_lanes_in_use], 16
        jne     return_null_submit_eea3

        ; Search for zero length (if all lengths are non zero, execute crypto code)
        ; If at least one of the lengths is zero, it means that the job has been completed
        ; and it can be returned (leaving the lane id in "idx"), without executing
        ; any crypto code
        vpxor   ymm1, ymm1
        vmovdqa ymm0, [state + _zuc_lens]
        vpcmpw  k1, ymm0, ymm1, 0
        kmovw   DWORD(idx), k1
        bsf     DWORD(idx), DWORD(tmp)
        jnz     len_is_0_submit_eea3

        ; Move state into r11, as register for state will be used
        ; to pass parameter to next function
        mov     r11, state

        ;; If Windows, reserve memory in stack for parameter transferring
%ifndef LINUX
        ;; 48 bytes for 6 parameters (already aligned to 16 bytes)
        sub     rsp, 48
%endif
        lea     arg1, [r11 + _zuc_args_keys]
        lea     arg2, [r11 + _zuc_args_IV]
        lea     arg3, [r11 + _zuc_args_in]
        lea     arg4, [r11 + _zuc_args_out]
%ifdef LINUX
        lea     arg5, [r11 + _zuc_lens]
        lea     arg6, [r11 + _zuc_job_in_lane]
%else
        lea     r12, [r11 + _zuc_lens]
        mov     arg5, r12
        lea     r12, [r11 + _zuc_job_in_lane]
        mov     arg6, r12
%endif

        call    ZUC_EEA3_16_BUFFER

%ifndef LINUX
        add     rsp, 48
%endif
        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

        ;; Clear all lengths (function will encrypt whole buffers)
        vpxor   ymm0, ymm0
        vmovdqa [state + _zuc_lens], ymm0

len_is_0_submit_eea3:
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub	qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], STS_COMPLETED_AES
        mov     word [state + _zuc_lens + idx*2], 0xFFFF
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

return_submit_eea3:

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

        ret

return_null_submit_eea3:
        xor     job_rax, job_rax
        jmp     return_submit_eea3

; JOB* FLUSH_JOB_ZUC_EEA3(MB_MGR_ZUC_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_ZUC_EEA3,function,internal)
FLUSH_JOB_ZUC_EEA3:

%define unused_lanes     rbx
%define tmp1             rbx

%define tmp2             rax

; idx needs to be in rbp
%define tmp              rbp
%define idx              rbp

%define tmp3             r8
%define tmp4             r9
%define tmp5             r10

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
        cmp     qword [state + _zuc_lanes_in_use], 0
        jz      return_null_flush_eea3

        ; Find if a job has been finished (length is zero)
        vpxor           ymm1, ymm1
        vmovdqa         ymm0, [state + _zuc_lens]
        vpcmpw          k1, ymm0, ymm1, 0
        kmovw           DWORD(idx), k1
        bsf             DWORD(idx), DWORD(tmp)
        jnz             len_is_0_flush_eea3

        ; find a lane with a non-null job
        vpxorq          zmm0, zmm0
        vmovdqu64       zmm1, [state + _zuc_job_in_lane]
        vmovdqu64       zmm2, [state + _zuc_job_in_lane + (8*8)]
        vpcmpq          k1, zmm1, zmm0, 4 ; NEQ
        vpcmpq          k2, zmm2, zmm0, 4 ; NEQ
        xor             tmp3, tmp3
        xor             tmp4, tmp4
        kmovw           DWORD(tmp3), k1
        kmovw           DWORD(tmp4), k2
        mov             DWORD(tmp5), DWORD(tmp4)
        shl             DWORD(tmp5), 8
        or              DWORD(tmp5), DWORD(tmp3) ; mask of non-null jobs in tmp5
        not             BYTE(tmp3)
        kmovw           k4, DWORD(tmp3)
        not             BYTE(tmp4)
        kmovw           k5, DWORD(tmp4)
        mov             DWORD(tmp3), DWORD(tmp5)
        not             WORD(tmp3)
        kmovw           k6, DWORD(tmp3)         ; mask of NULL jobs in k4, k5 and k6
        mov             DWORD(tmp3), DWORD(tmp5)
        xor             tmp5, tmp5
        bsf             WORD(tmp5), WORD(tmp3)   ; index of the 1st set bit in tmp5

        ;; copy good lane data into NULL lanes
        ;; - k1(L8)/k2(H8)    - masks of non-null jobs
        ;; - k4(L8)/k5(H8)/k6 - masks of NULL jobs
        ;; - tmp5 index of 1st non-null job

        ;; - in pointer
        mov             tmp3, [state + _zuc_args_in + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_in + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_in + (8*PTR_SZ)]{k5}, zmm1
        ;; - out pointer
        mov             tmp3, [state + _zuc_args_out + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_out + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_out + (8*PTR_SZ)]{k5}, zmm1
        ;; - key pointer
        mov             tmp3, [state + _zuc_args_keys + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_keys + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_keys + (8*PTR_SZ)]{k5}, zmm1
        ;; - IV pointer
        mov             tmp3, [state + _zuc_args_IV + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_IV + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_IV + (8*PTR_SZ)]{k5}, zmm1
        ;; - len
        mov             WORD(tmp3), [state + _zuc_lens + tmp5*2]
        vpbroadcastw    zmm1, WORD(tmp3)
        vmovdqu16       [state + _zuc_lens]{k6}, zmm1

        kmovq   tmp3, k6
        push    tmp3 ;; Save NULL jobs mask
        push    tmp5 ;; Save valid idx

        ; Move state into r11, as register for state will be used
        ; to pass parameter to next function
        mov     r11, state

        ;; If Windows, reserve memory in stack for parameter transferring
%ifndef LINUX
        ;; 48 bytes for 6 parameters (already aligned to 16 bytes)
        sub     rsp, 48
%endif
        lea     arg1, [r11 + _zuc_args_keys]
        lea     arg2, [r11 + _zuc_args_IV]
        lea     arg3, [r11 + _zuc_args_in]
        lea     arg4, [r11 + _zuc_args_out]
%ifdef LINUX
        lea     arg5, [r11 + _zuc_lens]
        lea     arg6, [r11 + _zuc_job_in_lane]
%else
        lea     r12, [r11 + _zuc_lens]
        mov     arg5, r12
        lea     r12, [r11 + _zuc_job_in_lane]
        mov     arg6, r12
%endif

        call    ZUC_EEA3_16_BUFFER

%ifndef LINUX
        add     rsp, 48
%endif

        pop     idx ;; Restore valid idx
        pop     tmp3 ;; Restore NULL jobs mask
        kmovq   k6, tmp3
        mov     state, [rsp + _gpr_save + 8*8]

        ;; Clear all lengths on valid jobs and set 0xFFFF to non-valid jobs
        ;; (crypto code above will encrypt all valid buffers)
        vpxor   ymm0, ymm0
        knotw   k6, k6  ;; Non-NULL jobs mask
        vmovdqu16 [state + _zuc_lens]{k6}, ymm0

        vpternlogq ymm0, ymm0, ymm0, 0x0F ;; YMM0 = 0xFF...FF
        knotw    k6, k6 ;; NULL jobs mask
        vmovdqu16 [state + _zuc_lens]{k6}, ymm0

len_is_0_flush_eea3:
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub	qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        ;; TODO: fix double store (above setting the length to 0 and now setting to FFFFF)
        mov     word [state + _zuc_lens + idx*2], 0xFFFF
        or      dword [job_rax + _status], STS_COMPLETED_AES
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

return_flush_eea3:

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

        ret

return_null_flush_eea3:
        xor     job_rax, job_rax
        jmp     return_flush_eea3

; JOB* SUBMIT_JOB_ZUC_EIA3(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_ZUC_EIA3,function,internal)
SUBMIT_JOB_ZUC_EIA3:

; idx needs to be in rbp
%define len              rbp
%define idx              rbp
%define tmp              rbp

%define lane             r8
%define unused_lanes     rbx
%define len2             r13

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
        and	lane, 0xF           ;; just a nibble
        shr     unused_lanes, 4
        mov     tmp, [job + _zuc_eia3_iv]
        mov     [state + _zuc_args_IV + lane*8], tmp
        mov     [state + _zuc_unused_lanes], unused_lanes
        add	qword [state + _zuc_lanes_in_use], 1

        mov     [state + _zuc_job_in_lane + lane*8], job
        mov     tmp, [job + _src]
        add     tmp, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _zuc_args_in + lane*8], tmp
        mov     tmp, [job + _zuc_eia3_key]
        mov     [state + _zuc_args_keys + lane*8], tmp
        mov     tmp, [job + _auth_tag_output]
        mov     [state + _zuc_args_out + lane*8], tmp

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_hash_in_bits]

        ;; TODO: Optimize to avoid store-to-load-fwd issues
        mov     [state + _zuc_lens + lane * 2], WORD(len)

        cmp     qword [state + _zuc_lanes_in_use], 16
        jne     return_null_submit_eia3

        ; Search for zero length (if all lengths are non zero, execute crypto code)
        ; If at least one of the lengths is zero, it means that the job has been completed
        ; and it can be returned (leaving the lane id in "idx"), without executing
        ; any crypto code
        vpxor   ymm1, ymm1
        vmovdqa ymm0, [state + _zuc_lens]
        vpcmpw  k1, ymm0, ymm1, 0
        kmovw   DWORD(idx), k1
        bsf     DWORD(idx), DWORD(tmp)
        jnz     len_is_0_submit_eia3

        ; Move state into r11, as register for state will be used
        ; to pass parameter to next function
        mov     r11, state

        ;; If Windows, reserve memory in stack for parameter transferring
%ifndef LINUX
        ;; 48 bytes for 6 parameters (already aligned to 16 bytes)
        sub     rsp, 48
%endif
        lea     arg1, [r11 + _zuc_args_keys]
        lea     arg2, [r11 + _zuc_args_IV]
        lea     arg3, [r11 + _zuc_args_in]
        lea     arg4, [r11 + _zuc_args_out]
%ifdef LINUX
        lea     arg5, [r11 + _zuc_lens]
        lea     arg6, [r11 + _zuc_job_in_lane]
%else
        lea     r12, [r11 + _zuc_lens]
        mov     arg5, r12
        lea     r12, [r11 + _zuc_job_in_lane]
        mov     arg6, r12
%endif

        call    ZUC_EIA3_16_BUFFER

%ifndef LINUX
        add     rsp, 48
%endif
        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

        ;; Clear all lengths (function will authenticate all buffers)
        vpxor   ymm0, ymm0
        vmovdqu [state + _zuc_lens], ymm0

len_is_0_submit_eia3:
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub	qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], STS_COMPLETED_HMAC
        mov     word [state + _zuc_lens + idx*2], 0xFFFF
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

return_submit_eia3:

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

        ret

return_null_submit_eia3:
        xor     job_rax, job_rax
        jmp     return_submit_eia3

; JOB* FLUSH_JOB_ZUC_EIA3(MB_MGR_ZUC_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_ZUC_EIA3,function,internal)
FLUSH_JOB_ZUC_EIA3:

%define unused_lanes     rbx
%define tmp1             rbx

%define tmp2             rax

; idx needs to be in rbp
%define tmp              rbp
%define idx              rbp

%define tmp3             r8
%define tmp4             r9
%define tmp5             r10

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
        cmp     qword [state + _zuc_lanes_in_use], 0
        jz      return_null_flush_eia3

        ; Find if a job has been finished (length is zero)
        vpxor   ymm1, ymm1
        vmovdqa ymm0, [state + _zuc_lens]
        vpcmpw  k1, ymm0, ymm1, 0
        kmovw   DWORD(idx), k1
        bsf     DWORD(idx), DWORD(tmp)
        jnz     len_is_0_flush_eia3

        ; find a lane with a non-null job
        vpxorq          zmm0, zmm0
        vmovdqu64       zmm1, [state + _zuc_job_in_lane]
        vmovdqu64       zmm2, [state + _zuc_job_in_lane + (8*8)]
        vpcmpq          k1, zmm1, zmm0, 4 ; NEQ
        vpcmpq          k2, zmm2, zmm0, 4 ; NEQ
        xor             tmp3, tmp3
        xor             tmp4, tmp4
        kmovw           DWORD(tmp3), k1
        kmovw           DWORD(tmp4), k2
        mov             DWORD(tmp5), DWORD(tmp4)
        shl             DWORD(tmp5), 8
        or              DWORD(tmp5), DWORD(tmp3) ; mask of non-null jobs in tmp5
        not             BYTE(tmp3)
        kmovw           k4, DWORD(tmp3)
        not             BYTE(tmp4)
        kmovw           k5, DWORD(tmp4)
        mov             DWORD(tmp3), DWORD(tmp5)
        not             WORD(tmp3)
        kmovw           k6, DWORD(tmp3)         ; mask of NULL jobs in k4, k5 and k6
        mov             DWORD(tmp3), DWORD(tmp5)
        xor             tmp5, tmp5
        bsf             WORD(tmp5), WORD(tmp3)   ; index of the 1st set bit in tmp5

        ;; copy good lane data into NULL lanes
        ;; - k1(L8)/k2(H8)    - masks of non-null jobs
        ;; - k4(L8)/k5(H8)/k6 - masks of NULL jobs
        ;; - tmp5 index of 1st non-null job

        ;; - in pointer
        mov             tmp3, [state + _zuc_args_in + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_in + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_in + (8*PTR_SZ)]{k5}, zmm1
        ;; - out pointer
        mov             tmp3, [state + _zuc_args_out + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_out + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_out + (8*PTR_SZ)]{k5}, zmm1
        ;; - key pointer
        mov             tmp3, [state + _zuc_args_keys + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_keys + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_keys + (8*PTR_SZ)]{k5}, zmm1
        ;; - IV pointer
        mov             tmp3, [state + _zuc_args_IV + tmp5*8]
        vpbroadcastq    zmm1, tmp3
        vmovdqu64       [state + _zuc_args_IV + (0*PTR_SZ)]{k4}, zmm1
        vmovdqu64       [state + _zuc_args_IV + (8*PTR_SZ)]{k5}, zmm1
        ;; - len
        mov             WORD(tmp3), [state + _zuc_lens + tmp5*2]
        vpbroadcastw    zmm1, WORD(tmp3)
        vmovdqu16       [state + _zuc_lens]{k6}, zmm1

        kmovq   tmp3, k6
        push    tmp3 ;; Save NULL jobs mask
        push    tmp5 ;; Save valid idx

        ; Move state into r11, as register for state will be used
        ; to pass parameter to next function
        mov     r11, state

%ifndef LINUX
        ;; 48 bytes for 6 parameters (already aligned to 16 bytes)
        sub     rsp, 48
%endif
        lea     arg1, [r11 + _zuc_args_keys]
        lea     arg2, [r11 + _zuc_args_IV]
        lea     arg3, [r11 + _zuc_args_in]
        lea     arg4, [r11 + _zuc_args_out]
%ifdef LINUX
        lea     arg5, [r11 + _zuc_lens]
        lea     arg6, [r11 + _zuc_job_in_lane]
%else
        lea     r12, [r11 + _zuc_lens]
        mov     arg5, r12
        lea     r12, [r11 + _zuc_job_in_lane]
        mov     arg6, r12
%endif

        call    ZUC_EIA3_16_BUFFER

%ifndef LINUX
        add     rsp, 48
%endif
        pop     idx ;; Restore valid idx
        pop     tmp3 ;; Restore NULL jobs mask
        kmovq   k6, tmp3
        mov     state, [rsp + _gpr_save + 8*8]

        ;; Clear all lengths on valid jobs and set 0xFFFF to non-valid jobs
        ;; (crypto code above will authenticate all valid buffers)
        vpxor   ymm0, ymm0
        knotw   k6, k6  ;; Non-NULL jobs mask
        vmovdqu16 [state + _zuc_lens]{k6}, ymm0

        vpternlogq ymm0, ymm0, ymm0, 0x0F ;; YMM0 = 0xFF...FF
        knotw    k6, k6 ;; NULL jobs mask
        vmovdqu16 [state + _zuc_lens]{k6}, ymm0

len_is_0_flush_eia3:
        ; process completed job "idx"
        ;; - decrement number of jobs in use
        sub	qword [state + _zuc_lanes_in_use], 1
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], STS_COMPLETED_HMAC
        ;; TODO: fix double store (above setting the length to 0 and now setting to FFFFF)
        mov     word [state + _zuc_lens + idx*2], 0xFFFF
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

return_flush_eia3:

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

        ret

return_null_flush_eia3:
        xor     job_rax, job_rax
        jmp     return_flush_eia3

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
