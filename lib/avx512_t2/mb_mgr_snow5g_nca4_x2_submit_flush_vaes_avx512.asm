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

mksection .text
default rel

extern snow5g_nca4_x2_job_vaes_avx512

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

; This routine and its callee clobbers all GPRs
struc STACK_NCA4
_gpr_save_nca4:      resq    10
%ifndef LINUX
_xmm_save_nca4:      resb    (16 * 10)       ; XMM6-15 save area (Windows only)
%endif
_rsp_save_nca4:      resq    1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Saves register contents and creates stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_NCA4_size
        and     rsp, -16

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
        ;; Restore XMM6-15 (Windows callee-saved)
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
;; Calls NCA4 2-buffer processing function
;; %1 = decrypt flag (0 = encrypt, 1 = decrypt)
;; %2 = state pointer
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro CALL_NCA4_2_BUFFER 2
        RESERVE_STACK_SPACE 6

        lea     arg2, [%2 + _snow5g_args_IV]
        lea     arg3, [%2 + _snow5g_args_in]
        lea     arg4, [%2 + _snow5g_args_out]
        ;; arg5 is a stack slot on Windows — lea needs a register destination
        lea     r12, [%2 + _snow5g_job_in_lane]
        mov     arg5, r12
        mov     arg6, %1
        lea     arg1, [%2 + _snow5g_args_keys]

        call    snow5g_nca4_x2_job_vaes_avx512

        RESTORE_STACK_SPACE 6
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Submits a job to the 2-buffer SNOW5G-NCA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SUBMIT_JOB_SNOW5G_NCA4_ENC_X2 1

%define lane             r8
%define tmp              r15
%define tmp2             r13

        SNOW5G_NCA4_FUNC_START

        ;; Lane index = current lanes in use (0 or 1)
        mov     lane, [state + _snow5g_lanes_in_use]
        add     qword [state + _snow5g_lanes_in_use], 1

        ;; Store job pointer in lane
        mov     [state + _snow5g_job_in_lane + lane*8], job

        ;; Copy job data into lane arrays
        mov     tmp, [job + _src]
        add     tmp, [job + _cipher_start_src_offset_in_bytes]
        mov     [state + _snow5g_args_in + lane*8], tmp

        ;; Store output pointer
        mov     tmp, [job + _dst]
        mov     [state + _snow5g_args_out + lane*8], tmp

        ;; Store key pointer
        mov     tmp, [job + _enc_keys]
        mov     [state + _snow5g_args_keys + lane*8], tmp

        ;; Copy IV to state array (16 bytes per lane)
        mov     tmp, [job + _iv]
        lea     tmp2, [lane*8]
        vmovdqu xmm0, [tmp]
        vmovdqu [state + _snow5g_args_IV + tmp2*2], xmm0

        ;; Check if all 2 lanes are full
        cmp     qword [state + _snow5g_lanes_in_use], 2
        jne     %%return_null_submit_nca4

        ;; Both lanes full - process them
        CALL_NCA4_2_BUFFER %1, state

        mov     state, [rsp + _gpr_save_nca4 + 8*8]

        ;; Complete both jobs and reset state
        mov     job_rax, [state + _snow5g_job_in_lane]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        mov     job_rax, [state + _snow5g_job_in_lane + 8]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        xor     tmp, tmp
        mov     [state + _snow5g_job_in_lane], tmp
        mov     [state + _snow5g_job_in_lane + 8], tmp
        mov     [state + _snow5g_lanes_in_use], tmp

        jmp     %%exit_submit

align_label
%%return_null_submit_nca4:
        xor     job_rax, job_rax

align_label
%%exit_submit:
        SNOW5G_NCA4_FUNC_END
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Flushes completed jobs from the 2-buffer SNOW5G-NCA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro FLUSH_JOB_SNOW5G_NCA4_ENC_X2 1

        SNOW5G_NCA4_FUNC_START

        ;; Check for empty
        cmp     qword [state + _snow5g_lanes_in_use], 0
        jz      %%return_null_flush_nca4

        ;; With 2 lanes, flush always has lane 0 valid, lane 1 null.
        ;; Fill lane 1 from lane 0.
        mov             r11, [state + _snow5g_args_in]
        mov             [state + _snow5g_args_in + 8], r11

        mov             r11, [state + _snow5g_args_out]
        mov             [state + _snow5g_args_out + 8], r11

        mov             r11, [state + _snow5g_args_keys]
        mov             [state + _snow5g_args_keys + 8], r11

        vmovdqa64       xmm0, [state + _snow5g_args_IV]
        vmovdqa64       [state + _snow5g_args_IV + 16], xmm0

        CALL_NCA4_2_BUFFER %1, state

        mov     state, [rsp + _gpr_save_nca4 + 8*8]

        ;; Complete lane 0 job and reset state
        mov     job_rax, [state + _snow5g_job_in_lane]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        mov     qword [state + _snow5g_job_in_lane], 0
        mov     qword [state + _snow5g_lanes_in_use], 0

        jmp     %%exit_flush

align_label
%%return_null_flush_nca4:
        xor     job_rax, job_rax

align_label
%%exit_flush:
        SNOW5G_NCA4_FUNC_END
%endmacro

;; submit_job_snow5g_nca4_enc_vaes_avx512(state, job) - encrypt queue
MKGLOBAL(submit_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_enc_vaes_avx512:
        endbranch64
        SUBMIT_JOB_SNOW5G_NCA4_ENC_X2 0
        ret

;; flush_job_snow5g_nca4_enc_vaes_avx512(state) - encrypt queue
MKGLOBAL(flush_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_enc_vaes_avx512:
        endbranch64
        FLUSH_JOB_SNOW5G_NCA4_ENC_X2 0
        ret

;; submit_job_snow5g_nca4_dec_vaes_avx512(state, job) - decrypt queue
MKGLOBAL(submit_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_dec_vaes_avx512:
        endbranch64
        SUBMIT_JOB_SNOW5G_NCA4_ENC_X2 1
        ret

;; flush_job_snow5g_nca4_dec_vaes_avx512(state) - decrypt queue
MKGLOBAL(flush_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_dec_vaes_avx512:
        endbranch64
        FLUSH_JOB_SNOW5G_NCA4_ENC_X2 1
        ret

mksection stack-noexec
