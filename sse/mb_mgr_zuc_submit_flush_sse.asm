;;
;; Copyright (c) 2019, Intel Corporation
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
%include "job_aes_hmac.asm"
%include "mb_mgr_datastruct.asm"

%include "include/reg_sizes.asm"
%include "include/const.inc"

%define SUBMIT_JOB_ZUC_EEA3 submit_job_zuc_eea3_sse
%define FLUSH_JOB_ZUC_EEA3 flush_job_zuc_eea3_sse
%define SUBMIT_JOB_ZUC_EIA3 submit_job_zuc_eia3_sse
%define FLUSH_JOB_ZUC_EIA3 flush_job_zuc_eia3_sse

section .data
default rel

align 16
one:    dq  1
two:    dq  2
three:  dq  3

extern zuc_eea3_4_buffer_job_sse
extern zuc_eia3_4_buffer_job_sse

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

; JOB* SUBMIT_JOB_ZUC_EEA3(MB_MGR_ZUC_OOO *state, JOB_AES_HMAC *job)
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
        movzx   lane, BYTE(unused_lanes)
        shr     unused_lanes, 8
        mov     tmp, [job + _iv]
        mov     [state + _zuc_args_IV + lane*8], tmp
        mov     [state + _zuc_unused_lanes], unused_lanes

        mov     [state + _zuc_job_in_lane + lane*8], job
        mov     tmp, [job + _src]
        add     tmp, [job + _cipher_start_src_offset_in_bytes]
        mov     [state + _zuc_args_in + lane*8], tmp
        mov     tmp, [job + _aes_enc_key_expanded]
        mov     [state + _zuc_args_keys + lane*8], tmp
        mov     tmp, [job + _dst]
        mov     [state + _zuc_args_out + lane*8], tmp

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_cipher_in_bytes]

        movdqa  xmm0, [state + _zuc_lens]
        XPINSRW xmm0, xmm1, tmp, lane, len, scale_x16
        movdqa  [state + _zuc_lens], xmm0

        cmp     unused_lanes, 0xff
        jne     return_null_submit_eea3

        ; Find minimum length (searching for zero length,
        ; to retrieve already encrypted buffers)
        phminposuw      xmm1, xmm0
        pextrw  len2, xmm1, 0   ; min value
        pextrw  idx, xmm1, 1    ; min index (0...3)
        cmp     len2, 0
        je      len_is_0_submit_eea3

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

        call    zuc_eea3_4_buffer_job_sse

%ifndef LINUX
        add     rsp, 48
%endif
        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

        ;; Clear all lengths (function will encrypt whole buffers)
        mov     qword [state + _zuc_lens], 0

len_is_0_submit_eea3:
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], STS_COMPLETED_AES
        shl     unused_lanes, 8
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

%define good_lane        rdx

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
        mov     unused_lanes, [state + _zuc_unused_lanes]
        bt      unused_lanes, 32+7
        jc      return_null_flush_eea3

        ; find a lane with a non-null job
        xor     good_lane, good_lane
        cmp     qword [state + _zuc_job_in_lane + 1*8], 0
        cmovne  good_lane, [rel one]
        cmp     qword [state + _zuc_job_in_lane + 2*8], 0
        cmovne  good_lane, [rel two]
        cmp     qword [state + _zuc_job_in_lane + 3*8], 0
        cmovne  good_lane, [rel three]

        ; copy good_lane to empty lanes
        mov     tmp1, [state + _zuc_args_in + good_lane*8]
        mov     tmp2, [state + _zuc_args_out + good_lane*8]
        mov     tmp3, [state + _zuc_args_keys + good_lane*8]
        mov     tmp4, [state + _zuc_args_IV + good_lane*8]
        mov     WORD(tmp5), [state + _zuc_lens + good_lane*2]

%assign I 0
%rep 4
        cmp     qword [state + _zuc_job_in_lane + I*8], 0
        jne     APPEND(skip_eea3_,I)
        mov     [state + _zuc_args_in + I*8], tmp1
        mov     [state + _zuc_args_out + I*8], tmp2
        mov     [state + _zuc_args_keys + I*8], tmp3
        mov     [state + _zuc_args_IV + I*8], tmp4
        mov     [state + _zuc_lens + I*2], WORD(tmp5)
APPEND(skip_eea3_,I):
%assign I (I+1)
%endrep

        mov     idx, good_lane
        cmp     WORD(tmp5), 0
        je      len_is_0_flush_eea3

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

        call    zuc_eea3_4_buffer_job_sse

%ifndef LINUX
        add     rsp, 48
%endif
        mov     state, [rsp + _gpr_save + 8*8]

        ;; Clear all lengths (function will encrypt whole buffers)
        mov     qword [state + _zuc_lens], 0

len_is_0_flush_eea3:
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], STS_COMPLETED_AES
        shl     unused_lanes, 8
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

; JOB* SUBMIT_JOB_ZUC_EIA3(MB_MGR_ZUC_OOO *state, JOB_AES_HMAC *job)
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
        movzx   lane, BYTE(unused_lanes)
        shr     unused_lanes, 8
        mov     tmp, [job + _zuc_eia3_iv]
        mov     [state + _zuc_args_IV + lane*8], tmp
        mov     [state + _zuc_unused_lanes], unused_lanes

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

        movdqa  xmm0, [state + _zuc_lens]
        XPINSRW xmm0, xmm1, tmp, lane, len, scale_x16
        movdqa  [state + _zuc_lens], xmm0

        cmp     unused_lanes, 0xff
        jne     return_null_submit_eia3

        ; Find minimum length (searching for zero length,
        ; to retrieve already encrypted buffers)
        phminposuw      xmm1, xmm0
        pextrw  len2, xmm1, 0   ; min value
        pextrw  idx, xmm1, 1    ; min index (0...3)
        cmp     len2, 0
        je      len_is_0_submit_eia3

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

        call    zuc_eia3_4_buffer_job_sse

%ifndef LINUX
        add     rsp, 48
%endif
        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

        ;; Clear all lengths (function will authenticate all buffers)
        mov     qword [state + _zuc_lens], 0

len_is_0_submit_eia3:
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], STS_COMPLETED_HMAC
        shl     unused_lanes, 8
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

; JOB* FLUSH_JOB_ZUC_EEA3(MB_MGR_ZUC_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_ZUC_EIA3,function,internal)
FLUSH_JOB_ZUC_EIA3:

%define unused_lanes     rbx
%define tmp1             rbx

%define good_lane        rdx

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
        mov     unused_lanes, [state + _zuc_unused_lanes]
        bt      unused_lanes, 32+7
        jc      return_null_flush_eia3

        ; find a lane with a non-null job
        xor     good_lane, good_lane
        cmp     qword [state + _zuc_job_in_lane + 1*8], 0
        cmovne  good_lane, [rel one]
        cmp     qword [state + _zuc_job_in_lane + 2*8], 0
        cmovne  good_lane, [rel two]
        cmp     qword [state + _zuc_job_in_lane + 3*8], 0
        cmovne  good_lane, [rel three]

        ; copy good_lane to empty lanes
        mov     tmp1, [state + _zuc_args_in + good_lane*8]
        mov     tmp2, [state + _zuc_args_out + good_lane*8]
        mov     tmp3, [state + _zuc_args_keys + good_lane*8]
        mov     tmp4, [state + _zuc_args_IV + good_lane*8]
        mov     WORD(tmp5), [state + _zuc_lens + good_lane*2]

%assign I 0
%rep 4
        cmp     qword [state + _zuc_job_in_lane + I*8], 0
        jne     APPEND(skip_eia3_,I)
        mov     [state + _zuc_args_in + I*8], tmp1
        mov     [state + _zuc_args_out + I*8], tmp2
        mov     [state + _zuc_args_keys + I*8], tmp3
        mov     [state + _zuc_args_IV + I*8], tmp4
        mov     [state + _zuc_lens + I*2], WORD(tmp5)
APPEND(skip_eia3_,I):
%assign I (I+1)
%endrep

        mov     idx, good_lane
        cmp     WORD(tmp5), 0
        je      len_is_0_flush_eia3

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

        call    zuc_eia3_4_buffer_job_sse

%ifndef LINUX
        add     rsp, 48
%endif
        mov     state, [rsp + _gpr_save + 8*8]

        ;; Clear all lengths (function will authenticate all buffers)
        mov     qword [state + _zuc_lens], 0

len_is_0_flush_eia3:
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], STS_COMPLETED_HMAC
        shl     unused_lanes, 8
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
