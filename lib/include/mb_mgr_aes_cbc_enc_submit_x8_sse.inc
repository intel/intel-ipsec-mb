;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"

%include "include/reg_sizes.inc"
%include "include/const.inc"
%include "include/align_sse.inc"

;; AES_CBC_ENC_X8 and SUBMIT_JOB_AES_ENC must be set by the includer

; void AES_CBC_ENC_X8(AES_ARGS *args, UINT64 len_in_bytes);
extern AES_CBC_ENC_X8

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%else
%define arg1    rcx
%define arg2    rdx
%endif

%define state   arg1
%define job     arg2
%define len2    arg2

%define job_rax          rax

; idx needs to be in rbp
%define len              rbp
%define idx              rbp
%define tmp              rbp

%define lane             r8

%define iv               r9

%define unused_lanes     rbx
; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    8
%ifndef LINUX
_xmm_save:      resq    20      ; xmm6-xmm15, Windows only
%endif
_rsp_save:      resq    1
endstruc

mksection .rodata
default rel

align 16
dupw:
        dq 0x0100010001000100, 0x0100010001000100

mksection .text

; JOB* SUBMIT_JOB_AES_ENC(MB_MGR_AES_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_AES_ENC,function,internal)
align_function
SUBMIT_JOB_AES_ENC:
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
        ;; Windows x64 ABI: xmm6-xmm15 are callee-saved; AES_CBC_ENC_X8
        ;; clobbers them, so save/restore locally around this function
        movdqa  [rsp + _xmm_save + 16*0], xmm6
        movdqa  [rsp + _xmm_save + 16*1], xmm7
        movdqa  [rsp + _xmm_save + 16*2], xmm8
        movdqa  [rsp + _xmm_save + 16*3], xmm9
        movdqa  [rsp + _xmm_save + 16*4], xmm10
        movdqa  [rsp + _xmm_save + 16*5], xmm11
        movdqa  [rsp + _xmm_save + 16*6], xmm12
        movdqa  [rsp + _xmm_save + 16*7], xmm13
        movdqa  [rsp + _xmm_save + 16*8], xmm14
        movdqa  [rsp + _xmm_save + 16*9], xmm15
%endif
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _aes_unused_lanes]
        mov     lane, unused_lanes
        and     lane, 0xf
        shr     unused_lanes, 4
        mov     iv, [job + _iv]
        mov     [state + _aes_unused_lanes], unused_lanes

        mov     [state + _aes_job_in_lane + lane*8], job
        mov     tmp, [job + _src]
        add     tmp, [job + _cipher_start_src_offset_in_bytes]
        movdqu  xmm0, [iv]
        mov     [state + _aes_args_in + lane*8], tmp
        mov     tmp, [job + _enc_keys]
        mov     [state + _aes_args_keys + lane*8], tmp
        mov     tmp, [job + _dst]
        mov     [state + _aes_args_out + lane*8], tmp
        shl     lane, 4 ; multiply by 16
        movdqa  [state + _aes_args_IV + lane], xmm0

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_cipher_in_bytes]
        and     len, -16        ; DOCSIS may pass size unaligned to block size

        movdqa  xmm0, [state + _aes_lens]
        XPINSRW xmm0, xmm1, tmp, lane, len, no_scale
        movdqa  [state + _aes_lens], xmm0

        cmp     unused_lanes, 0xf
        jne     return_null

        ; Find min length
        phminposuw      xmm1, xmm0
        pextrw  len2, xmm1, 0   ; min value
        pextrw  idx, xmm1, 1    ; min index (0...3)
        cmp     len2, 0
        je      len_is_0

        pshufb  xmm1, [rel dupw]   ; duplicate words across all lanes
        psubw   xmm0, xmm1
        movdqa  [state + _aes_lens], xmm0

        ; "state" and "args" are the same address, arg1
        ; len is arg2
        call    AES_CBC_ENC_X8
        ; state and idx are intact

align_label
len_is_0:
        ; process completed job "idx"
        mov     job_rax, [state + _aes_job_in_lane + idx*8]
        mov     unused_lanes, [state + _aes_unused_lanes]
        mov     qword [state + _aes_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _aes_unused_lanes], unused_lanes
%ifdef SAFE_DATA
        ;; Clear IV
        pxor    xmm0, xmm0
        shl     idx, 3 ; multiply by 8
        movdqa  [state + _aes_args_IV + idx*2], xmm0
        mov     qword [state + _aes_args_keys + idx], 0
%endif

align_label
return:
        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
        movdqa  xmm6,  [rsp + _xmm_save + 16*0]
        movdqa  xmm7,  [rsp + _xmm_save + 16*1]
        movdqa  xmm8,  [rsp + _xmm_save + 16*2]
        movdqa  xmm9,  [rsp + _xmm_save + 16*3]
        movdqa  xmm10, [rsp + _xmm_save + 16*4]
        movdqa  xmm11, [rsp + _xmm_save + 16*5]
        movdqa  xmm12, [rsp + _xmm_save + 16*6]
        movdqa  xmm13, [rsp + _xmm_save + 16*7]
        movdqa  xmm14, [rsp + _xmm_save + 16*8]
        movdqa  xmm15, [rsp + _xmm_save + 16*9]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        ret

align_label
return_null:
        xor     job_rax, job_rax
        jmp     return

mksection stack-noexec
