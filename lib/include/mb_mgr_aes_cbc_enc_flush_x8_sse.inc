;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/align_sse.inc"

%include "include/reg_sizes.inc"

;; NUM_LANES, AES_CBC_ENC_X8 and FLUSH_JOB_AES_ENC must be set by the includer

; void AES_CBC_ENC_X8(AES_ARGS *args, UINT64 len_in_bytes);
extern AES_CBC_ENC_X8

mksection .rodata
default rel

align 16
len_masks:
        dq 0x000000000000FFFF, 0x0000000000000000
        dq 0x00000000FFFF0000, 0x0000000000000000
        dq 0x0000FFFF00000000, 0x0000000000000000
        dq 0xFFFF000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0x000000000000FFFF
        dq 0x0000000000000000, 0x00000000FFFF0000
        dq 0x0000000000000000, 0x0000FFFF00000000
        dq 0x0000000000000000, 0xFFFF000000000000

align 16
dupw:
        dq 0x0100010001000100, 0x0100010001000100

one:    dq  1
two:    dq  2
three:  dq  3
four:   dq  4
five:   dq  5
six:    dq  6
seven:  dq  7

mksection .text

%define APPEND(a,b) a %+ b

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

%define unused_lanes     rbx
%define tmp1             rbx

%define good_lane        rdx
%define iv               rdx

%define tmp2             rax

; idx needs to be in rbp
%define tmp              rbp
%define idx              rbp

%define tmp3             r8

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    8
%ifndef LINUX
_xmm_save:      resq    20      ; xmm6-xmm15, Windows only
%endif
_rsp_save:      resq    1
endstruc

; JOB* FLUSH_JOB_AES_ENC(MB_MGR_AES_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(FLUSH_JOB_AES_ENC,function,internal)
align_function
FLUSH_JOB_AES_ENC:
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

        ; check for empty
        mov     unused_lanes, [state + _aes_unused_lanes]
        bt      unused_lanes, ((NUM_LANES * 4) + 3)
        jc      return_null

        ; find a lane with a non-null job
        xor     good_lane, good_lane
        cmp     qword [state + _aes_job_in_lane + 1*8], 0
        cmovne  good_lane, [rel one]
        cmp     qword [state + _aes_job_in_lane + 2*8], 0
        cmovne  good_lane, [rel two]
        cmp     qword [state + _aes_job_in_lane + 3*8], 0
        cmovne  good_lane, [rel three]
        cmp     qword [state + _aes_job_in_lane + 4*8], 0
        cmovne  good_lane, [rel four]
        cmp     qword [state + _aes_job_in_lane + 5*8], 0
        cmovne  good_lane, [rel five]
        cmp     qword [state + _aes_job_in_lane + 6*8], 0
        cmovne  good_lane, [rel six]
        cmp     qword [state + _aes_job_in_lane + 7*8], 0
        cmovne  good_lane, [rel seven]

        ; copy good_lane to empty lanes
        mov     tmp1, [state + _aes_args_in + good_lane*8]
        mov     tmp2, [state + _aes_args_out + good_lane*8]
        mov     tmp3, [state + _aes_args_keys + good_lane*8]
        shl     good_lane, 4 ; multiply by 16
        movdqa  xmm2, [state + _aes_args_IV + good_lane]
        movdqa  xmm0, [state + _aes_lens]

%assign I 0
%rep NUM_LANES
        cmp     qword [state + _aes_job_in_lane + I*8], 0
        jne     APPEND(skip_,I)
        mov     [state + _aes_args_in + I*8], tmp1
        mov     [state + _aes_args_out + I*8], tmp2
        mov     [state + _aes_args_keys + I*8], tmp3
        movdqa  [state + _aes_args_IV + I*16], xmm2
        por     xmm0, [rel len_masks + 16*I]
APPEND(skip_,I):
%assign I (I+1)
%endrep

        ; Find min length
        phminposuw      xmm1, xmm0
        pextrw  len2, xmm1, 0   ; min value
        pextrw  idx, xmm1, 1    ; min index (0...3)
        or      len2, len2
        jz      len_is_0

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
        ;; Clear IVs of returned job and "NULL lanes"
        pxor    xmm0, xmm0
%assign I 0
%rep NUM_LANES
        cmp     qword [state + _aes_job_in_lane + I*8], 0
        jne     APPEND(skip_clear_,I)
        movdqa  [state + _aes_args_IV + I*16], xmm0
APPEND(skip_clear_,I):
%assign I (I+1)
%endrep
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
