;;
;; Copyright (c) 2012-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/align_sse.inc"

%ifndef AES_XCBC_X4
%define AES_XCBC_X4 aes_xcbc_mac_128_x4
%define FLUSH_JOB_AES_XCBC flush_job_aes_xcbc_sse
%endif

; void AES_XCBC_X4(AES_XCBC_ARGS_x16 *args, UINT64 len_in_bytes);
extern AES_XCBC_X4

mksection .rodata
default rel

align 16
len_masks:
        ;ddq 0x0000000000000000000000000000FFFF
        dq 0x000000000000FFFF, 0x0000000000000000
        ;ddq 0x000000000000000000000000FFFF0000
        dq 0x00000000FFFF0000, 0x0000000000000000
        ;ddq 0x00000000000000000000FFFF00000000
        dq 0x0000FFFF00000000, 0x0000000000000000
        ;ddq 0x0000000000000000FFFF000000000000
        dq 0xFFFF000000000000, 0x0000000000000000
one:    dq  1
two:    dq  2
three:  dq  3

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

%if 1
%define unused_lanes     rbx
%define tmp1             rbx

%define icv              rdx

%define tmp2             rax

; idx needs to be in rbp
%define tmp              r10
%define idx              rbp

%define tmp3             r8
%define lane_data        r9
%endif

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    8
%ifndef LINUX
_xmm_save:      resq    20      ; xmm6-xmm15, Windows only
%endif
_rsp_save:      resq    1
endstruc

; JOB* FLUSH_JOB_AES_XCBC(MB_MGR_AES_XCBC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(FLUSH_JOB_AES_XCBC,function,internal)
align_function
FLUSH_JOB_AES_XCBC:

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

        ;; Windows x64 ABI: xmm6-xmm15 are callee-saved; AES_XCBC_X4
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
        mov     unused_lanes, [state + _aes_xcbc_unused_lanes]
        bt      unused_lanes, 32+7
        jc      return_null

        ; find a lane with a non-null job
        xor     idx, idx
        cmp     qword [state + _aes_xcbc_ldata + 1 * _XCBC_LANE_DATA_size + _xcbc_job_in_lane], 0
        cmovne  idx, [rel one]
        cmp     qword [state + _aes_xcbc_ldata + 2 * _XCBC_LANE_DATA_size + _xcbc_job_in_lane], 0
        cmovne  idx, [rel two]
        cmp     qword [state + _aes_xcbc_ldata + 3 * _XCBC_LANE_DATA_size + _xcbc_job_in_lane], 0
        cmovne  idx, [rel three]

align_loop
copy_lane_data:
        ; copy idx to empty lanes
        mov     tmp1, [state + _aes_xcbc_args_in + idx*8]
        mov     tmp3, [state + _aes_xcbc_args_keys + idx*8]
        shl     idx, 4 ; multiply by 16
        movdqa  xmm2, [state + _aes_xcbc_args_ICV + idx]
        movdqa  xmm0, [state + _aes_xcbc_lens]

%assign I 0
%rep 4
        cmp     qword [state + _aes_xcbc_ldata + I * _XCBC_LANE_DATA_size + _xcbc_job_in_lane], 0
        jne     APPEND(skip_,I)
        mov     [state + _aes_xcbc_args_in + I*8], tmp1
        mov     [state + _aes_xcbc_args_keys + I*8], tmp3
        movdqa  [state + _aes_xcbc_args_ICV + I*16], xmm2
        por     xmm0, [rel len_masks + 16*I]
APPEND(skip_,I):
%assign I (I+1)
%endrep

        movdqa  [state + _aes_xcbc_lens], xmm0

        ; Find min length
        phminposuw      xmm1, xmm0
        pextrw  len2, xmm1, 0   ; min value
        pextrw  idx, xmm1, 1    ; min index (0...3)
        cmp     len2, 0
        je      len_is_0

        pshuflw xmm1, xmm1, 0
        psubw   xmm0, xmm1
        movdqa  [state + _aes_xcbc_lens], xmm0

        ; "state" and "args" are the same address, arg1
        ; len is arg2
        call    AES_XCBC_X4
        ; state and idx are intact

align_label
len_is_0:
        ; process completed job "idx"
        imul    lane_data, idx, _XCBC_LANE_DATA_size
        lea     lane_data, [state + _aes_xcbc_ldata + lane_data]
        cmp     dword [lane_data + _xcbc_final_done], 0
        jne     end_loop

        mov     dword [lane_data + _xcbc_final_done], 1
        mov     word [state + _aes_xcbc_lens + 2*idx], 16
        lea     tmp, [lane_data + _xcbc_final_block]
        mov     [state + _aes_xcbc_args_in + 8*idx], tmp
        jmp     copy_lane_data

align_label
end_loop:
        mov     job_rax, [lane_data + _xcbc_job_in_lane]
        mov     icv,  [job_rax + _auth_tag_output]
        mov     unused_lanes, [state + _aes_xcbc_unused_lanes]
        mov     qword [lane_data + _xcbc_job_in_lane], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        shl     unused_lanes, 8
        or      unused_lanes, idx
        shl     idx, 4 ; multiply by 16
        mov     [state + _aes_xcbc_unused_lanes], unused_lanes

        ; copy 12 bytes
        movdqa  xmm0, [state + _aes_xcbc_args_ICV + idx]
        movq    [icv], xmm0
        pextrd  [icv + 8], xmm0, 2

%ifdef SAFE_DATA
        pxor    xmm0, xmm0

        ;; Clear ICV's and final blocks in returned job and NULL lanes
%assign I 0
%rep 4
        cmp     qword [state + _aes_xcbc_ldata + I * _XCBC_LANE_DATA_size + _xcbc_job_in_lane], 0
        jne     APPEND(skip_clear_,I)
        movdqa  [state + _aes_xcbc_args_ICV + I*16], xmm0
        lea     lane_data, [state + _aes_xcbc_ldata + (I * _XCBC_LANE_DATA_size)]
        movdqa  [lane_data + _xcbc_final_block], xmm0
        movdqa  [lane_data + _xcbc_final_block + 16], xmm0
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
