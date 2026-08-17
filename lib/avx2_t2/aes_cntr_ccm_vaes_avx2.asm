;;
;; Copyright (c) 2025, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%use smartalign
; %define AES_CTR_DECLARE_DATA 1
%define CNTR_CCM_AVX2 1

%include "include/aes_cntr_by16_vaes_avx2.inc"
%include "include/align_avx.inc"

%include "include/cet.inc"

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    6
_rsp_save:      resq    1
endstruc

;; Save registers states
%macro FUNC_SAVE 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -32

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*4], rsi
        mov     [rsp + _gpr_save + 8*5], rdi
%endif
        mov     [rsp + _rsp_save], rax  ; original SP
%endmacro

;; Restore registers states
%macro FUNC_RESTORE 0
        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*4]
        mov     rdi, [rsp + _gpr_save + 8*5]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

align_function
; IMB_JOB * aes_cntr_ccm_128_vaes_avx2(IMB_JOB *job)
; arg 1 : job
MKGLOBAL(aes_cntr_ccm_128_vaes_avx2,function,internal)
aes_cntr_ccm_128_vaes_avx2:
        endbranch64
        FUNC_SAVE
        DO_CNTR 128, CCM
        FUNC_RESTORE
        ret

align_function
; IMB_JOB * aes_cntr_ccm_256_vaes_avx2(IMB_JOB *job)
; arg 1 : job
MKGLOBAL(aes_cntr_ccm_256_vaes_avx2,function,internal)
aes_cntr_ccm_256_vaes_avx2:
        endbranch64
        FUNC_SAVE
        DO_CNTR 256, CCM
        FUNC_RESTORE
        ret

mksection stack-noexec
