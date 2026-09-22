;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; AES-CBC-128

; arg 1: IN:   pointer to input (cipher text)
; arg 2: IV:   pointer to IV
; arg 3: KEYS: pointer to keys
; arg 4: OUT:  pointer to output (plain text)
; arg 5: LEN:  length in bytes (multiple of 16)

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    rax
%endif

%include "include/aes_cbc_dec_by8_sse.inc"
%include "include/align_sse.inc"

mksection .text

MKGLOBAL(aes_cbc_dec_128_by8_sse,function,internal)
align_function
aes_cbc_dec_128_by8_sse:
%ifndef LINUX
        mov     arg5, [rsp + 5*8]
%endif
        AES_CBC_DEC arg1, arg2, arg3, arg4, arg5, r10, 9
        ret

mksection stack-noexec
