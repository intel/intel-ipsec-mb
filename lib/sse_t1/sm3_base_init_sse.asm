;;
;; Copyright (c) 2023-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash

%include "include/os.inc"
%include "include/align_sse.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%endif

mksection .rodata
default rel

align 16
I_const:
        dd 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600
        dd 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sm3_base_init(uint32_t digest[8])
align_function
MKGLOBAL(sm3_base_init,function,internal)
align_function
sm3_base_init:
        movdqu  xmm0, [rel I_const + 0*16]
        movdqu  xmm1, [rel I_const + 1*16]
        movdqu  [arg1 + 0*16], xmm0
        movdqu  [arg1 + 1*16], xmm1
        ret


mksection stack-noexec
