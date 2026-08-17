;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/memcpy.inc"
%include "include/align_sse.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%endif

mksection .text

; void memcpy_fn_sse_16(void *dst, const void *src, const size_t size)
MKGLOBAL(memcpy_fn_sse_16,function,internal)
align_function
memcpy_fn_sse_16:
        memcpy_sse_16 arg1, arg2, arg3, r10, r11

        ret

MKGLOBAL(memcpy_fn_sse_128,function,internal)
align_function
memcpy_fn_sse_128:
        movdqu  xmm0, [arg2]
        movdqu  xmm1, [arg2 + 16]
        movdqu  xmm2, [arg2 + 16*2]
        movdqu  xmm3, [arg2 + 16*3]
        movdqu  [arg1], xmm0
        movdqu  [arg1 + 16], xmm1
        movdqu  [arg1 + 16*2], xmm2
        movdqu  [arg1 + 16*3], xmm3
        movdqu  xmm0, [arg2 + 16*4]
        movdqu  xmm1, [arg2 + 16*5]
        movdqu  xmm2, [arg2 + 16*6]
        movdqu  xmm3, [arg2 + 16*7]
        movdqu  [arg1 + 16*4], xmm0
        movdqu  [arg1 + 16*5], xmm1
        movdqu  [arg1 + 16*6], xmm2
        movdqu  [arg1 + 16*7], xmm3

        ret

MKGLOBAL(safe_memcpy,function,internal)
align_function
safe_memcpy:
%ifndef LINUX
        ;; save rdi and rsi
        mov     rax, rdi
        mov     r9,  rsi

        mov     rdi, arg1
        mov     rsi, arg2
%endif
        mov     rcx, arg3
        rep     movsb

%ifndef LINUX
        ;; restore rdi and rsi
        mov     rdi, rax
        mov     rsi, r9
%endif
        ret

mksection stack-noexec
