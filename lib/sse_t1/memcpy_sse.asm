;;
;; Copyright (c) 2020-2026, Intel Corporation
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
        or      arg3, arg3
        jz      .end

align_loop
.loop16:
        cmp     arg3, 16
        jb      .check8
        movdqu  xmm0, [arg2]
        movdqu  [arg1], xmm0
        add     arg1, 16
        add     arg2, 16
        sub     arg3, 16
        jz      .end
        jmp     .loop16

align_label
.check8:
        cmp     arg3, 8
        jb      .check4
        mov     rax, [arg2]
        mov     [arg1], rax
        add     arg1, 8
        add     arg2, 8
        sub     arg3, 8
        jz      .end

align_label
.check4:
        cmp     arg3, 4
        jb      .loop1
        mov     eax, [arg2]
        mov     [arg1], eax
        add     arg1, 4
        add     arg2, 4
        sub     arg3, 4
        jz      .end

align_loop
.loop1:
        mov     al, [arg2]
        mov     [arg1], al
        add     arg1, 1
        add     arg2, 1
        sub     arg3, 1
        jnz     .loop1

align_label
.end:
        pxor    xmm0, xmm0
        xor     rax, rax
        ret

mksection stack-noexec
