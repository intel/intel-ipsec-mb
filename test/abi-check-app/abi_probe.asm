;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2026, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; xmm_abi_probe() only makes sense on the Windows x64 ABI, where
;; XMM6-XMM15 are callee-saved. This file is only ever built with
;; -DWIN_ABI (see test/abi-check-app/CMakeLists.txt).
%ifndef WIN_ABI
%error "abi_probe.asm requires WIN_ABI (Windows x64 calling convention)"
%endif

%use smartalign

;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : function or data
;;;  - scope : internal, private, default (ignored in win64 coff format)
%define MKGLOBAL(name,type,scope) global name

section .data
default rel

;; Unique 128-bit sentinel pattern per XMM register, index 0 => XMM6, index 9 => XMM15
align 16
sentinel_tab:
%assign i 6
%rep 10
        dq 0x5a5a5a5a00000000 | i, 0xa5a5a5a500000000 | i
%assign i (i+1)
%endrep

;; Unique 64-bit sentinel pattern per checked GP register, in the order
;; rbx, rbp, rsi, rdi, r12, r13, r14, r15 (matches ABI_PROBE_GP_BIT() order)
align 8
gp_sentinel_tab:
%assign i 0
%rep 8
        dq 0xc3c3c3c300000000 | i
%assign i (i+1)
%endrep

section .text

;; uint32_t xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out)
;;
;; Fills XMM6-XMM15 and the callee-saved general purpose registers
;; (rbx, rbp, rsi, rdi, r12-r15) with sentinel patterns, calls
;; func_ptr(arg1), stores the return value at *ret_out (if not NULL) and
;; returns a bitmask of the registers that did not keep their sentinel
;; value across the call: bit 0 => XMM6, ... bit 9 => XMM15, bit 10 => rbx,
;; bit 11 => rbp, bit 12 => rsi, bit 13 => rdi, bit 14 => r12, bit 15 => r13,
;; bit 16 => r14, bit 17 => r15 (see ABI_PROBE_XMM_BIT()/ABI_PROBE_GP_BIT()).
;;
;; rbx, rbp, rsi, rdi, r12-r15 are filled with sentinels for the whole
;; duration of the call, so func_ptr and its argument are kept in stack
;; slots and func_ptr is invoked with an indirect memory-operand call,
;; leaving every sentinel-holding register untouched by the call setup
;; itself.
;;
;; arg1 (rcx) [in] func_ptr
;; arg2 (rdx) [in] arg1 for func_ptr
;; arg3 (r8)  [in] ret_out
MKGLOBAL(xmm_abi_probe,function,)
align 16
xmm_abi_probe:
        push    rbp
        push    rbx
        push    rsi
        push    rdi
        push    r12
        push    r13
        push    r14
        push    r15
        ;; 32 bytes shadow space + 24 bytes of locals (func_ptr, func_arg,
        ;; ret_out), stack stays 16-byte aligned right before the call
        sub     rsp, 56

        mov     [rsp + 32], rcx  ;; func_ptr
        mov     [rsp + 40], rdx  ;; arg1 for func_ptr
        mov     [rsp + 48], r8   ;; ret_out

        lea     rax, [rel sentinel_tab]
        movdqu  xmm6, [rax + 0*16]
        movdqu  xmm7, [rax + 1*16]
        movdqu  xmm8, [rax + 2*16]
        movdqu  xmm9, [rax + 3*16]
        movdqu  xmm10, [rax + 4*16]
        movdqu  xmm11, [rax + 5*16]
        movdqu  xmm12, [rax + 6*16]
        movdqu  xmm13, [rax + 7*16]
        movdqu  xmm14, [rax + 8*16]
        movdqu  xmm15, [rax + 9*16]

        lea     rax, [rel gp_sentinel_tab]
        mov     rbx, [rax + 0*8]
        mov     rbp, [rax + 1*8]
        mov     rsi, [rax + 2*8]
        mov     rdi, [rax + 3*8]
        mov     r12, [rax + 4*8]
        mov     r13, [rax + 5*8]
        mov     r14, [rax + 6*8]
        mov     r15, [rax + 7*8]

        mov     rcx, [rsp + 40]  ;; arg1 for func_ptr

        call    qword [rsp + 32]

        mov     r10, [rsp + 48]  ;; ret_out (volatile, safe to use post-call)
        test    r10, r10
        jz      .no_ret_out
        mov     [r10], rax
.no_ret_out:

        xor     r9d, r9d        ;; corruption bitmask accumulator
        lea     rax, [rel sentinel_tab]

%assign i 6
%assign bit 0
%rep 10
        movdqu  xmm0, [rax + bit*16]
        pcmpeqb xmm0, xmm %+ i
        pmovmskb r10d, xmm0
        cmp     r10d, 0xffff
        je      .ok %+ bit
        or      r9d, (1 << bit)
.ok %+ bit:
%assign i (i+1)
%assign bit (bit+1)
%endrep

        lea     rax, [rel gp_sentinel_tab]
%assign bit 10
        cmp     rbx, [rax + 0*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:
%assign bit (bit+1)
        cmp     rbp, [rax + 1*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:
%assign bit (bit+1)
        cmp     rsi, [rax + 2*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:
%assign bit (bit+1)
        cmp     rdi, [rax + 3*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:
%assign bit (bit+1)
        cmp     r12, [rax + 4*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:
%assign bit (bit+1)
        cmp     r13, [rax + 5*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:
%assign bit (bit+1)
        cmp     r14, [rax + 6*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:
%assign bit (bit+1)
        cmp     r15, [rax + 7*8]
        je      .gpok %+ bit
        or      r9d, (1 << bit)
.gpok %+ bit:

        mov     eax, r9d

        add     rsp, 56
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbx
        pop     rbp
        ret
