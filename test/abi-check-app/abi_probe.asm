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

;; Unique 128-bit sentinel pattern per register, index 0 => XMM6, index 9 => XMM15
align 16
sentinel_tab:
%assign i 6
%rep 10
        dq 0x5a5a5a5a00000000 | i, 0xa5a5a5a500000000 | i
%assign i (i+1)
%endrep

section .text

;; uint32_t xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out)
;;
;; Fills XMM6-XMM15 with the sentinel patterns from sentinel_tab, calls
;; func_ptr(arg1), stores the return value at *ret_out (if not NULL) and
;; returns a bitmask of the XMM6-XMM15 registers that did not keep their
;; sentinel value across the call (bit 0 => XMM6, ... bit 9 => XMM15).
;;
;; arg1 (rcx) [in] func_ptr
;; arg2 (rdx) [in] arg1 for func_ptr
;; arg3 (r8)  [in] ret_out
MKGLOBAL(xmm_abi_probe,function,)
align 16
xmm_abi_probe:
        push    rbx
        push    rsi
        ;; 32 bytes shadow space for the call below, stack stays 16-byte
        ;; aligned right before the "call rbx" instruction
        sub     rsp, 40

        mov     rbx, rcx        ;; rbx = func_ptr
        mov     rsi, r8         ;; rsi = ret_out

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

        mov     rcx, rdx        ;; arg1 for func_ptr

        call    rbx

        test    rsi, rsi
        jz      .no_ret_out
        mov     [rsi], rax
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

        mov     eax, r9d

        add     rsp, 40
        pop     rsi
        pop     rbx
        ret
