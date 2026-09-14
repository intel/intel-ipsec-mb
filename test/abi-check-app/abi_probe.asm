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

;; read-only data, mapped to the COFF .rdata section on Windows
section .rdata
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

;; uint32_t xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out,
;;                        int check_vzeroupper)
;;
;; Fills XMM6-XMM15 and the callee-saved general purpose registers
;; (rbx, rbp, rsi, rdi, r12-r15) with sentinel patterns, calls
;; func_ptr(arg1), stores the return value at *ret_out (if not NULL) and
;; returns a bitmask of the registers that did not keep their sentinel
;; value across the call: bit 0 => XMM6, ... bit 9 => XMM15, bit 10 => rbx,
;; bit 11 => rbp, bit 12 => rsi, bit 13 => rdi, bit 14 => r12, bit 15 => r13,
;; bit 16 => r14, bit 17 => r15 (see ABI_PROBE_XMM_BIT()/ABI_PROBE_GP_BIT()).
;;
;; The original caller-side values of XMM6-XMM15 are saved before the
;; sentinels are loaded and restored before returning, so this probe itself
;; behaves as a proper Windows x64 callee and does not corrupt the caller's
;; (compiler-managed) XMM state - it only observes what func_ptr() does to
;; the sentinel values in between.
;;
;; rbx, rbp, rsi, rdi, r12-r15 are filled with sentinels for the whole
;; duration of the call, so func_ptr and its argument are kept in stack
;; slots and func_ptr is invoked with an indirect memory-operand call,
;; leaving every sentinel-holding register untouched by the call setup
;; itself.
;;
;; When check_vzeroupper is non-zero, the upper 128 bits of YMM6-YMM15 are
;; also seeded with a non-zero pattern before the call. If any of them are
;; still non-zero afterwards, bit ABI_PROBE_VZEROUPPER_BIT is set: this is
;; a best-effort signal that func_ptr() executed AVX code without a
;; trailing VZEROUPPER (a performance-cliff bug for callers running legacy
;; SSE code afterwards), NOT a violation of the callee-saved register ABI
;; the other bits check (the upper YMM/ZMM halves are not defined as
;; callee-saved). Callers should only pass a non-zero check_vzeroupper for
;; architectures that are expected to execute AVX+ code paths (e.g. not
;; for the SSE architecture), since on an SSE-only path the seeded upper
;; halves are never touched and would otherwise be reported as "dirty".
;;
;; arg1 (rcx) [in] func_ptr
;; arg2 (rdx) [in] arg1 for func_ptr
;; arg3 (r8)  [in] ret_out
;; arg4 (r9)  [in] check_vzeroupper
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
        ;; 32 bytes shadow space + 32 bytes of locals (func_ptr, func_arg,
        ;; ret_out, check_vzeroupper) + 160 bytes to save the caller's
        ;; original xmm6-xmm15 + 8 bytes padding to keep the stack 16-byte
        ;; aligned right before the call below
        sub     rsp, 232

        mov     [rsp + 32], rcx  ;; func_ptr
        mov     [rsp + 40], rdx  ;; arg1 for func_ptr
        mov     [rsp + 48], r8   ;; ret_out
        mov     [rsp + 56], r9   ;; check_vzeroupper

        ;; save the caller's original xmm6-xmm15 before they are clobbered
        ;; with sentinel values, so they can be restored before returning
        movdqu  [rsp + 64 + 0*16], xmm6
        movdqu  [rsp + 64 + 1*16], xmm7
        movdqu  [rsp + 64 + 2*16], xmm8
        movdqu  [rsp + 64 + 3*16], xmm9
        movdqu  [rsp + 64 + 4*16], xmm10
        movdqu  [rsp + 64 + 5*16], xmm11
        movdqu  [rsp + 64 + 6*16], xmm12
        movdqu  [rsp + 64 + 7*16], xmm13
        movdqu  [rsp + 64 + 8*16], xmm14
        movdqu  [rsp + 64 + 9*16], xmm15

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

        test    r9, r9
        jz      .no_vzu_seed
        ;; duplicate the low 128-bit sentinel into the upper 128 bits of
        ;; each ymm6-ymm15, giving a known non-zero pattern to test for
        ;; being left dirty (i.e. no VZEROUPPER) by func_ptr()
%assign i 6
%rep 10
        vinsertf128 ymm %+ i, ymm %+ i, xmm %+ i, 1
%assign i (i+1)
%endrep
.no_vzu_seed:

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

        ;; check whether func_ptr() left any of the seeded upper 128-bit
        ;; halves of ymm6-ymm15 dirty (non-zero); only meaningful if the
        ;; caller requested it (check_vzeroupper != 0, saved at [rsp+56])
        mov     r10, [rsp + 56]
        test    r10, r10
        jz      .no_vzu_check
        pxor    xmm1, xmm1
%assign i 6
%rep 10
        vextractf128 xmm0, ymm %+ i, 1
        por     xmm1, xmm0
%assign i (i+1)
%endrep
        ptest   xmm1, xmm1
        jz      .vzu_clean
        or      r9d, (1 << 18)  ;; ABI_PROBE_VZEROUPPER_BIT
.vzu_clean:
        ;; leave our own AVX state clean before returning to the caller
        vzeroupper
.no_vzu_check:

        mov     eax, r9d        ;; save the corruption mask before restoring xmm6-15

        ;; restore the caller's original xmm6-xmm15
        movdqu  xmm6,  [rsp + 64 + 0*16]
        movdqu  xmm7,  [rsp + 64 + 1*16]
        movdqu  xmm8,  [rsp + 64 + 2*16]
        movdqu  xmm9,  [rsp + 64 + 3*16]
        movdqu  xmm10, [rsp + 64 + 4*16]
        movdqu  xmm11, [rsp + 64 + 5*16]
        movdqu  xmm12, [rsp + 64 + 6*16]
        movdqu  xmm13, [rsp + 64 + 7*16]
        movdqu  xmm14, [rsp + 64 + 8*16]
        movdqu  xmm15, [rsp + 64 + 9*16]

        add     rsp, 232
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbx
        pop     rbp
        ret
