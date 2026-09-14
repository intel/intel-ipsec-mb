;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2026, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%use smartalign

%include "os.inc"
%include "cet.inc"

%ifdef WIN_ABI
;; Windows x64 declares XMM6-XMM15 and RBX, RBP, RSI, RDI, R12-R15
;; callee-saved
%define ABI_NUM_XMM     10
%define ABI_NUM_GP      8

;; Windows x64 requires 32 bytes of shadow space below the outgoing arguments
%define SHADOW_SPACE    32

;;; ABI function arguments
%define arg1            rcx
%define arg2            rdx
%define arg3            r8
%define arg4            r9
%else
;; System V AMD64 has no callee-saved XMM registers at all and declares
;; only RBX, RBP and R12-R15 callee-saved (RSI and RDI are argument
;; registers there, unlike on Windows x64)
%define ABI_NUM_XMM     0
%define ABI_NUM_GP      6

;; System V AMD64 has no shadow space
%define SHADOW_SPACE    0

;;; ABI function arguments
%define arg1            rdi
%define arg2            rsi
%define arg3            rdx
%define arg4            rcx
%endif

;; bit reporting a dirty upper YMM state, past the XMM and GP register bits
%define ABI_VZU_BIT     (ABI_NUM_XMM + ABI_NUM_GP)

;; stack frame layout, relative to RSP after the frame has been allocated
%define LOC_FUNC        (SHADOW_SPACE + 0)
%define LOC_ARG         (SHADOW_SPACE + 8)
%define LOC_RETOUT      (SHADOW_SPACE + 16)
%define LOC_VZU         (SHADOW_SPACE + 24)
%define LOC_XMM         (SHADOW_SPACE + 32)

;; shadow space (if any) + 32 bytes of locals (func_ptr, func_arg, ret_out,
;; check_vzeroupper) + room to save the caller's callee-saved XMM registers
;; (if any) + 8 bytes of padding to keep the stack 16-byte aligned right
;; before the call below (an even number of pushes precedes it)
%define FRAME_SIZE      (LOC_XMM + (ABI_NUM_XMM * 16) + 8)

mksection .rodata
default rel

%if ABI_NUM_XMM > 0
;; Unique 128-bit sentinel pattern per XMM register, index 0 => XMM6, index 9 => XMM15
align 16
sentinel_tab:
%assign i 6
%rep ABI_NUM_XMM
        dq 0x5a5a5a5a00000000 | i, 0xa5a5a5a500000000 | i
%assign i (i+1)
%endrep
%endif

;; Unique 64-bit sentinel pattern per checked GP register, in the order the
;; registers are loaded below (matches ABI_PROBE_GP_BIT()/ABI_PROBE_GP_NAMES)
align 8
gp_sentinel_tab:
%assign i 0
%rep ABI_NUM_GP
        dq 0xc3c3c3c300000000 | i
%assign i (i+1)
%endrep

;; Non-zero pattern written into the upper 128 bits of YMM6-YMM15 to detect
;; a missing VZEROUPPER; inserted with VINSERTF128 so that the lower halves
;; (which hold the XMM sentinels on Windows x64) are left untouched
align 16
vzu_seed_pattern:
        dq 0x3c3c3c3cf00dcafe, 0xc3c3c3c3cafef00d

mksection .text

;; Verifies one callee-saved general purpose register against its sentinel
;;
;; %1 [in] callee-saved GP register to verify
;; %2 [in] index into gp_sentinel_tab, also the bit index within the GP range
;; %3 [in] register holding the gp_sentinel_tab address
;; %4 [in/out] 32-bit register accumulating the corruption bitmask
%macro CHECK_GP_REG 4
%define %%GP_REG   %1
%define %%IDX      %2
%define %%TAB_PTR  %3
%define %%MASK_ACC %4

        cmp     %%GP_REG, [%%TAB_PTR + %%IDX*8]
        je      %%gp_ok
        or      %%MASK_ACC, (1 << (ABI_NUM_XMM + %%IDX))
%%gp_ok:
%endmacro

;; uint32_t xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out,
;;                        int check_vzeroupper)
;;
;; Fills the callee-saved registers of the target ABI with sentinel
;; patterns, calls func_ptr(arg1), stores the return value at *ret_out (if
;; not NULL) and returns a bitmask of the registers that did not keep their
;; sentinel value across the call.
;;
;; On Windows x64 the checked set is XMM6-XMM15 (bit 0 => XMM6, ... bit 9 =>
;; XMM15) followed by rbx, rbp, rsi, rdi, r12-r15 (bits 10-17). On System V
;; AMD64 no XMM register is callee-saved, so the checked set is only rbx,
;; rbp, r12-r15 (bits 0-5). See ABI_PROBE_XMM_BIT()/ABI_PROBE_GP_BIT().
;;
;; On Windows x64 the original caller-side values of XMM6-XMM15 are saved
;; before the sentinels are loaded and restored before returning, so this
;; probe itself behaves as a proper callee and does not corrupt the caller's
;; (compiler-managed) XMM state - it only observes what func_ptr() does to
;; the sentinel values in between. On System V AMD64 those registers are
;; call-clobbered, so no save/restore is needed.
;;
;; The callee-saved GP registers are filled with sentinels for the whole
;; duration of the call, so func_ptr and its argument are kept in stack
;; slots and func_ptr is invoked with an indirect memory-operand call,
;; leaving every sentinel-holding register untouched by the call setup
;; itself.
;;
;; When check_vzeroupper is non-zero, the upper 128 bits of YMM6-YMM15 are
;; also seeded with a non-zero pattern before the call. If any of them are
;; still non-zero afterwards, bit ABI_VZU_BIT is set: this is a best-effort
;; signal that func_ptr() executed AVX code without a trailing VZEROUPPER
;; (a performance-cliff bug for callers running legacy SSE code
;; afterwards), NOT a violation of the callee-saved register ABI the other
;; bits check (the upper YMM/ZMM halves are not defined as callee-saved on
;; either ABI). Callers should only pass a non-zero check_vzeroupper for
;; architectures that are expected to execute AVX+ code paths (e.g. not for
;; the SSE architecture), since on an SSE-only path the seeded upper halves
;; are never touched and would otherwise be reported as "dirty". This is
;; also what keeps the AVX and SSE4.1 instructions below - the only ones in
;; this file that are not baseline x86-64 - from ever executing on a CPU
;; that does not support them.
;;
;; arg1 [in] func_ptr
;; arg2 [in] arg1 for func_ptr
;; arg3 [in] ret_out
;; arg4 [in] check_vzeroupper
MKGLOBAL(xmm_abi_probe,function,)
align 16
xmm_abi_probe:
        endbranch64
        push    rbp
        push    rbx
%ifdef WIN_ABI
        push    rsi
        push    rdi
%endif
        push    r12
        push    r13
        push    r14
        push    r15

        sub     rsp, FRAME_SIZE

        mov     [rsp + LOC_FUNC], arg1
        mov     [rsp + LOC_ARG], arg2
        mov     [rsp + LOC_RETOUT], arg3
        mov     [rsp + LOC_VZU], arg4

%if ABI_NUM_XMM > 0
        ;; save the caller's original xmm6-xmm15 before they are clobbered
        ;; with sentinel values, so they can be restored before returning
%assign i 6
%assign slot 0
%rep ABI_NUM_XMM
        movdqu  [rsp + LOC_XMM + slot*16], xmm %+ i
%assign i (i+1)
%assign slot (slot+1)
%endrep

        lea     rax, [rel sentinel_tab]
%assign i 6
%assign slot 0
%rep ABI_NUM_XMM
        movdqu  xmm %+ i, [rax + slot*16]
%assign i (i+1)
%assign slot (slot+1)
%endrep
%endif

        mov     rax, [rsp + LOC_VZU]
        test    rax, rax
        jz      .no_vzu_seed
        ;; write a known non-zero pattern into the upper 128 bits of each
        ;; ymm6-ymm15 to test for being left dirty (i.e. no VZEROUPPER) by
        ;; func_ptr(); the lower halves keep whatever they hold already
        lea     rax, [rel vzu_seed_pattern]
%assign i 6
%rep 10
        vinsertf128 ymm %+ i, ymm %+ i, [rax], 1
%assign i (i+1)
%endrep
.no_vzu_seed:

        lea     rax, [rel gp_sentinel_tab]
        mov     rbx, [rax + 0*8]
        mov     rbp, [rax + 1*8]
%ifdef WIN_ABI
        mov     rsi, [rax + 2*8]
        mov     rdi, [rax + 3*8]
        mov     r12, [rax + 4*8]
        mov     r13, [rax + 5*8]
        mov     r14, [rax + 6*8]
        mov     r15, [rax + 7*8]
%else
        mov     r12, [rax + 2*8]
        mov     r13, [rax + 3*8]
        mov     r14, [rax + 4*8]
        mov     r15, [rax + 5*8]
%endif

        mov     arg1, [rsp + LOC_ARG]  ;; arg1 for func_ptr

        call    qword [rsp + LOC_FUNC]

        mov     r10, [rsp + LOC_RETOUT]  ;; volatile, safe to use post-call
        test    r10, r10
        jz      .no_ret_out
        mov     [r10], rax
.no_ret_out:

        xor     r9d, r9d        ;; corruption bitmask accumulator

%if ABI_NUM_XMM > 0
        lea     rax, [rel sentinel_tab]
%assign i 6
%assign bit 0
%rep ABI_NUM_XMM
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
%endif

        lea     rax, [rel gp_sentinel_tab]
        CHECK_GP_REG rbx, 0, rax, r9d
        CHECK_GP_REG rbp, 1, rax, r9d
%ifdef WIN_ABI
        CHECK_GP_REG rsi, 2, rax, r9d
        CHECK_GP_REG rdi, 3, rax, r9d
        CHECK_GP_REG r12, 4, rax, r9d
        CHECK_GP_REG r13, 5, rax, r9d
        CHECK_GP_REG r14, 6, rax, r9d
        CHECK_GP_REG r15, 7, rax, r9d
%else
        CHECK_GP_REG r12, 2, rax, r9d
        CHECK_GP_REG r13, 3, rax, r9d
        CHECK_GP_REG r14, 4, rax, r9d
        CHECK_GP_REG r15, 5, rax, r9d
%endif

        ;; check whether func_ptr() left any of the seeded upper 128-bit
        ;; halves of ymm6-ymm15 dirty (non-zero); only meaningful if the
        ;; caller requested it (check_vzeroupper != 0)
        mov     r10, [rsp + LOC_VZU]
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
        or      r9d, (1 << ABI_VZU_BIT)
.vzu_clean:
        ;; leave our own AVX state clean before returning to the caller
        vzeroupper
.no_vzu_check:

        mov     eax, r9d        ;; save the corruption mask before restoring xmm6-15

%if ABI_NUM_XMM > 0
        ;; restore the caller's original xmm6-xmm15
%assign i 6
%assign slot 0
%rep ABI_NUM_XMM
        movdqu  xmm %+ i, [rsp + LOC_XMM + slot*16]
%assign i (i+1)
%assign slot (slot+1)
%endrep
%endif

        add     rsp, FRAME_SIZE
        pop     r15
        pop     r14
        pop     r13
        pop     r12
%ifdef WIN_ABI
        pop     rdi
        pop     rsi
%endif
        pop     rbx
        pop     rbp
        ret

mksection stack-noexec
