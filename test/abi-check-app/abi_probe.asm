;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2026, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%use smartalign

%include "os.inc"
%include "cet.inc"

%ifdef WIN_ABI
;; callee-saved: XMM6-XMM15 and RBX, RBP, RSI, RDI, R12-R15
%define ABI_NUM_XMM     10
%define ABI_NUM_GP      8

;; 32 bytes of shadow space required below the outgoing arguments
%define SHADOW_SPACE    32

;;; ABI function arguments
%define arg1            rcx
%define arg2            rdx
%define arg3            r8
%define arg4            r9
%else
;; callee-saved: RBX, RBP, R12-R15 only; no XMM register and no shadow space
%define ABI_NUM_XMM     0
%define ABI_NUM_GP      6
%define SHADOW_SPACE    0

;;; ABI function arguments
%define arg1            rdi
%define arg2            rsi
%define arg3            rdx
%define arg4            rcx
%endif

;; dirty upper YMM state bit, past the XMM and GP register bits
%define ABI_VZU_BIT     (ABI_NUM_XMM + ABI_NUM_GP)

;; stack frame layout, relative to RSP after the frame has been allocated
%define LOC_FUNC        (SHADOW_SPACE + 0)
%define LOC_ARG         (SHADOW_SPACE + 8)
%define LOC_RETOUT      (SHADOW_SPACE + 16)
%define LOC_VZU         (SHADOW_SPACE + 24)
%define LOC_XMM         (SHADOW_SPACE + 32)

;; shadow space + locals + saved caller XMM + 8 bytes of padding to keep
;; the stack 16-byte aligned at the call (an even number of pushes precedes it)
%define FRAME_SIZE      (LOC_XMM + (ABI_NUM_XMM * 16) + 8)

mksection .rodata
default rel

%if ABI_NUM_XMM > 0
;; unique sentinel per XMM register, index 0 => XMM6
align 16
sentinel_tab:
%assign i 6
%rep ABI_NUM_XMM
        dq 0x5a5a5a5a00000000 | i, 0xa5a5a5a500000000 | i
%assign i (i+1)
%endrep
%endif

;; unique sentinel per checked GP register, in ABI_PROBE_GP_NAMES order
align 8
gp_sentinel_tab:
%assign i 0
%rep ABI_NUM_GP
        dq 0xc3c3c3c300000000 | i
%assign i (i+1)
%endrep

;; non-zero pattern for the upper 128 bits of YMM6-YMM15; inserted with
;; VINSERTF128 so the lower halves (XMM sentinels on Windows) are untouched
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
;; Checked set: XMM6-XMM15 (bits 0-9) then rbx, rbp, rsi, rdi, r12-r15
;; (bits 10-17) on Windows x64; rbx, rbp, r12-r15 (bits 0-5) on System V
;; AMD64. See ABI_PROBE_XMM_BIT()/ABI_PROBE_GP_BIT().
;;
;; On Windows x64 the caller's XMM6-XMM15 are saved and restored around the
;; sentinels, so the probe behaves as a proper callee. On System V AMD64
;; they are call-clobbered, so no save/restore is needed.
;;
;; The GP sentinels are live across the call, so func_ptr and its argument
;; are kept in stack slots and called through an indirect memory operand.
;;
;; When check_vzeroupper is non-zero, the upper 128 bits of YMM6-YMM15 are
;; seeded before the call and bit ABI_VZU_BIT is set if any are still dirty
;; afterwards. That signals AVX code without a trailing VZEROUPPER (a
;; performance cliff for legacy SSE callers), not an ABI violation, as the
;; upper YMM/ZMM halves are not callee-saved on either ABI. Only pass a
;; non-zero value for architectures running AVX+ code: an SSE-only path
;; never touches the seed and would be reported as dirty. It also gates the
;; only non-baseline (AVX and SSE4.1) instructions in this file.
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
        ;; save the caller's xmm6-xmm15 before loading the sentinels
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
        ;; seed the upper halves of ymm6-ymm15, low halves left as they are
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

        mov     arg1, [rsp + LOC_ARG]

        call    qword [rsp + LOC_FUNC]

        mov     r10, [rsp + LOC_RETOUT]  ;; volatile, safe post-call
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

        ;; report the seeded upper ymm6-ymm15 halves if left dirty
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
        vzeroupper      ;; leave our own AVX state clean
.no_vzu_check:

        mov     eax, r9d        ;; return the corruption mask

%if ABI_NUM_XMM > 0
        ;; restore the caller's xmm6-xmm15
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
