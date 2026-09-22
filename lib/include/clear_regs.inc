;;
;; Copyright (c) 2019-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef _CLEAR_REGS_INC_
%define _CLEAR_REGS_INC_

%include "include/os.inc"

;
; This macro clears any GP registers passed
;
%macro clear_gps 1-16
%define %%NUM_REGS %0
%rep %%NUM_REGS
        xor %1, %1
%rotate 1
%endrep
%endmacro

;
; This macro clears any XMM registers passed on SSE
;
%macro clear_xmms_sse 1-16
%define %%NUM_REGS %0
%rep %%NUM_REGS
        pxor    %1, %1
%rotate 1
%endrep
%endmacro

;
; This macro clears any XMM registers passed on AVX
;
%macro clear_xmms_avx 1-16
%define %%NUM_REGS %0
%rep %%NUM_REGS
        vpxor   %1, %1
%rotate 1
%endrep
%endmacro

;
; This macro clears selected XMM registers on AVX but skips
; XMM6-XMM15 on Windows, as those are restored by epilogue.
;
%macro clear_scratch_xmms_avx_regs 1-16
%rep %0
%ifdef LINUX
        vpxor   %1, %1
%else
%defstr %%REG_STR %1
%substr %%IDX_STR %%REG_STR 4,-1
%deftok %%REG_IDX %%IDX_STR
%if (%%REG_IDX < 6) || (%%REG_IDX > 15)
        vpxor   %1, %1
%endif
%endif ; LINUX
%rotate 1
%endrep
%endmacro

;
; This macro clears any ZMM registers passed on
;
%macro clear_zmms_avx512 1-32

%assign num_reg %0
%assign num_xors 3

; clear up to 3 registers with vpxorq
%if num_reg < 3
%assign num_xors num_reg
%endif

; save 1st register for later
%xdefine %%SAVE_XMM XWORD(%1)

%rep num_xors
        vpxorq          XWORD(%1), XWORD(%1), XWORD(%1)
%rotate 1
%endrep

; clear the rest of the registers with move from the 1st register
%assign num_reg (num_reg - num_xors)

%rep num_reg
        vmovdqa64       XWORD(%1), %%SAVE_XMM
%rotate 1
%endrep

%undef %%SAVE_XMM

%endmacro

;
; This macro clears the ZMM registers passed as arguments but
; skips the ones that the function epilogue restores anyway.
;
; On Windows, XMM6-XMM15 are non-volatile so any function clobbering them
; has to restore the caller's values on exit (see FUNC_SAVE/FUNC_RESTORE).
; Clearing them beforehand is redundant work as the restore immediately
; overwrites the cleared value with data belonging to the caller.
;
%macro clear_scratch_zmms_avx512 1-32

%assign %%NUM_CLEARS 0

%rep %0

%ifdef LINUX
        ;; on Linux all registers are scratch registers
%assign %%SKIP_REG 0
%else
        ;; Retrieve the register index and skip XMM6-XMM15
        ;; - this fragment could look better (with newer NASM) but it is
        ;;   compatible with NASM 2.14.02
        ;;   - map register name to string
        ;;   - get sub-string with the register number
        ;;   - make new token out of the sub-string - it results in a
        ;;     number that can be compared
%defstr %%REG_STR %1
%substr %%IDX_STR %%REG_STR 4,-1
%deftok %%REG_IDX %%IDX_STR
%assign %%SKIP_REG 0
%if (%%REG_IDX >= 6) && (%%REG_IDX <= 15)
%assign %%SKIP_REG 1
%endif
%endif ; LINUX

%if %%SKIP_REG == 0
%if %%NUM_CLEARS == 0
        ;; save 1st cleared register for later
%xdefine %%SAVE_XMM XWORD(%1)
%endif
        ;; clear up to 3 registers with vpxorq and
        ;; the rest with move from the 1st cleared register
%if %%NUM_CLEARS < 3
        vpxorq          XWORD(%1), XWORD(%1), XWORD(%1)
%else
        vmovdqa64       XWORD(%1), %%SAVE_XMM
%endif
%assign %%NUM_CLEARS (%%NUM_CLEARS + 1)
%endif ; %%SKIP_REG == 0

%rotate 1
%endrep

%if %%NUM_CLEARS > 0
%undef %%SAVE_XMM
%endif

%endmacro

;
; This macro clears scratch GP registers
; for Windows or Linux
;
%macro clear_scratch_gps_asm 0
        clear_gps rax, rcx, rdx, r8, r9, r10, r11
%ifdef LINUX
        clear_gps rdi, rsi
%endif
%endmacro

;
; This macro clears scratch XMM registers on SSE
;
%macro clear_scratch_xmms_sse_asm 0
%ifdef LINUX
%assign i 0
%rep 16
        pxor    xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
; On Windows, XMM0-XMM5 registers are scratch registers
%else
%assign i 0
%rep 6
        pxor    xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endif ; LINUX
%endmacro

;
; This macro clears scratch XMM registers on AVX
;
%macro clear_scratch_xmms_avx_asm 0
%ifdef LINUX
%assign i 0
%rep 16
        vpxor   xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%else
; On Windows, XMM0-XMM5 registers are scratch registers
%assign i 0
%rep 6
        vpxor   xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endif ; LINUX
%endmacro

;
; This macro clears scratch YMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15)
;
%macro clear_scratch_ymms_asm 0
%ifdef LINUX
; On Linux, all YMM registers are scratch registers
        vzeroall
%else
; On Windows, XMM0-XMM5 registers are scratch registers
%assign i 0
%rep 6
        vpxor   xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endif ; LINUX
%endmacro

;
; This macro clears scratch ZMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15). YMM registers are used
; on purpose, since XOR'ing YMM registers is faster
; than XOR'ing ZMM registers, and the operation clears
; also the upper 256 bits
;
%macro clear_scratch_zmms_asm 0
%ifdef LINUX
; On Linux, all ZMM registers are scratch registers
        vpxorq  xmm0, xmm0, xmm0
        vpxorq  xmm1, xmm1, xmm1
        vpxorq  xmm2, xmm2, xmm2
%assign i 3
%rep (16 + 13)
%assign j (i % 3)
        vmovdqa64  xmm %+ i, xmm %+ j
%assign i (i+1)
%endrep
%else
; On Windows, XMM0-XMM5 registers are scratch registers
        vpxorq  xmm0, xmm0, xmm0
        vpxorq  xmm1, xmm1, xmm1
        vpxorq  xmm2, xmm2, xmm2
        vmovdqa64  xmm3, xmm0
        vmovdqa64  xmm4, xmm1
        vmovdqa64  xmm5, xmm2
%assign i 16
%rep 16
%assign j (i % 3)
        vmovdqa64  xmm %+ i, xmm %+ j
%assign i (i+1)
%endrep
%endif ; LINUX
        vzeroupper
%endmacro

;
; This macro clears all XMM registers on SSE
;
%macro clear_all_xmms_sse_asm 0
%assign i 0
%rep 16
        pxor    xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endmacro

;
; This macro clears all XMM registers on AVX
;
%macro clear_all_xmms_avx_asm 0
%assign i 0
%rep 16
        vpxor   xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endmacro

;
; This macro clears all YMM registers
;
%macro clear_all_ymms_asm 0
        vzeroall
%endmacro

;
; This macro clears all ZMM registers
;
; YMM registers are used on purpose, since XOR'ing YMM registers
; is faster than XOR'ing ZMM registers, and the operation clears
; also the upper 256 bits
;
%macro clear_all_zmms_asm 0
        vpxorq  xmm0, xmm0, xmm0
        vpxorq  xmm1, xmm1, xmm1
        vpxorq  xmm2, xmm2, xmm2
%assign i 3
%rep (16 + 13)
%assign j (i % 3)
        vmovdqa64  xmm %+ i, xmm %+ j
%assign i (i+1)
%endrep
        vzeroupper
%endmacro

%endif ;; _CLEAR_REGS_INC_
