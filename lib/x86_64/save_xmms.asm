;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"

%ifdef LINUX
%define ARG1    rdi
%else
%define ARG1    rcx
%endif

mksection .text
; void save_xmms(UINT128 array[10])
MKGLOBAL(save_xmms,function,internal)
save_xmms:
        movdqa  [ARG1 + 0*16], xmm6
        movdqa  [ARG1 + 1*16], xmm7
        movdqa  [ARG1 + 2*16], xmm8
        movdqa  [ARG1 + 3*16], xmm9
        movdqa  [ARG1 + 4*16], xmm10
        movdqa  [ARG1 + 5*16], xmm11
        movdqa  [ARG1 + 6*16], xmm12
        movdqa  [ARG1 + 7*16], xmm13
        movdqa  [ARG1 + 8*16], xmm14
        movdqa  [ARG1 + 9*16], xmm15
        ret

; void restore_xmms(UINT128 array[10])
MKGLOBAL(restore_xmms,function,internal)
restore_xmms:
        movdqa  xmm6, [ARG1 + 0*16]
        movdqa  xmm7, [ARG1 + 1*16]
        movdqa  xmm8, [ARG1 + 2*16]
        movdqa  xmm9, [ARG1 + 3*16]
        movdqa  xmm10, [ARG1 + 4*16]
        movdqa  xmm11, [ARG1 + 5*16]
        movdqa  xmm12, [ARG1 + 6*16]
        movdqa  xmm13, [ARG1 + 7*16]
        movdqa  xmm14, [ARG1 + 8*16]
        movdqa  xmm15, [ARG1 + 9*16]
%ifdef SAFE_DATA
        ;; Clear potential sensitive data stored in stack
        pxor    xmm0, xmm0
        movdqa  [ARG1 + 0 * 16], xmm0
        movdqa  [ARG1 + 1 * 16], xmm0
        movdqa  [ARG1 + 2 * 16], xmm0
        movdqa  [ARG1 + 3 * 16], xmm0
        movdqa  [ARG1 + 4 * 16], xmm0
        movdqa  [ARG1 + 5 * 16], xmm0
        movdqa  [ARG1 + 6 * 16], xmm0
        movdqa  [ARG1 + 7 * 16], xmm0
        movdqa  [ARG1 + 8 * 16], xmm0
        movdqa  [ARG1 + 9 * 16], xmm0
%endif

        ret

        ; void save_xmms_avx(UINT128 array[10])
MKGLOBAL(save_xmms_avx,function,internal)
save_xmms_avx:
        vmovdqa [ARG1 + 0*16], xmm6
        vmovdqa [ARG1 + 1*16], xmm7
        vmovdqa [ARG1 + 2*16], xmm8
        vmovdqa [ARG1 + 3*16], xmm9
        vmovdqa [ARG1 + 4*16], xmm10
        vmovdqa [ARG1 + 5*16], xmm11
        vmovdqa [ARG1 + 6*16], xmm12
        vmovdqa [ARG1 + 7*16], xmm13
        vmovdqa [ARG1 + 8*16], xmm14
        vmovdqa [ARG1 + 9*16], xmm15
        ret

; void restore_xmms_avx(UINT128 array[10])
MKGLOBAL(restore_xmms_avx,function,internal)
restore_xmms_avx:
        vmovdqa xmm6, [ARG1 + 0*16]
        vmovdqa xmm7, [ARG1 + 1*16]
        vmovdqa xmm8, [ARG1 + 2*16]
        vmovdqa xmm9, [ARG1 + 3*16]
        vmovdqa xmm10, [ARG1 + 4*16]
        vmovdqa xmm11, [ARG1 + 5*16]
        vmovdqa xmm12, [ARG1 + 6*16]
        vmovdqa xmm13, [ARG1 + 7*16]
        vmovdqa xmm14, [ARG1 + 8*16]
        vmovdqa xmm15, [ARG1 + 9*16]

%ifdef SAFE_DATA
        ;; Clear potential sensitive data stored in stack
        vpxor   xmm0, xmm0
        vmovdqa [ARG1 + 0 * 16], xmm0
        vmovdqa [ARG1 + 1 * 16], xmm0
        vmovdqa [ARG1 + 2 * 16], xmm0
        vmovdqa [ARG1 + 3 * 16], xmm0
        vmovdqa [ARG1 + 4 * 16], xmm0
        vmovdqa [ARG1 + 5 * 16], xmm0
        vmovdqa [ARG1 + 6 * 16], xmm0
        vmovdqa [ARG1 + 7 * 16], xmm0
        vmovdqa [ARG1 + 8 * 16], xmm0
        vmovdqa [ARG1 + 9 * 16], xmm0
%endif
        ret

mksection stack-noexec
