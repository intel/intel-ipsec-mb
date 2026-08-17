;;
;; Copyright (c) 2019-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"

mksection .rodata
default rel
align 64
swap_mask:
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

mksection .text

; Function which XOR's 16 bytes of the input buffer with 16 bytes of the
; KeyStream, placing the result in the output buffer.
; KeyStream bytes must be swapped on 32 bit boundary before this operation
%macro xor_keystream 1
%define %%SIMDTYPE %1 ; "SSE" or "AVX"

%ifidn %%SIMDTYPE, AVX
        %define %%MOVDQU  vmovdqu
        %define %%MOVDQA  vmovdqa
        %define %%PXOR    vpxor
        %define %%PSHUFB  vpshufb
%else
        %define %%MOVDQU  movdqu
        %define %%MOVDQA  movdqa
        %define %%PXOR    pxor
        %define %%PSHUFB  pshufb
%endif
%ifdef LINUX
        %define         %%pIn   rdi
        %define         %%pOut  rsi
        %define         %%pKS   rdx
%else
        %define         %%pIn   rcx
        %define         %%pOut  rdx
        %define         %%pKS   r8
%endif

        %define         %%XKEY    xmm0
        %define         %%XIN     xmm1

        %%MOVDQA        %%XKEY,   [%%pKS]
        %%PSHUFB        %%XKEY,   [rel swap_mask]
        %%MOVDQU        %%XIN,    [%%pIn]
        %%PXOR          %%XKEY,   %%XIN
        %%MOVDQU        [%%pOut], %%XKEY

%endmacro

MKGLOBAL(asm_XorKeyStream16B_avx,function,internal)
asm_XorKeyStream16B_avx:
        xor_keystream AVX
        ret

MKGLOBAL(asm_XorKeyStream16B_sse,function,internal)
asm_XorKeyStream16B_sse:
        xor_keystream SSE
        ret

MKGLOBAL(asm_XorKeyStream32B_avx2,function,internal)
asm_XorKeyStream32B_avx2:
%ifdef LINUX
        %define         pIn     rdi
        %define         pOut    rsi
        %define         pKS     rdx
%else
        %define         pIn     rcx
        %define         pOut    rdx
        %define         pKS     r8
%endif
        %define         YKEY   ymm0
        %define         YIN    ymm1

        vmovdqa         YKEY, [pKS]
        vpshufb         YKEY, [rel swap_mask]

        vmovdqu         YIN, [pIn]
        vpxor           YKEY, YIN

        vmovdqu         [pOut], YKEY
        vzeroupper
        ret

MKGLOBAL(asm_XorKeyStream64B_avx512,function,internal)
asm_XorKeyStream64B_avx512:
%ifdef LINUX
        %define         pIn     rdi
        %define         pOut    rsi
        %define         pKS     rdx
%else
        %define         pIn     rcx
        %define         pOut    rdx
        %define         pKS     r8
%endif
        %define         ZKEY    zmm0
        %define         ZIN     zmm1

        vmovdqa64       ZKEY,   [pKS]
        vpshufb         ZKEY,   [rel swap_mask]
        vmovdqu64       ZIN,    [pIn]
        vpxorq          ZKEY,   ZIN
        vmovdqu64       [pOut], ZKEY
        vzeroupper
        ret

mksection stack-noexec
