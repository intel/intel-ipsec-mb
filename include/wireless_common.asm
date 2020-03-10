;;
;; Copyright (c) 2019-2020, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;

%include "include/os.asm"

section .data
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

section .text

; Function which XOR's 64 bytes of the input buffer with 64 bytes of the
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
        %define	        %%pIn	rdi
        %define	        %%pOut	rsi
        %define	        %%pKS	rdx
%else
        %define	        %%pIn	rcx
        %define	        %%pOut	rdx
        %define	        %%pKS	r8

        mov             rax, rsp
        sub             rsp, 48
        and             rsp, ~15
        %%MOVDQA        [rsp], xmm6
        %%MOVDQA        [rsp + 16], xmm7
        %%MOVDQA        [rsp + 32], xmm8
%endif
        %define         XKEY0   xmm0
        %define         XKEY1   xmm1
        %define         XKEY2   xmm2
        %define         XKEY3   xmm3
        %define         XIN0    xmm4
        %define         XIN1    xmm5
        %define         XIN2    xmm6
        %define         XIN3    xmm7
        %define         XSHUF   xmm8

        %%MOVDQA        XSHUF, [rel swap_mask]
        %%MOVDQA        XKEY0, [%%pKS]
        %%MOVDQA        XKEY1, [%%pKS + 16]
        %%MOVDQA        XKEY2, [%%pKS + 32]
        %%MOVDQA        XKEY3, [%%pKS + 48]

        %%PSHUFB        XKEY0, XSHUF
        %%PSHUFB        XKEY1, XSHUF
        %%PSHUFB        XKEY2, XSHUF
        %%PSHUFB        XKEY3, XSHUF

        %%MOVDQU        XIN0, [%%pIn]
        %%MOVDQU        XIN1, [%%pIn + 16]
        %%MOVDQU        XIN2, [%%pIn + 32]
        %%MOVDQU        XIN3, [%%pIn + 48]

        %%PXOR          XKEY0, XIN0
        %%PXOR          XKEY1, XIN1
        %%PXOR          XKEY2, XIN2
        %%PXOR          XKEY3, XIN3

        %%MOVDQU        [%%pOut],      XKEY0
        %%MOVDQU        [%%pOut + 16], XKEY1
        %%MOVDQU        [%%pOut + 32], XKEY2
        %%MOVDQU        [%%pOut + 48], XKEY3

%ifndef LINUX
        %%MOVDQA        xmm6, [rsp]
        %%MOVDQA        xmm7, [rsp + 16]
        %%MOVDQA        xmm8, [rsp + 32]
        mov             rsp,rax
%endif
%endmacro

MKGLOBAL(asm_XorKeyStream64B_avx,function,internal)
asm_XorKeyStream64B_avx:
        xor_keystream AVX
        ret

MKGLOBAL(asm_XorKeyStream64B_sse,function,internal)
asm_XorKeyStream64B_sse:
        xor_keystream SSE
        ret

MKGLOBAL(asm_XorKeyStream64B_avx2,function,internal)
asm_XorKeyStream64B_avx2:
%ifdef LINUX
        %define	        pIn	rdi
        %define	        pOut	rsi
        %define	        pKS	rdx
%else
        %define	        pIn	rcx
        %define	        pOut	rdx
        %define	        pKS	r8
%endif
        %define         YKEY0   ymm0
        %define         YKEY1   ymm1
        %define         YIN0    ymm2
        %define         YIN1    ymm3
        %define         YSHUF   ymm4

        vmovdqa         YSHUF, [rel swap_mask]
        vmovdqa         YKEY0, [pKS]
        vmovdqa         YKEY1, [pKS + 32]

        vpshufb         YKEY0, YSHUF
        vpshufb         YKEY1, YSHUF

        vmovdqu         YIN0, [pIn]
        vmovdqu         YIN1, [pIn + 32]

        vpxor           YKEY0, YIN0
        vpxor           YKEY1, YIN1

        vmovdqu         [pOut],      YKEY0
        vmovdqu         [pOut + 32], YKEY1

        ret

MKGLOBAL(asm_XorKeyStream64B_avx512,function,internal)
asm_XorKeyStream64B_avx512:
%ifdef LINUX
        %define	        pIn     rdi
        %define	        pOut    rsi
        %define	        pKS     rdx
%else
        %define	        pIn     rcx
        %define	        pOut    rdx
        %define	        pKS     r8
%endif
        %define         ZKEY    zmm0
        %define         ZIN     zmm1

        vmovdqa64       ZKEY,   [pKS]
        vpshufb         ZKEY,   [rel swap_mask]
        vmovdqu64       ZIN,    [pIn]
        vpxorq          ZKEY,   ZIN
        vmovdqu64       [pOut], ZKEY

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
