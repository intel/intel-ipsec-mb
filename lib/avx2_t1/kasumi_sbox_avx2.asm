;;
;; Copyright (c) 2026, Intel Corporation
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

;; Bitsliced constant-time KASUMI FI function implementation.
;; The S7/S9 S-box substitutions are computed using Boolean equations
;; evaluated in parallel across YMM register words, based on:
;;   E. Urquhart and D. Chambers, "An Optimised Constant-time Implementation
;;   of KASUMI FI Function," ISSC, 2024.
;;   https://ieeexplore.ieee.org/document/10603289

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/constant_lookup.inc"
%include "include/align_avx.inc"

mksection .rodata
default rel

MKGLOBAL(sbox_mask_x0,data,internal)
MKGLOBAL(sbox_mask_x1,data,internal)
MKGLOBAL(sbox_mask_x2,data,internal)
MKGLOBAL(sbox_mask_x3,data,internal)
MKGLOBAL(sbox_mask_x4,data,internal)
MKGLOBAL(sbox_mask_x5,data,internal)
MKGLOBAL(sbox_mask_x6,data,internal)
MKGLOBAL(sbox_mask_x7,data,internal)
MKGLOBAL(sbox_mask_x8,data,internal)
MKGLOBAL(sbox_mask_last,data,internal)
MKGLOBAL(high_7,data,internal)

align 32
;; Masks representing the (stitched) S(7/9)-box Boolean equations
;; Mask bits in positions where corresponding input bit is not a part of the y-equation
sbox_mask_x0     dq  0xB3FF347F3AFFDEFF, 0x77FF9DBF93DF756F, 0x6BFF5B7FAFEFABFF, 0x7FFF37FF7FFFEFFF
sbox_mask_x1     dq  0x1ABFEB7F77FF5F6F, 0xFBFF2D7FEF3FC6BF, 0x3EFFBDBF7FFF377F, 0x55FF5FFFDFBFB7FF
sbox_mask_x2     dq  0xBD7FCDBFD6FFF7DF, 0x5DFF7EFF25B77BFF, 0xFF7FAFFFF7FFDFBF, 0x9BBF9ABFAFFF7FFF
sbox_mask_x3     dq  0xEDBF97FFFB7F7BBF, 0xBFFFB6FFCFCF9ACF, 0xB7BFDFFF9BFFDDFF, 0xEFDFE37FBBDFFBFF
sbox_mask_x4     dq  0xCEFFE7DF9FBF9BD7, 0xFEFFDF7FF6EFE37F, 0xDFFFEEFFDEFFE7FF, 0xEEFFFDFFF5FF9DFF
sbox_mask_x5     dq  0xF0FFF9FFE3BFE3E7, 0xCF7FE7BFF8F7FC77, 0xEFFFF7FFED7FF9DF, 0xF3FFFDDFC6EFDF7F
sbox_mask_x6     dq  0xFF3FFE1FFC3FFC07, 0xEFFFF83FFF07FF87, 0xF5FFF9FFF1BFFEFF, 0xFCFFFE7FF8FFE6BF
sbox_mask_x7     dq  0xffffffffffffffff, 0xF1BFffffffffffff, 0xF9FFFEDFFE3FFF3F, 0xFF7FFF9FFF77F8DF
sbox_mask_x8     dq  0xffffffffffffffff, 0xFE3Fffffffffffff, 0xFE3FFF1FFFCFFFDF, 0xFF9FFFEFFF87FF1F
sbox_mask_last   dq  0xFFC0FFF0FFE0FFF8, 0xFFE0FFC0FFFCFFFC, 0xFFC0FFE0FFF8FFF0, 0xFFE0FFF8FFF8FFF0

align 32
;; Masks which isolate the relevant input bits in each word
;; e.g. ith iteration isolates ith bit in each of the low 7 words and the (i+7)th bit
;; in each of the high 9 words.
;; Therefore in isolate_input_bits_i, the ith bit in each of low 7 words is set, and
;; the (i+7)th bit in each of the high 9 words is set.
isolate_input_bits_0    dq  0x0001000100010001, 0x0080000100010001, 0x0080008000800080, 0x0080008000800080
isolate_input_bits_1    dq  0x0002000200020002, 0x0100000200020002, 0x0100010001000100, 0x0100010001000100
isolate_input_bits_2    dq  0x0004000400040004, 0x0200000400040004, 0x0200020002000200, 0x0200020002000200
isolate_input_bits_3    dq  0x0008000800080008, 0x0400000800080008, 0x0400040004000400, 0x0400040004000400
isolate_input_bits_4    dq  0x0010001000100010, 0x0800001000100010, 0x0800080008000800, 0x0800080008000800
isolate_input_bits_5    dq  0x0020002000200020, 0x1000002000200020, 0x1000100010001000, 0x1000100010001000
isolate_input_bits_6    dq  0x0040004000400040, 0x2000004000400040, 0x2000200020002000, 0x2000200020002000
isolate_input_bits_7    dq  0x0000000000000000, 0x4000000000000000, 0x4000400040004000, 0x4000400040004000
isolate_input_bits_8    dq  0x0000000000000000, 0x8000000000000000, 0x8000800080008000, 0x8000800080008000

align 8
pext_odd_bytes_mask    dq  0xAAAAAAAA

align 32
nibble_mask:       times 32 db 0x0F

align 32
parity_nibble_lut:
        ;; Nibble parity lookup: entry[i] = 0xFF if popcount(i) is odd, 0x00 if even
        db 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF
        db 0xFF, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0x00
        db 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF
        db 0xFF, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0x00

mksection .text

%ifdef LINUX
        %define arg1    rdi
        %define arg2    rsi
        %define arg3    rdx
        %define arg4    rcx
%else
        %define arg1    rcx
        %define arg2    rdx
        %define arg3    r8
        %define arg4    r9
%endif

%define     y0    ymm2
%define     y1    ymm3
%define     y2    ymm4
%define     y3    ymm5
%define     y4    ymm6
%define     y5    ymm7
%define     y6    ymm8
%define     y7    ymm9
%define     y8    ymm11

%define     y(n)  y %+ n
%define     sbox_mask_x(n)   sbox_mask_x %+ n

%define     x_mask(n)   x %+ n %+_mask
%define     isolate_input_bits(n) isolate_input_bits_ %+ n
%define     permute_bytes_input_(x) permute_bytes_input_ %+ x
%define     permute_words_input_(x) permute_words_input_ %+ x

;; Number of non-volatile XMM/YMM registers saved on Windows (xmm6-xmm11, xmm13)
%define XMM_SAVES 7
%define STACK_SIZE (XMM_SAVES * 16)

;; KASUMI_SBOX_AVX2
;; Computes the combined Kasumi S7 and S9 S-box substitution using a bitsliced
;; AVX2 implementation based on Boolean equations.
;;
;; The 16-bit input value in arg1 is broadcast across all words of a YMM register.
;; Each input bit is isolated and compared against its expected position to produce
;; an all-ones or all-zeros mask per word. These per-bit masks are OR'd with
;; precomputed S-box Boolean equation constants (sbox_mask_x0..x8), then AND'd
;; together to evaluate the combined S7/S9 output equations. A nibble-parity
;; LUT reduction (via VPSHUFB) collapses each word to a single output bit,
;; and VPMOVMSKB + PEXT extract the 16-bit S-box result into RAX.
;;
;; Input:  arg1 (16-bit value in low word)
;; Output: rax  (16-bit S-box result: S9 in upper 9 bits, S7 in lower 7 bits)
;; Clobbers: ymm0-ymm11, ymm13, r10
%macro KASUMI_SBOX_AVX2 0
        vmovd       xmm13, DWORD(arg1)     ; load input into low word of xmm13
        vpbroadcastw ymm13, xmm13          ; broadcast input across all words of ymm13
%assign i 0
%rep 9
        vpand   y(i), ymm13, [rel isolate_input_bits(i)]
        vpcmpeqw y(i), y(i), [rel isolate_input_bits(i)]  ; fill with 1s if equal to 0, else fill with 0s
%assign i (i + 1)
%endrep
%assign i 0
%rep 9
        vpor    y(i), y(i), [rel sbox_mask_x(i)] ; or the x-masks with the x-values
%assign i (i + 1)
%endrep
        vmovdqa     ymm10, [rel parity_nibble_lut]  ; preload nibble parity LUT
        vpand   y0, y1      ; carry out the AND operations to combine all x-masks
        vpand   y2, y3
        vpand   y4, y5
        vpand   y7, y8
        vpand   y0, y2
        vpand   y4, y6
        vpand   y4, y7
        vpand   y0, y0, [rel sbox_mask_last] ; mask which accounts for setting 1s and 0s in set locations
        vpand   y0, y4
        ;; Horizontal XOR via nibble parity LUT reduction
        vpand       ymm1, y0, [rel nibble_mask]          ; isolate low nibbles
        vpsrlw      ymm0, y0, 4                           ; shift high nibbles down
        vpand       ymm0, ymm0, [rel nibble_mask]         ; isolate high nibbles
        vpshufb     ymm1, ymm10, ymm1                     ; parity of low nibbles (0x00 or 0xFF)
        vpshufb     ymm0, ymm10, ymm0                     ; parity of high nibbles
        vpxor       ymm0, ymm0, ymm1                      ; byte parity
        vpsllw      ymm1, ymm0, 8                         ; replicate byte parity to high byte
        vpxor       y0, ymm0, ymm1                        ; word parity in MSB of each word

        vpmovmskb   r10, y0
        pext        rax, r10, [rel pext_odd_bytes_mask]
%endmacro

;; arg1: data
;; arg2: key1
;; arg3: key2
;; arg4: key3
align_function
MKGLOBAL(kasumi_FI_avx2, function, internal)
kasumi_FI_avx2:
%ifndef LINUX
        sub             rsp, STACK_SIZE
        vmovdqu         [rsp + 0*16], xmm6
        vmovdqu         [rsp + 1*16], xmm7
        vmovdqu         [rsp + 2*16], xmm8
        vmovdqu         [rsp + 3*16], xmm9
        vmovdqu         [rsp + 4*16], xmm10
        vmovdqu         [rsp + 5*16], xmm11
        vmovdqu         [rsp + 6*16], xmm13
%endif

        ;; Kasumi FI: unbalanced Feistel with combined S7/S9 via AVX2
        xor     arg1, arg2                              ;; mix data with key1
        KASUMI_SBOX_AVX2                                ;; 1st S-box pass
        shl     arg1, 7                                 ;; rotate S7 to high positions
        and     arg1, 0x3F80                      ;; place S9 bits in upper positions
        xor     arg1, rax                               ;; merge S9 with S7
        mov     r10, arg1
        shr     r10, 7
        and     r10, 0x7F                               ;; extract high 7-bit field
        xor     arg1, r10                               ;; clear high positions
        ror     WORD(arg3), 9                           ;; rotate key2 for subkey alignment
        xor     arg1, arg3                              ;; mix key2 into state
        KASUMI_SBOX_AVX2                                ;; 2nd S-box pass
        shl     arg1, 7                                 ;; rotate S7 to high positions
        and     arg1, 0x3F80                      ;; place S9 bits in upper positions
        xor     rax, arg1                               ;; merge S9 with S7
        mov     r10, rax
        shr     r10, 7
        and     r10, 0x7F                               ;; extract high 7-bit field
        xor     rax, r10                                ;; clear high positions
        ror     ax, 7                                   ;; rotate S7/S9 into final positions
        xor     rax, arg4                               ;; mix with key3

        vzeroall
%ifndef LINUX
        vmovdqu         xmm6,  [rsp + 0*16]
        vmovdqu         xmm7,  [rsp + 1*16]
        vmovdqu         xmm8,  [rsp + 2*16]
        vmovdqu         xmm9,  [rsp + 3*16]
        vmovdqu         xmm10, [rsp + 4*16]
        vmovdqu         xmm11, [rsp + 5*16]
        vmovdqu         xmm13, [rsp + 6*16]
        add             rsp, STACK_SIZE
%endif

        ret
