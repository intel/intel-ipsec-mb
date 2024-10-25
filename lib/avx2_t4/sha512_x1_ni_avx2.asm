;;
;; Copyright (c) 2023-2024, Intel Corporation
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

;; ===========================================================
;; NOTE about comment format:
;;
;;      ymm = a b c d
;;           ^       ^
;;           |       |
;;      MSB--+       +--LSB
;;
;;      a - most significant word in `ymm`
;;      d - least significant word in `ymm`
;; ===========================================================

%use smartalign

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/reg_sizes.inc"

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rdx
%define arg4	rcx
%else
%define arg1	rcx
%define arg2	rdx
%define arg3	r8
%define arg4	r9
%endif

%define arg_hash        arg1
%define arg_msg         arg2
%define arg_num_blks    arg3

MKGLOBAL(SHA512_K_AVX,data,internal)
align 64
SHA512_K_AVX:
       dq      0x428a2f98d728ae22,0x7137449123ef65cd
       dq      0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
       dq      0x3956c25bf348b538,0x59f111f1b605d019
       dq      0x923f82a4af194f9b,0xab1c5ed5da6d8118
       dq      0xd807aa98a3030242,0x12835b0145706fbe
       dq      0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
       dq      0x72be5d74f27b896f,0x80deb1fe3b1696b1
       dq      0x9bdc06a725c71235,0xc19bf174cf692694
       dq      0xe49b69c19ef14ad2,0xefbe4786384f25e3
       dq      0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
       dq      0x2de92c6f592b0275,0x4a7484aa6ea6e483
       dq      0x5cb0a9dcbd41fbd4,0x76f988da831153b5
       dq      0x983e5152ee66dfab,0xa831c66d2db43210
       dq      0xb00327c898fb213f,0xbf597fc7beef0ee4
       dq      0xc6e00bf33da88fc2,0xd5a79147930aa725
       dq      0x06ca6351e003826f,0x142929670a0e6e70
       dq      0x27b70a8546d22ffc,0x2e1b21385c26c926
       dq      0x4d2c6dfc5ac42aed,0x53380d139d95b3df
       dq      0x650a73548baf63de,0x766a0abb3c77b2a8
       dq      0x81c2c92e47edaee6,0x92722c851482353b
       dq      0xa2bfe8a14cf10364,0xa81a664bbc423001
       dq      0xc24b8b70d0f89791,0xc76c51a30654be30
       dq      0xd192e819d6ef5218,0xd69906245565a910
       dq      0xf40e35855771202a,0x106aa07032bbd1b8
       dq      0x19a4c116b8d2d0c8,0x1e376c085141ab53
       dq      0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
       dq      0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
       dq      0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
       dq      0x748f82ee5defb2fc,0x78a5636f43172f60
       dq      0x84c87814a1f0ab72,0x8cc702081a6439ec
       dq      0x90befffa23631e28,0xa4506cebde82bde9
       dq      0xbef9a3f7b2c67915,0xc67178f2e372532b
       dq      0xca273eceea26619c,0xd186b8c721c0c207
       dq      0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
       dq      0x06f067aa72176fba,0x0a637dc5a2c898a6
       dq      0x113f9804bef90dae,0x1b710b35131c471b
       dq      0x28db77f523047d84,0x32caab7b40c72493
       dq      0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
       dq      0x4cc5d4becb3e42b6,0x597f299cfc657e2a
       dq      0x5fcb6fab3ad6faec,0x6c44198c4a475817

align 16
SHA512_SHUFF_MASK_AVX:
       dq 0x0001020304050607, 0x08090a0b0c0d0e0f

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha512_update_ni_x1(uint64_t digest[8], const void *input, uint64_t num_blocks)
;; arg1 : [in/out] pointer to hash value
;; arg2 : [in] message pointer
;; arg3 : [in] number of blocks to process

align 32
MKGLOBAL(sha512_update_ni_x1,function,internal)
sha512_update_ni_x1:
        or              arg_num_blks, arg_num_blks
        je              .done_hash

%ifidn __OUTPUT_FORMAT__, win64
        ;; xmm6:xmm9, xmm11:xmm15 need to be maintained for Windows
        ;; xmm10 not used
        sub             rsp, 9*16
        vmovdqu         [rsp + 0*16], xmm6
        vmovdqu         [rsp + 1*16], xmm7
        vmovdqu         [rsp + 2*16], xmm8
        vmovdqu         [rsp + 3*16], xmm9
        vmovdqu         [rsp + 4*16], xmm11
        vmovdqu         [rsp + 5*16], xmm12
        vmovdqu         [rsp + 6*16], xmm13
        vmovdqu         [rsp + 7*16], xmm14
        vmovdqu         [rsp + 8*16], xmm15
%endif
        vbroadcasti128  ymm15, [rel SHA512_SHUFF_MASK_AVX]

        ;; load current hash value and transform
        vmovdqu         ymm0, [arg_hash]
        vmovdqu         ymm1, [arg_hash + 32]
        ;; ymm0 = D C B A, ymm1 = H G F E
        vperm2i128      ymm2, ymm0, ymm1, 0x20
        vperm2i128      ymm3, ymm0, ymm1, 0x31
        ;; ymm2 = F E B A, ymm3 = H G D C
        vpermq          ymm13, ymm2, 0x1b
        vpermq          ymm14, ymm3, 0x1b
        ;; ymm13 = A B E F, ymm14 = C D G H

        lea             rax, [rel SHA512_K_AVX]
align 32
.block_loop:
        vmovdqa         ymm11, ymm13    ;; ABEF
        vmovdqa         ymm12, ymm14    ;; CDGH

        ;; R0 - R3
        vmovdqu         ymm0, [arg_msg + 0 * 32]
        vpshufb         ymm3, ymm0, ymm15               ;; ymm0/ymm3 = W[0..3]
        vpaddq          ymm0, ymm3, [rax + 0 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; R4 - R7
        vmovdqu         ymm0, [arg_msg + 1 * 32]
        vpshufb         ymm4, ymm0, ymm15               ;; ymm0/ymm4 = W[4..7]
        vpaddq          ymm0, ymm4, [rax + 1 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm3, xmm4                      ;; ymm3 = W[0..3] + S0(W[1..4])

        ;; R8 - R11
        vmovdqu         ymm0, [arg_msg + 2 * 32]
        vpshufb         ymm5, ymm0, ymm15               ;; ymm0/ymm5 = W[8..11]
        vpaddq          ymm0, ymm5, [rax + 2 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm4, xmm5                      ;; ymm4 = W[4..7] + S0(W[5..8])

        ;; R12 - R15
        vmovdqu         ymm0, [arg_msg + 3 * 32]
        vpshufb         ymm6, ymm0, ymm15               ;; ymm0/ymm6 = W[12..15]
        vpaddq          ymm0, ymm6, [rax + 3 * 32]
        vpermq          ymm8, ymm6, 0x1b                ;; ymm8 = W[12] W[13] W[14] W[15]
        vpermq          ymm9, ymm5, 0x39                ;; ymm9 = W[8]  W[11] W[10] W[9]
        vpblendd        ymm8, ymm8, ymm9, 0x3f          ;; ymm8 = W[12] W[11] W[10] W[9]
        vpaddq          ymm3, ymm3, ymm8
        vsha512msg2     ymm3, ymm6                      ;; W[16..19] = ymm3 + W[9..12] + S1(W[14..17])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm5, xmm6                      ;; ymm5 = W[8..11] + S0(W[9..12])

%assign I 4

%rep 3
        ;; R16 - R19, R32 - R35, R48 - R51
        vpaddq          ymm0, ymm3, [rax + I * 32]
        vpermq          ymm8, ymm3, 0x1b                ;; ymm8 = W[16] W[17] W[18] W[19]
        vpermq          ymm9, ymm6, 0x39                ;; ymm9 = W[12] W[15] W[14] W[13]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[16] W[15] W[14] W[13]
        vpaddq          ymm4, ymm4, ymm7                ;; ymm4 = W[4..7] + S0(W[5..8]) + W[13..16]
        vsha512msg2     ymm4, ymm3                      ;; ymm4 += S1(W[14..17])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm6, xmm3                      ;; ymm6 = W[12..15] + S0(W[13..16])
%assign I (I + 1)

        ;; R20 - R23, R36 - R39, R52 - R55
        vpaddq          ymm0, ymm4, [rax + I * 32]
        vpermq          ymm8, ymm4, 0x1b                ;; ymm8 = W[20] W[21] W[22] W[23]
        vpermq          ymm9, ymm3, 0x39                ;; ymm9 = W[16] W[19] W[18] W[17]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[20] W[19] W[18] W[17]
        vpaddq          ymm5, ymm5, ymm7                ;; ymm5 = W[8..11] + S0(W[9..12]) + W[17..20]
        vsha512msg2     ymm5, ymm4                      ;; ymm5 += S1(W[18..21])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm3, xmm4                      ;; ymm3 = W[16..19] + S0(W[17..20])
%assign I (I + 1)

        ;; R24 - R27, R40 - R43, R56 - R59
        vpaddq          ymm0, ymm5, [rax + I * 32]
        vpermq          ymm8, ymm5, 0x1b                ;; ymm8 = W[24] W[25] W[26] W[27]
        vpermq          ymm9, ymm4, 0x39                ;; ymm9 = W[20] W[23] W[22] W[21]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[24] W[23] W[22] W[21]
        vpaddq          ymm6, ymm6, ymm7                ;; ymm6 = W[12..15] + S0(W[13..16]) + W[21..24]
        vsha512msg2     ymm6, ymm5                      ;; ymm6 += S1(W[22..25])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm4, xmm5                      ;; ymm4 = W[20..23] + S0(W[21..24])
%assign I (I + 1)

        ;; R28 - R31, R44 - R47, R60 - R63
        vpaddq          ymm0, ymm6, [rax + I * 32]
        vpermq          ymm8, ymm6, 0x1b                ;; ymm8 = W[28] W[29] W[30] W[31]
        vpermq          ymm9, ymm5, 0x39                ;; ymm9 = W[24] W[27] W[26] W[25]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[28] W[27] W[26] W[25]
        vpaddq          ymm3, ymm3, ymm7                ;; ymm3 = W[16..19] + S0(W[17..20]) + W[25..28]
        vsha512msg2     ymm3, ymm6                      ;; ymm3 += S1(W[26..29])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm5, xmm6                      ;; ymm5 = W[24..27] + S0(W[25..28])
%assign I (I + 1)
%endrep

        ;; R64 - R67
        vpaddq          ymm0, ymm3, [rax + 16 * 32]
        vpermq          ymm8, ymm3, 0x1b                ;; ymm8 = W[64] W[65] W[66] W[67]
        vpermq          ymm9, ymm6, 0x39                ;; ymm9 = W[60] W[63] W[62] W[61]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[64] W[63] W[62] W[61]
        vpaddq          ymm4, ymm4, ymm7                ;; ymm4 = W[52..55] + S0(W[53..56]) + W[61..64]
        vsha512msg2     ymm4, ymm3                      ;; ymm4 += S1(W[62..65])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm6, xmm3                      ;; ymm6 = W[60..63] + S0(W[61..64])

        ;; R68 - R71
        vpaddq          ymm0, ymm4, [rax + 17 * 32]
        vpermq          ymm8, ymm4, 0x1b                ;; ymm8 = W[68] W[69] W[70] W[71]
        vpermq          ymm9, ymm3, 0x39                ;; ymm9 = W[64] W[67] W[66] W[65]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[68] W[67] W[66] W[65]
        vpaddq          ymm5, ymm5, ymm7                ;; ymm5 = W[56..59] + S0(W[57..60]) + W[65..68]
        vsha512msg2     ymm5, ymm4                      ;; ymm5 += S1(W[66..69])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; R72 - R75
        vpaddq          ymm0, ymm5, [rax + 18 * 32]
        vpermq          ymm8, ymm5, 0x1b                ;; ymm8 = W[72] W[73] W[74] W[75]
        vpermq          ymm9, ymm4, 0x39                ;; ymm9 = W[68] W[71] W[70] W[69]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[72] W[71] W[70] W[69]
        vpaddq          ymm6, ymm6, ymm7                ;; ymm6 = W[60..63] + S0(W[61..64]) + W[69..72]
        vsha512msg2     ymm6, ymm5                      ;; ymm6 += S1(W[70..73])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; R76 - R79
        vpaddq          ymm0, ymm6, [rax + 19 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; update hash value
        vpaddq          ymm14, ymm14, ymm12
        vpaddq          ymm13, ymm13, ymm11
        add             arg_msg, 4 * 32
        dec             arg_num_blks
        jnz             .block_loop

        ;; store the hash value back in memory
        ;;     ymm13 = ABEF
        ;;     ymm14 = CDGH
        vperm2i128      ymm1, ymm13, ymm14, 0x31
        vperm2i128      ymm2, ymm13, ymm14, 0x20
        vpermq          ymm1, ymm1, 0xb1        ;; ymm1 = D C B A
        vpermq          ymm2, ymm2, 0xb1        ;; ymm2 = H G F E
        vmovdqu         [arg_hash + 0*32], ymm1
        vmovdqu         [arg_hash + 1*32], ymm2

        vzeroupper

%ifidn __OUTPUT_FORMAT__, win64
        ;; xmm6:xmm9, xmm11:xmm15 need to be maintained for Windows
        ;; xmm10 not used
        vmovdqu         xmm6, [rsp + 0*16]
        vmovdqu         xmm7, [rsp + 1*16]
        vmovdqu         xmm8, [rsp + 2*16]
        vmovdqu         xmm9, [rsp + 3*16]
        vmovdqu         xmm11, [rsp + 4*16]
        vmovdqu         xmm12, [rsp + 5*16]
        vmovdqu         xmm13, [rsp + 6*16]
        vmovdqu         xmm14, [rsp + 7*16]
        vmovdqu         xmm15, [rsp + 8*16]
        add             rsp, 9*16
%endif

.done_hash:

	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha512_ni_block_avx2(const void *input, uint64_t digest[8])
;; arg1 : [in] message pointer
;; arg2 : [in/out] pointer to hash value

align 32
MKGLOBAL(sha512_ni_block_avx2,function,internal)
sha512_ni_block_avx2:
        mov     rax, arg1
        mov     arg1, arg2
        mov     arg2, rax
        mov     DWORD(arg3), 1
        jmp     sha512_update_ni_x1

mksection stack-noexec
