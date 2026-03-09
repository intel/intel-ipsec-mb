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

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/cet.inc"
%include "include/constant_lookup.inc"
%include "include/align_avx512.inc"

extern sbox_mask_x0, sbox_mask_x1, sbox_mask_x2, sbox_mask_x3
extern sbox_mask_x4, sbox_mask_x5, sbox_mask_x6, sbox_mask_x7
extern sbox_mask_x8, sbox_mask_last, high_7

mksection .rodata
default rel

align 32
;; Masks used in 1st AVX512 S-box calculation. Permute bytes of register so that in iteration i,
;; the ith input bit is present as the lowest bit of each of the low 7 words
;; and the (i+7)th input bit is present as the lowest bit of each of the high 9 words
permute_bytes_input_0  dq  0x0000000000000000, 0x0707000000000000, 0x0707070707070707, 0x0707070707070707
permute_bytes_input_1  dq  0x0101010101010101, 0x0808010101010101, 0x0808080808080808, 0x0808080808080808
permute_bytes_input_2  dq  0x0202020202020202, 0x0909020202020202, 0x0909090909090909, 0x0909090909090909
permute_bytes_input_3  dq  0x0303030303030303, 0x0a0a030303030303, 0x0a0a0a0a0a0a0a0a, 0x0a0a0a0a0a0a0a0a
permute_bytes_input_4  dq  0x0404040404040404, 0x0b0b040404040404, 0x0b0b0b0b0b0b0b0b, 0x0b0b0b0b0b0b0b0b
permute_bytes_input_5  dq  0x0505050505050505, 0x0c0c050505050505, 0x0c0c0c0c0c0c0c0c, 0x0c0c0c0c0c0c0c0c
permute_bytes_input_6  dq  0x0606060606060606, 0x0d0d060606060606, 0x0d0d0d0d0d0d0d0d, 0x0d0d0d0d0d0d0d0d
permute_bytes_input_7  dq  0xffffffffffffffff, 0x0e0effffffffffff, 0x0e0e0e0e0e0e0e0e, 0x0e0e0e0e0e0e0e0e
permute_bytes_input_8  dq  0xffffffffffffffff, 0x0f0fffffffffffff, 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f

align 32
;; Masks used in 2nd AVX512 S-box calculation. Permute words of register so that in iteration i,
;; the ith input bit is present as the lowest bit of each of the low 7 words
;; and the (i+7)th input bit is present as the lowest bit of each of the high 9 words
permute_words_input_0  dq  0x0000000000000000, 0x0007000000000000, 0x0007000700070007, 0x0007000700070007
permute_words_input_1  dq  0x0001000100010001, 0x0008000100010001, 0x0008000800080008, 0x0008000800080008
permute_words_input_2  dq  0x0002000200020002, 0x0009000200020002, 0x0009000900090009, 0x0009000900090009
permute_words_input_3  dq  0x0003000300030003, 0x000a000300030003, 0x000a000a000a000a, 0x000a000a000a000a
permute_words_input_4  dq  0x0004000400040004, 0x000b000400040004, 0x000b000b000b000b, 0x000b000b000b000b
permute_words_input_5  dq  0x0005000500050005, 0x000c000500050005, 0x000c000c000c000c, 0x000c000c000c000c
permute_words_input_6  dq  0x0006000600060006, 0x000d000600060006, 0x000d000d000d000d, 0x000d000d000d000d
permute_words_input_7  dq  0xffffffffffffffff, 0x000effffffffffff, 0x000e000e000e000e, 0x000e000e000e000e
permute_words_input_8  dq  0xffffffffffffffff, 0x000fffffffffffff, 0x000f000f000f000f, 0x000f000f000f000f

align 32
least_sig_bit_word dq 0x0001000100010001, 0x0001000100010001, 0x0001000100010001, 0x0001000100010001
vpermb_mask        dq 0x1010101010101010, 0x0000101010101010, 0x0404030302020101, 0x1010101006060505
vpermw_mask        dq 0x000a000900080007, 0x000f000d000c000b, 0x000f000f000f000f, 0x000f000f000f000f

align 8
kmask_s7      dq  0x7F

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

%define     x0    xmm2
%define     x1    xmm3
%define     x2    xmm4
%define     x3    xmm5
%define     x4    xmm6
%define     x5    xmm7
%define     x6    xmm8
%define     x7    xmm9
%define     x8    xmm11
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

%define     x(n)  x %+ n
%define     x_mask(n)   x %+ n %+_mask
%define     permute_bytes_input_(x) permute_bytes_input_ %+ x
%define     permute_words_input_(x) permute_words_input_ %+ x

;; Number of non-volatile XMM/YMM registers saved on Windows (xmm6-xmm11, xmm13)
%define XMM_SAVES 7
%define STACK_SIZE (XMM_SAVES * 16)

;; KASUMI_SBOX_AVX512a
;; Computes the combined Kasumi S7/S9 S-box substitution using AVX-512
;; byte-granularity permutation (VPERMB).
;;
;; The input value is expected in ymm10 as a byte mask created by loading the
;; input bits into a mask register and then using VPMOVM2B to set
;; each byte in ymm10 to match the corresponding input bit.
;; VPERMB distributes the relevant input bits across YMM lanes so that each
;; iteration's bit appears as the LSB of the corresponding S-box word.
;; The per-bit results are combined with the precomputed Boolean equation
;; constants (sbox_mask_x0..x8) using VPTERNLOGQ (ternary logic: A AND B OR C)
;; then masked with sbox_mask_last. VPOPCNTW counts the set bits per word,
;; producing the parity-based S-box output bits in ymm2.
;;
;; Input:  ymm10 (byte mask of input value)
;; Output: ymm2  (per-word popcount result encoding S-box output bits)
;; Clobbers: ymm2-ymm9, ymm11
%macro KASUMI_SBOX_AVX512a 0
%assign i 0
%rep 9
        vmovdqa     y(i), [rel permute_bytes_input_(i)]
        vpermb      y(i), y(i), ymm10
%assign i (i + 1)
%endrep
        vpor        y0, y0, [rel sbox_mask_x(0)]
%assign i 1
%rep 8
        vpternlogq  y0, y(i), [rel sbox_mask_x(i)], 0xE0
%assign i (i + 1)
%endrep
        vpandd      ymm2, ymm2, [rel sbox_mask_last]
        vpopcntw    ymm2, ymm2
%endmacro

;; KASUMI_SBOX_AVX512b
;; Computes the combined Kasumi S7/S9 S-box substitution using AVX-512
;; word-granularity permutation (VPERMW).
;;
;; This is the second-pass S-box evaluation used after the intermediate key
;; mixing step. The input value is expected in ymm10 as word elements (with
;; only the LSB of each word significant). VPERMW distributes the relevant
;; input bits across YMM lanes, then VPTERNLOGQ combines them with the
;; precomputed Boolean equation constants (sbox_mask_x0..x8). The result is
;; masked with sbox_mask_last and VPOPCNTW produces the parity-based S-box
;; output bits in ymm2.
;;
;; Input:  ymm10 (word elements with LSB-significant input bits)
;; Output: ymm2  (per-word popcount result encoding S-box output bits)
;; Clobbers: ymm2-ymm9, ymm11
%macro KASUMI_SBOX_AVX512b 0
%assign i 0
%rep 9
        vmovdqa     y(i), [rel permute_words_input_(i)]
        vpermw      y(i), y(i), ymm10
%assign i (i + 1)
%endrep
        vpor        y0, y0, [rel sbox_mask_x(0)]
%assign i 1
%rep 8
        vpternlogq  y0, y(i), [rel sbox_mask_x(i)], 0xE0
%assign i (i + 1)
%endrep
        vpandd      ymm2, ymm2, [rel sbox_mask_last]
        vpopcntw    ymm2, ymm2
%endmacro

;; arg1: data
;; arg2: key1
;; arg3: key2
;; arg4: key3
align_function
MKGLOBAL(kasumi_FI_avx512, function, internal)
kasumi_FI_avx512:
        endbranch64
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

        ;; Kasumi FI: unbalanced Feistel with combined S7/S9 via AVX-512

        xor     arg1, arg2                              ;; mix data with key1
        kmovd       k4, [rel kmask_s7]                      ;; k4 = S7 isolation mask (low 7 bits)
        vmovdqa     ymm1, [rel vpermb_mask]
        vmovdqa     ymm0, [rel vpermw_mask]
        kmovd       k1, DWORD(arg1)
        vpmovm2b    ymm10, k1                            ;; expand bits to byte mask
        KASUMI_SBOX_AVX512a                              ;; 1st S-box pass
        vpermb      ymm10, ymm1, ymm10                  ;; rearrange input for Feistel cross-mix
        vpxord      ymm10, ymm10, ymm2                  ;; XOR with S-box output
        vpermw      ymm3 {k4}{z}, ymm0, ymm10           ;; align S9/S7 halves
        vpxord      ymm10, ymm10, ymm3                  ;; complete cross-mix
        ror         WORD(arg3), 9                        ;; rotate key2 for subkey alignment
        kmovd       k6, DWORD(arg3)
        vpmovm2w    ymm11, k6
        vpxord      ymm10, ymm10, ymm11                 ;; mix key2 into state
        vpand       ymm10, ymm10, [rel least_sig_bit_word] ;; isolate LSBs per word
        vpcmpw      k2, ymm10, [rel least_sig_bit_word], 0 ;; save S9 result bits
        vpcmpeqw    ymm10, ymm10, [rel least_sig_bit_word] ;; set words to all-1s/0s for S-box input
        KASUMI_SBOX_AVX512b                              ;; 2nd S-box pass
        vpand       ymm2, ymm2, [rel least_sig_bit_word] ;; isolate LSBs of S-box output
        vpcmpw      k1, ymm2, [rel least_sig_bit_word], 0 ;; save S7 result bits
        kmovd       DWORD(arg1), k2                      ;; S9 bits
        kmovd       eax, k1                              ;; S7 bits
        pdep    arg1, arg1, [rel high_7]                 ;; place S9 bits in upper positions
        xor     rax, arg1                                ;; merge S9 with S7
        pext    r10, rax, [rel high_7]                   ;; extract high 7-bit field
        xor     rax, r10                                 ;; clear high positions
        ror     ax, 7                                    ;; rotate S7/S9 into final positions
        xor     rax, arg4                                ;; mix with key3

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
