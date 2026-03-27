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
%include "include/align_avx512.inc"

extern sbox_mask_x0, sbox_mask_x1, sbox_mask_x2, sbox_mask_x3
extern sbox_mask_x4, sbox_mask_x5, sbox_mask_x6, sbox_mask_x7
extern sbox_mask_x8, sbox_mask_last

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
%define     permute_bytes_input_(x) permute_bytes_input_ %+ x
%define     permute_words_input_(x) permute_words_input_ %+ x

;; ============================================================================
;; GP register definitions for kasumi_1_block_avx512
;;
;; Inputs (aliased to calling convention registers):
%define KS      arg1           ; pointer into key schedule (advances each round)
%define DPTR    arg2           ; pointer to data block (constant throughout)
%define TMPH    r13            ; temp_h (16-bit value in low word)
%define TMPL    r14            ; temp_l (16-bit value in low word)
%define STATE   r11            ; FI Feistel state accumulator (survives sbox)
;;
;; Scratch (clobbered by macros):
%define TMP0    rax            ; S-box output / general scratch
%define TMP1    r10            ; S-box input / general scratch
%define TMP2    r15            ; FL scratch

%define DPTR0   arg3
%define DPTR2   arg4
%define DPTR4   rbx
%define DPTR6   r12

;; ============================================================================

;; Preloaded YMM/k constants (survive across sbox macro calls):
%define YPERMW  ymm0       ; vpermw_mask   (word permutation indices for 2nd sbox pass)
%define YPERMB  ymm1       ; vpermb_mask   (byte permutation indices for 1st sbox pass)
%define YLSB    ymm12      ; least_sig_bit_word (LSB-per-word test mask)
%define KMASK7  k4         ; kmask_s7      (low 7 bits mask for S7 isolation)

;; Stack frame for kasumi_1_block_avx512
;; Windows: 5 pushes + ret = 48, sub rsp, 144 => total = 192, 192 mod 16 = 0
%ifndef LINUX
%define BLK_STACK_SIZE  144
%define BLK_XMM_OFFSET  32      ; 32 (shadow space)
%endif

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
        vpandd      y0, y0, [rel sbox_mask_last]
        vpopcntw    y0, y0
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
        vpandd      y0, y0, [rel sbox_mask_last]
        vpopcntw    y0, y0
%endmacro

;; ============================================================================
;; KASUMI_FI_AVX512 - Inline FI sub-function
;;
;; FI is a 16-bit unbalanced Feistel structure:
;;   Input:  16-bit value split as l0[9] || r0[7]
;;   Round 1: r1 = S9[l0] ^ ZE(r0),  l1 = S7[r0] ^ LS7(r1)
;;   Key mix: l2[7] || r2[9] = (l1 || r1) ^ KIi,j
;;   Round 2: r3 = S9[r2] ^ ZE(l2),  l3 = S7[l2] ^ LS7(r3)
;;   Output:  l3[7] || r3[9]
;;
;; where ZE() = zero-extend 7->9 bits, LS7() = least significant 7 bits.
;; The S7/S9 S-box evaluations use bitsliced AVX-512 Boolean equations.
;;
;; %1 (data)    = 32-bit register holding data input (upper 16 bits zero)
;; %2 (key1_off)  = byte offset into key_sched for key1 (uint16_t)
;; %3 (key2_off)  = byte offset into key_sched for key2 (uint16_t)
;; %4 (key3)    = 32-bit register holding key3 (upper 16 bits zero)
;; %5 (result)  = 32-bit register to receive zero-extended 16-bit result
;; Clobbers: TMP0, TMP1, STATE, ymm2-ymm11, k1, k2, k6
;; ============================================================================
%macro KASUMI_FI_AVX512 5
%define %%data     %1
%define %%key1_off %2
%define %%key2_off %3
%define %%key3     %4
%define %%result   %5

        ;; --- FI Round 1: (data ^ KOi,j) -> S9/S7 -> l1||r1 ---
        ;; STATE = FI_input ^ KOi,j  (= l0[9] || r0[7])
        movzx   DWORD(TMP0), word [KS + %%key1_off]      ; KOi,j
        mov     DWORD(STATE), %%data
        xor     DWORD(STATE), DWORD(TMP0)

        ;; Bitslice STATE into ymm10 and evaluate S9/S7 (1st pass)
        kmovd       k1, DWORD(STATE)
        vpmovm2b    ymm10, k1                           ; expand bits to byte mask
        KASUMI_SBOX_AVX512a                              ; S9[l0] and S7[r0]

        ;; Feistel cross: r1 = S9[l0] ^ ZE(r0), l1 = S7[r0] ^ LS7(r1)
        vpermb      ymm10, YPERMB, ymm10                ; rearrange l0/r0 for cross
        vpxord      ymm10, ymm10, ymm2                  ; XOR with S-box output
        vpermw      ymm3 {KMASK7}{z}, YPERMW, ymm10     ; isolate and align halves
        vpxord      ymm10, ymm10, ymm3                  ; l1[7] || r1[9]

        ;; --- FI key mix: l2||r2 = (l1||r1) ^ KIi,j ---
        movzx   DWORD(TMP1), word [KS + %%key2_off]      ; KIi,j
        ror     WORD(TMP1), 9                            ; align KIi,j halves to l[7]||r[9] layout
        kmovd       k6, DWORD(TMP1)
        vpmovm2w    ymm11, k6
        vpxord      ymm10, ymm10, ymm11                 ; l2[7] || r2[9]

        ;; --- FI Round 2: l2||r2 -> S9/S7 -> l3||r3 ---
        vptestmw    k2, ymm10, YLSB                      ; k2 = l2||r2 LSBs
        vpmovm2w    ymm10, k2
        KASUMI_SBOX_AVX512b                              ; S9[r2] and S7[l2]

        ;; Extract FI output: reassemble l3[7] || r3[9]
        vptestmw    k1, ymm2, YLSB                      ; k1 = S-box output LSBs
        kmovd       DWORD(STATE), k2                    ; r2 bits (from round 2 input)
        kmovd       DWORD(%%result), k1                 ; S-box output bits

        ror         WORD(%%result), 7                   ; pack into l3[7] || r3[9]
        and         DWORD(STATE), 0x7F
        xor         DWORD(%%result), DWORD(STATE)       ; r3 = S9[r2] ^ ZE(l2)
        mov         DWORD(STATE), DWORD(%%result)
        and         DWORD(STATE), 0x7F
        shl         DWORD(STATE), 9
        xor         DWORD(%%result), DWORD(STATE)       ; l3 = S7[l2] ^ LS7(r3)
        xor         DWORD(%%result), %%key3              ; fused FO XOR: ^= r_{j-1}
%endmacro

;; ============================================================================
;; FLp1 - Inline FL sub-function
;;
;; FL is a key-dependent linear mixing function.
;; Per the spec (with L = left 16 bits, R = right 16 bits):
;;   R' = R ^ ROL16(L AND KLi,1, 1)
;;   L' = L ^ ROL16(R' OR KLi,2, 1)
;;
;; Expected register state on entry:
;;   KS   - pointer to current round's 8 subkeys (uint16_t[8])
;;   TMPH - 16-bit temp_h value in low word
;;   TMPL - 16-bit temp_l value in low word
;;   DPTR - pointer to data block (not used directly, preserved)
;;
;; Register mapping: TMPL = L (left), TMPH = R (right)
;;   KLi,1 = key_sched[0], KLi,2 = key_sched[1]
;;
;; Clobbers: TMP0, TMP1, TMP2
;; ============================================================================
%macro FLp1 1
        movzx   DWORD(TMP0), word [KS + %1 + 0]         ; KLi,1

        ;; R' = R ^ ROL16(L AND KLi,1, 1)
        mov     DWORD(TMP2), DWORD(TMPL)
        and     DWORD(TMP2), DWORD(TMP0)                 ; L AND KLi,1
        rol     WORD(TMP2), 1                            ; ROL16(..., 1)
        xor     DWORD(TMP2), DWORD(TMPH)                 ; R' = R ^ ROL16(L AND KLi,1, 1)

        ;; L' = L ^ ROL16(R' OR KLi,2, 1)
        movzx   DWORD(TMPH), word [KS + %1 + 2]          ; KLi,2
        or      DWORD(TMPH), DWORD(TMP2)                 ; R' OR KLi,2
        rol     WORD(TMPH), 1                            ; ROL16(..., 1)
        xor     DWORD(TMPH), DWORD(TMPL)                 ; L' = L ^ ROL16(R' OR KLi,2, 1)

        ;; Output: TMPH = L', TMPL = R'
        mov     DWORD(TMPL), DWORD(TMP2)                 ; TMPL = R'
%endmacro

;; ============================================================================
;; FOp1 - FO sub-function
;;
;; FO is a 32-bit three-round Feistel:
;;   For j = 1, 2, 3:
;;     r_j = FI(l_{j-1} ^ KOi,j, KIi,j) ^ r_{j-1}
;;     l_j = r_{j-1}
;;   Output = l3 || r3
;;
;; The FO Feistel XOR (^ r_{j-1}) is fused into the FI macro.
;;
;; Register mapping: TMPH = left half, TMPL = right half
;; Subkeys per round: KOi,j at key_sched[2j], KIi,j at key_sched[2j+1]
;; Clobbers: TMP0, TMP1, STATE, ymm2-ymm14, k1, k2, k6
;; ============================================================================
%macro FOp1 1
        ;; j=1: r1 = FI(l0 ^ KOi,1, KIi,1) ^ r0;  l1 = r0
        KASUMI_FI_AVX512 DWORD(TMPH), {%1 + 4},  {%1 + 6},  DWORD(TMPL), TMPH
        ;; j=2: r2 = FI(l1 ^ KOi,2, KIi,2) ^ r1;  l2 = r1
        KASUMI_FI_AVX512 DWORD(TMPL), {%1 + 8},  {%1 + 10}, DWORD(TMPH), TMPL
        ;; j=3: r3 = FI(l2 ^ KOi,3, KIi,3) ^ r2;  l3 = r2
        KASUMI_FI_AVX512 DWORD(TMPH), {%1 + 12}, {%1 + 14}, DWORD(TMPL), TMPH
%endmacro

;; ============================================================================
;; kasumi_1_block_avx512(const uint16_t *key_sched, uint16_t *data)
;;
;; 64-bit block cipher with 8 rounds. Per the spec:
;;   For i = 1, 3, 5, 7 (odd):  F_i = FO_i(FL_i(L_{i-1}))
;;   For i = 2, 4, 6, 8 (even): F_i = FL_i(FO_i(L_{i-1}))
;; where L_i = F_i ^ R_{i-1},  R_i = L_{i-1}
;;
;; The data block is treated as four 16-bit words: D[0]||D[1]||D[2]||D[3]
;; where D[0]||D[1] = left 32 bits, D[2]||D[3] = right 32 bits.
;;
;; Each round consumes 8 subkeys (KLi,1-2; KOi,1-3; KIi,1-3) = 16 bytes.
;; S-box substitutions use constant-time bitsliced AVX-512 Boolean equations.
;;
;; Parameters:
;;   arg1 = const uint16_t *key_sched  (64 x uint16_t = 128 bytes)
;;   arg2 = uint16_t *data             (64-bit block, 4 x uint16_t, in-place)
;; ============================================================================
align_function
MKGLOBAL(kasumi_1_block_avx512, function, internal)
kasumi_1_block_avx512:
        ;; Save callee-saved GPRs
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15

%ifndef LINUX
        sub     rsp, BLK_STACK_SIZE

        ;; Save non-volatile XMM registers (Windows)
        vmovdqu [rsp + BLK_XMM_OFFSET + 0*16], xmm6
        vmovdqu [rsp + BLK_XMM_OFFSET + 1*16], xmm7
        vmovdqu [rsp + BLK_XMM_OFFSET + 2*16], xmm8
        vmovdqu [rsp + BLK_XMM_OFFSET + 3*16], xmm9
        vmovdqu [rsp + BLK_XMM_OFFSET + 4*16], xmm10
        vmovdqu [rsp + BLK_XMM_OFFSET + 5*16], xmm11
        vmovdqu [rsp + BLK_XMM_OFFSET + 6*16], xmm12
%endif

        ;; KS = arg1 = key schedule pointer (advances each round)
        ;; DPTR = arg2 = data pointer (constant)

        ;; Preload constants that survive across all sbox evaluations
        kmovd       KMASK7, [rel kmask_s7]               ; S7 isolation mask (low 7 bits)
        vmovdqa     YPERMB, [rel vpermb_mask]             ; byte permutation for 1st sbox
        vmovdqa     YPERMW, [rel vpermw_mask]             ; word permutation for 2nd sbox
        vmovdqa     YLSB, [rel least_sig_bit_word]       ; LSB-per-word test mask


        ;; Load 64-bit data block as four 16-bit words: D[0..3]
        movzx   DWORD(DPTR0), word [DPTR + 0]   ; D[0]
        movzx   DWORD(DPTR2), word [DPTR + 2]   ; D[1]
        movzx   DWORD(DPTR4), word [DPTR + 4]   ; D[2]
        movzx   DWORD(DPTR6), word [DPTR + 6]   ; D[3]


        ;; =============================================================
        ;; Round 1 (odd): D[0]||D[1] ^= FO_1(FL_1(D[2]||D[3]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR4)          ; right half = D[2]
        mov   DWORD(TMPL), DWORD(DPTR6)          ; D[3]

        FLp1 0*16
        FOp1 0*16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 2 (even): D[2]||D[3] ^= FL_2(FO_2(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1 1*16
        FLp1 1*16

        xor     DWORD(DPTR6), DWORD(TMPH)        ; D[3] ^= L'
        xor     DWORD(DPTR4), DWORD(TMPL)        ; D[2] ^= R'

        ;; =============================================================
        ;; Round 3 (odd): D[0]||D[1] ^= FO_3(FL_3(D[2]||D[3]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR4)          ; right half = D[2]
        mov   DWORD(TMPL), DWORD(DPTR6)          ; D[3]

        FLp1 2*16
        FOp1 2*16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 4 (even): D[2]||D[3] ^= FL_4(FO_4(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1 3*16
        FLp1 3*16

        xor     DWORD(DPTR6), DWORD(TMPH)        ; D[3] ^= L'
        xor     DWORD(DPTR4), DWORD(TMPL)        ; D[2] ^= R'

        ;; =============================================================
        ;; Round 5 (odd): D[0]||D[1] ^= FO_5(FL_5(D[2]||D[3]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR4)          ; right half = D[2]
        mov   DWORD(TMPL), DWORD(DPTR6)          ; D[3]

        FLp1 4*16
        FOp1 4*16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 6 (even): D[2]||D[3] ^= FL_6(FO_6(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1 5*16
        FLp1 5*16

        xor     DWORD(DPTR6), DWORD(TMPH)        ; D[3] ^= L'
        xor     DWORD(DPTR4), DWORD(TMPL)        ; D[2] ^= R'

        ;; =============================================================
        ;; Round 7 (odd): D[0]||D[1] ^= FO_7(FL_7(D[2]||D[3]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR4)          ; right half = D[2]
        mov   DWORD(TMPL), DWORD(DPTR6)          ; D[3]

        FLp1 6*16
        FOp1 6*16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 8 (even): D[2]||D[3] ^= FL_8(FO_8(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1 7*16
        FLp1 7*16

        xor     DWORD(DPTR6), DWORD(TMPH)        ; D[3] ^= L'
        xor     DWORD(DPTR4), DWORD(TMPL)        ; D[2] ^= R'

        ;; Store result: D[0]||D[1]||D[2]||D[3]
        mov   [DPTR + 0], WORD(DPTR0)
        mov   [DPTR + 2], WORD(DPTR2)
        mov   [DPTR + 4], WORD(DPTR4)
        mov   [DPTR + 6], WORD(DPTR6)

        vzeroall                                 ; single vzeroall at the end

%ifndef LINUX
        ;; Restore non-volatile XMM registers (Windows)
        vmovdqu xmm6,  [rsp + BLK_XMM_OFFSET + 0*16]
        vmovdqu xmm7,  [rsp + BLK_XMM_OFFSET + 1*16]
        vmovdqu xmm8,  [rsp + BLK_XMM_OFFSET + 2*16]
        vmovdqu xmm9,  [rsp + BLK_XMM_OFFSET + 3*16]
        vmovdqu xmm10, [rsp + BLK_XMM_OFFSET + 4*16]
        vmovdqu xmm11, [rsp + BLK_XMM_OFFSET + 5*16]
        vmovdqu xmm12, [rsp + BLK_XMM_OFFSET + 6*16]

        add     rsp, BLK_STACK_SIZE
%endif

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx

        ret

mksection stack-noexec
