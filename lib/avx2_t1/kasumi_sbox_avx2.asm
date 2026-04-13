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
MKGLOBAL(isolate_input_bits_0,data,internal)
MKGLOBAL(isolate_input_bits_1,data,internal)
MKGLOBAL(isolate_input_bits_2,data,internal)
MKGLOBAL(isolate_input_bits_3,data,internal)
MKGLOBAL(isolate_input_bits_4,data,internal)
MKGLOBAL(isolate_input_bits_5,data,internal)
MKGLOBAL(isolate_input_bits_6,data,internal)
MKGLOBAL(isolate_input_bits_7,data,internal)
MKGLOBAL(isolate_input_bits_8,data,internal)

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

;; GP register definitions for kasumi_1_block_avx2
;;
;; Inputs (aliased to calling convention registers):
%define KS       arg1           ; pointer into key schedule (advances each round)
%define DPTR     arg2           ; pointer to data block (constant throughout)
%define TMPH     r13            ; round working register (left/right half)
%define TMPL     r14            ; round working register (right/left half)
%define STATE    r11            ; FI Feistel state accumulator (survives sbox)

;; Data block registers (hold D[0..3] across all 8 rounds):
%ifdef LINUX
%define DPTR0    rdx            ; D[0]
%define DPTR2    rcx            ; D[1]
%else
%define DPTR0    r8             ; D[0]
%define DPTR2    r9             ; D[1]
%endif
%define DPTR4    rbx            ; D[2] (callee-saved)
%define DPTR6    r12            ; D[3] (callee-saved)

;; Scratch (clobbered by macros):
%define TMP0     rax            ; S-box output / general scratch
%define TMP1     r10            ; S-box input / general scratch
%define TMP2     r15            ; FL scratch

;; Stack frame for kasumi_1_block_avx2
%ifndef LINUX
%define BLK_STACK_SIZE  (10 * 16)       ; 10 non-volatile XMM registers x 16 bytes
%endif

;; KASUMI_SBOX_AVX2
;; Computes the combined Kasumi S7 and S9 S-box substitution using a bitsliced
;; AVX2 implementation based on Boolean equations.
;;
;; The 16-bit input value in TMP1 is broadcast across all words of a YMM register.
;; Each input bit is isolated and compared against its expected position to produce
;; an all-ones or all-zeros mask per word. These per-bit masks are OR'd with
;; precomputed S-box Boolean equation constants (sbox_mask_x0..x8), then AND'd
;; together to evaluate the combined S7/S9 output equations. A nibble-parity
;; LUT reduction (via VPSHUFB) collapses each word to a single output bit,
;; and VPMOVMSKB + PEXT extract the 16-bit S-box result into TMP0.
;;
;; Expects ymm10 to be preloaded with the parity_nibble_lut for the LUT reduction step.
;;
;; Input: %%sbox_input (16-bit value in low word)
;; Output: %%sbox_result (16-bit S-box result: S9 in upper 9 bits, S7 in lower 7 bits)
;; Clobbers: ymm0-ymm11, ymm13, TMP1
%macro KASUMI_SBOX_AVX2 2
%define %%sbox_input  %1
%define %%sbox_result %2

        vmovd       xmm13, DWORD(%%sbox_input)      ; load input into low word of xmm13
        vpbroadcastw ymm13, xmm13                   ; broadcast input across all words of ymm13
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
        vpand   y0, y1                              ; carry out the AND operations to combine all x-masks
        vpand   y2, y3
        vpand   y4, y5
        vpand   y7, y8
        vpand   y0, y2
        vpand   y4, y6
        vpand   y4, y7
        vpand   y0, y0, [rel sbox_mask_last] ; mask which accounts for setting 1s and 0s in set locations
        vpand   y0, y4
        ;; Horizontal XOR via nibble parity LUT reduction
        vpand       ymm1, y0, [rel nibble_mask]           ; isolate low nibbles
        vpsrlw      ymm0, y0, 4                           ; shift high nibbles down
        vpand       ymm0, ymm0, [rel nibble_mask]         ; isolate high nibbles
        vpshufb     ymm1, ymm10, ymm1                     ; parity of low nibbles (0x00 or 0xFF)
        vpshufb     ymm0, ymm10, ymm0                     ; parity of high nibbles
        vpxor       ymm0, ymm0, ymm1                      ; byte parity
        vpsllw      ymm1, ymm0, 8                         ; replicate byte parity to high byte
        vpxor       y0, ymm0, ymm1                        ; word parity in MSB of each word

        vpmovmskb   DWORD(TMP1), y0
        pext        %%sbox_result, TMP1, [rel pext_odd_bytes_mask]
%endmacro

;; ============================================================================
;; KASUMI_FI_AVX2 - Inline FI sub-function
;;
;; FI is a 16-bit unbalanced Feistel structure:
;;   Input:  16-bit value split as l0[9] || r0[7]
;;   Round 1: r1 = S9[l0] ^ ZE(r0),  l1 = S7[r0] ^ LS7(r1)
;;   Key mix: l2[7] || r2[9] = (l1 || r1) ^ KIi,j
;;   Round 2: r3 = S9[r2] ^ ZE(l2),  l3 = S7[l2] ^ LS7(r3)
;;   Output:  l3[7] || r3[9]
;;
;; where ZE() = zero-extend 7->9 bits, LS7() = least significant 7 bits.
;; The S7/S9 S-box evaluations use bitsliced AVX2 Boolean equations.
;;
;; %1 (data)      = 64-bit register holding data input (upper 16 bits zero)
;; %2 (key1_off)  = byte offset into key_sched for KOi,j (uint16_t)
;; %3 (key2_off)  = byte offset into key_sched for KIi,j (uint16_t)
;; %4 (key3)      = 64-bit register holding r_{j-1} (upper 16 bits zero)
;; %5 (result)    = 64-bit register to receive zero-extended 16-bit result
;; Clobbers: TMP0, TMP1, STATE, ymm0-ymm11, ymm13
;; ============================================================================
%macro KASUMI_FI_AVX2 5
%define %%data     %1
%define %%key1_off %2
%define %%key2_off %3
%define %%key3     %4
%define %%result   %5

        ;; --- FI Round 1: (data ^ KOi,j) -> S9/S7 -> l1||r1 ---
        ;; STATE = FI_input ^ KOi,j  (= l0[9] || r0[7])
        mov     DWORD(STATE), DWORD(%%data)
        xor     WORD(STATE), word [KS + %%key1_off]     ; ^ KOi,j

        KASUMI_SBOX_AVX2 STATE, TMP0                    ; TMP0 = S-box(STATE);

        ;; Feistel cross: r1 = S9[l0] ^ ZE(r0), l1 = S7[r0] ^ LS7(r1)
        shl     DWORD(STATE), 7                         ; ZE(r0): shift r0[7] up to align with S9[l0]
        and     DWORD(STATE), 0x3F80                    ; isolate ZE(r0) in S9 position [13:7]
        xor     DWORD(STATE), DWORD(TMP0)               ; upper 9 = r1 = S9[l0]^ZE(r0), lower 7 = S7[r0]
        mov     DWORD(TMP0), DWORD(STATE)
        shr     DWORD(TMP0), 7                          ; extract LS7(r1) from upper field
        and     DWORD(TMP0), 0x7F                       ; LS7(r1)
        xor     DWORD(STATE), DWORD(TMP0)               ; lower 7 = l1 = S7[r0] ^ LS7(r1)

        ;; --- FI key mix: l2||r2 = (l1||r1) ^ KIi,j ---
        ;; STATE layout = r1[9]||l1[7]; ROR16(KIi,j, 9) aligns to this layout
        movzx   TMP1, word [KS + %%key2_off]            ; KIi,j
        ror     WORD(TMP1), 9                           ; align KIi,j to r[9]||l[7] layout
        xor     STATE, TMP1                             ; l2[7] || r2[9] (STATE[31:16]=0)

        ;; --- FI Round 2: l2||r2 -> S9/S7 -> l3||r3 ---
        KASUMI_SBOX_AVX2 STATE, %%result                ; %%result = S-box(STATE)

        ;; Feistel cross: r3 = S9[r2] ^ ZE(l2), l3 = S7[l2] ^ LS7(r3)
        shl     DWORD(STATE), 7                         ; ZE(l2): shift l2[7] up to align with S9[r2]
        and     DWORD(STATE), 0x3F80                    ; isolate ZE(l2) in S9 position [13:7]
        xor     DWORD(%%result), DWORD(STATE)           ; upper 9 = r3 = S9[r2]^ZE(l2), lower 7 = S7[l2]
        mov     DWORD(STATE), DWORD(%%result)
        shr     DWORD(STATE), 7                         ; extract LS7(r3) from upper field
        and     DWORD(STATE), 0x7F                      ; LS7(r3)
        xor     DWORD(%%result), DWORD(STATE)           ; lower 7 = l3 = S7[l2] ^ LS7(r3)
        ror     WORD(%%result), 7                       ; pack into l3[7] || r3[9] output layout

        ;; Fused FO XOR: ^= r_{j-1}
        xor     DWORD(%%result), DWORD(%%key3)          ; ^= r_{j-1} (passed as key3)
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
;; Clobbers: TMP2
;; ============================================================================
%macro FLp1 0
        ;; R' = R ^ ROL16(L AND KLi,1, 1)
        movzx   DWORD(TMP2), word [KS + 0]           ; KLi,1 (zero-extended)
        and     DWORD(TMP2), DWORD(TMPL)             ; L AND KLi,1
        rol     WORD(TMP2), 1                        ; ROL16(..., 1)
        xor     DWORD(TMP2), DWORD(TMPH)             ; R' = R ^ ROL16(L AND KLi,1, 1)

        ;; L' = L ^ ROL16(R' OR KLi,2, 1)
        movzx   DWORD(TMPH), word [KS + 2]           ; KLi,2 (zero-extended)
        or      DWORD(TMPH), DWORD(TMP2)             ; R' OR KLi,2
        rol     WORD(TMPH), 1                        ; ROL16(..., 1)
        xor     DWORD(TMPH), DWORD(TMPL)             ; L' = L ^ ROL16(R' OR KLi,2, 1)

        ;; Output: TMPH = L', TMPL = R'
        mov     DWORD(TMPL), DWORD(TMP2)             ; TMPL = R'
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
;; Expected register state on entry:
;;   KS   - pointer to current round's 8 subkeys (uint16_t[8])
;;   TMPH - 16-bit temp_h value in low word
;;   TMPL - 16-bit temp_l value in low word
;;   DPTR - pointer to data block (not used directly, preserved)
;;
;; Register mapping: TMPH = left half, TMPL = right half
;; Subkeys per round: KOi,j at key_sched[2j], KIi,j at key_sched[2j+1]
;; Clobbers: TMP0, TMP1, STATE, ymm0-ymm11, ymm13
;; ============================================================================
%macro FOp1 0
        ;; j=1: r1 = FI(l0 ^ KOi,1, KIi,1) ^ r0;  l1 = r0
        KASUMI_FI_AVX2 TMPH, 4, 6, TMPL, TMPH
        ;; j=2: r2 = FI(l1 ^ KOi,2, KIi,2) ^ r1;  l2 = r1
        KASUMI_FI_AVX2 TMPL, 8, 10, TMPH, TMPL
        ;; j=3: r3 = FI(l2 ^ KOi,3, KIi,3) ^ r2;  l3 = r2
        KASUMI_FI_AVX2 TMPH, 12, 14, TMPL, TMPH
%endmacro

;; ============================================================================
;; kasumi_1_block_avx2(const uint16_t *key_sched, uint16_t *data)
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
;; S-box substitutions use constant-time bitsliced AVX2 Boolean equations.
;;
;; Parameters:
;;   arg1 = const uint16_t *key_sched  (64 x uint16_t = 128 bytes)
;;   arg2 = uint16_t *data             (64-bit block, 4 x uint16_t, in-place)
;; ============================================================================
align_function
MKGLOBAL(kasumi_1_block_avx2, function, internal)
kasumi_1_block_avx2:
        ;; Save callee-saved GPRs
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15

%ifndef LINUX
        sub     rsp, BLK_STACK_SIZE

        ;; Save non-volatile XMM registers (Windows)
        vmovdqu [rsp + 0*16], xmm6
        vmovdqu [rsp + 1*16], xmm7
        vmovdqu [rsp + 2*16], xmm8
        vmovdqu [rsp + 3*16], xmm9
        vmovdqu [rsp + 4*16], xmm10
        vmovdqu [rsp + 5*16], xmm11
        vmovdqu [rsp + 6*16], xmm12
        vmovdqu [rsp + 7*16], xmm13
        vmovdqu [rsp + 8*16], xmm14
        vmovdqu [rsp + 9*16], xmm15
%endif

        ;; KS = arg1 = key schedule pointer (advances each round)
        ;; DPTR = arg2 = data pointer (constant)

        ;; preload nibble parity LUT to persist across all sbox evaluations
        vmovdqa     ymm10, [rel parity_nibble_lut]

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

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 2 (even): D[2]||D[3] ^= FL_2(FO_2(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1
        FLp1

        add     KS, 16

        xor     DWORD(DPTR6), DWORD(TMPH)        ; D[3] ^= L'
        xor     DWORD(DPTR4), DWORD(TMPL)        ; D[2] ^= R'

        ;; =============================================================
        ;; Round 3 (odd): D[0]||D[1] ^= FO_3(FL_3(D[2]||D[3]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR4)          ; right half = D[2]
        mov   DWORD(TMPL), DWORD(DPTR6)          ; D[3]

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 4 (even): D[2]||D[3] ^= FL_4(FO_4(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1
        FLp1

        add     KS, 16

        xor     DWORD(DPTR6), DWORD(TMPH)        ; D[3] ^= L'
        xor     DWORD(DPTR4), DWORD(TMPL)        ; D[2] ^= R'

        ;; =============================================================
        ;; Round 5 (odd): D[0]||D[1] ^= FO_5(FL_5(D[2]||D[3]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR4)          ; right half = D[2]
        mov   DWORD(TMPL), DWORD(DPTR6)          ; D[3]

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 6 (even): D[2]||D[3] ^= FL_6(FO_6(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1
        FLp1

        add     KS, 16

        xor     DWORD(DPTR6), DWORD(TMPH)        ; D[3] ^= L'
        xor     DWORD(DPTR4), DWORD(TMPL)        ; D[2] ^= R'

        ;; =============================================================
        ;; Round 7 (odd): D[0]||D[1] ^= FO_7(FL_7(D[2]||D[3]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR4)          ; right half = D[2]
        mov   DWORD(TMPL), DWORD(DPTR6)          ; D[3]

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)        ; D[1] ^= R'
        xor     DWORD(DPTR0), DWORD(TMPH)        ; D[0] ^= L'

        ;; =============================================================
        ;; Round 8 (even): D[2]||D[3] ^= FL_8(FO_8(D[0]||D[1]))
        ;; =============================================================

        mov   DWORD(TMPH), DWORD(DPTR2)          ; left half = D[1]
        mov   DWORD(TMPL), DWORD(DPTR0)          ; D[0]

        FOp1
        FLp1

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
        vmovdqu xmm6,  [rsp + 0*16]
        vmovdqu xmm7,  [rsp + 1*16]
        vmovdqu xmm8,  [rsp + 2*16]
        vmovdqu xmm9,  [rsp + 3*16]
        vmovdqu xmm10, [rsp + 4*16]
        vmovdqu xmm11, [rsp + 5*16]
        vmovdqu xmm12, [rsp + 6*16]
        vmovdqu xmm13, [rsp + 7*16]
        vmovdqu xmm14, [rsp + 8*16]
        vmovdqu xmm15, [rsp + 9*16]

        add     rsp, BLK_STACK_SIZE
%endif

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx

        ret

mksection stack-noexec
