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
%define KS       arg1           ; pointer into key schedule (advances each round)
%define DPTR     arg2           ; pointer to data block (constant throughout)
%define TMPH     r13            ; temp_h (16-bit value in low word)
%define TMPL     r14            ; temp_l (16-bit value in low word)
%define STATE    r11            ; FI Feistel state accumulator (survives sbox)
;;
;; Scratch (clobbered by macros):
%define TMP0     rax            ; S-box output / general scratch
%define TMP1     r10            ; S-box input / general scratch
%define TMP2     r15            ; FL scratch
;; ============================================================================

;; Preloaded YMM/k constants (survive across sbox macro calls):
%define YPERMW  ymm0       ; vpermw_mask   (word permutation indices for 2nd sbox pass)
%define YPERMB  ymm1       ; vpermb_mask   (byte permutation indices for 1st sbox pass)
%define YLSB    ymm12      ; least_sig_bit_word (LSB-per-word test mask)
%define KMASK7  k4         ; kmask_s7      (low 7 bits mask for S7 isolation)

;; Stack frame for kasumi_1_block_avx512
;; Windows: 3 pushes + ret = 32, sub rsp, 192 => total = 224, 224 mod 16 = 0
%ifndef LINUX
%define BLK_STACK_SIZE  192
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
;; Performs the FI unbalanced Feistel with two AVX-512 S-box evaluations.
;; Assumes YPERMW, YPERMB, YLSB, KMASK7 are preloaded with constants.
;;
;; %1 (data)      = 16-bit register holding data input
;; %2 (key1_off)  = byte offset into key_sched for key1 (uint16_t)
;; %3 (key2_off)  = byte offset into key_sched for key2 (uint16_t)
;; %4 (key3)      = 16-bit register holding key3
;; %5 (result)    = 16-bit register to receive result
;; Clobbers: TMP0, TMP1, STATE, ymm2-ymm11, k1, k2, k6
;; ============================================================================
%macro KASUMI_FI_AVX512 5
%define %%data     %1
%define %%key1_off %2
%define %%key2_off %3
%define %%key3     %4
%define %%result   %5

        ;; --- First half of FI Feistel ---
        ;; STATE = data ^ key1
        movzx   STATE, %%data
        xor     WORD(STATE), word [KS + %%key1_off]

        ;; Expand input bits to byte mask and run 1st S-box pass
        kmovd       k1, DWORD(STATE)
        vpmovm2b    ymm10, k1                           ; expand bits to byte mask
        KASUMI_SBOX_AVX512a                              ; 1st S-box pass (output: ymm2)

        ;; Feistel cross-mix: rearrange + XOR with S-box output
        vpermb      ymm10, YPERMB, ymm10                ; rearrange input for cross-mix
        vpxord      ymm10, ymm10, ymm2                  ; XOR with S-box output
        vpermw      ymm3 {KMASK7}{z}, YPERMW, ymm10     ; align S9/S7 halves
        vpxord      ymm10, ymm10, ymm3                  ; complete cross-mix

        ;; --- Second half of FI Feistel ---
        ;; Mix key2 into state (rotate key2 in register, not memory)
        movzx   DWORD(TMP1), word [KS + %%key2_off]
        ror     WORD(TMP1), 9                            ; rotate key2 for subkey alignment
        kmovd       k6, DWORD(TMP1)
        vpmovm2w    ymm11, k6
        vpxord      ymm10, ymm10, ymm11                 ; mix key2 into state

        ;; Extract LSBs as word mask and run 2nd S-box pass
        vptestmw    k2, ymm10, YLSB                      ; k2 = words with LSB set
        vpmovm2w    ymm10, k2
        KASUMI_SBOX_AVX512b                              ; 2nd S-box pass (output: ymm2)

        ;; Extract 16-bit result from S-box output
        vptestmw    k1, ymm2, YLSB                       ; k1 = words with LSB set
        kmovd       DWORD(STATE), k2                     ; S9 bits
        kmovd       DWORD(TMP0), k1                      ; S7 bits
        shl     STATE, 7                                  ; rotate S7 to high positions
        and     STATE, 0x3F80                             ; place S9 bits in upper positions
        xor     TMP0, STATE                              ; merge S9 with S7
        mov     STATE, TMP0
        shr     STATE, 7                                 ; extract high 7-bit field
        and     STATE, 0x7F
        xor     TMP0, STATE                              ; clear high positions
        ror     WORD(TMP0), 7                            ; rotate S7/S9 into final positions

        ;; Mix with key3
        xor     WORD(TMP0), %%key3
        mov     %%result, WORD(TMP0)
%endmacro

;; ============================================================================
;; FLp1 - Inline FL sub-function
;;
;; Computes the FL layer using subkeys key_sched[0] (ka) and key_sched[1] (kb).
;; Modifies TMPH and TMPL in-place.
;;
;; Expected register state on entry:
;;   KS   - pointer to current round's 8 subkeys (uint16_t[8])
;;   TMPH - 16-bit temp_h value in low word
;;   TMPL - 16-bit temp_l value in low word
;;   DPTR - pointer to data block (not used directly, preserved)
;;
;; Algorithm:
;;   r  = temp_l & ka
;;   r  = temp_h ^ ROL16(r, 1)
;;   l  = r | kb
;;   temp_h = temp_l ^ ROL16(l, 1)
;;   temp_l = r
;;
;; Clobbers: TMP0, TMP1, TMP2
;; ============================================================================
%macro FLp1 0
        movzx   DWORD(TMP0), word [KS + 0]         ; ka = key_sched[0]

        ;; r = temp_l & ka
        mov     WORD(TMP2), WORD(TMPL)
        and     WORD(TMP2), WORD(TMP0)
        ;; r = temp_h ^ ROL16(r, 1)
        rol     WORD(TMP2), 1
        xor     WORD(TMP2), WORD(TMPH)

        ;; l = r | kb
        mov     WORD(TMPH), WORD(TMP2)
        or      WORD(TMPH), word [KS + 2]    ; kb = key_sched[1]
        ;; temp_h = old_temp_l ^ ROL16(l, 1)
        rol     WORD(TMPH), 1
        xor     WORD(TMPH), WORD(TMPL)

        ;; Commit results (TMPH already holds new temp_h)
        mov     WORD(TMPL), WORD(TMP2)            ; TMPL = new temp_l = r
%endmacro

;; ============================================================================
;; FOp1 - FO sub-function
;;
;; Invokes KASUMI_FI_AVX512 three times using subkeys key_sched[2..7]:
;;   h = FI(h, key_sched[2], key_sched[3], l)       key offsets: +4,  +6
;;   l = FI(l, key_sched[4], key_sched[5], h)       key offsets: +8,  +10
;;   h = FI(h, key_sched[6], key_sched[7], l)       key offsets: +12, +14
;;
;; Expected register state on entry:
;;   KS   - pointer to current round's 8 subkeys (uint16_t[8])
;;   TMPH - 16-bit temp_h value in low word
;;   TMPL - 16-bit temp_l value in low word
;;   DPTR - pointer to data block (not used directly, preserved)
;;
;; Clobbers: TMP0, TMP1, STATE, ymm2-ymm11, k1, k2, k6
;; ============================================================================
%macro FOp1 0
        KASUMI_FI_AVX512 WORD(TMPH), 4, 6, WORD(TMPL), WORD(TMPH)
        KASUMI_FI_AVX512 WORD(TMPL), 8, 10, WORD(TMPH), WORD(TMPL)
        KASUMI_FI_AVX512 WORD(TMPH), 12, 14, WORD(TMPL), WORD(TMPH)
%endmacro

;; ============================================================================
;; kasumi_1_block_avx512(const uint16_t *key_sched, uint16_t *data)
;;
;; Performs the Kasumi block cipher on a single 64-bit data block.
;; Executes 8 rounds (4 odd/even pairs, fully unrolled):
;;   - Odd rounds:  FL -> FO
;;   - Even rounds: FO -> FL
;;
;; Each round consumes 8 subkeys (16 bytes) from the key schedule.
;; The FO sub-function uses KASUMI_FI_AVX512 for constant-time S-box
;; substitution via bitsliced AVX-512 Boolean equations.
;;
;; Parameters:
;;   arg1 = const uint16_t *key_sched  (64 x uint16_t = 128 bytes)
;;   arg2 = uint16_t *data           (64-bit block, 4 x uint16_t, in-place)
;; ============================================================================
align_function
MKGLOBAL(kasumi_1_block_avx512, function, internal)
kasumi_1_block_avx512:
        ;; Save callee-saved GPRs
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
        vmovdqu [rsp + BLK_XMM_OFFSET + 7*16], xmm13
        vmovdqu [rsp + BLK_XMM_OFFSET + 8*16], xmm14
        vmovdqu [rsp + BLK_XMM_OFFSET + 9*16], xmm15
%endif

        ;; KS = arg1 = key schedule pointer (advances each round)
        ;; DPTR = arg2 = data pointer (constant)

        ;; Preload constants that survive across all sbox evaluations
        kmovd       KMASK7, [rel kmask_s7]               ; S7 isolation mask (low 7 bits)
        vmovdqa     YPERMB, [rel vpermb_mask]             ; byte permutation for 1st sbox
        vmovdqa     YPERMW, [rel vpermw_mask]             ; word permutation for 2nd sbox
        vmovdqa     YLSB, [rel least_sig_bit_word]       ; LSB-per-word test mask

        ;; =============================================================
        ;; Round 1 (odd): FL -> FO
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 4]   ; TMPH = data[2]
        movzx   DWORD(TMPL), word [DPTR + 6]   ; TMPL = data[3]

        FLp1
        FOp1

        add     KS, 16

        xor     [DPTR + 2], WORD(TMPL)          ; data[1] ^= temp_l
        xor     [DPTR + 0], WORD(TMPH)          ; data[0] ^= temp_h

        ;; =============================================================
        ;; Round 2 (even): FO -> FL
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 2]   ; TMPH = data[1]
        movzx   DWORD(TMPL), word [DPTR + 0]   ; TMPL = data[0]

        FOp1
        FLp1

        add     KS, 16

        xor     [DPTR + 6], WORD(TMPH)          ; data[3] ^= temp_h
        xor     [DPTR + 4], WORD(TMPL)          ; data[2] ^= temp_l

        ;; =============================================================
        ;; Round 3 (odd): FL -> FO
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 4]   ; TMPH = data[2]
        movzx   DWORD(TMPL), word [DPTR + 6]   ; TMPL = data[3]

        FLp1
        FOp1

        add     KS, 16

        xor     [DPTR + 2], WORD(TMPL)          ; data[1] ^= temp_l
        xor     [DPTR + 0], WORD(TMPH)          ; data[0] ^= temp_h

        ;; =============================================================
        ;; Round 4 (even): FO -> FL
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 2]   ; TMPH = data[1]
        movzx   DWORD(TMPL), word [DPTR + 0]   ; TMPL = data[0]

        FOp1
        FLp1

        add     KS, 16

        xor     [DPTR + 6], WORD(TMPH)          ; data[3] ^= temp_h
        xor     [DPTR + 4], WORD(TMPL)          ; data[2] ^= temp_l

        ;; =============================================================
        ;; Round 5 (odd): FL -> FO
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 4]   ; TMPH = data[2]
        movzx   DWORD(TMPL), word [DPTR + 6]   ; TMPL = data[3]

        FLp1
        FOp1

        add     KS, 16

        xor     [DPTR + 2], WORD(TMPL)          ; data[1] ^= temp_l
        xor     [DPTR + 0], WORD(TMPH)          ; data[0] ^= temp_h

        ;; =============================================================
        ;; Round 6 (even): FO -> FL
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 2]   ; TMPH = data[1]
        movzx   DWORD(TMPL), word [DPTR + 0]   ; TMPL = data[0]

        FOp1
        FLp1

        add     KS, 16

        xor     [DPTR + 6], WORD(TMPH)          ; data[3] ^= temp_h
        xor     [DPTR + 4], WORD(TMPL)          ; data[2] ^= temp_l

        ;; =============================================================
        ;; Round 7 (odd): FL -> FO
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 4]   ; TMPH = data[2]
        movzx   DWORD(TMPL), word [DPTR + 6]   ; TMPL = data[3]

        FLp1
        FOp1

        add     KS, 16

        xor     [DPTR + 2], WORD(TMPL)          ; data[1] ^= temp_l
        xor     [DPTR + 0], WORD(TMPH)          ; data[0] ^= temp_h

        ;; =============================================================
        ;; Round 8 (even): FO -> FL
        ;; =============================================================

        movzx   DWORD(TMPH), word [DPTR + 2]   ; TMPH = data[1]
        movzx   DWORD(TMPL), word [DPTR + 0]   ; TMPL = data[0]

        FOp1
        FLp1

        xor     [DPTR + 6], WORD(TMPH)          ; data[3] ^= temp_h
        xor     [DPTR + 4], WORD(TMPL)          ; data[2] ^= temp_l

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
        vmovdqu xmm13, [rsp + BLK_XMM_OFFSET + 7*16]
        vmovdqu xmm14, [rsp + BLK_XMM_OFFSET + 8*16]
        vmovdqu xmm15, [rsp + BLK_XMM_OFFSET + 9*16]

        add     rsp, BLK_STACK_SIZE
%endif

        pop     r15
        pop     r14
        pop     r13

        ret

mksection stack-noexec
