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

;; Bitsliced constant-time KASUMI FI function implementation (SSE).
;; This is the XMM (128-bit) port of the AVX2 bitsliced KASUMI S-box described in:
;;   E. Urquhart and D. Chambers, "An Optimised Constant-time Implementation
;;   of KASUMI FI Function," ISSC, 2024.
;;   https://ieeexplore.ieee.org/document/10603289
;;
;; Since XMM registers are 128 bits wide (8 x 16-bit words) versus the 256 bits
;; (16 x 16-bit words) used by the AVX2 version, the bitsliced computation is
;; split into two sequential 128-bit passes:
;;   Pass A: lower 8 words of each constant  -> S7[0..6] and S9[0]
;;   Pass B: upper 8 words of each constant  -> S9[1..8]
;; The 8-bit result of each pass is combined to produce the 16-bit S-box output.
;;
;; Parity extraction avoids PEXT (BMI2) by using PSRAW + PACKSSWB + PMOVMSKB,
;; keeping the instruction set to SSE4.2 / SSSE3.

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/constant_lookup.inc"
%include "include/align_sse.inc"
%include "include/clear_regs.inc"

;; Borrow the shared boolean-equation mask constants from kasumi_sbox_avx2.asm.
;; These 32-byte (256-bit) tables are accessed in two 16-byte halves:
;;   pass A uses [rel sbox_mask_x(i)]      (offset +0,  first  16 bytes)
;;   pass B uses [rel sbox_mask_x(i) + 16] (offset +16, second 16 bytes)
extern sbox_mask_x0, sbox_mask_x1, sbox_mask_x2, sbox_mask_x3
extern sbox_mask_x4, sbox_mask_x5, sbox_mask_x6, sbox_mask_x7
extern sbox_mask_x8, sbox_mask_last
extern isolate_input_bits_0, isolate_input_bits_1, isolate_input_bits_2
extern isolate_input_bits_3, isolate_input_bits_4, isolate_input_bits_5
extern isolate_input_bits_6, isolate_input_bits_7, isolate_input_bits_8

mksection .rodata
default rel

align 16
;; Nibble mask: 0x0F per byte, used to isolate the 4-bit nibbles in the
;; parity reduction step.
nibble_mask_sse:       times 16 db 0x0F

align 16
;; Nibble parity lookup table (SSSE3 PSHUFB).
;; entry[i] = 0xFF if popcount(i) is odd, 0x00 if even.
parity_nibble_lut_sse:
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

;; SSE working registers (xmm2-xmm9 for s0-s7, skip xmm10=parity_lut, xmm11=s8)
;; xmm12 is preloaded with nibble_mask_sse for the lifetime of the function.
%define     s0    xmm2
%define     s1    xmm3
%define     s2    xmm4
%define     s3    xmm5
%define     s4    xmm6
%define     s5    xmm7
%define     s6    xmm8
%define     s7    xmm9
%define     s8    xmm11
%define     nibble_mask_reg  xmm12

%define     s(n)               s %+ n
%define     sbox_mask_x(n)     sbox_mask_x %+ n
%define     isolate_input_bits_sse(n)  isolate_input_bits_ %+ n

;; GP register definitions for kasumi_1_block_sse (identical to AVX2 version)
%define KS       arg1           ; pointer into key schedule (advances each round)
%define DPTR     arg2           ; pointer to data block (constant throughout)
%define TMPH     r13            ; round working register (left/right half)
%define TMPL     r14            ; round working register (right/left half)
%define STATE    r11            ; FI Feistel state accumulator (survives sbox)

%ifdef LINUX
%define DPTR0    rdx            ; D[0]
%define DPTR2    rcx            ; D[1]
%else
%define DPTR0    r8             ; D[0]
%define DPTR2    r9             ; D[1]
%endif
%define DPTR4    rbx            ; D[2] (callee-saved)
%define DPTR6    r12            ; D[3] (callee-saved)

%define TMP0     rax            ; S-box output / general scratch
%define TMP1     r10            ; S-box input / general scratch
%define TMP2     r15            ; FL scratch

;; Stack frame for kasumi_1_block_sse (Windows only: 10 non-volatile XMM saves)
%ifndef LINUX
%define BLK_STACK_SIZE  (10 * 16)
%endif

;; ============================================================================
;; KASUMI_SBOX_PARITY_REDUCE_SSE
;;
;; Given the AND-chain result in s0, compute the XOR parity of each 16-bit word
;; and collect the 8 resulting bits into TMP1[7:0].
;;
;; Algorithm:
;;   1. Split each byte of s0 into low and high nibbles.
;;   2. Look up nibble parity via PSHUFB against parity_nibble_lut_sse -> byte parity.
;;   3. XOR high-byte and low-byte parities within each word -> word parity in bit 15.
;;   4. PSRAW by 15 fills each word with its parity -> 0xFFFF/0x0000.
;;   5. PACKSSWB packs the 8 words into 8 bytes -> 0xFF/0x00 per word.
;;   6. PMOVMSKB extracts the MSB of each byte -> 8-bit result in TMP1[7:0].
;;
;; Input:    s0 (xmm2) = AND-chain result to reduce (8 x 16-bit words)
;; Requires: xmm10 (parity_nibble_lut_sse) and xmm12 (nibble_mask_reg) preloaded.
;; Output:   TMP1[7:0] = 8 word-parity bits (one per XMM word).
;; Clobbers: xmm0, xmm1, s0
;; ============================================================================
%macro KASUMI_SBOX_PARITY_REDUCE_SSE 0
        ;; Split s0 into low and high nibbles in one pass:
        ;; copy s0 for low nibbles, then shift s0 in-place for high nibbles.
        movdqa      xmm1, s0                        ; xmm1 = s0 (low-nibble source)
        psrlw       s0, 4                           ; s0   = high nibbles shifted to low positions
        pand        xmm1, nibble_mask_reg           ; xmm1 = low  nibbles (0x00-0x0F)
        pand        s0,   nibble_mask_reg           ; s0   = high nibbles (0x00-0x0F)

        ;; LUT lookup for both nibble bands.
        ;; SSE pshufb: DATA register is shuffled according to CTRL register.
        movdqa      xmm0, xmm10                    ; xmm0 = LUT copy
        pshufb      xmm0, xmm1                     ; xmm0[i] = parity(low_nibble[i])
        movdqa      xmm1, xmm10                    ; xmm1 = LUT copy
        pshufb      xmm1, s0                       ; xmm1[i] = parity(high_nibble[i])

        ;; Byte parity = parity(low nibble) XOR parity(high nibble)
        pxor        xmm0, xmm1                     ; xmm0 = byte parity (0xFF or 0x00 per byte)

        ;; Word parity: XOR high-byte parity into low-byte parity across each word.
        ;; s0 is free here; reuse it as scratch to avoid clobbering xmm1.
        movdqa      s0, xmm0
        psllw       s0, 8                          ; low-byte parities -> high-byte positions
        pxor        xmm0, s0                       ; xmm0[MSB of each word] = word parity

        ;; Extract word parities as an 8-bit mask.
        psraw       xmm0, 15                       ; fill each word: 0xFFFF (odd) / 0x0000 (even)
        packsswb    xmm0, xmm0                     ; pack words -> bytes (0xFF / 0x00)
        pmovmskb    DWORD(TMP1), xmm0              ; bits[7:0] = one parity bit per word
%endmacro

;; ============================================================================
;; KASUMI_SBOX_SSE
;;
;; Computes the combined Kasumi S7 and S9 S-box substitution using a bitsliced
;; SSE implementation based on Boolean equations.
;;
;; The 16-bit input is broadcast across all 8 words of an XMM register.  The
;; computation is performed twice (Pass A and Pass B), each time processing a
;; different 16-byte slice of the 32-byte Boolean-equation constants:
;;   Pass A: [rel const]      (bytes 0-15)  -> S7[0..6] and S9[0]  (bits 0-7)
;;   Pass B: [rel const + 16] (bytes 16-31) -> S9[1..8]             (bits 8-15)
;;
;; For each pass, the algorithm:
;;   1. Broadcasts the input word to all 8 XMM words.
;;   2. For each input bit i (0-8), isolates that bit per word and compares
;;      with the isolation mask to produce a per-word 0xFFFF/0x0000 flag.
;;   3. ORs each flag with the corresponding Boolean-equation mask (sbox_mask_xi).
;;   4. ANDs all 9 masks together with sbox_mask_last to evaluate the S-box.
;;   5. Reduces each word to its XOR parity bit using a nibble-LUT approach.
;;   6. Collects the 8 parity bits via PACKSSWB + PMOVMSKB.
;;
;; Requires: xmm10 = parity_nibble_lut_sse, xmm12 = nibble_mask_sse (both preloaded).
;;
;; Input:    %%sbox_input  - 16-bit value in low word of a 64-bit GP register
;; Output:   %%sbox_result - 16-bit S-box result: S9[8:0] in bits [15:7],
;;                           S7[6:0] in bits [6:0]
;; Clobbers: xmm0-xmm9, xmm11, xmm13, TMP1
;; ============================================================================
%macro KASUMI_SBOX_SSE 2
%define %%sbox_input  %1
%define %%sbox_result %2

        ;; Broadcast the 16-bit input word to all 8 words of xmm13.
        movd        xmm13, DWORD(%%sbox_input)    ; load input into xmm13[15:0]
        pshuflw     xmm13, xmm13, 0               ; replicate word 0 -> all 4 low words
        punpcklqdq  xmm13, xmm13                  ; copy low 64 bits to high 64 bits

        ;; ===== Pass A: lower 16 bytes of constants (words 0-7: S7[0..6] + S9[0]) =====

        ;; For each input bit i: isolate it, compare to produce 0xFFFF/0x0000, then OR
        ;; with the Boolean-equation mask. Fused into a single loop so the address
        ;; calculations for isolate_i and sbox_mask_x(i) fall in the same dispatch window.
%assign i 0
%rep 9
        movdqa  s(i), xmm13
        pand    s(i), [rel isolate_input_bits_sse(i)]
        pcmpeqw s(i), [rel isolate_input_bits_sse(i)]
        por     s(i), [rel sbox_mask_x(i)]
%assign i (i + 1)
%endrep

        ;; AND-tree: reduce 9 registers to a single result in s0.
        pand    s0, s1
        pand    s2, s3
        pand    s4, s5
        pand    s7, s8
        pand    s0, s2
        pand    s4, s6
        pand    s4, s7
        pand    s0, [rel sbox_mask_last]           ; apply constant initialisation mask
        pand    s0, s4                             ; s0 = combined AND-chain result (pass A)

        ;; Extract 8 parity bits from s0 into TMP1[7:0].
        KASUMI_SBOX_PARITY_REDUCE_SSE

        movzx   DWORD(%%sbox_result), BYTE(TMP1)   ; pass A result -> bits [7:0] of output

        ;; ===== Pass B: upper 16 bytes of constants (words 8-15: S9[1..8]) =====

%assign i 0
%rep 9
        movdqa  s(i), xmm13
        pand    s(i), [rel isolate_input_bits_sse(i) + 16]
        pcmpeqw s(i), [rel isolate_input_bits_sse(i) + 16]
        por     s(i), [rel sbox_mask_x(i) + 16]
%assign i (i + 1)
%endrep

        pand    s0, s1
        pand    s2, s3
        pand    s4, s5
        pand    s7, s8
        pand    s0, s2
        pand    s4, s6
        pand    s4, s7
        pand    s0, [rel sbox_mask_last + 16]      ; apply constant initialisation mask
        pand    s0, s4                             ; s0 = combined AND-chain result (pass B)

        ;; Extract 8 parity bits from s0 into TMP1[7:0].
        KASUMI_SBOX_PARITY_REDUCE_SSE

        movzx   DWORD(TMP1), BYTE(TMP1)            ; zero-extend pass B byte
        shl     DWORD(TMP1), 8                     ; shift to bits [15:8]
        or      DWORD(%%sbox_result), DWORD(TMP1)  ; combine: bits[15:8]=S9[8:1], bits[7:0]=S9[0]||S7
%endmacro

;; ============================================================================
;; KASUMI_FI_SSE - Inline FI sub-function (identical structure to AVX2 version)
;;
;; FI is a 16-bit unbalanced Feistel structure:
;;   Input:  16-bit value split as l0[9] || r0[7]
;;   Round 1: r1 = S9[l0] ^ ZE(r0),  l1 = S7[r0] ^ LS7(r1)
;;   Key mix: l2[7] || r2[9] = (l1 || r1) ^ KIi,j
;;   Round 2: r3 = S9[r2] ^ ZE(l2),  l3 = S7[l2] ^ LS7(r3)
;;   Output:  l3[7] || r3[9]
;;
;; Input:
;;   %1 (data)      = 64-bit register holding data input (upper 48 bits zero)
;;   %2 (key1_off)  = byte offset into key_sched for KOi,j (uint16_t)
;;   %3 (key2_off)  = byte offset into key_sched for KIi,j (uint16_t)
;;   %4 (key3)      = 64-bit register holding r_{j-1} (upper 48 bits zero)
;; Output:
;;   %5 (result)    = 64-bit register to receive zero-extended 16-bit result
;; Clobbers: TMP0, TMP1, STATE, xmm0-xmm9, xmm11, xmm13
;; ============================================================================
%macro KASUMI_FI_SSE 5
%define %%data     %1
%define %%key1_off %2
%define %%key2_off %3
%define %%key3     %4
%define %%result   %5

        ;; --- FI Round 1: (data ^ KOi,j) -> S9/S7 -> l1||r1 ---
        movzx   DWORD(STATE), WORD(%%data)
        xor     WORD(STATE), word [KS + %%key1_off]     ; ^ KOi,j

        KASUMI_SBOX_SSE STATE, TMP0                     ; TMP0 = S-box(STATE)

        ;; Feistel cross: r1 = S9[l0] ^ ZE(r0), l1 = S7[r0] ^ LS7(r1)
        shl     DWORD(STATE), 7                         ; ZE(r0): shift r0[7] up
        and     DWORD(STATE), 0x3F80                    ; isolate ZE(r0) in S9 position [13:7]
        xor     DWORD(STATE), DWORD(TMP0)               ; upper 9 = r1; lower 7 = S7[r0]
        mov     DWORD(TMP0), DWORD(STATE)
        shr     DWORD(TMP0), 7                          ; extract LS7(r1)
        and     DWORD(TMP0), 0x7F                       ; LS7(r1)
        xor     DWORD(STATE), DWORD(TMP0)               ; lower 7 = l1 = S7[r0] ^ LS7(r1)

        ;; --- FI key mix: l2||r2 = (l1||r1) ^ KIi,j ---
        movzx   TMP1, word [KS + %%key2_off]            ; KIi,j
        ror     WORD(TMP1), 9                           ; align to r[9]||l[7] layout
        xor     STATE, TMP1                             ; l2[7] || r2[9]

        ;; --- FI Round 2: l2||r2 -> S9/S7 -> l3||r3 ---
        KASUMI_SBOX_SSE STATE, %%result                 ; %%result = S-box(STATE)

        ;; Feistel cross: r3 = S9[r2] ^ ZE(l2), l3 = S7[l2] ^ LS7(r3)
        shl     DWORD(STATE), 7                         ; ZE(l2): shift l2[7] up
        and     DWORD(STATE), 0x3F80                    ; isolate ZE(l2) in S9 position [13:7]
        xor     DWORD(%%result), DWORD(STATE)           ; upper 9 = r3; lower 7 = S7[l2]
        mov     DWORD(STATE), DWORD(%%result)
        shr     DWORD(STATE), 7                         ; extract LS7(r3)
        and     DWORD(STATE), 0x7F                      ; LS7(r3)
        xor     DWORD(%%result), DWORD(STATE)           ; lower 7 = l3 = S7[l2] ^ LS7(r3)
        ror     WORD(%%result), 7                       ; pack into l3[7] || r3[9] output layout

        ;; Fused FO XOR: ^= r_{j-1}
        xor     DWORD(%%result), DWORD(%%key3)          ; ^= r_{j-1}
%endmacro

;; ============================================================================
;; FLp1 - Inline FL sub-function (identical to AVX2 version, GP-only)
;;
;; FL is a key-dependent linear mixing function. Per the spec:
;;   R' = R ^ ROL16(L AND KLi,1, 1)
;;   L' = L ^ ROL16(R' OR KLi,2, 1)
;;
;; Input:
;;   KS   - pointer to current round's 8 subkeys (uint16_t[8])
;;   TMPH - 16-bit R (right half) in low word
;;   TMPL - 16-bit L (left half)  in low word
;;   DPTR - pointer to data block (not used directly, preserved)
;;
;; Register mapping: TMPL = L (left), TMPH = R (right)
;;   KLi,1 = key_sched[0], KLi,2 = key_sched[1]
;;
;; Output:
;;   TMPH = L' (updated left half)
;;   TMPL = R' (updated right half)
;; Clobbers: TMP2
;; ============================================================================
%macro FLp1 0
        movzx   DWORD(TMP2), word [KS + 0]           ; KLi,1
        and     DWORD(TMP2), DWORD(TMPL)             ; L AND KLi,1
        rol     WORD(TMP2), 1                        ; ROL16(..., 1)
        xor     DWORD(TMP2), DWORD(TMPH)             ; R' = R ^ ROL16(L AND KLi,1, 1)

        movzx   DWORD(TMPH), word [KS + 2]           ; KLi,2
        or      DWORD(TMPH), DWORD(TMP2)             ; R' OR KLi,2
        rol     WORD(TMPH), 1                        ; ROL16(..., 1)
        xor     DWORD(TMPH), DWORD(TMPL)             ; L' = L ^ ROL16(R' OR KLi,2, 1)

        mov     DWORD(TMPL), DWORD(TMP2)             ; TMPL = R'
%endmacro

;; ============================================================================
;; FOp1 - FO sub-function (identical to AVX2 version)
;;
;; FO is a 32-bit three-round Feistel:
;;   For j = 1, 2, 3:
;;     r_j = FI(l_{j-1} ^ KOi,j, KIi,j) ^ r_{j-1}
;;     l_j = r_{j-1}
;;   Output = l3 || r3
;;
;; The FO Feistel XOR (^ r_{j-1}) is fused into the FI macro.
;;
;; Input:
;;   KS   - pointer to current round's 8 subkeys (uint16_t[8])
;;   TMPH - 16-bit left half in low word
;;   TMPL - 16-bit right half in low word
;;   DPTR - pointer to data block (not used directly, preserved)
;;
;; Register mapping: TMPH = left half, TMPL = right half
;; Subkeys per round: KOi,j at key_sched[2j], KIi,j at key_sched[2j+1]
;;
;; Output:
;;   TMPH = l3 (updated left half)
;;   TMPL = r3 (updated right half)
;; Clobbers: TMP0, TMP1, STATE, xmm0-xmm9, xmm11, xmm13
;; ============================================================================
%macro FOp1 0
        KASUMI_FI_SSE TMPH, 4, 6, TMPL, TMPH
        KASUMI_FI_SSE TMPL, 8, 10, TMPH, TMPL
        KASUMI_FI_SSE TMPH, 12, 14, TMPL, TMPH
%endmacro

;; ============================================================================
;; kasumi_1_block_sse(const uint16_t *key_sched, uint16_t *data)
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
;; S-box substitutions use constant-time bitsliced SSE Boolean equations.
;;
;; Parameters:
;;   arg1 = const uint16_t *key_sched  (64 x uint16_t = 128 bytes)
;;   arg2 = uint16_t *data             (64-bit block, 4 x uint16_t, in-place)
;; ============================================================================
align_function
MKGLOBAL(kasumi_1_block_sse, function, internal)
kasumi_1_block_sse:
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15

%ifndef LINUX
        sub     rsp, BLK_STACK_SIZE

        movdqu  [rsp + 0*16], xmm6
        movdqu  [rsp + 1*16], xmm7
        movdqu  [rsp + 2*16], xmm8
        movdqu  [rsp + 3*16], xmm9
        movdqu  [rsp + 4*16], xmm10
        movdqu  [rsp + 5*16], xmm11
        movdqu  [rsp + 6*16], xmm12
        movdqu  [rsp + 7*16], xmm13
        movdqu  [rsp + 8*16], xmm14
        movdqu  [rsp + 9*16], xmm15
%endif

        ;; Preload constants that persist across all S-box calls.
        movdqa      xmm10, [rel parity_nibble_lut_sse]   ; nibble parity LUT
        movdqa      xmm12, [rel nibble_mask_sse]         ; 0x0F per byte, used in parity reduce

        ;; Load the 64-bit data block as four 16-bit words: D[0..3].
        movzx   DWORD(DPTR0), word [DPTR + 0]    ; D[0]
        movzx   DWORD(DPTR2), word [DPTR + 2]    ; D[1]
        movzx   DWORD(DPTR4), word [DPTR + 4]    ; D[2]
        movzx   DWORD(DPTR6), word [DPTR + 6]    ; D[3]

        ;; =============================================================
        ;; Round 1 (odd): D[0]||D[1] ^= FO_1(FL_1(D[2]||D[3]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR4)
        mov   DWORD(TMPL), DWORD(DPTR6)

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)
        xor     DWORD(DPTR0), DWORD(TMPH)

        ;; =============================================================
        ;; Round 2 (even): D[2]||D[3] ^= FL_2(FO_2(D[0]||D[1]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR2)
        mov   DWORD(TMPL), DWORD(DPTR0)

        FOp1
        FLp1

        add     KS, 16

        xor     DWORD(DPTR6), DWORD(TMPH)
        xor     DWORD(DPTR4), DWORD(TMPL)

        ;; =============================================================
        ;; Round 3 (odd): D[0]||D[1] ^= FO_3(FL_3(D[2]||D[3]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR4)
        mov   DWORD(TMPL), DWORD(DPTR6)

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)
        xor     DWORD(DPTR0), DWORD(TMPH)

        ;; =============================================================
        ;; Round 4 (even): D[2]||D[3] ^= FL_4(FO_4(D[0]||D[1]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR2)
        mov   DWORD(TMPL), DWORD(DPTR0)

        FOp1
        FLp1

        add     KS, 16

        xor     DWORD(DPTR6), DWORD(TMPH)
        xor     DWORD(DPTR4), DWORD(TMPL)

        ;; =============================================================
        ;; Round 5 (odd): D[0]||D[1] ^= FO_5(FL_5(D[2]||D[3]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR4)
        mov   DWORD(TMPL), DWORD(DPTR6)

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)
        xor     DWORD(DPTR0), DWORD(TMPH)

        ;; =============================================================
        ;; Round 6 (even): D[2]||D[3] ^= FL_6(FO_6(D[0]||D[1]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR2)
        mov   DWORD(TMPL), DWORD(DPTR0)

        FOp1
        FLp1

        add     KS, 16

        xor     DWORD(DPTR6), DWORD(TMPH)
        xor     DWORD(DPTR4), DWORD(TMPL)

        ;; =============================================================
        ;; Round 7 (odd): D[0]||D[1] ^= FO_7(FL_7(D[2]||D[3]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR4)
        mov   DWORD(TMPL), DWORD(DPTR6)

        FLp1
        FOp1

        add     KS, 16

        xor     DWORD(DPTR2), DWORD(TMPL)
        xor     DWORD(DPTR0), DWORD(TMPH)

        ;; =============================================================
        ;; Round 8 (even): D[2]||D[3] ^= FL_8(FO_8(D[0]||D[1]))
        ;; =============================================================
        mov   DWORD(TMPH), DWORD(DPTR2)
        mov   DWORD(TMPL), DWORD(DPTR0)

        FOp1
        FLp1

        xor     DWORD(DPTR6), DWORD(TMPH)
        xor     DWORD(DPTR4), DWORD(TMPL)

        ;; Store the 64-bit result back to the data block.
        mov     [DPTR + 0], WORD(DPTR0)
        mov     [DPTR + 2], WORD(DPTR2)
        mov     [DPTR + 4], WORD(DPTR4)
        mov     [DPTR + 6], WORD(DPTR6)

%ifdef SAFE_DATA
        ;; Zero all XMM registers used during computation to clear sensitive data.
        clear_xmms_sse xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13
%endif

%ifndef LINUX
        movdqu  xmm6,  [rsp + 0*16]
        movdqu  xmm7,  [rsp + 1*16]
        movdqu  xmm8,  [rsp + 2*16]
        movdqu  xmm9,  [rsp + 3*16]
        movdqu  xmm10, [rsp + 4*16]
        movdqu  xmm11, [rsp + 5*16]
        movdqu  xmm12, [rsp + 6*16]
        movdqu  xmm13, [rsp + 7*16]
        movdqu  xmm14, [rsp + 8*16]
        movdqu  xmm15, [rsp + 9*16]

        add     rsp, BLK_STACK_SIZE
%endif

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx

        ret

mksection stack-noexec
