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

;; ============================================================================
;; DES Single-Block Engine (FIPS 46-3)
;; ============================================================================
;;
;; Implements: des_enc_dec_1_sse(data, ks, enc) -> ciphertext/plaintext
;;
;; DES structure per FIPS 46-3:
;;   IP -> 16 Feistel rounds -> FP
;;   Each round:
;;      L(i) = R(i-1)
;;      R(i) = L(i-1) XOR f(R(i-1), K(i))
;;   Round function f:
;;      f(R, K) = P(S(E(R) XOR K))
;;
;; Key optimizations vs. textbook DES:
;;
;; 1. E-in-key-schedule: E expansion is baked into the key schedule at
;;    key setup time, saving instructions per round at runtime.
;;    ROL(R, 1) pre-rotation aligns E windows to byte boundaries.
;;    (See fRK function for details.)
;;
;; 2. Constant-time S-box: Uses pcmpeqb to scan all 64 entries per S-box,
;;    preventing cache-timing side channels. All 8 S-boxes run in parallel.
;;    (See sbox_1_to_8 function.)
;;
;; 3. SIMD P permutation: Uses pshufb bit-as-byte shuffle.
;;
;; ============================================================================

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/align_sse.inc"
%include "include/clear_regs.inc"

mksection .rodata
default rel

;; ============================================================================
;; S-box lookup constants
;; ============================================================================
;; Reference index tables for constant-time pcmpeqb scan (see sbox_1_to_8).
;; Each table contains 16 sequential byte values [base..base+15].
;; The scan compares the broadcast S-box index against these to produce a
;; one-hot mask that selects the correct S-box entry without data-dependent
;; memory access.

align 16
idx_tab8:
        db 0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,
        db 0x08,  0x09,  0x0A,  0x0B,  0x0C,  0x0D,  0x0E,  0x0F

align 16
idx_tab31_16:
        db 0x10,  0x11,  0x12,  0x13,  0x14,  0x15,  0x16,  0x17,
        db 0x18,  0x19,  0x1A,  0x1B,  0x1C,  0x1D,  0x1E,  0x1F

align 16
idx_tab47_32:
        db 0x20,  0x21,  0x22,  0x23,  0x24,  0x25,  0x26,  0x27,
        db 0x28,  0x29,  0x2A,  0x2B,  0x2C,  0x2D,  0x2E,  0x2F

align 16
idx_tab63_48:
        db 0x30,  0x31,  0x32,  0x33,  0x34,  0x35,  0x36,  0x37,
        db 0x38,  0x39,  0x3A,  0x3B,  0x3C,  0x3D,  0x3E,  0x3F

;; Byte-broadcast constants for pshufb: replicate byte N to all 16 positions.
;; Used in sbox_1_to_8 to select individual S-box indices from the packed r9 register.
;;
;; r9 byte layout (after E-in-key-schedule):
;;   byte 0 = S1 index    byte 4 = S2 index
;;   byte 1 = S3 index    byte 5 = S4 index
;;   byte 2 = S5 index    byte 6 = S6 index
;;   byte 3 = S7 index    byte 7 = S8 index

align 16
zero:
        db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

align 16
one:
        db 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        db 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01

align 16
two:
        db 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        db 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02

align 16
three:
        db 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        db 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03

align 16
four:
        db 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        db 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04

align 16
five:
        db 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        db 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05

align 16
six:
        db 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        db 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06

align 16
seven:
        db 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        db 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07

;; Mask for E-in-key-schedule: after XOR with key, mask each byte to 6 valid bits
align 16
mask_3f:
        db 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        db 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f

;; ============================================================================
;; Key schedule conversion constants (convert_ks_for_sse)
;; ============================================================================
;; Repack standard 8-byte round key [S1,S2,S3,S4,S5,S6,S7,S8] into E-in-ks:
;;   ks_lo (bytes 0-3): S1, S3, S5, S7  (even S-boxes at byte boundaries)
;;   ks_hi (bytes 4-7): S2, S4, S6, S8  (odd S-boxes, needs ROR 4 at runtime)

;; pshufb mask: pick bytes {0,2,4,6, 1,3,5,7, 8,10,12,14, 9,11,13,15}
;; Processes two round keys at once from a 16-byte load:
;;   low qword:  [S1a,S3a,S5a,S7a, S2a,S4a,S6a,S8a]
;;   high qword: [S1b,S3b,S5b,S7b, S2b,S4b,S6b,S8b]
align 16
ks_shuf:
        db 0x00, 0x02, 0x04, 0x06, 0x01, 0x03, 0x05, 0x07
        db 0x08, 0x0a, 0x0c, 0x0e, 0x09, 0x0b, 0x0d, 0x0f

;; Shift odd S-boxes left by 4 bits within each byte (multiply by 16)
;; Applied to ks_hi bytes to create the <<4 pre-shift
align 16
ks_hi_mask:
        db 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
        db 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff

;; ============================================================================
;; P permutation constants (FIPS 46-3, Table on page 13)
;; ============================================================================
;; P permutes the 32-bit S-box output before XOR with L half.
;;
;; Implementation: "bit-as-byte" pshufb approach
;;   1. Expand 32-bit value to 32 bytes (one byte per bit: 0x00 or 0xFF)
;;   2. pshufb rearranges bytes according to P table
;;   3. pmovmskb collapses bytes back to bits
;; This replaces 70 GP shift/mask/OR instructions with 21 SIMD instructions.
;;
;; FIPS P table (output bit <- input bit, 0-indexed):
;;   P = [15,6,19,20,28,11,27,16, 0,14,22,25,4,17,30,9,
;;         1,7,23,13,31,26,2,8, 18,12,29,5,21,10,3,24]

;; Bit-to-byte expansion: replicate each source byte to 8 positions
align 16
p_expand_byte01:
        db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        db 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01

align 16
p_expand_byte23:
        db 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
        db 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03

;; Isolate individual bits within each byte
align 16
p_bit_isolate:
        db 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
        db 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

;; P permutation shuffle masks (output bit <- input bit, 0-indexed)
;; P = [15,6,19,20,28,11,27,16, 0,14,22,25,4,17,30,9,
;;       1,7,23,13,31,26,2,8, 18,12,29,5,21,10,3,24]
;; Source: xmm_lo = input bits 0-15, xmm_hi = input bits 16-31
;; 0x80 = zero (source bit not in this half)

;; Output bits 0-15, selected from input bits 0-15
align 16
p_lo_from_lo:
        db 0x0f, 0x06, 0x80, 0x80, 0x80, 0x0b, 0x80, 0x80
        db 0x00, 0x0e, 0x80, 0x80, 0x04, 0x80, 0x80, 0x09

;; Output bits 0-15, selected from input bits 16-31
align 16
p_lo_from_hi:
        db 0x80, 0x80, 0x03, 0x04, 0x0c, 0x80, 0x0b, 0x00
        db 0x80, 0x80, 0x06, 0x09, 0x80, 0x01, 0x0e, 0x80

;; Output bits 16-31, selected from input bits 0-15
align 16
p_hi_from_lo:
        db 0x01, 0x07, 0x80, 0x0d, 0x80, 0x80, 0x02, 0x08
        db 0x80, 0x0c, 0x80, 0x05, 0x80, 0x0a, 0x03, 0x80

;; Output bits 16-31, selected from input bits 16-31
align 16
p_hi_from_hi:
        db 0x80, 0x80, 0x07, 0x80, 0x0f, 0x0a, 0x80, 0x80
        db 0x02, 0x80, 0x0d, 0x80, 0x05, 0x80, 0x80, 0x08

;; ============================================================================
;; DES S-box tables (FIPS 46-3, pages 10-12)
;; ============================================================================
;; Each S-box maps a 6-bit input to a 4-bit output. There are 8 S-boxes (S1-S8).
;; Each table has 64 byte entries, indexed by 6-bit value V from the E-phase.
;;
;; FIPS defines the 6-bit input as {b1,b2,b3,b4,b5,b6} where:
;;   row = b1*2 + b6 (0-3), col = b2*8 + b3*4 + b4*2 + b5 (0-15)
;;
;; This library stores bits as: bit0=b1, bit1=b2, ..., bit5=b6 (LSB-first),
;; so the 6-bit index V maps as:
;;   row = (V & 1)*2 + ((V >> 5) & 1)
;;   col = (V >> 1) & 0xF
;;
;; Output nibbles are bit-reflected (FIPS bit 1 -> C bit 3, etc.) to match
;; the pre-P packing convention.
;; ============================================================================

;; S1
align 16
sbox1:
        db 0x07, 0x02, 0x0c, 0x0f, 0x04, 0x0b, 0x0a, 0x0c
        db 0x0b, 0x07, 0x06, 0x09, 0x0d, 0x04, 0x00, 0x0a
        db 0x02, 0x08, 0x05, 0x03, 0x0f, 0x06, 0x09, 0x05
        db 0x08, 0x01, 0x03, 0x0e, 0x01, 0x0d, 0x0e, 0x00
        db 0x00, 0x0f, 0x05, 0x0a, 0x07, 0x02, 0x09, 0x05
        db 0x0e, 0x01, 0x03, 0x0c, 0x0b, 0x08, 0x0c, 0x06
        db 0x0f, 0x03, 0x06, 0x0d, 0x04, 0x09, 0x0a, 0x00
        db 0x02, 0x04, 0x0d, 0x07, 0x08, 0x0e, 0x01, 0x0b

;; S2
align 16
sbox2:
        db 0x0f, 0x00, 0x09, 0x0a, 0x06, 0x05, 0x03, 0x09
        db 0x01, 0x0e, 0x04, 0x03, 0x0c, 0x0b, 0x0a, 0x04
        db 0x08, 0x07, 0x0e, 0x01, 0x0d, 0x02, 0x00, 0x0c
        db 0x07, 0x0d, 0x0b, 0x06, 0x02, 0x08, 0x05, 0x0f
        db 0x0c, 0x0b, 0x03, 0x0d, 0x0f, 0x0c, 0x06, 0x00
        db 0x02, 0x05, 0x08, 0x0e, 0x01, 0x02, 0x0d, 0x07
        db 0x0b, 0x01, 0x00, 0x06, 0x04, 0x0f, 0x09, 0x0a
        db 0x0e, 0x08, 0x05, 0x03, 0x07, 0x04, 0x0a, 0x09

;; S3
align 16
sbox3:
        db 0x05, 0x0b, 0x08, 0x0d, 0x06, 0x01, 0x0d, 0x0a
        db 0x09, 0x02, 0x03, 0x04, 0x0f, 0x0c, 0x04, 0x07
        db 0x00, 0x06, 0x0b, 0x08, 0x0c, 0x0f, 0x02, 0x05
        db 0x07, 0x09, 0x0e, 0x03, 0x0a, 0x00, 0x01, 0x0e
        db 0x0b, 0x08, 0x04, 0x02, 0x0c, 0x06, 0x03, 0x0d
        db 0x00, 0x0b, 0x0a, 0x07, 0x06, 0x01, 0x0f, 0x04
        db 0x0e, 0x05, 0x01, 0x0f, 0x02, 0x09, 0x0d, 0x0a
        db 0x09, 0x00, 0x07, 0x0c, 0x05, 0x0e, 0x08, 0x03

;; S4
align 16
sbox4:
        db 0x0e, 0x05, 0x08, 0x0f, 0x00, 0x03, 0x0d, 0x0a
        db 0x07, 0x09, 0x01, 0x0c, 0x09, 0x0e, 0x02, 0x01
        db 0x0b, 0x06, 0x04, 0x08, 0x06, 0x0d, 0x03, 0x04
        db 0x0c, 0x00, 0x0a, 0x07, 0x05, 0x0b, 0x0f, 0x02
        db 0x0b, 0x0c, 0x02, 0x09, 0x06, 0x05, 0x08, 0x03
        db 0x0d, 0x00, 0x04, 0x0a, 0x00, 0x0b, 0x07, 0x04
        db 0x01, 0x0f, 0x0e, 0x02, 0x0f, 0x08, 0x05, 0x0e
        db 0x0a, 0x06, 0x03, 0x0d, 0x0c, 0x01, 0x09, 0x07

;; S5
align 16
sbox5:
        db 0x04, 0x02, 0x01, 0x0f, 0x0e, 0x05, 0x0b, 0x06
        db 0x02, 0x08, 0x0c, 0x03, 0x0d, 0x0e, 0x07, 0x00
        db 0x03, 0x04, 0x0a, 0x09, 0x05, 0x0b, 0x00, 0x0c
        db 0x08, 0x0d, 0x0f, 0x0a, 0x06, 0x01, 0x09, 0x07
        db 0x07, 0x0d, 0x0a, 0x06, 0x02, 0x08, 0x0c, 0x05
        db 0x04, 0x03, 0x0f, 0x00, 0x0b, 0x04, 0x01, 0x0a
        db 0x0d, 0x01, 0x00, 0x0f, 0x0e, 0x07, 0x09, 0x02
        db 0x03, 0x0e, 0x05, 0x09, 0x08, 0x0b, 0x06, 0x0c

;; S6
align 16
sbox6:
        db 0x03, 0x09, 0x00, 0x0e, 0x09, 0x04, 0x07, 0x08
        db 0x05, 0x0f, 0x0c, 0x02, 0x06, 0x03, 0x0a, 0x0d
        db 0x08, 0x07, 0x0b, 0x00, 0x04, 0x01, 0x0e, 0x0b
        db 0x0f, 0x0a, 0x02, 0x05, 0x01, 0x0c, 0x0d, 0x06
        db 0x05, 0x02, 0x06, 0x0d, 0x0e, 0x09, 0x00, 0x06
        db 0x02, 0x04, 0x0b, 0x08, 0x09, 0x0f, 0x0c, 0x01
        db 0x0f, 0x0c, 0x08, 0x07, 0x03, 0x0a, 0x0d, 0x00
        db 0x04, 0x03, 0x07, 0x0e, 0x0a, 0x05, 0x01, 0x0b

;; S7
align 16
sbox7:
        db 0x02, 0x08, 0x0c, 0x05, 0x0f, 0x03, 0x0a, 0x00
        db 0x04, 0x0d, 0x09, 0x06, 0x01, 0x0e, 0x06, 0x09
        db 0x0d, 0x02, 0x03, 0x0f, 0x00, 0x0c, 0x05, 0x0a
        db 0x07, 0x0b, 0x0e, 0x01, 0x0b, 0x07, 0x08, 0x04
        db 0x0b, 0x06, 0x07, 0x09, 0x02, 0x08, 0x04, 0x07
        db 0x0d, 0x0b, 0x0a, 0x00, 0x08, 0x05, 0x01, 0x0c
        db 0x00, 0x0d, 0x0c, 0x0a, 0x09, 0x02, 0x0f, 0x04
        db 0x0e, 0x01, 0x03, 0x0f, 0x05, 0x0e, 0x06, 0x03

;; S8
align 16
sbox8:
        db 0x0b, 0x0e, 0x05, 0x00, 0x06, 0x09, 0x0a, 0x0f
        db 0x01, 0x02, 0x0c, 0x05, 0x0d, 0x07, 0x03, 0x0a
        db 0x04, 0x0d, 0x09, 0x06, 0x0f, 0x03, 0x00, 0x0c
        db 0x02, 0x08, 0x07, 0x0b, 0x08, 0x04, 0x0e, 0x01
        db 0x08, 0x04, 0x03, 0x0f, 0x05, 0x02, 0x00, 0x0c
        db 0x0b, 0x07, 0x06, 0x09, 0x0e, 0x01, 0x09, 0x06
        db 0x0f, 0x08, 0x0a, 0x03, 0x0c, 0x05, 0x07, 0x0a
        db 0x01, 0x0e, 0x0d, 0x00, 0x02, 0x0b, 0x04, 0x0d

mksection .text

%ifdef LINUX
        %define arg1    rdi
        %define arg2    rsi
        %define arg3    rdx
%else
        %define arg1    rcx
        %define arg2    rdx
        %define arg3    r8
%endif

;; ============================================================================
;; PERMUTE_OP - Bit permutation building block (Initial/Final Permutation)
;;
;; Implements Heller's technique for IP and FP (FIPS 46-3, pages 7-8, 14):
;;   t = (pb ^ (pa >> n)) & mask;
;;   pb ^= t;
;;   pa ^= (t << n)
;;
;; Five PERMUTE_OP calls with specific (n, mask) pairs implement IP:
;;   (4, 0x0f0f0f0f), (16, 0x0000ffff), (2, 0x33333333),
;;   (8, 0x00ff00ff), (1, 0x55555555)
;; FP is IP inverse (same operations in reverse order).
;; ============================================================================
%macro PERMUTE_OP 6
%define %%pa_reg    %1  ;; [in/out] PA GP register (32-bits)
%define %%pb_reg    %2  ;; [in/out] PB GP register (32-bits)
%define %%shift     %3  ;; [in] number of bits to shift; numerical value
%define %%mask      %4  ;; [in] mask for and operation; numerical value
%define %%t1        %5  ;; [clobbered] temporary GP register (32-bits)
%define %%t2        %6  ;; [clobbered] temporary GP register (32-bits)

        mov     %%t1, %%pb_reg
        mov     %%t2, %%pa_reg
        shr     %%t2, %%shift
        xor     %%t1, %%t2
        and     %%t1, %%mask
        xor     %%pb_reg, %%t1
        shl     %%t1, %%shift
        xor     %%pa_reg, %%t1
%endmacro

;; ============================================================================
;; sbox_1_to_8 - All 8 S-box lookups in one call (FIPS 46-3, pages 10-12)
;; ============================================================================
;;
;; Constant-time S-box scan technique:
;;
;;   For each 6-bit index, broadcast it to all 16 bytes of an XMM register.
;;   Compare against reference index table [0..15], [16..31], [32..47], [48..63]
;;   using pcmpeqb. Exactly ONE byte matches -> produces 0xFF mask in that position.
;;   AND with S-box table row selects the matching entry; OR accumulates results.
;;   psadbw reduction (sum of absolute differences with zero) extracts the single
;;   non-zero byte as a scalar.
;;
;;   This guarantees no data-dependent memory access pattern, preventing
;;   cache-timing side channels (unlike OpenSSL's SPtrans direct indexing).
;;
;;   Cost: 4 scan iterations × 8 S-boxes = 32 pcmpeqb + 32 pand + 24 por
;;
;; Input:  r9   = 8 packed 6-bit S-box indices (one per byte)
;;                 byte 0 = S1, byte 1 = S3, byte 2 = S5, byte 3 = S7
;;                 byte 4 = S2, byte 5 = S4, byte 6 = S6, byte 7 = S8
;;         r10  = pointer to 16 byte buffer (aligned); XMM overflow
;; Output: xmm0 = 32-bit S-box result (8 × 4-bit nibbles packed)
;;                 bits [3:0]=S1, [7:4]=S2, [11:8]=S3, ..., [31:28]=S8
;; Clobbers: xmm0-xmm15, [r10] (16 bytes, must be 16-byte aligned)
;; Note: Caller (des_enc_dec_1_sse) sets r10 to aligned scratch pointer.
;; ============================================================================
align_function
sbox_1_to_8:
        movq    xmm7, r9
        pand    xmm7, [rel mask_3f]    ; mask to 6 bits per byte

        ;; broadcast 6-bit indexes to all 16 bytes
        ;; New r9 layout: bytes [3:0]=S1,S3,S5,S7  bytes [7:4]=S2,S4,S6,S8
        movdqa  xmm0, xmm7              ; sbox1 (S1)
        pshufb  xmm0, [rel zero]        ; byte 0
        movdqa  xmm1, xmm7              ; sbox2 (S2)
        pshufb  xmm1, [rel four]        ; byte 4
        movdqa  xmm2, xmm7              ; sbox3 (S3)
        pshufb  xmm2, [rel one]         ; byte 1
        movdqa  xmm3, xmm7              ; sbox4 (S4)
        pshufb  xmm3, [rel five]        ; byte 5
        movdqa  xmm4, xmm7              ; sbox5 (S5)
        pshufb  xmm4, [rel two]         ; byte 2
        movdqa  xmm5, xmm7              ; sbox6 (S6)
        pshufb  xmm5, [rel six]         ; byte 6
        movdqa  xmm6, xmm7              ; sbox7 (S7)
        pshufb  xmm6, [rel three]       ; byte 3

        ;; scan entries 0-15 and init accumulators xmm8-xmm15
        movdqa  xmm15, [rel idx_tab8]

        movdqa  xmm8, xmm15
        pcmpeqb xmm8, xmm0
        pand    xmm8, [rel sbox1]
        movdqa  [r10], xmm8             ; save in scratch

        movdqa  xmm9, xmm15
        pcmpeqb xmm9, xmm1
        pand    xmm9, [rel sbox2]

        movdqa  xmm10, xmm15
        pcmpeqb xmm10, xmm2
        pand    xmm10, [rel sbox3]

        movdqa  xmm11, xmm15
        pcmpeqb xmm11, xmm3
        pand    xmm11, [rel sbox4]

        movdqa  xmm12, xmm15
        pcmpeqb xmm12, xmm4
        pand    xmm12, [rel sbox5]

        movdqa  xmm13, xmm15
        pcmpeqb xmm13, xmm5
        pand    xmm13, [rel sbox6]

        movdqa  xmm14, xmm15
        pcmpeqb xmm14, xmm6
        pand    xmm14, [rel sbox7]

                                        ; sbox8 (S8) already in xmm7
        pshufb  xmm7, [rel seven]       ; byte 7
        pcmpeqb xmm15, xmm7
        pand    xmm15, [rel sbox8]

        ;; scan entries 16-31
        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm0
        pand    xmm8, [rel sbox1 + 16]
        por     xmm8, [r10]
        movdqa  [r10], xmm8

        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm1
        pand    xmm8, [rel sbox2 + 16]
        por     xmm9, xmm8

        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm2
        pand    xmm8, [rel sbox3 + 16]
        por     xmm10, xmm8

        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm3
        pand    xmm8, [rel sbox4 + 16]
        por     xmm11, xmm8

        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm4
        pand    xmm8, [rel sbox5 + 16]
        por     xmm12, xmm8

        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm5
        pand    xmm8, [rel sbox6 + 16]
        por     xmm13, xmm8

        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm6
        pand    xmm8, [rel sbox7 + 16]
        por     xmm14, xmm8

        movdqa  xmm8, [rel idx_tab31_16]
        pcmpeqb xmm8, xmm7
        pand    xmm8, [rel sbox8 + 16]
        por     xmm15, xmm8

        ;; scan entries 32-47
        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm0
        pand    xmm8, [rel sbox1 + 32]
        por     xmm8, [r10]
        movdqa  [r10], xmm8

        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm1
        pand    xmm8, [rel sbox2 + 32]
        por     xmm9, xmm8

        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm2
        pand    xmm8, [rel sbox3 + 32]
        por     xmm10, xmm8

        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm3
        pand    xmm8, [rel sbox4 + 32]
        por     xmm11, xmm8

        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm4
        pand    xmm8, [rel sbox5 + 32]
        por     xmm12, xmm8

        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm5
        pand    xmm8, [rel sbox6 + 32]
        por     xmm13, xmm8

        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm6
        pand    xmm8, [rel sbox7 + 32]
        por     xmm14, xmm8

        movdqa  xmm8, [rel idx_tab47_32]
        pcmpeqb xmm8, xmm7
        pand    xmm8, [rel sbox8 + 32]
        por     xmm15, xmm8

        ;; scan entries 48-63
        movdqa  xmm8, [rel idx_tab63_48]
        pcmpeqb xmm8, xmm0
        pand    xmm8, [rel sbox1 + 48]
        por     xmm8, [r10]

        movdqa  xmm0, [rel idx_tab63_48]
        pcmpeqb xmm0, xmm1
        pand    xmm0, [rel sbox2 + 48]
        por     xmm9, xmm0

        movdqa  xmm0, [rel idx_tab63_48]
        pcmpeqb xmm0, xmm2
        pand    xmm0, [rel sbox3 + 48]
        por     xmm10, xmm0

        movdqa  xmm0, [rel idx_tab63_48]
        pcmpeqb xmm0, xmm3
        pand    xmm0, [rel sbox4 + 48]
        por     xmm11, xmm0

        movdqa  xmm0, [rel idx_tab63_48]
        pcmpeqb xmm0, xmm4
        pand    xmm0, [rel sbox5 + 48]
        por     xmm12, xmm0

        movdqa  xmm0, [rel idx_tab63_48]
        pcmpeqb xmm0, xmm5
        pand    xmm0, [rel sbox6 + 48]
        por     xmm13, xmm0

        movdqa  xmm0, [rel idx_tab63_48]
        pcmpeqb xmm0, xmm6
        pand    xmm0, [rel sbox7 + 48]
        por     xmm14, xmm0

        movdqa  xmm0, [rel idx_tab63_48]
        pcmpeqb xmm0, xmm7
        pand    xmm0, [rel sbox8 + 48]
        por     xmm15, xmm0

        ;; reduce 16 bytes to single byte via psadbw, shifts and or
        ;; (exactly one byte is non-zero, so SAD with zero = that value)
        movdqa  xmm0, [rel zero]
        psadbw  xmm8,  xmm0
        psadbw  xmm9,  xmm0
        psadbw  xmm10, xmm0
        psadbw  xmm11, xmm0
        psadbw  xmm12, xmm0
        psadbw  xmm13, xmm0
        psadbw  xmm14, xmm0
        psadbw  xmm15, xmm0
                                ; index 0 result is not shifted
        pslld   xmm9, 4         ; index 1 result shifted by 4 bits
        pslld   xmm10, 8        ; index 2 result shifted by 8 bits
        pslld   xmm11, 12       ; index 3 result shifted by 12 bits
        pslld   xmm12, 16       ; index 4 result shifted by 16 bits
        pslld   xmm13, 20       ; index 5 result shifted by 20 bits
        pslld   xmm14, 24       ; index 6 result shifted by 24 bits
        pslld   xmm15, 28       ; index 7 result shifted by 28 bits

        ;; 8 XMM's -> 4 XMM's collapse
        por     xmm8, xmm9
        por     xmm10, xmm11
        por     xmm12, xmm13
        por     xmm14, xmm15

        ;; 4 XMM's -> 2 XMM's collapse
        por     xmm8, xmm10
        por     xmm12, xmm14

        ;; 2 XMM's -> 1 XMM's collapse
        por     xmm8, xmm12

        ;; 2 quadwords -> 1 quadword collapse
        movdqa  xmm0, xmm8
        psrldq  xmm0, 8

        por     xmm0, xmm8

        ret


;; ============================================================================
;; fRK - DES Feistel round function (FIPS 46-3, Figure 2)
;; ============================================================================
;;
;; Computes: f(R, K) = P(S(E(R) XOR K))
;;
;; === E-in-key-schedule optimization ===
;;
;; Standard DES E expansion (FIPS 46-3, Table on page 8) maps 32-bit R to
;; 48 bits. The key insight: if R is pre-rotated by ROL(R, 1), the 8 groups
;; of 6 bits from E(R) align to byte boundaries in R', eliminating runtime
;; extraction shifts. The E expansion is baked into the key schedule instead.
;;
;; Standard E expansion (FIPS bit numbering, 1-based):
;;   E = [32, 1, 2, 3, 4, 5 |  4, 5, 6, 7, 8, 9 |  8, 9,10,11,12,13 |
;;        12,13,14,15,16,17 | 16,17,18,19,20,21 | 20,21,22,23,24,25 |
;;        24,25,26,27,28,29 | 28,29,30,31,32,1]
;;
;; After ROL(R, 1), E windows become:
;;   Bits [5:0]   = S1 -> byte 0 of R'
;;   Bits [9:4]   = S2 -> byte 0-1 of R' (needs 4-bit shift)
;;   Bits [13:8]  = S3 -> byte 1 of R'
;;   Bits [17:12] = S4 -> byte 1-2 of R' (needs 4-bit shift)
;;   ...pattern continues...
;;
;; Key format (convert_ks_for_sse output, 64 bits per round):
;;   ks_lo (bits [31:0]):  S1@[5:0], S3@[13:8], S5@[21:16], S7@[29:24]
;;   ks_hi (bits [63:32]): S2@[9:4], S4@[17:12], S6@[25:20], S8@{[31:28],[1:0]}
;;
;; Runtime E-phase (7 instructions, replaces ~30):
;;   u = R' ^ ks_lo          -> even S-boxes at byte boundaries
;;   t = ROR(R' ^ ks_hi, 4)  -> odd S-boxes shifted to byte boundaries
;;   r9 = u | (t << 32)      -> 8 indices packed in one 64-bit register
;;   pand [mask_3f]           -> mask to 6 valid bits per byte
;;
;; Input:  r11d = R' (32-bit half-block, pre-rotated by ROL 1)
;;         r10  = pointer to 16-byte aligned scratch buffer (for sbox_1_to_8)
;;         r14  = pointer to current round key (uint64_t: ks_lo|ks_hi)
;; Output: eax  = f(R, K) result (32-bit P-permuted, NOT pre-rotated)
;; Clobbers: rax, rcx, r8, r9, xmm0-xmm15
;; ============================================================================

align_function
fRK:
        ;; === E-phase with key XOR (E baked into key schedule) ===
        ;; r9 bytes [3:0] = S1,S3,S5,S7 indices (from u)
        ;; r9 bytes [7:4] = S2,S4,S6,S8 indices (from t)
        mov     r9d, r11d
        xor     r9d, [r14]             ; u = R' ^ ks_lo

        mov     ecx, r11d
        xor     ecx, [r14 + 4]         ; v = R' ^ ks_hi
        ror     ecx, 4                 ; t = ROR(v, 4)

        shl     rcx, 32
        or      r9, rcx                ; r9 = [t | u]

        call    sbox_1_to_8

        ;; ================================================================
        ;; P permutation using pshufb (bit-as-byte shuffle)
        ;; Input:  xmm0 = 32-bit pre-P value (8 x 4-bit S-box results)
        ;; Output: eax = P-permuted 32-bit result
        ;; Uses:   xmm0-xmm3 (scratch)
        ;; ================================================================

        ;; Step 1: Bit-to-byte expansion (32 bits -> 2x16 bytes, 0x00/0xFF)
        movdqa  xmm2, [rel p_bit_isolate]

        movdqa  xmm1, xmm0
        pshufb  xmm0, [rel p_expand_byte01]    ; byte0->pos0-7, byte1->pos8-15
        pand    xmm0, xmm2
        pcmpeqb xmm0, xmm2                     ; xmm0 = input bits 0-15 (1 byte -> 1 bit)

        pshufb  xmm1, [rel p_expand_byte23]    ; byte2->pos0-7, byte3->pos8-15
        pand    xmm1, xmm2
        pcmpeqb xmm1, xmm2                     ; xmm1 = input bits 16-31

        ;; Step 2: pshufb permutation — output bits 0-15
        movdqa  xmm2, xmm0
        pshufb  xmm2, [rel p_lo_from_lo]
        movdqa  xmm3, xmm1
        pshufb  xmm3, [rel p_lo_from_hi]
        por     xmm2, xmm3
        pmovmskb eax, xmm2                     ; eax = output bits 0-15

        ;; Step 3: pshufb permutation — output bits 16-31
        pshufb  xmm0, [rel p_hi_from_lo]
        pshufb  xmm1, [rel p_hi_from_hi]
        por     xmm0, xmm1
        pmovmskb ecx, xmm0                     ; ecx = output bits 16-31
        shl     ecx, 16
        or      eax, ecx
        ret

;; ============================================================================
;; convert_ks_for_sse - Convert key schedule to E-in-ks format
;; ============================================================================
;;
;; Converts 16 round keys from standard format (one S-box per byte) to the
;; E-in-key-schedule format used by fRK.
;;
;; Standard format (per round, 8 bytes):
;;   [S1, S2, S3, S4, S5, S6, S7, S8]  (6 valid bits per byte)
;;
;; E-in-ks format (per round, 8 bytes as two 32-bit words):
;;   ks_lo = S1 | S3<<8 | S5<<16 | S7<<24
;;   ks_hi = (S2|S4<<8|S6<<16|S8<<24) << 4   (as a 32-bit shift)
;;
;; void convert_ks_for_sse(uint64_t *ks_new, const uint64_t *ks_old);
;; arg1 = ks_new : output buffer (16 × uint64_t)
;; arg2 = ks_old : input key schedule (16 × uint64_t, standard format)
;; ============================================================================
align_function
MKGLOBAL(convert_ks_for_sse,function,internal)
convert_ks_for_sse:
        movdqa  xmm4, [rel ks_shuf]    ; shuffle mask: pick even/odd bytes
        movdqa  xmm5, [rel ks_hi_mask] ; mask for hi dwords

        ;; Process 16 round keys, 2 at a time (8 iterations)
        mov     eax, 8
align_loop
.ks_loop:
        ;; Load 2 round keys (16 bytes)
        movdqu  xmm0, [arg2]

        ;; Reorder bytes: [S1,S3,S5,S7, S2,S4,S6,S8] per qword
        pshufb  xmm0, xmm4

        ;; Extract hi dwords (bytes 4-7 of each qword = S2,S4,S6,S8)
        movdqa  xmm1, xmm0
        pand    xmm1, xmm5             ; hi dwords only

        ;; ROL([S2,S4,S6,S8], 4)
        ;; S8 bits [5:4] would overflow past bit 31 when shifted left by 4.
        ;; Extract overflow: dword >> 28 gives S8[5:4] in bits [1:0]
        movdqa  xmm3, xmm1
        psrld   xmm3, 28               ; wrap bits for S8

        ;; Shift hi dwords left by 4 bits (32-bit shift per dword)
        pslld   xmm1, 4

        ;; OR in the S8 wrap bits at positions [1:0]
        por     xmm1, xmm3

        ;; Clear hi dword positions in original, keep lo dwords
        movdqa  xmm2, xmm5
        pandn   xmm2, xmm0             ; ~hi_mask & data = lo dwords only

        ;; Combine: ks_lo in low dwords, ks_hi in high dwords
        por     xmm2, xmm1

        ;; Store 2 converted round keys
        movdqu  [arg1], xmm2

        add     arg2, 16
        add     arg1, 16
        dec     eax
        jnz     .ks_loop

        ret

;; ============================================================================
;; des_enc_dec_1_sse - DES single-block encrypt/decrypt (FIPS 46-3)
;; ============================================================================
;;
;; Full DES block cipher: IP -> 16 Feistel rounds -> FP
;;
;; Flow:
;;   1. Split 64-bit input into L and R halves
;;   2. Initial Permutation (IP) via 5 PERMUTE_OP steps
;;   3. Pre-rotate: R'=ROL(R,1), L'=ROL(L,1) for E-in-key-schedule
;;   4. 16 rounds (8 pairs):
;;        L' ^= ROL(fRK(R', Ki), 1)    <- ROL compensates non-rotated fRK output
;;        R' ^= ROL(fRK(L', Ki+1), 1)
;;   5. Un-rotate: R=ROR(R',1), L=ROR(L',1)
;;   6. Final Permutation (FP) via 5 PERMUTE_OP steps (IP inverse)
;;   7. Recombine as 64-bit output
;;
;; The ROL(fRK_result, 1) after each round is needed because fRK operates on
;; pre-rotated R' but produces a non-rotated P output. Since L' is also
;; pre-rotated, the XOR result must be shifted to match.
;;
;; Register allocation (callee-saved across 16 rounds):
;;   r12d = R' (right half, pre-rotated)
;;   r13d = L' (left half, pre-rotated)
;;   r14  = key schedule pointer (advanced by r15 each round)
;;   r15  = key step (+8 for encrypt, -8 for decrypt)
;;
;; uint64_t des_enc_dec_1_sse(uint64_t data, const uint64_t *ks, int enc);
;; arg1 = data : DES block (R in low 32 bits, L in high 32 bits)
;; arg2 = ks   : pointer to 16 round keys (uint64_t[16], E-in-ks format)
;; arg3 = enc  : 1 = encrypt, 0 = decrypt
;; returns: processed block (L in low 32, R in high 32)
;; ============================================================================
align_function
MKGLOBAL(des_enc_dec_1_sse,function,internal)
des_enc_dec_1_sse:
        ;; Save 5 GP registers and allocate 16-byte aligned scratch for
        ;; sbox_1_to_8 spill (once for all rounds).
        ;; r10 = aligned pointer passed to sbox_1_to_8 via [r10]
        sub     rsp, 5*8 + 16
        mov     r10, rsp
        mov     [r10 + 16 + 8*0], rbx
        mov     [r10 + 16 + 8*1], r12
        mov     [r10 + 16 + 8*2], r13
        mov     [r10 + 16 + 8*3], r14
        mov     [r10 + 16 + 8*4], r15

%ifndef LINUX
        ;; Windows x64 ABI: xmm6-xmm15 are non-volatile (callee-saved)
        sub     rsp, 10*16
        movdqa  [rsp + 0*16], xmm6
        movdqa  [rsp + 1*16], xmm7
        movdqa  [rsp + 2*16], xmm8
        movdqa  [rsp + 3*16], xmm9
        movdqa  [rsp + 4*16], xmm10
        movdqa  [rsp + 5*16], xmm11
        movdqa  [rsp + 6*16], xmm12
        movdqa  [rsp + 7*16], xmm13
        movdqa  [rsp + 8*16], xmm14
        movdqa  [rsp + 9*16], xmm15
%endif

        ;; extract r and l from data
        mov     r12d, DWORD(arg1)       ; r = low32(data)
        shr     arg1, 32
        mov     r13d, DWORD(arg1)       ; l = high32(data)
        mov     r14, arg2               ; key schedule pointer

        ;; set up key direction: encrypt forward, decrypt backward
        xor     eax, eax
        mov     DWORD(arg1), 15 * 8     ;; decrypt: start at k[15], step -8
        mov     r15d, 8
        mov     rbx, -8
        test    DWORD(arg3), DWORD(arg3)
        cmovz   r15, rbx        ;; r15 is key pointer increment (enc: 8, dec: -8)
        cmovz   rax, arg1       ;; rax is key start offset (enc: 0, dec: 15*8)
        add     r14, rax        ;; adjust key pointer

        ;; === Initial Permutation (IP) ===
        ;; ip_z(pl=&r, pr=&l)
        PERMUTE_OP r13d, r12d, 4,  0x0f0f0f0f, eax, ecx
        PERMUTE_OP r12d, r13d, 16, 0x0000ffff, eax, ecx
        PERMUTE_OP r13d, r12d, 2,  0x33333333, eax, ecx
        PERMUTE_OP r12d, r13d, 8,  0x00ff00ff, eax, ecx
        PERMUTE_OP r13d, r12d, 1,  0x55555555, eax, ecx

        ;; Pre-rotate for E-in-key-schedule: R'=ROL(R,1), L'=ROL(L,1)
        rol     r12d, 1
        rol     r13d, 1

        ;; === 16 Feistel Rounds (8 pairs) ===
        ;; fRK result is NOT pre-rotated, so ROL(eax,1) compensates before XOR

        ;; 1
        ;; Round A: l' ^= ROL(fRK(r', key[i]), 1)
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        ;; Round B: r' ^= ROL(fRK(l', key[i+1]), 1)
        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax
        add     r14, r15

        ;; 2
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax
        add     r14, r15

        ;; 3
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax
        add     r14, r15

        ;; 4
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax
        add     r14, r15

        ;; 5
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax
        add     r14, r15

        ;; 6
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax
        add     r14, r15

        ;; 7
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax
        add     r14, r15

        ;; 8
        mov     r11d, r12d
        call    fRK
        rol     eax, 1
        xor     r13d, eax
        add     r14, r15

        mov     r11d, r13d
        call    fRK
        rol     eax, 1
        xor     r12d, eax

        ;; Un-rotate after rounds: R=ROR(R',1), L=ROR(L',1)
        ror     r12d, 1
        ror     r13d, 1

        ;; === Final Permutation (FP) ===
        ;; fp_z(pl=&r, pr=&l)
        PERMUTE_OP r12d, r13d, 1,  0x55555555, eax, ecx
        PERMUTE_OP r13d, r12d, 8,  0x00ff00ff, eax, ecx
        PERMUTE_OP r12d, r13d, 2,  0x33333333, eax, ecx
        PERMUTE_OP r13d, r12d, 16, 0x0000ffff, eax, ecx
        PERMUTE_OP r12d, r13d, 4,  0x0f0f0f0f, eax, ecx

        ;; return ((uint64_t)l) | (((uint64_t)r) << 32)
        mov     eax, r13d
        mov     ecx, r12d
        shl     rcx, 32
        or      rax, rcx

%ifdef SAFE_DATA
        ;; clear XMM's and sbox_1_to_8 scratch
        clear_scratch_xmms_sse_asm
        movdqa  [r10], xmm0
%endif

%ifndef LINUX
        movdqa  xmm6,  [rsp + 0*16]
        movdqa  xmm7,  [rsp + 1*16]
        movdqa  xmm8,  [rsp + 2*16]
        movdqa  xmm9,  [rsp + 3*16]
        movdqa  xmm10, [rsp + 4*16]
        movdqa  xmm11, [rsp + 5*16]
        movdqa  xmm12, [rsp + 6*16]
        movdqa  xmm13, [rsp + 7*16]
        movdqa  xmm14, [rsp + 8*16]
        movdqa  xmm15, [rsp + 9*16]
        add     rsp, 10*16
%endif

        mov     rbx, [r10 + 16 + 8*0]
        mov     r12, [r10 + 16 + 8*1]
        mov     r13, [r10 + 16 + 8*2]
        mov     r14, [r10 + 16 + 8*3]
        mov     r15, [r10 + 16 + 8*4]

        add     rsp, 5*8 + 16
        ret


mksection stack-noexec
