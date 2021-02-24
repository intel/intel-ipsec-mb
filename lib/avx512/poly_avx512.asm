;;
;; Copyright (c) 2021, Intel Corporation
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
%include "include/reg_sizes.asm"
%include "include/memcpy.asm"
%include "include/imb_job.asm"
%include "include/clear_regs.asm"

[bits 64]
default rel

align 64
mask_26:
dq      0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff

align 64
high_bit:
dq      0x1000000, 0x1000000, 0x1000000, 0x1000000, 0x1000000, 0x1000000, 0x1000000, 0x1000000

align 64
byte_len_to_mask_table:
        dw      0x0000, 0x0001, 0x0003, 0x0007,
        dw      0x000f, 0x001f, 0x003f, 0x007f,
        dw      0x00ff, 0x01ff, 0x03ff, 0x07ff,
        dw      0x0fff, 0x1fff, 0x3fff, 0x7fff,
        dw      0xffff

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx

%define job     arg1
%define gp1     rsi
%define gp2     rcx

%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9

%define job     rdi
%define gp1     rcx     ;; 'arg1' copied to 'job' at start
%define gp2     rsi
%endif

;; don't use rdx and rax - they are needed for multiply operation
%define gp3     rbp
%define gp4     r8
%define gp5     r9
%define gp6     r10
%define gp7     r11
%define gp8     r12
%define gp9     r13
%define gp10    r14
%define gp11    r15

%xdefine len    gp11
%xdefine msg    gp10

%define POLY1305_BLOCK_SIZE 16

%define APPEND(a,b) a %+ b

struc STACKFRAME
_gpr_save:      resq    8
_r_save:        resq    16 ; Memory to save limbs of powers of R
_rp_save:       resq    8  ; Memory to save limbs of powers of R'
endstruc

section .text

;; =============================================================================
;; Transposes the quadwords of 4 YMM registers
;; =============================================================================
%macro TRANSPOSE4_U64 8
%define %%R0    %1 ; [in/out] YMM with Input row 0 / Output column 0
%define %%R1    %2 ; [in/out] YMM with Input row 1 / Output column 1
%define %%R2    %3 ; [in/out] YMM with Input row 2 / Output column 2
%define %%R3    %4 ; [in/out] YMM with Input row 3 / Output column 3
%define %%T0    %5 ; [clobbered] Temporary YMM register
%define %%T1    %6 ; [clobbered] Temporary YMM register
%define %%T2    %7 ; [clobbered] Temporary YMM register
%define %%T3    %8 ; [clobbered] Temporary YMM register

        vshufpd	%%T0, %%R0, %%R1, 0x0
        vshufpd	%%T1, %%R0, %%R1, 0xF
        vshufpd	%%T2, %%R2, %%R3, 0x0
        vshufpd	%%T3, %%R2, %%R3, 0xF

	vperm2i128 %%R0, %%T0, %%T2, 0x20
	vperm2i128 %%R2, %%T0, %%T2, 0x31
	vperm2i128 %%R1, %%T1, %%T3, 0x20
	vperm2i128 %%R3, %%T1, %%T3, 0x31
%endmacro

;; =============================================================================
;; =============================================================================
;; Initializes POLY1305 context structure
;; =============================================================================
%macro POLY1305_INIT 6
%define %%KEY %1        ; [in] pointer to 32-byte key
%define %%A0  %2        ; [out] GPR with accumulator bits 63..0
%define %%A1  %3        ; [out] GPR with accumulator bits 127..64
%define %%A2  %4        ; [out] GPR with accumulator bits 195..128
%define %%R0  %5        ; [out] GPR with R constant bits 63..0
%define %%R1  %6        ; [out] GPR with R constant bits 127..64

        ;; R = KEY[0..15] & 0xffffffc0ffffffc0ffffffc0fffffff
        mov     %%R0, 0x0ffffffc0fffffff
        and     %%R0, [%%KEY + (0 * 8)]

        mov     %%R1, 0x0ffffffc0ffffffc
        and     %%R1, [%%KEY + (1 * 8)]

        ;; set accumulator to 0
        xor     %%A0, %%A0
        xor     %%A1, %%A1
        xor     %%A2, %%A2
%endmacro

;; =============================================================================
;; =============================================================================
;; Computes hash for message length being multiple of block size
;; =============================================================================
%macro POLY1305_MUL_REDUCE 11
%define %%A0      %1    ; [in/out] GPR with accumulator bits 63:0
%define %%A1      %2    ; [in/out] GPR with accumulator bits 127:64
%define %%A2      %3    ; [in/out] GPR with accumulator bits 195:128
%define %%R0      %4    ; [in] GPR with R constant bits 63:0
%define %%R1      %5    ; [in] GPR with R constant bits 127:64
%define %%C1      %6    ; [in] C1 = R1 + (R1 >> 2)
%define %%T1      %7    ; [clobbered] GPR register
%define %%T2      %8    ; [clobbered] GPR register
%define %%T3      %9    ; [clobbered] GPR register
%define %%GP_RAX  %10   ; [clobbered] RAX register
%define %%GP_RDX  %11   ; [clobbered] RDX register

        ;; Combining 64-bit x 64-bit multiplication with reduction steps
        ;;
        ;; NOTES:
        ;;   1) A2 here is only two bits so anything above is subject of reduction.
        ;;      Constant C1 = R1 + (R1 >> 2) simplifies multiply with less operations
        ;;   2) Magic 5x comes from mod 2^130-5 property and incorporating
        ;;      reduction into multiply phase.
        ;;      See "Cheating at modular arithmetic" and "Poly1305's prime: 2^130 - 5"
        ;;      paragraphs at https://loup-vaillant.fr/tutorials/poly1305-design for more details.
        ;;
        ;; Flow of the code below is as follows:
        ;;
        ;;          A2        A1        A0
        ;;        x           R1        R0
        ;;   -----------------------------
        ;;       A2×R0     A1×R0     A0×R0
        ;;   +             A0×R1
        ;;   +           5xA2xR1   5xA1xR1
        ;;   -----------------------------
        ;;     [0|L2L] [L1H|L1L] [L0H|L0L]
        ;;
        ;;   Registers:  T3:T2     T1:A0
        ;;
        ;; Completing the multiply and adding (with carry) 3x128-bit limbs into
        ;; 192-bits again (3x64-bits):
        ;; A0 = L0L
        ;; A1 = L0H + L1L
        ;; T3 = L1H + L2L

        ;; T3:T2 = (A0 * R1)
        mov     %%GP_RAX, %%R1
        mul     %%A0
        mov     %%T2, %%GP_RAX
        mov     %%GP_RAX, %%R0
        mov     %%T3, %%GP_RDX

        ;; T1:A0 = (A0 * R0)
        mul     %%A0
        mov     %%A0, %%GP_RAX  ;; A0 not used in other operations
        mov     %%GP_RAX, %%R0
        mov     %%T1, %%GP_RDX

        ;; T3:T2 += (A1 * R0)
        mul     %%A1
        add     %%T2, %%GP_RAX
        mov     %%GP_RAX, %%C1
        adc     %%T3, %%GP_RDX

        ;; T1:A0 += (A1 * R1x5)
        mul     %%A1
        mov     %%A1, %%A2      ;; use A1 for A2
        add     %%A0, %%GP_RAX
        adc     %%T1, %%GP_RDX

        ;; NOTE: A2 is clamped to 2-bits,
        ;;       R1/R0 is clamped to 60-bits,
        ;;       their product is less than 2^64.

        ;; T3:T2 += (A2 * R1x5)
        imul    %%A1, %%C1
        add     %%T2, %%A1
        mov     %%A1, %%T1 ;; T1:A0 => A1:A0
        adc     %%T3, 0

        ;; T3:A1 += (A2 * R0)
        imul    %%A2, %%R0
        add     %%A1, %%T2
        adc     %%T3, %%A2

        ;; At this point, 3 64-bit limbs are in T3:A1:A0
        ;; T3 can span over more than 2 bits so final partial reduction step is needed.
        ;;
        ;; Partial reduction (just to fit into 130 bits)
        ;;    A2 = T3 & 3
        ;;    k = (T3 & ~3) + (T3 >> 2)
        ;;         Y    x4  +  Y    x1
        ;;    A2:A1:A0 += k
        ;;
        ;; Result will be in A2:A1:A0
        mov     %%T1, %%T3
        mov     DWORD(%%A2), DWORD(%%T3)
        and     %%T1, ~3
        shr     %%T3, 2
        and     DWORD(%%A2), 3
        add     %%T1, %%T3

        ;; A2:A1:A0 += k (kept in T1)
        add     %%A0, %%T1
        adc     %%A1, 0
        adc     DWORD(%%A2), 0
%endmacro

;; =============================================================================
;; =============================================================================
;; Computes hash for 8 16-byte message blocks.
;; It computes H8 = ((H0 + M1) * R^8 + M2 * R^7 + M3 * R^6 + M4 * R^5 +
;;                   M5 * R^4 + M6 * R^3 + M7 * R^2 + M8 * R)
;;
;; It first multiplies all 8 blocks with powers of R:
;;
;;      a4      a3      a2      a1      a0
;; ×    b4      b3      b2      b1      b0
;; ---------------------------------------
;;   a4×b0   a3×b0   a2×b0   a1×b0   a0×b0
;; + a3×b1   a2×b1   a1×b1   a0×b1 5×a4×b1
;; + a2×b2   a1×b2   a0×b2 5×a4×b2 5×a3×b2
;; + a1×b3   a0×b3 5×a4×b3 5×a3×b3 5×a2×b3
;; + a0×b4 5×a4×b4 5×a3×b4 5×a2×b4 5×a1×b4
;; ---------------------------------------
;;      p4      p3      p2      p1      p0
;;
;; Then, it propagates the carry (higher bits after bit 25) from lower limbs into higher limbs,
;; multiplying by 5 in case of the carry of p4.
;;
;; =============================================================================
%macro POLY1305_MUL_REDUCE_VEC 32
%define %%A0      %1  ; [in/out] ZMM register containing 1st 26-bit limb of the 8 blocks
%define %%A1      %2  ; [in/out] ZMM register containing 2nd 26-bit limb of the 8 blocks
%define %%A2      %3  ; [in/out] ZMM register containing 3rd 26-bit limb of the 8 blocks
%define %%A3      %4  ; [in/out] ZMM register containing 4th 26-bit limb of the 8 blocks
%define %%A4      %5  ; [in/out] ZMM register containing 5th 26-bit limb of the 8 blocks
%define %%R0      %6  ; [in] ZMM register (R0) to include the 1st limb in IDX
%define %%R1      %7  ; [in] ZMM register (R1) to include the 2nd limb in IDX
%define %%R2      %8  ; [in] ZMM register (R2) to include the 3rd limb in IDX
%define %%R3      %9  ; [in] ZMM register (R3) to include the 4th limb in IDX
%define %%R4      %10 ; [in] ZMM register (R4) to include the 5th limb in IDX
%define %%R1P     %11 ; [in] ZMM register (R1') to include the 2nd limb (multiplied by 5) in IDX
%define %%R2P     %12 ; [in] ZMM register (R2') to include the 3rd limb (multiplied by 5) in IDX
%define %%R3P     %13 ; [in] ZMM register (R3') to include the 4th limb (multiplied by 5) in IDX
%define %%R4P     %14 ; [in] ZMM register (R4') to include the 5th limb (multiplied by 5) in IDX
%define %%P0      %15 ; [clobbered] ZMM register to contain p[0] of the 8 blocks
%define %%P1      %16 ; [clobbered] ZMM register to contain p[1] of the 8 blocks
%define %%P2      %17 ; [clobbered] ZMM register to contain p[2] of the 8 blocks
%define %%P3      %18 ; [clobbered] ZMM register to contain p[3] of the 8 blocks
%define %%P4      %19 ; [clobbered] ZMM register to contain p[4] of the 8 blocks
%define %%MASK_26 %20 ; [in] ZMM register containing 26-bit mask
%define %%ZTMP1   %21 ; [clobbered] Temporary ZMM register
%define %%ZTMP2   %22 ; [clobbered] Temporary ZMM register
%define %%ZTMP3   %23 ; [clobbered] Temporary ZMM register
%define %%ZTMP4   %24 ; [clobbered] Temporary ZMM register
%define %%ZTMP5   %25 ; [clobbered] Temporary ZMM register
%define %%ZTMP6   %26 ; [clobbered] Temporary ZMM register
%define %%ZTMP7   %27 ; [clobbered] Temporary ZMM register
%define %%ZTMP8   %28 ; [clobbered] Temporary ZMM register
%define %%ZTMP9   %29 ; [clobbered] Temporary ZMM register
%define %%ZTMP10  %30 ; [clobbered] Temporary ZMM register
%define %%TMP     %31 ; [clobbered] Temporary GP register
%define %%TMP2    %32 ; [clobbered] Temporary GP register

%define %%XTMP1 XWORD(%%ZTMP1)
%define %%XTMP2 XWORD(%%ZTMP2)

        ; Calculate p[0] addends
        vpmuludq        %%ZTMP1, %%A0, %%R0
        vpmuludq        %%ZTMP2, %%A1, %%R4P
        vpmuludq        %%ZTMP3, %%A2, %%R3P
        vpmuludq        %%ZTMP4, %%A3, %%R2P
        vpmuludq        %%ZTMP5, %%A4, %%R1P

        ; Calculate p[1] addends
        vpmuludq        %%ZTMP6, %%A0, %%R1
        vpmuludq        %%ZTMP7, %%A1, %%R0
        vpmuludq        %%ZTMP8, %%A2, %%R4P
        vpmuludq        %%ZTMP9, %%A3, %%R3P
        vpmuludq        %%ZTMP10, %%A4, %%R2P

        ; Calculate p[0]
        vpaddq          %%P0, %%ZTMP1, %%ZTMP2
        vpaddq          %%P0, %%ZTMP3
        vpaddq          %%P0, %%ZTMP4
        vpaddq          %%P0, %%ZTMP5

        ; Calculate p[1]
        vpaddq          %%P1, %%ZTMP6, %%ZTMP7
        vpaddq          %%P1, %%ZTMP8
        vpaddq          %%P1, %%ZTMP9
        vpaddq          %%P1, %%ZTMP10

        ; Calculate p[2] addends
        vpmuludq        %%ZTMP1, %%A0, %%R2
        vpmuludq        %%ZTMP2, %%A1, %%R1
        vpmuludq        %%ZTMP3, %%A2, %%R0
        vpmuludq        %%ZTMP4, %%A3, %%R4P
        vpmuludq        %%ZTMP5, %%A4, %%R3P

        ; Calculate p[3] addends
        vpmuludq        %%ZTMP6, %%A0, %%R3
        vpmuludq        %%ZTMP7, %%A1, %%R2
        vpmuludq        %%ZTMP8, %%A2, %%R1
        vpmuludq        %%ZTMP9, %%A3, %%R0
        vpmuludq        %%ZTMP10, %%A4, %%R4P

        ; Calculate p[2]
        vpaddq          %%P2, %%ZTMP1, %%ZTMP2
        vpaddq          %%P2, %%ZTMP3
        vpaddq          %%P2, %%ZTMP4
        vpaddq          %%P2, %%ZTMP5

        ; Calculate p[3]
        vpaddq          %%P3, %%ZTMP6, %%ZTMP7
        vpaddq          %%P3, %%ZTMP8
        vpaddq          %%P3, %%ZTMP9
        vpaddq          %%P3, %%ZTMP10

        ; Calculate p[4] addends
        vpmuludq        %%ZTMP1, %%A0, %%R4
        vpmuludq        %%ZTMP2, %%A1, %%R3
        vpmuludq        %%ZTMP3, %%A2, %%R2
        vpmuludq        %%ZTMP4, %%A3, %%R1
        vpmuludq        %%ZTMP5, %%A4, %%R0

        ; Calculate p[4]
        vpaddq          %%P4, %%ZTMP1, %%ZTMP2
        vpaddq          %%P4, %%ZTMP3
        vpaddq          %%P4, %%ZTMP4
        vpaddq          %%P4, %%ZTMP5

        ; First pass of carry propagation
        vpsrlq          %%ZTMP1, %%P0, 26
        vpaddq          %%P1, %%ZTMP1
        vpsrlq          %%ZTMP1, %%P1, 26
        vpaddq          %%P2, %%ZTMP1
        vpsrlq          %%ZTMP1, %%P2, 26
        vpaddq          %%P3, %%ZTMP1
        vpsrlq          %%ZTMP1, %%P3, 26
        vpaddq          %%P4, %%ZTMP1

        vpsrlq          %%ZTMP1, %%P4, 26
        vpsllq          %%ZTMP2, %%ZTMP1, 2
        vpaddq          %%ZTMP1, %%ZTMP2 ; (*5)
        vpandq          %%P0, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%P1, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%P2, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%P3, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%P4, %%MASK_26 ; Clear top 32+6 bits
        vpaddq          %%P0, %%ZTMP1

        ; Second pass of carry propagation
        vpsrlq          %%ZTMP1, %%P0, 26
        vpaddq          %%P1, %%ZTMP1
        vpsrlq          %%ZTMP1, %%P1, 26
        vpaddq          %%P2, %%ZTMP1
        vpsrlq          %%ZTMP1, %%P2, 26
        vpaddq          %%P3, %%ZTMP1
        vpsrlq          %%ZTMP1, %%P3, 26
        vpaddq          %%P4, %%ZTMP1

        vpandq          %%A0, %%P0, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%A1, %%P1, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%A2, %%P2, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%A3, %%P3, %%MASK_26 ; Clear top 32+6 bits
        vpandq          %%A4, %%P4, %%MASK_26 ; Clear top 32+6 bits

%endmacro

;; =============================================================================
;; =============================================================================
;; Computes hash for message length being multiple of block size
;; =============================================================================
%macro POLY1305_BLOCKS 13
%define %%MSG     %1    ; [in/out] GPR pointer to input message (updated)
%define %%LEN     %2    ; [in/out] GPR in: length in bytes / out: length mod 16
%define %%A0      %3    ; [in/out] accumulator bits 63..0
%define %%A1      %4    ; [in/out] accumulator bits 127..64
%define %%A2      %5    ; [in/out] accumulator bits 195..128
%define %%R0      %6    ; [in] R constant bits 63..0
%define %%R1      %7    ; [in] R constant bits 127..64
%define %%T0      %8    ; [clobbered] GPR register
%define %%T1      %9    ; [clobbered] GPR register
%define %%T2      %10   ; [clobbered] GPR register
%define %%T3      %11   ; [clobbered] GPR register
%define %%GP_RAX  %12   ; [clobbered] RAX register
%define %%GP_RDX  %13   ; [clobbered] RDX register

%define %%MASK_26 zmm31

        ; Minimum of 256 bytes to run vectorized code
        cmp     %%LEN, POLY1305_BLOCK_SIZE*16
        jb      %%_final_loop

        vmovdqa64 %%MASK_26, [rel mask_26]

        ; Spread accumulator into 26-bit limbs in quadwords
        mov     %%T0, %%A0
        and     %%T0, 0x3ffffff ;; First limb (A[25:0])
        vmovq   xmm5, %%T0

        mov     %%T0, %%A0
        shr     %%T0, 26
        and     %%T0, 0x3ffffff ;; Second limb (A[51:26])
        vmovq   xmm6, %%T0

        mov     %%T0, %%A1
        shrd    %%A0, %%T0, 52
        and     %%A0, 0x3ffffff ;; Third limb (A[77:52])
        vmovq   xmm7, %%A0

        mov     %%T0, %%A1
        shr     %%T0, 14
        and     %%T0, 0x3ffffff ; Fourth limb (A[103:78])
        vmovq   xmm8, %%T0

        shrd    %%A1, %%A2, 40
        vmovq   xmm9, %%A1

        ; Load first block of data (128 bytes)
        vmovdqu64 zmm0, [%%MSG]
        vmovdqu64 zmm1, [%%MSG + 64]

        ; Interleave the data to form 26-bit limbs
        ;
        ; zmm15 to have bits 0-25 of all 8 blocks in 8 qwords
        ; zmm16 to have bits 51-26 of all 8 blocks in 8 qwords
        ; zmm17 to have bits 77-52 of all 8 blocks in 8 qwords
        ; zmm18 to have bits 103-78 of all 8 blocks in 8 qwords
        ; zmm19 to have bits 127-104 of all 8 blocks in 8 qwords
        vpunpckhqdq zmm19, zmm0, zmm1
        vpunpcklqdq zmm15, zmm0, zmm1

        vpsrlq  zmm17, zmm15, 52
        vpsllq  zmm18, zmm19, 12

        vpsrlq  zmm16, zmm15, 26
        vpsrlq  zmm20, zmm19, 14
        vpsrlq  zmm19, 40
        vpandq  zmm15, %%MASK_26
        vpandq  zmm16, %%MASK_26
        vpternlogq zmm17, zmm18, %%MASK_26, 0xA8 ; (A OR B AND C)
        vpandq  zmm18, zmm20, %%MASK_26

        ; Add 2^128 to all 8 final qwords of the message
        vporq   zmm19, [rel high_bit]

        vpaddq  zmm15, zmm5
        vpaddq  zmm16, zmm6
        vpaddq  zmm17, zmm7
        vpaddq  zmm18, zmm8
        vpaddq  zmm19, zmm9

        ; Use memory in stack to save powers of R, before loading them into ZMM registers
        ; The first 16*8 bytes will contain the 16 bytes of the 8 powers of R
        ; The last 64 bytes will contain the last 2 bits of powers of R, spread in 8 qwords,
        ; to be OR'd with the highest qwords (in zmm26)
        mov     [rsp + _r_save + 16*7], %%R0
        mov     [rsp + _r_save + 16*7 + 8], %%R1

        xor     %%T0, %%T0
        mov     [rsp + _rp_save + 8*7], %%T0

        ; Calculate R^2
        mov     %%T0, %%R1
        shr     %%T0, 2
        add     %%T0, %%R1      ;; T0 = R1 + (R1 >> 2)

        mov     %%A0, %%R0
        mov     %%A1, %%R1
        xor     %%A2, %%A2

        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        mov     [rsp + _r_save + 16*6], %%A0
        mov     [rsp + _r_save + 16*6 + 8], %%A1
        mov     %%T3, %%A2
        shl     %%T3, 24
        mov     [rsp + _rp_save + 8*5], %%T3

        ; Calculate R^3
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        mov     [rsp + _r_save + 16*5], %%A0
        mov     [rsp + _r_save + 16*5 + 8], %%A1
        mov     %%T3, %%A2
        shl     %%T3, 24
        mov     [rsp + _rp_save + 8*3], %%T3

        ; Calculate R^4
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        mov     [rsp + _r_save + 16*4], %%A0
        mov     [rsp + _r_save + 16*4 + 8], %%A1
        mov     %%T3, %%A2
        shl     %%T3, 24
        mov     [rsp + _rp_save + 8], %%T3

        ; Calculate R^5
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        mov     [rsp + _r_save + 16*3], %%A0
        mov     [rsp + _r_save + 16*3 + 8], %%A1
        mov     %%T3, %%A2
        shl     %%T3, 24
        mov     [rsp + _rp_save + 8*6], %%T3

        ; Calculate R^6
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        mov     [rsp + _r_save + 16*2], %%A0
        mov     [rsp + _r_save + 16*2 + 8], %%A1
        mov     %%T3, %%A2
        shl     %%T3, 24
        mov     [rsp + _rp_save + 8*4], %%T3

        ; Calculate R^7
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        mov     [rsp + _r_save + 16], %%A0
        mov     [rsp + _r_save + 16 + 8], %%A1
        mov     %%T3, %%A2
        shl     %%T3, 24
        mov     [rsp + _rp_save + 8*2], %%T3

        ; Calculate R^8
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        mov     [rsp + _r_save], %%A0
        mov     [rsp + _r_save + 8], %%A1
        mov     %%T3, %%A2
        shl     %%T3, 24
        mov     [rsp + _rp_save], %%T3

        ; Broadcast 26-bit limbs of R^8
        mov     %%T0, %%A0
        and     %%T0, 0x3ffffff ;; First limb (R^8[25:0])
        vpbroadcastq zmm22, %%T0

        mov     %%T0, %%A0
        shr     %%T0, 26
        and     %%T0, 0x3ffffff ;; Second limb (R^8[51:26])
        vpbroadcastq zmm23, %%T0

        mov     %%T0, %%A1
        shrd    %%A0, %%T0, 52
        and     %%A0, 0x3ffffff ;; Third limb (R^8[77:52])
        vpbroadcastq zmm24, %%A0

        mov     %%T0, %%A1
        shr     %%T0, 14
        and     %%T0, 0x3ffffff ; Fourth limb (R^8[103:78])
        vmovq   xmm0, %%T0
        vpbroadcastq zmm25, %%T0

        shrd    %%A1, %%A2, 40 ;; Fifth limb (R^8[129:104])
        vpbroadcastq zmm26, %%A1

        ; Generate 5*R^8
        vpsllq  zmm27, zmm23, 2
        vpsllq  zmm28, zmm24, 2
        vpsllq  zmm29, zmm25, 2
        vpsllq  zmm30, zmm26, 2

        vpaddq  zmm27, zmm23
        vpaddq  zmm28, zmm24
        vpaddq  zmm29, zmm25
        vpaddq  zmm30, zmm26

        ; Perform first 8 multiplications by R^8

        ; zmm15-zmm19 contain the 8 blocks of message plus the previous accumulator
        ; zmm22-26 contain the 5x26-bit limbs of the powers of R^8
        ; zmm27-30 contain the 5x26-bit limbs of the powers of R^8' (5*R^8)
        POLY1305_MUL_REDUCE_VEC zmm15, zmm16, zmm17, zmm18, zmm19, \
                                zmm22, zmm23, zmm24, zmm25, zmm26, \
                                zmm27, zmm28, zmm29, zmm30, \
                                zmm5, zmm6, zmm7, zmm8, zmm9, zmm31, \
                                zmm10, zmm11, zmm12, zmm13, zmm14, \
                                zmm0, zmm1, zmm2, zmm3, zmm4, \
                                %%GP_RAX, %%GP_RDX

        sub     %%LEN, 128
        add     %%MSG, 128

        mov     %%T0, %%LEN
        and     %%T0, 0xffffffffffffff80 ; multiple of 128 bytes

%%_poly1305_blocks_loop:
        cmp     %%T0, 128
        jbe     %%_poly1305_blocks_loop_end

        ; Load next block of data (128 bytes)
        vmovdqu64 zmm0, [%%MSG]
        vmovdqu64 zmm1, [%%MSG + 64]

        ; Interleave the data to form 26-bit limbs
        ;
        ; zmm0 to have bits 0-25 of all 8 blocks in 8 qwords
        ; zmm1 to have bits 51-26 of all 8 blocks in 8 qwords
        ; zmm2 to have bits 77-52 of all 8 blocks in 8 qwords
        ; zmm3 to have bits 103-78 of all 8 blocks in 8 qwords
        ; zmm4 to have bits 127-104 of all 8 blocks in 8 qwords
        vpunpckhqdq zmm4, zmm0, zmm1
        vpunpcklqdq zmm0, zmm0, zmm1

        vpsrlq  zmm2, zmm0, 52
        vpsllq  zmm3, zmm4, 12
        vpsrlq  zmm1, zmm0, 26
        vpsrlq  zmm5, zmm4, 14
        vpsrlq  zmm4, 40
        vpandq  zmm0, %%MASK_26
        vpandq  zmm1, %%MASK_26
        vpternlogq zmm2, zmm3, %%MASK_26, 0xA8 ; (A OR B AND C)
        vpandq  zmm5, %%MASK_26

        ; Add 2^128 to all 8 final qwords of the message
        vporq   zmm4, [rel high_bit]

        ; Add new message blocks to previous accumulator
        vpaddq  zmm15, zmm0
        vpaddq  zmm16, zmm1
        vpaddq  zmm17, zmm2
        vpaddq  zmm18, zmm5
        vpaddq  zmm19, zmm4

        ; zmm15-zmm19 contain the 8 blocks of message plus the previous accumulator
        ; zmm22-26 contain the 5x26-bit limbs of the powers of R
        ; zmm27-30 contain the 5x26-bit limbs of the powers of R' (5*R)
        POLY1305_MUL_REDUCE_VEC zmm15, zmm16, zmm17, zmm18, zmm19, \
                                zmm22, zmm23, zmm24, zmm25, zmm26, \
                                zmm27, zmm28, zmm29, zmm30, \
                                zmm5, zmm6, zmm7, zmm8, zmm9, zmm31, \
                                zmm10, zmm11, zmm12, zmm13, zmm14, \
                                zmm0, zmm1, zmm2, zmm3, zmm4, \
                                %%GP_RAX, %%GP_RDX

        add     %%MSG, POLY1305_BLOCK_SIZE*8
        sub     %%T0, POLY1305_BLOCK_SIZE*8

        jmp     %%_poly1305_blocks_loop

%%_poly1305_blocks_loop_end:

        ;; Need to multiply by r^8,r^7... r

        ; Interleave the powers of R to form 26-bit limbs
        ;
        ; zmm22 to have bits 0-25 of all 8 powers of R in 8 qwords
        ; zmm23 to have bits 51-26 of all 8 powers of R in 8 qwords
        ; zmm24 to have bits 77-52 of all 8 powers of R in 8 qwords
        ; zmm25 to have bits 103-78 of all 8 powers of R in 8 qwords
        ; zmm26 to have bits 127-104 of all 8 powers of R in 8 qwords
        vmovdqu64 zmm0, [rsp + _r_save]
        vmovdqu64 zmm1, [rsp + _r_save + 64]

        vpunpckhqdq zmm26, zmm0, zmm1
        vpunpcklqdq zmm22, zmm0, zmm1

        vpsrlq  zmm24, zmm22, 52
        vpsllq  zmm25, zmm26, 12
        vpsrlq  zmm23, zmm22, 26
        vpsrlq  zmm30, zmm26, 14
        vpsrlq  zmm26, 40

        vpandq  zmm22, %%MASK_26                 ; R0
        vpandq  zmm23, %%MASK_26                 ; R1
        vpternlogq zmm24, zmm25, %%MASK_26, 0xA8 ; R2 (A OR B AND C)
        vpandq  zmm25, zmm30, %%MASK_26          ; R3

        ; rsp + _rp_save contains the 2 highest bits of the powers of R
        vporq   zmm26, [rsp + _rp_save]   ; R4

        ; zmm27 to have bits 51-26 of all 8 powers of R' in 8 qwords
        ; zmm28 to have bits 77-52 of all 8 powers of R' in 8 qwords
        ; zmm29 to have bits 103-78 of all 8 powers of R' in 8 qwords
        ; zmm30 to have bits 127-104 of all 8 powers of R' in 8 qwords
        vpsllq  zmm0, zmm23, 2
        vpaddq  zmm27, zmm23, zmm0 ; R1' (R1*5)

        vpsllq  zmm1, zmm24, 2
        vpaddq  zmm28, zmm24, zmm1 ; R2' (R2*5)

        vpsllq  zmm2, zmm25, 2
        vpaddq  zmm29, zmm25, zmm2 ; R3' (R3*5)

        vpsllq  zmm3, zmm26, 2
        vpaddq  zmm30, zmm26, zmm3 ; R4' (R4*5)

        ; Load next block of data (128 bytes)
        vmovdqu64 zmm0, [%%MSG]
        vmovdqu64 zmm1, [%%MSG + 64]

        ; Interleave the data to form 26-bit limbs
        ;
        ; zmm0 to have bits 0-25 of all 8 blocks in 8 qwords
        ; zmm1 to have bits 51-26 of all 8 blocks in 8 qwords
        ; zmm2 to have bits 77-52 of all 8 blocks in 8 qwords
        ; zmm3 to have bits 103-78 of all 8 blocks in 8 qwords
        ; zmm4 to have bits 127-104 of all 8 blocks in 8 qwords
        vpunpckhqdq zmm4, zmm0, zmm1
        vpunpcklqdq zmm0, zmm0, zmm1

        vpsrlq  zmm2, zmm0, 52
        vpsllq  zmm3, zmm4, 12
        vpsrlq  zmm1, zmm0, 26
        vpsrlq  zmm5, zmm4, 14
        vpsrlq  zmm4, 40
        vpandq  zmm0, %%MASK_26
        vpandq  zmm1, %%MASK_26
        vpternlogq zmm2, zmm3, %%MASK_26, 0xA8 ; (A OR B AND C)
        vpandq  zmm3, zmm5, %%MASK_26

        ; Add 2^128 to all 8 final qwords of the message
        vporq   zmm4, [rel high_bit]

        ; Add previous accumulator to first block of message
        vpaddq  zmm15, zmm0
        vpaddq  zmm16, zmm1
        vpaddq  zmm17, zmm2
        vpaddq  zmm18, zmm3
        vpaddq  zmm19, zmm4

        ; zmm15-zmm19 contain the 8 blocks of message plus the previous accumulator
        ; zmm22-26 contain the 5x26-bit limbs of the powers of R
        ; zmm27-30 contain the 5x26-bit limbs of the powers of R' (5*R)
        POLY1305_MUL_REDUCE_VEC zmm15, zmm16, zmm17, zmm18, zmm19, \
                                zmm22, zmm23, zmm24, zmm25, zmm26, \
                                zmm27, zmm28, zmm29, zmm30, \
                                zmm5, zmm6, zmm7, zmm8, zmm9, zmm31, \
                                zmm10, zmm11, zmm12, zmm13, zmm14, \
                                zmm0, zmm1, zmm2, zmm3, zmm4, \
                                %%GP_RAX, %%GP_RDX

        ;; Add all blocks
        vmovdqa64       zmm0, zmm15
        vmovdqa64       zmm1, zmm16
        vmovdqa64       zmm2, zmm17
        vmovdqa64       zmm3, zmm18
        vmovdqa64       zmm4, zmm19

        vextracti64x4   YWORD(zmm5), zmm0, 1
        vextracti64x4   YWORD(zmm6), zmm1, 1
        vextracti64x4   YWORD(zmm7), zmm2, 1
        vextracti64x4   YWORD(zmm8), zmm3, 1
        vextracti64x4   YWORD(zmm9), zmm4, 1

        ; Transpose first 32 bytes of P0-P3
        TRANSPOSE4_U64  YWORD(zmm0), YWORD(zmm1), YWORD(zmm2), YWORD(zmm3), \
                        YWORD(zmm10), YWORD(zmm11), YWORD(zmm12), ymm13

        ; Transpose final 32 bytes of P0-P3
        TRANSPOSE4_U64  YWORD(zmm5), YWORD(zmm6), YWORD(zmm7), YWORD(zmm8), \
                        YWORD(zmm10), YWORD(zmm11), YWORD(zmm12), ymm13

        ; Add all P0, P1, P2, P3
        vpaddq          zmm0, zmm1
        vpaddq          zmm0, zmm2
        vpaddq          zmm0, zmm3
        vpaddq          zmm0, zmm5
        vpaddq          zmm0, zmm6
        vpaddq          zmm0, zmm7
        vpaddq          zmm0, zmm8

        ; Add all P4
        vmovq           %%T0, XWORD(zmm4) ; P4
        vpextrq         %%T1, XWORD(zmm4), 1 ; P4^2
        add             %%T0, %%T1
        vextracti32x4   XWORD(zmm1), zmm4, 1
        vmovq           %%T1, XWORD(zmm1) ; P4^3
        add             %%T0, %%T1
        vpextrq         %%T1, XWORD(zmm1), 1 ; P4^4
        add             %%T0, %%T1 ; %%T0 = P4 + P4^2 + P4^3 + P4^4

        vmovq           %%T1, XWORD(zmm9) ; P4^5
        add             %%T0, %%T1
        vpextrq         %%T1, XWORD(zmm9), 1 ; P4^6
        add             %%T0, %%T1
        vextracti32x4   XWORD(zmm1), zmm9, 1
        vmovq           %%T1, XWORD(zmm1) ; P4^7
        add             %%T0, %%T1
        vpextrq         %%T1, XWORD(zmm1), 1 ; P4^8
        add             %%T0, %%T1 ; %%T0 = P4 + P4^2 + P4^3 + P4^4 + ... P^8
        vmovq           xmm19, %%T0

        ; Move P0-P4 to A0-A4
        vmovq           %%T0, XWORD(zmm0)
        vmovq           xmm15, %%T0
        vpextrq         %%T0, XWORD(zmm0), 1
        vmovq           xmm16, %%T0
        vextracti32x4   XWORD(zmm1), zmm0, 1
        vmovq           %%T0, XWORD(zmm1)
        vmovq           xmm17, %%T0
        vpextrq         %%T0, XWORD(zmm1), 1
        vmovq           xmm18, %%T0

        ; Carry propagation
        vpsrlq          xmm0, xmm15, 26
        vpandq          xmm15, XWORD(%%MASK_26) ; Clear top 32+6 bits
        vpaddq          xmm16, xmm0
        vpsrlq          xmm0, xmm16, 26
        vpandq          xmm16, XWORD(%%MASK_26) ; Clear top 32+6 bits
        vpaddq          xmm17, xmm0
        vpsrlq          xmm0, xmm17, 26
        vpandq          xmm17, XWORD(%%MASK_26) ; Clear top 32+6 bits
        vpaddq          xmm18, xmm0
        vpsrlq          xmm0, xmm18, 26
        vpandq          xmm18, XWORD(%%MASK_26) ; Clear top 32+6 bits
        vpaddq          xmm19, xmm0
        vpsrlq          xmm0, xmm19, 26
        vpandq          xmm19, XWORD(%%MASK_26) ; Clear top 32+6 bits
        vmovdqa64       xmm1, xmm0
        vpsllq          xmm0, 2
        vpaddq          xmm0, xmm1
        vpaddq          xmm15, xmm0

        ; Put together A
        vmovq   %%A0, xmm15
        vmovq   %%T0, xmm16
        shl     %%T0, 26
        or      %%A0, %%T0
        vmovq   %%T0, xmm17
        mov     %%T1, %%T0
        shl     %%T1, 52
        or      %%A0, %%T1
        shr     %%T0, 12
        mov     %%A1, %%T0
        vmovq   %%T1, xmm18
        shl     %%T1, 14
        or      %%A1, %%T1
        vmovq   %%T0, xmm19
        mov     %%T1, %%T0
        shl     %%T1, 40
        or      %%A1, %%T1
        shr     %%T0, 24
        mov     %%A2, %%T0

        add     %%MSG, 128

        and     %%LEN, 0x7f ; Get remaining lengths (LEN < 128 bytes)
        vzeroupper
%%_final_loop:
        cmp     %%LEN, POLY1305_BLOCK_SIZE
        jb      %%_poly1305_blocks_exit

        ;; A += MSG[i]
        add     %%A0, [%%MSG + 0]
        adc     %%A1, [%%MSG + 8]
        adc     %%A2, 1                 ;; no padding bit

        mov     %%T0, %%R1
        shr     %%T0, 2
        add     %%T0, %%R1      ;; T0 = R1 + (R1 >> 2)

        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, \
                            %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        add     %%MSG, POLY1305_BLOCK_SIZE
        sub     %%LEN, POLY1305_BLOCK_SIZE

        jmp     %%_final_loop
%%_poly1305_blocks_exit:
%endmacro

;; =============================================================================
;; =============================================================================
;; Computes hash for the final partial block
;; =============================================================================
%macro POLY1305_PARTIAL_BLOCK 15
%define %%BUF     %1    ; [in/clobbered] pointer to 16 byte scratch buffer
%define %%MSG     %2    ; [in] GPR pointer to input message
%define %%LEN     %3    ; [in] GPR message length
%define %%A0      %4    ; [in/out] accumulator bits 63..0
%define %%A1      %5    ; [in/out] accumulator bits 127..64
%define %%A2      %6    ; [in/out] accumulator bits 195..128
%define %%R0      %7    ; [in] R constant bits 63..0
%define %%R1      %8    ; [in] R constant bits 127..64
%define %%T0      %9    ; [clobbered] GPR register
%define %%T1      %10   ; [clobbered] GPR register
%define %%T2      %11   ; [clobbered] GPR register
%define %%T3      %12   ; [clobbered] GPR register
%define %%GP_RAX  %13   ; [clobbered] RAX register
%define %%GP_RDX  %14   ; [clobbered] RDX register
%define %%PAD_16  %15   ; [in] text "pad_to_16" or "no_padding"

        lea     %%T1, [rel byte_len_to_mask_table]
        kmovq   k1, [%%T1 + %%LEN*2]
        vmovdqu8 xmm0{k1}{z}, [%%MSG]
        vmovdqu64 [%%BUF], xmm0

%ifnidn %%PAD_16,pad_to_16
        ;; pad the message in the scratch buffer
        mov     byte [%%BUF + %%LEN], 0x01
%endif
        ;; A += MSG[i]
        add     %%A0, [%%BUF + 0]
        adc     %%A1, [%%BUF + 8]
%ifnidn %%PAD_16,pad_to_16
        adc     %%A2, 0                 ;; no padding bit
%else
        adc     %%A2, 1                 ;; padding bit please
%endif

        mov     %%T0, %%R1
        shr     %%T0, 2
        add     %%T0, %%R1      ;; T0 = R1 + (R1 >> 2)

        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, \
                            %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

%ifdef SAFE_DATA
        ;; clear the scratch buffer
        vpxorq  xmm0, xmm0
        vmovdqu64 [%%BUF], xmm0
%endif

%endmacro

;; =============================================================================
;; =============================================================================
;; Finalizes Poly1305 hash calculation on a message
;; =============================================================================
%macro POLY1305_FINALIZE 8
%define %%KEY     %1    ; [in] pointer to 32 byte key
%define %%MAC     %2    ; [in/out] pointer to store MAC value into (16 bytes)
%define %%A0      %3    ; [in/out] accumulator bits 63..0
%define %%A1      %4    ; [in/out] accumulator bits 127..64
%define %%A2      %5    ; [in/out] accumulator bits 195..128
%define %%T0      %6    ; [clobbered] GPR register
%define %%T1      %7    ; [clobbered] GPR register
%define %%T2      %8    ; [clobbered] GPR register

        ;; T = A - P, where P = 2^130 - 5
        ;;     P[63..0]    = 0xFFFFFFFFFFFFFFFB
        ;;     P[127..64]  = 0xFFFFFFFFFFFFFFFF
        ;;     P[195..128] = 0x0000000000000003
        mov     %%T0, %%A0
        mov     %%T1, %%A1
        mov     %%T2, %%A2

        sub     %%T0, -5        ;; 0xFFFFFFFFFFFFFFFB
        sbb     %%T1, -1        ;; 0xFFFFFFFFFFFFFFFF
        sbb     %%T2, 0x3

        ;; if A > (2^130 - 5) then A = T
        ;;     - here, if borrow/CF == false then A = T
        cmovnc  %%A0, %%T0
        cmovnc  %%A1, %%T1

        ;; MAC = (A + S) mod 2^128 (S = key[16..31])
        add     %%A0, [%%KEY + (2 * 8)]
        adc     %%A1, [%%KEY + (3 * 8)]

        ;; store MAC
        mov     [%%MAC + (0 * 8)], %%A0
        mov     [%%MAC + (1 * 8)], %%A1
%endmacro

;; =============================================================================
;; =============================================================================
;; Creates stack frame and saves registers
;; =============================================================================
%macro FUNC_ENTRY 0
        sub     rsp, STACKFRAME_size

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif

%endmacro       ; FUNC_ENTRY

;; =============================================================================
;; =============================================================================
;; Restores registers and removes the stack frame
;; =============================================================================
%macro FUNC_EXIT 0
        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        add     rsp, STACKFRAME_size

%ifdef SAFE_DATA
       clear_scratch_gps_asm
%endif ;; SAFE_DATA

%endmacro

align 32
MKGLOBAL(poly1305_aead_update_avx512,function,internal)
poly1305_aead_update_avx512:

%ifdef SAFE_PARAM
        or      arg1, arg1
        jz      .poly1305_update_exit

        or      arg3, arg3
        jz      .poly1305_update_exit

        or      arg4, arg4
        jz      .poly1305_update_exit
%endif

        FUNC_ENTRY

%ifdef LINUX
%xdefine _a0 gp3
%xdefine _a1 gp4
%xdefine _a2 gp5
%xdefine _r0 gp6
%xdefine _r1 gp7
%xdefine _len arg2
%xdefine _arg3 arg4             ; use rcx, arg3 = rdx
%else
%xdefine _a0 gp3
%xdefine _a1 rdi
%xdefine _a2 gp5                ; = arg4 / r9
%xdefine _r0 gp6
%xdefine _r1 gp7
%xdefine _len gp2               ; rsi
%xdefine _arg3 arg3             ; arg
%endif

        ;; load R
        mov     _r0, [arg4 + 0 * 8]
        mov     _r1, [arg4 + 1 * 8]

        ;; load accumulator / current hash value
        ;; note: arg4 can't be used beyond this point
%ifdef LINUX
        mov     _arg3, arg3             ; note: _arg3 = arg4 (linux)
%endif
        mov     _a0, [_arg3 + 0 * 8]
        mov     _a1, [_arg3 + 1 * 8]
        mov     _a2, [_arg3 + 2 * 8]    ; note: _a2 = arg4 (win)

%ifndef LINUX
        mov     _len, arg2      ;; arg2 = rdx on Windows
%endif
        POLY1305_BLOCKS arg1, _len, _a0, _a1, _a2, _r0, _r1, \
                        gp10, gp11, gp8, gp9, rax, rdx

        or      _len, _len
        jz      .poly1305_update_no_partial_block

        ;; create stack frame for the partial block scratch buffer
        sub     rsp, 16

        POLY1305_PARTIAL_BLOCK rsp, arg1, _len, _a0, _a1, _a2, _r0, _r1, \
                               gp10, gp11, gp8, gp9, rax, rdx, pad_to_16

        ;; remove the stack frame (memory is cleared as part of the macro)
        add     rsp, 16

.poly1305_update_no_partial_block:
        ;; save accumulator back
        mov     [_arg3 + 0 * 8], _a0
        mov     [_arg3 + 1 * 8], _a1
        mov     [_arg3 + 2 * 8], _a2

        FUNC_EXIT
.poly1305_update_exit:
        ret

align 32
MKGLOBAL(poly1305_aead_complete_avx512,function,internal)
poly1305_aead_complete_avx512:

%ifdef SAFE_PARAM
        or      arg1, arg1
        jz      .poly1305_complete_exit

        or      arg2, arg2
        jz      .poly1305_complete_exit

        or      arg3, arg3
        jz      .poly1305_complete_exit
%endif

        FUNC_ENTRY

%xdefine _a0 gp6
%xdefine _a1 gp7
%xdefine _a2 gp8

        ;; load accumulator / current hash value
        mov     _a0, [arg1 + 0 * 8]
        mov     _a1, [arg1 + 1 * 8]
        mov     _a2, [arg1 + 2 * 8]

        POLY1305_FINALIZE arg2, arg3, _a0, _a1, _a2, gp9, gp10, gp11

        ;; clear Poly key
%ifdef SAFE_DATA
        vpxorq  ymm0, ymm0
        vmovdqu64 [arg2], ymm0
%endif

        FUNC_EXIT
.poly1305_complete_exit:
        ret

;; =============================================================================
;; =============================================================================
;; void poly1305_mac_plain_avx512(IMB_JOB *job)
;; arg1 - job structure
align 32
MKGLOBAL(poly1305_mac_plain_avx512,function,internal)
poly1305_mac_plain_avx512:
        FUNC_ENTRY

%ifndef LINUX
        mov     job, arg1
%endif

%ifdef SAFE_PARAM
        or      job, job
        jz      .poly1305_mac_exit
%endif

%xdefine _a0 gp1
%xdefine _a1 gp2
%xdefine _a2 gp3
%xdefine _r0 gp4
%xdefine _r1 gp5

        mov     gp6, [job + _poly1305_key]
        POLY1305_INIT   gp6, _a0, _a1, _a2, _r0, _r1

        mov     msg, [job + _src]
        add     msg, [job + _hash_start_src_offset_in_bytes]
        mov     len, [job + _msg_len_to_hash]
        POLY1305_BLOCKS msg, len, _a0, _a1, _a2, _r0, _r1, \
                        gp6, gp7, gp8, gp9, rax, rdx

        or      len, len
        jz      .poly1305_no_partial_block

        ;; create stack frame for the partial block scratch buffer
        sub     rsp, 16

        POLY1305_PARTIAL_BLOCK rsp, msg, len, _a0, _a1, _a2, _r0, _r1, \
                               gp6, gp7, gp8, gp9, rax, rdx, no_padding

        ;; remove the stack frame (memory is cleared as part of the macro)
        add     rsp, 16

.poly1305_no_partial_block:
        mov     rax, [job + _poly1305_key]
        mov     rdx, [job + _auth_tag_output]
        POLY1305_FINALIZE rax, rdx, _a0, _a1, _a2, gp6, gp7, gp8

.poly1305_mac_exit:
        FUNC_EXIT
        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
