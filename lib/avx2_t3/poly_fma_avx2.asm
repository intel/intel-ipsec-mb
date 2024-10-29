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

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/memcpy.inc"
%include "include/imb_job.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"

;; Enforce VEX encoding for AVX2 capable systems
%xdefine vpmadd52luq {vex3}vpmadd52luq
%xdefine vpmadd52huq {vex3}vpmadd52huq

[bits 64]
default rel

align 32
mask_44:
dq      0xfffffffffff, 0xfffffffffff, 0xfffffffffff, 0xfffffffffff

align 32
mask_42:
dq      0x3ffffffffff, 0x3ffffffffff, 0x3ffffffffff, 0x3ffffffffff

align 32
high_bit:
dq      0x10000000000, 0x10000000000, 0x10000000000, 0x10000000000

align 16
pad16_bit:
dq      0x01, 0x0
dq      0x0100, 0x0
dq      0x010000, 0x0
dq      0x01000000, 0x0
dq      0x0100000000, 0x0
dq      0x010000000000, 0x0
dq      0x01000000000000, 0x0
dq      0x0100000000000000, 0x0
dq      0x0, 0x01
dq      0x0, 0x0100
dq      0x0, 0x010000
dq      0x0, 0x01000000
dq      0x0, 0x0100000000
dq      0x0, 0x010000000000
dq      0x0, 0x01000000000000
dq      0x0, 0x0100000000000000

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
_r4_r1_save:    resy    3  ; Memory to save limbs of powers of R
_r4_save:       resy    3  ; Memory to save limbs of powers of R
_r4p_save:      resy    2  ; Memory to save limbs of powers of R
_gpr_save:      resq    8  ; Memory to save GP registers
_xmm_save:      reso    10 ; Memory to save XMM registers
_rsp_save:      resq    1  ; Memory to save RSP
endstruc

mksection .text

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
%macro POLY1305_MUL_REDUCE 11-12
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
%define %%ONLY128 %12   ; [in] Used if input A2 is 0

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
%if %0 == 11
        mov     %%A1, %%A2      ;; use A1 for A2
%endif
        add     %%A0, %%GP_RAX
        adc     %%T1, %%GP_RDX

        ;; NOTE: A2 is clamped to 2-bits,
        ;;       R1/R0 is clamped to 60-bits,
        ;;       their product is less than 2^64.

%if %0 == 11
        ;; T3:T2 += (A2 * R1x5)
        imul    %%A1, %%C1
        add     %%T2, %%A1
        mov     %%A1, %%T1 ;; T1:A0 => A1:A0
        adc     %%T3, 0

        ;; T3:A1 += (A2 * R0)
        imul    %%A2, %%R0
        add     %%A1, %%T2
        adc     %%T3, %%A2
        ;; If A2 == 0, just move and add T1-T2 to A1
%else
        mov     %%A1, %%T1
        add     %%A1, %%T2
        adc     %%T3, 0
%endif

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
;; Computes hash for 4 16-byte message blocks,
;; and adds new message blocks to accumulator,
;; interleaving this computation with the loading and splatting
;; of new data.
;;
;; It first multiplies all 4 blocks with powers of R
;;
;;      a2      a1      a0
;; ×    b2      b1      b0
;; ---------------------------------------
;;     a2×b0   a1×b0   a0×b0
;; +   a1×b1   a0×b1 5×a2×b1
;; +   a0×b2 5×a2×b2 5×a1×b2
;; ---------------------------------------
;;        p2      p1      p0
;;
;; Then, it propagates the carry (higher bits after bit 43)
;; from lower limbs into higher limbs,
;; multiplying by 5 in case of the carry of p2, and adds
;; the results to A0-A2 and B0-B2.
;;
;; =============================================================================
%macro POLY1305_MSG_MUL_REDUCE_VEC4 22
%define %%A0      %1  ; [in/out] YMM register containing 1st 44-bit limb of blocks 1-4
%define %%A1      %2  ; [in/out] YMM register containing 2nd 44-bit limb of blocks 1-4
%define %%A2      %3  ; [in/out] YMM register containing 3rd 44-bit limb of blocks 1-4
%define %%R0      %4  ; [in] YMM register/memory (R0) to include the 1st limb of R
%define %%R1      %5  ; [in] YMM register/memory (R1) to include the 2nd limb of R
%define %%R2      %6  ; [in] YMM register/memory (R2) to include the 3rd limb of R
%define %%R1P     %7  ; [in] YMM register/memory (R1') to include the 2nd limb of R (multiplied by 5)
%define %%R2P     %8  ; [in] YMM register/memory (R2') to include the 3rd limb of R (multiplied by 5)
%define %%P0_L    %9  ; [clobbered] YMM register to contain p[0] of the 4 blocks 1-4
%define %%P0_H    %10 ; [clobbered] YMM register to contain p[0] of the 4 blocks 1-4
%define %%P1_L    %11 ; [clobbered] YMM register to contain p[1] of the 4 blocks 1-4
%define %%P1_H    %12 ; [clobbered] YMM register to contain p[1] of the 4 blocks 1-4
%define %%P2_L    %13 ; [clobbered] YMM register to contain p[2] of the 4 blocks 1-4
%define %%P2_H    %14 ; [clobbered] YMM register to contain p[2] of the 4 blocks 1-4
%define %%YTMP1   %15 ; [clobbered] Temporary YMM register
%define %%YTMP2   %16 ; [clobbered] Temporary YMM register
%define %%YTMP3   %17 ; [clobbered] Temporary YMM register
%define %%YTMP4   %18 ; [clobbered] Temporary YMM register
%define %%YTMP5   %19 ; [clobbered] Temporary YMM register
%define %%YTMP6   %20 ; [clobbered] Temporary YMM register
%define %%MSG     %21 ; [in/out] Pointer to message
%define %%LEN     %22 ; [in/out] Length left of message

        ;; Reset accumulator
        vpxor   %%P0_L, %%P0_L
        vpxor   %%P0_H, %%P0_H
        vpxor   %%P1_L, %%P1_L
        vpxor   %%P1_H, %%P1_H
        vpxor   %%P2_L, %%P2_L
        vpxor   %%P2_H, %%P2_H

        ;; This code interleaves hash computation with input loading/splatting

                ; Calculate products
                vpmadd52luq %%P0_L, %%A2, %%R1P
                vpmadd52huq %%P0_H, %%A2, %%R1P
        ;; input loading of new blocks
        add     %%MSG, POLY1305_BLOCK_SIZE*4
        sub     %%LEN, POLY1305_BLOCK_SIZE*4

                vpmadd52luq %%P1_L, %%A2, %%R2P
                vpmadd52huq %%P1_H, %%A2, %%R2P
        ; Load next block of data (64 bytes)
        vmovdqu   %%YTMP1, [%%MSG]
        vmovdqu   %%YTMP2, [%%MSG + 32]

        ; Interleave new blocks of data
        vpunpckhqdq %%YTMP3, %%YTMP1, %%YTMP2
        vpunpcklqdq %%YTMP1, %%YTMP1, %%YTMP2

                vpmadd52luq %%P0_L, %%A0, %%R0
                vpmadd52huq %%P0_H, %%A0, %%R0
        ; Highest 42-bit limbs of new blocks
        vpsrlq  %%YTMP6, %%YTMP3, 24
        vpor    %%YTMP6, [rel high_bit] ; Add 2^128 to all 4 final qwords of the message

        ; Middle 44-bit limbs of new blocks
        vpsrlq  %%YTMP2, %%YTMP1, 44
        vpsllq  %%YTMP4, %%YTMP3, 20

                vpmadd52luq %%P2_L, %%A2, %%R0
                vpmadd52huq %%P2_H, %%A2, %%R0
        vpor    %%YTMP2, %%YTMP4
        vpand   %%YTMP2, [rel mask_44]

        ; Lowest 44-bit limbs of new blocks
        vpand   %%YTMP1, [rel mask_44]

                vpmadd52luq %%P1_L, %%A0, %%R1
                vpmadd52huq %%P1_H, %%A0, %%R1

                vpmadd52luq %%P0_L, %%A1, %%R2P
                vpmadd52huq %%P0_H, %%A1, %%R2P

                vpmadd52luq %%P2_L, %%A0, %%R2
                vpmadd52huq %%P2_H, %%A0, %%R2
        ; Carry propagation (first pass)
        vpsrlq  %%YTMP5, %%P0_L, 44
        vpsllq  %%P0_H, 8

                vpmadd52luq %%P1_L, %%A1, %%R0
                vpmadd52huq %%P1_H, %%A1, %%R0
        ; Carry propagation (first pass) - continue
        vpand   %%A0, %%P0_L, [rel mask_44] ; Clear top 20 bits
        vpaddq  %%P0_H, %%YTMP5

                vpmadd52luq %%P2_L, %%A1, %%R1
                vpmadd52huq %%P2_H, %%A1, %%R1
        ; Carry propagation (first pass) - continue
        vpaddq  %%P1_L, %%P0_H
        vpsllq  %%P1_H, 8
        vpsrlq  %%YTMP5, %%P1_L, 44
        vpand   %%A1, %%P1_L, [rel mask_44] ; Clear top 20 bits

        vpaddq  %%P2_L, %%P1_H          ; P2_L += P1_H + P1_L[63:44]
        vpaddq  %%P2_L, %%YTMP5
        vpand   %%A2, %%P2_L, [rel mask_42] ; Clear top 22 bits
        vpaddq  %%A2, %%YTMP6 ; Add highest bits from new blocks to accumulator
        vpsrlq  %%YTMP5, %%P2_L, 42
        vpsllq  %%P2_H, 10
        vpaddq  %%P2_H, %%YTMP5

        ; Carry propagation (second pass)
        ; Multiply by 5 the highest bits (above 130 bits)
        vpaddq  %%A0, %%P2_H
        vpsllq  %%P2_H, 2
        vpaddq  %%A0, %%P2_H

        vpsrlq  %%YTMP5, %%A0, 44
        vpand   %%A0, [rel mask_44]
        vpaddq  %%A0, %%YTMP1 ; Add low 42-bit bits from new blocks to accumulator
        vpaddq  %%A1, %%YTMP2 ; Add medium 42-bit bits from new blocks to accumulator
        vpaddq  %%A1, %%YTMP5
%endmacro

;; =============================================================================
;; =============================================================================
;; Computes hash for 4 16-byte message blocks.
;;
;; It first multiplies all 4 blocks with powers of R (4 blocks from A0-A2
;; multiplied by R0-R2)
;;
;;
;;      a2      a1      a0
;; ×    b2      b1      b0
;; ---------------------------------------
;;     a2×b0   a1×b0   a0×b0
;; +   a1×b1   a0×b1 5×a2×b1
;; +   a0×b2 5×a2×b2 5×a1×b2
;; ---------------------------------------
;;        p2      p1      p0
;;
;; Then, it propagates the carry (higher bits after bit 43) from lower limbs into higher limbs,
;; multiplying by 5 in case of the carry of p2.
;;
;; =============================================================================
%macro POLY1305_MUL_REDUCE_VEC4 16
%define %%A0      %1  ; [in/out] YMM register containing 1st 44-bit limb of the 4 blocks
%define %%A1      %2  ; [in/out] YMM register containing 2nd 44-bit limb of the 4 blocks
%define %%A2      %3  ; [in/out] YMM register containing 3rd 44-bit limb of the 4 blocks
%define %%R0      %4  ; [in] YMM register/memory (R0) to include the 1st limb of R
%define %%R1      %5  ; [in] YMM register/memory (R1) to include the 2nd limb of R
%define %%R2      %6  ; [in] YMM register/memory (R2) to include the 3rd limb of R
%define %%R1P     %7  ; [in] YMM register/memory (R1') to include the 2nd limb of R (multiplied by 5)
%define %%R2P     %8  ; [in] YMM register/memory (R2') to include the 3rd limb of R (multiplied by 5)
%define %%P0_L    %9  ; [clobbered] YMM register to contain p[0] of the 4 blocks
%define %%P0_H    %10 ; [clobbered] YMM register to contain p[0] of the 4 blocks
%define %%P1_L    %11 ; [clobbered] YMM register to contain p[1] of the 4 blocks
%define %%P1_H    %12 ; [clobbered] YMM register to contain p[1] of the 4 blocks
%define %%P2_L    %13 ; [clobbered] YMM register to contain p[2] of the 4 blocks
%define %%P2_H    %14 ; [clobbered] YMM register to contain p[2] of the 4 blocks
%define %%YTMP1   %15 ; [clobbered] Temporary YMM register
%define %%YTMP2   %16 ; [clobbered] Temporary YMM register

        ;; Reset accumulator
        vpxor   %%P0_L, %%P0_L
        vpxor   %%P0_H, %%P0_H
        vpxor   %%P1_L, %%P1_L
        vpxor   %%P1_H, %%P1_H
        vpxor   %%P2_L, %%P2_L
        vpxor   %%P2_H, %%P2_H

        ;; This code interleaves hash computation with input loading/splatting

        ; Calculate products
        vpmadd52luq %%P0_L, %%A2, %%R1P
        vpmadd52huq %%P0_H, %%A2, %%R1P

        vpmadd52luq %%P1_L, %%A2, %%R2P
        vpmadd52huq %%P1_H, %%A2, %%R2P

        vpmadd52luq %%P0_L, %%A0, %%R0
        vpmadd52huq %%P0_H, %%A0, %%R0

        vpmadd52luq %%P2_L, %%A2, %%R0
        vpmadd52huq %%P2_H, %%A2, %%R0

        vpmadd52luq %%P1_L, %%A0, %%R1
        vpmadd52huq %%P1_H, %%A0, %%R1

        vpmadd52luq %%P0_L, %%A1, %%R2P
        vpmadd52huq %%P0_H, %%A1, %%R2P

        vpmadd52luq %%P2_L, %%A0, %%R2
        vpmadd52huq %%P2_H, %%A0, %%R2

        ; Carry propagation (first pass)
        vpsrlq  %%YTMP1, %%P0_L, 44
        vpsllq  %%P0_H, 8

        vpmadd52luq %%P1_L, %%A1, %%R0
        vpmadd52huq %%P1_H, %%A1, %%R0

        ; Carry propagation (first pass) - continue
        vpand   %%A0, %%P0_L, [rel mask_44] ; Clear top 20 bits
        vpaddq  %%P0_H, %%YTMP1

        vpmadd52luq %%P2_L, %%A1, %%R1
        vpmadd52huq %%P2_H, %%A1, %%R1

        ; Carry propagation (first pass) - continue
        vpaddq  %%P1_L, %%P0_H
        vpsllq  %%P1_H, 8
        vpsrlq  %%YTMP1, %%P1_L, 44
        vpand   %%A1, %%P1_L, [rel mask_44] ; Clear top 20 bits

        vpaddq  %%P2_L, %%P1_H          ; P2_L += P1_H + P1_L[63:44]
        vpaddq  %%P2_L, %%YTMP1
        vpand   %%A2, %%P2_L, [rel mask_42] ; Clear top 22 bits
        vpsrlq  %%YTMP1, %%P2_L, 42
        vpsllq  %%P2_H, 10
        vpaddq  %%P2_H, %%YTMP1

        ; Carry propagation (second pass)
        ; Multiply by 5 the highest bits (above 130 bits)
        vpaddq  %%A0, %%P2_H
        vpsllq  %%P2_H, 2
        vpaddq  %%A0, %%P2_H

        vpsrlq  %%YTMP1, %%A0, 44
        vpand   %%A0, [rel mask_44]
        vpaddq  %%A1, %%YTMP1
%endmacro

;; =============================================================================
;; =============================================================================
;; Computes hash for message length being multiple of block size
;; =============================================================================
%macro POLY1305_BLOCKS 14
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
%define %%PAD_16  %14   ; [in] text "pad_to_16" or "no_padding"

%define %%YMM_ACC0 ymm0
%define %%YMM_ACC1 ymm1
%define %%YMM_ACC2 ymm2

%define %%YTMP1 ymm3
%define %%YTMP2 ymm4
%define %%YTMP3 ymm5
%define %%YTMP4 ymm6
%define %%YTMP5 ymm7
%define %%YTMP6 ymm8
%define %%YTMP7 ymm9
%define %%YTMP8 ymm10
%define %%YTMP9 ymm11
%define %%YTMP10 ymm12
%define %%YTMP11 ymm13
%define %%YTMP12 ymm14
%define %%YTMP13 ymm15

%define %%YMM_R0 %%YTMP11
%define %%YMM_R1 %%YTMP12
%define %%YMM_R2 %%YTMP13

%define %%XTMP1 XWORD(%%YTMP1)
%define %%XTMP2 XWORD(%%YTMP2)
%define %%XTMP3 XWORD(%%YTMP3)

        ; Minimum of 256 bytes to run vectorized code
        cmp     %%LEN, POLY1305_BLOCK_SIZE*16
        jb      %%_final_loop

        ; Spread accumulator into 44-bit limbs in quadwords
        mov     %%T0, %%A0
        and     %%T0, [rel mask_44] ;; First limb (A[43:0])
        vmovq   %%XTMP1, %%T0

        mov     %%T0, %%A1
        shrd    %%A0, %%T0, 44
        and     %%A0, [rel mask_44] ;; Second limb (A[77:52])
        vmovq   %%XTMP2, %%A0

        shrd    %%A1, %%A2, 24
        and     %%A1, [rel mask_42] ;; Third limb (A[129:88])
        vmovq   %%XTMP3, %%A1

        ; Load first block of data (64 bytes)
        vmovdqu   %%YTMP4, [%%MSG]
        vmovdqu   %%YTMP5, [%%MSG + 32]

        ; Interleave the data to form 44-bit limbs
        ;
        ; %%YMM_ACC0 to have bits 0-43 of all 4 blocks in 4 qwords
        ; %%YMM_ACC1 to have bits 87-44 of all 4 blocks in 4 qwords
        ; %%YMM_ACC2 to have bits 127-88 of all 4 blocks in 4 qwords
        vpunpckhqdq %%YMM_ACC2, %%YTMP4, %%YTMP5
        vpunpcklqdq %%YMM_ACC0, %%YTMP4, %%YTMP5

        vpsrlq  %%YMM_ACC1, %%YMM_ACC0, 44
        vpsllq  %%YTMP4, %%YMM_ACC2, 20
        vpor    %%YMM_ACC1, %%YTMP4
        vpand   %%YMM_ACC1, [rel mask_44]

        vpand   %%YMM_ACC0, [rel mask_44]
        vpsrlq  %%YMM_ACC2, 24

        ; Add 2^128 to all 4 final qwords of the message
        vpor    %%YMM_ACC2, [rel high_bit]

        vpaddq  %%YMM_ACC0, %%YTMP1
        vpaddq  %%YMM_ACC1, %%YTMP2
        vpaddq  %%YMM_ACC2, %%YTMP3

        ; Use memory in stack to save powers of R, before loading them into YMM registers
        ; The first 16*4 bytes will contain the 16 bytes of the 4 powers of R
        ; The last 32 bytes will contain the last 2 bits of powers of R, spread in 4 qwords,
        ; to be OR'd with the highest qwords
        vmovq   %%XTMP1, %%R0
        vpinsrq %%XTMP1, %%R1, 1
        vinserti128 %%YTMP5, %%XTMP1, 1

        vpxor   %%YTMP10, %%YTMP10
        vpxor   %%YTMP6, %%YTMP6

        ; Calculate R^2
        mov     %%T0, %%R1
        shr     %%T0, 2
        add     %%T0, %%R1      ;; T0 = R1 + (R1 >> 2)

        mov     %%A0, %%R0
        mov     %%A1, %%R1

        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX, no_A2

        vmovq   %%XTMP1, %%A0
        vpinsrq %%XTMP1, %%A1, 1
        vinserti128 %%YTMP5, %%XTMP1, 0

        vmovq   %%XTMP1, %%A2
        vinserti128 %%YTMP6, %%XTMP1, 0

        ; Calculate R^3
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        vmovq   %%XTMP1, %%A0
        vpinsrq %%XTMP1, %%A1, 1
        vinserti128 %%YTMP7, %%XTMP1, 1

        vmovq   %%XTMP1, %%A2
        vinserti128 %%YTMP2, %%XTMP1, 1

        ; Calculate R^4
        POLY1305_MUL_REDUCE %%A0, %%A1, %%A2, %%R0, %%R1, %%T0, %%T1, %%T2, %%T3, %%GP_RAX, %%GP_RDX

        vmovq   %%XTMP1, %%A0
        vpinsrq %%XTMP1, %%A1, 1
        vinserti128 %%YTMP7, %%XTMP1, 0

        vmovq   %%XTMP1, %%A2
        vinserti128 %%YTMP2, %%XTMP1, 0

        vpunpckhqdq %%YMM_R2, %%YTMP5, %%YTMP10
        vpunpcklqdq %%YMM_R0, %%YTMP5, %%YTMP10
        vpunpckhqdq %%YTMP3, %%YTMP7, %%YTMP10
        vpunpcklqdq %%YTMP4, %%YTMP7, %%YTMP10

        vpslldq %%YMM_R2, %%YMM_R2, 8
        vpslldq %%YTMP6, %%YTMP6, 8
        vpslldq %%YMM_R0, %%YMM_R0, 8
        vpor    %%YMM_R2, %%YMM_R2, %%YTMP3
        vpor    %%YMM_R0, %%YMM_R0, %%YTMP4
        vpor    %%YTMP6, %%YTMP6, %%YTMP2

        ; Move 2 MSbits to top 24 bits, to be OR'ed later
        vpsllq  %%YTMP6, 40

        vpsrlq  %%YMM_R1, %%YMM_R0, 44
        vpsllq  %%YTMP5, %%YMM_R2, 20
        vpor    %%YMM_R1, %%YTMP5
        vpand   %%YMM_R1, [rel mask_44]

        vpand   %%YMM_R0, [rel mask_44]
        vpsrlq  %%YMM_R2, 24

        vpor    %%YMM_R2, %%YTMP6

        ; Store R^4-R for later use
        vmovdqa   [rsp + _r4_r1_save], %%YMM_R0
        vmovdqa   [rsp + _r4_r1_save + 32], %%YMM_R1
        vmovdqa   [rsp + _r4_r1_save + 32*2], %%YMM_R2

        ; Broadcast 44-bit limbs of R^4
        mov     %%T0, %%A0
        and     %%T0, [rel mask_44] ;; First limb (R^4[43:0])
        vmovq   XWORD(%%YMM_R0), %%T0
        vpermq  %%YMM_R0, %%YMM_R0, 0x0

        mov     %%T0, %%A1
        shrd    %%A0, %%T0, 44
        and     %%A0, [rel mask_44] ;; Second limb (R^4[87:44])
        vmovq   XWORD(%%YMM_R1), %%A0
        vpermq  %%YMM_R1, %%YMM_R1, 0x0

        shrd    %%A1, %%A2, 24
        and     %%A1, [rel mask_42] ;; Third limb (R^4[129:88])
        vmovq   XWORD(%%YMM_R2), %%A1
        vpermq  %%YMM_R2, %%YMM_R2, 0x0

        ; Generate 4*5*R^4
        vpsllq  %%YTMP1, %%YMM_R1, 2
        vpsllq  %%YTMP2, %%YMM_R2, 2

        ; 5*R^4
        vpaddq  %%YTMP1, %%YMM_R1
        vpaddq  %%YTMP2, %%YMM_R2

        ; 4*5*R^4
        vpsllq  %%YTMP1, 2
        vpsllq  %%YTMP2, 2

        ; Store R^4-R for later use
        vmovdqa   [rsp + _r4_save], %%YMM_R0
        vmovdqa   [rsp + _r4_save + 32], %%YMM_R1
        vmovdqa   [rsp + _r4_save + 32*2], %%YMM_R2
        vmovdqa   [rsp + _r4p_save], %%YTMP1
        vmovdqa   [rsp + _r4p_save + 32], %%YTMP2

        mov     %%T0, %%LEN
        and     %%T0, 0xffffffffffffffc0 ; multiple of 64 bytes

%%_poly1305_blocks_loop:
        cmp     %%T0, POLY1305_BLOCK_SIZE*4
        jbe     %%_poly1305_blocks_loop_end

        POLY1305_MSG_MUL_REDUCE_VEC4 %%YMM_ACC0, %%YMM_ACC1, %%YMM_ACC2, \
                                     [rsp + _r4_save], [rsp + _r4_save + 32], [rsp + _r4_save + 32*2], \
                                     [rsp + _r4p_save], [rsp + _r4p_save + 32], \
                                     %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                                     %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10, %%YTMP11, %%YTMP12, \
                                     %%MSG, %%T0

        jmp     %%_poly1305_blocks_loop

%%_poly1305_blocks_loop_end:

        ;; Need to multiply by r^4, r^3, r^2, r

        ; Read R^4-R
        vmovdqa   %%YMM_R0, [rsp + _r4_r1_save]
        vmovdqa   %%YMM_R1, [rsp + _r4_r1_save + 32]
        vmovdqa   %%YMM_R2, [rsp + _r4_r1_save + 32*2]

        ; Then multiply by r^4-r

        ; %%YTMP1 to have bits 87-44 of all 1-4th powers of R' in 4 qwords
        ; %%YTMP2 to have bits 129-88 of all 1-4th powers of R' in 4 qwords
        vpsllq  %%YTMP10, %%YMM_R1, 2
        vpaddq  %%YTMP1, %%YMM_R1, %%YTMP10 ; R1' (R1*5)
        vpsllq  %%YTMP10, %%YMM_R2, 2
        vpaddq  %%YTMP2, %%YMM_R2, %%YTMP10 ; R2' (R2*5)

        ; 4*5*R
        vpsllq  %%YTMP1, 2
        vpsllq  %%YTMP2, 2

        POLY1305_MUL_REDUCE_VEC4 %%YMM_ACC0, %%YMM_ACC1, %%YMM_ACC2, \
                                 %%YMM_R0, %%YMM_R1, %%YMM_R2, %%YTMP1, %%YTMP2, \
                                 %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                                 %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10

        vextracti128   XWORD(%%YTMP1), %%YMM_ACC0, 1
        vextracti128   XWORD(%%YTMP2), %%YMM_ACC1, 1
        vextracti128   XWORD(%%YTMP3), %%YMM_ACC2, 1

        vpaddq  XWORD(%%YMM_ACC0), XWORD(%%YTMP1)
        vpaddq  XWORD(%%YMM_ACC1), XWORD(%%YTMP2)
        vpaddq  XWORD(%%YMM_ACC2), XWORD(%%YTMP3)

        vpsrldq XWORD(%%YTMP1), XWORD(%%YMM_ACC0), 8
        vpsrldq XWORD(%%YTMP2), XWORD(%%YMM_ACC1), 8
        vpsrldq XWORD(%%YTMP3), XWORD(%%YMM_ACC2), 8

        ; Finish folding and clear second qword
        vpaddq  XWORD(%%YMM_ACC0), XWORD(%%YTMP1)
        vpaddq  XWORD(%%YMM_ACC1), XWORD(%%YTMP2)
        vpaddq  XWORD(%%YMM_ACC2), XWORD(%%YTMP3)
        vmovq   XWORD(%%YMM_ACC0), XWORD(%%YMM_ACC0)
        vmovq   XWORD(%%YMM_ACC1), XWORD(%%YMM_ACC1)
        vmovq   XWORD(%%YMM_ACC2), XWORD(%%YMM_ACC2)

        add     %%MSG, POLY1305_BLOCK_SIZE*4

        and     %%LEN, (POLY1305_BLOCK_SIZE*4 - 1) ; Get remaining lengths (LEN < 64 bytes)

%%_simd_to_gp:
        ; Carry propagation
        vpsrlq  %%XTMP1, XWORD(%%YMM_ACC0), 44
        vpand   XWORD(%%YMM_ACC0), [rel mask_44] ; Clear top 20 bits
        vpaddq  XWORD(%%YMM_ACC1), %%XTMP1
        vpsrlq  %%XTMP1, XWORD(%%YMM_ACC1), 44
        vpand   XWORD(%%YMM_ACC1), [rel mask_44] ; Clear top 20 bits
        vpaddq  XWORD(%%YMM_ACC2), %%XTMP1
        vpsrlq  %%XTMP1, XWORD(%%YMM_ACC2), 42
        vpand   XWORD(%%YMM_ACC2), [rel mask_42] ; Clear top 22 bits
        vpsllq  %%XTMP2, %%XTMP1, 2
        vpaddq  %%XTMP1, %%XTMP2
        vpaddq  XWORD(%%YMM_ACC0), %%XTMP1

        ; Put together A
        vmovq   %%A0, XWORD(%%YMM_ACC0)

        vmovq   %%T0, XWORD(%%YMM_ACC1)
        mov     %%T1, %%T0
        shl     %%T1, 44
        or      %%A0, %%T1

        shr     %%T0, 20
        vmovq   %%A2, XWORD(%%YMM_ACC2)
        mov     %%A1, %%A2
        shl     %%A1, 24
        or      %%A1, %%T0
        shr     %%A2, 40

        ; Clear powers of R
%ifdef SAFE_DATA
        vpxor   %%YTMP1, %%YTMP1
        vmovdqa [rsp + _r4_r1_save], %%YTMP1
        vmovdqa [rsp + _r4_r1_save + 32], %%YTMP1
        vmovdqa [rsp + _r4_r1_save + 32*2], %%YTMP1
        vmovdqa [rsp + _r4_save], %%YTMP1
        vmovdqa [rsp + _r4_save + 32], %%YTMP1
        vmovdqa [rsp + _r4_save + 32*2], %%YTMP1
        vmovdqa [rsp + _r4p_save], %%YTMP1
        vmovdqa [rsp + _r4p_save + 32], %%YTMP1
%endif

%%_final_loop:
        cmp     %%LEN, POLY1305_BLOCK_SIZE
        jb      %%_poly1305_blocks_partial

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

%%_poly1305_blocks_partial:

        or      %%LEN, %%LEN
        jz      %%_poly1305_blocks_exit

        simd_load_avx_16 %%XTMP1, %%MSG, %%LEN

%ifnidn %%PAD_16,pad_to_16
        ;; pad the message
        lea     %%T2, [rel pad16_bit]
        shl     %%LEN, 4
        vpor    %%XTMP1, [%%T2 + %%LEN]
%endif
        vmovq   %%T0, %%XTMP1
        vpextrq %%T1, %%XTMP1, 1
        ;; A += MSG[i]
        add     %%A0, %%T0
        adc     %%A1, %%T1
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

%%_poly1305_blocks_exit:
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
        mov     rax, rsp
        sub     rsp, STACKFRAME_size
	and	rsp, -32

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%assign i 0
%assign j 6
%rep 10
	vmovdqa	[rsp + _xmm_save + i*16], APPEND(xmm, j)
%assign i (i + 1)
%assign j (j + 1)
%endrep
%endif
        mov     [rsp + _rsp_save], rax

%endmacro       ; FUNC_ENTRY

;; =============================================================================
;; =============================================================================
;; Restores registers and removes the stack frame
;; =============================================================================
%macro FUNC_EXIT 0
%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_all_ymms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%assign i 0
%assign j 6
%rep 10
	vmovdqa	APPEND(xmm, j), [rsp + _xmm_save + i*16]
%assign i (i + 1)
%assign j (j + 1)
%endrep
%endif
        mov     rsp, [rsp + _rsp_save]

%endmacro

;; =============================================================================
;; =============================================================================
;; void poly1305_aead_update_fma_avx2(const void *msg, const uint64_t msg_len,
;;                                      void *hash, const void *key)
;; arg1 - Input message
;; arg2 - Message length
;; arg3 - Input/output hash
;; arg4 - Poly1305 key
align 32
MKGLOBAL(poly1305_aead_update_fma_avx2,function,internal)
poly1305_aead_update_fma_avx2:

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
                        gp10, gp11, gp8, gp9, rax, rdx, pad_to_16

        ;; save accumulator back
        mov     [_arg3 + 0 * 8], _a0
        mov     [_arg3 + 1 * 8], _a1
        mov     [_arg3 + 2 * 8], _a2

        FUNC_EXIT
.poly1305_update_exit:
        ret

;; =============================================================================
;; =============================================================================
;; void poly1305_aead_complete_fma_avx2(const void *hash, const void *key,
;;                                        void *tag)
;; arg1 - Input hash
;; arg2 - Poly1305 key
;; arg3 - Output tag
align 32
MKGLOBAL(poly1305_aead_complete_fma_avx2,function,internal)
poly1305_aead_complete_fma_avx2:

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
        vpxor   xmm0, xmm0
        vmovdqu   [arg2], ymm0
%endif

        FUNC_EXIT
.poly1305_complete_exit:
        ret

;; =============================================================================
;; =============================================================================
;; void poly1305_mac_fma_avx2(IMB_JOB *job)
;; arg1 - job structure
align 32
MKGLOBAL(poly1305_mac_fma_avx2,function,internal)
poly1305_mac_fma_avx2:
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
                        gp6, gp7, gp8, gp9, rax, rdx, no_padding

        mov     rax, [job + _poly1305_key]
        mov     rdx, [job + _auth_tag_output]
        POLY1305_FINALIZE rax, rdx, _a0, _a1, _a2, gp6, gp7, gp8

.poly1305_mac_exit:
        FUNC_EXIT
        ret

mksection stack-noexec
