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
%include "include/cet.inc"
%include "include/memcpy.asm"
%include "include/const.inc"
%define APPEND(a,b) a %+ b
%define APPEND3(a,b,c) a %+ b %+ c

%ifdef LINUX
%define arg1 rdi
%define arg2 rsi
%define arg3 rdx
%define arg4 rcx
%else
%define arg1 rcx
%define arg2 rdx
%define arg3 r8
%define arg4 r9
%endif

%define E                  rax
%define qword_len          r12
%define offset             r10
%define tmp                r10
%define tmp2               arg4
%define tmp3               r11
%define tmp4               r13
%define tmp5               r14
%define tmp6               r15
%define in_ptr             arg1
%define KS                 arg2
%define bit_len            arg3
%define end_offset         tmp3

%define EV                 xmm2
%define SNOW3G_CONST       xmm7
%define P1                 xmm8

%define INSERT_HIGH64_MASK k1


section .data
default rel

align 64
snow3g_constant:
dq      0x000000000000001b, 0x0000000000000000
dq      0x000000000000001b, 0x0000000000000000
dq      0x000000000000001b, 0x0000000000000000
dq      0x000000000000001b, 0x0000000000000000

align 64
bswap64:
dq      0x0001020304050607, 0x08090a0b0c0d0e0f
dq      0x0001020304050607, 0x08090a0b0c0d0e0f
dq      0x0001020304050607, 0x08090a0b0c0d0e0f
dq      0x0001020304050607, 0x08090a0b0c0d0e0f

section .text

%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     16*5
        %define GP_STORAGE      8*8
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      6*8
%endif

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro FUNC_SAVE 0
        mov     r11, rsp
        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~15

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm9 need to be maintained for Windows
        vmovdqa [rsp + 0*16], xmm6
        vmovdqa [rsp + 1*16], xmm7
        vmovdqa [rsp + 2*16], xmm8
        vmovdqa [rsp + 3*16], xmm9
        vmovdqa [rsp + 4*16], xmm10
        mov     [rsp + GP_OFFSET + 48], rdi
        mov     [rsp + GP_OFFSET + 56], rsi
%endif
        mov     [rsp + GP_OFFSET],      r12
        mov     [rsp + GP_OFFSET + 8],  r13
        mov     [rsp + GP_OFFSET + 16], r14
        mov     [rsp + GP_OFFSET + 24], r15
        mov     [rsp + GP_OFFSET + 32], rbx
        mov     [rsp + GP_OFFSET + 40], r11 ;; rsp pointer
%endmacro


%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqa xmm6,  [rsp + 0*16]
        vmovdqa xmm7,  [rsp + 1*16]
        vmovdqa xmm8,  [rsp + 2*16]
        vmovdqa xmm9,  [rsp + 3*16]
        vmovdqa xmm9,  [rsp + 4*16]
        mov     rdi, [rsp + GP_OFFSET + 48]
        mov     rsi, [rsp + GP_OFFSET + 56]
%endif
        mov     r12, [rsp + GP_OFFSET]
        mov     r13, [rsp + GP_OFFSET + 8]
        mov     r14, [rsp + GP_OFFSET + 16]
        mov     r15, [rsp + GP_OFFSET + 24]
        mov     rbx, [rsp + GP_OFFSET + 32]
        mov     rsp, [rsp + GP_OFFSET + 40]
%endmacro


;; Horizontal XOR - 4 x 128bits xored together
%macro VHPXORI4x128 2
%define %%REG   %1      ;; [in/out] zmm with 4x128bits to xor; 128bit output
%define %%TMP   %2      ;; [clobbered] zmm temporary register

        vextracti64x4   YWORD(%%TMP), %%REG, 1
        vpxorq          YWORD(%%REG), YWORD(%%REG), YWORD(%%TMP)
        vextracti32x4   XWORD(%%TMP), YWORD(%%REG), 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)

%endmacro


;; Horizontal XOR - 2 x 128bits xored together
%macro VHPXORI2x128 2
%define %%REG   %1      ; [in/out] YMM/ZMM with 2x128bits to xor; 128bit output
%define %%TMP   %2      ; [clobbered] XMM/YMM/ZMM temporary register
        vextracti32x4   XWORD(%%TMP), %%REG, 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro


;; Reduce from 128 bits to 64 bits
%macro REDUCE_TO_64 2
%define %%IN_OUT        %1 ;; [in/out]
%define %%XTMP          %2 ;; [clobbered]

        vpclmulqdq      %%XTMP, %%IN_OUT, SNOW3G_CONST, 0x01
        vpxor           %%IN_OUT, %%IN_OUT, %%XTMP

        vpclmulqdq      %%XTMP, %%XTMP, SNOW3G_CONST, 0x01
        vpxor           %%IN_OUT, %%IN_OUT, %%XTMP

%endmacro


;; Multiply 64b x 64b and reduce result to 64 bits
;; Lower 64-bits of xmms are multiplied
%macro MUL_AND_REDUCE_64x64_LOW 2-3
%define %%IN0_OUT       %1 ;; [in/out]
%define %%IN1           %2 ;; [in] Note: clobbered when only 2 args passed
%define %%XTMP          %3 ;; [clobbered]

        vpclmulqdq      %%IN0_OUT, %%IN0_OUT, %%IN1, 0x00
%if %0 == 2
        ;; clobber XTMP1 if 3 args passed, otherwise preserve
        REDUCE_TO_64    %%IN0_OUT, %%IN1
%else
        REDUCE_TO_64    %%IN0_OUT, %%XTMP
%endif
%endmacro


;; Multiply 64b x 64b blocks and reduce result to 64 bits.
;; Lower and higher 64-bits of all 128-bit lanes are multiplied.
;; Passing different size regs will operate on a different number of blocks
;; - xmms => 2x2 blocks
;; - ymms => 4x4 blocks
;; - zmms => 8x8 blocks
;; Results are combined and returned in single register
%macro  MUL_AND_REDUCE_64x64  7
%define %%IN0_OUT       %1 ;; [in/out] xmm/ymm/zmm with multiply first operands
%define %%IN1           %2 ;; [in] xmm/ymm/zmm with multiply second operands
%define %%T1            %3 ;; [clobbered] xmm/ymm/zmm
%define %%T2            %4 ;; [clobbered] xmm/ymm/zmm
%define %%T3            %5 ;; [clobbered] xmm/ymm/zmm
%define %%T4            %6 ;; [clobbered] xmm/ymm/zmm
%define %%SNOW3G_CONST  %7 ;; [in] xmm/ymm/zmm with SNOW3G constant

        ;; perform multiplication
        vpclmulqdq      %%T1, %%IN0_OUT, %%IN1, 0x00  ; %%T1 = a0*b0 (for xmms)
        vpclmulqdq      %%T2, %%IN0_OUT, %%IN1, 0x11  ; %%T2 = a1*b1

        ;; perform reduction on results
        vpclmulqdq      %%T3, %%T1, %%SNOW3G_CONST, 0x01
        vpclmulqdq      %%T4, %%T2, %%SNOW3G_CONST, 0x01

        vpxorq          %%T1, %%T1, %%T3
        vpxorq          %%T2, %%T2, %%T4

        vpclmulqdq      %%T3, %%T3, %%SNOW3G_CONST, 0x01
        vpclmulqdq      %%T4, %%T4, %%SNOW3G_CONST, 0x01

        vpxorq          %%IN0_OUT, %%T1, %%T3
        vpxorq          %%T2, %%T2, %%T4

        ;; combine results into single register
        vpslldq         %%T2, %%T2, 8
        vmovdqa64       %%IN0_OUT{INSERT_HIGH64_MASK}, %%T2

%endmacro


;; Precompute powers of P up to P^4 or P^16
;; Results are arranged from highest power to lowest at 128b granularity
;; Example:
;;   For up to P^4, results are returned in a single YMM
;;   register in the following order:
;;       OUT0[P3P4, P1P2]
;;   For up to P^16, results are returned in 2 ZMM registers
;;   in the following order:
;;       OUT0[P7P8,     P5P6,   P3P4,  P1P2]
;;       OUT1[P15P16, P13P14, P11P12, P9P10]
%macro  PRECOMPUTE_CONSTANTS 7-9
%define %%P1            %1  ;; [in] initial P^1 to be multiplied
%define %%HIGHEST_POWER %2  ;; [in] highest power to calculate (4 or 16)
%define %%OUT0          %3  ;; [out] ymm/zmm containing results
%define %%T1      	%4  ;; [clobbered] xmm
%define %%T2      	%5  ;; [clobbered] xmm
%define %%T3      	%6  ;; [clobbered] xmm
%define %%T4      	%7  ;; [clobbered] xmm
%define %%OUT1 	        %8  ;; [out] ymm/zmm containing results
%define %%T5      	%9  ;; [clobbered] xmm

%xdefine %%Y_OUT0 YWORD(%%OUT0)
%xdefine %%YT1 YWORD(%%T1)
%xdefine %%YT2 YWORD(%%T2)
%xdefine %%YT3 YWORD(%%T3)
%xdefine %%YT4 YWORD(%%T4)

%xdefine %%Z_OUT0 ZWORD(%%OUT0)
%xdefine %%ZT1 ZWORD(%%T1)
%xdefine %%ZT2 ZWORD(%%T2)
%xdefine %%ZT3 ZWORD(%%T3)
%xdefine %%ZT4 ZWORD(%%T4)

%if %0 > 7
%xdefine %%Y_OUT1 YWORD(%%OUT1)
%xdefine %%Z_OUT1 ZWORD(%%OUT1)
%xdefine %%YT5 YWORD(%%T5)
%xdefine %%ZT5 ZWORD(%%T5)
%endif

        vmovdqa         %%T1, %%P1
        MUL_AND_REDUCE_64x64_LOW %%T1, %%P1, %%T4       ;; %%T1 = P2
        vmovdqa         %%T2, %%T1
        MUL_AND_REDUCE_64x64_LOW %%T2, %%P1, %%T4       ;; %%T2 = P3
        vmovq           %%T2, %%T2
        vmovdqa         %%T3, %%T2
        MUL_AND_REDUCE_64x64_LOW %%T3, %%P1, %%T4       ;; %%T3 = P4

%if %%HIGHEST_POWER <= 4
        ;; if highest power is 4
        ;; then arrange powers from highest to lowest and finish
        vpunpcklqdq     %%T1, %%P1, %%T1                ;; P1P2
        vpunpcklqdq     %%OUT0, %%T2, %%T3              ;; P3P4
        vinserti64x2    %%Y_OUT0, %%Y_OUT0, %%T1, 0x1   ;; P3P4P1P2
%else
        ;; otherwise arrange powers later
        vpunpcklqdq     %%OUT0, %%P1, %%T1              ;; P1P2
        vpunpcklqdq     %%T1, %%T2, %%T3                ;; P3P4
        vinserti64x2    %%Y_OUT0, %%Y_OUT0, %%T1, 0x1   ;; P1P2P3P4
        vpermq          %%YT1, %%Y_OUT0, 0xff           ;; broadcast P4 across T1

        ;;   P1 P2 P3 P4
        ;; * P4 P4 P4 P4
        ;; ------------------
        ;;   P5 P6 P7 P8
        MUL_AND_REDUCE_64x64 %%YT1, %%Y_OUT0, %%YT2, %%YT3, %%YT4, %%YT5, YWORD(SNOW3G_CONST)

        ;; T1 contains P5-P8
        ;; insert P5P6P7P8 into high 256bits of OUT0
        vinserti64x4    %%Z_OUT0, %%Z_OUT0, %%YT1, 0x1

        ;; broadcast P8 across OUT1 and multiply
        valignq         %%YT1, %%YT1, %%YT1, 3
        vpbroadcastq    %%Z_OUT1, %%T1

        ;;   P1 P2 P3 P4 P5 P6 P7 P8
        ;; * P8 P8 P8 P8 P8 P8 P8 P8
        ;; -------------------------
        ;;   P9P10P11P12P13P14P15P16
        MUL_AND_REDUCE_64x64 %%Z_OUT1, %%Z_OUT0, %%ZT2, %%ZT3, %%ZT4, %%ZT5, ZWORD(SNOW3G_CONST)

        ;; put the highest powers to the lower lanes
        vshufi64x2      %%Z_OUT0, %%Z_OUT0, %%Z_OUT0, 00_01_10_11b ;;  P7P8P,   P5P6,   P3P4,  P1P2
        vshufi64x2      %%Z_OUT1, %%Z_OUT1, %%Z_OUT1, 00_01_10_11b ;; P15P16, P13P14, P11P12, P9P10
%endif
%endmacro


;; uint32_t
;; snow3g_f9_1_buffer_internal_vaes_avx512(const uint64_t *pBufferIn,
;;                                         const uint32_t KS[5],
;;                                         const uint64_t lengthInBits);
align 64
MKGLOBAL(snow3g_f9_1_buffer_internal_vaes_avx512,function,internal)
snow3g_f9_1_buffer_internal_vaes_avx512:
        endbranch64

        FUNC_SAVE

        vmovdqa64       ZWORD(SNOW3G_CONST), [rel snow3g_constant]
        mov             tmp, 10101010b
        kmovq           INSERT_HIGH64_MASK, tmp

        vpxor           EV, EV

        ;; P1 = ((uint64_t)KS[0] << 32) | ((uint64_t)KS[1])
        vmovq   P1, [KS]
        vpshufd P1, P1, 1110_0001b

        mov     qword_len, bit_len              ;; lenInBits -> lenInQwords
        shr     qword_len, 6

        cmp     qword_len, 16                   ;; check at least 16 blocks
        jae     init_16_block_loop

        cmp     qword_len, 4                    ;; check at least 4 blocks
        jae     init_4_block_loop

        jmp     start_single_block_loop

init_16_block_loop:
        ;; precompute up to P^16
        PRECOMPUTE_CONSTANTS P1, 16, xmm0, xmm3, xmm4, xmm5, xmm6, xmm1, xmm9

start_16_block_loop:
        vmovdqu64       zmm3, [in_ptr]
        vmovdqu64       zmm4, [in_ptr + 64]

        vpshufb         zmm3, zmm3, [rel bswap64]
        vpshufb         zmm4, zmm4, [rel bswap64]

        vpxorq          zmm3, zmm3, ZWORD(EV)

        vpclmulqdq      zmm5, zmm4, zmm0, 0x10 ;;   p8 -  p1
        vpclmulqdq      zmm6, zmm4, zmm0, 0x01 ;; x m8 - m15

        vpclmulqdq      zmm10, zmm3, zmm1, 0x10 ;;   p16 - p9
        vpclmulqdq      zmm11, zmm3, zmm1, 0x01 ;; x m0  - m7

        ;; sum results
        vpternlogq      zmm10, zmm5, zmm6, 0x96
        vpxorq          ZWORD(EV), zmm10, zmm11
        VHPXORI4x128    ZWORD(EV), zmm4

        REDUCE_TO_64    EV, xmm3
        vmovq XWORD(EV), XWORD(EV)

        add     in_ptr, 16*8
        sub     qword_len, 16
        cmp     qword_len, 16

        ;; less than 16 blocks left
        jb      lt_16_blocks
        jmp     start_16_block_loop

lt_16_blocks:
        ;; check at least 4 blocks left
        cmp     qword_len, 4
        jb      single_block_check

        ;; at least 4 blocks left
        ;; shift P1P2, P3P4 to lower half of zmm0 and go to 4 block loop
        vextracti64x4   ymm0, zmm0, 0x1
        jmp             start_4_block_loop

init_4_block_loop:
        ;; precompute up to P^4
        PRECOMPUTE_CONSTANTS P1, 4, xmm0, xmm3, xmm4, xmm5, xmm6

start_4_block_loop:
        vmovdqu         ymm3, [in_ptr]
        vpshufb         ymm3, ymm3, [rel bswap64]

        vpxor           ymm3, ymm3, YWORD(EV)

        vpclmulqdq      ymm6, ymm3, ymm0, 0x10 ;;   p4 -  p1
        vpclmulqdq      ymm4, ymm3, ymm0, 0x01 ;; x m0 - m3

        ;; sum results
        vpxorq          YWORD(EV), ymm4, ymm6
        VHPXORI2x128    YWORD(EV), ymm3

        REDUCE_TO_64    EV, xmm3

        vmovq XWORD(EV), XWORD(EV)

        add     in_ptr, 4*8
        sub     qword_len, 4
        cmp     qword_len, 4

        ;; less than 4 blocks left
        jb      single_block_check
        jmp     start_4_block_loop

start_single_block_loop:
        vmovq   xmm0, [in_ptr]
        vpshufb xmm0, xmm0, [rel bswap64]
        vpxor   EV, xmm0
        MUL_AND_REDUCE_64x64_LOW EV, P1, xmm1

        add    in_ptr, 1*8
        dec    qword_len

single_block_check:
        cmp     qword_len, 0
        jne     start_single_block_loop

        mov     tmp5, 0x3f      ;; len_in_bits % 64
        and     tmp5, bit_len
        jz      skip_rem_bits

        ;; load last N bytes
        mov     tmp2, tmp5      ;; (rem_bits + 7) / 8
        add     tmp2, 7
        shr     tmp2, 3

        simd_load_avx_15_1 xmm3, in_ptr, tmp2
        vmovq   tmp3, xmm3
        bswap   tmp3

        mov     tmp, 0xffffffffffffffff
        mov     tmp6, 64
        sub     tmp6, tmp5

        SHIFT_GP tmp, tmp6, tmp, tmp5, left

        and     tmp3, tmp       ;; V &= (((uint64_t)-1) << (64 - rem_bits)); /* mask extra bits */
        vmovq   xmm0, tmp3
        vpxor   EV, xmm0

        MUL_AND_REDUCE_64x64_LOW EV, P1, xmm3

skip_rem_bits:
        ;; /* Multiply by Q */
        ;; E = multiply_and_reduce64(E ^ lengthInBits,
        ;;                           (((uint64_t)z[2] << 32) | ((uint64_t)z[3])));
        ;; /* Final MAC */
        ;; *(uint32_t *)pDigest =
        ;;        (uint32_t)BSWAP64(E ^ ((uint64_t)z[4] << 32));
        vmovq   xmm3, bit_len
        vpxor   EV, xmm3

        vmovq   xmm1, [KS + 8]                  ;; load z[2:3]
        vpshufd xmm1, xmm1, 1110_0001b

        mov     DWORD(tmp4), [KS + (4 * 4)]     ;; tmp4 == z[4] << 32
        shl     tmp4, 32

        MUL_AND_REDUCE_64x64_LOW EV, xmm1, xmm3
        vmovq   E, EV
        xor     E, tmp4

        bswap   E                               ;; return E (rax/eax)

        FUNC_RESTORE

        ret


%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
