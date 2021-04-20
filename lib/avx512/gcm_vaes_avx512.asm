;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2018-2021, Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;
; Authors:
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford
;       Tomasz Kantecki
;
;
; References:
;       This code was derived and highly optimized from the code described in paper:
;               Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation on Intel Architecture Processors. August, 2010
;       The details of the implementation is explained in:
;               Erdinc Ozturk et. al. Enabling High-Performance Galois-Counter-Mode on Intel Architecture Processors. October, 2012.
;
;
;
;
; Assumptions:
;
;
;
; iv:
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                             Salt  (From the SA)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     Initialization Vector                     |
;       |         (This is the sequence number from IPSec header)       |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x1                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;
;
; AAD:
;       AAD will be padded with 0 to the next 16byte multiple
;       for example, assume AAD is a u32 vector
;
;       if AAD is 8 bytes:
;       AAD[3] = {A0, A1};
;       padded AAD in xmm register = {A1 A0 0 0}
;
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                               SPI (A1)                        |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     32-bit Sequence Number (A0)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x0                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;                                       AAD Format with 32-bit Sequence Number
;
;       if AAD is 12 bytes:
;       AAD[3] = {A0, A1, A2};
;       padded AAD in xmm register = {A2 A1 A0 0}
;
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                               SPI (A2)                        |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                 64-bit Extended Sequence Number {A1,A0}       |
;       |                                                               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x0                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;        AAD Format with 64-bit Extended Sequence Number
;
;
; aadLen:
;       Must be a multiple of 4 bytes and from the definition of the spec.
;       The code additionally supports any aadLen length.
;
; TLen:
;       from the definition of the spec, TLen can only be 8, 12 or 16 bytes.
;
; poly = x^128 + x^127 + x^126 + x^121 + 1
; throughout the code, one tab and two tab indentations are used. one tab is for GHASH part, two tabs is for AES part.
;

%include "include/os.asm"
%include "include/reg_sizes.asm"
%include "include/clear_regs.asm"
%include "include/gcm_defines.asm"
%include "include/gcm_keys_vaes_avx512.asm"
%include "include/memcpy.asm"
%include "include/aes_common.asm"
%include "include/cet.inc"
%ifndef GCM128_MODE
%ifndef GCM192_MODE
%ifndef GCM256_MODE
%error "No GCM mode selected for gcm_avx512.asm!"
%endif
%endif
%endif

;; Decide on AES-GCM key size to compile for
%ifdef GCM128_MODE
%define NROUNDS 9
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _128 %+ y %+ vaes_avx512
%define GMAC_FN_NAME(x) imb_aes_gmac_ %+ x %+ _128_ %+ vaes_avx512
%endif

%ifdef GCM192_MODE
%define NROUNDS 11
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _192 %+ y %+ vaes_avx512
%define GMAC_FN_NAME(x) imb_aes_gmac_ %+ x %+ _192_ %+ vaes_avx512
%endif

%ifdef GCM256_MODE
%define NROUNDS 13
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _256 %+ y %+ vaes_avx512
%define GMAC_FN_NAME(x) imb_aes_gmac_ %+ x %+ _256_ %+ vaes_avx512
%endif

section .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Stack frame definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     (10*16)      ; space for 10 XMM registers
        %define GP_STORAGE      ((9*8) + 24) ; space for 9 GP registers + 24 bytes for 64 byte alignment
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      (8*8)   ; space for 7 GP registers + 1 for alignment
%endif
%define LOCAL_STORAGE           (48*16) ; space for up to 48 AES blocks

;;; sequence is (bottom-up): GP, XMM, local
%define STACK_GP_OFFSET         0
%define STACK_XMM_OFFSET        (STACK_GP_OFFSET + GP_STORAGE)
%define STACK_LOCAL_OFFSET      (STACK_XMM_OFFSET + XMM_STORAGE)
%define STACK_FRAME_SIZE        (STACK_LOCAL_OFFSET + LOCAL_STORAGE)

;; for compatibility with stack argument definitions in gcm_defines.asm
%define STACK_OFFSET 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utility Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; ===========================================================================
;;; ===========================================================================
;;; Horizontal XOR - 4 x 128bits xored together
%macro VHPXORI4x128 2
%define %%REG   %1      ; [in/out] ZMM with 4x128bits to xor; 128bit output
%define %%TMP   %2      ; [clobbered] ZMM temporary register
        vextracti64x4   YWORD(%%TMP), %%REG, 1
        vpxorq          YWORD(%%REG), YWORD(%%REG), YWORD(%%TMP)
        vextracti32x4   XWORD(%%TMP), YWORD(%%REG), 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro               ; VHPXORI4x128

;;; ===========================================================================
;;; ===========================================================================
;;; Horizontal XOR - 2 x 128bits xored together
%macro VHPXORI2x128 2
%define %%REG   %1      ; [in/out] YMM/ZMM with 2x128bits to xor; 128bit output
%define %%TMP   %2      ; [clobbered] XMM/YMM/ZMM temporary register
        vextracti32x4   XWORD(%%TMP), %%REG, 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro               ; VHPXORI2x128

;;; ===========================================================================
;;; ===========================================================================
;;; schoolbook multiply - 1st step
%macro VCLMUL_STEP1 6-7
%define %%KP    %1      ; [in] key pointer
%define %%HI    %2      ; [in] previous blocks 4 to 7
%define %%TMP   %3      ; [clobbered] ZMM/YMM/XMM temporary
%define %%TH    %4      ; [out] high product
%define %%TM    %5      ; [out] medium product
%define %%TL    %6      ; [out] low product
%define %%HKEY  %7      ; [in/optional] hash key for multiplication

%if %0 == 6
        vmovdqu64       %%TMP, [%%KP + HashKey_4]
%else
        vmovdqa64       %%TMP, %%HKEY
%endif
        vpclmulqdq      %%TH, %%HI, %%TMP, 0x11     ; %%T5 = a1*b1
        vpclmulqdq      %%TL, %%HI, %%TMP, 0x00     ; %%T7 = a0*b0
        vpclmulqdq      %%TM, %%HI, %%TMP, 0x01     ; %%T6 = a1*b0
        vpclmulqdq      %%TMP, %%HI, %%TMP, 0x10    ; %%T4 = a0*b1
        vpxorq          %%TM, %%TM, %%TMP           ; [%%TH : %%TM : %%TL]
%endmacro               ; VCLMUL_STEP1

;;; ===========================================================================
;;; ===========================================================================
;;; schoolbook multiply - 2nd step
%macro VCLMUL_STEP2 9-11
%define %%KP    %1      ; [in] key pointer
%define %%HI    %2      ; [out] ghash high 128 bits
%define %%LO    %3      ; [in/out] cipher text blocks 0-3 (in); ghash low 128 bits (out)
%define %%TMP0  %4      ; [clobbered] ZMM/YMM/XMM temporary
%define %%TMP1  %5      ; [clobbered] ZMM/YMM/XMM temporary
%define %%TMP2  %6      ; [clobbered] ZMM/YMM/XMM temporary
%define %%TH    %7      ; [in] high product
%define %%TM    %8      ; [in] medium product
%define %%TL    %9      ; [in] low product
%define %%HKEY  %10     ; [in/optional] hash key for multiplication
%define %%HXOR  %11     ; [in/optional] type of horizontal xor (4 - 4x128; 2 - 2x128; 1 - none)

%if %0 == 9
        vmovdqu64       %%TMP0, [%%KP + HashKey_8]
%else
        vmovdqa64       %%TMP0, %%HKEY
%endif
        vpclmulqdq      %%TMP1, %%LO, %%TMP0, 0x10     ; %%TMP1 = a0*b1
        vpclmulqdq      %%TMP2, %%LO, %%TMP0, 0x11     ; %%TMP2 = a1*b1
        vpxorq          %%TH, %%TH, %%TMP2
        vpclmulqdq      %%TMP2, %%LO, %%TMP0, 0x00     ; %%TMP2 = a0*b0
        vpxorq          %%TL, %%TL, %%TMP2
        vpclmulqdq      %%TMP0, %%LO, %%TMP0, 0x01     ; %%TMP0 = a1*b0
        vpternlogq      %%TM, %%TMP1, %%TMP0, 0x96     ; %%TM = TM xor TMP1 xor TMP0

        ;; finish multiplications
        vpsrldq         %%TMP2, %%TM, 8
        vpxorq          %%HI, %%TH, %%TMP2
        vpslldq         %%TMP2, %%TM, 8
        vpxorq          %%LO, %%TL, %%TMP2

        ;; xor 128bit words horizontally and compute [(X8*H1) + (X7*H2) + ... ((X1+Y0)*H8]
        ;; note: (X1+Y0) handled elsewhere
%if %0 < 11
        VHPXORI4x128    %%HI, %%TMP2
        VHPXORI4x128    %%LO, %%TMP1
%else
%if %%HXOR == 4
        VHPXORI4x128    %%HI, %%TMP2
        VHPXORI4x128    %%LO, %%TMP1
%elif %%HXOR == 2
        VHPXORI2x128    %%HI, %%TMP2
        VHPXORI2x128    %%LO, %%TMP1
%endif                          ; HXOR
        ;; for HXOR == 1 there is nothing to be done
%endif                          ; !(%0 < 11)
        ;; HIx holds top 128 bits
        ;; LOx holds low 128 bits
        ;; - further reductions to follow
%endmacro               ; VCLMUL_STEP2

;;; ===========================================================================
;;; ===========================================================================
;;; AVX512 reduction macro
%macro VCLMUL_REDUCE 6
%define %%OUT   %1      ; [out] zmm/ymm/xmm: result (must not be %%TMP1 or %%HI128)
%define %%POLY  %2      ; [in] zmm/ymm/xmm: polynomial
%define %%HI128 %3      ; [in] zmm/ymm/xmm: high 128b of hash to reduce
%define %%LO128 %4      ; [in] zmm/ymm/xmm: low 128b of hash to reduce
%define %%TMP0  %5      ; [in] zmm/ymm/xmm: temporary register
%define %%TMP1  %6      ; [in] zmm/ymm/xmm: temporary register

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; first phase of the reduction
        vpclmulqdq      %%TMP0, %%POLY, %%LO128, 0x01
        vpslldq         %%TMP0, %%TMP0, 8       ; shift-L 2 DWs
        vpxorq          %%TMP0, %%LO128, %%TMP0 ; first phase of the reduction complete

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; second phase of the reduction
        vpclmulqdq      %%TMP1, %%POLY, %%TMP0, 0x00
        vpsrldq         %%TMP1, %%TMP1, 4       ; shift-R only 1-DW to obtain 2-DWs shift-R

        vpclmulqdq      %%OUT, %%POLY, %%TMP0, 0x10
        vpslldq         %%OUT, %%OUT, 4         ; shift-L 1-DW to obtain result with no shifts

        vpternlogq      %%OUT, %%TMP1, %%HI128, 0x96    ; OUT/GHASH = OUT xor TMP1 xor HI128
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endmacro

;;; ===========================================================================
;;; ===========================================================================
;;; schoolbook multiply (1 to 8 blocks) - 1st step
%macro VCLMUL_1_TO_8_STEP1 8
%define %%KP      %1    ; [in] key pointer
%define %%HI      %2    ; [in] ZMM ciphered blocks 4 to 7
%define %%TMP1    %3    ; [clobbered] ZMM temporary
%define %%TMP2    %4    ; [clobbered] ZMM temporary
%define %%TH      %5    ; [out] ZMM high product
%define %%TM      %6    ; [out] ZMM medium product
%define %%TL      %7    ; [out] ZMM low product
%define %%NBLOCKS %8    ; [in] number of blocks to ghash (0 to 8)

%if %%NBLOCKS == 8
        VCLMUL_STEP1    %%KP, %%HI, %%TMP1, %%TH, %%TM, %%TL
%elif  %%NBLOCKS == 7
        vmovdqu64       %%TMP2, [%%KP + HashKey_3]
        vmovdqa64       %%TMP1, [rel mask_out_top_block]
        vpandq          %%TMP2, %%TMP1
        vpandq          %%HI, %%TMP1
        VCLMUL_STEP1    NULL, %%HI, %%TMP1, %%TH, %%TM, %%TL, %%TMP2
%elif  %%NBLOCKS == 6
        vmovdqu64       YWORD(%%TMP2), [%%KP + HashKey_2]
        VCLMUL_STEP1    NULL, YWORD(%%HI), YWORD(%%TMP1), \
                YWORD(%%TH), YWORD(%%TM), YWORD(%%TL), YWORD(%%TMP2)
%elif  %%NBLOCKS == 5
        vmovdqu64       XWORD(%%TMP2), [%%KP + HashKey_1]
        VCLMUL_STEP1    NULL, XWORD(%%HI), XWORD(%%TMP1), \
                XWORD(%%TH), XWORD(%%TM), XWORD(%%TL), XWORD(%%TMP2)
%else
        vpxorq          %%TH, %%TH
        vpxorq          %%TM, %%TM
        vpxorq          %%TL, %%TL
%endif
%endmacro               ; VCLMUL_1_TO_8_STEP1

;;; ===========================================================================
;;; ===========================================================================
;;; schoolbook multiply (1 to 8 blocks) - 2nd step
%macro VCLMUL_1_TO_8_STEP2 10
%define %%KP      %1    ; [in] key pointer
%define %%HI      %2    ; [out] ZMM ghash high 128bits
%define %%LO      %3    ; [in/out] ZMM ciphered blocks 0 to 3 (in); ghash low 128bits (out)
%define %%TMP0    %4    ; [clobbered] ZMM temporary
%define %%TMP1    %5    ; [clobbered] ZMM temporary
%define %%TMP2    %6    ; [clobbered] ZMM temporary
%define %%TH      %7    ; [in/clobbered] ZMM high sum
%define %%TM      %8    ; [in/clobbered] ZMM medium sum
%define %%TL      %9    ; [in/clobbered] ZMM low sum
%define %%NBLOCKS %10   ; [in] number of blocks to ghash (0 to 8)

%if %%NBLOCKS == 8
        VCLMUL_STEP2    %%KP, %%HI, %%LO, %%TMP0, %%TMP1, %%TMP2, %%TH, %%TM, %%TL
%elif %%NBLOCKS == 7
        vmovdqu64       %%TMP2, [%%KP + HashKey_7]
        VCLMUL_STEP2    NULL, %%HI, %%LO, %%TMP0, %%TMP1, %%TMP2, %%TH, %%TM, %%TL, %%TMP2, 4
%elif %%NBLOCKS == 6
        vmovdqu64       %%TMP2, [%%KP + HashKey_6]
        VCLMUL_STEP2    NULL, %%HI, %%LO, %%TMP0, %%TMP1, %%TMP2, %%TH, %%TM, %%TL, %%TMP2, 4
%elif %%NBLOCKS == 5
        vmovdqu64       %%TMP2, [%%KP + HashKey_5]
        VCLMUL_STEP2    NULL, %%HI, %%LO, %%TMP0, %%TMP1, %%TMP2, %%TH, %%TM, %%TL, %%TMP2, 4
%elif %%NBLOCKS == 4
        vmovdqu64       %%TMP2, [%%KP + HashKey_4]
        VCLMUL_STEP2    NULL, %%HI, %%LO, %%TMP0, %%TMP1, %%TMP2, %%TH, %%TM, %%TL, %%TMP2, 4
%elif %%NBLOCKS == 3
        vmovdqu64       %%TMP2, [%%KP + HashKey_3]
        vmovdqa64       %%TMP1, [rel mask_out_top_block]
        vpandq          %%TMP2, %%TMP1
        vpandq          %%LO, %%TMP1
        VCLMUL_STEP2    NULL, %%HI, %%LO, %%TMP0, %%TMP1, %%TMP2, %%TH, %%TM, %%TL, %%TMP2, 4
%elif %%NBLOCKS == 2
        vmovdqu64       YWORD(%%TMP2), [%%KP + HashKey_2]
        VCLMUL_STEP2    NULL, YWORD(%%HI), YWORD(%%LO), \
                YWORD(%%TMP0), YWORD(%%TMP1), YWORD(%%TMP2), \
                YWORD(%%TH), YWORD(%%TM), YWORD(%%TL), YWORD(%%TMP2), 2
%elif %%NBLOCKS == 1
        vmovdqu64       XWORD(%%TMP2), [%%KP + HashKey_1]
        VCLMUL_STEP2    NULL, XWORD(%%HI), XWORD(%%LO), \
                XWORD(%%TMP0), XWORD(%%TMP1), XWORD(%%TMP2), \
                XWORD(%%TH), XWORD(%%TM), XWORD(%%TL), XWORD(%%TMP2), 1
%else
        vpxorq          %%HI, %%HI
        vpxorq          %%LO, %%LO
%endif
%endmacro               ; VCLMUL_1_TO_8_STEP2

;;; ===========================================================================
;;; ===========================================================================
;;; schoolbook multiply of 16 blocks (8 x 16 bytes)

%macro GHASH_16 21
%define %%TYPE  %1      ; [in] ghash type: start (xor hash), mid, end (same as mid; no reduction), end_reduce (reduction)
%define %%GH    %2      ; [in/out] ZMM ghash sum: high 128-bits
%define %%GM    %3      ; [in/out] ZMM ghash sum: middle 128-bits
%define %%GL    %4      ; [in/out] ZMM ghash sum: low 128-bits
%define %%INPTR %5      ; [in] data input pointer
%define %%INOFF %6      ; [in] data input offset
%define %%INDIS %7      ; [in] data input displacment
%define %%HKPTR %8      ; [in] hash key pointer
%define %%HKOFF %9      ; [in] hash key offset
%define %%HKDIS %10     ; [in] hash key displacment
%define %%HASH  %11     ; [in/out] ZMM hash value in/out
%define %%ZTMP0 %12     ; [clobbered] temporary ZMM
%define %%ZTMP1 %13     ; [clobbered] temporary ZMM
%define %%ZTMP2 %14     ; [clobbered] temporary ZMM
%define %%ZTMP3 %15     ; [clobbered] temporary ZMM
%define %%ZTMP4 %16     ; [clobbered] temporary ZMM
%define %%ZTMP5 %17     ; [clobbered] temporary ZMM
%define %%ZTMP6 %18     ; [clobbered] temporary ZMM
%define %%ZTMP7 %19     ; [clobbered] temporary ZMM
%define %%ZTMP8 %20     ; [clobbered] temporary ZMM
%define %%ZTMP9 %21     ; [clobbered] temporary ZMM

        ;; ghash blocks 0-3
        vmovdqa64       %%ZTMP8, [%%INPTR + %%INOFF + %%INDIS]
%ifidn %%TYPE, start
        vpxorq          %%ZTMP8, %%HASH
%endif
        vmovdqu64       %%ZTMP9, [%%HKPTR + %%HKOFF + %%HKDIS]
        vpclmulqdq      %%ZTMP0, %%ZTMP8, %%ZTMP9, 0x11     ; T0H = a1*b1
        vpclmulqdq      %%ZTMP1, %%ZTMP8, %%ZTMP9, 0x00     ; T0L = a0*b0
        vpclmulqdq      %%ZTMP2, %%ZTMP8, %%ZTMP9, 0x01     ; T0M1 = a1*b0
        vpclmulqdq      %%ZTMP3, %%ZTMP8, %%ZTMP9, 0x10     ; T0M2 = a0*b1
        ;; ghash blocks 4-7
        vmovdqa64       %%ZTMP8, [%%INPTR + %%INOFF + %%INDIS + 64]
        vmovdqu64       %%ZTMP9, [%%HKPTR + %%HKOFF + %%HKDIS + 64]
        vpclmulqdq      %%ZTMP4, %%ZTMP8, %%ZTMP9, 0x11     ; T1H = a1*b1
        vpclmulqdq      %%ZTMP5, %%ZTMP8, %%ZTMP9, 0x00     ; T1L = a0*b0
        vpclmulqdq      %%ZTMP6, %%ZTMP8, %%ZTMP9, 0x01     ; T1M1 = a1*b0
        vpclmulqdq      %%ZTMP7, %%ZTMP8, %%ZTMP9, 0x10     ; T1M2 = a0*b1
        ;; update sums
%ifidn %%TYPE, start
        vpxorq          %%GM, %%ZTMP2, %%ZTMP6              ; GM = T0M1 + T1M1
        vpxorq          %%GH, %%ZTMP0, %%ZTMP4              ; GH = T0H + T1H
        vpxorq          %%GL, %%ZTMP1, %%ZTMP5              ; GL = T0L + T1L
        vpternlogq      %%GM, %%ZTMP3, %%ZTMP7, 0x96        ; GM = T0M2 + T1M1
%else ;; mid, end, end_reduce
        vpternlogq      %%GM, %%ZTMP2, %%ZTMP6, 0x96        ; GM += T0M1 + T1M1
        vpternlogq      %%GH, %%ZTMP0, %%ZTMP4, 0x96        ; GH += T0H + T1H
        vpternlogq      %%GL, %%ZTMP1, %%ZTMP5, 0x96        ; GL += T0L + T1L
        vpternlogq      %%GM, %%ZTMP3, %%ZTMP7, 0x96        ; GM += T0M2 + T1M1
%endif
        ;; ghash blocks 8-11
        vmovdqa64       %%ZTMP8, [%%INPTR + %%INOFF + %%INDIS + 128]
        vmovdqu64       %%ZTMP9, [%%HKPTR + %%HKOFF + %%HKDIS + 128]
        vpclmulqdq      %%ZTMP0, %%ZTMP8, %%ZTMP9, 0x11     ; T0H = a1*b1
        vpclmulqdq      %%ZTMP1, %%ZTMP8, %%ZTMP9, 0x00     ; T0L = a0*b0
        vpclmulqdq      %%ZTMP2, %%ZTMP8, %%ZTMP9, 0x01     ; T0M1 = a1*b0
        vpclmulqdq      %%ZTMP3, %%ZTMP8, %%ZTMP9, 0x10     ; T0M2 = a0*b1
        ;; ghash blocks 12-15
        vmovdqa64       %%ZTMP8, [%%INPTR + %%INOFF + %%INDIS + 192]
        vmovdqu64       %%ZTMP9, [%%HKPTR + %%HKOFF + %%HKDIS + 192]
        vpclmulqdq      %%ZTMP4, %%ZTMP8, %%ZTMP9, 0x11     ; T1H = a1*b1
        vpclmulqdq      %%ZTMP5, %%ZTMP8, %%ZTMP9, 0x00     ; T1L = a0*b0
        vpclmulqdq      %%ZTMP6, %%ZTMP8, %%ZTMP9, 0x01     ; T1M1 = a1*b0
        vpclmulqdq      %%ZTMP7, %%ZTMP8, %%ZTMP9, 0x10     ; T1M2 = a0*b1
        ;; update sums
        vpternlogq      %%GM, %%ZTMP2, %%ZTMP6, 0x96        ; GM += T0M1 + T1M1
        vpternlogq      %%GH, %%ZTMP0, %%ZTMP4, 0x96        ; GH += T0H + T1H
        vpternlogq      %%GL, %%ZTMP1, %%ZTMP5, 0x96        ; GL += T0L + T1L
        vpternlogq      %%GM, %%ZTMP3, %%ZTMP7, 0x96        ; GM += T0M2 + T1M1

%ifidn %%TYPE, end_reduce
        ;; integrate GM into GH and GL
        vpsrldq         %%ZTMP0, %%GM, 8
        vpslldq         %%ZTMP1, %%GM, 8
        vpxorq          %%GH, %%GH, %%ZTMP0
        vpxorq          %%GL, %%GL, %%ZTMP1

        ;; add GH and GL 128-bit words horizontally
        VHPXORI4x128    %%GH, %%ZTMP0
        VHPXORI4x128    %%GL, %%ZTMP1

        ;; reduction
        vmovdqa64       XWORD(%%ZTMP2), [rel POLY2]
        VCLMUL_REDUCE   XWORD(%%HASH), XWORD(%%ZTMP2), \
                        XWORD(%%GH), XWORD(%%GL), XWORD(%%ZTMP0), XWORD(%%ZTMP1)
%endif
%endmacro

;;; ===========================================================================
;;; ===========================================================================
;;; GHASH 1 to 16 blocks of cipher text
;;; - performs reduction at the end
%macro  GHASH_1_TO_16 18-24
%define %%KP            %1      ; [in] pointer to expanded keys
%define %%GHASH         %2      ; [out] ghash output
%define %%T1            %3      ; [clobbered] temporary ZMM
%define %%T2            %4      ; [clobbered] temporary ZMM
%define %%T3            %5      ; [clobbered] temporary ZMM
%define %%T4            %6      ; [clobbered] temporary ZMM
%define %%T5            %7      ; [clobbered] temporary ZMM
%define %%T6            %8      ; [clobbered] temporary ZMM
%define %%T7            %9      ; [clobbered] temporary ZMM
%define %%T8            %10     ; [clobbered] temporary ZMM
%define %%T9            %11     ; [clobbered] temporary ZMM
%define %%AAD_HASH_IN   %12     ; [in] input hash value
%define %%CIPHER_IN0    %13     ; [in] ZMM with cipher text blocks 0-3
%define %%CIPHER_IN1    %14     ; [in] ZMM with cipher text blocks 4-7
%define %%CIPHER_IN2    %15     ; [in] ZMM with cipher text blocks 8-11
%define %%CIPHER_IN3    %16     ; [in] ZMM with cipher text blocks 12-15
%define %%NUM_BLOCKS    %17     ; [in] numerical value, number of blocks
%define %%INSTANCE_TYPE %18     ; [in] multi_call or single_call
%define %%ROUND         %19     ; [in] Round number (for multi_call): "first", "mid", "last"
%define %%HKEY_START    %20     ; [in] Hash subkey to start from (for multi_call): 48, 32, 16
%define %%PREV_H        %21     ; [in/out] In: High result from previous call, Out: High result of this call
%define %%PREV_L        %22     ; [in/out] In: Low result from previous call, Out: Low result of this call
%define %%PREV_M1       %23     ; [in/out] In: Medium 1 result from previous call, Out: Medium 1 result of this call
%define %%PREV_M2       %24     ; [in/out] In: Medium 2 result from previous call, Out: Medium 2 result of this call

%define %%T0H           %%T1
%define %%T0L           %%T2
%define %%T0M1          %%T3
%define %%T0M2          %%T4

%define %%T1H           %%T5
%define %%T1L           %%T6
%define %%T1M1          %%T7
%define %%T1M2          %%T8

%define %%HK            %%T9

%assign reg_idx     0
%assign blocks_left %%NUM_BLOCKS

%ifidn %%INSTANCE_TYPE, single_call
%assign hashk           HashKey_ %+ %%NUM_BLOCKS
%assign first_result 1
%assign reduce       1
        vpxorq          %%CIPHER_IN0, %%CIPHER_IN0, %%AAD_HASH_IN
%else ; %%INSTANCE_TYPE == multi_call

%assign hashk           HashKey_ %+ %%HKEY_START
%ifidn %%ROUND, first
%assign first_result 1
%assign reduce       0
        vpxorq          %%CIPHER_IN0, %%CIPHER_IN0, %%AAD_HASH_IN
%elifidn %%ROUND, mid
%assign first_result 0
%assign reduce       0
        vmovdqa64          %%T0H, %%PREV_H
        vmovdqa64          %%T0L, %%PREV_L
        vmovdqa64          %%T0M1, %%PREV_M1
        vmovdqa64          %%T0M2, %%PREV_M2
%else ; %%ROUND == last
%assign first_result 0
%assign reduce       1
        vmovdqa64          %%T0H, %%PREV_H
        vmovdqa64          %%T0L, %%PREV_L
        vmovdqa64          %%T0M1, %%PREV_M1
        vmovdqa64          %%T0M2, %%PREV_M2
%endif ; %%ROUND

%endif ; %%INSTANCE_TYPE


%rep (blocks_left / 4)
%xdefine %%REG_IN %%CIPHER_IN %+ reg_idx
        vmovdqu64       %%HK, [%%KP + hashk]
%if first_result == 1
        vpclmulqdq      %%T0H, %%REG_IN, %%HK, 0x11      ; H = a1*b1
        vpclmulqdq      %%T0L, %%REG_IN, %%HK, 0x00      ; L = a0*b0
        vpclmulqdq      %%T0M1, %%REG_IN, %%HK, 0x01     ; M1 = a1*b0
        vpclmulqdq      %%T0M2, %%REG_IN, %%HK, 0x10     ; TM2 = a0*b1
%assign first_result 0
%else
        vpclmulqdq      %%T1H, %%REG_IN, %%HK, 0x11      ; H = a1*b1
        vpclmulqdq      %%T1L, %%REG_IN, %%HK, 0x00      ; L = a0*b0
        vpclmulqdq      %%T1M1, %%REG_IN, %%HK, 0x01     ; M1 = a1*b0
        vpclmulqdq      %%T1M2, %%REG_IN, %%HK, 0x10     ; M2 = a0*b1
        vpxorq          %%T0H, %%T0H, %%T1H
        vpxorq          %%T0L, %%T0L, %%T1L
        vpxorq          %%T0M1, %%T0M1, %%T1M1
        vpxorq          %%T0M2, %%T0M2, %%T1M2
%endif
%undef %%REG_IN
%assign reg_idx     (reg_idx + 1)
%assign hashk       (hashk + 64)
%assign blocks_left (blocks_left - 4)
%endrep

%if blocks_left > 0
;; There are 1, 2 or 3 blocks left to process.
;; It may also be that they are the only blocks to process.

%xdefine %%REG_IN %%CIPHER_IN %+ reg_idx

%if first_result == 1
;; Case where %%NUM_BLOCKS = 1, 2 or 3
%xdefine %%OUT_H  %%T0H
%xdefine %%OUT_L  %%T0L
%xdefine %%OUT_M1 %%T0M1
%xdefine %%OUT_M2 %%T0M2
%else
%xdefine %%OUT_H  %%T1H
%xdefine %%OUT_L  %%T1L
%xdefine %%OUT_M1 %%T1M1
%xdefine %%OUT_M2 %%T1M2
%endif

%if blocks_left == 1
        vmovdqu64       XWORD(%%HK), [%%KP + hashk]
        vpclmulqdq      XWORD(%%OUT_H), XWORD(%%REG_IN), XWORD(%%HK), 0x11      ; %%TH = a1*b1
        vpclmulqdq      XWORD(%%OUT_L), XWORD(%%REG_IN), XWORD(%%HK), 0x00      ; %%TL = a0*b0
        vpclmulqdq      XWORD(%%OUT_M1), XWORD(%%REG_IN), XWORD(%%HK), 0x01     ; %%TM1 = a1*b0
        vpclmulqdq      XWORD(%%OUT_M2), XWORD(%%REG_IN), XWORD(%%HK), 0x10     ; %%TM2 = a0*b1
%elif blocks_left == 2
        vmovdqu64       YWORD(%%HK), [%%KP + hashk]
        vpclmulqdq      YWORD(%%OUT_H), YWORD(%%REG_IN), YWORD(%%HK), 0x11      ; %%TH = a1*b1
        vpclmulqdq      YWORD(%%OUT_L), YWORD(%%REG_IN), YWORD(%%HK), 0x00      ; %%TL = a0*b0
        vpclmulqdq      YWORD(%%OUT_M1), YWORD(%%REG_IN), YWORD(%%HK), 0x01     ; %%TM1 = a1*b0
        vpclmulqdq      YWORD(%%OUT_M2), YWORD(%%REG_IN), YWORD(%%HK), 0x10     ; %%TM2 = a0*b1
%else ; blocks_left == 3
        vmovdqu64       YWORD(%%HK), [%%KP + hashk]
        vinserti64x2    %%HK, [%%KP + hashk + 32], 2
        vpclmulqdq      %%OUT_H, %%REG_IN, %%HK, 0x11      ; %%TH = a1*b1
        vpclmulqdq      %%OUT_L, %%REG_IN, %%HK, 0x00      ; %%TL = a0*b0
        vpclmulqdq      %%OUT_M1, %%REG_IN, %%HK, 0x01     ; %%TM1 = a1*b0
        vpclmulqdq      %%OUT_M2, %%REG_IN, %%HK, 0x10     ; %%TM2 = a0*b1
%endif ; blocks_left

%undef %%REG_IN
%undef %%OUT_H
%undef %%OUT_L
%undef %%OUT_M1
%undef %%OUT_M2

%if first_result != 1
        vpxorq          %%T0H, %%T0H, %%T1H
        vpxorq          %%T0L, %%T0L, %%T1L
        vpxorq          %%T0M1, %%T0M1, %%T1M1
        vpxorq          %%T0M2, %%T0M2, %%T1M2
%endif

%endif ; blocks_left > 0

%if reduce == 1
        ;; integrate TM into TH and TL
        vpxorq          %%T0M1, %%T0M1, %%T0M2
        vpsrldq         %%T1M1, %%T0M1, 8
        vpslldq         %%T1M2, %%T0M1, 8
        vpxorq          %%T0H, %%T0H, %%T1M1
        vpxorq          %%T0L, %%T0L, %%T1M2

        ;; add TH and TL 128-bit words horizontally
        VHPXORI4x128    %%T0H, %%T1M1
        VHPXORI4x128    %%T0L, %%T1M2

        ;; reduction
        vmovdqa64       XWORD(%%HK), [rel POLY2]
        VCLMUL_REDUCE   XWORD(%%GHASH), XWORD(%%HK), \
                        XWORD(%%T0H), XWORD(%%T0L), XWORD(%%T0M1), XWORD(%%T0M2)
%else ;; reduce == 0
        vmovdqa64       %%PREV_H, %%T0H
        vmovdqa64       %%PREV_L, %%T0L
        vmovdqa64       %%PREV_M1, %%T0M1
        vmovdqa64       %%PREV_M2, %%T0M2
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; GHASH_MUL MACRO to implement: Data*HashKey mod (128,127,126,121,0)
;;; Input: A and B (128-bits each, bit-reflected)
;;; Output: C = A*B*x mod poly, (i.e. >>1 )
;;; To compute GH = GH*HashKey mod poly, give HK = HashKey<<1 mod poly as input
;;; GH = GH * HK * x mod poly which is equivalent to GH*HashKey mod poly.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GHASH_MUL  7
%define %%GH %1         ;; [in/out] xmm/ymm/zmm with multiply operand(s) (128-bits)
%define %%HK %2         ;; [in] xmm/ymm/zmm with hash key value(s) (128-bits)
%define %%T1 %3         ;; [clobbered] xmm/ymm/zmm
%define %%T2 %4         ;; [clobbered] xmm/ymm/zmm
%define %%T3 %5         ;; [clobbered] xmm/ymm/zmm
%define %%T4 %6         ;; [clobbered] xmm/ymm/zmm
%define %%T5 %7         ;; [clobbered] xmm/ymm/zmm

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        vpclmulqdq      %%T1, %%GH, %%HK, 0x11  ; %%T1 = a1*b1
        vpclmulqdq      %%T2, %%GH, %%HK, 0x00  ; %%T2 = a0*b0
        vpclmulqdq      %%T3, %%GH, %%HK, 0x01  ; %%T3 = a1*b0
        vpclmulqdq      %%GH, %%GH, %%HK, 0x10  ; %%GH = a0*b1
        vpxorq          %%GH, %%GH, %%T3


        vpsrldq         %%T3, %%GH, 8           ; shift-R %%GH 2 DWs
        vpslldq         %%GH, %%GH, 8           ; shift-L %%GH 2 DWs

        vpxorq          %%T1, %%T1, %%T3
        vpxorq          %%GH, %%GH, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;first phase of the reduction
        vmovdqu64       %%T3, [rel POLY2]

        vpclmulqdq      %%T2, %%T3, %%GH, 0x01
        vpslldq         %%T2, %%T2, 8           ; shift-L %%T2 2 DWs

        vpxorq          %%GH, %%GH, %%T2        ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;second phase of the reduction
        vpclmulqdq      %%T2, %%T3, %%GH, 0x00
        vpsrldq         %%T2, %%T2, 4           ; shift-R only 1-DW to obtain 2-DWs shift-R

        vpclmulqdq      %%GH, %%T3, %%GH, 0x10
        vpslldq         %%GH, %%GH, 4           ; Shift-L 1-DW to obtain result with no shifts

        ; second phase of the reduction complete, the result is in %%GH
        vpternlogq      %%GH, %%T1, %%T2, 0x96  ; GH = GH xor T1 xor T2
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; In PRECOMPUTE, the commands filling Hashkey_i_k are not required for avx512
;;; functions, but are kept to allow users to switch cpu architectures between calls
;;; of pre, init, update, and finalize.
%macro  PRECOMPUTE 10
%define %%GDATA %1      ;; [in/out] GPR, pointer to GCM key data structure, content updated
%define %%HK    %2      ;; [in] xmm, hash key
%define %%T1    %3      ;; [clobbered] xmm
%define %%T2    %4      ;; [clobbered] xmm
%define %%T3    %5      ;; [clobbered] xmm
%define %%T4    %6      ;; [clobbered] xmm
%define %%T5    %7      ;; [clobbered] xmm
%define %%T6    %8      ;; [clobbered] xmm
%define %%T7    %9      ;; [clobbered] xmm
%define %%T8    %10     ;; [clobbered] xmm

%xdefine %%ZT1 ZWORD(%%T1)
%xdefine %%ZT2 ZWORD(%%T2)
%xdefine %%ZT3 ZWORD(%%T3)
%xdefine %%ZT4 ZWORD(%%T4)
%xdefine %%ZT5 ZWORD(%%T5)
%xdefine %%ZT6 ZWORD(%%T6)
%xdefine %%ZT7 ZWORD(%%T7)
%xdefine %%ZT8 ZWORD(%%T8)

        vmovdqa64       %%T5, %%HK
        vinserti64x2    %%ZT7, %%HK, 3

        ;; calculate HashKey^2<<1 mod poly
        GHASH_MUL       %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2
        vmovdqu64       [%%GDATA + HashKey_2], %%T5
        vinserti64x2    %%ZT7, %%T5, 2

        ;; calculate HashKey^3<<1 mod poly
        GHASH_MUL       %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2
        vmovdqu64       [%%GDATA + HashKey_3], %%T5
        vinserti64x2    %%ZT7, %%T5, 1

        ;; calculate HashKey^4<<1 mod poly
        GHASH_MUL       %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2
        vmovdqu64       [%%GDATA + HashKey_4], %%T5
        vinserti64x2    %%ZT7, %%T5, 0

        ;; switch to 4x128-bit computations now
        vshufi64x2      %%ZT5, %%ZT5, %%ZT5, 0x00       ;; broadcast HashKey^4 across all ZT5
        vmovdqa64       %%ZT8, %%ZT7                    ;; save HashKey^4 to HashKey^1 in ZT8

        ;; calculate HashKey^5<<1 mod poly, HashKey^6<<1 mod poly, ... HashKey^8<<1 mod poly
        GHASH_MUL       %%ZT7, %%ZT5, %%ZT1, %%ZT3, %%ZT4, %%ZT6, %%ZT2
        vmovdqu64       [%%GDATA + HashKey_8], %%ZT7    ;; HashKey^8 to HashKey^5 in ZT7 now
        vshufi64x2      %%ZT5, %%ZT7, %%ZT7, 0x00       ;; broadcast HashKey^8 across all ZT5

        ;; calculate HashKey^9<<1 mod poly, HashKey^10<<1 mod poly, ... HashKey^48<<1 mod poly
        ;; use HashKey^8 as multiplier against ZT8 and ZT7 - this allows deeper ooo execution
%assign i 12
%rep ((48 - 8) / 8)
        ;; compute HashKey^(4 + n), HashKey^(3 + n), ... HashKey^(1 + n)
        GHASH_MUL       %%ZT8, %%ZT5, %%ZT1, %%ZT3, %%ZT4, %%ZT6, %%ZT2
        vmovdqu64       [%%GDATA + HashKey_ %+ i], %%ZT8
%assign i (i + 4)

        ;; compute HashKey^(8 + n), HashKey^(7 + n), ... HashKey^(5 + n)
        GHASH_MUL       %%ZT7, %%ZT5, %%ZT1, %%ZT3, %%ZT4, %%ZT6, %%ZT2
        vmovdqu64       [%%GDATA + HashKey_ %+ i], %%ZT7
%assign i (i + 4)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; READ_SMALL_DATA_INPUT
;;; Packs xmm register with data when data input is less or equal to 16 bytes
;;; Returns 0 if data has length 0
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro READ_SMALL_DATA_INPUT    5
%define %%OUTPUT        %1 ; [out] xmm register
%define %%INPUT         %2 ; [in] buffer pointer to read from
%define %%LENGTH        %3 ; [in] number of bytes to read
%define %%TMP1          %4 ; [clobbered]
%define %%MASK          %5 ; [out] k1 to k7 register to store the partial block mask

        cmp             %%LENGTH, 16
        jge             %%_read_small_data_ge16
        lea             %%TMP1, [rel byte_len_to_mask_table]
%ifidn __OUTPUT_FORMAT__, win64
        add             %%TMP1, %%LENGTH
        add             %%TMP1, %%LENGTH
        kmovw           %%MASK, [%%TMP1]
%else
        kmovw           %%MASK, [%%TMP1 + %%LENGTH*2]
%endif
        vmovdqu8        %%OUTPUT{%%MASK}{z}, [%%INPUT]
        jmp             %%_read_small_data_end
%%_read_small_data_ge16:
        VX512LDR        %%OUTPUT, [%%INPUT]
        mov             %%TMP1, 0xffff
        kmovq           %%MASK, %%TMP1
%%_read_small_data_end:
%endmacro ; READ_SMALL_DATA_INPUT

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; CALC_AAD_HASH: Calculates the hash of the data which will not be encrypted.
; Input: The input data (A_IN), that data's length (A_LEN), and the hash key (HASH_KEY).
; Output: The hash of the data (AAD_HASH).
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  CALC_AAD_HASH   26
%define %%A_IN          %1      ; [in] AAD text pointer
%define %%A_LEN         %2      ; [in] AAD length
%define %%AAD_HASH      %3      ; [in/out] xmm ghash value
%define %%GDATA_KEY     %4      ; [in] pointer to keys
%define %%ZT0           %5      ; [clobbered] ZMM register
%define %%ZT1           %6      ; [clobbered] ZMM register
%define %%ZT2           %7      ; [clobbered] ZMM register
%define %%ZT3           %8      ; [clobbered] ZMM register
%define %%ZT4           %9      ; [clobbered] ZMM register
%define %%ZT5           %10     ; [clobbered] ZMM register
%define %%ZT6           %11     ; [clobbered] ZMM register
%define %%ZT7           %12     ; [clobbered] ZMM register
%define %%ZT8           %13     ; [clobbered] ZMM register
%define %%ZT9           %14     ; [clobbered] ZMM register
%define %%ZT10          %15     ; [clobbered] ZMM register
%define %%ZT11          %16     ; [clobbered] ZMM register
%define %%ZT12          %17     ; [clobbered] ZMM register
%define %%ZT13          %18     ; [clobbered] ZMM register
%define %%ZT14          %19     ; [clobbered] ZMM register
%define %%ZT15          %20     ; [clobbered] ZMM register
%define %%ZT16          %21     ; [clobbered] ZMM register
%define %%ZT17          %22     ; [clobbered] ZMM register
%define %%T1            %23     ; [clobbered] GP register
%define %%T2            %24     ; [clobbered] GP register
%define %%T3            %25     ; [clobbered] GP register
%define %%MASKREG       %26     ; [clobbered] mask register

%define %%SHFMSK %%ZT13

        mov             %%T1, %%A_IN            ; T1 = AAD
        mov             %%T2, %%A_LEN           ; T2 = aadLen

        or              %%T2, %%T2
        jz              %%_CALC_AAD_done

        vmovdqa64       %%SHFMSK, [rel SHUF_MASK]

%%_get_AAD_loop48x16:
        cmp             %%T2, (48*16)
        jl              %%_exit_AAD_loop48x16

        vmovdqu64       %%ZT1, [%%T1 + 64*0]  ; Blocks 0-3
        vmovdqu64       %%ZT2, [%%T1 + 64*1]  ; Blocks 4-7
        vmovdqu64       %%ZT3, [%%T1 + 64*2]  ; Blocks 8-11
        vmovdqu64       %%ZT4, [%%T1 + 64*3]  ; Blocks 12-15
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK

        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        16, multi_call, first, 48, %%ZT14, %%ZT15, %%ZT16, %%ZT17

        vmovdqu64       %%ZT1, [%%T1 + 16*16 + 64*0]  ; Blocks 16-19
        vmovdqu64       %%ZT2, [%%T1 + 16*16 + 64*1]  ; Blocks 20-23
        vmovdqu64       %%ZT3, [%%T1 + 16*16 + 64*2]  ; Blocks 24-27
        vmovdqu64       %%ZT4, [%%T1 + 16*16 + 64*3]  ; Blocks 28-31
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK

        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        16, multi_call, mid, 32, %%ZT14, %%ZT15, %%ZT16, %%ZT17

        vmovdqu64       %%ZT1, [%%T1 + 32*16 + 64*0]  ; Blocks 32-35
        vmovdqu64       %%ZT2, [%%T1 + 32*16 + 64*1]  ; Blocks 36-39
        vmovdqu64       %%ZT3, [%%T1 + 32*16 + 64*2]  ; Blocks 40-43
        vmovdqu64       %%ZT4, [%%T1 + 32*16 + 64*3]  ; Blocks 44-47
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK

        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        16, multi_call, last, 16, %%ZT14, %%ZT15, %%ZT16, %%ZT17

        sub             %%T2, (48*16)
        je              %%_CALC_AAD_done

        add             %%T1, (48*16)
        jmp             %%_get_AAD_loop48x16

%%_exit_AAD_loop48x16:
        ; Less than 48x16 bytes remaining
        cmp             %%T2, (32*16)
        jl              %%_less_than_32x16

        ; Get next 16 blocks
        vmovdqu64       %%ZT1, [%%T1 + 64*0]
        vmovdqu64       %%ZT2, [%%T1 + 64*1]
        vmovdqu64       %%ZT3, [%%T1 + 64*2]
        vmovdqu64       %%ZT4, [%%T1 + 64*3]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK

        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        16, multi_call, first, 32, %%ZT14, %%ZT15, %%ZT16, %%ZT17

        vmovdqu64       %%ZT1, [%%T1 + 16*16 + 64*0]
        vmovdqu64       %%ZT2, [%%T1 + 16*16 + 64*1]
        vmovdqu64       %%ZT3, [%%T1 + 16*16 + 64*2]
        vmovdqu64       %%ZT4, [%%T1 + 16*16 + 64*3]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK

        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        16, multi_call, last, 16, %%ZT14, %%ZT15, %%ZT16, %%ZT17

        sub             %%T2, (32*16)
        je              %%_CALC_AAD_done

        add             %%T1, (32*16)
        jmp             %%_less_than_16x16

%%_less_than_32x16:
        cmp             %%T2, (16*16)
        jl              %%_less_than_16x16
        ; Get next 16 blocks
        vmovdqu64       %%ZT1, [%%T1 + 64*0]
        vmovdqu64       %%ZT2, [%%T1 + 64*1]
        vmovdqu64       %%ZT3, [%%T1 + 64*2]
        vmovdqu64       %%ZT4, [%%T1 + 64*3]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK

        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        16, single_call

        sub             %%T2, (16*16)
        je              %%_CALC_AAD_done

        add             %%T1, (16*16)

        ; Less than 16x16 bytes remaining
%%_less_than_16x16:
        ;; prep mask source address
        lea             %%T3, [rel byte64_len_to_mask_table]
        lea             %%T3, [%%T3 + %%T2*8]

        ;; calculate number of blocks to ghash (including partial bytes)
        add             %%T2, 15
        and             %%T2, -16       ; 1 to 16 blocks possible here
        shr             %%T2, 4
        cmp             %%T2, 1
        je              %%_AAD_blocks_1
        cmp             %%T2, 2
        je              %%_AAD_blocks_2
        cmp             %%T2, 3
        je              %%_AAD_blocks_3
        cmp             %%T2, 4
        je              %%_AAD_blocks_4
        cmp             %%T2, 5
        je              %%_AAD_blocks_5
        cmp             %%T2, 6
        je              %%_AAD_blocks_6
        cmp             %%T2, 7
        je              %%_AAD_blocks_7
        cmp             %%T2, 8
        je              %%_AAD_blocks_8
        cmp             %%T2, 9
        je              %%_AAD_blocks_9
        cmp             %%T2, 10
        je              %%_AAD_blocks_10
        cmp             %%T2, 11
        je              %%_AAD_blocks_11
        cmp             %%T2, 12
        je              %%_AAD_blocks_12
        cmp             %%T2, 13
        je              %%_AAD_blocks_13
        cmp             %%T2, 14
        je              %%_AAD_blocks_14
        cmp             %%T2, 15
        je              %%_AAD_blocks_15
        ;; fall through for 16 blocks

        ;; The flow of each of these cases is identical:
        ;; - load blocks plain text
        ;; - shuffle loaded blocks
        ;; - xor in current hash value into block 0
        ;; - perform up multiplications with ghash keys
        ;; - jump to reduction code

%%_AAD_blocks_16:
        ; Adjust address to range of byte64_len_to_mask_table
        sub             %%T3, (64 * 3 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3, [%%T1 + 64*2]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%T1 + 64*3]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        16, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_15:
        sub             %%T3, (64 * 3 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3, [%%T1 + 64*2]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%T1 + 64*3]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        15, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_14:
        sub             %%T3, (64 * 3 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3, [%%T1 + 64*2]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%T1 + 64*3]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        14, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_13:
        sub             %%T3, (64 * 3 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3, [%%T1 + 64*2]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%T1 + 64*3]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        vpshufb         %%ZT4, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        13, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_12:
        sub             %%T3, (64 * 2 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3{%%MASKREG}{z}, [%%T1 + 64*2]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, no_zmm, \
                        12, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_11:
        sub             %%T3, (64 * 2 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3{%%MASKREG}{z}, [%%T1 + 64*2]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, no_zmm, \
                        11, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_10:
        sub             %%T3, (64 * 2 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3{%%MASKREG}{z}, [%%T1 + 64*2]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, no_zmm, \
                        10, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_9:
        sub             %%T3, (64 * 2 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2, [%%T1 + 64*1]
        vmovdqu8        %%ZT3{%%MASKREG}{z}, [%%T1 + 64*2]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT3, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT5, %%ZT6, %%ZT7, %%ZT8, \
                        %%ZT9, %%ZT10, %%ZT11, %%ZT12, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, %%ZT3, no_zmm, \
                        9, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_8:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2{%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, no_zmm, no_zmm, \
                        8, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_7:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        %%ZT2{%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         %%ZT2, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, no_zmm, no_zmm, \
                        7, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_6:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        YWORD(%%ZT2){%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         YWORD(%%ZT2), YWORD(%%SHFMSK)
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, no_zmm, no_zmm, \
                        6, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_5:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1, [%%T1 + 64*0]
        vmovdqu8        XWORD(%%ZT2){%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT1, %%SHFMSK
        vpshufb         XWORD(%%ZT2), XWORD(%%SHFMSK)
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, %%ZT2, no_zmm, no_zmm, \
                        5, single_call
        jmp             %%_CALC_AAD_done


%%_AAD_blocks_4:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1{%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         %%ZT1, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, no_zmm, no_zmm, no_zmm, \
                        4, single_call
        jmp             %%_CALC_AAD_done

%%_AAD_blocks_3:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT1{%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         %%ZT1, %%SHFMSK
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, no_zmm, no_zmm, no_zmm, \
                        3, single_call
        jmp             %%_CALC_AAD_done


%%_AAD_blocks_2:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        YWORD(%%ZT1){%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         YWORD(%%ZT1), YWORD(%%SHFMSK)
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, no_zmm, no_zmm, no_zmm, \
                        2, single_call
        jmp             %%_CALC_AAD_done


%%_AAD_blocks_1:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        XWORD(%%ZT1){%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         XWORD(%%ZT1), XWORD(%%SHFMSK)
        GHASH_1_TO_16 %%GDATA_KEY, ZWORD(%%AAD_HASH), \
                        %%ZT0, %%ZT3, %%ZT4, %%ZT5, %%ZT6, \
                        %%ZT7, %%ZT8, %%ZT9, %%ZT10, \
                        ZWORD(%%AAD_HASH), %%ZT1, no_zmm, no_zmm, no_zmm, \
                        1, single_call
%%_CALC_AAD_done:
        ;; result in AAD_HASH

%endmacro ; CALC_AAD_HASH

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; PARTIAL_BLOCK
;;; Handles encryption/decryption and the tag partial blocks between
;;; update calls.
;;; Requires the input data be at least 1 byte long.
;;; Output:
;;; A cipher/plain of the first partial block (CYPH_PLAIN_OUT),
;;; AAD_HASH and updated GDATA_CTX
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PARTIAL_BLOCK 22
%define %%GDATA_KEY             %1 ; [in] key pointer
%define %%GDATA_CTX             %2 ; [in] context pointer
%define %%CYPH_PLAIN_OUT        %3 ; [in] output buffer
%define %%PLAIN_CYPH_IN         %4 ; [in] input buffer
%define %%PLAIN_CYPH_LEN        %5 ; [in] buffer length
%define %%DATA_OFFSET           %6 ; [in/out] data offset (gets updated)
%define %%AAD_HASH              %7 ; [out] updated GHASH value
%define %%ENC_DEC               %8 ; [in] cipher direction
%define %%GPTMP0                %9 ; [clobbered] GP temporary register
%define %%GPTMP1                %10 ; [clobbered] GP temporary register
%define %%GPTMP2                %11 ; [clobbered] GP temporary register
%define %%ZTMP0                 %12 ; [clobbered] ZMM temporary register
%define %%ZTMP1                 %13 ; [clobbered] ZMM temporary register
%define %%ZTMP2                 %14 ; [clobbered] ZMM temporary register
%define %%ZTMP3                 %15 ; [clobbered] ZMM temporary register
%define %%ZTMP4                 %16 ; [clobbered] ZMM temporary register
%define %%ZTMP5                 %17 ; [clobbered] ZMM temporary register
%define %%ZTMP6                 %18 ; [clobbered] ZMM temporary register
%define %%ZTMP7                 %19 ; [clobbered] ZMM temporary register
%define %%ZTMP8                 %20 ; [clobbered] ZMM temporary register
%define %%ZTMP9                 %21 ; [clobbered] ZMM temporary register
%define %%MASKREG               %22 ; [clobbered] mask temporary register

%define %%XTMP0 XWORD(%%ZTMP0)
%define %%XTMP1 XWORD(%%ZTMP1)
%define %%XTMP2 XWORD(%%ZTMP2)
%define %%XTMP3 XWORD(%%ZTMP3)
%define %%XTMP4 XWORD(%%ZTMP4)
%define %%XTMP5 XWORD(%%ZTMP5)
%define %%XTMP6 XWORD(%%ZTMP6)
%define %%XTMP7 XWORD(%%ZTMP7)
%define %%XTMP8 XWORD(%%ZTMP8)
%define %%XTMP9 XWORD(%%ZTMP9)

%define %%LENGTH        %%GPTMP0
%define %%IA0           %%GPTMP1
%define %%IA1           %%GPTMP2

        mov             %%LENGTH, [%%GDATA_CTX + PBlockLen]
        or              %%LENGTH, %%LENGTH
        je              %%_partial_block_done           ;Leave Macro if no partial blocks

        READ_SMALL_DATA_INPUT   %%XTMP0, %%PLAIN_CYPH_IN, %%PLAIN_CYPH_LEN, %%IA0, %%MASKREG

        ;; XTMP1 = my_ctx_data.partial_block_enc_key
        vmovdqu64       %%XTMP1, [%%GDATA_CTX + PBlockEncKey]
        vmovdqu64       %%XTMP2, [%%GDATA_KEY + HashKey]

        ;; adjust the shuffle mask pointer to be able to shift right %%LENGTH bytes
        ;; (16 - %%LENGTH) is the number of bytes in plaintext mod 16)
        lea             %%IA0, [rel SHIFT_MASK]
        add             %%IA0, %%LENGTH
        vmovdqu64       %%XTMP3, [%%IA0]   ; shift right shuffle mask
        vpshufb         %%XTMP1, %%XTMP3

%ifidn  %%ENC_DEC, DEC
        ;;  keep copy of cipher text in %%XTMP4
        vmovdqa64       %%XTMP4, %%XTMP0
%endif
        vpxorq          %%XTMP1, %%XTMP0      ; Cyphertext XOR E(K, Yn)

        ;; Set %%IA1 to be the amount of data left in CYPH_PLAIN_IN after filling the block
        ;; Determine if partial block is not being filled and shift mask accordingly
        mov             %%IA1, %%PLAIN_CYPH_LEN
        add             %%IA1, %%LENGTH
        sub             %%IA1, 16
        jge             %%_no_extra_mask
        sub             %%IA0, %%IA1
%%_no_extra_mask:
        ;; get the appropriate mask to mask out bottom %%LENGTH bytes of %%XTMP1
        ;; - mask out bottom %%LENGTH bytes of %%XTMP1
        vmovdqu64       %%XTMP0, [%%IA0 + ALL_F - SHIFT_MASK]
        vpand           %%XTMP1, %%XTMP0

%ifidn  %%ENC_DEC, DEC
        vpand           %%XTMP4, %%XTMP0
        vpshufb         %%XTMP4, [rel SHUF_MASK]
        vpshufb         %%XTMP4, %%XTMP3
        vpxorq          %%AAD_HASH, %%XTMP4
%else
        vpshufb         %%XTMP1, [rel SHUF_MASK]
        vpshufb         %%XTMP1, %%XTMP3
        vpxorq          %%AAD_HASH, %%XTMP1
%endif
        cmp             %%IA1, 0
        jl              %%_partial_incomplete

        ;; GHASH computation for the last <16 Byte block
        GHASH_MUL       %%AAD_HASH, %%XTMP2, %%XTMP5, %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9

        mov             qword [%%GDATA_CTX + PBlockLen], 0

        ;;  Set %%IA1 to be the number of bytes to write out
        mov             %%IA0, %%LENGTH
        mov             %%LENGTH, 16
        sub             %%LENGTH, %%IA0
        jmp             %%_enc_dec_done

%%_partial_incomplete:
%ifidn __OUTPUT_FORMAT__, win64
        mov             %%IA0, %%PLAIN_CYPH_LEN
        add             [%%GDATA_CTX + PBlockLen], %%IA0
%else
        add             [%%GDATA_CTX + PBlockLen], %%PLAIN_CYPH_LEN
%endif
        mov             %%LENGTH, %%PLAIN_CYPH_LEN

%%_enc_dec_done:
        ;; output encrypted Bytes

        lea             %%IA0, [rel byte_len_to_mask_table]
        kmovw           %%MASKREG, [%%IA0 + %%LENGTH*2]
        vmovdqu64       [%%GDATA_CTX + AadHash], %%AAD_HASH

%ifidn  %%ENC_DEC, ENC
        ;; shuffle XTMP1 back to output as ciphertext
        vpshufb         %%XTMP1, [rel SHUF_MASK]
        vpshufb         %%XTMP1, %%XTMP3
%endif
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{%%MASKREG}, %%XTMP1
        add             %%DATA_OFFSET, %%LENGTH
%%_partial_block_done:
%endmacro ; PARTIAL_BLOCK


%macro GHASH_SINGLE_MUL 9
%define %%GDATA                 %1
%define %%HASHKEY               %2
%define %%CIPHER                %3
%define %%STATE_11              %4
%define %%STATE_00              %5
%define %%STATE_MID             %6
%define %%T1                    %7
%define %%T2                    %8
%define %%FIRST                 %9

        vmovdqu         %%T1, [%%GDATA + %%HASHKEY]
%ifidn %%FIRST, first
        vpclmulqdq      %%STATE_11, %%CIPHER, %%T1, 0x11         ; %%T4 = a1*b1
        vpclmulqdq      %%STATE_00, %%CIPHER, %%T1, 0x00         ; %%T4_2 = a0*b0
        vpclmulqdq      %%STATE_MID, %%CIPHER, %%T1, 0x01        ; %%T6 = a1*b0
        vpclmulqdq      %%T2, %%CIPHER, %%T1, 0x10               ; %%T5 = a0*b1
        vpxor           %%STATE_MID, %%STATE_MID, %%T2
%else
        vpclmulqdq      %%T2, %%CIPHER, %%T1, 0x11
        vpxor           %%STATE_11, %%STATE_11, %%T2

        vpclmulqdq      %%T2, %%CIPHER, %%T1, 0x00
        vpxor           %%STATE_00, %%STATE_00, %%T2

        vpclmulqdq      %%T2, %%CIPHER, %%T1, 0x01
        vpxor           %%STATE_MID, %%STATE_MID, %%T2

        vpclmulqdq      %%T2, %%CIPHER, %%T1, 0x10
        vpxor           %%STATE_MID, %%STATE_MID, %%T2
%endif

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%macro INITIAL_BLOCKS_PARTIAL_CIPHER 25
%define %%GDATA_KEY             %1  ; [in] key pointer
%define %%GDATA_CTX             %2  ; [in] context pointer
%define %%CYPH_PLAIN_OUT        %3  ; [in] text output pointer
%define %%PLAIN_CYPH_IN         %4  ; [in] text input pointer
%define %%LENGTH                %5  ; [in/clobbered] length in bytes
%define %%DATA_OFFSET           %6  ; [in/out] current data offset (updated)
%define %%NUM_BLOCKS            %7  ; [in] can only be 1, 2, 3, 4, 5, ..., 15 or 16 (not 0)
%define %%CTR                   %8  ; [in/out] current counter value
%define %%ENC_DEC               %9  ; [in] cipher direction (ENC/DEC)
%define %%INSTANCE_TYPE         %10 ; [in] multi_call or single_call
%define %%DAT0                  %11 ; [out] ZMM with cipher text shuffled for GHASH
%define %%DAT1                  %12 ; [out] ZMM with cipher text shuffled for GHASH
%define %%DAT2                  %13 ; [out] ZMM with cipher text shuffled for GHASH
%define %%DAT3                  %14 ; [out] ZMM with cipher text shuffled for GHASH
%define %%LAST_CIPHER_BLK       %15 ; [out] XMM to put ciphered counter block partially xor'ed with text
%define %%LAST_GHASH_BLK        %16 ; [out] XMM to put last cipher text block shuffled for GHASH
%define %%CTR0                  %17 ; [clobbered] ZMM temporary
%define %%CTR1                  %18 ; [clobbered] ZMM temporary
%define %%CTR2                  %19 ; [clobbered] ZMM temporary
%define %%CTR3                  %20 ; [clobbered] ZMM temporary
%define %%ZT1                   %21 ; [clobbered] ZMM temporary
%define %%IA0                   %22 ; [clobbered] GP temporary
%define %%IA1                   %23 ; [clobbered] GP temporary
%define %%MASKREG               %24 ; [clobbered] mask register
%define %%SHUFMASK              %25 ; [in] ZMM with BE/LE shuffle mask

        ;; prepare AES counter blocks
%if %%NUM_BLOCKS == 1
        vpaddd          XWORD(%%CTR0), %%CTR, [rel ONE]
%elif %%NUM_BLOCKS == 2
        vshufi64x2      YWORD(%%CTR0), YWORD(%%CTR), YWORD(%%CTR), 0
        vpaddd          YWORD(%%CTR0), YWORD(%%CTR0), [rel ddq_add_1234]
%else
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        vpaddd          %%CTR0, ZWORD(%%CTR), [rel ddq_add_1234]
%if %%NUM_BLOCKS > 4
        vpaddd          %%CTR1, ZWORD(%%CTR), [rel ddq_add_5678]
%endif
%if %%NUM_BLOCKS > 8
        vpaddd          %%CTR2, %%CTR0, [rel ddq_add_8888]
%endif
%if %%NUM_BLOCKS > 12
        vpaddd          %%CTR3, %%CTR1, [rel ddq_add_8888]
%endif
%endif

        ;; get load/store mask
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
%if %%NUM_BLOCKS > 12
        sub             %%IA1, 3 * 64
%elif %%NUM_BLOCKS > 8
        sub             %%IA1, 2 * 64
%elif %%NUM_BLOCKS > 4
        sub             %%IA1, 64
%endif
        kmovq           %%MASKREG, [%%IA0 + %%IA1*8]

        ;; extract new counter value
        ;; shuffle the counters for AES rounds
%if %%NUM_BLOCKS <= 4
        vextracti32x4   %%CTR, %%CTR0, (%%NUM_BLOCKS - 1)
%elif %%NUM_BLOCKS <= 8
        vextracti32x4   %%CTR, %%CTR1, (%%NUM_BLOCKS - 5)
%elif %%NUM_BLOCKS <= 12
        vextracti32x4   %%CTR, %%CTR2, (%%NUM_BLOCKS - 9)
%else
        vextracti32x4   %%CTR, %%CTR3, (%%NUM_BLOCKS - 13)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUM_BLOCKS, vpshufb, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%SHUFMASK, %%SHUFMASK, %%SHUFMASK, %%SHUFMASK

        ;; load plain/cipher text
       ZMM_LOAD_MASKED_BLOCKS_0_16 %%NUM_BLOCKS, %%PLAIN_CYPH_IN, %%DATA_OFFSET, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, %%MASKREG

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (NROUNDS + 2)
        vbroadcastf64x2 %%ZT1, [%%GDATA_KEY + (j * 16)]
        ZMM_AESENC_ROUND_BLOCKS_0_16 %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%ZT1, j, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%NUM_BLOCKS, NROUNDS
%assign j (j + 1)
%endrep

%ifidn %%INSTANCE_TYPE, multi_call
        ;; retrieve the last cipher counter block (partially XOR'ed with text)
        ;; - this is needed for partial block cases
%if %%NUM_BLOCKS <= 4
        vextracti32x4   %%LAST_CIPHER_BLK, %%CTR0, (%%NUM_BLOCKS - 1)
%elif %%NUM_BLOCKS <= 8
        vextracti32x4   %%LAST_CIPHER_BLK, %%CTR1, (%%NUM_BLOCKS - 5)
%elif %%NUM_BLOCKS <= 12
        vextracti32x4   %%LAST_CIPHER_BLK, %%CTR2, (%%NUM_BLOCKS - 9)
%else
        vextracti32x4   %%LAST_CIPHER_BLK, %%CTR3, (%%NUM_BLOCKS - 13)
%endif
%endif
        ;; write cipher/plain text back to output and
        ZMM_STORE_MASKED_BLOCKS_0_16 %%NUM_BLOCKS, %%CYPH_PLAIN_OUT, %%DATA_OFFSET, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, %%MASKREG

        ;; zero bytes outside the mask before hashing
%if %%NUM_BLOCKS <= 4
        vmovdqu8        %%CTR0{%%MASKREG}{z}, %%CTR0
%elif %%NUM_BLOCKS <= 8
        vmovdqu8        %%CTR1{%%MASKREG}{z}, %%CTR1
%elif %%NUM_BLOCKS <= 12
        vmovdqu8        %%CTR2{%%MASKREG}{z}, %%CTR2
%else
        vmovdqu8        %%CTR3{%%MASKREG}{z}, %%CTR3
%endif

        ;; Shuffle the cipher text blocks for hashing part
        ;; ZT5 and ZT6 are expected outputs with blocks for hashing
%ifidn  %%ENC_DEC, DEC
        ;; Decrypt case
        ;; - cipher blocks are in ZT5 & ZT6
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUM_BLOCKS, vpshufb, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%SHUFMASK, %%SHUFMASK, %%SHUFMASK, %%SHUFMASK
%else
        ;; Encrypt case
        ;; - cipher blocks are in CTR0-CTR3
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUM_BLOCKS, vpshufb, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%SHUFMASK, %%SHUFMASK, %%SHUFMASK, %%SHUFMASK
%endif                          ; Encrypt

%ifidn %%INSTANCE_TYPE, multi_call
        ;; Extract the last block for partials and multi_call cases
%if %%NUM_BLOCKS <= 4
        vextracti32x4   %%LAST_GHASH_BLK, %%DAT0, %%NUM_BLOCKS - 1
%elif %%NUM_BLOCKS <= 8
        vextracti32x4   %%LAST_GHASH_BLK, %%DAT1, %%NUM_BLOCKS - 5
%elif %%NUM_BLOCKS <= 12
        vextracti32x4   %%LAST_GHASH_BLK, %%DAT2, %%NUM_BLOCKS - 9
%else
        vextracti32x4   %%LAST_GHASH_BLK, %%DAT3, %%NUM_BLOCKS - 13
%endif
%endif

%endmacro                       ; INITIAL_BLOCKS_PARTIAL_CIPHER

%macro INITIAL_BLOCKS_PARTIAL_GHASH 23
%define %%GDATA_KEY             %1  ; [in] key pointer
%define %%GDATA_CTX             %2  ; [in] context pointer
%define %%LENGTH                %3  ; [in/clobbered] length in bytes
%define %%DATA_OFFSET           %4  ; [in/out] current data offset (updated)
%define %%NUM_BLOCKS            %5  ; [in] can only be 1, 2, 3, 4, 5, ..., 15 or 16 (not 0)
%define %%HASH_IN_OUT           %6  ; [in/out] XMM ghash in/out value
%define %%ENC_DEC               %7  ; [in] cipher direction (ENC/DEC)
%define %%INSTANCE_TYPE         %8  ; [in] multi_call or single_call
%define %%DAT0                  %9  ; [in] ZMM with cipher text shuffled for GHASH
%define %%DAT1                  %10 ; [in] ZMM with cipher text shuffled for GHASH
%define %%DAT2                  %11 ; [in] ZMM with cipher text shuffled for GHASH
%define %%DAT3                  %12 ; [in] ZMM with cipher text shuffled for GHASH
%define %%LAST_CIPHER_BLK       %13 ; [in] XMM with ciphered counter block partially xor'ed with text
%define %%LAST_GHASH_BLK        %14 ; [in] XMM with last cipher text block shuffled for GHASH
%define %%ZT0                   %15 ; [clobbered] ZMM temporary
%define %%ZT1                   %16 ; [clobbered] ZMM temporary
%define %%ZT2                   %17 ; [clobbered] ZMM temporary
%define %%ZT3                   %18 ; [clobbered] ZMM temporary
%define %%ZT4                   %19 ; [clobbered] ZMM temporary
%define %%ZT5                   %20 ; [clobbered] ZMM temporary
%define %%ZT6                   %21 ; [clobbered] ZMM temporary
%define %%ZT7                   %22 ; [clobbered] ZMM temporary
%define %%ZT8                   %23 ; [clobbered] ZMM temporary

%ifidn %%INSTANCE_TYPE, single_call

       GHASH_1_TO_16 %%GDATA_KEY, %%HASH_IN_OUT, \
                        %%ZT0, %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, ZWORD(%%HASH_IN_OUT), \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%NUM_BLOCKS, single_call

%else

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Hash all but the last block of data
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;; update data offset
%if %%NUM_BLOCKS > 1
        ;; The final block of data may be <16B
        add     %%DATA_OFFSET, 16 * (%%NUM_BLOCKS - 1)
        sub     %%LENGTH, 16 * (%%NUM_BLOCKS - 1)
%endif

%if %%NUM_BLOCKS < 16
        ;; NOTE: the 'jl' is always taken for num_initial_blocks = 16.
        ;;      This is run in the context of GCM_ENC_DEC_SMALL for length < 256.
        cmp     %%LENGTH, 16
        jl      %%_small_initial_partial_block

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Handle a full length final block - encrypt and hash all blocks
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        sub     %%LENGTH, 16
        add     %%DATA_OFFSET, 16
        mov     [%%GDATA_CTX + PBlockLen], %%LENGTH

        ;; Hash all of the data
        GHASH_1_TO_16 %%GDATA_KEY, %%HASH_IN_OUT, \
                        %%ZT0, %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, ZWORD(%%HASH_IN_OUT), \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%NUM_BLOCKS, single_call

        jmp             %%_small_initial_compute_done
%endif                          ; %if %%NUM_BLOCKS < 16

%%_small_initial_partial_block:

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Handle ghash for a <16B final block
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;; In this case if it's a single call to encrypt we can
        ;; hash all of the data but if it's an init / update / finalize
        ;; series of call we need to leave the last block if it's
        ;; less than a full block of data.

        mov             [%%GDATA_CTX + PBlockLen], %%LENGTH
        vmovdqu64       [%%GDATA_CTX + PBlockEncKey], %%LAST_CIPHER_BLK

%assign k (%%NUM_BLOCKS - 1)
%assign last_block_to_hash 1

%if (%%NUM_BLOCKS > last_block_to_hash)

        ;; ZT12-ZT20 - temporary registers
        GHASH_1_TO_16 %%GDATA_KEY, %%HASH_IN_OUT, \
                        %%ZT0, %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, ZWORD(%%HASH_IN_OUT), \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        k, single_call

        ;; just fall through no jmp needed
%else
        ;; Record that a reduction is not needed -
        ;; In this case no hashes are computed because there
        ;; is only one initial block and it is < 16B in length.
        ;; We only need to check if a reduction is needed if
        ;; initial_blocks == 1 and init/update/final is being used.
        ;; In this case we may just have a partial block, and that
        ;; gets hashed in finalize.

        ;; The hash should end up in HASH_IN_OUT.
        ;; The only way we should get here is if there is
        ;; a partial block of data, so xor that into the hash.
        vpxorq          %%HASH_IN_OUT, %%HASH_IN_OUT, %%LAST_GHASH_BLK
        ;; The result is in %%HASH_IN_OUT
        jmp             %%_after_reduction
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; After GHASH reduction
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_small_initial_compute_done:
        ;; If using init/update/finalize, we need to xor any partial block data
        ;; into the hash.
%if %%NUM_BLOCKS > 1
        ;; NOTE: for %%NUM_BLOCKS = 0 the xor never takes place
%if %%NUM_BLOCKS != 16
        ;; NOTE: for %%NUM_BLOCKS = 16, %%LENGTH, stored in [PBlockLen] is never zero
        or              %%LENGTH, %%LENGTH
        je              %%_after_reduction
%endif                          ; %%NUM_BLOCKS != 16
        vpxorq          %%HASH_IN_OUT, %%HASH_IN_OUT, %%LAST_GHASH_BLK
%endif                          ; %%NUM_BLOCKS > 1

%%_after_reduction:

%endif                          ; %%INSTANCE_TYPE, multi_call

        ;; Final hash is now in HASH_IN_OUT

%endmacro                       ; INITIAL_BLOCKS_PARTIAL_GHASH


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; INITIAL_BLOCKS_PARTIAL macro with support for a partial final block.
;;; It may look similar to INITIAL_BLOCKS but its usage is different:
;;; - first encrypts/decrypts required number of blocks and then
;;;   ghashes these blocks
;;; - Small packets or left over data chunks (<256 bytes)
;;;     - single or multi call
;;; - Remaining data chunks below 256 bytes (multi buffer code)
;;;
;;; num_initial_blocks is expected to include the partial final block
;;; in the count.
%macro INITIAL_BLOCKS_PARTIAL 30
%define %%GDATA_KEY             %1  ; [in] key pointer
%define %%GDATA_CTX             %2  ; [in] context pointer
%define %%CYPH_PLAIN_OUT        %3  ; [in] text output pointer
%define %%PLAIN_CYPH_IN         %4  ; [in] text input pointer
%define %%LENGTH                %5  ; [in/clobbered] length in bytes
%define %%DATA_OFFSET           %6  ; [in/out] current data offset (updated)
%define %%NUM_BLOCKS            %7  ; [in] can only be 1, 2, 3, 4, 5, ..., 15 or 16 (not 0)
%define %%CTR                   %8  ; [in/out] current counter value
%define %%HASH_IN_OUT           %9  ; [in/out] XMM ghash in/out value
%define %%ENC_DEC               %10 ; [in] cipher direction (ENC/DEC)
%define %%INSTANCE_TYPE         %11 ; [in] multi_call or single_call
%define %%CTR0                  %12 ; [clobbered] ZMM temporary
%define %%CTR1                  %13 ; [clobbered] ZMM temporary
%define %%CTR2                  %14 ; [clobbered] ZMM temporary
%define %%CTR3                  %15 ; [clobbered] ZMM temporary
%define %%DAT0                  %16 ; [clobbered] ZMM temporary
%define %%DAT1                  %17 ; [clobbered] ZMM temporary
%define %%DAT2                  %18 ; [clobbered] ZMM temporary
%define %%DAT3                  %19 ; [clobbered] ZMM temporary
%define %%LAST_CIPHER_BLK       %20 ; [clobbered] ZMM temporary
%define %%LAST_GHASH_BLK        %21 ; [clobbered] ZMM temporary
%define %%ZT0                   %22 ; [clobbered] ZMM temporary
%define %%ZT1                   %23 ; [clobbered] ZMM temporary
%define %%ZT2                   %24 ; [clobbered] ZMM temporary
%define %%ZT3                   %25 ; [clobbered] ZMM temporary
%define %%ZT4                   %26 ; [clobbered] ZMM temporary
%define %%IA0                   %27 ; [clobbered] GP temporary
%define %%IA1                   %28 ; [clobbered] GP temporary
%define %%MASKREG               %29 ; [clobbered] mask register
%define %%SHUFMASK              %30 ; [in] ZMM with BE/LE shuffle mask

        INITIAL_BLOCKS_PARTIAL_CIPHER \
                        %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                        %%LENGTH, %%DATA_OFFSET, %%NUM_BLOCKS, %%CTR, \
                        %%ENC_DEC, %%INSTANCE_TYPE, %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        XWORD(%%LAST_CIPHER_BLK), XWORD(%%LAST_GHASH_BLK), \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, %%ZT0, \
                        %%IA0, %%IA1, %%MASKREG, %%SHUFMASK

        INITIAL_BLOCKS_PARTIAL_GHASH \
                        %%GDATA_KEY, %%GDATA_CTX, %%LENGTH, %%DATA_OFFSET, \
                        %%NUM_BLOCKS, %%HASH_IN_OUT, %%ENC_DEC, \
                        %%INSTANCE_TYPE, %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        XWORD(%%LAST_CIPHER_BLK), XWORD(%%LAST_GHASH_BLK), \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, %%ZT0, %%ZT1, \
                        %%ZT2, %%ZT3, %%ZT4

%endmacro                       ; INITIAL_BLOCKS_PARTIAL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Main GCM macro stitching cipher with GHASH
;;; - operates on single stream
;;; - encrypts 16 blocks at a time
;;; - ghash the 16 previously encrypted ciphertext blocks
;;; - no partial block or multi_call handling here
%macro  GHASH_16_ENCRYPT_16_PARALLEL 42
%define %%GDATA                 %1  ; [in] key pointer
%define %%CYPH_PLAIN_OUT        %2  ; [in] pointer to output buffer
%define %%PLAIN_CYPH_IN         %3  ; [in] pointer to input buffer
%define %%DATA_OFFSET           %4  ; [in] data offset
%define %%CTR_BE                %5  ; [in/out] ZMM counter blocks (last 4) in big-endian
%define %%CTR_CHECK             %6  ; [in/out] GP with 8-bit counter for overflow check
%define %%HASHKEY_OFFSET        %7  ; [in] numerical offset for the highest hash key
%define %%AESOUT_BLK_OFFSET     %8  ; [in] numerical offset for AES-CTR out
%define %%GHASHIN_BLK_OFFSET    %9  ; [in] numerical offset for GHASH blocks in
%define %%SHFMSK                %10 ; [in] ZMM with byte swap mask for pshufb
%define %%ZT1                   %11 ; [clobbered] temporary ZMM (cipher)
%define %%ZT2                   %12 ; [clobbered] temporary ZMM (cipher)
%define %%ZT3                   %13 ; [clobbered] temporary ZMM (cipher)
%define %%ZT4                   %14 ; [clobbered] temporary ZMM (cipher)
%define %%ZT5                   %15 ; [clobbered/out] temporary ZMM or GHASH OUT (final_reduction)
%define %%ZT6                   %16 ; [clobbered] temporary ZMM (cipher)
%define %%ZT7                   %17 ; [clobbered] temporary ZMM (cipher)
%define %%ZT8                   %18 ; [clobbered] temporary ZMM (cipher)
%define %%ZT9                   %19 ; [clobbered] temporary ZMM (cipher)
%define %%ZT10                  %20 ; [clobbered] temporary ZMM (ghash)
%define %%ZT11                  %21 ; [clobbered] temporary ZMM (ghash)
%define %%ZT12                  %22 ; [clobbered] temporary ZMM (ghash)
%define %%ZT13                  %23 ; [clobbered] temporary ZMM (ghash)
%define %%ZT14                  %24 ; [clobbered] temporary ZMM (ghash)
%define %%ZT15                  %25 ; [clobbered] temporary ZMM (ghash)
%define %%ZT16                  %26 ; [clobbered] temporary ZMM (ghash)
%define %%ZT17                  %27 ; [clobbered] temporary ZMM (ghash)
%define %%ZT18                  %28 ; [clobbered] temporary ZMM (ghash)
%define %%ZT19                  %29 ; [clobbered] temporary ZMM
%define %%ZT20                  %30 ; [clobbered] temporary ZMM
%define %%ZT21                  %31 ; [clobbered] temporary ZMM
%define %%ZT22                  %32 ; [clobbered] temporary ZMM
%define %%ZT23                  %33 ; [clobbered] temporary ZMM
%define %%ADDBE_4x4             %34 ; [in] ZMM with 4x128bits 4 in big-endian
%define %%ADDBE_1234            %35 ; [in] ZMM with 4x128bits 1, 2, 3 and 4 in big-endian
%define %%TO_REDUCE_L           %36 ; [in/out] ZMM for low 4x128-bit GHASH sum
%define %%TO_REDUCE_H           %37 ; [in/out] ZMM for hi 4x128-bit GHASH sum
%define %%TO_REDUCE_M           %38 ; [in/out] ZMM for medium 4x128-bit GHASH sum
%define %%DO_REDUCTION          %39 ; [in] "no_reduction", "final_reduction", "first_time"
%define %%ENC_DEC               %40 ; [in] cipher direction
%define %%DATA_DISPL            %41 ; [in] fixed numerical data displacement/offset
%define %%GHASH_IN              %42 ; [in] current GHASH value or "no_ghash_in"

%define %%B00_03 %%ZT1
%define %%B04_07 %%ZT2
%define %%B08_11 %%ZT3
%define %%B12_15 %%ZT4

%define %%GH1H  %%ZT5 ; @note: do not change this mapping
%define %%GH1L  %%ZT6
%define %%GH1M  %%ZT7
%define %%GH1T  %%ZT8

%define %%GH2H  %%ZT9
%define %%GH2L  %%ZT10
%define %%GH2M  %%ZT11
%define %%GH2T  %%ZT12

%define %%RED_POLY %%GH2T
%define %%RED_P1   %%GH2L
%define %%RED_T1   %%GH2H
%define %%RED_T2   %%GH2M

%define %%GH3H  %%ZT13
%define %%GH3L  %%ZT14
%define %%GH3M  %%ZT15
%define %%GH3T  %%ZT16

%define %%DATA1 %%ZT13
%define %%DATA2 %%ZT14
%define %%DATA3 %%ZT15
%define %%DATA4 %%ZT16

%define %%AESKEY1  %%ZT17
%define %%AESKEY2  %%ZT18

%define %%GHKEY1  %%ZT19
%define %%GHKEY2  %%ZT20
%define %%GHDAT1  %%ZT21
%define %%GHDAT2  %%ZT22

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; prepare counter blocks

        cmp             BYTE(%%CTR_CHECK), (256 - 16)
        jae             %%_16_blocks_overflow
        vpaddd          %%B00_03, %%CTR_BE, %%ADDBE_1234
        vpaddd          %%B04_07, %%B00_03, %%ADDBE_4x4
        vpaddd          %%B08_11, %%B04_07, %%ADDBE_4x4
        vpaddd          %%B12_15, %%B08_11, %%ADDBE_4x4
        jmp             %%_16_blocks_ok
%%_16_blocks_overflow:
        vpshufb         %%CTR_BE, %%CTR_BE, %%SHFMSK
        vmovdqa64       %%B12_15, [rel ddq_add_4444]
        vpaddd          %%B00_03, %%CTR_BE, [rel ddq_add_1234]
        vpaddd          %%B04_07, %%B00_03, %%B12_15
        vpaddd          %%B08_11, %%B04_07, %%B12_15
        vpaddd          %%B12_15, %%B08_11, %%B12_15
        vpshufb         %%B00_03, %%SHFMSK
        vpshufb         %%B04_07, %%SHFMSK
        vpshufb         %%B08_11, %%SHFMSK
        vpshufb         %%B12_15, %%SHFMSK
%%_16_blocks_ok:

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; pre-load constants
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 0)]
%ifnidn %%GHASH_IN, no_ghash_in
        vpxorq          %%GHDAT1, %%GHASH_IN, [rsp + %%GHASHIN_BLK_OFFSET + (0*64)]
%else
        vmovdqa64       %%GHDAT1, [rsp + %%GHASHIN_BLK_OFFSET + (0*64)]
%endif
        vmovdqu64       %%GHKEY1, [%%GDATA + %%HASHKEY_OFFSET + (0*64)]

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; save counter for the next round
        ;; increment counter overflow check register
        vshufi64x2      %%CTR_BE, %%B12_15, %%B12_15, 1111_1111b
        add             BYTE(%%CTR_CHECK), 16

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; pre-load constants
        vbroadcastf64x2 %%AESKEY2, [%%GDATA + (16 * 1)]
        vmovdqu64       %%GHKEY2, [%%GDATA + %%HASHKEY_OFFSET + (1*64)]
        vmovdqa64       %%GHDAT2, [rsp + %%GHASHIN_BLK_OFFSET + (1*64)]

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; stitch AES rounds with GHASH

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES round 0 - ARK

        vpxorq          %%B00_03, %%AESKEY1
        vpxorq          %%B04_07, %%AESKEY1
        vpxorq          %%B08_11, %%AESKEY1
        vpxorq          %%B12_15, %%AESKEY1
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 2)]

        ;;==================================================
        ;; GHASH 4 blocks (15 to 12)
        vpclmulqdq      %%GH1H, %%GHDAT1, %%GHKEY1, 0x11     ; a1*b1
        vpclmulqdq      %%GH1L, %%GHDAT1, %%GHKEY1, 0x00     ; a0*b0
        vpclmulqdq      %%GH1M, %%GHDAT1, %%GHKEY1, 0x01     ; a1*b0
        vpclmulqdq      %%GH1T, %%GHDAT1, %%GHKEY1, 0x10     ; a0*b1

        vmovdqu64       %%GHKEY1, [%%GDATA + %%HASHKEY_OFFSET + (2*64)]
        vmovdqa64       %%GHDAT1, [rsp + %%GHASHIN_BLK_OFFSET + (2*64)]

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES round 1
        vaesenc         %%B00_03, %%B00_03, %%AESKEY2
        vaesenc         %%B04_07, %%B04_07, %%AESKEY2
        vaesenc         %%B08_11, %%B08_11, %%AESKEY2
        vaesenc         %%B12_15, %%B12_15, %%AESKEY2
        vbroadcastf64x2 %%AESKEY2, [%%GDATA + (16 * 3)]

        ;; =================================================
        ;; GHASH 4 blocks (11 to 8)
        vpclmulqdq      %%GH2M, %%GHDAT2, %%GHKEY2, 0x10     ; a0*b1
        vpclmulqdq      %%GH2T, %%GHDAT2, %%GHKEY2, 0x01     ; a1*b0
        vpclmulqdq      %%GH2H, %%GHDAT2, %%GHKEY2, 0x11     ; a1*b1
        vpclmulqdq      %%GH2L, %%GHDAT2, %%GHKEY2, 0x00     ; a0*b0

        vmovdqu64       %%GHKEY2, [%%GDATA + %%HASHKEY_OFFSET + (3*64)]
        vmovdqa64       %%GHDAT2, [rsp + %%GHASHIN_BLK_OFFSET + (3*64)]

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES round 2
        vaesenc         %%B00_03, %%B00_03, %%AESKEY1
        vaesenc         %%B04_07, %%B04_07, %%AESKEY1
        vaesenc         %%B08_11, %%B08_11, %%AESKEY1
        vaesenc         %%B12_15, %%B12_15, %%AESKEY1
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 4)]

        ;; =================================================
        ;; GHASH 4 blocks (7 to 4)
        vpclmulqdq      %%GH3M, %%GHDAT1, %%GHKEY1, 0x10     ; a0*b1
        vpclmulqdq      %%GH3T, %%GHDAT1, %%GHKEY1, 0x01     ; a1*b0
        vpclmulqdq      %%GH3H, %%GHDAT1, %%GHKEY1, 0x11     ; a1*b1
        vpclmulqdq      %%GH3L, %%GHDAT1, %%GHKEY1, 0x00     ; a0*b0

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES rounds 3
        vaesenc         %%B00_03, %%B00_03, %%AESKEY2
        vaesenc         %%B04_07, %%B04_07, %%AESKEY2
        vaesenc         %%B08_11, %%B08_11, %%AESKEY2
        vaesenc         %%B12_15, %%B12_15, %%AESKEY2
        vbroadcastf64x2 %%AESKEY2, [%%GDATA + (16 * 5)]

        ;; =================================================
        ;; Gather (XOR) GHASH for 12 blocks
        vpternlogq      %%GH1H, %%GH2H, %%GH3H, 0x96
        vpternlogq      %%GH1L, %%GH2L, %%GH3L, 0x96
        vpternlogq      %%GH1T, %%GH2T, %%GH3T, 0x96
        vpternlogq      %%GH1M, %%GH2M, %%GH3M, 0x96

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES rounds 4
        vaesenc         %%B00_03, %%B00_03, %%AESKEY1
        vaesenc         %%B04_07, %%B04_07, %%AESKEY1
        vaesenc         %%B08_11, %%B08_11, %%AESKEY1
        vaesenc         %%B12_15, %%B12_15, %%AESKEY1
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 6)]

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; load plain/cipher text (recycle GH3xx registers)
        VX512LDR        %%DATA1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + %%DATA_DISPL + (0 * 64)]
        VX512LDR        %%DATA2, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + %%DATA_DISPL + (1 * 64)]
        VX512LDR        %%DATA3, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + %%DATA_DISPL + (2 * 64)]
        VX512LDR        %%DATA4, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + %%DATA_DISPL + (3 * 64)]

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES rounds 5
        vaesenc         %%B00_03, %%B00_03, %%AESKEY2
        vaesenc         %%B04_07, %%B04_07, %%AESKEY2
        vaesenc         %%B08_11, %%B08_11, %%AESKEY2
        vaesenc         %%B12_15, %%B12_15, %%AESKEY2
        vbroadcastf64x2 %%AESKEY2, [%%GDATA + (16 * 7)]

        ;; =================================================
        ;; GHASH 4 blocks (3 to 0)
        vpclmulqdq      %%GH2M, %%GHDAT2, %%GHKEY2, 0x10     ; a0*b1
        vpclmulqdq      %%GH2T, %%GHDAT2, %%GHKEY2, 0x01     ; a1*b0
        vpclmulqdq      %%GH2H, %%GHDAT2, %%GHKEY2, 0x11     ; a1*b1
        vpclmulqdq      %%GH2L, %%GHDAT2, %%GHKEY2, 0x00     ; a0*b0

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES round 6
        vaesenc         %%B00_03, %%B00_03, %%AESKEY1
        vaesenc         %%B04_07, %%B04_07, %%AESKEY1
        vaesenc         %%B08_11, %%B08_11, %%AESKEY1
        vaesenc         %%B12_15, %%B12_15, %%AESKEY1
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 8)]

        ;; =================================================
        ;; gather GHASH in GH1L (low) and GH1H (high)
%ifidn %%DO_REDUCTION, first_time
        vpternlogq      %%GH1M, %%GH1T, %%GH2T, 0x96        ; TM
        vpxorq          %%TO_REDUCE_M, %%GH1M, %%GH2M       ; TM
        vpxorq          %%TO_REDUCE_H, %%GH1H, %%GH2H       ; TH
        vpxorq          %%TO_REDUCE_L, %%GH1L, %%GH2L       ; TL
%endif
%ifidn %%DO_REDUCTION, no_reduction
        vpternlogq      %%GH1M, %%GH1T, %%GH2T, 0x96        ; TM
        vpternlogq      %%TO_REDUCE_M, %%GH1M, %%GH2M, 0x96 ; TM
        vpternlogq      %%TO_REDUCE_H, %%GH1H, %%GH2H, 0x96 ; TH
        vpternlogq      %%TO_REDUCE_L, %%GH1L, %%GH2L, 0x96 ; TL
%endif
%ifidn %%DO_REDUCTION, final_reduction
        ;; phase 1: add mid products together
        ;; also load polynomial constant for reduction
        vpternlogq      %%GH1M, %%GH1T, %%GH2T, 0x96 ; TM
        vpternlogq      %%GH1M, %%TO_REDUCE_M, %%GH2M, 0x96

        vpsrldq         %%GH2M, %%GH1M, 8
        vpslldq         %%GH1M, %%GH1M, 8

        vmovdqa64       XWORD(%%RED_POLY), [rel POLY2]
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES round 7
        vaesenc         %%B00_03, %%B00_03, %%AESKEY2
        vaesenc         %%B04_07, %%B04_07, %%AESKEY2
        vaesenc         %%B08_11, %%B08_11, %%AESKEY2
        vaesenc         %%B12_15, %%B12_15, %%AESKEY2
        vbroadcastf64x2 %%AESKEY2, [%%GDATA + (16 * 9)]

        ;; =================================================
        ;; Add mid product to high and low
%ifidn %%DO_REDUCTION, final_reduction
        vpternlogq      %%GH1H, %%GH2H, %%GH2M, 0x96    ; TH = TH1 + TH2 + TM>>64
        vpxorq          %%GH1H, %%TO_REDUCE_H
        vpternlogq      %%GH1L, %%GH2L, %%GH1M, 0x96    ; TL = TL1 + TL2 + TM<<64
        vpxorq          %%GH1L, %%TO_REDUCE_L
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES round 8
        vaesenc         %%B00_03, %%B00_03, %%AESKEY1
        vaesenc         %%B04_07, %%B04_07, %%AESKEY1
        vaesenc         %%B08_11, %%B08_11, %%AESKEY1
        vaesenc         %%B12_15, %%B12_15, %%AESKEY1
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 10)]

        ;; =================================================
        ;; horizontal xor of low and high 4x128
%ifidn %%DO_REDUCTION, final_reduction
        VHPXORI4x128    %%GH1H, %%GH2H
        VHPXORI4x128    %%GH1L, %%GH2L
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES round 9
        vaesenc         %%B00_03, %%B00_03, %%AESKEY2
        vaesenc         %%B04_07, %%B04_07, %%AESKEY2
        vaesenc         %%B08_11, %%B08_11, %%AESKEY2
        vaesenc         %%B12_15, %%B12_15, %%AESKEY2
%if (NROUNDS >= 11)
        vbroadcastf64x2 %%AESKEY2, [%%GDATA + (16 * 11)]
%endif
        ;; =================================================
        ;; first phase of reduction
%ifidn %%DO_REDUCTION, final_reduction
        vpclmulqdq      XWORD(%%RED_P1), XWORD(%%RED_POLY), XWORD(%%GH1L), 0x01
        vpslldq         XWORD(%%RED_P1), XWORD(%%RED_P1), 8             ; shift-L 2 DWs
        vpxorq          XWORD(%%RED_P1), XWORD(%%GH1L), XWORD(%%RED_P1) ; first phase of the reduct
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES rounds up to 11 (AES192) or 13 (AES256)
        ;; AES128 is done
%if (NROUNDS >= 11)
        vaesenc         %%B00_03, %%B00_03, %%AESKEY1
        vaesenc         %%B04_07, %%B04_07, %%AESKEY1
        vaesenc         %%B08_11, %%B08_11, %%AESKEY1
        vaesenc         %%B12_15, %%B12_15, %%AESKEY1
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 12)]

        vaesenc         %%B00_03, %%B00_03, %%AESKEY2
        vaesenc         %%B04_07, %%B04_07, %%AESKEY2
        vaesenc         %%B08_11, %%B08_11, %%AESKEY2
        vaesenc         %%B12_15, %%B12_15, %%AESKEY2
%if (NROUNDS == 13)
        vbroadcastf64x2 %%AESKEY2, [%%GDATA + (16 * 13)]

        vaesenc         %%B00_03, %%B00_03, %%AESKEY1
        vaesenc         %%B04_07, %%B04_07, %%AESKEY1
        vaesenc         %%B08_11, %%B08_11, %%AESKEY1
        vaesenc         %%B12_15, %%B12_15, %%AESKEY1
        vbroadcastf64x2 %%AESKEY1, [%%GDATA + (16 * 14)]

        vaesenc         %%B00_03, %%B00_03, %%AESKEY2
        vaesenc         %%B04_07, %%B04_07, %%AESKEY2
        vaesenc         %%B08_11, %%B08_11, %%AESKEY2
        vaesenc         %%B12_15, %%B12_15, %%AESKEY2
%endif ; GCM256 / NROUNDS = 13 (15 including the first and the last)
%endif ; GCM192 / NROUNDS = 11 (13 including the first and the last)

        ;; =================================================
        ;; second phase of the reduction
%ifidn %%DO_REDUCTION, final_reduction
        vpclmulqdq      XWORD(%%RED_T1), XWORD(%%RED_POLY), XWORD(%%RED_P1), 0x00
        vpsrldq         XWORD(%%RED_T1), XWORD(%%RED_T1), 4 ; shift-R 1-DW to obtain 2-DWs shift-R

        vpclmulqdq      XWORD(%%RED_T2), XWORD(%%RED_POLY), XWORD(%%RED_P1), 0x10
        vpslldq         XWORD(%%RED_T2), XWORD(%%RED_T2), 4 ; shift-L 1-DW for result without shifts
        ;; GH1H = GH1H x RED_T1 x RED_T2
        vpternlogq      XWORD(%%GH1H), XWORD(%%RED_T2), XWORD(%%RED_T1), 0x96
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; the last AES round
        vaesenclast     %%B00_03, %%B00_03, %%AESKEY1
        vaesenclast     %%B04_07, %%B04_07, %%AESKEY1
        vaesenclast     %%B08_11, %%B08_11, %%AESKEY1
        vaesenclast     %%B12_15, %%B12_15, %%AESKEY1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; XOR against plain/cipher text
        vpxorq          %%B00_03, %%B00_03, %%DATA1
        vpxorq          %%B04_07, %%B04_07, %%DATA2
        vpxorq          %%B08_11, %%B08_11, %%DATA3
        vpxorq          %%B12_15, %%B12_15, %%DATA4

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; store cipher/plain text
        VX512STR        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + %%DATA_DISPL + (0 * 64)], %%B00_03
        VX512STR        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + %%DATA_DISPL + (1 * 64)], %%B04_07
        VX512STR        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + %%DATA_DISPL + (2 * 64)], %%B08_11
        VX512STR        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + %%DATA_DISPL + (3 * 64)], %%B12_15

        ;; =================================================
        ;; shuffle cipher text blocks for GHASH computation
%ifidn %%ENC_DEC, ENC
        vpshufb         %%B00_03, %%B00_03, %%SHFMSK
        vpshufb         %%B04_07, %%B04_07, %%SHFMSK
        vpshufb         %%B08_11, %%B08_11, %%SHFMSK
        vpshufb         %%B12_15, %%B12_15, %%SHFMSK
%else
        vpshufb         %%B00_03, %%DATA1, %%SHFMSK
        vpshufb         %%B04_07, %%DATA2, %%SHFMSK
        vpshufb         %%B08_11, %%DATA3, %%SHFMSK
        vpshufb         %%B12_15, %%DATA4, %%SHFMSK
%endif

        ;; =================================================
        ;; store shuffled cipher text for ghashing
        vmovdqa64       [rsp + %%AESOUT_BLK_OFFSET + (0*64)], %%B00_03
        vmovdqa64       [rsp + %%AESOUT_BLK_OFFSET + (1*64)], %%B04_07
        vmovdqa64       [rsp + %%AESOUT_BLK_OFFSET + (2*64)], %%B08_11
        vmovdqa64       [rsp + %%AESOUT_BLK_OFFSET + (3*64)], %%B12_15

%ifidn %%DO_REDUCTION, final_reduction
        ;; =================================================
        ;; Return GHASH value  through %%GH1H
%endif

%endmacro                       ; GHASH_16_ENCRYPT_16_PARALLEL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Encryption of a single block
%macro  ENCRYPT_SINGLE_BLOCK 2
%define %%GDATA %1
%define %%XMM0  %2

                vpxorq          %%XMM0, %%XMM0, [%%GDATA+16*0]
%assign i 1
%rep NROUNDS
                vaesenc         %%XMM0, [%%GDATA+16*i]
%assign i (i+1)
%endrep
                vaesenclast     %%XMM0, [%%GDATA+16*i]
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Save register content for the caller
%macro FUNC_SAVE 0
        ;; Required for Update/GMC_ENC
        ;the number of pushes must equal STACK_OFFSET
        mov     rax, rsp

        sub     rsp, STACK_FRAME_SIZE
        and     rsp, ~63

        mov     [rsp + STACK_GP_OFFSET + 0*8], r12
        mov     [rsp + STACK_GP_OFFSET + 1*8], r13
        mov     [rsp + STACK_GP_OFFSET + 2*8], r14
        mov     [rsp + STACK_GP_OFFSET + 3*8], r15
        mov     [rsp + STACK_GP_OFFSET + 4*8], rax ; stack
        mov     r14, rax                               ; r14 is used to retrieve stack args
        mov     [rsp + STACK_GP_OFFSET + 5*8], rbp
        mov     [rsp + STACK_GP_OFFSET + 6*8], rbx
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + STACK_GP_OFFSET + 7*8], rdi
        mov     [rsp + STACK_GP_OFFSET + 8*8], rsi
%endif

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        vmovdqu [rsp + STACK_XMM_OFFSET + 0*16], xmm6
        vmovdqu [rsp + STACK_XMM_OFFSET + 1*16], xmm7
        vmovdqu [rsp + STACK_XMM_OFFSET + 2*16], xmm8
        vmovdqu [rsp + STACK_XMM_OFFSET + 3*16], xmm9
        vmovdqu [rsp + STACK_XMM_OFFSET + 4*16], xmm10
        vmovdqu [rsp + STACK_XMM_OFFSET + 5*16], xmm11
        vmovdqu [rsp + STACK_XMM_OFFSET + 6*16], xmm12
        vmovdqu [rsp + STACK_XMM_OFFSET + 7*16], xmm13
        vmovdqu [rsp + STACK_XMM_OFFSET + 8*16], xmm14
        vmovdqu [rsp + STACK_XMM_OFFSET + 9*16], xmm15
%endif
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Restore register content for the caller
%macro FUNC_RESTORE 0

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm15, [rsp + STACK_XMM_OFFSET + 9*16]
        vmovdqu xmm14, [rsp + STACK_XMM_OFFSET + 8*16]
        vmovdqu xmm13, [rsp + STACK_XMM_OFFSET + 7*16]
        vmovdqu xmm12, [rsp + STACK_XMM_OFFSET + 6*16]
        vmovdqu xmm11, [rsp + STACK_XMM_OFFSET + 5*16]
        vmovdqu xmm10, [rsp + STACK_XMM_OFFSET + 4*16]
        vmovdqu xmm9, [rsp + STACK_XMM_OFFSET + 3*16]
        vmovdqu xmm8, [rsp + STACK_XMM_OFFSET + 2*16]
        vmovdqu xmm7, [rsp + STACK_XMM_OFFSET + 1*16]
        vmovdqu xmm6, [rsp + STACK_XMM_OFFSET + 0*16]
%endif

        ;; Required for Update/GMC_ENC
        mov     rbp, [rsp + STACK_GP_OFFSET + 5*8]
        mov     rbx, [rsp + STACK_GP_OFFSET + 6*8]
%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + STACK_GP_OFFSET + 7*8]
        mov     rsi, [rsp + STACK_GP_OFFSET + 8*8]
%endif
        mov     r12, [rsp + STACK_GP_OFFSET + 0*8]
        mov     r13, [rsp + STACK_GP_OFFSET + 1*8]
        mov     r14, [rsp + STACK_GP_OFFSET + 2*8]
        mov     r15, [rsp + STACK_GP_OFFSET + 3*8]
        mov     rsp, [rsp + STACK_GP_OFFSET + 4*8] ; stack
%endmacro


%macro CALC_J0 26
%define %%KEY           %1 ;; [in] Pointer to GCM KEY structure
%define %%IV            %2 ;; [in] Pointer to IV
%define %%IV_LEN        %3 ;; [in] IV length
%define %%J0            %4 ;; [out] XMM reg to contain J0
%define %%ZT0           %5 ;; [clobbered] ZMM register
%define %%ZT1           %6 ;; [clobbered] ZMM register
%define %%ZT2           %7 ;; [clobbered] ZMM register
%define %%ZT3           %8 ;; [clobbered] ZMM register
%define %%ZT4           %9 ;; [clobbered] ZMM register
%define %%ZT5           %10 ;; [clobbered] ZMM register
%define %%ZT6           %11 ;; [clobbered] ZMM register
%define %%ZT7           %12 ;; [clobbered] ZMM register
%define %%ZT8           %13 ;; [clobbered] ZMM register
%define %%ZT9           %14 ;; [clobbered] ZMM register
%define %%ZT10          %15 ;; [clobbered] ZMM register
%define %%ZT11          %16 ;; [clobbered] ZMM register
%define %%ZT12          %17 ;; [clobbered] ZMM register
%define %%ZT13          %18 ;; [clobbered] ZMM register
%define %%ZT14          %19 ;; [clobbered] ZMM register
%define %%ZT15          %20 ;; [clobbered] ZMM register
%define %%ZT16          %21 ;; [clobbered] ZMM register
%define %%ZT17          %22 ;; [clobbered] ZMM register
%define %%T1            %23 ;; [clobbered] GP register
%define %%T2            %24 ;; [clobbered] GP register
%define %%T3            %25 ;; [clobbered] GP register
%define %%MASKREG       %26 ;; [clobbered] mask register

%define %%POLY   %%ZT8
%define %%TH     %%ZT7
%define %%TM     %%ZT6
%define %%TL     %%ZT5

        ;; J0 = GHASH(IV || 0s+64 || len(IV)64)
        ;; s = 16 * RoundUp(len(IV)/16) -  len(IV) */

        ;; Calculate GHASH of (IV || 0s)
        vpxor   %%J0, %%J0
        CALC_AAD_HASH %%IV, %%IV_LEN, %%J0, %%KEY, %%ZT0, %%ZT1, %%ZT2, %%ZT3, \
                      %%ZT4, %%ZT5, %%ZT6, %%ZT7, %%ZT8, %%ZT9, %%ZT10, %%ZT11, \
                      %%ZT12, %%ZT13,  %%ZT14, %%ZT15, %%ZT16, %%ZT17, \
                      %%T1, %%T2, %%T3, %%MASKREG

        ;; Calculate GHASH of last 16-byte block (0 || len(IV)64)
        mov     %%T1, %%IV_LEN
        shl     %%T1, 3 ;; IV length in bits
        vmovq   XWORD(%%ZT2), %%T1
        ;; Might need shuffle of ZT2
        vpxorq  %%ZT2, ZWORD(%%J0)
        VCLMUL_1_TO_8_STEP1 %%KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 1
        VCLMUL_1_TO_8_STEP2 %%KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 1

        ;; Multiplications have been done. Do the reduction now
        vmovdqa64       XWORD(%%POLY), [rel POLY2]
        VCLMUL_REDUCE   %%J0, XWORD(%%POLY), XWORD(%%ZT1), XWORD(%%ZT2), \
                        XWORD(%%ZT0), XWORD(%%ZT3)
        vpshufb %%J0, [rel SHUF_MASK] ; perform a 16Byte swap
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; GCM_INIT initializes a gcm_context_data struct to prepare for encoding/decoding.
;;; Input: gcm_key_data * (GDATA_KEY), gcm_context_data *(GDATA_CTX), IV,
;;; Additional Authentication data (A_IN), Additional Data length (A_LEN).
;;; Output: Updated GDATA_CTX with the hash of A_IN (AadHash) and initialized other parts of GDATA_CTX.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_INIT        30-31
%define %%GDATA_KEY     %1      ; [in] GCM expanded keys pointer
%define %%GDATA_CTX     %2      ; [in] GCM context pointer
%define %%IV            %3      ; [in] IV pointer
%define %%A_IN          %4      ; [in] AAD pointer
%define %%A_LEN         %5      ; [in] AAD length in bytes
%define %%GPR1          %6      ; [clobbered] GP register
%define %%GPR2          %7      ; [clobbered] GP register
%define %%GPR3          %8      ; [clobbered] GP register
%define %%MASKREG       %9      ; [clobbered] mask register
%define %%AAD_HASH      %10     ; [out] XMM for AAD_HASH value (xmm14)
%define %%CUR_COUNT     %11     ; [out] XMM with current counter (xmm2)
%define %%ZT0           %12     ; [clobbered] ZMM register
%define %%ZT1           %13     ; [clobbered] ZMM register
%define %%ZT2           %14     ; [clobbered] ZMM register
%define %%ZT3           %15     ; [clobbered] ZMM register
%define %%ZT4           %16     ; [clobbered] ZMM register
%define %%ZT5           %17     ; [clobbered] ZMM register
%define %%ZT6           %18     ; [clobbered] ZMM register
%define %%ZT7           %19     ; [clobbered] ZMM register
%define %%ZT8           %20     ; [clobbered] ZMM register
%define %%ZT9           %21     ; [clobbered] ZMM register
%define %%ZT10          %22     ; [clobbered] ZMM register
%define %%ZT11          %23     ; [clobbered] ZMM register
%define %%ZT12          %24     ; [clobbered] ZMM register
%define %%ZT13          %25     ; [clobbered] ZMM register
%define %%ZT14          %26     ; [clobbered] ZMM register
%define %%ZT15          %27     ; [clobbered] ZMM register
%define %%ZT16          %28     ; [clobbered] ZMM register
%define %%ZT17          %29     ; [clobbered] ZMM register
%define %%INSTANCE_TYPE %30     ; [in] "single_call" or "multi_call"
%define %%IV_LEN        %31     ; [in] IV length

        ;; prepare IV
%if %0 == 31 ;; IV is different than 12 bytes
        CALC_J0 %%GDATA_KEY, %%IV, %%IV_LEN, %%CUR_COUNT, \
                        %%ZT0, %%ZT1, %%ZT2, %%ZT3, %%ZT4, %%ZT5, %%ZT6, %%ZT7, \
                        %%ZT8, %%ZT9, %%ZT10, %%ZT11, %%ZT12, %%ZT13, \
                        %%ZT14, %%ZT15, %%ZT16, %%ZT17, %%GPR1, %%GPR2, %%GPR3, %%MASKREG
%else ;; IV is 12 bytes
        ;; read 12 IV bytes and pad with 0x00000001
        vmovdqa64       %%CUR_COUNT, [rel ONEf]
        mov             %%GPR2, %%IV
        mov             DWORD(%%GPR1), 0x0000_0fff
        kmovd           %%MASKREG, DWORD(%%GPR1)
        vmovdqu8        %%CUR_COUNT{%%MASKREG}, [%%GPR2]      ; ctr = IV | 0x1
%endif

        ;; calculate AAD hash
        cmp             %%A_LEN, 12
        jne             %%_aad_is_not_12_bytes

        ;; load 12 bytes of AAD
%if %0 == 31 ;; IV is different than 12 bytes
        mov             DWORD(%%GPR1), 0x0000_0fff
        kmovd           %%MASKREG, DWORD(%%GPR1)
%endif
        mov             %%GPR1, %%A_IN
        vmovdqu8        XWORD(%%AAD_HASH){%%MASKREG}{z}, [%%GPR1]
        vmovdqu8        XWORD(%%ZT0), [%%GDATA_KEY + HashKey_1]
        vpshufb         XWORD(%%AAD_HASH), [rel SHUF_MASK]

        ;; GHASH 12 bytes of AAD
        GHASH_MUL       XWORD(%%AAD_HASH), XWORD(%%ZT0), \
                        XWORD(%%ZT1), XWORD(%%ZT2), XWORD(%%ZT3), XWORD(%%ZT4), XWORD(%%ZT5)

        jmp             %%_aad_compute_done

%%_aad_is_not_12_bytes:
        vpxor           %%AAD_HASH, %%AAD_HASH
        CALC_AAD_HASH   %%A_IN, %%A_LEN, %%AAD_HASH, %%GDATA_KEY, \
                        %%ZT0, %%ZT1, %%ZT2, %%ZT3, %%ZT4, %%ZT5, %%ZT6, %%ZT7, %%ZT8, %%ZT9, \
                        %%ZT10, %%ZT11, %%ZT12, %%ZT13,  %%ZT14, %%ZT15, %%ZT16, %%ZT17, \
                        %%GPR1, %%GPR2, %%GPR3, %%MASKREG
%%_aad_compute_done:

        ;; set up context fields
        mov             %%GPR1, %%A_LEN
        mov             [%%GDATA_CTX + AadLen], %%GPR1        ; ctx.aad_length = aad_length
        vmovdqu64       [%%GDATA_CTX + AadHash], %%AAD_HASH   ; ctx.aad hash = aad_hash

        xor             %%GPR1, %%GPR1
        mov             [%%GDATA_CTX + InLen], %%GPR1         ; ctx.in_length = 0
%ifidn %%INSTANCE_TYPE, multi_call
        mov             [%%GDATA_CTX + PBlockLen], %%GPR1     ; ctx.partial_block_length = 0
%endif

        vmovdqu64       [%%GDATA_CTX + OrigIV], %%CUR_COUNT    ; ctx.orig_IV = iv
        vpshufb         %%CUR_COUNT, [rel SHUF_MASK]
        vmovdqu64       [%%GDATA_CTX + CurCount], %%CUR_COUNT ; ctx.current_counter = iv (LE format)
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cipher and ghash of payloads shorter than 256 bytes
;;; - number of blocks in the message comes as argument
;;; - depending on the number of blocks an optimized variant of
;;;   INITIAL_BLOCKS_PARTIAL is invoked
%macro  GCM_ENC_DEC_SMALL   39
%define %%GDATA_KEY         %1  ; [in] key pointer
%define %%GDATA_CTX         %2  ; [in] context pointer
%define %%CYPH_PLAIN_OUT    %3  ; [in] output buffer
%define %%PLAIN_CYPH_IN     %4  ; [in] input buffer
%define %%PLAIN_CYPH_LEN    %5  ; [in] buffer length
%define %%ENC_DEC           %6  ; [in] cipher direction
%define %%DATA_OFFSET       %7  ; [in] data offset
%define %%LENGTH            %8  ; [in] data length
%define %%NUM_BLOCKS        %9  ; [in] number of blocks to process 1 to 16
%define %%CTR               %10 ; [in/out] XMM counter block
%define %%HASH_IN_OUT       %11 ; [in/out] XMM GHASH value
%define %%INSTANCE_TYPE     %12 ; [in] single or multi call
%define %%ZTMP0             %13 ; [clobbered] ZMM register
%define %%ZTMP1             %14 ; [clobbered] ZMM register
%define %%ZTMP2             %15 ; [clobbered] ZMM register
%define %%ZTMP3             %16 ; [clobbered] ZMM register
%define %%ZTMP4             %17 ; [clobbered] ZMM register
%define %%ZTMP5             %18 ; [clobbered] ZMM register
%define %%ZTMP6             %19 ; [clobbered] ZMM register
%define %%ZTMP7             %20 ; [clobbered] ZMM register
%define %%ZTMP8             %21 ; [clobbered] ZMM register
%define %%ZTMP9             %22 ; [clobbered] ZMM register
%define %%ZTMP10            %23 ; [clobbered] ZMM register
%define %%ZTMP11            %24 ; [clobbered] ZMM register
%define %%ZTMP12            %25 ; [clobbered] ZMM register
%define %%ZTMP13            %26 ; [clobbered] ZMM register
%define %%ZTMP14            %27 ; [clobbered] ZMM register
%define %%ZTMP15            %28 ; [clobbered] ZMM register
%define %%ZTMP16            %29 ; [clobbered] ZMM register
%define %%ZTMP17            %30 ; [clobbered] ZMM register
%define %%ZTMP18            %31 ; [clobbered] ZMM register
%define %%ZTMP19            %32 ; [clobbered] ZMM register
%define %%ZTMP20            %33 ; [clobbered] ZMM register
%define %%ZTMP21            %34 ; [clobbered] ZMM register
%define %%ZTMP22            %35 ; [clobbered] ZMM register
%define %%IA0               %36 ; [clobbered] GP register
%define %%IA1               %37 ; [clobbered] GP register
%define %%MASKREG           %38 ; [clobbered] mask register
%define %%SHUFMASK          %39 ; [in] ZMM with BE/LE shuffle mask

        cmp     %%NUM_BLOCKS, 8
        je      %%_small_initial_num_blocks_is_8
        jl      %%_small_initial_num_blocks_is_7_1


        cmp     %%NUM_BLOCKS, 12
        je      %%_small_initial_num_blocks_is_12
        jl      %%_small_initial_num_blocks_is_11_9

        ;; 16, 15, 14 or 13
        cmp     %%NUM_BLOCKS, 16
        je      %%_small_initial_num_blocks_is_16
        cmp     %%NUM_BLOCKS, 15
        je      %%_small_initial_num_blocks_is_15
        cmp     %%NUM_BLOCKS, 14
        je      %%_small_initial_num_blocks_is_14
        jmp     %%_small_initial_num_blocks_is_13

%%_small_initial_num_blocks_is_11_9:
        ;; 11, 10 or 9
        cmp     %%NUM_BLOCKS, 11
        je      %%_small_initial_num_blocks_is_11
        cmp     %%NUM_BLOCKS, 10
        je      %%_small_initial_num_blocks_is_10
        jmp     %%_small_initial_num_blocks_is_9

%%_small_initial_num_blocks_is_7_1:
        cmp     %%NUM_BLOCKS, 4
        je      %%_small_initial_num_blocks_is_4
        jl      %%_small_initial_num_blocks_is_3_1
        ;; 7, 6 or 5
        cmp     %%NUM_BLOCKS, 7
        je      %%_small_initial_num_blocks_is_7
        cmp     %%NUM_BLOCKS, 6
        je      %%_small_initial_num_blocks_is_6
        jmp     %%_small_initial_num_blocks_is_5

%%_small_initial_num_blocks_is_3_1:
        ;; 3, 2 or 1
        cmp     %%NUM_BLOCKS, 3
        je      %%_small_initial_num_blocks_is_3
        cmp     %%NUM_BLOCKS, 2
        je      %%_small_initial_num_blocks_is_2

        ;; for %%NUM_BLOCKS == 1, just fall through and no 'jmp' needed

        ;; Use rep to generate different block size variants
        ;; - one block size has to be the first one
        ;; - ZTMP15 - ZTMP22 are free
%assign num_blocks 1
%rep 16
%%_small_initial_num_blocks_is_ %+ num_blocks :
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, num_blocks, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, \
                %%ZTMP10, %%ZTMP11, %%ZTMP12, %%ZTMP13, %%ZTMP14, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFMASK
%if num_blocks != 16
        jmp     %%_small_initial_blocks_encrypted
%endif
%assign num_blocks (num_blocks + 1)
%endrep

%%_small_initial_blocks_encrypted:

%endmacro                       ; GCM_ENC_DEC_SMALL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_ENC_DEC Encodes/Decodes given data. Assumes that the passed gcm_context_data struct
; has been initialized by GCM_INIT
; Requires the input data be at least 1 byte long because of READ_SMALL_INPUT_DATA.
; Input: gcm_key_data struct* (GDATA_KEY), gcm_context_data *(GDATA_CTX), input text (PLAIN_CYPH_IN),
; input text length (PLAIN_CYPH_LEN) and whether encoding or decoding (ENC_DEC).
; Output: A cypher of the given plain text (CYPH_PLAIN_OUT), and updated GDATA_CTX
; Clobbers rax, r10-r15, and zmm0-zmm31, k1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_ENC_DEC         7
%define %%GDATA_KEY         %1  ; [in] key pointer
%define %%GDATA_CTX         %2  ; [in] context pointer
%define %%CYPH_PLAIN_OUT    %3  ; [in] output buffer pointer
%define %%PLAIN_CYPH_IN     %4  ; [in] input buffer pointer
%define %%PLAIN_CYPH_LEN    %5  ; [in] buffer length
%define %%ENC_DEC           %6  ; [in] cipher direction
%define %%INSTANCE_TYPE     %7  ; [in] 'single_call' or 'multi_call' selection

%define %%IA0               r10
%define %%IA1               r12
%define %%IA2               r13
%define %%IA3               r15
%define %%IA4               r11
%define %%IA5               rax

%define %%LENGTH            %%IA2
%define %%CTR_CHECK         %%IA3
%define %%DATA_OFFSET       %%IA4

%define %%HASHK_PTR         %%IA5

%define %%GCM_INIT_CTR_BLOCK    xmm2 ; hardcoded in GCM_INIT for now

%define %%AES_PARTIAL_BLOCK     xmm8
%define %%CTR_BLOCK2z           zmm18
%define %%CTR_BLOCKz            zmm9
%define %%CTR_BLOCKx            xmm9
%define %%AAD_HASHz             zmm14
%define %%AAD_HASHx             xmm14

;;; ZTMP0 - ZTMP12 - used in by8 code, by128/48 code and GCM_ENC_DEC_SMALL
%define %%ZTMP0                 zmm0
%define %%ZTMP1                 zmm3
%define %%ZTMP2                 zmm4
%define %%ZTMP3                 zmm5
%define %%ZTMP4                 zmm6
%define %%ZTMP5                 zmm7
%define %%ZTMP6                 zmm10
%define %%ZTMP7                 zmm11
%define %%ZTMP8                 zmm12
%define %%ZTMP9                 zmm13
%define %%ZTMP10                zmm15
%define %%ZTMP11                zmm16
%define %%ZTMP12                zmm17

;;; ZTMP13 - ZTMP22 - used in by128/48 code and GCM_ENC_DEC_SMALL
;;; - some used by8 code as well through TMPxy names
%define %%ZTMP13                zmm19
%define %%ZTMP14                zmm20
%define %%ZTMP15                zmm21
%define %%ZTMP16                zmm30   ; can be used in very/big_loop part
%define %%ZTMP17                zmm31   ; can be used in very/big_loop part
%define %%ZTMP18                zmm1
%define %%ZTMP19                zmm2
%define %%ZTMP20                zmm8
%define %%ZTMP21                zmm22
%define %%ZTMP22                zmm23

;;; Free to use: zmm24 - zmm29
;;; - used by by128/48 and by8
%define %%GH                    zmm24
%define %%GL                    zmm25
%define %%GM                    zmm26
%define %%SHUF_MASK             zmm29
%define %%CTR_BLOCK_SAVE        zmm28

;;; - used by by128/48 code only
%define %%ADDBE_4x4             zmm27
%define %%ADDBE_1234            zmm28       ; conflicts with CTR_BLOCK_SAVE

;; used by8 code only
%define %%GH4KEY                %%ZTMP17
%define %%GH8KEY                %%ZTMP16
%define %%BLK0                  %%ZTMP18
%define %%BLK1                  %%ZTMP19
%define %%ADD8BE                zmm27
%define %%ADD8LE                %%ZTMP13

%define %%MASKREG               k1

;; reduction every 48 blocks, depth 32 blocks
;; @note 48 blocks is the maximum capacity of the stack frame
%assign big_loop_nblocks        48
%assign big_loop_depth          32

;;; Macro flow:
;;; - for message size bigger than very_big_loop_nblocks process data
;;;   with "very_big_loop" parameters
;;; - for message size bigger than big_loop_nblocks process data
;;;   with "big_loop" parameters
;;; - calculate the number of 16byte blocks in the message
;;; - process (number of 16byte blocks) mod 8
;;;   '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
;;; - process 8 16 byte blocks at a time until all are done in %%_encrypt_by_8_new

%ifidn __OUTPUT_FORMAT__, win64
        cmp             %%PLAIN_CYPH_LEN, 0
%else
        or              %%PLAIN_CYPH_LEN, %%PLAIN_CYPH_LEN
%endif
        je              %%_enc_dec_done

        xor             %%DATA_OFFSET, %%DATA_OFFSET

        ;; Update length of data processed
%ifidn __OUTPUT_FORMAT__, win64
        mov             %%IA0, %%PLAIN_CYPH_LEN
        add             [%%GDATA_CTX + InLen], %%IA0
%else
        add             [%%GDATA_CTX + InLen], %%PLAIN_CYPH_LEN
%endif
        vmovdqu64       %%AAD_HASHx, [%%GDATA_CTX + AadHash]

%ifidn %%INSTANCE_TYPE, multi_call
        ;; NOTE: partial block processing makes only sense for multi_call here.
        ;; Used for the update flow - if there was a previous partial
        ;; block fill the remaining bytes here.
        PARTIAL_BLOCK %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%PLAIN_CYPH_LEN, %%DATA_OFFSET, %%AAD_HASHx, %%ENC_DEC, \
                %%IA0, %%IA1, %%IA2, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%MASKREG
%endif

        ;;  lift counter block from GCM_INIT to here
%ifidn %%INSTANCE_TYPE, single_call
        vmovdqu64       %%CTR_BLOCKx, %%GCM_INIT_CTR_BLOCK
%else
        vmovdqu64       %%CTR_BLOCKx, [%%GDATA_CTX + CurCount]
%endif

        ;; Save the amount of data left to process in %%LENGTH
        mov             %%LENGTH, %%PLAIN_CYPH_LEN
%ifidn %%INSTANCE_TYPE, multi_call
        ;; NOTE: %%DATA_OFFSET is zero in single_call case.
        ;;      Consequently PLAIN_CYPH_LEN will never be zero after
        ;;      %%DATA_OFFSET subtraction below.
        ;; There may be no more data if it was consumed in the partial block.
        sub             %%LENGTH, %%DATA_OFFSET
        je              %%_enc_dec_done
%endif                          ; %%INSTANCE_TYPE, multi_call

        vmovdqa64       %%SHUF_MASK, [rel SHUF_MASK]
        vmovdqa64       %%ADDBE_4x4, [rel ddq_addbe_4444]

        cmp             %%LENGTH, (16 * 16)
        jb              %%_message_below_16_blocks

        ;; overwritten above by CTR_BLOCK_SAVE
        vmovdqa64        %%ADDBE_1234, [rel ddq_addbe_1234]

        ;; start the pipeline
        ;; - 32 blocks aes-ctr
        ;; - 16 blocks ghash + aes-ctr

        ;; set up CTR_CHECK
        vmovd           DWORD(%%CTR_CHECK), %%CTR_BLOCKx
        and             DWORD(%%CTR_CHECK), 255

        ;; in LE format after init, convert to BE
        vshufi64x2      %%CTR_BLOCKz, %%CTR_BLOCKz, %%CTR_BLOCKz, 0
        vpshufb         %%CTR_BLOCKz, %%CTR_BLOCKz, %%SHUF_MASK

        ;; ==== AES-CTR - first 16 blocks
%assign aesout_offset (STACK_LOCAL_OFFSET + (0 * 16))
%assign data_in_out_offset 0

        INITIAL_BLOCKS_16       %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, %%GDATA_KEY, %%DATA_OFFSET, \
                                no_ghash, %%CTR_BLOCKz, %%CTR_CHECK, %%ADDBE_4x4, %%ADDBE_1234, \
                                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                                %%SHUF_MASK, %%ENC_DEC, aesout_offset, data_in_out_offset

        cmp             %%LENGTH, (32 * 16)
        jb              %%_message_below_32_blocks

        ;; ==== AES-CTR - next 16 blocks
%assign aesout_offset (STACK_LOCAL_OFFSET + (16 * 16))
%assign data_in_out_offset (16 * 16)

        INITIAL_BLOCKS_16       %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, %%GDATA_KEY, %%DATA_OFFSET, \
                                no_ghash, %%CTR_BLOCKz, %%CTR_CHECK, %%ADDBE_4x4, %%ADDBE_1234, \
                                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                                %%SHUF_MASK, %%ENC_DEC, aesout_offset, data_in_out_offset

        add             %%DATA_OFFSET, (32 * 16)
        sub             %%LENGTH, (32 * 16)

        cmp             %%LENGTH, (big_loop_nblocks * 16)
        jb              %%_no_more_big_nblocks

        ;; ====
        ;; ==== AES-CTR + GHASH - 48 blocks loop
        ;; ====
%%_encrypt_big_nblocks:
        ;; ==== AES-CTR + GHASH - 16 blocks, start
%assign aesout_offset (STACK_LOCAL_OFFSET + (32 * 16))
%assign data_in_out_offset (0 * 16)
%assign ghashin_offset (STACK_LOCAL_OFFSET + (0 * 16))

        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, \
                %%CTR_BLOCKz, %%CTR_CHECK, \
                HashKey_48, aesout_offset, ghashin_offset, %%SHUF_MASK, \
                %%ZTMP0,  %%ZTMP1,  %%ZTMP2,  %%ZTMP3, \
                %%ZTMP4,  %%ZTMP5,  %%ZTMP6,  %%ZTMP7, \
                %%ZTMP8,  %%ZTMP9,  %%ZTMP10, %%ZTMP11,\
                %%ZTMP12, %%ZTMP13, %%ZTMP14, %%ZTMP15,\
                %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                %%ZTMP20, %%ZTMP21, %%ZTMP22, \
                %%ADDBE_4x4, %%ADDBE_1234, \
                %%GL, %%GH, %%GM, \
                first_time, %%ENC_DEC, data_in_out_offset, %%AAD_HASHz

        ;; ==== AES-CTR + GHASH - 16 blocks, no reduction
%assign aesout_offset (STACK_LOCAL_OFFSET + (0 * 16))
%assign data_in_out_offset (16 * 16)
%assign ghashin_offset (STACK_LOCAL_OFFSET + (16 * 16))

        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, \
                %%CTR_BLOCKz, %%CTR_CHECK, \
                HashKey_32, aesout_offset, ghashin_offset, %%SHUF_MASK, \
                %%ZTMP0,  %%ZTMP1,  %%ZTMP2,  %%ZTMP3, \
                %%ZTMP4,  %%ZTMP5,  %%ZTMP6,  %%ZTMP7, \
                %%ZTMP8,  %%ZTMP9,  %%ZTMP10, %%ZTMP11,\
                %%ZTMP12, %%ZTMP13, %%ZTMP14, %%ZTMP15,\
                %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                %%ZTMP20, %%ZTMP21, %%ZTMP22, \
                %%ADDBE_4x4, %%ADDBE_1234, \
                %%GL, %%GH, %%GM, \
                no_reduction, %%ENC_DEC, data_in_out_offset, no_ghash_in

        ;; ==== AES-CTR + GHASH - 16 blocks, reduction
%assign aesout_offset (STACK_LOCAL_OFFSET + (16 * 16))
%assign data_in_out_offset (32 * 16)
%assign ghashin_offset (STACK_LOCAL_OFFSET + (32 * 16))

        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, \
                %%CTR_BLOCKz, %%CTR_CHECK, \
                HashKey_16, aesout_offset, ghashin_offset, %%SHUF_MASK, \
                %%ZTMP0,  %%ZTMP1,  %%ZTMP2,  %%ZTMP3, \
                %%ZTMP4,  %%ZTMP5,  %%ZTMP6,  %%ZTMP7, \
                %%ZTMP8,  %%ZTMP9,  %%ZTMP10, %%ZTMP11,\
                %%ZTMP12, %%ZTMP13, %%ZTMP14, %%ZTMP15,\
                %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                %%ZTMP20, %%ZTMP21, %%ZTMP22, \
                %%ADDBE_4x4, %%ADDBE_1234, \
                %%GL, %%GH, %%GM, \
                final_reduction, %%ENC_DEC, data_in_out_offset, no_ghash_in

        ;; === xor cipher block 0 with GHASH (ZT4)
        vmovdqa64       %%AAD_HASHz, %%ZTMP4

        add             %%DATA_OFFSET, (big_loop_nblocks * 16)
        sub             %%LENGTH, (big_loop_nblocks * 16)
        cmp             %%LENGTH, (big_loop_nblocks * 16)
        jae             %%_encrypt_big_nblocks

%%_no_more_big_nblocks:

        cmp             %%LENGTH, (32 * 16)
        jae             %%_encrypt_32_blocks

        cmp             %%LENGTH, (16 * 16)
        jae             %%_encrypt_16_blocks

%%_encrypt_0_blocks_ghash_32:
        ;; ==== save the last counter block
        vpshufb         %%CTR_BLOCKx, XWORD(%%SHUF_MASK)
        vmovdqa64       XWORD(%%CTR_BLOCK_SAVE), %%CTR_BLOCKx

        ;; ==== GHASH 32 blocks and follow with reduction
        GHASH_16        start, %%GH, %%GM, %%GL, rsp, STACK_LOCAL_OFFSET, (0 * 16), %%GDATA_KEY, HashKey_32, 0, %%AAD_HASHz, \
                        %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9
        GHASH_16        end, %%GH, %%GM, %%GL, rsp, STACK_LOCAL_OFFSET, (16 * 16), %%GDATA_KEY, HashKey_16, 0, no_hash_input, \
                        %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9

        jmp             %%_integrate_and_reduce

        ;; =====================================================
        ;; =====================================================
        ;; ==== GHASH & encrypt 1 x 16 blocks (done before)
        ;; ==== GHASH & encrypt 1 x 16 blocks
        ;; ==== GHASH 16 blocks + reduction
        ;; ==== GHASH 2 x 16 blocks (32) and follow with reduction
%%_encrypt_32_blocks:
        ;; ==== AES-CTR + GHASH - 16 blocks, start
%assign aesout_offset (STACK_LOCAL_OFFSET + (32 * 16))
%assign ghashin_offset (STACK_LOCAL_OFFSET + (0 * 16))
%assign data_in_out_offset (0 * 16)

        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, \
                %%CTR_BLOCKz, %%CTR_CHECK, \
                HashKey_48, aesout_offset, ghashin_offset, %%SHUF_MASK, \
                %%ZTMP0,  %%ZTMP1,  %%ZTMP2,  %%ZTMP3, \
                %%ZTMP4,  %%ZTMP5,  %%ZTMP6,  %%ZTMP7, \
                %%ZTMP8,  %%ZTMP9,  %%ZTMP10, %%ZTMP11,\
                %%ZTMP12, %%ZTMP13, %%ZTMP14, %%ZTMP15,\
                %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                %%ZTMP20, %%ZTMP21, %%ZTMP22, \
                %%ADDBE_4x4, %%ADDBE_1234, \
                %%GL, %%GH, %%GM, \
                first_time, %%ENC_DEC, data_in_out_offset, %%AAD_HASHz

        ;; ==== AES-CTR + GHASH - 16 blocks, no reduction
%assign aesout_offset (STACK_LOCAL_OFFSET + (0 * 16))
%assign ghashin_offset (STACK_LOCAL_OFFSET + (16 * 16))
%assign data_in_out_offset (16 * 16)

        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, \
                %%CTR_BLOCKz, %%CTR_CHECK, \
                HashKey_32, aesout_offset, ghashin_offset, %%SHUF_MASK, \
                %%ZTMP0,  %%ZTMP1,  %%ZTMP2,  %%ZTMP3, \
                %%ZTMP4,  %%ZTMP5,  %%ZTMP6,  %%ZTMP7, \
                %%ZTMP8,  %%ZTMP9,  %%ZTMP10, %%ZTMP11,\
                %%ZTMP12, %%ZTMP13, %%ZTMP14, %%ZTMP15,\
                %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                %%ZTMP20, %%ZTMP21, %%ZTMP22, \
                %%ADDBE_4x4, %%ADDBE_1234, \
                %%GL, %%GH, %%GM, \
                no_reduction, %%ENC_DEC, data_in_out_offset, no_ghash_in

        ;; ==== save the last counter block
        vpshufb         %%CTR_BLOCKx, XWORD(%%SHUF_MASK)
        vmovdqa64       XWORD(%%CTR_BLOCK_SAVE), %%CTR_BLOCKx

        ;; ==== GHASH 16 blocks with reduction
        GHASH_16        end_reduce, %%GH, %%GM, %%GL, rsp, STACK_LOCAL_OFFSET, (32 * 16), %%GDATA_KEY, HashKey_16, 0, %%AAD_HASHz, \
                        %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9

        ;; ==== GHASH 16 blocks & follow with reduction
        GHASH_16        start, %%GH, %%GM, %%GL, rsp, STACK_LOCAL_OFFSET, (0 * 16), %%GDATA_KEY, HashKey_16, 0, %%AAD_HASHz, \
                        %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9

        sub             %%LENGTH, (32 * 16)
        add             %%DATA_OFFSET, (32 * 16)
        jmp             %%_integrate_and_reduce

        ;; =====================================================
        ;; =====================================================
        ;; ==== GHASH & encrypt 16 blocks (done before)
        ;; ==== GHASH 2 x 16 blocks (32) + reduction
        ;; ==== GHASH 1 x 16 blocks (32) and follow with reduction
%%_encrypt_16_blocks:
        ;; ==== AES-CTR + GHASH - 16 blocks, start
%assign aesout_offset (STACK_LOCAL_OFFSET + (32 * 16))
%assign ghashin_offset (STACK_LOCAL_OFFSET + (0 * 16))
%assign data_in_out_offset (0 * 16)

        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, \
                %%CTR_BLOCKz, %%CTR_CHECK, \
                HashKey_48, aesout_offset, ghashin_offset, %%SHUF_MASK, \
                %%ZTMP0,  %%ZTMP1,  %%ZTMP2,  %%ZTMP3, \
                %%ZTMP4,  %%ZTMP5,  %%ZTMP6,  %%ZTMP7, \
                %%ZTMP8,  %%ZTMP9,  %%ZTMP10, %%ZTMP11,\
                %%ZTMP12, %%ZTMP13, %%ZTMP14, %%ZTMP15,\
                %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                %%ZTMP20, %%ZTMP21, %%ZTMP22, \
                %%ADDBE_4x4, %%ADDBE_1234, \
                %%GL, %%GH, %%GM, \
                first_time, %%ENC_DEC, data_in_out_offset, %%AAD_HASHz

        ;; ==== save the last counter block
        vpshufb         %%CTR_BLOCKx, XWORD(%%SHUF_MASK)
        vmovdqa64       XWORD(%%CTR_BLOCK_SAVE), %%CTR_BLOCKx

        ;; ==== GHASH 2 x 16 blocks and follow with reduction
        GHASH_16        mid, %%GH, %%GM, %%GL, rsp, STACK_LOCAL_OFFSET, (16 * 16), %%GDATA_KEY, HashKey_32, 0, no_hash_input, \
                        %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9

        GHASH_16        end, %%GH, %%GM, %%GL, rsp, STACK_LOCAL_OFFSET, (32 * 16), %%GDATA_KEY, HashKey_16, 0, no_hash_input, \
                        %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9

        sub             %%LENGTH, (16 * 16)
        add             %%DATA_OFFSET, (16 * 16)

        ;; fall through to reduction part

%%_integrate_and_reduce:
        ;; integrate TM into TH and TL
        vpsrldq         %%ZTMP0, %%GM, 8
        vpslldq         %%ZTMP1, %%GM, 8
        vpxorq          %%GH, %%GH, %%ZTMP0
        vpxorq          %%GL, %%GL, %%ZTMP1

        ;; add TH and TL 128-bit words horizontally
        VHPXORI4x128    %%GH, %%ZTMP0
        VHPXORI4x128    %%GL, %%ZTMP1

        ;; reduction
        vmovdqa64       XWORD(%%ZTMP9), [rel POLY2]
        VCLMUL_REDUCE   XWORD(%%AAD_HASHz), XWORD(%%ZTMP9), XWORD(%%GH), XWORD(%%GL), XWORD(%%ZTMP0), XWORD(%%ZTMP1)

        or              %%LENGTH, %%LENGTH
        jz              %%_ghash_done

%%_message_below_16_blocks:
        ;; Determine how many blocks to process
        ;; - process one additional block if there is a partial block
        mov             %%IA1, %%LENGTH
        add             %%IA1, 15
        shr             %%IA1, 4
        ;; %%IA1 can be in the range from 0 to 16

        GCM_ENC_DEC_SMALL \
                %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%PLAIN_CYPH_LEN, %%ENC_DEC, %%DATA_OFFSET, \
                %%LENGTH, %%IA1, %%CTR_BLOCKx, %%AAD_HASHx, %%INSTANCE_TYPE, \
                %%ZTMP0,  %%ZTMP1,  %%ZTMP2,  %%ZTMP3,  \
                %%ZTMP4,  %%ZTMP5,  %%ZTMP6,  %%ZTMP7,  \
                %%ZTMP8,  %%ZTMP9,  %%ZTMP10, %%ZTMP11, \
                %%ZTMP12, %%ZTMP13, %%ZTMP14, %%ZTMP15, \
                %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                %%ZTMP20, %%ZTMP21, %%ZTMP22, \
                %%IA0, %%IA3, %%MASKREG, %%SHUF_MASK

        vmovdqa64       XWORD(%%CTR_BLOCK_SAVE), %%CTR_BLOCKx

        jmp     %%_ghash_done

%%_message_below_32_blocks:
        ;; 32 > number of blocks > 16

        ;; save the last counter block
        vpshufb         %%CTR_BLOCKx, XWORD(%%SHUF_MASK)
        vmovdqa64       XWORD(%%CTR_BLOCK_SAVE), %%CTR_BLOCKx

        ;; ==== GHASH 16 blocks and follow with reduction
        GHASH_16        start, %%GH, %%GM, %%GL, rsp, STACK_LOCAL_OFFSET, (0 * 16), %%GDATA_KEY, HashKey_16, 0, %%AAD_HASHz, \
                        %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9

        sub             %%LENGTH, (16 * 16)
        add             %%DATA_OFFSET, (16 * 16)
        jmp             %%_integrate_and_reduce

%%_ghash_done:
        vmovdqu64       [%%GDATA_CTX + CurCount], XWORD(%%CTR_BLOCK_SAVE)
        vmovdqu64       [%%GDATA_CTX + AadHash], %%AAD_HASHx
%%_enc_dec_done:

%endmacro                       ; GCM_ENC_DEC

;;; ===========================================================================
;;; ===========================================================================
;;; Encrypt/decrypt the initial 16 blocks
%macro INITIAL_BLOCKS_16 22
%define %%IN            %1      ; [in] input buffer
%define %%OUT           %2      ; [in] output buffer
%define %%KP            %3      ; [in] pointer to expanded keys
%define %%DATA_OFFSET   %4      ; [in] data offset
%define %%GHASH         %5      ; [in] ZMM with AAD (low 128 bits)
%define %%CTR           %6      ; [in] ZMM with CTR BE blocks 4x128 bits
%define %%CTR_CHECK     %7      ; [in/out] GPR with counter overflow check
%define %%ADDBE_4x4     %8      ; [in] ZMM 4x128bits with value 4 (big endian)
%define %%ADDBE_1234    %9      ; [in] ZMM 4x128bits with values 1, 2, 3 & 4 (big endian)
%define %%T0            %10     ; [clobered] temporary ZMM register
%define %%T1            %11     ; [clobered] temporary ZMM register
%define %%T2            %12     ; [clobered] temporary ZMM register
%define %%T3            %13     ; [clobered] temporary ZMM register
%define %%T4            %14     ; [clobered] temporary ZMM register
%define %%T5            %15     ; [clobered] temporary ZMM register
%define %%T6            %16     ; [clobered] temporary ZMM register
%define %%T7            %17     ; [clobered] temporary ZMM register
%define %%T8            %18     ; [clobered] temporary ZMM register
%define %%SHUF_MASK     %19     ; [in] ZMM with BE/LE shuffle mask
%define %%ENC_DEC       %20     ; [in] ENC (encrypt) or DEC (decrypt) selector
%define %%BLK_OFFSET    %21     ; [in] stack frame offset to ciphered blocks
%define %%DATA_DISPL    %22     ; [in] fixed numerical data displacement/offset

%define %%B00_03        %%T5
%define %%B04_07        %%T6
%define %%B08_11        %%T7
%define %%B12_15        %%T8

%assign stack_offset (%%BLK_OFFSET)

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; prepare counter blocks

        cmp             BYTE(%%CTR_CHECK), (256 - 16)
        jae             %%_next_16_overflow
        vpaddd          %%B00_03, %%CTR, %%ADDBE_1234
        vpaddd          %%B04_07, %%B00_03, %%ADDBE_4x4
        vpaddd          %%B08_11, %%B04_07, %%ADDBE_4x4
        vpaddd          %%B12_15, %%B08_11, %%ADDBE_4x4
        jmp             %%_next_16_ok
%%_next_16_overflow:
        vpshufb         %%CTR, %%CTR, %%SHUF_MASK
        vmovdqa64       %%B12_15, [rel ddq_add_4444]
        vpaddd          %%B00_03, %%CTR, [rel ddq_add_1234]
        vpaddd          %%B04_07, %%B00_03, %%B12_15
        vpaddd          %%B08_11, %%B04_07, %%B12_15
        vpaddd          %%B12_15, %%B08_11, %%B12_15
        vpshufb         %%B00_03, %%SHUF_MASK
        vpshufb         %%B04_07, %%SHUF_MASK
        vpshufb         %%B08_11, %%SHUF_MASK
        vpshufb         %%B12_15, %%SHUF_MASK
%%_next_16_ok:
        vshufi64x2      %%CTR, %%B12_15, %%B12_15, 1111_1111b
        add             BYTE(%%CTR_CHECK), 16

        ;; === load 16 blocks of data
        VX512LDR        %%T0, [%%IN + %%DATA_OFFSET + %%DATA_DISPL + (64*0)]
        VX512LDR        %%T1, [%%IN + %%DATA_OFFSET + %%DATA_DISPL + (64*1)]
        VX512LDR        %%T2, [%%IN + %%DATA_OFFSET + %%DATA_DISPL + (64*2)]
        VX512LDR        %%T3, [%%IN + %%DATA_OFFSET + %%DATA_DISPL + (64*3)]

        ;; move to AES encryption rounds
%assign i 0
        vbroadcastf64x2 %%T4, [%%KP + (16*i)]
        vpxorq          %%B00_03, %%B00_03, %%T4
        vpxorq          %%B04_07, %%B04_07, %%T4
        vpxorq          %%B08_11, %%B08_11, %%T4
        vpxorq          %%B12_15, %%B12_15, %%T4
%assign i (i + 1)

%rep NROUNDS
        vbroadcastf64x2 %%T4, [%%KP + (16*i)]
        vaesenc         %%B00_03, %%B00_03, %%T4
        vaesenc         %%B04_07, %%B04_07, %%T4
        vaesenc         %%B08_11, %%B08_11, %%T4
        vaesenc         %%B12_15, %%B12_15, %%T4
%assign i (i + 1)
%endrep

        vbroadcastf64x2 %%T4, [%%KP + (16*i)]
        vaesenclast     %%B00_03, %%B00_03, %%T4
        vaesenclast     %%B04_07, %%B04_07, %%T4
        vaesenclast     %%B08_11, %%B08_11, %%T4
        vaesenclast     %%B12_15, %%B12_15, %%T4

        ;;  xor against text
        vpxorq          %%B00_03, %%B00_03, %%T0
        vpxorq          %%B04_07, %%B04_07, %%T1
        vpxorq          %%B08_11, %%B08_11, %%T2
        vpxorq          %%B12_15, %%B12_15, %%T3

        ;; store
        VX512STR        [%%OUT + %%DATA_OFFSET + %%DATA_DISPL + (64*0)], %%B00_03
        VX512STR        [%%OUT + %%DATA_OFFSET + %%DATA_DISPL + (64*1)], %%B04_07
        VX512STR        [%%OUT + %%DATA_OFFSET + %%DATA_DISPL + (64*2)], %%B08_11
        VX512STR        [%%OUT + %%DATA_OFFSET + %%DATA_DISPL + (64*3)], %%B12_15

%ifidn  %%ENC_DEC, DEC
        ;; decryption - cipher text needs to go to GHASH phase
        vpshufb         %%B00_03, %%T0, %%SHUF_MASK
        vpshufb         %%B04_07, %%T1, %%SHUF_MASK
        vpshufb         %%B08_11, %%T2, %%SHUF_MASK
        vpshufb         %%B12_15, %%T3, %%SHUF_MASK
%else
        ;; encryption
        vpshufb         %%B00_03, %%B00_03, %%SHUF_MASK
        vpshufb         %%B04_07, %%B04_07, %%SHUF_MASK
        vpshufb         %%B08_11, %%B08_11, %%SHUF_MASK
        vpshufb         %%B12_15, %%B12_15, %%SHUF_MASK
%endif

%ifnidn %%GHASH, no_ghash
        ;; === xor cipher block 0 with GHASH for the next GHASH round
        vpxorq          %%B00_03, %%B00_03, %%GHASH
%endif

        vmovdqa64       [rsp + stack_offset + (0 * 64)], %%B00_03
        vmovdqa64       [rsp + stack_offset + (1 * 64)], %%B04_07
        vmovdqa64       [rsp + stack_offset + (2 * 64)], %%B08_11
        vmovdqa64       [rsp + stack_offset + (3 * 64)], %%B12_15
%endmacro                       ;INITIAL_BLOCKS_16

;;; ===========================================================================

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_COMPLETE Finishes Encryption/Decryption of last partial block after GCM_UPDATE finishes.
; Input: A gcm_key_data * (GDATA_KEY), gcm_context_data (GDATA_CTX).
; Output: Authorization Tag (AUTH_TAG) and Authorization Tag length (AUTH_TAG_LEN)
; Clobbers xmm0-xmm2, xmm5-xmm6, xmm9-xmm11, xmm13-xmm15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_COMPLETE            9
%define %%GDATA_KEY             %1      ; [in] GP with pointer to key structure
%define %%GDATA_CTX             %2      ; [in] GP with pointer to context structure
%define %%AUTH_TAG              %3      ; [in] pointer to store auth tag into (GP or mem)
%define %%AUTH_TAG_LEN          %4      ; [in] length in bytes of auth tag (GP or mem)
%define %%INSTANCE_TYPE         %5      ; [in] instance type "single_call" vs "multi_call"
%define %%MASKREG               %6      ; [clobbered] temporary K register
%define %%IA0                   %7      ; [clobbered] temporary GP
%define %%IA1                   %8      ; [clobbered] temporary GP
%define %%IA2                   %9      ; [clobbered] temporary GP

        ;; @note: xmm14 is hardcoded for hash input in singe_call case

        vmovdqu         xmm13, [%%GDATA_KEY + HashKey]
        ;; Start AES as early as possible
        vmovdqu         xmm9, [%%GDATA_CTX + OrigIV]    ; xmm9 = Y0
        ENCRYPT_SINGLE_BLOCK %%GDATA_KEY, xmm9  ; E(K, Y0)

%ifidn %%INSTANCE_TYPE, multi_call
        ;; If the GCM function is called as a single function call rather
        ;; than invoking the individual parts (init, update, finalize) we
        ;; can remove a write to read dependency on AadHash.
        vmovdqu         xmm14, [%%GDATA_CTX + AadHash]

        ;; Encrypt of the final partial block was already done in the main GCM_ENC_DEC macro.
        ;; It may be required to GHASH it now
        cmp             qword [%%GDATA_CTX + PBlockLen], 0
        je              %%_partial_done

        ;; GHASH computation for the last <16 Byte block
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6

%%_partial_done:
%endif
        vmovq           xmm15, [%%GDATA_CTX + InLen]
        vpinsrq         xmm15, [%%GDATA_CTX + AadLen], 1        ; xmm15 = len(A)||len(C)
        vpsllq          xmm15, xmm15, 3                         ; convert bytes into bits

        vpxor           xmm14, xmm15
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6
        vpshufb         xmm14, [rel SHUF_MASK]         ; perform a 16Byte swap

        vpxor           xmm9, xmm9, xmm14

        ;; xmm9 includes the final TAG
        mov             %%IA0, %%AUTH_TAG             ; r10 = authTag
        mov             %%IA1, %%AUTH_TAG_LEN         ; r11 = auth_tag_len

        cmp             %%IA1, 16
        je              %%_T_16

        cmp             %%IA1, 12
        je              %%_T_12

        cmp             %%IA1, 8
        je              %%_T_8

        lea             %%IA2, [rel byte64_len_to_mask_table]
        kmovq           %%MASKREG, [%%IA2 + %%IA1*8]
        vmovdqu8        [%%IA0]{%%MASKREG}, xmm9
        jmp             %%_return_T_done
%%_T_8:
        vmovq           [%%IA0], xmm9
        jmp             %%_return_T_done
%%_T_12:
        vmovq           [%%IA0], xmm9
        vpextrd         [%%IA0 + 8], xmm9, 2
        jmp             %%_return_T_done
%%_T_16:
        vmovdqu         [%%IA0], xmm9

%%_return_T_done:

%ifdef SAFE_DATA
        ;; Clear sensitive data from context structure
        vpxor           xmm0, xmm0
        vmovdqu         [%%GDATA_CTX + AadHash], xmm0
%ifidn %%INSTANCE_TYPE, multi_call
        vmovdqu         [%%GDATA_CTX + PBlockEncKey], xmm0
%endif
%endif
%endmacro ; GCM_COMPLETE


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_precomp_128_vaes_avx512 /
;       aes_gcm_precomp_192_vaes_avx512 /
;       aes_gcm_precomp_256_vaes_avx512
;       (struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(precomp,_),function,)
FN_NAME(precomp,_):
        endbranch64
;; Parameter is passed through register
%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_precomp
%endif

        FUNC_SAVE

        vpxor   xmm6, xmm6
        ENCRYPT_SINGLE_BLOCK    arg1, xmm6              ; xmm6 = HashKey

        vpshufb  xmm6, [rel SHUF_MASK]
        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        vmovdqa  xmm2, xmm6
        vpsllq   xmm6, xmm6, 1
        vpsrlq   xmm2, xmm2, 63
        vmovdqa  xmm1, xmm2
        vpslldq  xmm2, xmm2, 8
        vpsrldq  xmm1, xmm1, 8
        vpor     xmm6, xmm6, xmm2
        ;reduction
        vpshufd  xmm2, xmm1, 00100100b
        vpcmpeqd xmm2, [rel TWOONE]
        vpand    xmm2, xmm2, [rel POLY]
        vpxor    xmm6, xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu  [arg1 + HashKey], xmm6                 ; store HashKey<<1 mod poly


        PRECOMPUTE arg1, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm7, xmm8

        FUNC_RESTORE
exit_precomp:

        ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_128_vaes_avx512 / aes_gcm_init_192_vaes_avx512 / aes_gcm_init_256_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(init,_),function,)
FN_NAME(init,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_init

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_init

        ;; Check IV != NULL
        cmp     arg3, 0
        jz      exit_init

        ;; Check if aad_len == 0
        cmp     arg5, 0
        jz      skip_aad_check_init

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg4, 0
        jz      exit_init

skip_aad_check_init:
%endif
        GCM_INIT arg1, arg2, arg3, arg4, arg5, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, multi_call

exit_init:

        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_var_iv_128_vaes_avx512 / aes_gcm_init_var_iv_192_vaes_avx512 /
;       aes_gcm_init_var_iv_256_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8        *iv,
;        const u64 iv_len,
;        const u8  *aad,
;        const u64 aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(init_var_iv,_),function,)
FN_NAME(init_var_iv,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_init_IV

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_init_IV

        ;; Check IV != NULL
        cmp     arg3, 0
        jz      exit_init_IV

        ;; Check iv_len != 0
        cmp     arg4, 0
        jz      exit_init_IV

        ;; Check if aad_len == 0
        cmp     arg6, 0
        jz      skip_aad_check_init_IV

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg5, 0
        jz      exit_init_IV

skip_aad_check_init_IV:
%endif
        cmp     arg4, 12
        je      iv_len_12_init_IV

        GCM_INIT arg1, arg2, arg3, arg5, arg6, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, multi_call, arg4
        jmp     skip_iv_len_12_init_IV

iv_len_12_init_IV:
        GCM_INIT arg1, arg2, arg3, arg5, arg6, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, multi_call

skip_iv_len_12_init_IV:
%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_zmms_asm
%endif
exit_init_IV:


        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_update_vaes_avx512 / aes_gcm_enc_192_update_vaes_avx512 /
;       aes_gcm_enc_256_update_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      plaintext_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_update_),function,)
FN_NAME(enc,_update_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_update_enc

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_update_enc

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      exit_update_enc

        ;; Check out != NULL (plaintext_len != 0)
        cmp     arg3, 0
        jz      exit_update_enc

        ;; Check in != NULL (plaintext_len != 0)
        cmp     arg4, 0
        jz      exit_update_enc
%endif
        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, ENC, multi_call

exit_update_enc:
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_update_vaes_avx512 / aes_gcm_dec_192_update_vaes_avx512 /
;       aes_gcm_dec_256_update_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      plaintext_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_update_),function,)
FN_NAME(dec,_update_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_update_dec

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_update_dec

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      exit_update_dec

        ;; Check out != NULL (plaintext_len != 0)
        cmp     arg3, 0
        jz      exit_update_dec

        ;; Check in != NULL (plaintext_len != 0)
        cmp     arg4, 0
        jz      exit_update_dec
%endif

        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, DEC, multi_call

exit_update_dec:
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_finalize_vaes_avx512 / aes_gcm_enc_192_finalize_vaes_avx512 /
;       aes_gcm_enc_256_finalize_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_finalize_),function,)
FN_NAME(enc,_finalize_):
        endbranch64
;; All parameters are passed through registers
%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_enc_fin

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_enc_fin

        ;; Check auth_tag != NULL
        cmp     arg3, 0
        jz      exit_enc_fin

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg4, 0
        jz      exit_enc_fin

        cmp     arg4, 16
        ja      exit_enc_fin
%endif

        FUNC_SAVE
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call, k1, r10, r11, r12

        FUNC_RESTORE

exit_enc_fin:
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_finalize_vaes_avx512 / aes_gcm_dec_192_finalize_vaes_avx512
;       aes_gcm_dec_256_finalize_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_finalize_),function,)
FN_NAME(dec,_finalize_):
        endbranch64
;; All parameters are passed through registers
%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_dec_fin

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_dec_fin

        ;; Check auth_tag != NULL
        cmp     arg3, 0
        jz      exit_dec_fin

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg4, 0
        jz      exit_dec_fin

        cmp     arg4, 16
        ja      exit_dec_fin
%endif

        FUNC_SAVE
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call, k1, r10, r11, r12

        FUNC_RESTORE

exit_dec_fin:
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_vaes_avx512 / aes_gcm_enc_192_vaes_avx512 / aes_gcm_enc_256_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      plaintext_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_),function,)
FN_NAME(enc,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_enc

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_enc

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      exit_enc

        ;; Check auth_tag != NULL
        cmp     arg9, 0
        jz      exit_enc

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg10, 0
        jz      exit_enc

        cmp     arg10, 16
        ja      exit_enc

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_enc

        ;; Check out != NULL (plaintext_len != 0)
        cmp     arg3, 0
        jz      exit_enc

        ;; Check in != NULL (plaintext_len != 0)
        cmp     arg4, 0
        jz      exit_enc

skip_in_out_check_enc:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      skip_aad_check_enc

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg7, 0
        jz      exit_enc

skip_aad_check_enc:
%endif
        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, ENC, single_call
        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call, k1, r10, r11, r12

exit_enc:
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_vaes_avx512 / aes_gcm_dec_192_vaes_avx512 / aes_gcm_dec_256_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      plaintext_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_),function,)
FN_NAME(dec,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_dec

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_dec

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      exit_dec

        ;; Check auth_tag != NULL
        cmp     arg9, 0
        jz      exit_dec

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg10, 0
        jz      exit_dec

        cmp     arg10, 16
        ja      exit_dec

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_dec

        ;; Check out != NULL (plaintext_len != 0)
        cmp     arg3, 0
        jz      exit_dec

        ;; Check in != NULL (plaintext_len != 0)
        cmp     arg4, 0
        jz      exit_dec

skip_in_out_check_dec:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      skip_aad_check_dec

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg7, 0
        jz      exit_dec

skip_aad_check_dec:
%endif
        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, DEC, single_call
        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call, k1, r10, r11, r12

exit_dec:
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_var_iv_128_vaes_avx512 / aes_gcm_enc_var_iv_192_vaes_avx512 /
;       aes_gcm_enc_var_iv_256_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8        *out,
;        const u8  *in,
;        u64       plaintext_len,
;        u8        *iv,
;        const u64 iv_len,
;        const u8  *aad,
;        const u64 aad_len,
;        u8        *auth_tag,
;        const u64 auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc_var_iv,_),function,)
FN_NAME(enc_var_iv,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_enc_IV

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_enc_IV

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      exit_enc_IV

        ;; Check IV len != 0
        cmp     arg7, 0
        jz      exit_enc_IV

        ;; Check auth_tag != NULL
        cmp     arg10, 0
        jz      exit_enc_IV

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg11, 0
        jz      exit_enc_IV

        cmp     arg11, 16
        ja      exit_enc_IV

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_enc_IV

        ;; Check out != NULL (plaintext_len != 0)
        cmp     arg3, 0
        jz      exit_enc_IV

        ;; Check in != NULL (plaintext_len != 0)
        cmp     arg4, 0
        jz      exit_enc_IV

skip_in_out_check_enc_IV:
        ;; Check if aad_len == 0
        cmp     arg9, 0
        jz      skip_aad_check_enc_IV

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg8, 0
        jz      exit_enc_IV

skip_aad_check_enc_IV:
%endif
        cmp     arg7, 12
        je      iv_len_12_enc_IV

        GCM_INIT arg1, arg2, arg6, arg8, arg9, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call, arg7
        jmp     skip_iv_len_12_enc_IV

iv_len_12_enc_IV:
        GCM_INIT arg1, arg2, arg6, arg8, arg9, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call

skip_iv_len_12_enc_IV:
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, ENC, single_call
        GCM_COMPLETE arg1, arg2, arg10, arg11, single_call, k1, r10, r11, r12

exit_enc_IV:
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_vaes_avx512 / aes_gcm_dec_192_vaes_avx512 /
;       aes_gcm_dec_256_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8        *out,
;        const u8  *in,
;        u64       plaintext_len,
;        u8        *iv,
;        const u64 iv_len,
;        const u8  *aad,
;        const u64 aad_len,
;        u8        *auth_tag,
;        const u64 auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec_var_iv,_),function,)
FN_NAME(dec_var_iv,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_dec_IV

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_dec_IV

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      exit_dec_IV

        ;; Check IV len != 0
        cmp     arg7, 0
        jz      exit_dec_IV

        ;; Check auth_tag != NULL
        cmp     arg10, 0
        jz      exit_dec_IV

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg11, 0
        jz      exit_dec_IV

        cmp     arg11, 16
        ja      exit_dec_IV

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_dec_IV

        ;; Check out != NULL (plaintext_len != 0)
        cmp     arg3, 0
        jz      exit_dec_IV

        ;; Check in != NULL (plaintext_len != 0)
        cmp     arg4, 0
        jz      exit_dec_IV

skip_in_out_check_dec_IV:
        ;; Check if aad_len == 0
        cmp     arg9, 0
        jz      skip_aad_check_dec_IV

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg8, 0
        jz      exit_dec_IV

skip_aad_check_dec_IV:
%endif
        cmp     arg7, 12
        je      iv_len_12_dec_IV

        GCM_INIT arg1, arg2, arg6, arg8, arg9, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm12, \
                zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call, arg7
        jmp     skip_iv_len_12_dec_IV

iv_len_12_dec_IV:
        GCM_INIT arg1, arg2, arg6, arg8, arg9, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call

skip_iv_len_12_dec_IV:
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, DEC, single_call
        GCM_COMPLETE arg1, arg2, arg10, arg11, single_call, k1, r10, r11, r12

exit_dec_IV:
        FUNC_RESTORE
        ret

%ifdef GCM128_MODE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   ghash_pre_avx512
;       (const void *key, struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(ghash_pre_vaes_avx512,function,)
ghash_pre_vaes_avx512:
        endbranch64
;; Parameter is passed through register
%ifdef SAFE_PARAM
        ;; Check key != NULL
        cmp     arg1, 0
        jz      exit_ghash_pre

        ;; Check key_data != NULL
        cmp     arg2, 0
        jz      exit_ghash_pre
%endif

        FUNC_SAVE

        vmovdqu xmm6, [arg1]
        vpshufb  xmm6, [rel SHUF_MASK]
        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        vmovdqa  xmm2, xmm6
        vpsllq   xmm6, xmm6, 1
        vpsrlq   xmm2, xmm2, 63
        vmovdqa  xmm1, xmm2
        vpslldq  xmm2, xmm2, 8
        vpsrldq  xmm1, xmm1, 8
        vpor     xmm6, xmm6, xmm2
        ;reduction
        vpshufd  xmm2, xmm1, 00100100b
        vpcmpeqd xmm2, [rel TWOONE]
        vpand    xmm2, xmm2, [rel POLY]
        vpxor    xmm6, xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu  [arg2 + HashKey], xmm6                 ; store HashKey<<1 mod poly

        PRECOMPUTE arg2, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm7, xmm8

        FUNC_RESTORE
exit_ghash_pre:

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   ghash_vaes_avx512
;        const struct gcm_key_data *key_data,
;        const void   *in,
;        const u64    in_len,
;        void         *io_tag,
;        const u64    tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(ghash_vaes_avx512,function,)
ghash_vaes_avx512:
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_ghash

        ;; Check in != NULL
        cmp     arg2, 0
        jz      exit_ghash

        ;; Check in_len != 0
        cmp     arg3, 0
        jz      exit_ghash

        ;; Check tag != NULL
        cmp     arg4, 0
        jz      exit_ghash

        ;; Check tag_len != 0
        cmp     arg5, 0
        jz      exit_ghash
%endif

        ;; copy tag to xmm0
        vmovdqu	xmm0, [arg4]
        vpshufb xmm0, [rel SHUF_MASK] ; perform a 16Byte swap

        CALC_AAD_HASH arg2, arg3, xmm0, arg1, zmm1, zmm2, zmm3, zmm4, zmm5, \
                      zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, \
                      zmm15, zmm16, zmm17, zmm18, zmm19, r10, r11, r12, k1

        vpshufb xmm0, [rel SHUF_MASK] ; perform a 16Byte swap

        simd_store_avx arg4, xmm0, arg5, r12, rax

exit_ghash:
        FUNC_RESTORE

        ret
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; PARTIAL_BLOCK_GMAC
;;; Handles the tag partial blocks between update calls.
;;; Requires the input data be at least 1 byte long.
;;; Output:
;;; Updated AAD_HASH, DATA_OFFSET and GDATA_CTX
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PARTIAL_BLOCK_GMAC 20
%define %%GDATA_KEY             %1  ; [in] Key pointer
%define %%GDATA_CTX             %2  ; [in] context pointer
%define %%PLAIN_IN              %3  ; [in] input buffer
%define %%PLAIN_LEN             %4  ; [in] buffer length
%define %%DATA_OFFSET           %5  ; [out] data offset
%define %%AAD_HASH              %6  ; [out] updated GHASH value
%define %%GPTMP0                %7  ; [clobbered] GP temporary register
%define %%GPTMP1                %8  ; [clobbered] GP temporary register
%define %%GPTMP2                %9  ; [clobbered] GP temporary register
%define %%ZTMP0                 %10 ; [clobbered] ZMM temporary register
%define %%ZTMP1                 %11 ; [clobbered] ZMM temporary register
%define %%ZTMP2                 %12 ; [clobbered] ZMM temporary register
%define %%ZTMP3                 %13 ; [clobbered] ZMM temporary register
%define %%ZTMP4                 %14 ; [clobbered] ZMM temporary register
%define %%ZTMP5                 %15 ; [clobbered] ZMM temporary register
%define %%ZTMP6                 %16 ; [clobbered] ZMM temporary register
%define %%ZTMP7                 %17 ; [clobbered] ZMM temporary register
%define %%ZTMP8                 %18 ; [clobbered] ZMM temporary register
%define %%ZTMP9                 %19 ; [clobbered] ZMM temporary register
%define %%MASKREG               %20 ; [clobbered] mask temporary register

%define %%XTMP0 XWORD(%%ZTMP0)
%define %%XTMP1 XWORD(%%ZTMP1)
%define %%XTMP2 XWORD(%%ZTMP2)
%define %%XTMP3 XWORD(%%ZTMP3)
%define %%XTMP4 XWORD(%%ZTMP4)
%define %%XTMP5 XWORD(%%ZTMP5)
%define %%XTMP6 XWORD(%%ZTMP6)
%define %%XTMP7 XWORD(%%ZTMP7)
%define %%XTMP8 XWORD(%%ZTMP8)
%define %%XTMP9 XWORD(%%ZTMP9)

%define %%LENGTH        %%GPTMP0
%define %%IA0           %%GPTMP1
%define %%IA1           %%GPTMP2

        mov             %%LENGTH, [%%GDATA_CTX + PBlockLen]
        or              %%LENGTH, %%LENGTH
        je              %%_partial_block_done           ;Leave Macro if no partial blocks

        READ_SMALL_DATA_INPUT   %%XTMP4, %%PLAIN_IN, %%PLAIN_LEN, %%IA0, %%MASKREG

        vmovdqu64       %%XTMP2, [%%GDATA_KEY + HashKey]

        ;; adjust the shuffle mask pointer to be able to shift right %%LENGTH bytes
        ;; (16 - %%LENGTH) is the number of bytes in plaintext mod 16)
        lea             %%IA0, [rel SHIFT_MASK]
        add             %%IA0, %%LENGTH
        vmovdqu64       %%XTMP3, [%%IA0]   ; shift right shuffle mask

        ;; Determine if partial block is not being filled and shift mask accordingly
        mov             %%IA1, %%PLAIN_LEN
        add             %%IA1, %%LENGTH
        sub             %%IA1, 16
        jge             %%_no_extra_mask
        sub             %%IA0, %%IA1
%%_no_extra_mask:
        ;; get the appropriate mask to mask out bottom %%LENGTH bytes of %%XTMP1
        ;; - mask out bottom %%LENGTH bytes of %%XTMP1
        vmovdqu64       %%XTMP0, [%%IA0 + ALL_F - SHIFT_MASK]

        vpand           %%XTMP4, %%XTMP0
        vpshufb         %%XTMP4, [rel SHUF_MASK]
        vpshufb         %%XTMP4, %%XTMP3
        vpxorq          %%AAD_HASH, %%XTMP4
        cmp             %%IA1, 0
        jl              %%_partial_incomplete

        ;; GHASH computation for the last <16 Byte block
        GHASH_MUL       %%AAD_HASH, %%XTMP2, %%XTMP5, %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9

        mov             qword [%%GDATA_CTX + PBlockLen], 0

        ;;  Set %%LENGTH to be the number of bytes to skip after this macro
        mov             %%IA0, %%LENGTH
        mov             %%LENGTH, 16
        sub             %%LENGTH, %%IA0
        jmp             %%_ghash_done

%%_partial_incomplete:
%ifidn __OUTPUT_FORMAT__, win64
        mov             %%IA0, %%PLAIN_LEN
        add             [%%GDATA_CTX + PBlockLen], %%IA0
%else
        add             [%%GDATA_CTX + PBlockLen], %%PLAIN_LEN
%endif
        mov             %%LENGTH, %%PLAIN_LEN

%%_ghash_done:
        vmovdqu64       [%%GDATA_CTX + AadHash], %%AAD_HASH

        mov             %%DATA_OFFSET, %%LENGTH
%%_partial_block_done:
%endmacro ; PARTIAL_BLOCK_GMAC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   imb_aes_gmac_update_128_vaes_avx512 /
;       imb_aes_gmac_update_192_vaes_avx512 /
;       imb_aes_gmac_update_256_vaes_avx512
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        const   u8 *in,
;        const   u64 plaintext_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(GMAC_FN_NAME(update),function,)
GMAC_FN_NAME(update):
        endbranch64
	FUNC_SAVE

        ;; Check if plaintext_len == 0
	cmp	arg4, 0
	je	exit_gmac_update

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      exit_gmac_update

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      exit_gmac_update

        ;; Check in != NULL (plaintext_len != 0)
        cmp     arg3, 0
        jz      exit_gmac_update
%endif

        ; Increment size of "AAD length" for GMAC
        add     [arg2 + AadLen], arg4

        ;; Deal with previous partial block
	xor	r11, r11
	vmovdqu64	xmm8, [arg2 + AadHash]

	PARTIAL_BLOCK_GMAC arg1, arg2, arg3, arg4, r11, xmm8, r10, r12, rax, \
                           zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, \
                           zmm9, zmm10, k1

        ; CALC_AAD_HASH needs to deal with multiple of 16 bytes
        sub     arg4, r11
        add     arg3, r11

        vmovq   xmm14, arg4 ; Save remaining length
        and     arg4, -16 ; Get multiple of 16 bytes

        or      arg4, arg4
        jz      no_full_blocks

        ;; Calculate GHASH of this segment
        CALC_AAD_HASH arg3, arg4, xmm8, arg1, zmm1, zmm2, zmm3, zmm4, zmm5, \
                      zmm6, zmm7, zmm9, zmm10, zmm11, zmm12, zmm13, zmm15, \
                      zmm16, zmm17, zmm18, zmm19, zmm20, r10, r11, r12, k1
	vmovdqu64	[arg2 + AadHash], xmm8	; ctx_data.aad hash = aad_hash

no_full_blocks:
        add     arg3, arg4 ; Point at partial block

        vmovq   arg4, xmm14 ; Restore original remaining length
        and     arg4, 15
        jz      exit_gmac_update

        ; Save next partial block
        mov	[arg2 + PBlockLen], arg4
        READ_SMALL_DATA_INPUT xmm1, arg3, arg4, r11, k1
        vpshufb xmm1, [rel SHUF_MASK]
        vpxorq   xmm8, xmm1
        vmovdqu64 [arg2 + AadHash], xmm8

exit_gmac_update:
	FUNC_RESTORE

	ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
