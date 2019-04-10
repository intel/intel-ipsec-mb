;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2018-2019, Intel Corporation All rights reserved.
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
%include "gcm_defines.asm"
%include "mb_mgr_datastruct.asm"
%include "job_aes_hmac.asm"
%include "include/memcpy.asm"

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
%endif

%ifdef GCM192_MODE
%define NROUNDS 11
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _192 %+ y %+ vaes_avx512
%endif

%ifdef GCM256_MODE
%define NROUNDS 13
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _256 %+ y %+ vaes_avx512
%endif

section .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Stack frame definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     (10*16) ; space for 10 XMM registers
        %define GP_STORAGE      (10*8)  ; space for 9 GP registers + 1 for alignment
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      (8*8)   ; space for 7 GP registers + 1 for alignment
%endif
%define LOCAL_STORAGE           (2*8)   ; space for 1 GP register + 1 for alignment

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; GHASH_MUL MACRO to implement: Data*HashKey mod (128,127,126,121,0)
;;; Input: A and B (128-bits each, bit-reflected)
;;; Output: C = A*B*x mod poly, (i.e. >>1 )
;;; To compute GH = GH*HashKey mod poly, give HK = HashKey<<1 mod poly as input
;;; GH = GH * HK * x mod poly which is equivalent to GH*HashKey mod poly.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GHASH_MUL  7
%define %%GH %1         ; 16 Bytes
%define %%HK %2         ; 16 Bytes
%define %%T1 %3
%define %%T2 %4
%define %%T3 %5
%define %%T4 %6
%define %%T5 %7
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
%macro  PRECOMPUTE 8
%define %%GDATA %1
%define %%HK    %2
%define %%T1    %3
%define %%T2    %4
%define %%T3    %5
%define %%T4    %6
%define %%T5    %7
%define %%T6    %8

        ; Haskey_i_k holds XORed values of the low and high parts of the Haskey_i
        vmovdqa  %%T5, %%HK

        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^2<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_2], %%T5                    ;  [HashKey_2] = HashKey^2<<1 mod poly
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_2_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^3<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_3], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_3_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^4<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_4], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_4_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^5<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_5], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_5_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^6<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_6], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_6_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^7<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_7], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_7_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^8<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_8], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_8_k], %%T1
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
%macro  CALC_AAD_HASH   18
%define %%A_IN          %1      ; [in] AAD text pointer
%define %%A_LEN         %2      ; [in] AAD length
%define %%AAD_HASH      %3      ; [out] xmm ghash value
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
%define %%T1            %15     ; [clobbered] GP register
%define %%T2            %16     ; [clobbered] GP register
%define %%T3            %17     ; [clobbered] GP register
%define %%MASKREG       %18     ; [clobbered] mask register

%define %%SHFMSK %%ZT9
%define %%POLY   %%ZT8
%define %%TH     %%ZT7
%define %%TM     %%ZT6
%define %%TL     %%ZT5

        mov             %%T1, %%A_IN            ; T1 = AAD
        mov             %%T2, %%A_LEN           ; T2 = aadLen
        vpxorq          %%AAD_HASH, %%AAD_HASH

        vmovdqa64       %%SHFMSK, [rel SHUF_MASK]
        vmovdqa64       %%POLY, [rel POLY2]

%%_get_AAD_loop128:
        cmp             %%T2, 128
        jl              %%_exit_AAD_loop128

        vmovdqu64       %%ZT2, [%%T1 + 64*0]  ; LO blocks (0-3)
        vmovdqu64       %%ZT1, [%%T1 + 64*1]  ; HI blocks (4-7)
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT1, %%SHFMSK

        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH)

        VCLMUL_STEP1    %%GDATA_KEY, %%ZT1, %%ZT0, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%GDATA_KEY, %%ZT1, %%ZT2, %%ZT0, %%ZT3, %%ZT4, %%TH, %%TM, %%TL

        ;; result in %%ZT1(H):%%ZT2(L)
        ;; reduce and put the result in AAD_HASH
        VCLMUL_REDUCE   %%AAD_HASH, XWORD(%%POLY), XWORD(%%ZT1), XWORD(%%ZT2), \
                XWORD(%%ZT0), XWORD(%%ZT3)

        sub             %%T2, 128
        je              %%_CALC_AAD_done

        add             %%T1, 128
        jmp             %%_get_AAD_loop128

%%_exit_AAD_loop128:
        or              %%T2, %%T2
        jz              %%_CALC_AAD_done

        ;; prep mask source address
        lea             %%T3, [rel byte64_len_to_mask_table]
        lea             %%T3, [%%T3 + %%T2*8]

        ;; calculate number of blocks to ghash (including partial bytes)
        add             %%T2, 15
        and             %%T2, -16       ; 1 to 8 blocks possible here
        shr             %%T2, 4
        cmp             %%T2, 7
        je              %%_AAD_blocks_7
        cmp             %%T2, 6
        je              %%_AAD_blocks_6
        cmp             %%T2, 5
        je              %%_AAD_blocks_5
        cmp             %%T2, 4
        je              %%_AAD_blocks_4
        cmp             %%T2, 3
        je              %%_AAD_blocks_3
        cmp             %%T2, 2
        je              %%_AAD_blocks_2
        cmp             %%T2, 1
        je              %%_AAD_blocks_1
        ;; fall through for 8 blocks

        ;; The flow of each of these cases is identical:
        ;; - load blocks plain text
        ;; - shuffle loaded blocks
        ;; - xor in current hash value into block 0
        ;; - perform up multiplications with ghash keys
        ;; - jump to reduction code
%%_AAD_blocks_8:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT2, [%%T1 + 64*0]
        vmovdqu8        %%ZT1{%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT1, %%SHFMSK
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH) ; xor in current ghash
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 8
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 8
        jmp             %%_AAD_blocks_done

%%_AAD_blocks_7:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT2, [%%T1 + 64*0]
        vmovdqu8        %%ZT1{%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         %%ZT1, %%SHFMSK
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH) ; xor in current ghash
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 7
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 7
        jmp             %%_AAD_blocks_done

%%_AAD_blocks_6:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT2, [%%T1 + 64*0]
        vmovdqu8        YWORD(%%ZT1){%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         YWORD(%%ZT1), YWORD(%%SHFMSK)
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH)
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 6
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 6
        jmp             %%_AAD_blocks_done

%%_AAD_blocks_5:
        sub             %%T3, (64 * 8)
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT2, [%%T1 + 64*0]
        vmovdqu8        XWORD(%%ZT1){%%MASKREG}{z}, [%%T1 + 64*1]
        vpshufb         %%ZT2, %%SHFMSK
        vpshufb         XWORD(%%ZT1), XWORD(%%SHFMSK)
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH)
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 5
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 5
        jmp             %%_AAD_blocks_done

%%_AAD_blocks_4:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT2{%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         %%ZT2, %%SHFMSK
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH)
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 4
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 4
        jmp             %%_AAD_blocks_done

%%_AAD_blocks_3:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        %%ZT2{%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         %%ZT2, %%SHFMSK
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH)
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 3
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 3
        jmp             %%_AAD_blocks_done

%%_AAD_blocks_2:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        YWORD(%%ZT2){%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         YWORD(%%ZT2), YWORD(%%SHFMSK)
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH)
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 2
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 2
        jmp             %%_AAD_blocks_done

%%_AAD_blocks_1:
        kmovq           %%MASKREG, [%%T3]
        vmovdqu8        XWORD(%%ZT2){%%MASKREG}{z}, [%%T1 + 64*0]
        vpshufb         XWORD(%%ZT2), XWORD(%%SHFMSK)
        vpxorq          %%ZT2, %%ZT2, ZWORD(%%AAD_HASH)
        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT1, %%ZT0, %%ZT3, %%TH, %%TM, %%TL, 1
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT1, %%ZT2, \
                %%ZT0, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, 1

%%_AAD_blocks_done:
        ;; Multiplications have been done. Do the reduction now
        VCLMUL_REDUCE   %%AAD_HASH, XWORD(%%POLY), XWORD(%%ZT1), XWORD(%%ZT2), \
                        XWORD(%%ZT0), XWORD(%%ZT3)
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
;;; This macro is used to "warm-up" pipeline for GHASH_8_ENCRYPT_8_PARALLEL
;;; macro code. It is called only for data lenghts 128 and above.
;;; The flow is as follows:
;;; - encrypt the initial %%num_initial_blocks blocks (can be 0)
;;; - encrypt the next 8 blocks and stitch with
;;;   GHASH for the first %%num_initial_blocks
;;;   - the last 8th block can be partial (lengths between 129 and 239)
;;;   - partial block ciphering is handled within this macro
;;;     - top bytes of such block are cleared for
;;;       the subsequent GHASH calculations
;;;   - PBlockEncKey needs to be setup in case of multi-call
;;;     - top bytes of the block need to include encrypted counter block so that
;;;       when handling partial block case text is read and XOR'ed against it.
;;;       This needs to be in un-shuffled format.

%macro INITIAL_BLOCKS 25
%define %%GDATA_KEY             %1      ; [in] pointer to GCM keys
%define %%GDATA_CTX             %2      ; [in] pointer to GCM context
%define %%CYPH_PLAIN_OUT        %3      ; [in] output buffer
%define %%PLAIN_CYPH_IN         %4      ; [in] input buffer
%define %%LENGTH                %5      ; [in/out] number of bytes to process
%define %%DATA_OFFSET           %6      ; [in/out] data offset
%define %%num_initial_blocks    %7      ; [in] can be 0, 1, 2, 3, 4, 5, 6 or 7
%define %%CTR                   %8      ; [in/out] XMM counter block
%define %%AAD_HASH              %9      ; [in/out] ZMM with AAD hash
%define %%ZT1                   %10     ; [out] ZMM cipher blocks 0-3 for GHASH
%define %%ZT2                   %11     ; [out] ZMM cipher blocks 4-7 for GHASH
%define %%ZT3                   %12     ; [clobbered] ZMM temporary
%define %%ZT4                   %13     ; [clobbered] ZMM temporary
%define %%ZT5                   %14     ; [clobbered] ZMM temporary
%define %%ZT6                   %15     ; [clobbered] ZMM temporary
%define %%ZT7                   %16     ; [clobbered] ZMM temporary
%define %%ZT8                   %17     ; [clobbered] ZMM temporary
%define %%ZT9                   %18     ; [clobbered] ZMM temporary
%define %%ZT10                  %19     ; [clobbered] ZMM temporary
%define %%ZT11                  %20     ; [clobbered] ZMM temporary
%define %%ZT12                  %21     ; [clobbered] ZMM temporary
%define %%IA0                   %22     ; [clobbered] GP temporary
%define %%IA1                   %23     ; [clobbered] GP temporary
%define %%ENC_DEC               %24     ; [in] ENC/DEC selector
%define %%MASKREG               %25     ; [clobbered] mask register

%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)
%define %%T3 XWORD(%%ZT3)
%define %%T4 XWORD(%%ZT4)
%define %%T5 XWORD(%%ZT5)
%define %%T6 XWORD(%%ZT6)
%define %%T7 XWORD(%%ZT7)
%define %%T8 XWORD(%%ZT8)
%define %%T9 XWORD(%%ZT9)

%define %%TH %%ZT10
%define %%TM %%ZT11
%define %%TL %%ZT12

%if %%num_initial_blocks > 0
        ;; prepare AES counter blocks
%if %%num_initial_blocks == 1
        vpaddd          %%T3, %%CTR, [rel ONE]
%elif %%num_initial_blocks == 2
        vshufi64x2      YWORD(%%ZT3), YWORD(%%CTR), YWORD(%%CTR), 0
        vpaddd          YWORD(%%ZT3), YWORD(%%ZT3), [rel ddq_add_1234]
%else
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        vpaddd          %%ZT3, ZWORD(%%CTR), [rel ddq_add_1234]
        vpaddd          %%ZT4, ZWORD(%%CTR), [rel ddq_add_5678]
%endif

        ;; get load/store mask
%if (%%num_initial_blocks == 3) || (%%num_initial_blocks == 7)
        mov             %%IA0, 0x0000_ffff_ffff_ffff
        kmovq           %%MASKREG, %%IA0
%endif

        ;; extract new counter value (%%T3)
        ;; shuffle the counters for AES rounds
%if %%num_initial_blocks == 1
        vmovdqa64       %%CTR, %%T3
        vpshufb         %%T3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 2
        vextracti32x4   %%CTR, YWORD(%%ZT3), (%%num_initial_blocks - 1)
        vpshufb         YWORD(%%ZT3), [rel SHUF_MASK]
%elif %%num_initial_blocks <= 4
        vextracti32x4   %%CTR, %%ZT3, (%%num_initial_blocks - 1)
        vpshufb         %%ZT3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 5
        vmovdqa64       %%CTR, %%T4
        vpshufb         %%ZT3, [rel SHUF_MASK]
        vpshufb         %%T4, [rel SHUF_MASK]
%elif %%num_initial_blocks == 6
        vextracti32x4   %%CTR, YWORD(%%ZT4), (%%num_initial_blocks - 5)
        vpshufb         %%ZT3, [rel SHUF_MASK]
        vpshufb         YWORD(%%ZT4), [rel SHUF_MASK]
%else
        vextracti32x4   %%CTR, %%ZT4, (%%num_initial_blocks - 5)
        vpshufb         %%ZT3, [rel SHUF_MASK]
        vpshufb         %%ZT4, [rel SHUF_MASK]
%endif

        ;; load plain/cipher text
%if %%num_initial_blocks == 1
        vmovdqu8        %%T5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 2
        vmovdqu8        YWORD(%%ZT5), [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 3
        vmovdqu8        %%ZT5{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 4
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 5
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%T6, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%elif %%num_initial_blocks == 6
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        YWORD(%%ZT6), [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%else
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT6{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%endif

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT3, %%ZT4, %%ZT1, %%GDATA_KEY, j, \
                        %%ZT5, %%ZT6, %%num_initial_blocks
%assign j (j + 1)
%endrep

        ;; write cipher/plain text back to output and
        ;; zero bytes outside the mask before hashing
%if %%num_initial_blocks == 1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%T3
%elif %%num_initial_blocks == 2
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], YWORD(%%ZT3)
%elif %%num_initial_blocks == 3
        ;; Blocks 3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{%%MASKREG}, %%ZT3
%elif %%num_initial_blocks == 4
        ;; Blocks 4
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
%elif %%num_initial_blocks == 5
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64], %%T4
%elif %%num_initial_blocks == 6
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64], YWORD(%%ZT4)
%else
        ;; Blocks 7
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, %%ZT4
%endif

        ;; Shuffle the cipher text blocks for hashing part
        ;; ZT5 and ZT6 are expected outputs with blocks for hashing
%ifidn  %%ENC_DEC, DEC
        ;; Decrypt case
        ;; - cipher blocks are in ZT5 & ZT6
%if %%num_initial_blocks == 1
        vpshufb         %%T5, [rel SHUF_MASK]
%elif %%num_initial_blocks == 2
        vpshufb         YWORD(%%ZT5), [rel SHUF_MASK]
%elif %%num_initial_blocks <= 4
        vpshufb         %%ZT5, [rel SHUF_MASK]
%elif %%num_initial_blocks == 5
        vpshufb         %%ZT5, [rel SHUF_MASK]
        vpshufb         %%T6, [rel SHUF_MASK]
%elif %%num_initial_blocks == 6
        vpshufb         %%ZT5, [rel SHUF_MASK]
        vpshufb         YWORD(%%ZT6), [rel SHUF_MASK]
%else
        vpshufb         %%ZT5, [rel SHUF_MASK]
        vpshufb         %%ZT6, [rel SHUF_MASK]
%endif
%else
        ;; Encrypt case
        ;; - cipher blocks are in ZT3 & ZT4
%if %%num_initial_blocks == 1
        vpshufb         %%T5, %%T3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 2
        vpshufb         YWORD(%%ZT5), YWORD(%%ZT3), [rel SHUF_MASK]
%elif %%num_initial_blocks <= 4
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 5
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
        vpshufb         %%T6, %%T4, [rel SHUF_MASK]
%elif %%num_initial_blocks == 6
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
        vpshufb         YWORD(%%ZT6), YWORD(%%ZT4), [rel SHUF_MASK]
%else
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
        vpshufb         %%ZT6, %%ZT4, [rel SHUF_MASK]
%endif
%endif                          ; Encrypt

        ;; adjust data offset and length
        sub             %%LENGTH, (%%num_initial_blocks * 16)
        add             %%DATA_OFFSET, (%%num_initial_blocks * 16)

        ;; At this stage
        ;; - ZT5:ZT6 include cipher blocks to be GHASH'ed

%endif                          ;  %%num_initial_blocks > 0

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; - cipher of %%num_initial_blocks is done
        ;; - prepare counter blocks for the next 8 blocks (ZT3 & ZT4)
        ;;   - save the last block in %%CTR
        ;;   - shuffle the blocks for AES
        ;; - stitch encryption of the new blocks with
        ;;   GHASHING the previous blocks
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        vpaddd          %%ZT3, ZWORD(%%CTR), [rel ddq_add_1234]
        vpaddd          %%ZT4, ZWORD(%%CTR), [rel ddq_add_5678]
        vextracti32x4   %%CTR, %%ZT4, 3

        vpshufb         %%ZT3, [rel SHUF_MASK]
        vpshufb         %%ZT4, [rel SHUF_MASK]

        ;; get text load/store mask (assume full mask by default)
        mov             %%IA0, 0xffff_ffff_ffff_ffff
%if %%num_initial_blocks > 0
        ;; NOTE: 'jge' is always taken for %%num_initial_blocks = 0
        ;;      This macro is executed for lenght 128 and up,
        ;;      zero length is checked in GCM_ENC_DEC.
        ;; We know there is partial block if:
        ;;      LENGTH - 16*num_initial_blocks < 128
        cmp             %%LENGTH, 128
        jge             %%_initial_partial_block_continue
        mov             %%IA1, rcx
        mov             rcx, 128
        sub             rcx, %%LENGTH
        shr             %%IA0, cl
        mov             rcx, %%IA1
%%_initial_partial_block_continue:
%endif
        kmovq           %%MASKREG, %%IA0
        ;; load plain or cipher text
        vmovdqu8        %%ZT1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT2{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]

        ;; === AES ROUND 0
%assign aes_round 0
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT3, %%ZT4, %%ZT8, %%GDATA_KEY, aes_round, \
                        %%ZT1, %%ZT2, 8
%assign aes_round (aes_round + 1)

        ;; ===  GHASH blocks 4-7
%if (%%num_initial_blocks > 0)
        ;; Hash in AES state
        vpxorq          %%ZT5, %%ZT5, %%AAD_HASH

        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT6, %%ZT8, %%ZT9, \
                        %%TH, %%TM, %%TL, %%num_initial_blocks
%endif

        ;; === [1/3] of AES rounds

%rep ((NROUNDS + 1) / 3)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT3, %%ZT4, %%ZT8, %%GDATA_KEY, aes_round, \
                        %%ZT1, %%ZT2, 8
%assign aes_round (aes_round + 1)
%endrep                         ; %rep ((NROUNDS + 1) / 2)

        ;; ===  GHASH blocks 0-3 and gather
%if (%%num_initial_blocks > 0)
        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT6, %%ZT5, \
                %%ZT7, %%ZT8, %%ZT9, \
                %%TH, %%TM, %%TL, %%num_initial_blocks
%endif

        ;; === [2/3] of AES rounds

%rep ((NROUNDS + 1) / 3)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT3, %%ZT4, %%ZT8, %%GDATA_KEY, aes_round, \
                        %%ZT1, %%ZT2, 8
%assign aes_round (aes_round + 1)
%endrep                         ; %rep ((NROUNDS + 1) / 2)

        ;; ===  GHASH reduction

%if (%%num_initial_blocks > 0)
        ;; [out] AAD_HASH - hash output
        ;; [in]  T8 - polynomial
        ;; [in]  T6 - high, T5 - low
        ;; [clobbered] T9, T7 - temporary
        vmovdqu64       %%T8, [rel POLY2]
        VCLMUL_REDUCE   XWORD(%%AAD_HASH), %%T8, %%T6, %%T5, %%T7, %%T9
%endif

        ;; === [3/3] of AES rounds

%rep (((NROUNDS + 1) / 3) + 2)
%if aes_round < (NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT3, %%ZT4, %%ZT8, %%GDATA_KEY, aes_round, \
                        %%ZT1, %%ZT2, 8
%assign aes_round (aes_round + 1)
%endif
%endrep                         ; %rep ((NROUNDS + 1) / 2)

        ;; write cipher/plain text back to output and
        ;; zero bytes outside the mask before hashing
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, %%ZT4

        ;; check if there is partial block
        cmp             %%LENGTH, 128
        jl              %%_initial_save_partial
        ;; adjust offset and length
        add             %%DATA_OFFSET, 128
        sub             %%LENGTH, 128
        jmp             %%_initial_blocks_done
%%_initial_save_partial:
        ;; partial block case
        ;; - save the partial block in unshuffled format
        ;;   - ZT4 is partially XOR'ed with data and top bytes contain
        ;;     encrypted counter block only
        ;; - save number of bytes process in the partial block
        ;; - adjust offset and zero the length
        ;; - clear top bytes of the partial block for subsequent GHASH calculations
        vextracti32x4   [%%GDATA_CTX + PBlockEncKey], %%ZT4, 3
        add             %%DATA_OFFSET, %%LENGTH
        sub             %%LENGTH, (128 - 16)
        mov             [%%GDATA_CTX + PBlockLen], %%LENGTH
        xor             %%LENGTH, %%LENGTH
        vmovdqu8        %%ZT4{%%MASKREG}{z}, %%ZT4
%%_initial_blocks_done:

        ;; Shuffle AES result for GHASH.
%ifidn  %%ENC_DEC, DEC
        ;; Decrypt case
        ;; - cipher blocks are in ZT1 & ZT2
        vpshufb         %%ZT1, [rel SHUF_MASK]
        vpshufb         %%ZT2, [rel SHUF_MASK]
%else
        ;; Encrypt case
        ;; - cipher blocks are in ZT3 & ZT4
        vpshufb         %%ZT1, %%ZT3, [rel SHUF_MASK]
        vpshufb         %%ZT2, %%ZT4, [rel SHUF_MASK]
%endif                          ; Encrypt

        ;; Current hash value is in AAD_HASH

        ;; Combine GHASHed value with the corresponding ciphertext
        vpxorq          %%ZT1, %%ZT1, %%AAD_HASH

%endmacro                       ; INITIAL_BLOCKS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; INITIAL_BLOCKS_PARTIAL macro with support for a partial final block.
;;; It may look similar to INITIAL_BLOCKS but its usage is different:
;;; - It is not meant to cipher counter blocks for the main by8 loop.
;;;   Just ciphers amount of blocks and ghashes them.
;;; - Small packets (<128 bytes) - single or multi call
;;; - Remaining data chunks below 128 bytes (multi buffer code)
;;;
;;; num_initial_blocks is expected to include the partial final block
;;; in the count.
%macro INITIAL_BLOCKS_PARTIAL 23
%define %%GDATA_KEY             %1  ; [in] key pointer
%define %%GDATA_CTX             %2  ; [in] context pointer
%define %%CYPH_PLAIN_OUT        %3  ; [in] text out pointer
%define %%PLAIN_CYPH_IN         %4  ; [in] text out pointer
%define %%LENGTH                %5  ; [in/clobbered] length in bytes
%define %%DATA_OFFSET           %6  ; [in/out] current data offset (updated)
%define %%num_initial_blocks    %7  ; [in] can only be 1, 2, 3, 4, 5, 6, 7 or 8 (not 0)
%define %%CTR                   %8  ; [in/out] current counter value
%define %%HASH_IN_OUT           %9  ; [in/out] XMM ghash in/out value
%define %%ENC_DEC               %10 ; [in] cipher direction (ENC/DEC)
%define %%INSTANCE_TYPE         %11 ; [in] multi_call or single_call
%define %%ZT1                   %12 ; [clobbered] ZMM temporary
%define %%ZT2                   %13 ; [clobbered] ZMM temporary
%define %%ZT3                   %14 ; [clobbered] ZMM temporary
%define %%ZT4                   %15 ; [clobbered] ZMM temporary
%define %%ZT5                   %16 ; [clobbered] ZMM temporary
%define %%ZT6                   %17 ; [clobbered] ZMM temporary
%define %%ZT7                   %18 ; [clobbered] ZMM temporary
%define %%ZT8                   %19 ; [clobbered] ZMM temporary
%define %%ZT9                   %20 ; [clobbered] ZMM temporary
%define %%IA0                   %21 ; [clobbered] GP temporary
%define %%IA1                   %22 ; [clobbered] GP temporary
%define %%MASKREG               %23 ; [clobbered] mask register

%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)
%define %%T3 XWORD(%%ZT3)
%define %%T4 XWORD(%%ZT4)
%define %%T5 XWORD(%%ZT5)
%define %%T6 XWORD(%%ZT6)
%define %%T7 XWORD(%%ZT7)

%define %%TH %%ZT9
%define %%TM %%ZT2              ; safe to use after hash xor in
%define %%TL %%ZT8

        ;; Copy ghash to temp reg
        vmovdqa64       %%T2, %%HASH_IN_OUT

        ;; prepare AES counter blocks
%if %%num_initial_blocks == 1
        vpaddd          %%T3, %%CTR, [rel ONE]
%elif %%num_initial_blocks == 2
        vshufi64x2      YWORD(%%ZT3), YWORD(%%CTR), YWORD(%%CTR), 0
        vpaddd          YWORD(%%ZT3), YWORD(%%ZT3), [rel ddq_add_1234]
%else
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        vpaddd          %%ZT3, ZWORD(%%CTR), [rel ddq_add_1234]
        vpaddd          %%ZT4, ZWORD(%%CTR), [rel ddq_add_5678]
%endif

        ;; get load/store mask
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
%if %%num_initial_blocks > 4
        sub             %%IA1, 64
%endif
        kmovq           %%MASKREG, [%%IA0 + %%IA1*8]

        ;; extract new counter value (%%T3)
        ;; shuffle the counters for AES rounds
%if %%num_initial_blocks == 1
        vmovdqa64       %%CTR, %%T3
        vpshufb         %%T3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 2
        vextracti32x4   %%CTR, YWORD(%%ZT3), (%%num_initial_blocks - 1)
        vpshufb         YWORD(%%ZT3), [rel SHUF_MASK]
%elif %%num_initial_blocks <= 4
        vextracti32x4   %%CTR, %%ZT3, (%%num_initial_blocks - 1)
        vpshufb         %%ZT3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 5
        vmovdqa64       %%CTR, %%T4
        vpshufb         %%ZT3, [rel SHUF_MASK]
        vpshufb         %%T4, [rel SHUF_MASK]
%elif %%num_initial_blocks == 6
        vextracti32x4   %%CTR, YWORD(%%ZT4), (%%num_initial_blocks - 5)
        vpshufb         %%ZT3, [rel SHUF_MASK]
        vpshufb         YWORD(%%ZT4), [rel SHUF_MASK]
%else
        vextracti32x4   %%CTR, %%ZT4, (%%num_initial_blocks - 5)
        vpshufb         %%ZT3, [rel SHUF_MASK]
        vpshufb         %%ZT4, [rel SHUF_MASK]
%endif

        ;; load plain/cipher text
%if %%num_initial_blocks == 1
        vmovdqu8        %%T5{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 2
        vmovdqu8        YWORD(%%ZT5){%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks <= 4
        vmovdqu8        %%ZT5{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 5
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%T6{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%elif %%num_initial_blocks == 6
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        YWORD(%%ZT6){%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%else
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT6{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%endif

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT3, %%ZT4, %%ZT1, %%GDATA_KEY, j, \
                        %%ZT5, %%ZT6, %%num_initial_blocks
%assign j (j + 1)
%endrep

        ;; retrieve the last cipher counter block (partially XOR'ed with text)
        ;; - this is needed for partial block cases
%if %%num_initial_blocks == 1
        vmovdqa64       %%T1, %%T3
%elif %%num_initial_blocks == 2
        vextracti32x4   %%T1, YWORD(%%ZT3), (%%num_initial_blocks - 1)
%elif %%num_initial_blocks <= 4
        ;; Blocks 3 and 4
        vextracti32x4   %%T1, %%ZT3, (%%num_initial_blocks - 1)
%elif %%num_initial_blocks == 5
        vmovdqa64       %%T1, %%T4
%elif %%num_initial_blocks == 6
        vextracti32x4   %%T1, YWORD(%%ZT4), (%%num_initial_blocks - 5)
%else
        ;; Blocks 7 and 8
        vextracti32x4   %%T1, %%ZT4, (%%num_initial_blocks - 5)
%endif

        ;; write cipher/plain text back to output and
        ;; zero bytes outside the mask before hashing
%if %%num_initial_blocks == 1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{%%MASKREG}, %%T3
        vmovdqu8        %%T3{%%MASKREG}{z}, %%T3
%elif %%num_initial_blocks == 2
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{%%MASKREG}, YWORD(%%ZT3)
        vmovdqu8        YWORD(%%ZT3){%%MASKREG}{z}, YWORD(%%ZT3)
%elif %%num_initial_blocks <= 4
        ;; Blocks 3 and 4
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{%%MASKREG}, %%ZT3
        vmovdqu8        %%ZT3{%%MASKREG}{z}, %%ZT3
%elif %%num_initial_blocks == 5
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, %%T4
        vmovdqu8        %%T4{%%MASKREG}{z}, %%T4
%elif %%num_initial_blocks == 6
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, YWORD(%%ZT4)
        vmovdqu8        YWORD(%%ZT4){%%MASKREG}{z}, YWORD(%%ZT4)
%else
        ;; Blocks 7 and 8
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, %%ZT4
        vmovdqu8        %%ZT4{%%MASKREG}{z}, %%ZT4
%endif

        ;; Shuffle the cipher text blocks for hashing part
        ;; ZT5 and ZT6 are expected outputs with blocks for hashing
%ifidn  %%ENC_DEC, DEC
        ;; Decrypt case
        ;; - cipher blocks are in ZT5 & ZT6
%if %%num_initial_blocks == 1
        vpshufb         %%T5, [rel SHUF_MASK]
%elif %%num_initial_blocks == 2
        vpshufb         YWORD(%%ZT5), [rel SHUF_MASK]
%elif %%num_initial_blocks <= 4
        vpshufb         %%ZT5, [rel SHUF_MASK]
%elif %%num_initial_blocks == 5
        vpshufb         %%ZT5, [rel SHUF_MASK]
        vpshufb         %%T6, [rel SHUF_MASK]
%elif %%num_initial_blocks == 6
        vpshufb         %%ZT5, [rel SHUF_MASK]
        vpshufb         YWORD(%%ZT6), [rel SHUF_MASK]
%else
        vpshufb         %%ZT5, [rel SHUF_MASK]
        vpshufb         %%ZT6, [rel SHUF_MASK]
%endif
%else
        ;; Encrypt case
        ;; - cipher blocks are in ZT3 & ZT4
%if %%num_initial_blocks == 1
        vpshufb         %%T5, %%T3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 2
        vpshufb         YWORD(%%ZT5), YWORD(%%ZT3), [rel SHUF_MASK]
%elif %%num_initial_blocks <= 4
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
%elif %%num_initial_blocks == 5
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
        vpshufb         %%T6, %%T4, [rel SHUF_MASK]
%elif %%num_initial_blocks == 6
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
        vpshufb         YWORD(%%ZT6), YWORD(%%ZT4), [rel SHUF_MASK]
%else
        vpshufb         %%ZT5, %%ZT3, [rel SHUF_MASK]
        vpshufb         %%ZT6, %%ZT4, [rel SHUF_MASK]
%endif
%endif                          ; Encrypt

        ;; Extract the last block for partials and multi_call cases
%if %%num_initial_blocks <= 4
        vextracti32x4   %%T7, %%ZT5, %%num_initial_blocks - 1
%else
        vextracti32x4   %%T7, %%ZT6, %%num_initial_blocks - 5
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Hash all but the last block of data
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;; update data offset
%if %%num_initial_blocks > 1
        ;; The final block of data may be <16B
        add     %%DATA_OFFSET, 16 * (%%num_initial_blocks - 1)
        sub     %%LENGTH, 16 * (%%num_initial_blocks - 1)
%endif

%if %%num_initial_blocks < 8
        ;; NOTE: the 'jl' is always taken for num_initial_blocks = 8.
        ;;      This is run in the context of GCM_ENC_DEC_SMALL for length < 128.
        cmp     %%LENGTH, 16
        jl      %%_small_initial_partial_block

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Handle a full length final block - encrypt and hash all blocks
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        sub     %%LENGTH, 16
        add     %%DATA_OFFSET, 16
	mov	[%%GDATA_CTX + PBlockLen], %%LENGTH

        ;; Hash all of the data

        ;; ZT2 - incoming AAD hash (low 128bits)
        ;; ZT5, ZT6 - hold ciphertext
        ;; ZT3, ZT4 - temporary registers

        ;; Hash in AES state
        vpxorq          %%ZT5, %%ZT5, %%ZT2

        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT6, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, %%num_initial_blocks

        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT6, %%ZT5, \
                %%ZT1, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, %%num_initial_blocks

        ;; reduction is needed
        jmp             %%_small_initial_compute_reduction
%endif                          ; %if %%num_initial_blocks < 8

%%_small_initial_partial_block:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Handle ghash for a <16B final block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;; In this case if it's a single call to encrypt we can
        ;; hash all of the data but if it's an init / update / finalize
        ;; series of call we need to leave the last block if it's
        ;; less than a full block of data.

	mov	        [%%GDATA_CTX + PBlockLen], %%LENGTH
        ;; %%T1 is ciphered counter block
        vmovdqu64       [%%GDATA_CTX + PBlockEncKey], %%T1

%ifidn %%INSTANCE_TYPE, multi_call
%assign k (%%num_initial_blocks - 1)
%assign last_block_to_hash 1
%else
%assign k (%%num_initial_blocks)
%assign last_block_to_hash 0
%endif

%if (%%num_initial_blocks > last_block_to_hash)

        ;; T2 - incoming AAD hash
        ;; ZT5, ZT6 - hold ciphertext
        ;; ZT3, ZT4 - temporary registers
        ;; Hash in AES state
        vpxorq          %%ZT5, %%ZT5, %%ZT2

        VCLMUL_1_TO_8_STEP1 %%GDATA_KEY, %%ZT6, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, k

        VCLMUL_1_TO_8_STEP2 %%GDATA_KEY, %%ZT6, %%ZT5, \
                %%ZT1, %%ZT3, %%ZT4, \
                %%TH, %%TM, %%TL, k

        ;; reduction is required - just fall through no jmp needed
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
        vpxorq          %%HASH_IN_OUT, %%T2, %%T7

        ;; The result is in %%HASH_IN_OUT
        jmp             %%_after_reduction
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Ghash reduction
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_small_initial_compute_reduction:


        ;; [out] HASH_IN_OUT - hash output
        ;; [in]  T3 - polynomial
        ;; [in]  T6 - high, T5 - low
        ;; [clobbered] T1, T4 - temporary
        vmovdqu64       %%T3, [rel POLY2]
        VCLMUL_REDUCE   %%HASH_IN_OUT, %%T3, %%T6, %%T5, %%T1, %%T4

%ifidn %%INSTANCE_TYPE, multi_call
        ;; If using init/update/finalize, we need to xor any partial block data
        ;; into the hash.
%if %%num_initial_blocks > 1
        ;; NOTE: for %%num_initial_blocks = 0 the xor never takes place
%if %%num_initial_blocks != 8
        ;; NOTE: for %%num_initial_blocks = 8, %%LENGTH, stored in [PBlockLen] is never zero
        or              %%LENGTH, %%LENGTH
        je              %%_after_reduction
%endif                          ; %%num_initial_blocks != 8
        vpxorq          %%HASH_IN_OUT, %%HASH_IN_OUT, %%T7
%endif                          ; %%num_initial_blocks > 1
%endif                          ; %%INSTANCE_TYPE, multi_call

%%_after_reduction:
        ;; Final hash is now in HASH_IN_OUT

%endmacro                       ; INITIAL_BLOCKS_PARTIAL



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Main GCM macro stitching cipher with GHASH
;;; - operates on single stream
;;; - encrypts 8 blocks at a time
;;; - ghash the 8 previously encrypted ciphertext blocks
;;; For partial block case and multi_call , AES_PARTIAL_BLOCK on output
;;; contains encrypted counter block.
%macro  GHASH_8_ENCRYPT_8_PARALLEL 29
%define %%GDATA                 %1  ; [in] key pointer
%define %%CYPH_PLAIN_OUT        %2  ; [in] pointer to output buffer
%define %%PLAIN_CYPH_IN         %3  ; [in] pointer to input buffer
%define %%DATA_OFFSET           %4  ; [in] data offset
%define %%CTR                   %5  ; [in/out] ZMM last counter block (b-casted across ZMM)
%define %%GHASHIN_AESOUT_B03    %6  ; [in/out] ZMM ghash in / aes out blocks 0 to 3
%define %%GHASHIN_AESOUT_B47    %7  ; [in/out] ZMM ghash in / aes out blocks 4 to 7
%define %%AES_PARTIAL_BLOCK     %8  ; [out] XMM partial block (AES)
%define %%loop_idx              %9  ; [in] counter block prep selection "add+shuffle" or "add"
%define %%ENC_DEC               %10 ; [in] cipher direction
%define %%FULL_PARTIAL          %11 ; [in] last block type selection "full" or "partial"
%define %%IA0                   %12 ; [clobbered] temporary GP register
%define %%IA1                   %13 ; [clobbered] temporary GP register
%define %%LENGTH                %14 ; [in] length
%define %%INSTANCE_TYPE         %15 ; [in] 'single_call' or 'multi_call' selection
%define %%ZT1                   %16 ; [clobbered] temporary ZMM (cipher)
%define %%ZT2                   %17 ; [clobbered] temporary ZMM (cipher)
%define %%ZT3                   %18 ; [clobbered] temporary ZMM (cipher)
%define %%ZT4                   %19 ; [clobbered] temporary ZMM (cipher)
%define %%ZT5                   %20 ; [clobbered] temporary ZMM (cipher)
%define %%ZT10                  %21 ; [clobbered] temporary ZMM (ghash)
%define %%ZT11                  %22 ; [clobbered] temporary ZMM (ghash)
%define %%ZT12                  %23 ; [clobbered] temporary ZMM (ghash)
%define %%ZT13                  %24 ; [clobbered] temporary ZMM (ghash)
%define %%ZT14                  %25 ; [clobbered] temporary ZMM (ghash)
%define %%ZT15                  %26 ; [clobbered] temporary ZMM (ghash)
%define %%ZT16                  %27 ; [clobbered] temporary ZMM (ghash)
%define %%ZT17                  %28 ; [clobbered] temporary ZMM (ghash)
%define %%MASKREG               %29 ; [clobbered] mask register for partial loads/stores

        ;; keep the cipher blocks for further GHASH
        vmovdqa64       %%ZT10, %%GHASHIN_AESOUT_B03
        vmovdqa64       %%ZT11, %%GHASHIN_AESOUT_B47

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; populate counter blocks
%ifidn %%loop_idx, in_order
        ;; %%CTR is shuffled outside the scope of this macro
        ;; it has to be kept in unshuffled form
        vpaddd          %%ZT1, %%CTR, [rel ddq_add_1234]
        vpaddd          %%ZT2, %%CTR, [rel ddq_add_5678]
        vshufi64x2      %%CTR, %%ZT2, %%ZT2, 1111_1111b
        vpshufb         %%ZT1, [rel SHUF_MASK]
        vpshufb         %%ZT2, [rel SHUF_MASK]
%else
        vpaddd          %%ZT1, %%CTR, [rel ddq_addbe_1234]
        vpaddd          %%ZT2, %%CTR, [rel ddq_addbe_5678]
        vshufi64x2      %%CTR, %%ZT2, %%ZT2, 1111_1111b
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; load/store mask (partial case) and load the text data
%ifidn %%FULL_PARTIAL, full
        vmovdqu8        %%ZT4, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%else
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
        sub             %%IA1, 64
        kmovq           %%MASKREG, [%%IA0 + 8*%%IA1]
        vmovdqu8        %%ZT4, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT5{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; stitch AES rounds with GHASH

%assign aes_round 0
%assign hash_index 0

%rep (((NROUNDS + 2) / 3) + 1)

        ;; === 3 x AES ROUND
%rep 3
%if aes_round < (NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                %%ZT1, %%ZT2, %%ZT3, %%GDATA, aes_round, \
                %%ZT4, %%ZT5, 8
%assign aes_round (aes_round + 1)
%endif                          ; aes_round < (NROUNDS + 2)
%endrep                         ; 3 x AES ROUND

        ;; === GHASH on 8 blocks
%if hash_index == 0
        ;; GHASH - 1st round
        ;; [in] ZT11 - high blocks
        ;; [out] ZT12, ZT13, ZT14 - low, medium and high sums
        ;; [clobbered] ZT15
        VCLMUL_STEP1    %%GDATA, %%ZT11, %%ZT15, %%ZT12, %%ZT13, %%ZT14
%assign hash_index (hash_index + 1)
%elif hash_index == 1
        ;; GHASH - 2nd round
        ;; [in] ZT11 - high blocks
        ;; [in] ZT10 - low blocks
        ;; [in] ZT12, ZT13, ZT14 - low, medium and high sums
        ;; [clobbered] ZT15, ZT16, ZT17
        ;; [out] ZT11, ZT10 - high and low sums for further reduction
        VCLMUL_STEP2    %%GDATA, %%ZT11, %%ZT10, %%ZT15, %%ZT16, %%ZT17, %%ZT12, %%ZT13, %%ZT14
%assign hash_index (hash_index + 1)
%elif hash_index == 2
        ;; GHASH - reduction
        ;; [out] ZT13 - ghash result
        ;; [in]  ZT12 - polynomial
        ;; [in]  ZT11 - high, ZT10 - low
        ;; [clobbered] ZT15, ZT16 - temporary
        vmovdqu64       XWORD(%%ZT12), [rel POLY2]
        VCLMUL_REDUCE   XWORD(%%ZT13), XWORD(%%ZT12), XWORD(%%ZT11), XWORD(%%ZT10), \
                        XWORD(%%ZT15), XWORD(%%ZT16)
%assign hash_index (hash_index + 1)
%endif

%endrep                         ; stitched AES and GHASH loop

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; store the text data
%ifidn %%FULL_PARTIAL, full
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64], %%ZT2
%else
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, %%ZT2
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; prep cipher text blocks for the next ghash round

%ifnidn %%FULL_PARTIAL, full
%ifidn %%INSTANCE_TYPE, multi_call
        ;; for partial block & multi_call we need encrypted counter block
        vpxorq          %%ZT3, %%ZT2, %%ZT5
        vextracti32x4   %%AES_PARTIAL_BLOCK, %%ZT3, 3
%endif
        ;; for GHASH computation purpose clear the top bytes of the partial block
%ifidn %%ENC_DEC, ENC
        vmovdqu8        %%ZT2{%%MASKREG}{z}, %%ZT2
%else
        vmovdqu8        %%ZT5{%%MASKREG}{z}, %%ZT5
%endif
%endif

        ;; shuffle cipher text blocks for GHASH computation
%ifidn %%ENC_DEC, ENC
        vpshufb         %%ZT1, [rel SHUF_MASK]
        vpshufb         %%ZT2, [rel SHUF_MASK]
%else
        vpshufb         %%ZT1, %%ZT4, [rel SHUF_MASK]
        vpshufb         %%ZT2, %%ZT5, [rel SHUF_MASK]
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; copy shuffled cipher text blocks for GHASH
        vmovdqa64       %%GHASHIN_AESOUT_B03, %%ZT1
        vmovdqa64       %%GHASHIN_AESOUT_B47, %%ZT2

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; XOR current GHASH value (ZT13) into block 0
        vpxorq          %%GHASHIN_AESOUT_B03, %%ZT13

%endmacro                       ; GHASH_8_ENCRYPT_8_PARALLEL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; GHASH the last 8 ciphertext blocks.
%macro  GHASH_LAST_8 10
%define %%GDATA         %1      ; [in] key pointer
%define %%BL47          %2      ; [in/clobbered] ZMM AES blocks 4 to 7
%define %%BL03          %3      ; [in/cloberred] ZMM AES blocks 0 to 3
%define %%ZTH           %4      ; [cloberred] ZMM temporary
%define %%ZTM           %5      ; [cloberred] ZMM temporary
%define %%ZTL           %6      ; [cloberred] ZMM temporary
%define %%ZT01          %7      ; [cloberred] ZMM temporary
%define %%ZT02          %8      ; [cloberred] ZMM temporary
%define %%ZT03          %9      ; [cloberred] ZMM temporary
%define %%AAD_HASH      %10     ; [out] XMM hash value

        VCLMUL_STEP1    %%GDATA, %%BL47, %%ZT01, %%ZTH, %%ZTM, %%ZTL
        VCLMUL_STEP2    %%GDATA, %%BL47, %%BL03, %%ZT01, %%ZT02, %%ZT03, %%ZTH, %%ZTM, %%ZTL
        vmovdqa64       XWORD(%%ZT03), [rel POLY2]
        VCLMUL_REDUCE   %%AAD_HASH, XWORD(%%ZT03), XWORD(%%BL47), XWORD(%%BL03), \
                XWORD(%%ZT01), XWORD(%%ZT02)
%endmacro                       ; GHASH_LAST_8

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; GHASH the last 7 cipher text blocks.
;;; - it uses same GHASH macros as GHASH_LAST_8 but with some twist
;;; - it loads GHASH keys for each of the data blocks, so that:
;;;     - blocks 4, 5 and 6 will use GHASH keys 3, 2, 1 respectively
;;;     - code ensures that unused block 7 and corresponding GHASH key are zeroed
;;;       (clmul product is zero this way and will not affect the result)
;;;     - blocks 0, 1, 2 and 3 will use USE GHASH keys 7, 6, 5 and 4 respectively
%macro  GHASH_LAST_7 13
%define %%GDATA         %1      ; [in] key pointer
%define %%BL47          %2      ; [in/clobbered] ZMM AES blocks 4 to 7
%define %%BL03          %3      ; [in/cloberred] ZMM AES blocks 0 to 3
%define %%ZTH           %4      ; [cloberred] ZMM temporary
%define %%ZTM           %5      ; [cloberred] ZMM temporary
%define %%ZTL           %6      ; [cloberred] ZMM temporary
%define %%ZT01          %7      ; [cloberred] ZMM temporary
%define %%ZT02          %8      ; [cloberred] ZMM temporary
%define %%ZT03          %9      ; [cloberred] ZMM temporary
%define %%ZT04          %10     ; [cloberred] ZMM temporary
%define %%AAD_HASH      %11     ; [out] XMM hash value
%define %%MASKREG       %12     ; [clobbered] mask register to use for loads
%define %%IA0           %13     ; [clobbered] GP temporary register

        vmovdqa64       XWORD(%%ZT04), [rel POLY2]

        VCLMUL_1_TO_8_STEP1 %%GDATA, %%BL47, %%ZT01, %%ZT02, %%ZTH, %%ZTM, %%ZTL, 7

        VCLMUL_1_TO_8_STEP2 %%GDATA, %%BL47, %%BL03, \
                %%ZT01, %%ZT02, %%ZT03, \
                %%ZTH, %%ZTM, %%ZTL, 7

        VCLMUL_REDUCE   %%AAD_HASH, XWORD(%%ZT04), XWORD(%%BL47), XWORD(%%BL03), \
                XWORD(%%ZT01), XWORD(%%ZT02)
%endmacro                       ; GHASH_LAST_7


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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; GCM_INIT initializes a gcm_context_data struct to prepare for encoding/decoding.
;;; Input: gcm_key_data * (GDATA_KEY), gcm_context_data *(GDATA_CTX), IV,
;;; Additional Authentication data (A_IN), Additional Data length (A_LEN).
;;; Output: Updated GDATA_CTX with the hash of A_IN (AadHash) and initialized other parts of GDATA_CTX.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_INIT        21
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

        CALC_AAD_HASH   %%A_IN, %%A_LEN, %%AAD_HASH, %%GDATA_KEY, \
                        %%ZT0, %%ZT1, %%ZT2, %%ZT3, %%ZT4, %%ZT5, %%ZT6, %%ZT7, %%ZT8, %%ZT9, \
                        %%GPR1, %%GPR2, %%GPR3, %%MASKREG

        mov             %%GPR1, %%A_LEN
        vmovdqu64       [%%GDATA_CTX + AadHash], %%AAD_HASH   ; ctx.aad hash = aad_hash
        mov             [%%GDATA_CTX + AadLen], %%GPR1        ; ctx.aad_length = aad_length

        xor             %%GPR1, %%GPR1
        mov             [%%GDATA_CTX + InLen], %%GPR1         ; ctx.in_length = 0
        mov             [%%GDATA_CTX + PBlockLen], %%GPR1     ; ctx.partial_block_length = 0

        ;; read 12 IV bytes and pad with 0x00000001
        vmovdqu8        %%CUR_COUNT, [rel ONEf]
        mov             %%GPR2, %%IV
        mov             %%GPR1, 0x0000_0000_0000_0fff
        kmovq           %%MASKREG, %%GPR1
        vmovdqu8        %%CUR_COUNT{%%MASKREG}, [%%GPR2]      ; ctr = IV | 0x1

        vmovdqu64       [%%GDATA_CTX + OrigIV], %%CUR_COUNT   ; ctx.orig_IV = iv

        ;; store IV as counter in LE format
        vpshufb         %%CUR_COUNT, [rel SHUF_MASK]
        vmovdqu         [%%GDATA_CTX + CurCount], %%CUR_COUNT ; ctx.current_counter = iv
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cipher and ghash of payloads shorter than 128 bytes
;;; - number of blocks in the message comes as argument
;;; - depending on the number of blocks an optimized variant of
;;;   INITIAL_BLOCKS_PARTIAL is invoked
%macro  GCM_ENC_DEC_SMALL   24
%define %%GDATA_KEY         %1  ; [in] key pointer
%define %%GDATA_CTX         %2  ; [in] context pointer
%define %%CYPH_PLAIN_OUT    %3  ; [in] output buffer
%define %%PLAIN_CYPH_IN     %4  ; [in] input buffer
%define %%PLAIN_CYPH_LEN    %5  ; [in] buffer length
%define %%ENC_DEC           %6  ; [in] cipher direction
%define %%DATA_OFFSET       %7  ; [in] data offset
%define %%LENGTH            %8  ; [in] data length
%define %%NUM_BLOCKS        %9  ; [in] number of blocks to process 1 to 8
%define %%CTR               %10 ; [in/out] XMM counter block
%define %%HASH_IN_OUT       %11 ; [in/out] XMM GHASH value
%define %%INSTANCE_TYPE     %12 ; [in] single or multi call
%define %%ZTMP1             %13 ; [clobbered] ZMM register
%define %%ZTMP2             %14 ; [clobbered] ZMM register
%define %%ZTMP3             %15 ; [clobbered] ZMM register
%define %%ZTMP4             %16 ; [clobbered] ZMM register
%define %%ZTMP5             %17 ; [clobbered] ZMM register
%define %%ZTMP6             %18 ; [clobbered] ZMM register
%define %%ZTMP7             %19 ; [clobbered] ZMM register
%define %%ZTMP8             %20 ; [clobbered] ZMM register
%define %%ZTMP9             %21 ; [clobbered] ZMM register
%define %%IA0               %22 ; [clobbered] GP register
%define %%IA1               %23 ; [clobbered] GP register
%define %%MASKREG           %24 ; [clobbered] mask register

        cmp     %%NUM_BLOCKS, 8
        je      %%_small_initial_num_blocks_is_8
        cmp     %%NUM_BLOCKS, 7
        je      %%_small_initial_num_blocks_is_7
        cmp     %%NUM_BLOCKS, 6
        je      %%_small_initial_num_blocks_is_6
        cmp     %%NUM_BLOCKS, 5
        je      %%_small_initial_num_blocks_is_5
        cmp     %%NUM_BLOCKS, 4
        je      %%_small_initial_num_blocks_is_4
        cmp     %%NUM_BLOCKS, 3
        je      %%_small_initial_num_blocks_is_3
        cmp     %%NUM_BLOCKS, 2
        je      %%_small_initial_num_blocks_is_2

        jmp     %%_small_initial_num_blocks_is_1


%%_small_initial_num_blocks_is_8:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 8, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_7:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 7, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_6:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 6, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_5:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 5, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_4:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 4, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_3:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 3, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_2:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 2, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_1:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 1, \
                %%CTR, %%HASH_IN_OUT, %%ENC_DEC, %%INSTANCE_TYPE, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%IA0, %%IA1, %%MASKREG
%%_small_initial_blocks_encrypted:

%endmacro                       ; GCM_ENC_DEC_SMALL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_ENC_DEC Encodes/Decodes given data. Assumes that the passed gcm_context_data struct
; has been initialized by GCM_INIT
; Requires the input data be at least 1 byte long because of READ_SMALL_INPUT_DATA.
; Input: gcm_key_data struct* (GDATA_KEY), gcm_context_data *(GDATA_CTX), input text (PLAIN_CYPH_IN),
; input text length (PLAIN_CYPH_LEN) and whether encoding or decoding (ENC_DEC).
; Output: A cypher of the given plain text (CYPH_PLAIN_OUT), and updated GDATA_CTX
; Clobbers rax, r10-r15, and xmm0-xmm15
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

%define %%LENGTH            %%IA2
%define %%CTR_CHECK         %%IA3
%define %%DATA_OFFSET       %%IA4

%define %%GHASH_IN_AES_OUT_B03  zmm1
%define %%GHASH_IN_AES_OUT_B47  zmm2

%define %%GCM_INIT_CTR_BLOCK    xmm2 ; hardcoded in GCM_INIT for now

%define %%AES_PARTIAL_BLOCK     xmm8
%define %%CTR_BLOCKz            zmm9
%define %%CTR_BLOCKx            xmm9
%define %%AAD_HASHz             zmm14
%define %%AAD_HASHx             xmm14

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

%define %%MASKREG               k1

;;; Macro flow:
;;; - calculate the number of 16byte blocks in the message
;;; - process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
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
        ;; Determine how many blocks to process in INITIAL
        mov             %%IA1, %%LENGTH
        shr             %%IA1, 4
        and             %%IA1, 7

        ;; Process one additional block in INITIAL if there is a partial block
        mov             %%IA0, %%LENGTH
        and             %%IA0, 0xf
        add             %%IA0, 0xf
        shr             %%IA0, 4
        add             %%IA1, %%IA0
        ;; %%IA1 can be in the range from 0 to 8

        ;; Less than 128B will be handled by the small message code, which
        ;; can process up to 8 x blocks (16 bytes each)
        cmp             %%LENGTH, 128
        jge             %%_large_message_path

        GCM_ENC_DEC_SMALL \
                %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%PLAIN_CYPH_LEN, %%ENC_DEC, %%DATA_OFFSET, \
                %%LENGTH, %%IA1, %%CTR_BLOCKx, %%AAD_HASHx, %%INSTANCE_TYPE, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, %%IA0, %%IA3, %%MASKREG

        jmp     %%_ghash_done

%%_large_message_path:
        ;; Still, don't allow 8 INITIAL blocks since this will
        ;; can be handled by the x8 partial loop.
        and             %%IA1, 0x7
        je              %%_initial_num_blocks_is_0
        cmp             %%IA1, 7
        je              %%_initial_num_blocks_is_7
        cmp             %%IA1, 6
        je              %%_initial_num_blocks_is_6
        cmp             %%IA1, 5
        je              %%_initial_num_blocks_is_5
        cmp             %%IA1, 4
        je              %%_initial_num_blocks_is_4
        cmp             %%IA1, 3
        je              %%_initial_num_blocks_is_3
        cmp             %%IA1, 2
        je              %%_initial_num_blocks_is_2
        jmp             %%_initial_num_blocks_is_1

%%_initial_num_blocks_is_7:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 7, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, \
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_6:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 6, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11,\
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_5:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 5, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, \
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_4:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 4, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, \
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_3:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 3, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, \
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_2:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 2, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, \
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_1:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 1, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, \
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_0:
        INITIAL_BLOCKS  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 0, %%CTR_BLOCKx, %%AAD_HASHz, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, \
                %%IA0, %%IA1, %%ENC_DEC, %%MASKREG

%%_initial_blocks_encrypted:
        ;; move cipher blocks from intial blocks to input of by8 macro
        vmovdqa64       %%GHASH_IN_AES_OUT_B03, %%ZTMP0
        vmovdqa64       %%GHASH_IN_AES_OUT_B47, %%ZTMP1

        ;; The entire message was encrypted processed in initial and now need to be hashed
        or              %%LENGTH, %%LENGTH
        je              %%_encrypt_done

        vshufi64x2      %%CTR_BLOCKz, %%CTR_BLOCKz, %%CTR_BLOCKz, 0

        ;; Process 7 full blocks plus a partial block
        cmp             %%LENGTH, 128
        jl              %%_encrypt_by_8_partial

%%_encrypt_by_8_parallel:
        ;; in_order vs. out_order is an optimization to increment the counter
        ;; without shuffling it back into little endian.
        ;; %%CTR_CHECK keeps track of when we need to increment in order so
        ;; that the carry is handled correctly.
        vmovd           DWORD(%%CTR_CHECK), %%CTR_BLOCKx
        and             DWORD(%%CTR_CHECK), 255
        vpshufb         %%CTR_BLOCKz, [rel SHUF_MASK]

%%_encrypt_by_8_new:
        cmp             DWORD(%%CTR_CHECK), (255 - 8)
        jg              %%_encrypt_by_8

        add             BYTE(%%CTR_CHECK), 8
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%DATA_OFFSET, %%CTR_BLOCKz, \
                %%GHASH_IN_AES_OUT_B03, %%GHASH_IN_AES_OUT_B47, %%AES_PARTIAL_BLOCK, \
                out_order, %%ENC_DEC, full, %%IA0, %%IA1, %%LENGTH, %%INSTANCE_TYPE, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, %%ZTMP12, %%MASKREG

        add             %%DATA_OFFSET, 128
        sub             %%LENGTH, 128
        cmp             %%LENGTH, 128
        jge             %%_encrypt_by_8_new

        vpshufb         %%CTR_BLOCKz, [rel SHUF_MASK]
        jmp             %%_encrypt_by_8_parallel_done

%%_encrypt_by_8:
        vpshufb         %%CTR_BLOCKz, [rel SHUF_MASK]
        add             BYTE(%%CTR_CHECK), 8
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%DATA_OFFSET, %%CTR_BLOCKz, \
                %%GHASH_IN_AES_OUT_B03, %%GHASH_IN_AES_OUT_B47, %%AES_PARTIAL_BLOCK, \
                in_order, %%ENC_DEC, full, %%IA0, %%IA1, %%LENGTH, %%INSTANCE_TYPE, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, %%ZTMP12, %%MASKREG
        vpshufb         %%CTR_BLOCKz, [rel SHUF_MASK]
        add             %%DATA_OFFSET, 128
        sub             %%LENGTH, 128
        cmp             %%LENGTH, 128
        jge             %%_encrypt_by_8_new
        vpshufb         %%CTR_BLOCKz, [rel SHUF_MASK]

%%_encrypt_by_8_parallel_done:
        ;; Test to see if we need a by 8 with partial block. At this point
        ;; bytes remaining should be either zero or between 113-127.
        or              %%LENGTH, %%LENGTH
        je              %%_encrypt_done

%%_encrypt_by_8_partial:
        ;; Process parallel buffers with a final partial block.
        ;; 'in_order' shuffle needed to align key for partial block xor.
        ;; 'out_order' is a little faster because it avoids extra shuffles.
        ;;  - here it would require to account for byte overflow

        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%DATA_OFFSET, %%CTR_BLOCKz, \
                %%GHASH_IN_AES_OUT_B03, %%GHASH_IN_AES_OUT_B47, %%AES_PARTIAL_BLOCK, \
                in_order, %%ENC_DEC, partial, %%IA0, %%IA1, %%LENGTH, %%INSTANCE_TYPE, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%ZTMP7, %%ZTMP8, %%ZTMP9, %%ZTMP10, %%ZTMP11, %%ZTMP12, %%MASKREG

        add             %%DATA_OFFSET, (128 - 16)
        sub             %%LENGTH, (128 - 16)

%ifidn %%INSTANCE_TYPE, multi_call
        mov             [%%GDATA_CTX + PBlockLen], %%LENGTH
        vmovdqu64       [%%GDATA_CTX + PBlockEncKey], %%AES_PARTIAL_BLOCK
%endif

%%_encrypt_done:
        ;; GHASH last cipher text blocks in xmm1-xmm8
        ;; - if block 8th is partial in a multi-call path then skip the block
%ifidn %%INSTANCE_TYPE, multi_call
        cmp             qword [%%GDATA_CTX + PBlockLen], 0
        jz              %%_hash_last_8

        ;; save the 8th partial block as GHASH_LAST_7 will clobber %%GHASH_IN_AES_OUT_B47
        vextracti32x4   XWORD(%%ZTMP7), %%GHASH_IN_AES_OUT_B47, 3

        GHASH_LAST_7 %%GDATA_KEY, %%GHASH_IN_AES_OUT_B47, %%GHASH_IN_AES_OUT_B03, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                %%AAD_HASHx, %%MASKREG, %%IA0

        ;; XOR the partial word into the hash
        vpxorq          %%AAD_HASHx, %%AAD_HASHx, XWORD(%%ZTMP7)
        jmp             %%_ghash_done
%%_hash_last_8:
%endif
        GHASH_LAST_8 %%GDATA_KEY, %%GHASH_IN_AES_OUT_B47, %%GHASH_IN_AES_OUT_B03, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%AAD_HASHx
%%_ghash_done:
        vmovdqu64       [%%GDATA_CTX + CurCount], %%CTR_BLOCKx
        vmovdqu64       [%%GDATA_CTX + AadHash], %%AAD_HASHx
%%_enc_dec_done:

%endmacro                       ; GCM_ENC_DEC

;;; ===========================================================================
;;; AESROUND4x128 macro
;;; - 4 lanes, 8 blocks per lane
;;; - it handles special cases: the last and zero rounds
;;; Uses NROUNDS macro defined at the top of the file to check the last round
%macro AESROUND4x128 25
%define %%L0B03 %1              ; [in/out] lane 0, blocks 0 to 3
%define %%L0B47 %2              ; [in/out] lane 0, blocks 4 to 7
%define %%L1B03 %3              ; [in/out] lane 1, blocks 0 to 3
%define %%L1B47 %4              ; ...
%define %%L2B03 %5
%define %%L2B47 %6
%define %%L3B03 %7              ; ...
%define %%L3B47 %8              ; [in/out] lane 3, blocks 4 to 7
%define %%TMP0  %9
%define %%TMP1  %10
%define %%TMP2  %11
%define %%TMP3  %12
%define %%KP0   %13             ; [in] expanded key pointer lane 0
%define %%KP1   %14             ; [in] expanded key pointer lane 1
%define %%KP2   %15             ; [in] expanded key pointer lane 2
%define %%KP3   %16             ; [in] expanded key pointer lane 3
%define %%ROUND %17             ; [in] round number
%define %%D0L   %18             ; [in] plain/cipher text blocks 0-3 lane 0 - NEEDED FOR THE LAST ROUND ONLY (CAN BE EMPTY OTHERWISE)
%define %%D0H   %19             ; [in] plain/cipher text blocks 4-7 lane 0
%define %%D1L   %20             ; [in] plain/cipher text blocks 0-3 lane 1
%define %%D1H   %21             ; ...
%define %%D2L   %22
%define %%D2H   %23
%define %%D3L   %24             ; ...
%define %%D3H   %25             ; [in] plain/cipher text blocks 4-7 lane 3

        vbroadcastf64x2 %%TMP0, [%%KP0 + 16*(%%ROUND)]
        vbroadcastf64x2 %%TMP1, [%%KP1 + 16*(%%ROUND)]
        vbroadcastf64x2 %%TMP2, [%%KP2 + 16*(%%ROUND)]
        vbroadcastf64x2 %%TMP3, [%%KP3 + 16*(%%ROUND)]
%if %%ROUND < 1
        ;;  round 0
        vpxorq          %%L0B03, %%L0B03, %%TMP0
        vpxorq          %%L0B47, %%L0B47, %%TMP0
        vpxorq          %%L1B03, %%L1B03, %%TMP1
        vpxorq          %%L1B47, %%L1B47, %%TMP1
        vpxorq          %%L2B03, %%L2B03, %%TMP2
        vpxorq          %%L2B47, %%L2B47, %%TMP2
        vpxorq          %%L3B03, %%L3B03, %%TMP3
        vpxorq          %%L3B47, %%L3B47, %%TMP3
%else
%if %%ROUND <= NROUNDS
        ;; rounds 1 to 9/11/13
        vaesenc         %%L0B03, %%L0B03, %%TMP0
        vaesenc         %%L0B47, %%L0B47, %%TMP0
        vaesenc         %%L1B03, %%L1B03, %%TMP1
        vaesenc         %%L1B47, %%L1B47, %%TMP1
        vaesenc         %%L2B03, %%L2B03, %%TMP2
        vaesenc         %%L2B47, %%L2B47, %%TMP2
        vaesenc         %%L3B03, %%L3B03, %%TMP3
        vaesenc         %%L3B47, %%L3B47, %%TMP3
%else
        ;; the last round - mix enclast with text xor's
        vaesenclast     %%L0B03, %%L0B03, %%TMP0
        vpxorq          %%L0B03, %%L0B03, %%D0L
        vaesenclast     %%L0B47, %%L0B47, %%TMP0
        vpxorq          %%L0B47, %%L0B47, %%D0H
        vaesenclast     %%L1B03, %%L1B03, %%TMP1
        vpxorq          %%L1B03, %%L1B03, %%D1L
        vaesenclast     %%L1B47, %%L1B47, %%TMP1
        vpxorq          %%L1B47, %%L1B47, %%D1H
        vaesenclast     %%L2B03, %%L2B03, %%TMP2
        vpxorq          %%L2B03, %%L2B03, %%D2L
        vaesenclast     %%L2B47, %%L2B47, %%TMP2
        vpxorq          %%L2B47, %%L2B47, %%D2H
        vaesenclast     %%L3B03, %%L3B03, %%TMP3
        vpxorq          %%L3B03, %%L3B03, %%D3L
        vaesenclast     %%L3B47, %%L3B47, %%TMP3
        vpxorq          %%L3B47, %%L3B47, %%D3H
%endif
%endif
%endmacro                       ; AESROUND4x128

;;; ===========================================================================
;;; AESROUND_1_TO_8_BLOCKS macro
;;; - 1 lane, 1 to 8 blocks per lane
;;; - it handles special cases: the last and zero rounds
;;; Uses NROUNDS macro defined at the top of the file to check the last round
%macro AESROUND_1_TO_8_BLOCKS 8
%define %%L0B03 %1      ; [in/out] zmm; blocks 0 to 3
%define %%L0B47 %2      ; [in/out] zmm; blocks 4 to 7
%define %%TMP0  %3      ; [clobbered] zmm
%define %%KP    %4      ; [in] expanded key pointer
%define %%ROUND %5      ; [in] round number
%define %%D0L   %6      ; [in] zmm or no_data; plain/cipher text blocks 0-3
%define %%D0H   %7      ; [in] zmm or no_data; plain/cipher text blocks 4-7
%define %%NUMBL %8      ; [in] number of blocks; numerical value

%if (%%NUMBL == 1)
        ;; don't load the key
%elif (%%NUMBL == 2)
        vbroadcastf64x2 YWORD(%%TMP0), [%%KP + 16*(%%ROUND)]
%else
        vbroadcastf64x2 %%TMP0, [%%KP + 16*(%%ROUND)]
%endif

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vpxorq          %%L0B03, %%L0B03, %%TMP0
        vpxorq          %%L0B47, %%L0B47, %%TMP0
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vpxorq          %%L0B03, %%L0B03, %%TMP0
        vpxorq          YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%TMP0)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vpxorq          %%L0B03, %%L0B03, %%TMP0
        vpxorq          XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%TMP0)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vpxorq          %%L0B03, %%L0B03, %%TMP0
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vpxorq          YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%TMP0)
%else
        ;; 1 block
        vpxorq          XWORD(%%L0B03), XWORD(%%L0B03), [%%KP + 16*(%%ROUND)]
%endif                  ; NUM BLOCKS
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= NROUNDS)
        ;; rounds 1 to 9/11/13
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vaesenc         %%L0B03, %%L0B03, %%TMP0
        vaesenc         %%L0B47, %%L0B47, %%TMP0
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vaesenc         %%L0B03, %%L0B03, %%TMP0
        vaesenc         YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%TMP0)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vaesenc         %%L0B03, %%L0B03, %%TMP0
        vaesenc         XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%TMP0)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vaesenc         %%L0B03, %%L0B03, %%TMP0
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vaesenc         YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%TMP0)
%else
        ;; 1 block
        vaesenc         XWORD(%%L0B03), XWORD(%%L0B03), [%%KP + 16*(%%ROUND)]
%endif                  ; NUM BLOCKS
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > NROUNDS)
        ;; the last round - mix enclast with text xor's
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vaesenclast     %%L0B03, %%L0B03, %%TMP0
        vaesenclast     %%L0B47, %%L0B47, %%TMP0
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vaesenclast     %%L0B03, %%L0B03, %%TMP0
        vaesenclast     YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%TMP0)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vaesenclast     %%L0B03, %%L0B03, %%TMP0
        vaesenclast     XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%TMP0)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vaesenclast     %%L0B03, %%L0B03, %%TMP0
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vaesenclast     YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%TMP0)
%else
        ;; 1 block
        vaesenclast     XWORD(%%L0B03), XWORD(%%L0B03), [%%KP + 16*(%%ROUND)]
%endif                  ; NUM BLOCKS

;;; === XOR with data
%ifnidn %%D0L, no_data
%if (%%NUMBL == 1)
        vpxorq          XWORD(%%L0B03), XWORD(%%L0B03), XWORD(%%D0L)
%elif (%%NUMBL == 2)
        vpxorq          YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%D0L)
%else
        vpxorq          %%L0B03, %%L0B03, %%D0L
%endif
%endif                          ; !no_data
%ifnidn %%D0H, no_data
%if (%%NUMBL == 5)
        vpxorq          XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%D0H)
%elif (%%NUMBL == 6)
        vpxorq          YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%D0H)
%elif (%%NUMBL > 6)
        vpxorq          %%L0B47, %%L0B47, %%D0H
%endif
%endif                  ; !no_data
%endif                  ; The last round

%endmacro               ; AESROUND_1_TO_8_BLOCKS

;;; ===========================================================================
;;; ===========================================================================
;;; Encrypt the initial 8 blocks from 4 lanes and apply ghash on the ciphertext
%macro INITIAL_BLOCKS_x4 33
%define %%IN                    %1      ; pointer to array of pointers to input text
%define %%OUT                   %2      ; pointer to array of pointers to output text
%define %%KEYP0                 %3      ; pointer to expanded keys, lane 0
%define %%KEYP1                 %4      ; pointer to expanded keys, lane 1
%define %%KEYP2                 %5      ; pointer to expanded keys, lane 2
%define %%KEYP3                 %6      ; pointer to expanded keys, lane 3
%define %%TPTR0                 %7      ; temporary GP register
%define %%TPTR1                 %8      ; temporary GP register
%define %%TPTR2                 %9      ; temporary GP register
%define %%TPTR3                 %10     ; temporary GP register
%define %%L0B03                 %11     ; [out] cipher text blocks 0 to 3, lane 0
%define %%L0B47                 %12     ; [out] cipher text blocks 4 to 7, lane 0
%define %%L1B03                 %13     ; [out] cipher text blocks 0 to 3, lane 1
%define %%L1B47                 %14     ; ...
%define %%L2B03                 %15
%define %%L2B47                 %16
%define %%L3B03                 %17     ; ...
%define %%L3B47                 %18     ; [out] cipher text blocks 4 to 7, lane 3
%define %%GHASH                 %19     ; [in] AAD lane 0, 1, 2 and 3
%define %%T0                    %20     ; temporary AVX512 register
%define %%T1                    %21     ; temporary AVX512 register
%define %%T2                    %22     ; temporary AVX512 register
%define %%T3                    %23     ; temporary AVX512 register
%define %%T4                    %24     ; temporary AVX512 register
%define %%T5                    %25     ; temporary AVX512 register
%define %%T6                    %26     ; temporary AVX512 register
%define %%T7                    %27     ; temporary AVX512 register
%define %%T8                    %28     ; temporary AVX512 register
%define %%T9                    %29     ; temporary AVX512 register
%define %%T10                   %30     ; temporary AVX512 register
%define %%T11                   %31     ; temporary AVX512 register
%define %%ZMM_SHFMASK           %32     ; [in] shuffle mask changing byte order in 4 128bit words
%define %%ENC_DEC               %33     ; [in] ENC (encrypt) or DEC (decrypt) selector

%define %%INP0                  %%TPTR0
%define %%INP1                  %%TPTR1
%define %%INP2                  %%TPTR2
%define %%INP3                  %%TPTR3

%define %%OUTP0                 %%TPTR0
%define %%OUTP1                 %%TPTR1
%define %%OUTP2                 %%TPTR2
%define %%OUTP3                 %%TPTR3

        ;; load data in
        mov             %%INP0, [%%IN + 8*0]
        mov             %%INP1, [%%IN + 8*1]
        mov             %%INP2, [%%IN + 8*2]
        mov             %%INP3, [%%IN + 8*3]

        VX512LDR        %%T4, [%%INP0 + (16*0)]
        VX512LDR        %%T5, [%%INP0 + (16*4)]
        VX512LDR        %%T6, [%%INP1 + (16*0)]
        VX512LDR        %%T7, [%%INP1 + (16*4)]
        VX512LDR        %%T8, [%%INP2 + (16*0)]
        VX512LDR        %%T9, [%%INP2 + (16*4)]
        VX512LDR        %%T10,[%%INP3 + (16*0)]
        VX512LDR        %%T11,[%%INP3 + (16*4)]

        ;; shuffle IVB's
        vpshufb         %%L0B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L0B47, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L1B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L1B47, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L2B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L2B47, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L3B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L3B47, %%ZMM_SHFMASK    ; perform a 16Byte swap

        ;; move to AES encryption rounds
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 0, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 1, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 2, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 3, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 4, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 5, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 6, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 7, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 8, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 9, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 10, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

%ifndef GCM128_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 11, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 12, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

%ifdef GCM256_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 13, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 14, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11
%endif
%endif

        ;; store
        mov             %%OUTP0, [%%OUT + 8*0]
        mov             %%OUTP1, [%%OUT + 8*1]
        mov             %%OUTP2, [%%OUT + 8*2]
        mov             %%OUTP3, [%%OUT + 8*3]

        VX512STR        [%%OUTP0 + (16*0)], %%L0B03
        VX512STR        [%%OUTP0 + (16*4)], %%L0B47
        VX512STR        [%%OUTP1 + (16*0)], %%L1B03
        VX512STR        [%%OUTP1 + (16*4)], %%L1B47
        VX512STR        [%%OUTP2 + (16*0)], %%L2B03
        VX512STR        [%%OUTP2 + (16*4)], %%L2B47
        VX512STR        [%%OUTP3 + (16*0)], %%L3B03
        VX512STR        [%%OUTP3 + (16*4)], %%L3B47

%ifidn  %%ENC_DEC, DEC
        ;; decryption - cipher text needs to go to GHASH phase
        vpshufb         %%L0B03, %%T4, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%T5, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%T6, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%T7, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%T8, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%T9, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%T10, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%T11, %%ZMM_SHFMASK
%else
        ;; encryption
        vpshufb         %%L0B03, %%L0B03, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%L0B47, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%L1B03, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%L1B47, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%L2B03, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%L2B47, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%L3B03, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%L3B47, %%ZMM_SHFMASK
%endif

        ;; xor encrypted block 0 with GHASH for the next GHASH round
        vmovdqa64       XWORD(%%T1), XWORD(%%GHASH)
        vextracti32x4   XWORD(%%T2), %%GHASH, 1
        vextracti32x4   XWORD(%%T3), %%GHASH, 2
        vextracti32x4   XWORD(%%T4), %%GHASH, 3

        vpxorq          %%L0B03, %%T1
        vpxorq          %%L1B03, %%T2
        vpxorq          %%L2B03, %%T3
        vpxorq          %%L3B03, %%T4
%endmacro                       ;INITIAL_BLOCKS_x4

;;; ===========================================================================
;;; ===========================================================================
;;; Encrypt 8 blocks at a time on 4 lanes
;;; GHASH the 8 previously encrypted ciphertext blocks (4 lanes)
%macro  GHASH_8_ENCRYPT_8_PARALLEL_x4 44
%define %%IN                    %1      ; pointer to array of pointers to plain/cipher text
%define %%OUT                   %2      ; pointer to array of pointers to cipher/plain text
%define %%KEYP0                 %3      ; pointer to expanded keys, lane 0
%define %%KEYP1                 %4      ; pointer to expanded keys, lane 1
%define %%KEYP2                 %5      ; pointer to expanded keys, lane 2
%define %%KEYP3                 %6      ; pointer to expanded keys, lane 3
%define %%TPTR0                 %7      ; temporary GP register (used as pointer)
%define %%TPTR1                 %8      ; temporary GP register (used as pointer)
%define %%TPTR2                 %9      ; temporary GP register (used as pointer)
%define %%TPTR3                 %10     ; temporary GP register (used as pointer)
%define %%DATA_OFFSET           %11     ; current data offset (used with text loads and stores)
%define %%CTRL0                 %12     ; counter blocks 4 to 7 for lane 0
%define %%CTRL1                 %13     ; counter blocks 4 to 7 for lane 1
%define %%CTRL2                 %14     ; counter blocks 4 to 7 for lane 2
%define %%CTRL3                 %15     ; counter blocks 4 to 7 for lane 3
%define %%L0B03                 %16     ; lane 0 blocks 0 to 3
%define %%L0B47                 %17     ; lane 0 blocks 4 to 7
%define %%L1B03                 %18	; lane 1 blocks 0 to 3
%define %%L1B47                 %19	; lane 1 blocks 4 to 7
%define %%L2B03                 %20	; lane 2 blocks 0 to 3
%define %%L2B47                 %21	; lane 2 blocks 4 to 7
%define %%L3B03                 %22	; lane 3 blocks 0 to 3
%define %%L3B47                 %23	; lane 3 blocks 4 to 7
%define %%GHASH    		%24     ; [in/out] GHASH for 4 lanes
%define %%T0    		%25
%define %%T1    		%26
%define %%T2    		%27
%define %%T3    		%28
%define %%T4    		%29
%define %%T5    		%30
%define %%T6    		%31
%define %%T7    		%32
%define %%T8    		%33
%define %%T9    		%34
%define %%PREVLO0		%35     ; [in] 4 lanes x 8 blocks of cipher text for GHASH
%define %%PREVHI0		%36
%define %%PREVLO1		%37
%define %%PREVHI1		%38
%define %%PREVLO2		%39
%define %%PREVHI2		%40
%define %%PREVLO3		%41
%define %%PREVHI3		%42
%define %%ZMM_SHFMASK           %43     ; [in] byte swap shuffle mask for 128 bits
%define %%ENC_DEC               %44     ; [in] ENC (encryption) or DEC (decryption)

;;; ============================================================================
;;; a few virtual register mappings
%define %%INP0                  %%TPTR0
%define %%INP1                  %%TPTR1
%define %%INP2                  %%TPTR2
%define %%INP3                  %%TPTR3

%define %%OUTP0                 %%TPTR0
%define %%OUTP1                 %%TPTR1
%define %%OUTP2                 %%TPTR2
%define %%OUTP3                 %%TPTR3

%define %%TH                    %%T5
%define %%TM                    %%T6
%define %%TL                    %%T7

%define %%TEXTL0B03		%%T8
%define %%TEXTL0B47		%%T9
%define %%TEXTL1B03		%%PREVLO1 ; GHASH needs to be complete before using these
%define %%TEXTL1B47		%%PREVHI1
%define %%TEXTL2B03		%%PREVLO2
%define %%TEXTL2B47		%%PREVHI2
%define %%TEXTL3B03		%%PREVLO3
%define %%TEXTL3B47		%%PREVHI3
;;; ============================================================================

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 0, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        mov             %%INP0, [%%IN + 8*0]
        mov             %%INP1, [%%IN + 8*1]
        mov             %%INP2, [%%IN + 8*2]
        mov             %%INP3, [%%IN + 8*3]

        ;; =====================================================================
        VCLMUL_STEP1 %%KEYP0, %%PREVHI0, %%T4, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 1, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP0, %%PREVHI0, %%PREVLO0, %%T4, %%T8, %%T9, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 2, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; =====================================================================

        VCLMUL_STEP1 %%KEYP1, %%PREVHI1, %%T4, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 3, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP1, %%PREVHI1, %%PREVLO1, %%T4, %%T8, %%T9, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 4, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; accumulate GHASH results from 4 lanes into [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]
        vinserti64x2    %%PREVLO0, XWORD(%%PREVLO1), 1
        vinserti64x2    %%PREVHI0, XWORD(%%PREVHI1), 1

        ;; =====================================================================

        VCLMUL_STEP1 %%KEYP2, %%PREVHI2, %%T4, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 5, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP2, %%PREVHI2, %%PREVLO2, %%T4, %%T8, %%T9, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 6, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; accumulate GHASH results from 4 lanes into [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]
        vinserti64x2    %%PREVLO0, XWORD(%%PREVLO2), 2
        vinserti64x2    %%PREVHI0, XWORD(%%PREVHI2), 2

        ;; =====================================================================

        VCLMUL_STEP1 %%KEYP3, %%PREVHI3, %%T4, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 7, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP3, %%PREVHI3, %%PREVLO3, %%T4, %%T8, %%T9, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 8, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; accumulate GHASH results from 4 lanes into [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]
        vinserti64x2    %%PREVLO0, XWORD(%%PREVLO3), 3
        vinserti64x2    %%PREVHI0, XWORD(%%PREVHI3), 3

        ;; =====================================================================
        ;; load plain/cipher text
        ;; - this cannot be done before GHASH is complete (reuses same registers)

        VX512LDR        %%TEXTL0B03, [%%INP0 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL0B47, [%%INP0 + %%DATA_OFFSET + 64*1]
        VX512LDR        %%TEXTL1B03, [%%INP1 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL1B47, [%%INP1 + %%DATA_OFFSET + 64*1]
        VX512LDR        %%TEXTL2B03, [%%INP2 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL2B47, [%%INP2 + %%DATA_OFFSET + 64*1]
        VX512LDR        %%TEXTL3B03, [%%INP3 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL3B47, [%%INP3 + %%DATA_OFFSET + 64*1]

        mov             %%OUTP0, [%%OUT + 8*0]
        mov             %%OUTP1, [%%OUT + 8*1]
        mov             %%OUTP2, [%%OUT + 8*2]
        mov             %%OUTP3, [%%OUT + 8*3]

        ;; =====================================================================
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 9, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 10, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

%ifndef GCM128_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 11, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 12, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
%ifdef GCM256_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 13, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 14, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
%endif                          ; GCM256
%endif                          ; !GCM128

        ;; =====================================================================
        ;; =====================================================================
        ;; =====================================================================

        ;; =====================================================================
        ;; first phase of the reduction (barret)
        ;; - becasue of bit ordering, LSB 128 bit word is reduced rather than MSB
        ;; - accumulated GHASH in [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]

        vmovdqu64       %%T3, [rel POLY2]

        vpclmulqdq      %%T4, %%T3, %%PREVLO0, 0x01
        vpslldq         %%T4, %%T4, 8                   ; shift-L 2 DWs
        vpxorq          %%PREVLO0, %%PREVLO0, %%T4      ; first phase of the reduction complete

        ;; =====================================================================
        ;; store cipher/plain text

        VX512STR        [%%OUTP0 + %%DATA_OFFSET + 64*0], %%L0B03
        VX512STR        [%%OUTP0 + %%DATA_OFFSET + 64*1], %%L0B47
        VX512STR        [%%OUTP1 + %%DATA_OFFSET + 64*0], %%L1B03
        VX512STR        [%%OUTP1 + %%DATA_OFFSET + 64*1], %%L1B47
        VX512STR        [%%OUTP2 + %%DATA_OFFSET + 64*0], %%L2B03
        VX512STR        [%%OUTP2 + %%DATA_OFFSET + 64*1], %%L2B47
        VX512STR        [%%OUTP3 + %%DATA_OFFSET + 64*0], %%L3B03
        VX512STR        [%%OUTP3 + %%DATA_OFFSET + 64*1], %%L3B47

        ;; =====================================================================
        ;; second phase of the reduction
        vpclmulqdq      %%T4, %%T3, %%PREVLO0, 0x00
        vpsrldq         %%T4, %%T4, 4                   ; shift-R 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%GHASH, %%T3, %%PREVLO0, 0x10
        vpslldq         %%GHASH, %%GHASH, 4             ; shift-L 1 DW (Shift-L 1-DW to obtain result with no shifts)

        ;; second phase of the reduction complete
        vpternlogq      %%GHASH, %%T4, %%PREVHI0, 0x96  ; GHASH = GHASH xor T4 xor PREVHI0

        ;; =====================================================================

        ;; prepare cipher blocks for the next GHASH round
%ifidn %%ENC_DEC, ENC
        vpshufb         %%L0B03, %%L0B03, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%L0B47, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%L1B03, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%L1B47, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%L2B03, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%L2B47, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%L3B03, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%L3B47, %%ZMM_SHFMASK
%else
        ;; GHASH is computed over cipher text (use text)
        vpshufb         %%L0B03, %%TEXTL0B03, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%TEXTL0B47, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%TEXTL1B03, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%TEXTL1B47, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%TEXTL2B03, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%TEXTL2B47, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%TEXTL3B03, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%TEXTL3B47, %%ZMM_SHFMASK
%endif

        ;; xor encrypted block 0 with GHASH for the next round
        vmovdqa64       XWORD(%%T1), XWORD(%%GHASH)
        vextracti32x4   XWORD(%%T2), %%GHASH, 1
        vextracti32x4   XWORD(%%T3), %%GHASH, 2
        vextracti32x4   XWORD(%%T4), %%GHASH, 3

        vpxorq          %%L0B03, %%T1
        vpxorq          %%L1B03, %%T2
        vpxorq          %%L2B03, %%T3
        vpxorq          %%L3B03, %%T4
%endmacro                       ; GHASH_8_ENCRYPT_8_PARALLEL_x4

;;; ===========================================================================
;;; ===========================================================================
;;; GHASH the last 8 ciphertext blocks on 4 lanes
%macro  GHASH_LAST_8x4 25
%define %%KEYP0                 %1      ; [in] pointer to expanded keys, lane 0
%define %%KEYP1                 %2      ; [in] pointer to expanded keys, lane 1
%define %%KEYP2                 %3      ; [in] pointer to expanded keys, lane 2
%define %%KEYP3                 %4      ; [in] pointer to expanded keys, lane 3
%define %%L0B03                 %5      ; [in] clobbered, ciper text, lane 0, blocks 0 to 3 (Y0 already XOR'ed on X1)
%define %%L0B47                 %6      ; [in] clobbered, ciper text, lane 0, blocks 4 to 7
%define %%L1B03                 %7      ; ...
%define %%L1B47                 %8
%define %%L2B03                 %9
%define %%L2B47                 %10
%define %%L3B03                 %11     ; ...
%define %%L3B47                 %12     ; [in] clobbered, ciper text, lane 3, blocks 4 to 7
%define %%GHASH    		%13     ; [out] ghash output
%define %%T1    		%14
%define %%T2    		%15
%define %%T3    		%16
%define %%T4    		%17
%define %%T5    		%18
%define %%T6    		%19
%define %%T7    		%20
%define %%T8    		%21
%define %%T9    		%22
%define %%T10    		%23
%define %%T11    		%24
%define %%T12   		%25

%define %%TH                    %%T5
%define %%TM                    %%T6
%define %%TL                    %%T7

%define %%L                     %%T1
%define %%H                     %%T2

        ;; =====================================================================
        ;; lane 0, 8 blocks

        VCLMUL_STEP1    %%KEYP0, %%L0B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP0, %%L0B47, %%L0B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vmovdqa64       XWORD(%%L), XWORD(%%L0B03)
        vmovdqa64       XWORD(%%H), XWORD(%%L0B47)

        ;; =====================================================================
        ;; lane 1, 8 blocks

        VCLMUL_STEP1    %%KEYP1, %%L1B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP1, %%L1B47, %%L1B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vinserti64x2    %%L, XWORD(%%L1B03), 1
        vinserti64x2    %%H, XWORD(%%L1B47), 1

        ;; =====================================================================
        ;; lane 2, 8 blocks

        VCLMUL_STEP1    %%KEYP2, %%L2B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP2, %%L2B47, %%L2B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vinserti64x2    %%L, XWORD(%%L2B03), 2
        vinserti64x2    %%H, XWORD(%%L2B47), 2

        ;; =====================================================================
        ;; lane 3, 8 blocks

        VCLMUL_STEP1    %%KEYP3, %%L3B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP3, %%L3B47, %%L3B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vinserti64x2    %%L, XWORD(%%L3B03), 3
        vinserti64x2    %%H, XWORD(%%L3B47), 3

        ;; =====================================================================
        ;; =====================================================================
        ;; first phase of the reduction <H(hi):L(low)>
        ;; - reducing L, rather H, due to bit ordering

        vmovdqu64       %%T3, [rel POLY2]

        vpclmulqdq      %%T4, %%T3, %%L, 0x01
        vpslldq         %%T4, %%T4, 8           ; shift-L xmm2 2 DWs

        vpxorq          %%L, %%L, %%T4          ; first phase of the reduction complete

        ;; =====================================================================
        ;; second phase of the reduction
        vpclmulqdq      %%T4, %%T3, %%L, 0x00
        vpsrldq         %%T4, %%T4, 4           ; shift-R 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%GHASH, %%T3, %%L, 0x10
        vpslldq         %%GHASH, %%GHASH, 4     ; shift-L 1 DW (Shift-L 1-DW to obtain result with no shifts)

        ;; second phase of the reduction complete
        vpternlogq      %%GHASH, %%T4, %%H, 0x96  ; GHASH = GHASH xor T4 xor H
        ;; =====================================================================
%endmacro

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_ENC_DEC_4x128 Encodes/Decodes given data
;;; - 4 lanes, 8 blocks at a time (hence 4x128 bytes or 4x8 blocks)
;;; - assumes that the passed gcm_context_data struct has been initialized by GCM_INIT
;;; - requires the input data be multiple of 128 bytes
;;; Input: gcm_key_data struct *GDATA_KEY[4]
;;;        gcm_context_data *GDATA_CTX[4]
;;;        input text PLAIN_CYPH_IN[4]
;;;        input text length (PLAIN_CYPH_LEN) and
;;;        whether encoding or decoding (ENC_DEC).
;;; Output: A cipher of the given plain text CYPH_PLAIN_OUT[4]
;;;         updated GDATA_CTX[4]
;;; Linux clobbers:   rax, rbx, rcx, rdx, rbp, r8-r15, zmm0-zmm31
;;; Windows clobbers: rax, rbx, rdi ,rsi, rbp, r8-r15, zmm0-zmm31
;;; ===========================================================================
%macro  GCM_ENC_DEC_4x128       3
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded keys
%define %%PLAIN_CYPH_LEN        %2 ; [in] length of the text to process (multiple of 128 bytes)
%define %%ENC_DEC               %3 ; [in] ENC (encrypt) or DEC (decrypt) selector

%define %%GDATA_KEY             %%STATE + _gcm_args_keys
%define %%GDATA_CTX             %%STATE + _gcm_args_ctx
%define %%CYPH_PLAIN_OUT        %%STATE + _gcm_args_out
%define %%PLAIN_CYPH_IN         %%STATE + _gcm_args_in

%define %%LEN_REG               %%PLAIN_CYPH_LEN
%define %%DATA_OFFSET           r14 ;; @note: on windows this reg is used to retrive stack args

;;; ===========================================================================
;;; register mappings within the macro

%define %%TPTR0                 r9
%define %%TPTR1                 r10
%define %%TPTR2                 r11
%define %%TPTR3                 r12

%define %%GPR0                  rax
%define %%GPR1                  rbx
%define %%GPR2                  rbp
%define %%GPR3                  r15

%ifidn __OUTPUT_FORMAT__, win64
%define %%KPTR0                 r8
%define %%KPTR1                 r13
%define %%KPTR2                 rdi
%define %%KPTR3                 rsi
%else
%define %%KPTR0                 rdx
%define %%KPTR1                 rcx
%define %%KPTR2                 r8
%define %%KPTR3                 r13
%endif

%define %%L0B03                 zmm0
%define %%L0B47                 zmm1
%define %%L1B03                 zmm2
%define %%L1B47                 zmm3
%define %%L2B03                 zmm4
%define %%L2B47                 zmm5
%define %%L3B03                 zmm6
%define %%L3B47                 zmm7

%define %%T1                    zmm8
%define %%T2                    zmm9
%define %%T3                    zmm10
%define %%T4                    zmm11
%define %%T5                    zmm12
%define %%T6                    zmm13
%define %%T7                    zmm14
%define %%T8                    zmm15
%define %%T9                    zmm16
%define %%T10                   zmm17
%define %%T11                   zmm18
%define %%T12                   zmm19
%define %%T13                   zmm20
%define %%T14                   zmm21
%define %%T15                   zmm22
%define %%T16                   zmm23
%define %%T17                   zmm24
%define %%T18                   zmm25

%define %%GHASH                 zmm26

%define %%CTRL0                 zmm27
%define %%CTRL1                 zmm28
%define %%CTRL2                 zmm29
%define %%CTRL3                 zmm30

%define %%ZMM_SHUF_MASK         zmm31

;;; ===========================================================================
;;; virtual register mappings

%define %%PREVLO0		%%T11 ; 4 lanes x 8 blocks of cipher text for GHASH
%define %%PREVHI0		%%T12
%define %%PREVLO1		%%T13
%define %%PREVHI1		%%T14
%define %%PREVLO2		%%T15
%define %%PREVHI2		%%T16
%define %%PREVLO3		%%T17
%define %%PREVHI3		%%T18

;;; ===========================================================================

        or              %%LEN_REG, %%LEN_REG
        jz              %%_enc_dec_done_x4

        mov             %%DATA_OFFSET, 128

        ;; load GCM CTX pointers for 4 lanes
        mov             %%TPTR0, [%%GDATA_CTX + (0*8)]
        mov             %%TPTR1, [%%GDATA_CTX + (1*8)]
        mov             %%TPTR2, [%%GDATA_CTX + (2*8)]
        mov             %%TPTR3, [%%GDATA_CTX + (3*8)]

        ;;  load common constants used in the code
        vmovdqa64       %%ZMM_SHUF_MASK, [rel SHUF_MASK]

        ;; Update length of data processed
        add             [%%TPTR0 + InLen], %%LEN_REG
        add             [%%TPTR1 + InLen], %%LEN_REG
        add             [%%TPTR2 + InLen], %%LEN_REG
        add             [%%TPTR3 + InLen], %%LEN_REG

        ;; extract current hash values from 4 lanes
        vmovdqu64       XWORD(%%GHASH), [%%TPTR0 + AadHash]
        vinserti64x2    %%GHASH, [%%TPTR1 + AadHash], 1
        vinserti64x2    %%GHASH, [%%TPTR2 + AadHash], 2
        vinserti64x2    %%GHASH, [%%TPTR3 + AadHash], 3

        ;;  lift CTR set from initial_blocks to here
        vmovdqa64       %%T1, [rel ddq_add_1234]
        vmovdqa64       %%T2, [rel ddq_add_5678]
        vbroadcastf64x2 %%CTRL0, [%%TPTR0 + CurCount]
        vbroadcastf64x2 %%CTRL1, [%%TPTR1 + CurCount]
        vbroadcastf64x2 %%CTRL2, [%%TPTR2 + CurCount]
        vbroadcastf64x2 %%CTRL3, [%%TPTR3 + CurCount]
        vpaddd          %%L0B03, %%CTRL0, %%T1
        vpaddd          %%L1B03, %%CTRL1, %%T1
        vpaddd          %%L2B03, %%CTRL2, %%T1
        vpaddd          %%L3B03, %%CTRL3, %%T1
        vpaddd          %%L0B47, %%CTRL0, %%T2
        vpaddd          %%L1B47, %%CTRL1, %%T2
        vpaddd          %%L2B47, %%CTRL2, %%T2
        vpaddd          %%L3B47, %%CTRL3, %%T2
        vmovdqa64       %%CTRL0, %%L0B47
        vmovdqa64       %%CTRL1, %%L1B47
        vmovdqa64       %%CTRL2, %%L2B47
        vmovdqa64       %%CTRL3, %%L3B47

        ;; load GCM key pointers for 4 lanes
        mov             %%KPTR0, [%%GDATA_KEY + (0*8)]
        mov             %%KPTR1, [%%GDATA_KEY + (1*8)]
        mov             %%KPTR2, [%%GDATA_KEY + (2*8)]
        mov             %%KPTR3, [%%GDATA_KEY + (3*8)]

%%_cipher_only_x4:
        ;; run cipher only over the first 8 blocks
        INITIAL_BLOCKS_x4       %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, \
                                %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                                %%TPTR0, %%TPTR1, %%TPTR2, %%TPTR3, \
                                %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                                %%GHASH, \
                                %%T1, %%T2, %%T3, %%T4, %%T5, %%T6, %%T7, %%T8, \
                                %%T9, %%T10, %%T11, %%T12, \
                                %%ZMM_SHUF_MASK, %%ENC_DEC

        ;; Update length
        sub     %%LEN_REG, 128
        jz      %%_encrypt_done_x4

        vmovq   %%GPR0, XWORD(%%CTRL0)
        vmovq   %%GPR1, XWORD(%%CTRL1)
        vmovq   %%GPR2, XWORD(%%CTRL2)
        vmovq   %%GPR3, XWORD(%%CTRL3)

        and     %%GPR0, 255
        and     %%GPR1, 255
        and     %%GPR2, 255
        and     %%GPR3, 255

        ;; shuffle the counters to BE
	vpshufb %%CTRL0, %%ZMM_SHUF_MASK
	vpshufb %%CTRL1, %%ZMM_SHUF_MASK
	vpshufb %%CTRL2, %%ZMM_SHUF_MASK
	vpshufb %%CTRL3, %%ZMM_SHUF_MASK

%%_encrypt_by_8_parallel_x4:
        ;; get max counter value
        cmp     %%GPR0, %%GPR1
        cmova   %%GPR1, %%GPR0
        cmp     %%GPR2, %%GPR1
        cmova   %%GPR1, %%GPR2
        cmp     %%GPR3, %%GPR1
        cmova   %%GPR1, %%GPR3
        ;; at this stage %%GPR1 includes max 8-bit LS counter from 4 lanes

        ;; if max counter is above 244 then overflow will occur
        cmp     %%GPR1, 244
        ja      %%_encrypt_by_8_overflow_x4

        ;; (256 - 8) because we process 8 blocks at a time
        ;; Max number of blocks that can be processed in a lane
        ;; without shuffling is (256 - 8)
        mov     %%GPR0, (256 - 8)
        sub     %%GPR0, %%GPR1
        shr     %%GPR0, 3
        ;; GPR0 holds number of iterations based on remaing blocks before overflow

        ;; get number of iterations from the remaining byte length
        mov     %%GPR1, %%LEN_REG
        shr     %%GPR1, 7

        ;; pick the smallest one (GPR0 will be the counter)
        cmp     %%GPR1, %%GPR0
        cmovb   %%GPR0, %%GPR1

%%_encrypt_by_8_x4:
        ;; copy previously encrypted blocks for GHASH
	vmovdqa64	%%PREVLO0, %%L0B03
	vmovdqa64	%%PREVHI0, %%L0B47
	vmovdqa64	%%PREVLO1, %%L1B03
	vmovdqa64	%%PREVHI1, %%L1B47
	vmovdqa64	%%PREVLO2, %%L2B03
	vmovdqa64	%%PREVHI2, %%L2B47
	vmovdqa64	%%PREVLO3, %%L3B03
	vmovdqa64	%%PREVHI3, %%L3B47

        ;; - no byte overflow and no shuffling required
        vmovdqa64       %%T1, [rel ddq_addbe_4444]
        vmovdqa64       %%T2, [rel ddq_addbe_8888]

        vpaddd          %%L0B03, %%CTRL0, %%T1
        vpaddd          %%L1B03, %%CTRL1, %%T1
        vpaddd          %%L2B03, %%CTRL2, %%T1
        vpaddd          %%L3B03, %%CTRL3, %%T1
        vpaddd          %%L0B47, %%CTRL0, %%T2
        vpaddd          %%L1B47, %%CTRL1, %%T2
        vpaddd          %%L2B47, %%CTRL2, %%T2
        vpaddd          %%L3B47, %%CTRL3, %%T2

        vmovdqa64       %%CTRL0, %%L0B47
        vmovdqa64       %%CTRL1, %%L1B47
        vmovdqa64       %%CTRL2, %%L2B47
        vmovdqa64       %%CTRL3, %%L3B47

        GHASH_8_ENCRYPT_8_PARALLEL_x4   %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, \
                                        %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                                        %%TPTR0, %%TPTR1, %%TPTR2, %%TPTR3, \
                                        %%DATA_OFFSET, \
                                        %%CTRL0, %%CTRL1, %%CTRL2, %%CTRL3, \
                                        %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                                        %%GHASH, \
                                        %%T1, %%T2, %%T3,  %%T4,  %%T5,  %%T6,  %%T7, \
                                        %%T8, %%T9, %%T10, \
                                        %%PREVLO0, %%PREVHI0, %%PREVLO1, %%PREVHI1, \
                                        %%PREVLO2, %%PREVHI2, %%PREVLO3, %%PREVHI3, \
                                        %%ZMM_SHUF_MASK, %%ENC_DEC
        add     %%DATA_OFFSET, 128
        sub     %%LEN_REG, 128
        sub     %%GPR0, 1
        jnz     %%_encrypt_by_8_x4

%%_encrypt_by_8_overflow_x4:
        ;; shuffle the counters back to LE
	vpshufb %%CTRL0, %%ZMM_SHUF_MASK
	vpshufb %%CTRL1, %%ZMM_SHUF_MASK
	vpshufb %%CTRL2, %%ZMM_SHUF_MASK
	vpshufb %%CTRL3, %%ZMM_SHUF_MASK

        or      %%LEN_REG, %%LEN_REG
        jz      %%_encrypt_done_x4

        ;; copy previously encrypted blocks for GHASH
	vmovdqa64	%%PREVLO0, %%L0B03
	vmovdqa64	%%PREVHI0, %%L0B47
	vmovdqa64	%%PREVLO1, %%L1B03
	vmovdqa64	%%PREVHI1, %%L1B47
	vmovdqa64	%%PREVLO2, %%L2B03
	vmovdqa64	%%PREVHI2, %%L2B47
	vmovdqa64	%%PREVLO3, %%L3B03
	vmovdqa64	%%PREVHI3, %%L3B47

        ;; prepare new counter blocks in LE
        vmovdqa64       %%T1, [rel ddq_add_4444]
        vmovdqa64       %%T2, [rel ddq_add_8888]
        vpaddd          %%L0B03, %%CTRL0, %%T1
        vpaddd          %%L1B03, %%CTRL1, %%T1
        vpaddd          %%L2B03, %%CTRL2, %%T1
        vpaddd          %%L3B03, %%CTRL3, %%T1
        vpaddd          %%L0B47, %%CTRL0, %%T2
        vpaddd          %%L1B47, %%CTRL1, %%T2
        vpaddd          %%L2B47, %%CTRL2, %%T2
        vpaddd          %%L3B47, %%CTRL3, %%T2

        ;; save the counter to GPR's for calculation of number of loops
        vmovq   %%GPR0, XWORD(%%L0B47)
        vmovq   %%GPR1, XWORD(%%L1B47)
        vmovq   %%GPR2, XWORD(%%L2B47)
        vmovq   %%GPR3, XWORD(%%L3B47)

        and     %%GPR0, 255
        and     %%GPR1, 255
        and     %%GPR2, 255
        and     %%GPR3, 255

        ;; convert counter blocks to BE
	vpshufb 	%%L0B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L0B47, %%ZMM_SHUF_MASK
	vpshufb 	%%L1B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L1B47, %%ZMM_SHUF_MASK
	vpshufb 	%%L2B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L2B47, %%ZMM_SHUF_MASK
	vpshufb 	%%L3B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L3B47, %%ZMM_SHUF_MASK

        ;; update 4 lane CTR in BE
        vmovdqa64       %%CTRL0, %%L0B47
        vmovdqa64       %%CTRL1, %%L1B47
        vmovdqa64       %%CTRL2, %%L2B47
        vmovdqa64       %%CTRL3, %%L3B47

        GHASH_8_ENCRYPT_8_PARALLEL_x4   %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, \
                                        %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                                        %%TPTR0, %%TPTR1, %%TPTR2, %%TPTR3, \
                                        %%DATA_OFFSET, \
                                        %%CTRL0, %%CTRL1, %%CTRL2, %%CTRL3, \
                                        %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                                        %%GHASH, \
                                        %%T1, %%T2, %%T3,  %%T4,  %%T5,  %%T6,  %%T7, \
                                        %%T8, %%T9, %%T10, \
                                        %%PREVLO0, %%PREVHI0, %%PREVLO1, %%PREVHI1, \
                                        %%PREVLO2, %%PREVHI2, %%PREVLO3, %%PREVHI3, \
                                        %%ZMM_SHUF_MASK, %%ENC_DEC
        add     %%DATA_OFFSET, 128
        sub     %%LEN_REG, 128
        jnz     %%_encrypt_by_8_parallel_x4

        ;; shuffle the counters back to LE
	vpshufb %%CTRL0, %%ZMM_SHUF_MASK
	vpshufb %%CTRL1, %%ZMM_SHUF_MASK
	vpshufb %%CTRL2, %%ZMM_SHUF_MASK
	vpshufb %%CTRL3, %%ZMM_SHUF_MASK

%%_encrypt_done_x4:
        GHASH_LAST_8x4  %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                        %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%GHASH, \
                        %%T1, %%T2, %%T3, %%T4, %%T5, %%T6, \
                        %%T7, %%T8, %%T9, %%T10, %%T11, %%T12

%%_ghash_done_x4:
        mov     %%TPTR0, [%%GDATA_CTX + (0*8)]
        mov     %%TPTR1, [%%GDATA_CTX + (1*8)]
        mov     %%TPTR2, [%%GDATA_CTX + (2*8)]
        mov     %%TPTR3, [%%GDATA_CTX + (3*8)]

        ;; save current counter blocks
        vextracti32x4   [%%TPTR0 + CurCount], %%CTRL0, 3
        vextracti32x4   [%%TPTR1 + CurCount], %%CTRL1, 3
        vextracti32x4   [%%TPTR2 + CurCount], %%CTRL2, 3
        vextracti32x4   [%%TPTR3 + CurCount], %%CTRL3, 3

        ;; save current hash values
        vmovdqu64       [%%TPTR0 + AadHash], XWORD(%%GHASH)
        vextracti64x2   [%%TPTR1 + AadHash], %%GHASH, 1
        vextracti64x2   [%%TPTR2 + AadHash], %%GHASH, 2
        vextracti64x2   [%%TPTR3 + AadHash], %%GHASH, 3

        ;; decrement lens
        ;; increment the input / output pointers
        ;; - output and input pointers are next to one another in the structure
        ;;   so updating all 8 pointers with a single zmm
        vpbroadcastq    %%T1, %%DATA_OFFSET     ; DATA_OFFSET should be equal to length
        vpaddq          %%T2, %%T1, [%%CYPH_PLAIN_OUT]
        vmovdqu64       [%%CYPH_PLAIN_OUT], %%T2
        vmovdqu64       YWORD(%%T3), [%%STATE + _gcm_lens]
        vpsubq          YWORD(%%T3), YWORD(%%T3), YWORD(%%T1)
        vmovdqu64       [%%STATE + _gcm_lens], YWORD(%%T3)

%%_enc_dec_done_x4:


%endmacro                       ; GCM_ENC_DEC_4x128

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_COMPLETE_x4 - completes one of MB jobs
;;; Clobbers rax, r9-r12, r14, r15 and zmm0-zmm31
;;; ===========================================================================
%macro  GCM_COMPLETE_x4         3
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%IDX                   %2 ; [in] lane index to be completed
%define %%ENC_DEC               %3

%ifidn __OUTPUT_FORMAT__, win64
%define %%GDATA_KEY             rdi
%define %%GDATA_CTX             rsi
%define %%CYPH_PLAIN_OUT        r11
%define %%PLAIN_CYPH_IN         r9
%else
%define %%GDATA_KEY             arg3
%define %%GDATA_CTX             arg4
%define %%CYPH_PLAIN_OUT        r8
%define %%PLAIN_CYPH_IN         r9
%endif


%define %%PLAIN_CYPH_LEN        rbp
%define %%AUTH_TAG              rbp
%define %%AUTH_TAGLEN           rbp

%define %%GPR                   rax

%define %%DATA_OFFSET           rbx

        mov             %%PLAIN_CYPH_LEN, [%%STATE + _gcm_lens + %%IDX*8]
        mov             %%GDATA_KEY, [%%STATE + _gcm_args_keys + %%IDX*8]
        mov             %%GDATA_CTX, [%%STATE + _gcm_args_ctx + %%IDX*8]
        mov             %%PLAIN_CYPH_IN, [%%STATE + _gcm_args_in + %%IDX*8]
        mov             %%CYPH_PLAIN_OUT, [%%STATE + _gcm_args_out + %%IDX*8]

        vmovdqu64       xmm16, [%%GDATA_KEY + HashKey]
        vmovdqu64       xmm17, [%%GDATA_CTX + AadHash]

;;; ===========================================================================
;;; finalize last blocks (<128 bytes)

;;; Macro flow:
;;; calculate the number of 16byte blocks in the message
;;; process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
;;; process 8 16 byte blocks at a time until all are done '%%_encrypt_by_8_new .. %%_eight_cipher_left'
;;; if there is a block of less tahn 16 bytes process it '%%_zero_cipher_left .. %%_multiple_of_16_bytes'

        or      %%PLAIN_CYPH_LEN, %%PLAIN_CYPH_LEN
        je      %%_enc_dec_done_x4

        xor     %%DATA_OFFSET, %%DATA_OFFSET

        ;; Update length of data processed
        add    [%%GDATA_CTX + InLen], %%PLAIN_CYPH_LEN

        vmovdqa64       xmm13, xmm16    ; load HashKey
        vmovdqu         xmm9, [%%GDATA_CTX + CurCount]

        ;; Save the amount of data left to process in r10
        mov     r13, %%PLAIN_CYPH_LEN

        ;; Determine how many blocks to process in INITIAL
        ;; - round up number of blocks for INITIAL in case of partial block
        mov     r12, %%PLAIN_CYPH_LEN
        add     r12, 15
        shr     r12, 4

        GCM_ENC_DEC_SMALL %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%PLAIN_CYPH_LEN, %%ENC_DEC, %%DATA_OFFSET, \
                r13, r12, xmm9, xmm17, single_call, \
                zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, zmm24, zmm25, zmm26, %%GPR, r15, k1

%%_ghash_done_x4:
        vmovdqu         [%%GDATA_CTX + CurCount], xmm9  ; current_counter = xmm9

%%_enc_dec_done_x4:
;;; ===========================================================================
;;; COMPLETE

        ;; Start AES as early as possible
        vmovdqu64       xmm9, [%%GDATA_CTX + OrigIV]    ; xmm9 = Y0
        ENCRYPT_SINGLE_BLOCK %%GDATA_KEY, xmm9  ; E(K, Y0)

        ;; If the GCM function is called as a single function call rather
        ;; than invoking the individual parts (init, update, finalize) we
        ;; can remove a write to read dependency on AadHash.
        vmovdqa64       xmm14, xmm17    ; xmm14 = AadHash
        vmovdqa64       xmm13, xmm16    ; load HashKey

%%_partial_done_x4:
        mov             %%GPR, [%%GDATA_CTX + AadLen]    ; aadLen (number of bytes)
        shl             %%GPR, 3                         ; convert into number of bits
        vmovd           xmm15, DWORD(%%GPR)              ; len(A) in xmm15

        mov             %%GPR, [%%GDATA_CTX + InLen]
        shl             %%GPR, 3                         ; len(C) in bits  (*128)
        vmovq           xmm1, %%GPR
        vpslldq         xmm15, xmm15, 8                  ; xmm15 = len(A)|| 0x0000000000000000
        vpor            xmm15, xmm15, xmm1               ; xmm15 = len(A)||len(C)

        ;; prep auth_tag store mask
        mov             %%AUTH_TAGLEN, [%%STATE + _gcm_args_taglen + %%IDX*8]
        lea             %%GPR, [rel byte_len_to_mask_table]
        kmovw           k1, [%%GPR + %%AUTH_TAGLEN*2]
        mov             %%AUTH_TAG, [%%STATE + _gcm_args_tag + %%IDX*8]

        ;; XOR current hash value with the next block xmm15
        vpxorq          xmm14, xmm15

        ;; xmm14: hash value [in/out]
        ;; xmm13: hash key [in]
        ;; xmm0, xmm10, xmm11, xmm5, xmm6 - temporary registers
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6
        vpshufb         xmm14, [rel SHUF_MASK]         ; perform a 16Byte swap

        vpxorq          xmm9, xmm9, xmm14

%%_return_T:
        vmovdqu8        [%%AUTH_TAG]{k1}, xmm9         ; store TAG
	vmovdqu64       [%%GDATA_CTX + AadHash], xmm17 ; store AadHash

        ;; put the lane back on free list
        mov             rax, [%%STATE + _gcm_unused_lanes]
        shl             rax, 4
        or              rax, %%IDX
        mov             [%%STATE + _gcm_unused_lanes], rax

        ;; mark job as complete
        mov             rax, [%%STATE + _gcm_job_in_lane + 8*%%IDX]
        or              dword [rax + _status], STS_COMPLETED
        ;; clear job pointer in this lane
        mov             qword [%%STATE + _gcm_job_in_lane + 8*%%IDX], 0
        ;; return finished job (rax)
%%_return_T_done:
%endmacro ; GCM_COMPLETE_x4


;;; ===========================================================================
;;; ===========================================================================
;;; GCM_FINALIZE_x4:
;;; - runs all lanes in parallel for %LEN
;;; - completes slected lane (any outstanding bytes < 128 bytes)
;;; - returns pointer of completed JOB
;;; Clobbers rax, r9-r12, r14, r15 and zmm0-zmm31
;;; ===========================================================================
%macro  GCM_FINALIZE_x4         4
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%IDX                   %2 ; [in] lane index to be completed
%define %%LEN                   %3 ; [in] common length to be prcessed across all lanes
%define %%ENC_DEC               %4

%%_gcm_finalize_4x128:
        ;;  save %IDX as it will get clobbered
        mov     [rsp + STACK_LOCAL_OFFSET + 0*8], %%IDX
        and     %%LEN, -128
        mov     arg2, %%LEN
        GCM_ENC_DEC_4x128 %%STATE, arg2, %%ENC_DEC

%%_gcm_complete_min_lane:
        ;;  restore %%IDX
        mov     arg2, [rsp + STACK_LOCAL_OFFSET + 0*8]
        GCM_COMPLETE_x4 %%STATE, arg2, %%ENC_DEC
%endmacro ; GCM_FINALIZE_x4
;;; ===========================================================================

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_FLUSH_MB:
;;; - finds min not null lane
;;; - replicates non_null data across null lanes
;;; - returns min length lane index and length
;;; ===========================================================================
%macro  GCM_FLUSH_MB 3
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%IDX                   %2 ; [out] lane index to be completed
%define %%LEN                   %3 ; [out] common length to be prcessed across all lanes

        ;; put max length into null lanes
        vmovdqu64       ymm0, [%%STATE + _gcm_job_in_lane]
        vpxorq          ymm1, ymm1
        vpcmpq          k2, ymm0, ymm1, 0 ; EQ

        kmovq           rax, k2           ; k2 = mask for null lanes
        xor             rax, 0xf
        kmovq           k1, rax           ; k1 = mask for not null lanes (~k2)

        vmovdqu64       ymm2, [%%STATE + _gcm_lens]
        vbroadcastf64x2 ymm4, [rel ALL_F]
        vporq           ymm2{k2}, ymm2, ymm4

        ;; find min lane & index
        vpsllq          ymm3, ymm2, 2 ;
        vporq           ymm3, ymm3, [rel index_to_lane4]
        vextracti32x4   xmm2, ymm3, 1
        vpminuq         xmm2, xmm3, xmm2
        vpsrldq         xmm3, xmm2, 8
        vpminuq         xmm2, xmm3, xmm2
        vmovq           %%LEN, xmm2
        mov             %%IDX, %%LEN
        and             %%IDX, 3
        shr             %%LEN, 2
        ;; At this stage:
        ;;   %%LEN - min length
        ;;   %%IDX - lane index

        ;; load context structure content from the non-null lane
        ;; it is 88 bytes long (64 + 24)
        ;; zmm7:ymm11
        mov             rax, 0x7
        kmovq           k3, rax
        mov             r10, [%%STATE + _gcm_args_ctx + 8*%%IDX]
        vmovdqu64       zmm7, [r10]
        vmovdqu64       ymm11{k3}, [r10 + 64]

        vmovdqu64       ymm7, [%%STATE + _gcm_args_in]
        vmovdqu64       ymm8, [%%STATE + _gcm_args_out]
        vmovdqu64       ymm9, [%%STATE + _gcm_args_keys]
        mov             r10, [%%STATE + _gcm_args_in + 8*%%IDX]
        mov             r11, [%%STATE + _gcm_args_out + 8*%%IDX]
        mov             r12, [%%STATE + _gcm_args_keys + 8*%%IDX]
        ;; r10 = (min lane) valid in ptr
        ;; r11 = (min lane) valid out ptr
        ;; r12 = (min lane) valid keys ptr

        ;; store valid in/out/key pointers to empty lanes
        vpbroadcastq    ymm4, r10
        vpbroadcastq    ymm5, r11
        vpbroadcastq    ymm6, r12

        vmovdqa64       ymm4{k1}, ymm7
        vmovdqa64       ymm5{k1}, ymm8
        vmovdqa64       ymm6{k1}, ymm9

        vmovdqu64       [%%STATE + _gcm_args_in], ymm4
        vmovdqu64       [%%STATE + _gcm_args_out], ymm5
        vmovdqu64       [%%STATE + _gcm_args_keys], ymm6

        ;; copy valid context into empty lanes
        kmovq           rax, k2 ; null lane mask to rax
        test            rax, 1
        jz              %%_copy_ctx_lane1
        mov             r10, [%%STATE + _gcm_args_ctx + 8*0]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_lane1:
        test            rax, 2
        jz              %%_copy_ctx_lane2
        mov             r10, [%%STATE + _gcm_args_ctx + 8*1]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_lane2:
        test            rax, 4
        jz              %%_copy_ctx_lane3
        mov             r10, [%%STATE + _gcm_args_ctx + 8*2]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_lane3:
        test            rax, 8
        jz              %%_copy_ctx_end
        mov             r10, [%%STATE + _gcm_args_ctx + 8*3]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_end:

%endmacro ; GCM_FLUSH_MB
;;; ===========================================================================

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_SUBMIT_MB:
;;; - finds free lane and populates it with data from JOB
;;; - if all lanes populated then finds min common length
;;; - returns min length lane index and size
;;; ===========================================================================
%macro  GCM_SUBMIT_MB 4
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%JOB                   %2 ; [in] lane index to be completed / [out] index
%define %%LEN                   %3 ; [out] common length to be prcessed across all lanes
%define %%ENC_DEC               %4 ; [in] encrypt / decrypt selector

%define %%IDX       rbp
%define %%RET_IDX   %%JOB
%ifidn __OUTPUT_FORMAT__, win64
%define %%LCTX      rdi
%else
%define %%LCTX      r8
%endif
        ;; get free lane
        mov             rbx, [%%STATE + _gcm_unused_lanes]
        mov             %%IDX, rbx
        shr             rbx, 4
        and             %%IDX, 0xf
        mov             [%%STATE + _gcm_unused_lanes], rbx

        ;; copy job data into the lane
        mov             [%%STATE + _gcm_job_in_lane + 8*%%IDX], %%JOB

        mov             r9, [%%JOB + _aes_enc_key_expanded]
        mov             [%%STATE + _gcm_args_keys + 8*%%IDX], r9

        mov             rax, [%%JOB + _src]
        add             rax, [%%JOB + _cipher_start_src_offset_in_bytes]
        mov             [%%STATE + _gcm_args_in + 8*%%IDX], rax

        mov             rax, [%%JOB + _dst]
        mov             [%%STATE + _gcm_args_out + 8*%%IDX], rax

        mov             rax, [%%JOB + _auth_tag_output]
        mov             [%%STATE + _gcm_args_tag + 8*%%IDX], rax

        mov             rax, [%%JOB + _auth_tag_output_len_in_bytes]
        mov             [%%STATE + _gcm_args_taglen + 8*%%IDX], rax

        vpbroadcastq    ymm15, [%%JOB + _msg_len_to_cipher_in_bytes]

        lea             rax, [rel index_to_lane4_mask]
        kmovw           k2, [rax + (index_to_lane4_not_mask - index_to_lane4_mask) + %%IDX*2]
        kmovw           k1, [rax + %%IDX*2]
        vmovdqu64       ymm14{k2}{z}, [%%STATE + _gcm_lens]
        vporq           ymm14{k1}, ymm14, ymm15
        vmovdqu64       [%%STATE + _gcm_lens], ymm14
        vmovdqu64       ymm31, ymm14

        ;; call gcm_init
        mov             r13, [%%JOB + _iv]
        mov             r14, [%%JOB + _gcm_aad]
        mov             rax, [%%JOB + _gcm_aad_len]
        mov             %%LCTX, [%%STATE + _gcm_args_ctx + 8*%%IDX]

        ;; GDATA_KEY     %1
        ;; GDATA_CTX     %2
        ;; IV            %3
        ;; A_IN          %4
        ;; A_LEN         %5
        ;; r10-r12 - temporary GPR's
        GCM_INIT        r9, %%LCTX, r13, r14, rax, r10, r11, r12, k1, xmm14, xmm2, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10

        ;; check if all lanes populated
        cmp             rbx, 0xf
        je              %%_gcm_ooo_ready
%%_gcm_ooo_not_ready:
        xor             rax, rax ; return NULL
        jmp             %%_gcm_submit_return

%%_gcm_ooo_ready:
        ;; find min lane & index
        vpsllq          ymm2, ymm31, 2 ;
        vporq           ymm2, ymm2, [rel index_to_lane4]
        vextracti32x4   xmm3, ymm2, 1
        vpminuq         xmm2, xmm3, xmm2
        vpsrldq         xmm3, xmm2, 8
        vpminuq         xmm2, xmm3, xmm2
        vmovq           %%LEN, xmm2
        mov             %%RET_IDX, %%LEN
        and             %%RET_IDX, 3
        shr             %%LEN, 2
        ;; At this stage:
        ;;   %%LEN - min length
        ;;   %%RET_IDX - lane index

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
%%_gcm_ooo_run:
        GCM_FINALIZE_x4 arg1, arg2, arg3, %%ENC_DEC
        ;; rax = finished job pointer
%%_gcm_submit_return:

%endmacro ; GCM_SUBMIT_MB
;;; ===========================================================================

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_COMPLETE Finishes Encyrption/Decryption of last partial block after GCM_UPDATE finishes.
; Input: A gcm_key_data * (GDATA_KEY), gcm_context_data (GDATA_CTX) and whether encoding or decoding (ENC_DEC).
; Output: Authorization Tag (AUTH_TAG) and Authorization Tag length (AUTH_TAG_LEN)
; Clobbers rax, r10-r12, and xmm0, xmm1, xmm5, xmm6, xmm9, xmm11, xmm14, xmm15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_COMPLETE            6
%define %%GDATA_KEY             %1
%define %%GDATA_CTX             %2
%define %%AUTH_TAG              %3
%define %%AUTH_TAG_LEN          %4
%define %%ENC_DEC               %5
%define %%INSTANCE_TYPE         %6
%define %%PLAIN_CYPH_LEN        rax

        vmovdqu xmm13, [%%GDATA_KEY + HashKey]
        ;; Start AES as early as possible
        vmovdqu xmm9, [%%GDATA_CTX + OrigIV]    ; xmm9 = Y0
        ENCRYPT_SINGLE_BLOCK %%GDATA_KEY, xmm9  ; E(K, Y0)

%ifidn %%INSTANCE_TYPE, multi_call
        ;; If the GCM function is called as a single function call rather
        ;; than invoking the individual parts (init, update, finalize) we
        ;; can remove a write to read dependency on AadHash.
        vmovdqu xmm14, [%%GDATA_CTX + AadHash]

        ;; Encrypt the final partial block. If we did this as a single call then
        ;; the partial block was handled in the main GCM_ENC_DEC macro.
	mov	r12, [%%GDATA_CTX + PBlockLen]
	cmp	r12, 0

	je %%_partial_done

	GHASH_MUL xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6 ;GHASH computation for the last <16 Byte block
	vmovdqu [%%GDATA_CTX + AadHash], xmm14

%%_partial_done:

%endif

        mov     r12, [%%GDATA_CTX + AadLen]     ; r12 = aadLen (number of bytes)
        mov     %%PLAIN_CYPH_LEN, [%%GDATA_CTX + InLen]

        shl     r12, 3                      ; convert into number of bits
        vmovd   xmm15, r12d                 ; len(A) in xmm15

        shl     %%PLAIN_CYPH_LEN, 3         ; len(C) in bits  (*128)
        vmovq   xmm1, %%PLAIN_CYPH_LEN
        vpslldq xmm15, xmm15, 8             ; xmm15 = len(A)|| 0x0000000000000000
        vpxor   xmm15, xmm15, xmm1          ; xmm15 = len(A)||len(C)

        vpxor   xmm14, xmm15
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6
        vpshufb  xmm14, [rel SHUF_MASK]         ; perform a 16Byte swap

        vpxor   xmm9, xmm9, xmm14


%%_return_T:
        mov     r10, %%AUTH_TAG             ; r10 = authTag
        mov     r11, %%AUTH_TAG_LEN         ; r11 = auth_tag_len

        cmp     r11, 16
        je      %%_T_16

        cmp     r11, 12
        je      %%_T_12

        cmp     r11, 8
        je      %%_T_8

        simd_store_avx r10, xmm9, r11, r12, rax
        jmp     %%_return_T_done
%%_T_8:
        vmovq    rax, xmm9
        mov     [r10], rax
        jmp     %%_return_T_done
%%_T_12:
        vmovq    rax, xmm9
        mov     [r10], rax
        vpsrldq xmm9, xmm9, 8
        vmovd    eax, xmm9
        mov     [r10 + 8], eax
        jmp     %%_return_T_done
%%_T_16:
        vmovdqu  [r10], xmm9

%%_return_T_done:
%endmacro ; GCM_COMPLETE


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_precomp_128_vaes_avx512 /
;       aes_gcm_precomp_192_vaes_avx512 /
;       aes_gcm_precomp_256_vaes_avx512
;       (struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(precomp,_),function,)
FN_NAME(precomp,_):
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


        PRECOMPUTE arg1, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5

        FUNC_RESTORE
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
        FUNC_SAVE
        GCM_INIT arg1, arg2, arg3, arg4, arg5, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10
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
        FUNC_SAVE
        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, ENC, multi_call
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
        FUNC_SAVE
        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, DEC, multi_call
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_finalize_vaes_avx512 / aes_gcm_enc_192_finalize_vaes_avx512 /
;	aes_gcm_enc_256_finalize_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_finalize_),function,)
FN_NAME(enc,_finalize_):
        FUNC_SAVE
        GCM_COMPLETE    arg1, arg2, arg3, arg4, ENC, multi_call
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_finalize_vaes_avx512 / aes_gcm_dec_192_finalize_vaes_avx512
;	aes_gcm_dec_256_finalize_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_finalize_),function,)
FN_NAME(dec,_finalize_):
        FUNC_SAVE
        GCM_COMPLETE    arg1, arg2, arg3, arg4, DEC, multi_call
        FUNC_RESTORE
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

        FUNC_SAVE
        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, ENC, single_call
        GCM_COMPLETE arg1, arg2, arg9, arg10, ENC, single_call
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

        FUNC_SAVE
        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, DEC, single_call
        GCM_COMPLETE arg1, arg2, arg9, arg10, DEC, single_call
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_enc_128_submit_vaes_vaes_avx512 / aes_gcm_enc_192_submit_vaes_vaes_avx512 /
;       aes_gcm_enc_256_submit_vaes_vaes_avx512
;       (MB_MGR_GCM_OOO *state, JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_submit_),function,internal)
FN_NAME(enc,_submit_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [in] job / [out] index
        ;; arg3 - [out] length
        GCM_SUBMIT_MB arg1, arg2, arg3, ENC
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_enc_128_flush_vaes_avx512 / aes_gcm_enc_192_flush_vaes_avx512 /
;       aes_gcm_enc_256_flush_vaes_avx512
;       (MB_MGR_GCM_OOO *state)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_flush_),function,internal)
FN_NAME(enc,_flush_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [out] index
        ;; arg3 - [out] length
        GCM_FLUSH_MB arg1, arg2, arg3

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
        GCM_FINALIZE_x4 arg1, arg2, arg3, ENC
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_dec_128_submit_vaes_avx512 / aes_gcm_dec_192_submit_vaes_avx512 /
;       aes_gcm_dec_256_submit_vaes_avx512
;       (MB_MGR_GCM_OOO *state, JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_submit_),function,internal)
FN_NAME(dec,_submit_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [in] job / [out] index
        ;; arg3 - [out] length
        GCM_SUBMIT_MB arg1, arg2, arg3, DEC
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_dec_128_flush_vaes_avx512 / aes_gcm_dec_192_flush_vaes_avx512 /
;       aes_gcm_dec_256_flush_vaes_avx512
;       (MB_MGR_GCM_OOO *state)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_flush_),function,internal)
FN_NAME(dec,_flush_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [out] index
        ;; arg3 - [out] length
        GCM_FLUSH_MB arg1, arg2, arg3

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
        GCM_FINALIZE_x4 arg1, arg2, arg3, DEC

        FUNC_RESTORE
        ret


%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
