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

; need to push 4 registers into stack to maintain
%define STACK_OFFSET   8*4

%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     16*10
%else
        %define XMM_STORAGE     0
%endif

%define TMP2    16*0    ; Temporary storage for AES State 2 (State 1 is stored in an XMM register)
%define TMP3    16*1    ; Temporary storage for AES State 3
%define TMP4    16*2    ; Temporary storage for AES State 4
%define TMP5    16*3    ; Temporary storage for AES State 5
%define TMP6    16*4    ; Temporary storage for AES State 6
%define TMP7    16*5    ; Temporary storage for AES State 7
%define TMP8    16*6    ; Temporary storage for AES State 8
%define LOCAL_STORAGE   16*7
%define VARIABLE_OFFSET LOCAL_STORAGE + XMM_STORAGE

%define LOCAL_STORAGE_AVX512 2*8  ; temporary storage
%define STACK_SIZE_GP_AVX512 10*8 ; up to 10 GP registers (5 GP + 3 reserve places for the algorithmic code)
%define STACK_OFFSET_AVX512    (LOCAL_STORAGE_AVX512 + XMM_STORAGE)
%define VARIABLE_OFFSET_AVX512 (LOCAL_STORAGE_AVX512 + XMM_STORAGE + STACK_SIZE_GP_AVX512)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Utility Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; ===========================================================================
;;; ===========================================================================
;;; Horizontal XOR - 4 x 128bits xored together
%macro VHPXORI4x128 2
%define %%REG   %1              ; [in/out] zmm512 4x128bits to xor; i128 on output
%define %%TMP   %2              ; temporary register
        vextracti64x4   YWORD(%%TMP), %%REG, 1
        vpxorq          YWORD(%%REG), YWORD(%%REG), YWORD(%%TMP)
        vextracti32x4   XWORD(%%TMP), YWORD(%%REG), 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro                       ; VHPXORI4x128

;;; ===========================================================================
;;; ===========================================================================
;;; schoolbook multiply - 1st step
%macro VCLMUL_STEP1 6
%define %%KP    %1              ; [in] key pointer
%define %%HI    %2              ; [in] previous blocks 4 to 7
%define %%TMP   %3
%define %%TH    %4              ; [out] tmp high
%define %%TM    %5              ; [out] tmp medium
%define %%TL    %6              ; [out] tmp low
        vmovdqu64       %%TMP, [%%KP + HashKey_4]
        vpclmulqdq      %%TH, %%HI, %%TMP, 0x11     ; %%T5 = a1*b1
        vpclmulqdq      %%TL, %%HI, %%TMP, 0x00     ; %%T7 = a0*b0
        vpclmulqdq      %%TM, %%HI, %%TMP, 0x01     ; %%T6 = a1*b0
        vpclmulqdq      %%TMP, %%HI, %%TMP, 0x10    ; %%T4 = a0*b1
        vpxorq          %%TM, %%TM, %%TMP           ; [%%TH : %%TM : %%TL]
%endmacro                       ; VCLMUL_STEP1

;;; ===========================================================================
;;; ===========================================================================
;;; schoolbook multiply - 2nd step
%macro VCLMUL_STEP2 9
%define %%KP    %1              ; [in] key pointer
%define %%HI    %2              ; [out] high 128b of hash to reduce
%define %%LO    %3              ; [in/out] previous blocks 0 to 3; low 128b of hash to reduce
%define %%TMP0  %4
%define %%TMP1  %5
%define %%TMP2  %6
%define %%TH    %7              ; [in] tmp high
%define %%TM    %8              ; [in] tmp medium
%define %%TL    %9              ; [in] tmp low

        vmovdqu64       %%TMP0, [%%KP + HashKey_8]
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
        VHPXORI4x128    %%HI, %%TMP2
        VHPXORI4x128    %%LO, %%TMP1
        ;; HIx holds top 128 bits
        ;; LOx holds low 128 bits
        ;; - further reductions to follow
%endmacro                       ; VCLMUL_STEP2

;;; ===========================================================================
;;; ===========================================================================
;;; AVX512 reduction macro
%macro VCLMUL_REDUCE 6
%define %%OUT   %1        ;; [out] zmm/ymm/xmm: result (must not be %%TMP1 or %%HI128)
%define %%POLY  %2        ;; [in] zmm/ymm/xmm: polynomial
%define %%HI128 %3        ;; [in] zmm/ymm/xmm: high 128b of hash to reduce
%define %%LO128 %4        ;; [in] zmm/ymm/xmm: low 128b of hash to reduce
%define %%TMP0  %5        ;; [in] zmm/ymm/xmm: temporary register
%define %%TMP1  %6        ;; [in] zmm/ymm/xmm: temporary register

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; first phase of the reduction
        vpclmulqdq      %%TMP0, %%POLY, %%LO128, 0x01
        vpslldq         %%TMP0, %%TMP0, 8               ; shift-L xmm2 2 DWs
        vpxorq          %%TMP0, %%LO128, %%TMP0         ; first phase of the reduction complete

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; second phase of the reduction
        vpclmulqdq      %%TMP1, %%POLY, %%TMP0, 0x00
        vpsrldq         %%TMP1, %%TMP1, 4               ; shift-R 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%OUT, %%POLY, %%TMP0, 0x10
        vpslldq         %%OUT, %%OUT, 4                 ; shift-L 1 DW (Shift-L 1-DW to obtain result with no shifts)

        vpternlogq      %%OUT, %%TMP1, %%HI128, 0x96    ; OUT (GHASH) = OUT xor TMP1 xor HI128(HI)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endmacro

;;; ===========================================================================
;;; ===========================================================================
;;; AVX512 VPCLMULQDQ SINGLE BLOCK GHASH MUL
%macro VCLMUL_1BLOCK 10
%define %%OUT         %1  ;; [in/out] zmm intermediate result
%define %%AAD_HASH    %2  ;; [in] xmm register with current hash value or 'no_aad'
%define %%GDATA       %3  ;; [in] pointer to hash key table
%define %%HKEY_OFFSET %4  ;; [in] offset to hash key table
%define %%TEXT        %5  ;; [in] pointer to data or an xmm register
%define %%TEXT_SRC    %6  ;; [in] selects source of the text (text_mem, text_zmm, text_ready)
%define %%FIRST_BLOCK %7  ;; [in] selects which block is processed (first or not_first)
%define %%SHFMSK      %8  ;; [in] ZMM register with byte shuffle mask or 'no_shuffle'
%define %%LT0         %9  ;; [clobbered] temporary zmm
%define %%LT1         %10 ;; [clobbered] temporary zmm

        ;; load, broadcast and permute the hash key
        vbroadcastf64x2 %%LT1, [%%GDATA + %%HKEY_OFFSET]
        ;; 0110_1001b => [ Med Med Low High ] multiply products
        ;; - see vpermilpd further down and VCLMUL_1BLOCK_GATHER for details
        vpermilpd       %%LT1, %%LT1, 0110_1001b        ; => [ MM LH ]

%ifidn %%FIRST_BLOCK, first
%ifnidn %%AAD_HASH, no_aad
        ;; current AAD needs to be broadcasted across ZMM then XOR with TEXT
        ;; use %%OUT for broadcasted AAD
        vmovdqa64       XWORD(%%OUT), %%AAD_HASH
        vshufi64x2      %%OUT, %%OUT, %%OUT, 0
%endif                          ; !no_aad
%endif                          ; first block

        ;; load and broadcast the text block
%ifidn %%TEXT_SRC, text_mem
        vbroadcastf64x2 %%LT0, [%%TEXT]
%endif
%ifidn %%TEXT_SRC, text_zmm
        vshufi64x2      %%LT0, %%TEXT, %%TEXT, 0000_0000b
%endif
%ifidn %%TEXT_SRC, text_ready
        vmovdqa64       %%LT0, %%TEXT
%endif

        ;; shuffle the text block
%ifnidn %%SHFMSK, no_shuffle
        vpshufb         %%LT0, %%SHFMSK
%endif

%ifidn %%FIRST_BLOCK, first
%ifnidn %%AAD_HASH, no_aad
        ;; xor current hash with the 1st text block
        vpxorq          %%LT0, %%LT0, %%OUT
%endif
%endif

%ifnidn %%TEXT_SRC, text_ready
        ;; 1001_1001b => [ Med Med Low High ] multiply products
        ;; - see vpermilpd above and VCLMUL_1BLOCK_GATHER for details
        vpermilpd       %%LT0, %%LT0, 1001_1001b
%endif

%ifidn %%FIRST_BLOCK, first
        ;; put result directly into OUT
        vpclmulqdq      %%OUT, %%LT0, %%LT1, 0x00       ; all 64-bit words permuted above
%else
        ;; xor CLMUL result with OUT and put result into OUT
        vpclmulqdq      %%LT0, %%LT0, %%LT1, 0x00       ; all 64-bit words permuted above
        vpxorq          %%OUT, %%LT0, %%OUT
%endif
%endmacro

;;; ===========================================================================
;;; ===========================================================================
;;; SINGLE BLOCK GHASH MUL PREPARE DATA BLOCK
;;; get the blocks ready for hashing
;;; - extract block
;;; - replicate block across whole ZMM register
;;; - permute 64-bit words for CLMUL
%macro VCLMUL_1BLOCK_DATAPREP 3
%define %%OUT         %1  ;; [out] zmm
%define %%IN          %2  ;; [in] zmm
%define %%INDEX       %3  ;; [in] 0 to 3

%if %%INDEX == 0
        vshufi64x2      %%OUT, %%IN, %%IN, 0000_0000b
%elif %%INDEX == 1
        vshufi64x2      %%OUT, %%IN, %%IN, 0101_0101b
%elif %%INDEX == 2
        vshufi64x2      %%OUT, %%IN, %%IN, 1010_1010b
%else
        vshufi64x2      %%OUT, %%IN, %%IN, 1111_1111b
%endif
        ;; 1001_1001b => [ Med Med Low High ] multiply products
        ;; - see vpermilpd above and VCLMUL_1BLOCK_GATHER for details
        vpermilpd       %%OUT, %%OUT, 1001_1001b
%endmacro

;;; ===========================================================================
;;; ===========================================================================
;;; AVX512 VPCLMULQDQ GATHER GHASH result for further reduction
;;;
;;; %%IN here looks as follows
;;; [127..  0] sum of hi 64-bit word multiplies (hi hash key with hi text)
;;; [255..128] sum of lo 64-bit word multiplies (lo hash key with lo text)
;;; [383..256] sum of med 64-bit word multiplies (hi hash key with lo text)
;;; [511..384] sum of med 64-bit word multiplies (lo hash key with hi text)
;;;
;;; - medium 128-bit words need to be xor'ed together
;;; - then the med results need to be added to lo and hi words accordingly
;;;
%macro VCLMUL_1BLOCK_GATHER 6
%define %%OUTH        %1  ;; [out] xmm result high 128 bits
%define %%OUTL        %2  ;; [out] xmm result low 128 bits
%define %%IN          %3  ;; [in] zmm intermediate result
%define %%LT1         %4  ;; [clobbered] temporary zmm
%define %%LT2         %5  ;; [clobbered] temporary zmm
%define %%LT3         %6  ;; [clobbered] temporary zmm

        vextracti32x4   XWORD(%%LT1), %%IN, 1
        vextracti32x4   XWORD(%%LT2), %%IN, 2
        vextracti32x4   XWORD(%%LT3), %%IN, 3
        vpxorq          XWORD(%%LT2), XWORD(%%LT2), XWORD(%%LT3)

        vpslldq         XWORD(%%LT3), XWORD(%%LT2), 8                   ; shift-L 2 DWs
        vpsrldq         XWORD(%%LT2), XWORD(%%LT2), 8                   ; shift-R 2 DWs
        ;; accumulate the results in %%OUTH:%%OUTL
        vpxorq          %%OUTH, XWORD(%%LT2), XWORD(%%IN)
        vpxorq          %%OUTL, XWORD(%%LT3), XWORD(%%LT1)
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GHASH_MUL MACRO to implement: Data*HashKey mod (128,127,126,121,0)
; Input: A and B (128-bits each, bit-reflected)
; Output: C = A*B*x mod poly, (i.e. >>1 )
; To compute GH = GH*HashKey mod poly, give HK = HashKey<<1 mod poly as input
; GH = GH * HK * x mod poly which is equivalent to GH*HashKey mod poly.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GHASH_MUL  7
%define %%GH %1         ; 16 Bytes
%define %%HK %2         ; 16 Bytes
%define %%T1 %3
%define %%T2 %4
%define %%T3 %5
%define %%T4 %6
%define %%T5 %7
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        vpclmulqdq      %%T1, %%GH, %%HK, 0x11          ; %%T1 = a1*b1
        vpclmulqdq      %%T2, %%GH, %%HK, 0x00          ; %%T2 = a0*b0
        vpclmulqdq      %%T3, %%GH, %%HK, 0x01          ; %%T3 = a1*b0
        vpclmulqdq      %%GH, %%GH, %%HK, 0x10          ; %%GH = a0*b1
        vpxorq          %%GH, %%GH, %%T3


        vpsrldq         %%T3, %%GH, 8                   ; shift-R %%GH 2 DWs
        vpslldq         %%GH, %%GH, 8                   ; shift-L %%GH 2 DWs

        vpxorq          %%T1, %%T1, %%T3
        vpxorq          %%GH, %%GH, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;first phase of the reduction
        vmovdqu64       %%T3, [rel POLY2]

        vpclmulqdq      %%T2, %%T3, %%GH, 0x01
        vpslldq         %%T2, %%T2, 8                    ; shift-L %%T2 2 DWs

        vpxorq          %%GH, %%GH, %%T2                 ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;second phase of the reduction
        vpclmulqdq      %%T2, %%T3, %%GH, 0x00
        vpsrldq         %%T2, %%T2, 4                    ; shift-R %%T2 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%GH, %%T3, %%GH, 0x10
        vpslldq         %%GH, %%GH, 4                    ; shift-L %%GH 1 DW (Shift-L 1-DW to obtain result with no shifts)

        ; second phase of the reduction complete, the result is in %%GH
        vpternlogq      %%GH, %%T1, %%T2, 0x96           ; GH = GH xor T1 xor T2
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endmacro


; In PRECOMPUTE, the commands filling Hashkey_i_k are not required for avx512
; functions, but are kept to allow users to switch cpu architectures between calls
; of pre, init, update, and finalize.
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
%macro  CALC_AAD_HASH   17
%define %%A_IN          %1
%define %%A_LEN         %2
%define %%AAD_HASH      %3      ; xmm output register
%define %%GDATA_KEY     %4
%define %%ZT0         %5      ; zmm temp reg 0
%define %%ZT1         %6      ; zmm temp reg 1
%define %%ZT2         %7
%define %%ZT3         %8
%define %%ZT4         %9
%define %%ZT5         %10     ; zmm temp reg 5
%define %%ZT6         %11     ; zmm temp reg 6
%define %%ZT7         %12     ; zmm temp reg 7
%define %%ZT8         %13     ; zmm temp reg 8
%define %%ZT9         %14     ; zmm temp reg 9
%define %%T1            %15     ; temp reg 1
%define %%T2            %16
%define %%T3            %17

%define %%SHFMSK %%ZT9
%define %%POLY   %%ZT8
%define %%TH     %%ZT7
%define %%TM     %%ZT6
%define %%TL     %%ZT5

        mov             %%T1, %%A_IN            ; T1 = AAD
        mov             %%T2, %%A_LEN           ; T2 = aadLen
        vpxor           %%AAD_HASH, %%AAD_HASH

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
        VCLMUL_REDUCE   %%AAD_HASH, XWORD(%%POLY), XWORD(%%ZT1), XWORD(%%ZT2), XWORD(%%ZT0), XWORD(%%ZT3)

        sub             %%T2, 128
        je              %%_CALC_AAD_done

        add             %%T1, 128
        jmp             %%_get_AAD_loop128

%%_exit_AAD_loop128:
        or              %%T2, %%T2
        jz              %%_CALC_AAD_done

        ;; calculate hash_key position to start with
        mov             %%T3, %%T2
        add             %%T3, 15
        and             %%T3, -16       ; 1 to 8 blocks possible here
        neg             %%T3
        add             %%T3, HashKey_1 + 16
        lea             %%T3, [%%GDATA_KEY + %%T3]

        ;; load, broadcast and shuffle TEXT
        cmp             %%T2, 16
        jl              %%_AAD_rd_partial_block

        VCLMUL_1BLOCK   %%ZT1, %%AAD_HASH, %%T3, 0, \
                        %%T1, text_mem, first, \
                        %%SHFMSK, %%ZT5, %%ZT6

        add             %%T3, 16        ; move to next hashkey
        add             %%T1, 16        ; move to next data block
        sub             %%T2, 16
        jmp             %%_AAD_blocks

%%_AAD_rd_partial_block:
        ;; need T3 as temporary register for partial read
        ;; save in ZT3 and restore later
        vmovq           XWORD(%%ZT3), %%T3
        READ_SMALL_DATA_INPUT   XWORD(%%ZT0), %%T1, %%T2, %%T3, k1
        vmovq           %%T3, XWORD(%%ZT3)
        VCLMUL_1BLOCK   %%ZT1, %%AAD_HASH, %%T3, 0, \
                        %%ZT0, text_zmm, first, \
                        %%SHFMSK, %%ZT5, %%ZT6
        jmp             %%_AAD_reduce

%%_AAD_blocks:
        or              %%T2, %%T2
        jz              %%_AAD_reduce

        cmp             %%T2, 16
        jl              %%_AAD_rd_partial_block_2

        VCLMUL_1BLOCK   %%ZT1, %%AAD_HASH, %%T3, 0, \
                        %%T1, text_mem, not_first, \
                        %%SHFMSK, %%ZT5, %%ZT6

        add             %%T3, 16        ; move to next hashkey
        add             %%T1, 16
        sub             %%T2, 16
        jmp             %%_AAD_blocks

%%_AAD_rd_partial_block_2:
        ;; need T3 as temporary register for partial read
        ;; save in ZT3 and restore later
        vmovq           XWORD(%%ZT3), %%T3
        READ_SMALL_DATA_INPUT \
                        XWORD(%%ZT0), %%T1, %%T2, %%T3, k1
        vmovq           %%T3, XWORD(%%ZT3)

        VCLMUL_1BLOCK   %%ZT1, %%AAD_HASH, %%T3, 0, \
                        %%ZT0, text_zmm, not_first, \
                        %%SHFMSK, %%ZT5, %%ZT6

%%_AAD_reduce:
        ;; accumulate the results in %%ZT0(H):%%ZT2(L)
        VCLMUL_1BLOCK_GATHER \
                        XWORD(%%ZT0), XWORD(%%ZT2), %%ZT1, %%ZT5, %%ZT6, %%ZT7

        VCLMUL_REDUCE   %%AAD_HASH, XWORD(%%POLY), \
                        XWORD(%%ZT0), XWORD(%%ZT2), \
                        XWORD(%%ZT5), XWORD(%%ZT6)
%%_CALC_AAD_done:

%endmacro ; CALC_AAD_HASH

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; PARTIAL_BLOCK: Handles encryption/decryption and the tag partial blocks between update calls.
; Requires the input data be at least 1 byte long.
; Input: gcm_key_data * (GDATA_KEY), gcm_context_data *(GDATA_CTX), input text (PLAIN_CYPH_IN),
; input text length (PLAIN_CYPH_LEN), the current data offset (DATA_OFFSET),
; and whether encoding or decoding (ENC_DEC)
; Output: A cypher of the first partial block (CYPH_PLAIN_OUT), and updated GDATA_CTX
; Clobbers rax, r10, r12, r13, r15, xmm0, xmm1, xmm2, xmm3, xmm5, xmm6, xmm9, xmm10, xmm11, xmm13
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PARTIAL_BLOCK    8
%define %%GDATA_KEY             %1
%define %%GDATA_CTX             %2
%define %%CYPH_PLAIN_OUT        %3
%define %%PLAIN_CYPH_IN         %4
%define %%PLAIN_CYPH_LEN        %5
%define %%DATA_OFFSET           %6
%define %%AAD_HASH              %7
%define %%ENC_DEC               %8

        mov     r13, [%%GDATA_CTX + PBlockLen]
        cmp     r13, 0
        je      %%_partial_block_done           ;Leave Macro if no partial blocks

        cmp     %%PLAIN_CYPH_LEN, 16            ;Read in input data without over reading
        jl      %%_fewer_than_16_bytes
        VXLDR   xmm1, [%%PLAIN_CYPH_IN]         ;If more than 16 bytes of data, just fill the xmm register
        jmp     %%_data_read

%%_fewer_than_16_bytes:
        lea     r10, [%%PLAIN_CYPH_IN]
        READ_SMALL_DATA_INPUT   xmm1, r10, %%PLAIN_CYPH_LEN, rax, k1

%%_data_read:                           ;Finished reading in data

        vmovdqu xmm9, [%%GDATA_CTX + PBlockEncKey]  ;xmm9 = my_ctx_data.partial_block_enc_key
        vmovdqu xmm13, [%%GDATA_KEY + HashKey]

        lea     r12, [rel SHIFT_MASK]

        add     r12, r13                        ; adjust the shuffle mask pointer to be able to shift r13 bytes (16-r13 is the number of bytes in plaintext mod 16)
        vmovdqu xmm2, [r12]                     ; get the appropriate shuffle mask
        vpshufb xmm9, xmm2                      ;shift right r13 bytes

%ifidn  %%ENC_DEC, DEC
        vmovdqa xmm3, xmm1
%endif
        vpxor   xmm9, xmm1                      ; Cyphertext XOR E(K, Yn)

        mov     r15, %%PLAIN_CYPH_LEN
        add     r15, r13
        sub     r15, 16                         ;Set r15 to be the amount of data left in CYPH_PLAIN_IN after filling the block
        jge     %%_no_extra_mask                ;Determine if if partial block is not being filled and shift mask accordingly
        sub     r12, r15
%%_no_extra_mask:

        vmovdqu xmm1, [r12 + ALL_F - SHIFT_MASK]; get the appropriate mask to mask out bottom r13 bytes of xmm9
        vpand   xmm9, xmm1                      ; mask out bottom r13 bytes of xmm9

%ifidn  %%ENC_DEC, DEC
        vpand   xmm3, xmm1
        vpshufb xmm3, [rel SHUF_MASK]
        vpshufb xmm3, xmm2
        vpxor   %%AAD_HASH, xmm3
%else
        vpshufb xmm9, [rel SHUF_MASK]
        vpshufb xmm9, xmm2
        vpxor   %%AAD_HASH, xmm9
%endif
        cmp     r15,0
        jl      %%_partial_incomplete

        GHASH_MUL       %%AAD_HASH, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6       ;GHASH computation for the last <16 Byte block
        xor     rax,rax
        mov     [%%GDATA_CTX + PBlockLen], rax
        jmp     %%_enc_dec_done
%%_partial_incomplete:
%ifidn __OUTPUT_FORMAT__, win64
        mov     rax, %%PLAIN_CYPH_LEN
       	add     [%%GDATA_CTX + PBlockLen], rax
%else
        add     [%%GDATA_CTX + PBlockLen], %%PLAIN_CYPH_LEN
%endif
%%_enc_dec_done:
        vmovdqu [%%GDATA_CTX + AadHash], %%AAD_HASH

%ifidn  %%ENC_DEC, ENC
        vpshufb xmm9, [rel SHUF_MASK]       ; shuffle xmm9 back to output as ciphertext
        vpshufb xmm9, xmm2
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; output encrypted Bytes
        cmp     r15,0
        jl      %%_partial_fill
        mov     r12, r13
        mov     r13, 16
        sub     r13, r12                        ; Set r13 to be the number of bytes to write out
        jmp     %%_count_set
%%_partial_fill:
        mov     r13, %%PLAIN_CYPH_LEN
%%_count_set:
        lea             rax, [rel byte_len_to_mask_table]
        kmovw           k1, [rax + r13*2]
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{k1}, xmm9
        add             %%DATA_OFFSET, r13
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

; if a = number of total plaintext bytes
; b = floor(a/16)
; %%num_initial_blocks = b mod 8;
; encrypt the initial %%num_initial_blocks blocks and apply ghash on the ciphertext
; %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r14 are used as a pointer only, not modified.
; Updated AAD_HASH is returned in %%T3

%macro INITIAL_BLOCKS 23
%define %%GDATA_KEY             %1
%define %%CYPH_PLAIN_OUT        %2
%define %%PLAIN_CYPH_IN         %3
%define %%LENGTH                %4
%define %%DATA_OFFSET           %5
%define %%num_initial_blocks    %6      ; can be 0, 1, 2, 3, 4, 5, 6 or 7
%define %%T1                    %7
%define %%T2                    %8
%define %%T3                    %9
%define %%T4                    %10
%define %%T5                    %11
%define %%CTR                   %12
%define %%XMM1                  %13
%define %%XMM2                  %14
%define %%XMM3                  %15
%define %%XMM4                  %16
%define %%XMM5                  %17
%define %%XMM6                  %18
%define %%XMM7                  %19
%define %%XMM8                  %20
%define %%T6                    %21
%define %%T_key                 %22
%define %%ENC_DEC               %23

%assign i (8-%%num_initial_blocks)
                ;; Move AAD_HASH to temp reg
                vmovdqu  %%T2, %%XMM8
                ;; Start AES for %%num_initial_blocks blocks
                ;; vmovdqu  %%CTR, [%%GDATA_CTX + CurCount]   ; %%CTR = Y0

%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vpaddd   %%CTR, %%CTR, [rel ONE]     ; INCR Y0
                vmovdqa  reg(i), %%CTR
                vpshufb  reg(i), [rel SHUF_MASK]     ; perform a 16Byte swap
%assign i (i+1)
%endrep

%if(%%num_initial_blocks>0)
vmovdqu  %%T_key, [%%GDATA_KEY+16*0]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vpxor    reg(i),reg(i),%%T_key
%assign i (i+1)
%endrep

%assign j 1
%rep NROUNDS
vmovdqu  %%T_key, [%%GDATA_KEY+16*j]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenc  reg(i),%%T_key
%assign i (i+1)
%endrep

%assign j (j+1)
%endrep


vmovdqu  %%T_key, [%%GDATA_KEY+16*j]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenclast      reg(i),%%T_key
%assign i (i+1)
%endrep

%endif ; %if(%%num_initial_blocks>0)



%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
                vpxor    reg(i), reg(i), %%T1
                ;; Write back ciphertext for %%num_initial_blocks blocks
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], reg(i)
                add     %%DATA_OFFSET, 16
                %ifidn  %%ENC_DEC, DEC
                    vmovdqa  reg(i), %%T1
                %endif
                ;; Prepare ciphertext for GHASH computations
                vpshufb  reg(i), [rel SHUF_MASK]
%assign i (i+1)
%endrep


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (9-%%num_initial_blocks)
%if(%%num_initial_blocks>0)
        vmovdqa %%T3, reg(i)
%assign i (i+1)
%endif
%if %%num_initial_blocks>1
%rep %%num_initial_blocks-1
        vmovdqu [rsp + TMP %+ i], reg(i)
%assign i (i+1)
%endrep
%endif
                ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
                ;; Haskey_i_k holds XORed values of the low and high parts of
                ;; the Haskey_i
                vpaddd   %%XMM1, %%CTR, [rel ONE]   ; INCR Y0
                vpaddd   %%XMM2, %%CTR, [rel TWO]   ; INCR Y0
                vpaddd   %%XMM3, %%XMM1, [rel TWO]  ; INCR Y0
                vpaddd   %%XMM4, %%XMM2, [rel TWO]  ; INCR Y0
                vpaddd   %%XMM5, %%XMM3, [rel TWO]  ; INCR Y0
                vpaddd   %%XMM6, %%XMM4, [rel TWO]  ; INCR Y0
                vpaddd   %%XMM7, %%XMM5, [rel TWO]  ; INCR Y0
                vpaddd   %%XMM8, %%XMM6, [rel TWO]  ; INCR Y0
                vmovdqa  %%CTR, %%XMM8

                vpshufb  %%XMM1, [rel SHUF_MASK]    ; perform a 16Byte swap
                vpshufb  %%XMM2, [rel SHUF_MASK]    ; perform a 16Byte swap
                vpshufb  %%XMM3, [rel SHUF_MASK]    ; perform a 16Byte swap
                vpshufb  %%XMM4, [rel SHUF_MASK]    ; perform a 16Byte swap
                vpshufb  %%XMM5, [rel SHUF_MASK]    ; perform a 16Byte swap
                vpshufb  %%XMM6, [rel SHUF_MASK]    ; perform a 16Byte swap
                vpshufb  %%XMM7, [rel SHUF_MASK]    ; perform a 16Byte swap
                vpshufb  %%XMM8, [rel SHUF_MASK]    ; perform a 16Byte swap

                vmovdqu  %%T_key, [%%GDATA_KEY+16*0]
                vpxor    %%XMM1, %%XMM1, %%T_key
                vpxor    %%XMM2, %%XMM2, %%T_key
                vpxor    %%XMM3, %%XMM3, %%T_key
                vpxor    %%XMM4, %%XMM4, %%T_key
                vpxor    %%XMM5, %%XMM5, %%T_key
                vpxor    %%XMM6, %%XMM6, %%T_key
                vpxor    %%XMM7, %%XMM7, %%T_key
                vpxor    %%XMM8, %%XMM8, %%T_key

%assign i (8-%%num_initial_blocks)
%assign j (9-%%num_initial_blocks)
%assign k (%%num_initial_blocks)

%define %%T4_2 %%T4
%if(%%num_initial_blocks>0)
        ;; Hash in AES state
        ;; T2 - incoming AAD hash
        vpxor %%T2, %%T3

        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, first
%endif

                vmovdqu  %%T_key, [%%GDATA_KEY+16*1]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

                vmovdqu  %%T_key, [%%GDATA_KEY+16*2]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>1)
        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

                vmovdqu  %%T_key, [%%GDATA_KEY+16*3]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

                vmovdqu  %%T_key, [%%GDATA_KEY+16*4]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>2)
        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>3)
        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

                vmovdqu  %%T_key, [%%GDATA_KEY+16*5]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

                vmovdqu  %%T_key, [%%GDATA_KEY+16*6]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>4)
        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

                vmovdqu  %%T_key, [%%GDATA_KEY+16*7]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

                vmovdqu  %%T_key, [%%GDATA_KEY+16*8]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>5)
        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

                vmovdqu  %%T_key, [%%GDATA_KEY+16*9]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

%ifndef GCM128_MODE
                vmovdqu  %%T_key, [%%GDATA_KEY+16*10]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key
%endif

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>6)
        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

%ifdef GCM128_MODE
                vmovdqu  %%T_key, [%%GDATA_KEY+16*10]
                vaesenclast  %%XMM1, %%T_key
                vaesenclast  %%XMM2, %%T_key
                vaesenclast  %%XMM3, %%T_key
                vaesenclast  %%XMM4, %%T_key
                vaesenclast  %%XMM5, %%T_key
                vaesenclast  %%XMM6, %%T_key
                vaesenclast  %%XMM7, %%T_key
                vaesenclast  %%XMM8, %%T_key
%endif

%ifdef GCM192_MODE
                vmovdqu  %%T_key, [%%GDATA_KEY+16*11]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

                vmovdqu          %%T_key, [%%GDATA_KEY+16*12]
                vaesenclast      %%XMM1, %%T_key
                vaesenclast      %%XMM2, %%T_key
                vaesenclast      %%XMM3, %%T_key
                vaesenclast      %%XMM4, %%T_key
                vaesenclast      %%XMM5, %%T_key
                vaesenclast      %%XMM6, %%T_key
                vaesenclast      %%XMM7, %%T_key
                vaesenclast      %%XMM8, %%T_key
%endif
%ifdef GCM256_MODE
                vmovdqu  %%T_key, [%%GDATA_KEY+16*11]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

                vmovdqu          %%T_key, [%%GDATA_KEY+16*12]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key
%endif

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>7)
        ;;                 GDATA,       HASHKEY, CIPHER,
        ;;               STATE_11, STATE_00, STATE_MID, T1, T2
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

%ifdef GCM256_MODE             ; GCM256
                vmovdqu  %%T_key, [%%GDATA_KEY+16*13]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key

                vmovdqu          %%T_key, [%%GDATA_KEY+16*14]
                vaesenclast      %%XMM1, %%T_key
                vaesenclast      %%XMM2, %%T_key
                vaesenclast      %%XMM3, %%T_key
                vaesenclast      %%XMM4, %%T_key
                vaesenclast      %%XMM5, %%T_key
                vaesenclast      %%XMM6, %%T_key
                vaesenclast      %%XMM7, %%T_key
                vaesenclast      %%XMM8, %%T_key
%endif                          ;  GCM256 mode

%if(%%num_initial_blocks>0)
        vpsrldq %%T3, %%T6, 8            ; shift-R %%T2 2 DWs
        vpslldq %%T6, %%T6, 8            ; shift-L %%T3 2 DWs
        vpxor   %%T1, %%T1, %%T3         ; accumulate the results in %%T1:%%T4
        vpxor   %%T4, %%T6, %%T4

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; First phase of the reduction
        vmovdqu         %%T3, [rel POLY2]

        vpclmulqdq      %%T2, %%T3, %%T4, 0x01
        vpslldq         %%T2, %%T2, 8             ; shift-L xmm2 2 DWs

        ;; First phase of the reduction complete
        vpxor           %%T4, %%T4, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Second phase of the reduction
        vpclmulqdq      %%T2, %%T3, %%T4, 0x00
        ;; Shift-R xmm2 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)
        vpsrldq         %%T2, %%T2, 4

        vpclmulqdq      %%T4, %%T3, %%T4, 0x10
        ;; Shift-L xmm0 1 DW (Shift-L 1-DW to obtain result with no shifts)
        vpslldq         %%T4, %%T4, 4
        ;; Second phase of the reduction complete
        vpxor           %%T4, %%T4, %%T2
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; The result is in %%T3
        vpxor           %%T3, %%T1, %%T4
%else
        ;; The hash should end up in T3
        vmovdqa  %%T3, %%T2
%endif

        ;; Final hash is now in T3
%if %%num_initial_blocks > 0
        ;; NOTE: obsolete in case %%num_initial_blocks = 0
        sub     %%LENGTH, 16*%%num_initial_blocks
%endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*0]
                vpxor    %%XMM1, %%XMM1, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*0], %%XMM1
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM1, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*1]
                vpxor    %%XMM2, %%XMM2, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*1], %%XMM2
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM2, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*2]
                vpxor    %%XMM3, %%XMM3, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*2], %%XMM3
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM3, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*3]
                vpxor    %%XMM4, %%XMM4, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*3], %%XMM4
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM4, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*4]
                vpxor    %%XMM5, %%XMM5, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*4], %%XMM5
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM5, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*5]
                vpxor    %%XMM6, %%XMM6, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*5], %%XMM6
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM6, %%T1
                %endif

               VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*6]
                vpxor    %%XMM7, %%XMM7, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*6], %%XMM7
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM7, %%T1
                %endif

%if %%num_initial_blocks > 0
                ;; NOTE: 'jl' is never taken for %%num_initial_blocks = 0
                ;;      This macro is executed for lenght 128 and up,
                ;;      zero length is checked in GCM_ENC_DEC.
                ;; If the last block is partial then the xor will be done later
                ;; in ENCRYPT_FINAL_PARTIAL_BLOCK.
                ;; We know it's partial if LENGTH - 16*num_initial_blocks < 128
                cmp %%LENGTH, 128
                jl %%_initial_skip_last_word_write
%endif
                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*7]
                vpxor    %%XMM8, %%XMM8, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*7], %%XMM8
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM8, %%T1
                %endif

                ;; Update %%LENGTH with the number of blocks processed
                sub     %%LENGTH, 16
                add     %%DATA_OFFSET, 16
%%_initial_skip_last_word_write:
                sub     %%LENGTH, 128-16
                add     %%DATA_OFFSET, 128-16

                vpshufb  %%XMM1, [rel SHUF_MASK]             ; perform a 16Byte swap
                ;; Combine GHASHed value with the corresponding ciphertext
                vpxor    %%XMM1, %%XMM1, %%T3
                vpshufb  %%XMM2, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM3, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM4, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM5, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM6, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM7, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM8, [rel SHUF_MASK]             ; perform a 16Byte swap

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_initial_blocks_done:


%endmacro                       ; INITIAL_BLOCKS

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
%macro INITIAL_BLOCKS_PARTIAL 24
%define %%GDATA_KEY             %1  ; [in] key pointer
%define %%GDATA_CTX             %2  ; [in] context pointer
%define %%CYPH_PLAIN_OUT        %3  ; [in] text out pointer
%define %%PLAIN_CYPH_IN         %4  ; [in] text out pointer
%define %%LENGTH                %5  ; [in/clobbered] length in bytes
%define %%DATA_OFFSET           %6  ; [in/out] current data offset (updated)
%define %%num_initial_blocks    %7  ; can only be 1, 2, 3, 4, 5, 6, 7 or 8 (not 0)
%define %%ZT1                   %8  ; [clobbered]
%define %%ZT2                   %9  ; [clobbered]
%define %%ZT3                   %10 ; [out] hash value
%define %%ZT4                   %11 ; [clobbered]
%define %%ZT5                   %12 ; [clobbered]
%define %%CTR                   %13 ; [in/out] current counter value
%define %%XMM1                  %14 ; [clobbered]
%define %%XMM2                  %15 ; [clobbered]
%define %%XMM3                  %16 ; [clobbered]
%define %%XMM4                  %17 ; [clobbered]
%define %%XMM5                  %18 ; [clobbered]
%define %%XMM6                  %19 ; [clobbered]
%define %%XMM7                  %20 ; [clobbered]
%define %%XMM8                  %21 ; [in] hash value
%define %%ZT6                   %22 ; [clobbered]
%define %%ENC_DEC               %23 ; [in] cipher direction (ENC/DEC)
%define %%INSTANCE_TYPE         %24 ; [in] multi_call or single_call

%define %%IA0 r12
%define %%IA1 rax

%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)
%define %%T3 XWORD(%%ZT3)
%define %%T4 XWORD(%%ZT4)
%define %%T5 XWORD(%%ZT5)
%define %%T6 XWORD(%%ZT6)

        ;; Move AAD_HASH to temp reg (%%T2)
        vmovdqa64       %%T2, %%XMM8

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
        kmovq           k1, [%%IA0 + %%IA1*8]

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
        vmovdqu8        %%T5{k1}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 2
        vmovdqu8        YWORD(%%ZT5){k1}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks <= 4
        vmovdqu8        %%ZT5{k1}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
%elif %%num_initial_blocks == 5
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%T6{k1}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%elif %%num_initial_blocks == 6
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        YWORD(%%ZT6){k1}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%else
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT6{k1}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
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
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{k1}, %%T3
        vmovdqu8        %%T3{k1}{z}, %%T3
%elif %%num_initial_blocks == 2
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{k1}, YWORD(%%ZT3)
        vmovdqu8        YWORD(%%ZT3){k1}{z}, YWORD(%%ZT3)
%elif %%num_initial_blocks <= 4
        ;; Blocks 3 and 4
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{k1}, %%ZT3
        vmovdqu8        %%ZT3{k1}{z}, %%ZT3
%elif %%num_initial_blocks == 5
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{k1}, %%T4
        vmovdqu8        %%T4{k1}{z}, %%T4
%elif %%num_initial_blocks == 6
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{k1}, YWORD(%%ZT4)
        vmovdqu8        YWORD(%%ZT4){k1}{z}, YWORD(%%ZT4)
%else
        ;; Blocks 7 and 8
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{k1}, %%ZT4
        vmovdqu8        %%ZT4{k1}{z}, %%ZT4
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

        ;; Convention was:
        ;; - xmm8 is the last block
        ;; - xmm1 is the first block (if %%num_initial_blocks is 8)
        ;; After last changes we only need to extract the last block
        ;; for partials and multi_call cases
        ;; At the moment xmm1 to xmm7 are unused but xmm8 is still
        ;; required to be set up to contain the last block
%if %%num_initial_blocks <= 4
        vextracti32x4   reg(8), %%ZT5, %%num_initial_blocks - 1
%else
        vextracti32x4   reg(8), %%ZT6, %%num_initial_blocks - 5
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
%assign j (9 - %%num_initial_blocks)
%assign k (%%num_initial_blocks)
%assign i 0

        ;; T2 - incoming AAD hash
        ;; ZT5, ZT6 - hold ciphertext
        ;; ZT1 - updated xor
        ;; ZT3, ZT4 - temporary registers

        ;; Hash in AES state
        vpxorq          %%ZT5, %%ZT5, %%ZT2

        VCLMUL_1BLOCK_DATAPREP \
                        regz(1), %%ZT5, i

        VCLMUL_1BLOCK   %%ZT1, no_aad, %%GDATA_KEY, HashKey_ %+ k, \
                        regz(1), text_ready, first, no_shuffle, %%ZT3, %%ZT4

%assign rep_count (%%num_initial_blocks - 1)
%rep rep_count
%assign j (j + 1)
%assign k (k - 1)
%assign i (i + 1)
%if i < 4
        ;; take blocks from ZT5
        VCLMUL_1BLOCK_DATAPREP \
                        regz(1), %%ZT5, i
%else
        ;; take blocks from ZT6
        VCLMUL_1BLOCK_DATAPREP \
                        regz(1), %%ZT6, i - 4
%endif
        VCLMUL_1BLOCK   %%ZT1, no_aad, %%GDATA_KEY, HashKey_ %+ k, \
                        regz(1), text_ready, not_first, no_shuffle, %%ZT3, %%ZT4
%endrep

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
%assign rep_count (%%num_initial_blocks - 2)
%assign k (%%num_initial_blocks - 1)
%assign last_block_to_hash 1
%else
%assign rep_count (%%num_initial_blocks - 1)
%assign k (%%num_initial_blocks)
%assign last_block_to_hash 0
%endif

%if (%%num_initial_blocks > last_block_to_hash)

%assign j (9 - %%num_initial_blocks)
%assign i 0

        ;; T2 - incoming AAD hash
        ;; ZT5, ZT6 - hold ciphertext
        ;; ZT1 - updated xor
        ;; ZT3, ZT4 - temporary registers
        ;; Hash in AES state
        vpxorq          %%ZT5, %%ZT5, %%ZT2

        VCLMUL_1BLOCK_DATAPREP \
                        regz(1), %%ZT5, i

        VCLMUL_1BLOCK   %%ZT1, no_aad, %%GDATA_KEY, HashKey_ %+ k, \
                        regz(1), text_ready, first, no_shuffle, %%ZT3, %%ZT4

%if rep_count > 0
        ;; rule out negative cases or zero
%rep rep_count
%assign j (j+1)
%assign k (k-1)
%assign i (i + 1)
%if i < 4
        ;; take blocks from ZT5
        VCLMUL_1BLOCK_DATAPREP \
                        regz(1), %%ZT5, i
%else
        ;; take blocks from ZT6
        VCLMUL_1BLOCK_DATAPREP \
                        regz(1), %%ZT6, i - 4
%endif
        VCLMUL_1BLOCK   %%ZT1, no_aad, %%GDATA_KEY, HashKey_ %+ k, \
                        regz(1), text_ready, not_first, no_shuffle, %%ZT3, %%ZT4
%endrep
%endif                       ; rep_count > 0

        ;; reduction is required - just fall through no jmp needed
%else
        ;; Record that a reduction is not needed -
        ;; In this case no hashes are computed because there
        ;; is only one initial block and it is < 16B in length.
        ;; We only need to check if a reduction is needed if
        ;; initial_blocks == 1 and init/update/final is being used.
        ;; In this case we may just have a partial block, and that
        ;; gets hashed in finalize.

        ;; The hash should end up in T3. The only way we should get here is if
        ;; there is a partial block of data, so xor that into the hash.
        vpxorq          %%T3, %%T2, reg(8)

        ;; The result is in %%T3
        jmp             %%_after_reduction
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Ghash reduction
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_small_initial_compute_reduction:

        ;; gather result from ZT1 into T1:T4
        VCLMUL_1BLOCK_GATHER %%T1, %%T4, %%ZT1, %%ZT4, %%ZT5, %%ZT6

        ;; [out] T3 - hash output
        ;; [in]  T3 - polynomial
        ;; [in]  T1 - high, T4 - low
        ;; [clobbered] T5, T6 - temporary
        vmovdqu64       %%T3, [rel POLY2]
        VCLMUL_REDUCE   %%T3, %%T3, %%T1, %%T4, %%T5, %%T6

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
        vpxorq          %%T3, %%T3, reg(8)
%endif                          ; %%num_initial_blocks > 1
%endif                          ; %%INSTANCE_TYPE, multi_call

%%_after_reduction:
        ;; Final hash is now in T3

%endmacro                       ; INITIAL_BLOCKS_PARTIAL



; encrypt 8 blocks at a time
; ghash the 8 previously encrypted ciphertext blocks
; %%GDATA (KEY), %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN are used as pointers only, not modified
; %%DATA_OFFSET is the data offset value
%macro  GHASH_8_ENCRYPT_8_PARALLEL 23
%define %%GDATA                 %1
%define %%CYPH_PLAIN_OUT        %2
%define %%PLAIN_CYPH_IN         %3
%define %%DATA_OFFSET           %4
%define %%T1    %5
%define %%T2    %6
%define %%T3    %7
%define %%T4    %8
%define %%T5    %9
%define %%T6    %10
%define %%CTR   %11
%define %%XMM1  %12
%define %%XMM2  %13
%define %%XMM3  %14
%define %%XMM4  %15
%define %%XMM5  %16
%define %%XMM6  %17
%define %%XMM7  %18
%define %%XMM8  %19
%define %%T7    %20
%define %%loop_idx      %21
%define %%ENC_DEC       %22
%define %%FULL_PARTIAL  %23

        vmovdqa %%T2, %%XMM1
        vmovdqu [rsp + TMP2], %%XMM2
        vmovdqu [rsp + TMP3], %%XMM3
        vmovdqu [rsp + TMP4], %%XMM4
        vmovdqu [rsp + TMP5], %%XMM5
        vmovdqu [rsp + TMP6], %%XMM6
        vmovdqu [rsp + TMP7], %%XMM7
        vmovdqu [rsp + TMP8], %%XMM8

%ifidn %%loop_idx, in_order
                vpaddd  %%XMM1, %%CTR,  [rel ONE]           ; INCR CNT
                vmovdqu %%T5, [rel TWO]
                vpaddd  %%XMM2, %%CTR, %%T5
                vpaddd  %%XMM3, %%XMM1, %%T5
                vpaddd  %%XMM4, %%XMM2, %%T5
                vpaddd  %%XMM5, %%XMM3, %%T5
                vpaddd  %%XMM6, %%XMM4, %%T5
                vpaddd  %%XMM7, %%XMM5, %%T5
                vpaddd  %%XMM8, %%XMM6, %%T5
                vmovdqa %%CTR, %%XMM8

                vmovdqu %%T5, [rel SHUF_MASK]
                vpshufb %%XMM1, %%T5             ; perform a 16Byte swap
                vpshufb %%XMM2, %%T5             ; perform a 16Byte swap
                vpshufb %%XMM3, %%T5             ; perform a 16Byte swap
                vpshufb %%XMM4, %%T5             ; perform a 16Byte swap
                vpshufb %%XMM5, %%T5             ; perform a 16Byte swap
                vpshufb %%XMM6, %%T5             ; perform a 16Byte swap
                vpshufb %%XMM7, %%T5             ; perform a 16Byte swap
                vpshufb %%XMM8, %%T5             ; perform a 16Byte swap
%else
                vpaddd  %%XMM1, %%CTR,  [rel ONEf]          ; INCR CNT
                vmovdqu %%T5, [rel TWOf]
                vpaddd  %%XMM2, %%CTR,  %%T5
                vpaddd  %%XMM3, %%XMM1, %%T5
                vpaddd  %%XMM4, %%XMM2, %%T5
                vpaddd  %%XMM5, %%XMM3, %%T5
                vpaddd  %%XMM6, %%XMM4, %%T5
                vpaddd  %%XMM7, %%XMM5, %%T5
                vpaddd  %%XMM8, %%XMM6, %%T5
                vmovdqa %%CTR, %%XMM8
%endif



        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                vmovdqu %%T1, [%%GDATA + 16*0]
                vpxor   %%XMM1, %%XMM1, %%T1
                vpxor   %%XMM2, %%XMM2, %%T1
                vpxor   %%XMM3, %%XMM3, %%T1
                vpxor   %%XMM4, %%XMM4, %%T1
                vpxor   %%XMM5, %%XMM5, %%T1
                vpxor   %%XMM6, %%XMM6, %%T1
                vpxor   %%XMM7, %%XMM7, %%T1
                vpxor   %%XMM8, %%XMM8, %%T1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                vmovdqu %%T1, [%%GDATA + 16*1]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1


                vmovdqu %%T1, [%%GDATA + 16*2]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_8]
        vpclmulqdq      %%T4, %%T2, %%T5, 0x11                  ; %%T4 = a1*b1
        vpclmulqdq      %%T7, %%T2, %%T5, 0x00                  ; %%T7 = a0*b0
        vpclmulqdq      %%T6, %%T2, %%T5, 0x01                  ; %%T6 = a1*b0
        vpclmulqdq      %%T5, %%T2, %%T5, 0x10                  ; %%T5 = a0*b1
        vpxor           %%T6, %%T6, %%T5

                vmovdqu %%T1, [%%GDATA + 16*3]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP2]
        vmovdqu         %%T5, [%%GDATA + HashKey_7]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x01
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*4]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu         %%T1, [rsp + TMP3]
        vmovdqu         %%T5, [%%GDATA + HashKey_6]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x01
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*5]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1


        vmovdqu         %%T1, [rsp + TMP4]
        vmovdqu         %%T5, [%%GDATA + HashKey_5]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x01
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*6]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP5]
        vmovdqu         %%T5, [%%GDATA + HashKey_4]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x01
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*7]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP6]
        vmovdqu         %%T5, [%%GDATA + HashKey_3]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x01
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*8]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP7]
        vmovdqu         %%T5, [%%GDATA + HashKey_2]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x01
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                vmovdqu %%T5, [%%GDATA + 16*9]
                vaesenc %%XMM1, %%T5
                vaesenc %%XMM2, %%T5
                vaesenc %%XMM3, %%T5
                vaesenc %%XMM4, %%T5
                vaesenc %%XMM5, %%T5
                vaesenc %%XMM6, %%T5
                vaesenc %%XMM7, %%T5
                vaesenc %%XMM8, %%T5

        vmovdqu         %%T1, [rsp + TMP8]
        vmovdqu         %%T5, [%%GDATA + HashKey]


        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x01
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T1, %%T4, %%T3


                vmovdqu %%T5, [%%GDATA + 16*10]
 %ifndef GCM128_MODE            ; GCM192 or GCM256
                vaesenc %%XMM1, %%T5
                vaesenc %%XMM2, %%T5
                vaesenc %%XMM3, %%T5
                vaesenc %%XMM4, %%T5
                vaesenc %%XMM5, %%T5
                vaesenc %%XMM6, %%T5
                vaesenc %%XMM7, %%T5
                vaesenc %%XMM8, %%T5

                vmovdqu %%T5, [%%GDATA + 16*11]
                vaesenc %%XMM1, %%T5
                vaesenc %%XMM2, %%T5
                vaesenc %%XMM3, %%T5
                vaesenc %%XMM4, %%T5
                vaesenc %%XMM5, %%T5
                vaesenc %%XMM6, %%T5
                vaesenc %%XMM7, %%T5
                vaesenc %%XMM8, %%T5

                vmovdqu %%T5, [%%GDATA + 16*12]
%endif
%ifdef GCM256_MODE
                vaesenc %%XMM1, %%T5
                vaesenc %%XMM2, %%T5
                vaesenc %%XMM3, %%T5
                vaesenc %%XMM4, %%T5
                vaesenc %%XMM5, %%T5
                vaesenc %%XMM6, %%T5
                vaesenc %%XMM7, %%T5
                vaesenc %%XMM8, %%T5

                vmovdqu %%T5, [%%GDATA + 16*13]
                vaesenc %%XMM1, %%T5
                vaesenc %%XMM2, %%T5
                vaesenc %%XMM3, %%T5
                vaesenc %%XMM4, %%T5
                vaesenc %%XMM5, %%T5
                vaesenc %%XMM6, %%T5
                vaesenc %%XMM7, %%T5
                vaesenc %%XMM8, %%T5

                vmovdqu %%T5, [%%GDATA + 16*14]
%endif                          ; GCM256

%assign i 0
%assign j 1
%rep 8

        ;; SNP TBD: This is pretty ugly - consider whether just XORing the
        ;; data in after vaesenclast is simpler and performant. Would
        ;; also have to ripple it through partial block and ghash_mul_8.
%ifidn %%FULL_PARTIAL, full
    %ifdef  NT_LD
        VXLDR   %%T2, [%%PLAIN_CYPH_IN+%%DATA_OFFSET+16*i]
        vpxor   %%T2, %%T2, %%T5
    %else
        vpxor   %%T2, %%T5, [%%PLAIN_CYPH_IN+%%DATA_OFFSET+16*i]
    %endif

    %ifidn %%ENC_DEC, ENC
        vaesenclast     reg(j), reg(j), %%T2
    %else
        vaesenclast     %%T3, reg(j), %%T2
        vpxor   reg(j), %%T2, %%T5
        VXSTR [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*i], %%T3
    %endif

%else
    ; Don't read the final data during partial block processing
    %ifdef  NT_LD
        %if (i<7)
            VXLDR   %%T2, [%%PLAIN_CYPH_IN+%%DATA_OFFSET+16*i]
            vpxor   %%T2, %%T2, %%T5
        %else
            ;; Stage the key directly in T2 rather than hash it with plaintext
            vmovdqu %%T2, %%T5
        %endif
    %else
        %if (i<7)
            vpxor   %%T2, %%T5, [%%PLAIN_CYPH_IN+%%DATA_OFFSET+16*i]
        %else
            ;; Stage the key directly in T2 rather than hash it with plaintext
            vmovdqu %%T2, %%T5
        %endif
    %endif

    %ifidn %%ENC_DEC, ENC
        vaesenclast     reg(j), reg(j), %%T2
    %else
        %if (i<7)
            vaesenclast     %%T3, reg(j), %%T2
            vpxor   reg(j), %%T2, %%T5
            ;; Do not read the data since it could fault
            VXSTR [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*i], %%T3
        %else
            vaesenclast     reg(j), reg(j), %%T2
        %endif
    %endif
%endif

%assign i (i+1)
%assign j (j+1)
%endrep


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


        vpslldq %%T3, %%T6, 8                                   ; shift-L %%T3 2 DWs
        vpsrldq %%T6, %%T6, 8                                   ; shift-R %%T2 2 DWs
        vpxor   %%T7, %%T7, %%T3
        vpxor   %%T1, %%T1, %%T6                                ; accumulate the results in %%T1:%%T7



        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;first phase of the reduction
        vmovdqu         %%T3, [rel POLY2]

        vpclmulqdq      %%T2, %%T3, %%T7, 0x01
        vpslldq         %%T2, %%T2, 8                           ; shift-L xmm2 2 DWs

        vpxor           %%T7, %%T7, %%T2                        ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    %ifidn %%ENC_DEC, ENC
        ; Write to the Ciphertext buffer
        VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*0], %%XMM1
        VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*1], %%XMM2
        VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*2], %%XMM3
        VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*3], %%XMM4
        VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*4], %%XMM5
        VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*5], %%XMM6
        VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*6], %%XMM7
        %ifidn %%FULL_PARTIAL, full
            ;; Avoid writing past the buffer if handling a partial block
            VXSTR   [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*7], %%XMM8
        %endif
    %endif


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;second phase of the reduction
        vpclmulqdq      %%T2, %%T3, %%T7, 0x00
        vpsrldq         %%T2, %%T2, 4                                   ; shift-R xmm2 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%T4, %%T3, %%T7, 0x10
        vpslldq         %%T4, %%T4, 4                                   ; shift-L xmm0 1 DW (Shift-L 1-DW to obtain result with no shifts)

        vpxor           %%T4, %%T4, %%T2                                ; second phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vpxor           %%T1, %%T1, %%T4                                ; the result is in %%T1

                vpshufb %%XMM1, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM2, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM3, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM4, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM5, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM6, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM7, [rel SHUF_MASK]             ; perform a 16Byte swap
        vpshufb %%XMM8, [rel SHUF_MASK]             ; perform a 16Byte swap


        vpxor   %%XMM1, %%T1


%endmacro                       ; GHASH_8_ENCRYPT_8_PARALLEL


; GHASH the last 4 ciphertext blocks.
%macro  GHASH_LAST_8 16
%define %%GDATA %1
%define %%T1    %2
%define %%T2    %3
%define %%T3    %4
%define %%T4    %5
%define %%T5    %6
%define %%T6    %7
%define %%T7    %8
%define %%XMM1  %9
%define %%XMM2  %10
%define %%XMM3  %11
%define %%XMM4  %12
%define %%XMM5  %13
%define %%XMM6  %14
%define %%XMM7  %15
%define %%XMM8  %16

        ;; Karatsuba Method

        vmovdqu         %%T5, [%%GDATA + HashKey_8]

        vpshufd         %%T2, %%XMM1, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM1
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T6, %%XMM1, %%T5, 0x11
        vpclmulqdq      %%T7, %%XMM1, %%T5, 0x00

        vpclmulqdq      %%XMM1, %%T2, %%T3, 0x00

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_7]
        vpshufd         %%T2, %%XMM2, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM2
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_6]
        vpshufd         %%T2, %%XMM3, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM3
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_5]
        vpshufd         %%T2, %%XMM4, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM4
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_4]
        vpshufd         %%T2, %%XMM5, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM5
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_3]
        vpshufd         %%T2, %%XMM6, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM6
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_2]
        vpshufd         %%T2, %%XMM7, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM7
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey]
        vpshufd         %%T2, %%XMM8, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM8
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM8, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM8, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2
        vpxor           %%XMM1, %%XMM1, %%T6
        vpxor           %%T2, %%XMM1, %%T7




        vpslldq %%T4, %%T2, 8
        vpsrldq %%T2, %%T2, 8

        vpxor   %%T7, %%T7, %%T4
        vpxor   %%T6, %%T6, %%T2                               ; <%%T6:%%T7> holds the result of the accumulated carry-less multiplications

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;first phase of the reduction
        vmovdqu         %%T3, [rel POLY2]

        vpclmulqdq      %%T2, %%T3, %%T7, 0x01
        vpslldq         %%T2, %%T2, 8                           ; shift-L xmm2 2 DWs

        vpxor           %%T7, %%T7, %%T2                        ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


        ;second phase of the reduction
        vpclmulqdq      %%T2, %%T3, %%T7, 0x00
        vpsrldq         %%T2, %%T2, 4                           ; shift-R %%T2 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%T4, %%T3, %%T7, 0x10
        vpslldq         %%T4, %%T4, 4                           ; shift-L %%T4 1 DW (Shift-L 1-DW to obtain result with no shifts)

        vpxor           %%T4, %%T4, %%T2                        ; second phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vpxor           %%T6, %%T6, %%T4                        ; the result is in %%T6
%endmacro


; GHASH the last 4 ciphertext blocks.
%macro  GHASH_LAST_7 15
%define %%GDATA %1
%define %%T1    %2
%define %%T2    %3
%define %%T3    %4
%define %%T4    %5
%define %%T5    %6
%define %%T6    %7
%define %%T7    %8
%define %%XMM1  %9
%define %%XMM2  %10
%define %%XMM3  %11
%define %%XMM4  %12
%define %%XMM5  %13
%define %%XMM6  %14
%define %%XMM7  %15

        ;; Karatsuba Method

        vmovdqu         %%T5, [%%GDATA + HashKey_7]

        vpshufd         %%T2, %%XMM1, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM1
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T6, %%XMM1, %%T5, 0x11
        vpclmulqdq      %%T7, %%XMM1, %%T5, 0x00

        vpclmulqdq      %%XMM1, %%T2, %%T3, 0x00

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_6]
        vpshufd         %%T2, %%XMM2, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM2
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_5]
        vpshufd         %%T2, %%XMM3, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM3
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_4]
        vpshufd         %%T2, %%XMM4, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM4
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_3]
        vpshufd         %%T2, %%XMM5, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM5
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_2]
        vpshufd         %%T2, %%XMM6, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM6
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_1]
        vpshufd         %%T2, %%XMM7, 01001110b
        vpshufd         %%T3, %%T5, 01001110b
        vpxor           %%T2, %%T2, %%XMM7
        vpxor           %%T3, %%T3, %%T5

        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vpxor           %%XMM1, %%XMM1, %%T6
        vpxor           %%T2, %%XMM1, %%T7




        vpslldq %%T4, %%T2, 8
        vpsrldq %%T2, %%T2, 8

        vpxor   %%T7, %%T7, %%T4
        vpxor   %%T6, %%T6, %%T2                               ; <%%T6:%%T7> holds the result of the accumulated carry-less multiplications

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;first phase of the reduction
        vmovdqu         %%T3, [rel POLY2]

        vpclmulqdq      %%T2, %%T3, %%T7, 0x01
        vpslldq         %%T2, %%T2, 8                           ; shift-L xmm2 2 DWs

        vpxor           %%T7, %%T7, %%T2                        ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


        ;second phase of the reduction
        vpclmulqdq      %%T2, %%T3, %%T7, 0x00
        vpsrldq         %%T2, %%T2, 4                           ; shift-R %%T2 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%T4, %%T3, %%T7, 0x10
        vpslldq         %%T4, %%T4, 4                           ; shift-L %%T4 1 DW (Shift-L 1-DW to obtain result with no shifts)

        vpxor           %%T4, %%T4, %%T2                        ; second phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vpxor           %%T6, %%T6, %%T4                        ; the result is in %%T6
%endmacro



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Handle encryption of the final partial block
;;; %%KEY - on output contains cipher text block for GHASH
;;;       - on input it contains encrypter counter block
%macro  ENCRYPT_FINAL_PARTIAL_BLOCK 8
%define %%KEY             %1    ; [in/out] XMM with encrypted counter block/cipher text
%define %%T1              %2    ; [clobbered] XMM temporary
%define %%CYPH_PLAIN_OUT  %3    ; [in] pointer to output buffer
%define %%PLAIN_CYPH_IN   %4    ; [in] pointer to input buffer
%define %%LENGTH          %5    ; [in] number of bytes in partial block
%define %%ENC_DEC         %6    ; [in] ENC/DEC selection
%define %%DATA_OFFSET     %7    ; [in] data offset from start of the buffer
%define %%IA0             %8    ; [clobbered] GP temporary register

        ;; On output it sets k1 with valid byte bit mask
        READ_SMALL_DATA_INPUT   %%T1, %%PLAIN_CYPH_IN+%%DATA_OFFSET, %%LENGTH, %%IA0, k1

        ;; At this point T1 contains the partial block data
        ;; Plain/cipher text XOR E(K, Yn)
        vpxorq          %%KEY, %%KEY, %%T1

        ;; Output %%LENGTH bytes
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET]{k1}, %%KEY

%ifidn  %%ENC_DEC, DEC
        ;; If decrypt, restore the ciphertext into %%KEY
        vmovdqa64       %%KEY, %%T1
%else
        vmovdqu8        %%KEY{k1}{z}, %%KEY
%endif
%endmacro                       ; ENCRYPT_FINAL_PARTIAL_BLOCK



; Encryption of a single block
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


;; Start of Stack Setup

%macro FUNC_SAVE 0
        ;; Required for Update/GMC_ENC
        ;the number of pushes must equal STACK_OFFSET
        push    r12
        push    r13
        push    r14
        push    r15
        mov     r14, rsp

        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~63

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        vmovdqu [rsp + LOCAL_STORAGE + 0*16],xmm6
        vmovdqu [rsp + LOCAL_STORAGE + 1*16],xmm7
        vmovdqu [rsp + LOCAL_STORAGE + 2*16],xmm8
        vmovdqu [rsp + LOCAL_STORAGE + 3*16],xmm9
        vmovdqu [rsp + LOCAL_STORAGE + 4*16],xmm10
        vmovdqu [rsp + LOCAL_STORAGE + 5*16],xmm11
        vmovdqu [rsp + LOCAL_STORAGE + 6*16],xmm12
        vmovdqu [rsp + LOCAL_STORAGE + 7*16],xmm13
        vmovdqu [rsp + LOCAL_STORAGE + 8*16],xmm14
        vmovdqu [rsp + LOCAL_STORAGE + 9*16],xmm15
%endif
%endmacro


%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm15, [rsp + LOCAL_STORAGE + 9*16]
        vmovdqu xmm14, [rsp + LOCAL_STORAGE + 8*16]
        vmovdqu xmm13, [rsp + LOCAL_STORAGE + 7*16]
        vmovdqu xmm12, [rsp + LOCAL_STORAGE + 6*16]
        vmovdqu xmm11, [rsp + LOCAL_STORAGE + 5*16]
        vmovdqu xmm10, [rsp + LOCAL_STORAGE + 4*16]
        vmovdqu xmm9, [rsp + LOCAL_STORAGE + 3*16]
        vmovdqu xmm8, [rsp + LOCAL_STORAGE + 2*16]
        vmovdqu xmm7, [rsp + LOCAL_STORAGE + 1*16]
        vmovdqu xmm6, [rsp + LOCAL_STORAGE + 0*16]
%endif
;; Required for Update/GMC_ENC
        mov     rsp, r14
        pop     r15
        pop     r14
        pop     r13
        pop     r12
%endmacro

%macro FUNC_SAVE_AVX512 0
        ;; Required for Update/GMC_ENC
        ;the number of pushes must equal STACK_OFFSET
        mov     rax, rsp

        sub     rsp, VARIABLE_OFFSET_AVX512
        and     rsp, ~63

        mov     [rsp + STACK_OFFSET_AVX512 + 0*8], r12
        mov     [rsp + STACK_OFFSET_AVX512 + 1*8], r13
        mov     [rsp + STACK_OFFSET_AVX512 + 2*8], r14
        mov     [rsp + STACK_OFFSET_AVX512 + 3*8], r15
        mov     [rsp + STACK_OFFSET_AVX512 + 4*8], rax ; stack
        mov     r14, rax                               ; r14 is used to retrieve stack args
        mov     [rsp + STACK_OFFSET_AVX512 + 5*8], rbp
        mov     [rsp + STACK_OFFSET_AVX512 + 6*8], rbx
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + STACK_OFFSET_AVX512 + 7*8], rdi
        mov     [rsp + STACK_OFFSET_AVX512 + 8*8], rsi
%endif

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 0*16], xmm6
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 1*16], xmm7
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 2*16], xmm8
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 3*16], xmm9
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 4*16], xmm10
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 5*16], xmm11
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 6*16], xmm12
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 7*16], xmm13
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 8*16], xmm14
        vmovdqu [rsp + LOCAL_STORAGE_AVX512 + 9*16], xmm15
%endif
%endmacro


%macro FUNC_RESTORE_AVX512 0

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm15, [rsp + LOCAL_STORAGE_AVX512 + 9*16]
        vmovdqu xmm14, [rsp + LOCAL_STORAGE_AVX512 + 8*16]
        vmovdqu xmm13, [rsp + LOCAL_STORAGE_AVX512 + 7*16]
        vmovdqu xmm12, [rsp + LOCAL_STORAGE_AVX512 + 6*16]
        vmovdqu xmm11, [rsp + LOCAL_STORAGE_AVX512 + 5*16]
        vmovdqu xmm10, [rsp + LOCAL_STORAGE_AVX512 + 4*16]
        vmovdqu xmm9, [rsp + LOCAL_STORAGE_AVX512 + 3*16]
        vmovdqu xmm8, [rsp + LOCAL_STORAGE_AVX512 + 2*16]
        vmovdqu xmm7, [rsp + LOCAL_STORAGE_AVX512 + 1*16]
        vmovdqu xmm6, [rsp + LOCAL_STORAGE_AVX512 + 0*16]
%endif

;; Required for Update/GMC_ENC
        mov     rbp, [rsp + STACK_OFFSET_AVX512 + 5*8]
        mov     rbx, [rsp + STACK_OFFSET_AVX512 + 6*8]
%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + STACK_OFFSET_AVX512 + 7*8]
        mov     rsi, [rsp + STACK_OFFSET_AVX512 + 8*8]
%endif
        mov     r12, [rsp + STACK_OFFSET_AVX512 + 0*8]
        mov     r13, [rsp + STACK_OFFSET_AVX512 + 1*8]
        mov     r14, [rsp + STACK_OFFSET_AVX512 + 2*8]
        mov     r15, [rsp + STACK_OFFSET_AVX512 + 3*8]
        mov     rsp, [rsp + STACK_OFFSET_AVX512 + 4*8] ; stack
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_INIT initializes a gcm_context_data struct to prepare for encoding/decoding.
; Input: gcm_key_data * (GDATA_KEY), gcm_context_data *(GDATA_CTX), IV,
; Additional Authentication data (A_IN), Additional Data length (A_LEN).
; Output: Updated GDATA_CTX with the hash of A_IN (AadHash) and initialized other parts of GDATA_CTX.
; Clobbers rax, r10-r13, and xmm0-xmm6
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_INIT        8
%define %%GDATA_KEY     %1      ; [in] GCM expanded keys pointer
%define %%GDATA_CTX     %2      ; [in] GCM context pointer
%define %%IV            %3      ; [in] IV pointer
%define %%A_IN          %4      ; [in] AAD pointer
%define %%A_LEN         %5      ; [in] AAD length in bytes
%define %%GPR1          %6      ; temp GPR
%define %%GPR2          %7      ; temp GPR
%define %%GPR3          %8      ; temp GPR

%define %%AAD_HASH      xmm14

        CALC_AAD_HASH   %%A_IN, %%A_LEN, %%AAD_HASH, %%GDATA_KEY, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, \
                        %%GPR1, %%GPR2, %%GPR3

        mov     %%GPR1, %%A_LEN
        vmovdqu [%%GDATA_CTX + AadHash], %%AAD_HASH         ; ctx_data.aad hash = aad_hash
        mov     [%%GDATA_CTX + AadLen], %%GPR1              ; ctx_data.aad_length = aad_length

        xor     %%GPR1, %%GPR1
        mov     [%%GDATA_CTX + InLen], %%GPR1               ; ctx_data.in_length = 0
        mov     [%%GDATA_CTX + PBlockLen], %%GPR1           ; ctx_data.partial_block_length = 0

        ;; read 12 IV bytes and pad with 0x00000001
        mov     %%GPR2, %%IV
        vmovd   xmm3, [%%GPR2 + 8]
        vpslldq xmm3, 8
        vmovq   xmm2, [%%GPR2]
        vmovdqa xmm4, [rel ONEf]
        vpternlogq xmm2, xmm3, xmm4, 0xfe     ; xmm2 = xmm2 or xmm3 or xmm4

        vmovdqu [%%GDATA_CTX + OrigIV], xmm2                ; ctx_data.orig_IV = iv

        ;; store IV as counter in LE format
        vpshufb xmm2, [rel SHUF_MASK]
        vmovdqu [%%GDATA_CTX + CurCount], xmm2              ; ctx_data.current_counter = iv
%endmacro

%macro  GCM_ENC_DEC_SMALL   12
%define %%GDATA_KEY         %1
%define %%GDATA_CTX         %2
%define %%CYPH_PLAIN_OUT    %3
%define %%PLAIN_CYPH_IN     %4
%define %%PLAIN_CYPH_LEN    %5
%define %%ENC_DEC           %6
%define %%DATA_OFFSET       %7
%define %%LENGTH            %8  ; assumed r13
%define %%NUM_BLOCKS        %9
%define %%CTR               %10 ; assumed xmm9
%define %%HASH_OUT          %11 ; assumed xmm14
%define %%INSTANCE_TYPE     %12

        ;; NOTE: the check below is obsolete in current implementation. The check is already done in GCM_ENC_DEC.
        ;; cmp     %%NUM_BLOCKS, 0
        ;; je      %%_small_initial_blocks_encrypted
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
        ;; r13   - %%LENGTH
        ;; xmm12 - T1
        ;; xmm13 - T2
        ;; xmm14 - T3   - AAD HASH OUT when not producing 8 AES keys
        ;; xmm15 - T4
        ;; xmm11 - T5
        ;; xmm9  - CTR
        ;; xmm1  - XMM1 - Cipher + Hash when producing 8 AES keys
        ;; xmm2  - XMM2
        ;; xmm3  - XMM3
        ;; xmm4  - XMM4
        ;; xmm5  - XMM5
        ;; xmm6  - XMM6
        ;; xmm7  - XMM7
        ;; xmm8  - XMM8 - AAD HASH IN
        ;; xmm10 - T6
        ;; xmm0  - T_key
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 8, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_7:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 7, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_6:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 6, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_5:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 5, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_4:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 4, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_3:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 3, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_2:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 2, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_1:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, %%DATA_OFFSET, 1, \
                zmm12, zmm13, zmm14, zmm15, zmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                zmm10, %%ENC_DEC, %%INSTANCE_TYPE
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
%define %%GDATA_KEY         %1
%define %%GDATA_CTX         %2
%define %%CYPH_PLAIN_OUT    %3
%define %%PLAIN_CYPH_IN     %4
%define %%PLAIN_CYPH_LEN    %5
%define %%ENC_DEC           %6
%define %%INSTANCE_TYPE     %7
%define %%DATA_OFFSET       r11

; Macro flow:
; calculate the number of 16byte blocks in the message
; process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
; process 8 16 byte blocks at a time until all are done '%%_encrypt_by_8_new .. %%_eight_cipher_left'
; if there is a block of less tahn 16 bytes process it '%%_zero_cipher_left .. %%_multiple_of_16_bytes'

%ifidn __OUTPUT_FORMAT__, win64
        cmp     %%PLAIN_CYPH_LEN, 0
%else
        or      %%PLAIN_CYPH_LEN, %%PLAIN_CYPH_LEN
%endif
        je      %%_enc_dec_done

        xor     %%DATA_OFFSET, %%DATA_OFFSET
        ;; Update length of data processed
%ifidn __OUTPUT_FORMAT__, win64
        mov     rax, %%PLAIN_CYPH_LEN
       	add     [%%GDATA_CTX + InLen], rax
%else
        add    [%%GDATA_CTX + InLen], %%PLAIN_CYPH_LEN
%endif
        vmovdqu xmm13, [%%GDATA_KEY + HashKey]
        vmovdqu xmm8, [%%GDATA_CTX + AadHash]

%ifidn %%INSTANCE_TYPE, multi_call
        ;; NOTE: partial block processing makes only sense for multi_call here.
        ;; Used for the update flow - if there was a previous partial
        ;; block fill the remaining bytes here.
        PARTIAL_BLOCK %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%PLAIN_CYPH_LEN, %%DATA_OFFSET, xmm8, %%ENC_DEC
%endif

        ;;  lift CTR set from initial_blocks to here
%ifidn %%INSTANCE_TYPE, single_call
        vmovdqu xmm9, xmm2
%else
        vmovdqu xmm9, [%%GDATA_CTX + CurCount]
%endif

        ;; Save the amount of data left to process in r10
        mov     r13, %%PLAIN_CYPH_LEN
%ifidn %%INSTANCE_TYPE, multi_call
        ;; NOTE: %%DATA_OFFSET is zero in single_call case.
        ;;      Consequently PLAIN_CYPH_LEN will never be zero after
        ;;      %%DATA_OFFSET subtraction below.
        sub     r13, %%DATA_OFFSET

        ;; There may be no more data if it was consumed in the partial block.
        cmp     r13, 0
        je      %%_enc_dec_done
%endif                          ; %%INSTANCE_TYPE, multi_call
        mov     r10, r13

        ;; Determine how many blocks to process in INITIAL
        mov     r12, r13
        shr     r12, 4
        and     r12, 7

        ;; Process one additional block in INITIAL if there is a partial block
        and     r10, 0xf
        blsmsk  r10, r10    ; Set CF if zero
        cmc                 ; Flip CF
        adc     r12, 0x0    ; Process an additional INITIAL block if CF set

        ;;      Less than 127B will be handled by the small message code, which
        ;;      can process up to 7 16B blocks.
        cmp     r13, 128
        jge     %%_large_message_path

        GCM_ENC_DEC_SMALL %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%PLAIN_CYPH_LEN, %%ENC_DEC, %%DATA_OFFSET, r13, r12, xmm9, xmm14, %%INSTANCE_TYPE
        jmp     %%_ghash_done

%%_large_message_path:
        and     r12, 0x7    ; Still, don't allow 8 INITIAL blocks since this will
                            ; can be handled by the x8 partial loop.

        cmp     r12, 0
        je      %%_initial_num_blocks_is_0
        cmp     r12, 7
        je      %%_initial_num_blocks_is_7
        cmp     r12, 6
        je      %%_initial_num_blocks_is_6
        cmp     r12, 5
        je      %%_initial_num_blocks_is_5
        cmp     r12, 4
        je      %%_initial_num_blocks_is_4
        cmp     r12, 3
        je      %%_initial_num_blocks_is_3
        cmp     r12, 2
        je      %%_initial_num_blocks_is_2

        jmp     %%_initial_num_blocks_is_1

%%_initial_num_blocks_is_7:
        ;; r13   - %%LENGTH
        ;; xmm12 - T1
        ;; xmm13 - T2
        ;; xmm14 - T3   - AAD HASH OUT when not producing 8 AES keys
        ;; xmm15 - T4
        ;; xmm11 - T5
        ;; xmm9  - CTR
        ;; xmm1  - XMM1 - Cipher + Hash when producing 8 AES keys
        ;; xmm2  - XMM2
        ;; xmm3  - XMM3
        ;; xmm4  - XMM4
        ;; xmm5  - XMM5
        ;; xmm6  - XMM6
        ;; xmm7  - XMM7
        ;; xmm8  - XMM8 - AAD HASH IN
        ;; xmm10 - T6
        ;; xmm0  - T_key
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 7, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_6:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 6, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_5:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 5, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_4:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 4, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_3:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 3, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_2:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 2, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_1:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 1, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_0:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 0, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC


%%_initial_blocks_encrypted:
        ;; The entire message was encrypted processed in initial and now need to be hashed
        cmp     r13, 0
        je      %%_encrypt_done

        ;; Encrypt the final <16 byte (partial) block, then hash
        cmp     r13, 16
        jl      %%_encrypt_final_partial

        ;; Process 7 full blocks plus a partial block
        cmp     r13, 128
        jl      %%_encrypt_by_8_partial


%%_encrypt_by_8_parallel:
        ;; in_order vs. out_order is an optimization to increment the counter without shuffling
        ;; it back into little endian. r15d keeps track of when we need to increent in order so
        ;; that the carry is handled correctly.
        vmovd   r15d, xmm9
        and     r15d, 255
        vpshufb xmm9, [rel SHUF_MASK]


%%_encrypt_by_8_new:
        cmp     r15d, 255-8
        jg      %%_encrypt_by_8



        ;; xmm0  - T1
        ;; xmm10 - T2
        ;; xmm11 - T3
        ;; xmm12 - T4
        ;; xmm13 - T5
        ;; xmm14 - T6
        ;; xmm9  - CTR
        ;; xmm1  - XMM1
        ;; xmm2  - XMM2
        ;; xmm3  - XMM3
        ;; xmm4  - XMM4
        ;; xmm5  - XMM5
        ;; xmm6  - XMM6
        ;; xmm7  - XMM7
        ;; xmm8  - XMM8
        ;; xmm15 - T7
        add     r15b, 8
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, out_order, %%ENC_DEC, full
        add     %%DATA_OFFSET, 128
        sub     r13, 128
        cmp     r13, 128
        jge     %%_encrypt_by_8_new

        vpshufb xmm9, [rel SHUF_MASK]
        jmp     %%_encrypt_by_8_parallel_done

%%_encrypt_by_8:
        vpshufb xmm9, [rel SHUF_MASK]
        add     r15b, 8
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, in_order, %%ENC_DEC, full
        vpshufb  xmm9, [rel SHUF_MASK]
        add     %%DATA_OFFSET, 128
        sub     r13, 128
        cmp     r13, 128
        jge     %%_encrypt_by_8_new
        vpshufb  xmm9, [rel SHUF_MASK]


%%_encrypt_by_8_parallel_done:
        ;; Test to see if we need a by 8 with partial block. At this point
        ;; bytes remaining should be either zero or between 113-127.
        cmp     r13, 0
        je      %%_encrypt_done

%%_encrypt_by_8_partial:
        ;; Shuffle needed to align key for partial block xor. out_order
        ;; is a little faster because it avoids extra shuffles.
        ;; TBD: Might need to account for when we don't have room to increment the counter.


        ;; Process parallel buffers with a final partial block.
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, in_order, %%ENC_DEC, partial


        add     %%DATA_OFFSET, 128-16
        sub     r13, 128-16

%%_encrypt_final_partial:

        vpshufb  xmm8, [rel SHUF_MASK]
        mov     [%%GDATA_CTX + PBlockLen], r13
        vmovdqu [%%GDATA_CTX + PBlockEncKey], xmm8

        ;; xmm8  - Final encrypted counter - need to hash with partial or full block ciphertext
        ENCRYPT_FINAL_PARTIAL_BLOCK xmm8, xmm0, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%ENC_DEC, %%DATA_OFFSET, rax

        vpshufb  xmm8, [rel SHUF_MASK]


%%_encrypt_done:

        ;; Mapping to macro parameters
        ;; IN:
        ;;   xmm9 contains the counter
        ;;   xmm1-xmm8 contain the xor'd ciphertext
        ;; OUT:
        ;;   xmm14 contains the final hash
        ;;             GDATA,   T1,    T2,    T3,    T4,    T5,    T6,    T7, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8
%ifidn %%INSTANCE_TYPE, multi_call
        mov     r13, [%%GDATA_CTX + PBlockLen]
        cmp     r13, 0
        jz      %%_hash_last_8
        GHASH_LAST_7 %%GDATA_KEY, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
        ;; XOR the partial word into the hash
        vpxor   xmm14, xmm14, xmm8
        jmp     %%_ghash_done
%endif
%%_hash_last_8:
        GHASH_LAST_8 %%GDATA_KEY, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8

%%_ghash_done:
        vmovdqu [%%GDATA_CTX + CurCount], xmm9  ; my_ctx_data.current_counter = xmm9
        vmovdqu [%%GDATA_CTX + AadHash], xmm14      ; my_ctx_data.aad hash = xmm14

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

; Macro flow:
; calculate the number of 16byte blocks in the message
; process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
; process 8 16 byte blocks at a time until all are done '%%_encrypt_by_8_new .. %%_eight_cipher_left'
; if there is a block of less tahn 16 bytes process it '%%_zero_cipher_left .. %%_multiple_of_16_bytes'

        or      %%PLAIN_CYPH_LEN, %%PLAIN_CYPH_LEN
        je      %%_enc_dec_done_x4

        xor     %%DATA_OFFSET, %%DATA_OFFSET

        ;; Update length of data processed
        add    [%%GDATA_CTX + InLen], %%PLAIN_CYPH_LEN

        vmovdqa64       xmm13, xmm16    ; load HashKey
        vmovdqa64       xmm8, xmm17     ; load AadHash; xmm8 is hash_in for gcm_enc_dec_small
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
                r13, r12, xmm9, xmm14, single_call

%%_ghash_done_x4:
        vmovdqu         [%%GDATA_CTX + CurCount], xmm9  ; current_counter = xmm9
        vmovdqa64       xmm17, xmm14                    ; AadHash = xmm14

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
        mov     [rsp + 0*8], %%IDX ; save %IDX as it will get clobbered
        and     %%LEN, -128
        mov     arg2, %%LEN
        GCM_ENC_DEC_4x128 %%STATE, arg2, %%ENC_DEC

%%_gcm_complete_min_lane:
        mov     arg2, [rsp + 0*8] ; restore %%IDX
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
        GCM_INIT        r9, %%LCTX, r13, r14, rax, r10, r11, r12

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
        push    r12
        push    r13
        push    r14
        push    r15

        mov     r14, rsp



        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~63                                 ; align rsp to 64 bytes

%ifidn __OUTPUT_FORMAT__, win64
        ; only xmm6 needs to be maintained
        vmovdqu [rsp + LOCAL_STORAGE + 0*16],xmm6
%endif

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

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm6, [rsp + LOCAL_STORAGE + 0*16]
%endif
        mov     rsp, r14

        pop     r15
        pop     r14
        pop     r13
        pop     r12
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
        push    r12
        push    r13
%ifidn __OUTPUT_FORMAT__, win64
        push    r14
        push    r15
        mov     r14, rsp
	; xmm6:xmm15 need to be maintained for Windows
	sub	rsp, 1*16
	movdqu	[rsp + 0*16], xmm6
%endif

        GCM_INIT arg1, arg2, arg3, arg4, arg5, r10, r11, r12

%ifidn __OUTPUT_FORMAT__, win64
	movdqu	xmm6 , [rsp + 0*16]
        mov     rsp, r14
        pop     r15
        pop     r14
%endif
        pop     r13
        pop     r12
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

        push r12

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        sub     rsp, 5*16
        vmovdqu [rsp + 0*16], xmm6
        vmovdqu [rsp + 1*16], xmm9
        vmovdqu [rsp + 2*16], xmm11
        vmovdqu [rsp + 3*16], xmm14
        vmovdqu [rsp + 4*16], xmm15
%endif
        GCM_COMPLETE    arg1, arg2, arg3, arg4, ENC, multi_call

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm15, [rsp + 4*16]
        vmovdqu xmm14, [rsp + 3*16]
        vmovdqu xmm11, [rsp + 2*16]
        vmovdqu xmm9, [rsp + 1*16]
        vmovdqu xmm6, [rsp + 0*16]
        add     rsp, 5*16
%endif

        pop r12
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

        push r12

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        sub     rsp, 5*16
        vmovdqu [rsp + 0*16], xmm6
        vmovdqu [rsp + 1*16], xmm9
        vmovdqu [rsp + 2*16], xmm11
        vmovdqu [rsp + 3*16], xmm14
        vmovdqu [rsp + 4*16], xmm15
%endif
        GCM_COMPLETE    arg1, arg2, arg3, arg4, DEC, multi_call

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm15, [rsp + 4*16]
        vmovdqu xmm14, [rsp + 3*16]
        vmovdqu xmm11, [rsp + 2*16]
        vmovdqu xmm9, [rsp + 1*16]
        vmovdqu xmm6, [rsp + 0*16]
        add     rsp, 5*16
%endif

        pop r12
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

        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12

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

        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12

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
        FUNC_SAVE_AVX512

        ;; arg1 - [in] state
        ;; arg2 - [in] job / [out] index
        ;; arg3 - [out] length
        GCM_SUBMIT_MB arg1, arg2, arg3, ENC

        FUNC_RESTORE_AVX512
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_enc_128_flush_vaes_avx512 / aes_gcm_enc_192_flush_vaes_avx512 /
;       aes_gcm_enc_256_flush_vaes_avx512
;       (MB_MGR_GCM_OOO *state)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_flush_),function,internal)
FN_NAME(enc,_flush_):
        FUNC_SAVE_AVX512

        ;; arg1 - [in] state
        ;; arg2 - [out] index
        ;; arg3 - [out] length
        GCM_FLUSH_MB arg1, arg2, arg3

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
        GCM_FINALIZE_x4 arg1, arg2, arg3, ENC

        FUNC_RESTORE_AVX512
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_dec_128_submit_vaes_avx512 / aes_gcm_dec_192_submit_vaes_avx512 /
;       aes_gcm_dec_256_submit_vaes_avx512
;       (MB_MGR_GCM_OOO *state, JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_submit_),function,internal)
FN_NAME(dec,_submit_):
        FUNC_SAVE_AVX512

        ;; arg1 - [in] state
        ;; arg2 - [in] job / [out] index
        ;; arg3 - [out] length
        GCM_SUBMIT_MB arg1, arg2, arg3, DEC

        FUNC_RESTORE_AVX512
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_dec_128_flush_vaes_avx512 / aes_gcm_dec_192_flush_vaes_avx512 /
;       aes_gcm_dec_256_flush_vaes_avx512
;       (MB_MGR_GCM_OOO *state)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_flush_),function,internal)
FN_NAME(dec,_flush_):
        FUNC_SAVE_AVX512

        ;; arg1 - [in] state
        ;; arg2 - [out] index
        ;; arg3 - [out] length
        GCM_FLUSH_MB arg1, arg2, arg3

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
        GCM_FINALIZE_x4 arg1, arg2, arg3, DEC

        FUNC_RESTORE_AVX512
        ret


%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
