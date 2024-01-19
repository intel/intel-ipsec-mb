;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2024, Intel Corporation All rights reserved.
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

%use smartalign

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/gcm_defines.inc"
%include "include/gcm_keys_avx2_avx512.inc"
%include "include/gcm_common.inc"
%include "include/memcpy.inc"
%include "include/cet.inc"
%include "include/error.inc"
%include "include/imb_job.inc"

%ifndef GCM128_MODE
%ifndef GCM192_MODE
%ifndef GCM256_MODE
%error "No GCM key size selected for gcm_common_avx2_avx512.inc!"
%endif
%endif
%endif

%ifdef IS_AVX512_GCM
%error "IS_AVX512_GCM: AVX512 variant removed!"
%endif

%ifdef IS_AVX2_GCM
%error "IS_AVX2_GCM: Definition not required!"
%endif

%define IS_AVX2_GCM

%xdefine GCM_API_POSTFIX avx_gen4
%xdefine GCM_API_POSTFIX_AVX512 avx512

;; Decide on AES-GCM key size to compile for
%ifdef GCM128_MODE
%define NROUNDS 9
%xdefine GCM_API_KEYSZ _128
%endif

%ifdef GCM192_MODE
%define NROUNDS 11
%xdefine GCM_API_KEYSZ _192
%endif

%ifdef GCM256_MODE
%define NROUNDS 13
%xdefine GCM_API_KEYSZ _256
%endif

;; Decide on AES-GCM key size to compile for
%define FN_NAME(x,y) aes_gcm_ %+ x %+ GCM_API_KEYSZ %+ y %+ GCM_API_POSTFIX
%define FN_NAME_AVX512(x,y) aes_gcm_ %+ x %+ GCM_API_KEYSZ %+ y %+ GCM_API_POSTFIX_AVX512

%define GMAC_FN_NAME(x) imb_aes_gmac_ %+ x %+ GCM_API_KEYSZ %+ _ %+ GCM_API_POSTFIX
%define GMAC_FN_NAME_AVX512(x) imb_aes_gmac_ %+ x %+ GCM_API_KEYSZ %+ _ %+ GCM_API_POSTFIX_AVX512

; need to store 5 GP registers on stack (align to 16 bytes)
; @note: the last 8-byte slot is used in JOB API to save/restore a register
%define GP_STORAGE 8*6

%define	TMP2	16*0    ; Temporary storage for AES State 2 (State 1 is stored in an XMM register)
%define	TMP3	16*1    ; Temporary storage for AES State 3
%define	TMP4	16*2    ; Temporary storage for AES State 4
%define	TMP5	16*3    ; Temporary storage for AES State 5
%define	TMP6	16*4    ; Temporary storage for AES State 6
%define	TMP7	16*5    ; Temporary storage for AES State 7
%define	TMP8	16*6    ; Temporary storage for AES State 8

%define	LOCAL_STORAGE	16*7

%ifidn __OUTPUT_FORMAT__, win64
	%define	XMM_STORAGE	16*10
%else
	%define	XMM_STORAGE	0
%endif

%define GP_OFFSET (LOCAL_STORAGE + XMM_STORAGE)

%define	VARIABLE_OFFSET	(GP_STORAGE + LOCAL_STORAGE + XMM_STORAGE)

;; extra memory for GCM context structure
%define CONTEXT_SIZE    6*16
%define CONTEXT_OFFSET  VARIABLE_OFFSET

;; Full stack frame layout:
;;                   RETURN ADDRESS + ARGS
;; R14 =  + 16*6  -> ---------------------------
;;                   GCM CONTEXT (JOB API only)
;;        + 6*8   -> ---------------------------
;;                   GP STORAGE
;;        + 16*10 -> --------------------------
;;                   XMM STORAGE (windows only)
;;        + 16*7  -> --------------------------
;;                   LOCAL STORAGE
;; RSP =          -> --------------------------

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Utility Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

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
        vpxor           %%GH, %%GH, %%T3

        vpsrldq         %%T3, %%GH, 8                   ; shift-R %%GH 2 DWs
        vpslldq         %%GH, %%GH, 8                   ; shift-L %%GH 2 DWs

        vpxor           %%T1, %%T1, %%T3
        vpxor           %%GH, %%GH, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;first phase of the reduction
        vmovdqa         %%T3, [rel POLY2]

        vpclmulqdq      %%T2, %%T3, %%GH, 0x01
        vpslldq         %%T2, %%T2, 8                    ; shift-L %%T2 2 DWs

        vpxor           %%GH, %%GH, %%T2                 ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;second phase of the reduction
        vpclmulqdq      %%T2, %%T3, %%GH, 0x00
        vpsrldq         %%T2, %%T2, 4                    ; shift-R %%T2 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%GH, %%T3, %%GH, 0x10
        vpslldq         %%GH, %%GH, 4                    ; shift-L %%GH 1 DW (Shift-L 1-DW to obtain result with no shifts)

        vpxor           %%GH, %%GH, %%T2                 ; second phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vpxor           %%GH, %%GH, %%T1                 ; the result is in %%GH

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; GHASH_MUL2 MACRO to implement: Data*HashKey mod (128,127,126,121,0)
;;; Input: A and B (128-bits each, bit-reflected)
;;; Output: C = A*B*x mod poly, (i.e. >>1 )
;;; To compute GH = GH*HashKey mod poly, give two constants:
;;;   HK = HashKey<<1 mod poly as input
;;;   KK = SWAP_H_L( HK_L * POLY) + HK
;;;   POLY = 0xC2 << 56
;;;
;;; Realize four multiplications first, to achieve partially reduced product
;;;   TLL = GH_L * KK_L
;;;   TLH = GH_L * KK_H
;;;   THL = GH_H * HK_L
;;;   THH = GH_H * HK_H
;;;
;;; Accumulate results into 2 registers, with corresponding weights
;;;   T1 = THH + TLH
;;;   T2 = THL + TLL
;;;
;;; Begin reduction
;;;    ----------
;;;    |   T1   |
;;;    ---------------
;;;         |   T2   |
;;;         ----------
;;;
;;;   T3 = SWAP_H_L(T2)
;;;   T5 = T2_L * POLY
;;;   GH = T1 + T5 + T3
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GHASH_MUL2  7
%define %%GH  %1        ;; [in/out] xmm with multiply operand(s) (128-bits)
%define %%HK  %2        ;; [in] xmm with hash key value(s) (128-bits)
%define %%KK  %3        ;; [in] xmm with hash key K value(s) (128-bits)
%define %%TLL %4        ;; [clobbered] xmm
%define %%TLH %5        ;; [clobbered] xmm
%define %%THL %6        ;; [clobbered] xmm
%define %%THH %7        ;; [clobbered] xmm

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vpclmulqdq      %%TLL, %%GH, %%KK, 0x00     ; TLL = GH_L * KK_L
        vpclmulqdq      %%TLH, %%GH, %%KK, 0x10     ; TLH = GH_L * KK_H
        vpclmulqdq      %%THL, %%GH, %%HK, 0x01     ; THL = GH_H * HK_L
        vpclmulqdq      %%THH, %%GH, %%HK, 0x11     ; THH = GH_H * HK_H

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; add products
        vpxor           %%TLL, %%TLL, %%THL
        vpxor           %%THH, %%THH, %%TLH

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction
        vpclmulqdq      %%GH, %%TLL, [rel POLY], 0x10
        vpshufd         %%TLH, %%TLL, 01001110b
        vpxor           %%GH, %%GH, %%THH
        vpxor           %%GH, %%GH, %%TLH
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endmacro

%macro  PRECOMPUTE 8
%define %%GDATA %1      ;; [in/out] pointer to GCM key data structure
%define %%HK    %2      ;; [in] Hash Key
%define %%T1    %3      ;; [clobbered] temporary XMM register
%define %%T2    %4      ;; [clobbered] temporary XMM register
%define %%T3    %5      ;; [clobbered] temporary XMM register
%define %%T4    %6      ;; [clobbered] temporary XMM register
%define %%T5    %7      ;; [clobbered] temporary XMM register
%define %%T6    %8      ;; [clobbered] temporary XMM register

        vmovdqa         %%T5, %%HK

        ;; calculate HashKeyX = HashKey x POLY
        vpclmulqdq      %%T1, %%T5, [rel POLY], 0x10
        vpshufd         %%T2, %%T5, 01001110b
        vpxor           %%T1, %%T1, %%T2
        vmovdqu         [%%GDATA + HashKeyK_1], %%T1

%assign i 2
%rep 7
        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^i<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_ %+ i], %%T5                ;  [HashKey_i] = HashKey^i<<1 mod poly

        ;; calculate HashKeyX = HashKey x POLY
        vpclmulqdq      %%T1, %%T5, [rel POLY], 0x10
        vpshufd         %%T2, %%T5, 01001110b
        vpxor           %%T1, %%T1, %%T2
        vmovdqu         [%%GDATA + HashKeyK_ %+ i], %%T1

%assign i (i + 1)
%endrep

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; CALC_GHASH: Calculates the hash of selected data
; Input: The input data (A_IN), that data's length (A_LEN), input hash value (AAD_HASH)
; Output: The hash of the data (AAD_HASH).
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  CALC_GHASH   11-12
%define %%A_IN          %1      ;; [in/clobbered] message pointer
%define %%A_LEN         %2      ;; [in/clobbered] message length
%define %%AAD_HASH      %3      ;; [in] input hash value (XMM)
%define %%GDATA_KEY     %4      ;; [in] pointer to GCM key data
%define %%XTMP0         %5      ;; [clobbered] temporary XMM
%define %%XTMP1         %6      ;; [clobbered] temporary XMM
%define %%XTMP2         %7      ;; [clobbered] temporary XMM
%define %%XTMP3         %8      ;; [clobbered] temporary XMM
%define %%XTMP4         %9      ;; [clobbered] temporary XMM
%define %%XTMP5         %10     ;; [clobbered] temporary XMM
%define %%T3            %11     ;; [clobbered] temporary GP register
%define %%MASKREG       %12     ;; [clobbered] mask register

%ifdef IS_AVX2_GCM
%if %0 != 11
%error "AVX2 CALC_GHASH needs 11 arguments!"
%endif
%endif

%ifdef IS_AVX512_GCM
%if %0 != 12
%error "AVX512 CALC_GHASH needs 12 arguments!"
%endif
%endif

        cmp     %%A_LEN, 16
        jb      %%_get_small_AAD_block

align 32
%%_get_AAD_loop128:
        cmp     %%A_LEN, 128
        jb      %%_exit_AAD_loop128

        vmovdqu         %%XTMP0, [%%A_IN + 16*0]
        vpshufb         %%XTMP0, %%XTMP0, [rel SHUF_MASK]

        vpxor           %%XTMP0, %%XTMP0, %%AAD_HASH

        vmovdqa         %%XTMP5, [%%GDATA_KEY + HashKeyK_8]
        vpclmulqdq      %%XTMP1, %%XTMP0, %%XTMP5, 0x00 ; XTMP1 = XTMP_L * KK_L
        vpclmulqdq      %%XTMP2, %%XTMP0, %%XTMP5, 0x10 ; XTMP2 = XTMP_L * KK_H
        vmovdqa         %%XTMP5, [%%GDATA_KEY + HashKey_8]
        vpclmulqdq      %%XTMP3, %%XTMP0, %%XTMP5, 0x01 ; XTMP3 = XTMP_H * HK_L
        vpclmulqdq      %%XTMP4, %%XTMP0, %%XTMP5, 0x11 ; XTMP4 = XTMP_H * HK_H
        vpxor           %%XTMP1, %%XTMP1, %%XTMP3       ; XTMP1 = XTMP1 + XTMP3
        vpxor           %%XTMP2, %%XTMP2, %%XTMP4       ; XTMP2 = XTMP2 + XTMP4

%assign i 1
%assign j 7
%rep 7
        vmovdqu         %%XTMP0, [%%A_IN + 16*i]
        vpshufb         %%XTMP0, %%XTMP0, [rel SHUF_MASK]

        vmovdqa         %%XTMP5, [%%GDATA_KEY + HashKeyK_ %+ j]
        vpclmulqdq      %%XTMP3, %%XTMP0, %%XTMP5, 0x00 ; XTMP1 = XTMP_L * KK_L
        vpclmulqdq      %%XTMP4, %%XTMP0, %%XTMP5, 0x10 ; XTMP2 = XTMP_L * KK_H
        vmovdqa         %%XTMP5, [%%GDATA_KEY + HashKey_ %+ j]
        vpxor           %%XTMP1, %%XTMP1, %%XTMP3
        vpxor           %%XTMP2, %%XTMP2, %%XTMP4
        vpclmulqdq      %%XTMP3, %%XTMP0, %%XTMP5, 0x01 ; XTMP3 = XTMP_H * HK_L
        vpclmulqdq      %%XTMP4, %%XTMP0, %%XTMP5, 0x11 ; XTMP4 = XTMP_H * HK_H
        vpxor           %%XTMP1, %%XTMP1, %%XTMP3
        vpxor           %%XTMP2, %%XTMP2, %%XTMP4

%assign i (i + 1)
%assign j (j - 1)
%endrep

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction
        vpclmulqdq      %%AAD_HASH, %%XTMP1, [rel POLY], 0x10
        vpshufd         %%XTMP3, %%XTMP1, 01001110b
        vpxor           %%AAD_HASH, %%AAD_HASH, %%XTMP2
        vpxor           %%AAD_HASH, %%AAD_HASH, %%XTMP3 ; the result is in %%AAD_HASH

        sub     %%A_LEN, 128
        je      %%_CALC_AAD_done

        add     %%A_IN, 128
        jmp     %%_get_AAD_loop128

%%_exit_AAD_loop128:
        cmp     %%A_LEN, 16
        jb      %%_get_small_AAD_block

        ;; calculate hash_key position to start with
        mov     %%T3, %%A_LEN
        and     %%T3, -16       ; 1 to 7 blocks possible here
        neg     %%T3
        add     %%T3, HashKey_1 + 16
        lea     %%T3, [%%GDATA_KEY + %%T3]

        vmovdqu         %%XTMP0, [%%A_IN]
        vpshufb         %%XTMP0, %%XTMP0, [rel SHUF_MASK]

        vpxor           %%XTMP0, %%XTMP0, %%AAD_HASH

        vmovdqa         %%XTMP5, [%%T3 + HKeyGap]
        vpclmulqdq      %%XTMP1, %%XTMP0, %%XTMP5, 0x00 ; XTMP1 = XTMP_L * KK_L
        vpclmulqdq      %%XTMP2, %%XTMP0, %%XTMP5, 0x10 ; XTMP2 = XTMP_L * KK_H
        vmovdqa         %%XTMP5, [%%T3]
        vpclmulqdq      %%XTMP3, %%XTMP0, %%XTMP5, 0x01 ; XTMP3 = XTMP_H * HK_L
        vpclmulqdq      %%XTMP4, %%XTMP0, %%XTMP5, 0x11 ; XTMP4 = XTMP_H * HK_H
        vpxor           %%XTMP1, %%XTMP1, %%XTMP3       ; XTMP1 = XTMP1 + XTMP3
        vpxor           %%XTMP2, %%XTMP2, %%XTMP4       ; XTMP2 = XTMP2 + XTMP4

        add     %%T3, 16        ; move to next hashkey
        add     %%A_IN, 16      ; move to next data block
        sub     %%A_LEN, 16
        cmp     %%A_LEN, 16
        jb      %%_AAD_reduce

align 32
%%_AAD_blocks:
        vmovdqu         %%XTMP0, [%%A_IN]
        vpshufb         %%XTMP0, %%XTMP0, [rel SHUF_MASK]

        vmovdqa         %%XTMP5, [%%T3 + HKeyGap]
        vpclmulqdq      %%XTMP3, %%XTMP0, %%XTMP5, 0x00 ; XTMP1 = XTMP_L * KK_L
        vpclmulqdq      %%XTMP4, %%XTMP0, %%XTMP5, 0x10 ; XTMP2 = XTMP_L * KK_H
        vmovdqa         %%XTMP5, [%%T3]
        vpxor           %%XTMP1, %%XTMP1, %%XTMP3
        vpxor           %%XTMP2, %%XTMP2, %%XTMP4
        vpclmulqdq      %%XTMP3, %%XTMP0, %%XTMP5, 0x01 ; XTMP3 = XTMP_H * HK_L
        vpclmulqdq      %%XTMP4, %%XTMP0, %%XTMP5, 0x11 ; XTMP4 = XTMP_H * HK_H
        vpxor           %%XTMP1, %%XTMP1, %%XTMP3
        vpxor           %%XTMP2, %%XTMP2, %%XTMP4

        add     %%T3, 16        ; move to next hashkey
        add     %%A_IN, 16
        sub     %%A_LEN, 16
        cmp     %%A_LEN, 16
        jae     %%_AAD_blocks

%%_AAD_reduce:
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction
        vpclmulqdq      %%AAD_HASH, %%XTMP1, [rel POLY], 0x10
        vpshufd         %%XTMP3, %%XTMP1, 01001110b
        vpxor           %%AAD_HASH, %%AAD_HASH, %%XTMP2
        vpxor           %%AAD_HASH, %%AAD_HASH, %%XTMP3 ; the result is in %%AAD_HASH

%%_get_small_AAD_block:
        or      %%A_LEN, %%A_LEN
        je      %%_CALC_AAD_done

        vmovdqa         %%XTMP0, [%%GDATA_KEY + HashKey_1]
        vmovdqa         %%XTMP1, [%%GDATA_KEY + HashKeyK_1]
%ifdef IS_AVX2_GCM
        READ_SMALL_DATA_INPUT_AVX %%XTMP2, %%A_IN, %%A_LEN, %%T3
%else
        READ_SMALL_DATA_INPUT_AVX512 %%XTMP2, %%A_IN, %%A_LEN, %%T3, %%MASKREG
%endif
        ;byte-reflect the AAD data
        vpshufb         %%XTMP2, %%XTMP2, [rel SHUF_MASK]
        vpxor           %%AAD_HASH, %%XTMP2
        GHASH_MUL2      %%AAD_HASH, %%XTMP0, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5

%%_CALC_AAD_done:

%endmacro ; CALC_GHASH

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; CALC_AAD_HASH: Calculates the hash of selected data which will not be encrypted.
; Input: The input data (A_IN), that data's length (A_LEN), and input hash (AAD_HASH)
; Output: The hash of the data (AAD_HASH).
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  CALC_AAD_HASH   13
%define %%A_IN          %1      ;; [in] message pointer
%define %%A_LEN         %2      ;; [in] message length
%define %%AAD_HASH      %3      ;; [in] input hash value (XMM)
%define %%GDATA_KEY     %4      ;; [in] pointer to GCM key data
%define %%XTMP0         %5      ;; [clobbered] temporary XMM
%define %%XTMP1         %6      ;; [clobbered] temporary XMM
%define %%XTMP2         %7      ;; [clobbered] temporary XMM
%define %%XTMP3         %8      ;; [clobbered] temporary XMM
%define %%XTMP4         %9      ;; [clobbered] temporary XMM
%define %%XTMP5         %10     ;; [clobbered] temporary XMM
%define %%T1            %11     ;; [clobbered] temporary GP register
%define %%T2            %12     ;; [clobbered] temporary GP register
%define %%T3            %13     ;; [clobbered] temporary GP register

        mov     %%T1, %%A_IN            ; T1 = AAD
        mov     %%T2, %%A_LEN           ; T2 = aadLen

%ifdef IS_AVX2_GCM
        CALC_GHASH      %%T1, %%T2, %%AAD_HASH, %%GDATA_KEY, \
                        %%XTMP0, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, \
                        %%T3
%endif

%ifdef IS_AVX512_GCM
        CALC_GHASH      %%T1, %%T2, %%AAD_HASH, %%GDATA_KEY, \
                        %%XTMP0, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, \
                        %%T3, k1
%endif

%endmacro ; CALC_AAD_HASH

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; PARTIAL_BLOCK: Handles encryption/decryption and the tag partial blocks between update calls.
; Requires the input data be at least 1 byte long.
; Input: gcm_key_data * (GDATA_KEY), gcm_context_data *(GDATA_CTX), input text (PLAIN_CIPH_IN),
; input text length (PLAIN_CIPH_LEN), the current data offset (DATA_OFFSET),
; the hash subkey (HASH_SUBKEY) and whether encoding or decoding (ENC_DEC)
; Output: A cipher of the first partial block (CIPH_PLAIN_OUT), and updated GDATA_CTX
; Clobbers rax, r10, r12, r13, r15, xmm0, xmm1, xmm2, xmm3, xmm5, xmm6, xmm9, xmm10, xmm11
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PARTIAL_BLOCK    8
%define %%GDATA_CTX             %1      ;; [in/out] GP with pointer to GCM context structure; context gets updated
%define %%CIPH_PLAIN_OUT        %2      ;; [in] GP with pointer to destination buffer
%define %%PLAIN_CIPH_IN         %3      ;; [in] GP with pointer to source buffer
%define %%PLAIN_CIPH_LEN        %4      ;; [in] GP with message length
%define %%DATA_OFFSET           %5      ;; [in/out] GP with offset to source/destination buffer
%define %%AAD_HASH              %6      ;; [in/out] an XMM with GHASH value
%define %%GDATA_KEY             %7      ;; [in] GP with pointer to GCM keys structure
%define %%ENC_DEC               %8      ;; [in] "ENC" or "DEC" cipher direction selector

        mov     r13, [%%GDATA_CTX + PBlockLen]
        or      r13, r13
        je      %%_partial_block_done           ;Leave Macro if no partial blocks

%ifdef IS_AVX2_GCM
        cmp     %%PLAIN_CIPH_LEN, 16            ;Read in input data without over reading
        jl      %%_fewer_than_16_bytes
        VXLDR   xmm1, [%%PLAIN_CIPH_IN]         ;If more than 16 bytes of data, just fill the xmm register
        jmp     %%_data_read

%%_fewer_than_16_bytes:
        lea     r10, [%%PLAIN_CIPH_IN + %%DATA_OFFSET]
        READ_SMALL_DATA_INPUT_AVX   xmm1, r10, %%PLAIN_CIPH_LEN, rax

%%_data_read:                           ;Finished reading in data
%else
        ; Read in input data without over reading
        READ_SMALL_DATA_INPUT_LEN_BT16_AVX512   xmm1, %%PLAIN_CIPH_IN, %%PLAIN_CIPH_LEN, r12, rax, k1
%endif
        vmovdqu xmm9, [%%GDATA_CTX + PBlockEncKey]  ;xmm9 = my_ctx_data.partial_block_enc_key

        lea     r12, [rel SHIFT_MASK]

        add     r12, r13                        ; adjust the shuffle mask pointer to be able to shift r13 bytes (16-r13 is the number of bytes in plaintext mod 16)
        vmovdqu xmm2, [r12]                     ; get the appropriate shuffle mask
        vpshufb xmm9, xmm2                      ;shift right r13 bytes

%ifidn  %%ENC_DEC, DEC
        vmovdqa xmm3, xmm1
%endif
        vpxor   xmm9, xmm1                      ; Ciphertext XOR E(K, Yn)

        mov     r15, %%PLAIN_CIPH_LEN
        add     r15, r13
        sub     r15, 16                         ;Set r15 to be the amount of data left in CIPH_PLAIN_IN after filling the block
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
        or      r15, r15
        jl      %%_partial_incomplete

        vmovdqa xmm3, [%%GDATA_KEY + HashKey_1]
        vmovdqa xmm1, [%%GDATA_KEY + HashKeyK_1]
        GHASH_MUL2      %%AAD_HASH, xmm3, xmm1, xmm0, xmm10, xmm11, xmm5       ;GHASH computation for the last <16 Byte block
        xor     rax, rax
        mov     [%%GDATA_CTX + PBlockLen], rax
        jmp     %%_enc_dec_done

%%_partial_incomplete:
%ifidn __OUTPUT_FORMAT__, win64
        mov     rax, %%PLAIN_CIPH_LEN
       	add     [%%GDATA_CTX + PBlockLen], rax
%else
        add     [%%GDATA_CTX + PBlockLen], %%PLAIN_CIPH_LEN
%endif
%%_enc_dec_done:
        vmovdqu [%%GDATA_CTX + AadHash], %%AAD_HASH

%ifidn  %%ENC_DEC, ENC
        vpshufb xmm9, [rel SHUF_MASK]       ; shuffle xmm9 back to output as ciphertext
        vpshufb xmm9, xmm2
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; output encrypted Bytes
        or      r15, r15
        jl      %%_partial_fill
        mov     r12, r13
        mov     r13, 16
        sub     r13, r12                        ; Set r13 to be the number of bytes to write out
        jmp     %%_count_set
%%_partial_fill:
        mov     r13, %%PLAIN_CIPH_LEN
%%_count_set:

%ifdef IS_AVX2_GCM
        simd_store_avx  %%CIPH_PLAIN_OUT, xmm9, r13, rax, r12, %%DATA_OFFSET
        add             %%DATA_OFFSET, r13
%else
        lea             rax, [rel byte_len_to_mask_table]
        kmovw           k1, [rax + r13*2]
        vmovdqu8        [%%CIPH_PLAIN_OUT + %%DATA_OFFSET]{k1}, xmm9
        add             %%DATA_OFFSET, r13
%endif
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_partial_block_done:
%endmacro ; PARTIAL_BLOCK

%macro GHASH_SINGLE_MUL 9
%define %%GDATA                 %1      ;; [in] GHASH key pointer
%define %%HASHKEY               %2      ;; [in] offset to GHASH key
%define %%CIPHER                %3      ;; [in] xmm with cipher text block
%define %%STATE_11              %4      ;; [in/out] GHASH product state (hi)
%define %%STATE_00              %5      ;; [in/out] GHASH product state (lo)
%define %%T1                    %6      ;; [clobbered] temporary xmm - (it was STATE_MID)
%define %%T2                    %7      ;; [clobbered] temporary xmm
%define %%T3                    %8      ;; [clobbered] temporary xmm
%define %%FIRST                 %9      ;; [in] "first" time or not ("update") selector

%ifidn %%FIRST, first
        vmovdqa         %%T1, [%%GDATA + %%HASHKEY + HKeyGap]
        vmovdqa         %%T2, [%%GDATA + %%HASHKEY]
        vpclmulqdq      %%STATE_00, %%CIPHER, %%T1, 0x00        ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%STATE_11, %%CIPHER, %%T1, 0x10        ; STATE_11 = DATA_L * KK_H
        vpclmulqdq      %%T1, %%CIPHER, %%T2, 0x01              ; T1 = DATA_H * HK_L
        vpclmulqdq      %%T2, %%CIPHER, %%T2, 0x11              ; T2 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%T1            ; STATE_00 += T1
        vpxor           %%STATE_11, %%STATE_11, %%T2            ; STATE_11 += T2
%else
        vmovdqa         %%T3, [%%GDATA + %%HASHKEY + HKeyGap]
        vpclmulqdq      %%T1, %%CIPHER, %%T3, 0x00              ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%T2, %%CIPHER, %%T3, 0x10              ; STATE_11 = DATA_L * KK_H
        vpxor           %%STATE_00, %%STATE_00, %%T1            ; STATE_00 += T1
        vpxor           %%STATE_11, %%STATE_11, %%T2            ; STATE_11 += T2
        vmovdqa         %%T3, [%%GDATA + %%HASHKEY]
        vpclmulqdq      %%T1, %%CIPHER, %%T3, 0x01              ; T1 = DATA_H * HK_L
        vpclmulqdq      %%T2, %%CIPHER, %%T3, 0x11              ; T2 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%T1            ; STATE_00 += T1
        vpxor           %%STATE_11, %%STATE_11, %%T2            ; STATE_11 += T2
%endif

%endmacro

; if a = number of total plaintext bytes
; b = floor(a/16)
; %%num_initial_blocks = b mod 8;
; encrypt the initial %%num_initial_blocks blocks and apply ghash on the ciphertext
; %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r14 are used as a pointer only, not modified.
; Updated AAD_HASH is returned in %%T3

%macro INITIAL_BLOCKS 23
%define %%GDATA_KEY             %1
%define %%CIPH_PLAIN_OUT        %2
%define %%PLAIN_CIPH_IN         %3
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
                vpaddd   %%CTR, %%CTR, [rel ONE]        ; INCR Y0
                vpshufb  reg(i), %%CTR, [rel SHUF_MASK] ; perform a 16Byte swap
%assign i (i+1)
%endrep

%if (%%num_initial_blocks > 0)
                vmovdqu  %%T_key, [%%GDATA_KEY+16*0]
%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks
                vpxor    reg(i), reg(i), %%T_key
%assign i (i+1)
%endrep

%assign j 1
%rep NROUNDS
                vmovdqu  %%T_key, [%%GDATA_KEY+16*j]
%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenc  reg(i), %%T_key
%assign i (i+1)
%endrep

%assign j (j+1)
%endrep

                vmovdqu  %%T_key, [%%GDATA_KEY+16*j]
%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenclast      reg(i),%%T_key
%assign i (i+1)
%endrep

%endif ; %if(%%num_initial_blocks>0)

%assign i (9 - %%num_initial_blocks)
%assign k 0
%rep %%num_initial_blocks
                VXLDR   %%T1, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + k*16]
                vpxor   reg(i), reg(i), %%T1

%ifidn  %%ENC_DEC, DEC
%if k == 0
                vmovdqa %%T6, %%T1
%else
                vmovdqa [rsp + TMP %+ i], %%T1
%endif
%endif

%assign i (i + 1)
%assign k (k + 1)
%endrep

%assign i (9 - %%num_initial_blocks)
%assign k 0
%rep %%num_initial_blocks
                ;; Write back ciphertext for %%num_initial_blocks blocks
                VXSTR  [%%CIPH_PLAIN_OUT + %%DATA_OFFSET + k*16], reg(i)
                ;; Prepare ciphertext for GHASH computations
%ifidn  %%ENC_DEC, DEC
%if k == 0
                vpshufb reg(i), %%T6, [rel SHUF_MASK]
%else
                vmovdqa %%T1, [rsp + TMP %+ i]
                vpshufb reg(i), %%T1, [rel SHUF_MASK]
%endif
%else
                vpshufb  reg(i), reg(i), [rel SHUF_MASK]
%endif
%assign i (i + 1)
%assign k (k + 1)
%endrep
                add     %%DATA_OFFSET, (16 * %%num_initial_blocks)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (9 - %%num_initial_blocks)
%if (%%num_initial_blocks > 0)
        vmovdqa %%T3, reg(i)
%assign i (i + 1)
%endif
%if (%%num_initial_blocks > 1)
%rep %%num_initial_blocks - 1
        vmovdqu [rsp + TMP %+ i], reg(i)
%assign i (i+1)
%endrep
%endif
                ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
                ;; Prepare 8 counter blocks and perform rounds of AES cipher on
                ;; them, load plain/cipher text and store cipher/plain text.
                ;; Stitch GHASH computation in between AES rounds.
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
        vmovdqu         %%T2, [rsp + TMP %+ j]
        GHASH_SINGLE_MUL %%GDATA_KEY, HashKey_ %+ k, %%T2, \
                         %%T1,     %%T4,   %%T6,    %%T5, %%T3, not_first
%endif

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%if(%%num_initial_blocks>3)
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
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction T4(low):T1(high), result in %%T3
        vpclmulqdq      %%T3, %%T4, [rel POLY], 0x10
        vpshufd         %%T6, %%T4, 01001110b
        vpxor           %%T3, %%T3, %%T1
        vpxor           %%T3, %%T3, %%T6
%else
        ;; The hash should end up in T3
        vmovdqa         %%T3, %%T2
%endif

        ;; Final hash is now in T3

%if %%num_initial_blocks > 0
                ;; NOTE: obsolete in case %%num_initial_blocks = 0
                sub     %%LENGTH, 16 * %%num_initial_blocks

                ;; NOTE: 'jl' is never taken for %%num_initial_blocks = 0
                ;;      This macro is executed for length 128 and up,
                ;;      zero length is checked in GCM_ENC_DEC.
                ;; If the last block is partial then the xor will be done later
                ;; in ENCRYPT_FINAL_PARTIAL_BLOCK.
                ;; We know it's partial if LENGTH - 16*num_initial_blocks < 128
                cmp %%LENGTH, 128
                jl %%_initial_skip_last_word_write
%endif

                ;; Load 8 plain/cipher text blocks and XOR them against AES blocks
%assign i 1
%rep 8
%assign k (i - 1)

                VXLDR   %%T1, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*k]
                vpxor   reg(i), reg(i), %%T1
%ifidn  %%ENC_DEC, DEC
%if i == 1
                vmovdqa %%T6, %%T1
%else
                vmovdqa [rsp + TMP %+ i], %%T1
%endif
%endif
%assign i (i + 1)
%endrep

                ;; Store 8 cipher/plain text blocks and prepare cipher text blocks for GHASH
%assign i 1
%rep 8
%assign k (i - 1)
                VXSTR  [%%CIPH_PLAIN_OUT + %%DATA_OFFSET + 16*k], reg(i)
%ifidn  %%ENC_DEC, DEC
%if i == 1
                vmovdqa reg(i), %%T6
%else
                vmovdqa reg(i), [rsp + TMP %+ i]
%endif
%endif
%assign i (i + 1)
%endrep

                ;; Update %%LENGTH with the number of blocks processed
                sub     %%LENGTH, 8*16
                add     %%DATA_OFFSET, 8*16

%if %%num_initial_blocks > 0
                ;; jmp and %%_initial_skip_last_word_write not required for %%num_initial_blocks=0 case
                jmp     %%_initial_words_done

%%_initial_skip_last_word_write:
                ;; Load 7 plain/cipher text blocks and XOR them against AES blocks
%assign i 1
%rep 7
%assign k (i - 1)

                VXLDR   %%T1, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*k]
                vpxor   reg(i), reg(i), %%T1
%ifidn  %%ENC_DEC, DEC
%if i == 1
                vmovdqa %%T6, %%T1
%else
                vmovdqa [rsp + TMP %+ i], %%T1
%endif
%endif
%assign i (i + 1)
%endrep

                ;; Store 7 cipher/plain text blocks and prepare cipher text blocks for GHASH
%assign i 1
%rep 7
%assign k (i - 1)
                VXSTR  [%%CIPH_PLAIN_OUT + %%DATA_OFFSET + 16*k], reg(i)
%ifidn  %%ENC_DEC, DEC
%if i == 1
                vmovdqa reg(i), %%T6
%else
                vmovdqa reg(i), [rsp + TMP %+ i]
%endif
%endif
%assign i (i + 1)
%endrep

                ;; Update %%LENGTH with the number of blocks processed
                sub     %%LENGTH, 7*16
                add     %%DATA_OFFSET, 7*16

%%_initial_words_done:
%endif ;; %%num_initial_blocks > 0

                vpshufb %%XMM1, [rel SHUF_MASK]             ; perform a 16Byte swap
                ;; Combine GHASHed value with the corresponding ciphertext
                vpxor   %%XMM1, %%XMM1, %%T3
                vpshufb %%XMM2, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM3, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM4, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM5, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM6, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM7, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM8, [rel SHUF_MASK]             ; perform a 16Byte swap

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_initial_blocks_done:

%endmacro

;;; INITIAL_BLOCKS macro with support for a partial final block.
;;; num_initial_blocks is expected to include the partial final block
;;;     in the count.
%macro INITIAL_BLOCKS_PARTIAL 25
%define %%GDATA_KEY             %1      ;; [in] pointer to GCM key data
%define %%GDATA_CTX             %2      ;; [in] pointer to GCM context data
%define %%CIPH_PLAIN_OUT        %3      ;; [in] pointer to destination buffer
%define %%PLAIN_CIPH_IN         %4      ;; [in] pointer to source buffer
%define %%LENGTH                %5      ;; [in] message length
%define %%DATA_OFFSET           %6      ;; [in/out] buffer offset
%define %%num_initial_blocks    %7      ;; [in] numeric value, number of blocks can be from 1 to 7 (not 0)
%define %%T1                    %8
%define %%T2                    %9
%define %%T3                    %10     ;; [out] hash value (XMM)
%define %%T4                    %11
%define %%T5                    %12
%define %%CTR                   %13
%define %%XMM1                  %14
%define %%XMM2                  %15
%define %%XMM3                  %16
%define %%XMM4                  %17
%define %%XMM5                  %18
%define %%XMM6                  %19
%define %%XMM7                  %20
%define %%XMM8                  %21     ;; [in] hash value (XMM)
%define %%T6                    %22
%define %%T_key                 %23
%define %%ENC_DEC               %24
%define %%INSTANCE_TYPE         %25

%assign i (8 - %%num_initial_blocks)
                ;; Move AAD_HASH to temp reg
                vmovdqu  %%T2, %%XMM8
                ;; vmovdqu  %%CTR, [%%GDATA_CTX + CurCount]  ; %%CTR = Y0

%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks
                ;; Compute AES counters
                vpaddd   %%CTR, %%CTR, [rel ONE]     ; INCR Y0
                vmovdqa  reg(i), %%CTR
                vpshufb  reg(i), [rel SHUF_MASK]     ; perform a 16Byte swap
%assign i (i + 1)
%endrep

                vmovdqu  %%T_key, [%%GDATA_KEY+16*0]
%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks
                ; Start AES for %%num_initial_blocks blocks
                vpxor    reg(i), reg(i), %%T_key
%assign i (i + 1)
%endrep

%assign j 1
%rep NROUNDS
                vmovdqu  %%T_key, [%%GDATA_KEY+16*j]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenc  reg(i), %%T_key
%assign i (i + 1)
%endrep

%assign j (j + 1)
%endrep

                vmovdqu  %%T_key, [%%GDATA_KEY+16*j]
%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenclast      reg(i),%%T_key
%assign i (i + 1)
%endrep

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Hash all but the last block of data
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign k 0
%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks - 1
                ;; Encrypt the message for all but the last block
                VXLDR   %%T1, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*k]
                vpxor   reg(i), reg(i), %%T1
%ifidn  %%ENC_DEC, DEC
%if k == 0
                vmovdqa %%T6, %%T1
%else
                vmovdqa [rsp + TMP %+ i], %%T1
%endif
%endif
%assign i (i + 1)
%assign k (k + 1)
%endrep

%assign k 0
%assign i (9 - %%num_initial_blocks)
%rep %%num_initial_blocks - 1
                ;; write back ciphertext for %%num_initial_blocks blocks
                VXSTR   [%%CIPH_PLAIN_OUT + %%DATA_OFFSET + 16*k], reg(i)
                ;; Prepare ciphertext for GHASH computations
%ifidn  %%ENC_DEC, DEC
%if k == 0
                vpshufb reg(i), %%T6, [rel SHUF_MASK]
%else
                vmovdqa reg(i), [rsp + TMP %+ i]
                vpshufb reg(i), reg(i), [rel SHUF_MASK]
%endif
%else ; ENC
                vpshufb reg(i), reg(i), [rel SHUF_MASK]
%endif
%assign i (i + 1)
%assign k (k + 1)
%endrep
                add     %%DATA_OFFSET, (16 * (%%num_initial_blocks - 1))

%if %%num_initial_blocks > 1
                ;; The final block of data may be <16B
                sub      %%LENGTH, 16*(%%num_initial_blocks-1)
%endif

%if %%num_initial_blocks < 8
                ;; NOTE: the 'jl' is always taken for num_initial_blocks = 8.
                ;;      This is run in the context of GCM_ENC_DEC_SMALL for length < 128.
                cmp      %%LENGTH, 16
                jl       %%_small_initial_partial_block

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Handle a full length final block - encrypt and hash all blocks
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                sub      %%LENGTH, 16
	        mov	[%%GDATA_CTX + PBlockLen], %%LENGTH

                ;; Encrypt the message
                VXLDR  %%T1, [%%PLAIN_CIPH_IN + %%DATA_OFFSET]
                vpxor    reg(i), reg(i), %%T1
                ;; write back ciphertext for %%num_initial_blocks blocks
                VXSTR  [%%CIPH_PLAIN_OUT + %%DATA_OFFSET], reg(i)
                add     %%DATA_OFFSET, 16
                ;; Prepare ciphertext for GHASH computations
%ifidn  %%ENC_DEC, DEC
                vpshufb  reg(i), %%T1, [rel SHUF_MASK]
%else
                vpshufb  reg(i), reg(i), [rel SHUF_MASK]
%endif

        ;; Hash all of the data
%assign i (8 - %%num_initial_blocks)
%assign j (9 - %%num_initial_blocks)
%assign k (%%num_initial_blocks)
%assign last_block_to_hash 0

%if (%%num_initial_blocks > last_block_to_hash)
        ;; Hash in AES state
        vpxor %%T2, %%T2, reg(j)

        ;; T2 - incoming AAD hash
        ;; reg(i) holds ciphertext
        ;; T5 - hash key
        ;; T6 - updated xor
        ;; reg(1)/xmm1 should now be available for tmp use
        vmovdqa         %%T5, [%%GDATA_KEY + HashKeyK_ %+ k]
        vmovdqa         %%T6, [%%GDATA_KEY + HashKey_ %+ k]
        vpclmulqdq      %%T1, %%T2, %%T5, 0x00          ; T1 = DATA_L * KK_L
        vpclmulqdq      %%T4, %%T2, %%T5, 0x10          ; T4 = DATA_L * KK_H
        vpclmulqdq      %%T5, %%T2, %%T6, 0x01          ; T5 = DATA_H * HK_L
        vpclmulqdq      %%T6, %%T2, %%T6, 0x11          ; T6 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T5                ; T1 += T5
        vpxor           %%T4, %%T4, %%T6                ; T4 += T6
%endif

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%assign rep_count (%%num_initial_blocks-1)
%rep rep_count

        vmovdqa         %%T5, [%%GDATA_KEY + HashKeyK_ %+ k]
        vmovdqa         %%T6, [%%GDATA_KEY + HashKey_ %+ k]
        vpclmulqdq      %%T3, reg(j), %%T5, 0x00        ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, reg(j), %%T5, 0x10        ; T5 = DATA_L * KK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T4, %%T4, %%T5                ; T4 += T5
        vpclmulqdq      %%T3, reg(j), %%T6, 0x01        ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, reg(j), %%T6, 0x11        ; T5 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T4, %%T4, %%T5                ; T4 += T5

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%endrep

        ;; Record that a reduction is needed
        mov            DWORD(r12), 1

        jmp      %%_small_initial_compute_hash

%endif                          ; %if %%num_initial_blocks < 8

%%_small_initial_partial_block:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Handle ghash for a <16B final block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;; In this case if it's a single call to encrypt we can
        ;; hash all of the data but if it's an init / update / finalize
        ;; series of call we need to leave the last block if it's
        ;; less than a full block of data.

	mov	[%%GDATA_CTX + PBlockLen], %%LENGTH
        vmovdqu [%%GDATA_CTX + PBlockEncKey], reg(i)
        ;; Handle a partial final block
        ;;                            GDATA,    KEY,   T1,   T2
        ;; r13 - length
        ;; LT16 - indicates type of read and that the buffer is less than 16 bytes long
        ;;      NOTE: could be replaced with %%LENGTH but at this point
        ;;      %%LENGTH is always less than 16.
        ;;      No PLAIN_CIPH_LEN argument available in this macro.
        ENCRYPT_FINAL_PARTIAL_BLOCK reg(i), %%T1, %%T3, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, LT16, %%ENC_DEC, %%DATA_OFFSET
        vpshufb  reg(i), [rel SHUF_MASK]

%ifidn %%INSTANCE_TYPE, multi_call
%assign i (8 - %%num_initial_blocks)
%assign j (9 - %%num_initial_blocks)
%assign k (%%num_initial_blocks - 1)
%assign last_block_to_hash 1
%else
%assign i (8 - %%num_initial_blocks)
%assign j (9 - %%num_initial_blocks)
%assign k (%%num_initial_blocks)
%assign last_block_to_hash 0
%endif

%if (%%num_initial_blocks > last_block_to_hash)
        ;; Record that a reduction is needed
        mov            DWORD(r12), 1
        ;; Hash in AES state
        vpxor          %%T2, %%T2, reg(j)

        ;; T2 - incoming AAD hash
        ;; reg(i) holds ciphertext
        ;; T5 - hash key
        ;; T6 - updated xor
        ;; reg(1)/xmm1 should now be available for tmp use
        vmovdqa         %%T5, [%%GDATA_KEY + HashKeyK_ %+ k]
        vmovdqa         %%T6, [%%GDATA_KEY + HashKey_ %+ k]
        vpclmulqdq      %%T1, %%T2, %%T5, 0x00          ; T1 = DATA_L * KK_L
        vpclmulqdq      %%T4, %%T2, %%T5, 0x10          ; T4 = DATA_L * KK_H
        vpclmulqdq      %%T5, %%T2, %%T6, 0x01          ; T5 = DATA_H * HK_L
        vpclmulqdq      %%T6, %%T2, %%T6, 0x11          ; T6 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T5                ; T1 += T5
        vpxor           %%T4, %%T4, %%T6                ; T4 += T6
%else
        ;; Record that a reduction is not needed -
        ;; In this case no hashes are computed because there
        ;; is only one initial block and it is < 16B in length.
        xor            r12, r12
%endif

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%ifidn %%INSTANCE_TYPE, multi_call
%assign rep_count (%%num_initial_blocks-2)
%%_multi_call_hash:
%else
%assign rep_count (%%num_initial_blocks-1)
%endif

%if rep_count < 0
        ;; fix for negative rep_count
%assign rep_count 0
%endif

%rep rep_count

        vmovdqa         %%T5, [%%GDATA_KEY + HashKeyK_ %+ k]
        vmovdqa         %%T6, [%%GDATA_KEY + HashKey_ %+ k]
        vpclmulqdq      %%T3, reg(j), %%T5, 0x00        ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, reg(j), %%T5, 0x10        ; T5 = DATA_L * KK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T4, %%T4, %%T5                ; T4 += T5
        vpclmulqdq      %%T3, reg(j), %%T6, 0x01        ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, reg(j), %%T6, 0x11        ; T5 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T4, %%T4, %%T5                ; T4 += T5

%assign i (i+1)
%assign j (j+1)
%assign k (k-1)
%endrep

%%_small_initial_compute_hash:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Ghash reduction
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%if(%%num_initial_blocks=1)
%ifidn %%INSTANCE_TYPE, multi_call
        ;; We only need to check if a reduction is needed if
        ;; initial_blocks == 1 and init/update/final is being used.
        ;; In this case we may just have a partial block, and that
        ;; gets hashed in finalize.
        or      r12, r12
        je      %%_no_reduction_needed
%endif
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction T1(low):T4(high), result in %%T3
        vpclmulqdq      %%T3, %%T1, [rel POLY], 0x10
        vpshufd         %%T6, %%T1, 01001110b
        vpxor           %%T3, %%T3, %%T4
        vpxor           %%T3, %%T3, %%T6

%ifidn %%INSTANCE_TYPE, multi_call
        ;; If using init/update/finalize, we need to xor any partial block data
        ;; into the hash.
%if %%num_initial_blocks > 1
        ;; NOTE: for %%num_initial_blocks = 0 the xor never takes place
%if %%num_initial_blocks != 8
        ;; NOTE: for %%num_initial_blocks = 8, %%LENGTH, stored in [PBlockLen] is never zero
        cmp             qword [%%GDATA_CTX + PBlockLen], 0
        je              %%_no_partial_block_xor
%endif                          ; %%num_initial_blocks != 8
        vpxor           %%T3, %%T3, reg(8)
%%_no_partial_block_xor:
%endif                          ; %%num_initial_blocks > 1
%endif                          ; %%INSTANCE_TYPE, multi_call

%if(%%num_initial_blocks=1)
%ifidn %%INSTANCE_TYPE, multi_call
        ;; NOTE: %%_no_reduction_needed case only valid for
        ;;      multi_call with initial_blocks = 1.
        ;; Look for comment above around '_no_reduction_needed'
        ;; The jmp below is obsolete as the code will fall through.

        ;; The result is in %%T3
        jmp             %%_after_reduction

%%_no_reduction_needed:
        ;; The hash should end up in T3. The only way we should get here is if
        ;; there is a partial block of data, so xor that into the hash.
        vpxor            %%T3, %%T2, reg(8)
%endif                          ; %%INSTANCE_TYPE = multi_call
%endif                          ; %%num_initial_blocks=1

%%_after_reduction:
        ;; Final hash is now in T3

%endmacro                       ; INITIAL_BLOCKS_PARTIAL

; encrypt 8 blocks at a time
; ghash the 8 previously encrypted ciphertext blocks
; %%GDATA (KEY), %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN are used as pointers only, not modified
; %%DATA_OFFSET is the data offset value
%macro  GHASH_8_ENCRYPT_8_PARALLEL 23
%define %%GDATA                 %1
%define %%CIPH_PLAIN_OUT        %2
%define %%PLAIN_CIPH_IN         %3
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
                vmovdqa %%T5, [rel TWO]
                vpaddd  %%XMM2, %%CTR, %%T5
                vpaddd  %%XMM3, %%XMM1, %%T5
                vpaddd  %%XMM4, %%XMM2, %%T5
                vpaddd  %%XMM5, %%XMM3, %%T5
                vpaddd  %%XMM6, %%XMM4, %%T5
                vpaddd  %%XMM7, %%XMM5, %%T5
                vpaddd  %%XMM8, %%XMM6, %%T5
                vmovdqa %%CTR, %%XMM8

                vmovdqa %%T5, [rel SHUF_MASK]
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
                vmovdqa %%T5, [rel TWOf]
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

        vmovdqa         %%T5, [%%GDATA + HashKeyK_8]
        vmovdqa         %%T6, [%%GDATA + HashKey_8]
        vpclmulqdq      %%T7, %%T2, %%T5, 0x00          ; T7 = DATA_L * KK_L
        vpclmulqdq      %%T4, %%T2, %%T5, 0x10          ; T4 = DATA_L * KK_H
        vpclmulqdq      %%T5, %%T2, %%T6, 0x01          ; T5 = DATA_H * HK_L
        vpclmulqdq      %%T6, %%T2, %%T6, 0x11          ; T6 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T5
        vpxor           %%T4, %%T4, %%T6

                vmovdqu %%T1, [%%GDATA + 16*3]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqa         %%T1, [rsp + TMP2]
        vmovdqa         %%T5, [%%GDATA + HashKeyK_7]
        vmovdqa         %%T6, [%%GDATA + HashKey_7]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00          ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, %%T1, %%T5, 0x10          ; T5 = DATA_L * KK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5
        vpclmulqdq      %%T3, %%T1, %%T6, 0x01          ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, %%T1, %%T6, 0x11          ; T5 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5

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
        vmovdqa         %%T1, [rsp + TMP3]
        vmovdqa         %%T5, [%%GDATA + HashKeyK_6]
        vmovdqa         %%T6, [%%GDATA + HashKey_6]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00          ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, %%T1, %%T5, 0x10          ; T5 = DATA_L * KK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5
        vpclmulqdq      %%T3, %%T1, %%T6, 0x01          ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, %%T1, %%T6, 0x11          ; T5 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5

                vmovdqu %%T1, [%%GDATA + 16*5]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqa         %%T1, [rsp + TMP4]
        vmovdqa         %%T5, [%%GDATA + HashKeyK_5]
        vmovdqa         %%T6, [%%GDATA + HashKey_5]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00          ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, %%T1, %%T5, 0x10          ; T5 = DATA_L * KK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5
        vpclmulqdq      %%T3, %%T1, %%T6, 0x01          ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, %%T1, %%T6, 0x11          ; T5 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5

                vmovdqu %%T1, [%%GDATA + 16*6]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqa         %%T1, [rsp + TMP5]
        vmovdqa         %%T5, [%%GDATA + HashKeyK_4]
        vmovdqa         %%T6, [%%GDATA + HashKey_4]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00          ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, %%T1, %%T5, 0x10          ; T5 = DATA_L * KK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5
        vpclmulqdq      %%T3, %%T1, %%T6, 0x01          ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, %%T1, %%T6, 0x11          ; T5 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5

                vmovdqu %%T1, [%%GDATA + 16*7]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqa         %%T1, [rsp + TMP6]
        vmovdqa         %%T5, [%%GDATA + HashKeyK_3]
        vmovdqa         %%T6, [%%GDATA + HashKey_3]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00          ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, %%T1, %%T5, 0x10          ; T5 = DATA_L * KK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5
        vpclmulqdq      %%T3, %%T1, %%T6, 0x01          ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, %%T1, %%T6, 0x11          ; T5 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5

                vmovdqu %%T1, [%%GDATA + 16*8]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqa         %%T1, [rsp + TMP7]
        vmovdqa         %%T5, [%%GDATA + HashKeyK_2]
        vmovdqa         %%T6, [%%GDATA + HashKey_2]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00          ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, %%T1, %%T5, 0x10          ; T5 = DATA_L * KK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5
        vpclmulqdq      %%T3, %%T1, %%T6, 0x01          ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, %%T1, %%T6, 0x11          ; T5 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5

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

        vmovdqa         %%T1, [rsp + TMP8]
        vmovdqa         %%T5, [%%GDATA + HashKeyK_1]
        vmovdqa         %%T6, [%%GDATA + HashKey_1]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00          ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T5, %%T1, %%T5, 0x10          ; T5 = DATA_L * KK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5
        vpclmulqdq      %%T3, %%T1, %%T6, 0x01          ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T5, %%T1, %%T6, 0x11          ; T5 = DATA_H * HK_H
        vpxor           %%T7, %%T7, %%T3
        vpxor           %%T4, %%T4, %%T5

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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; product in %%T4:%%T7

%assign i 0
%assign j 1
%rep 8

%assign skip_load_and_xor 0
%ifnidn %%FULL_PARTIAL, full
%if i >= 7
;; if partial case and dealing with the last block then skip load and xor
%assign skip_load_and_xor 1
%endif
%endif

%if skip_load_and_xor == 0
                VXLDR           %%T2, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*i]
%endif
                vaesenclast     reg(j), reg(j), %%T5
%if skip_load_and_xor == 0
                vpxor           reg(j), reg(j), %%T2
%ifidn %%ENC_DEC, DEC
%if i == 0
                vmovdqa         %%T6, %%T2
%else
                vmovdqa         [rsp + TMP %+ j], %%T2
%endif ; i
%endif ; DEC
%endif ; skip_load_and_xor

%assign i (i + 1)
%assign j (j + 1)
%endrep

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction T7(low):T4(high), result in %%T1
        vpclmulqdq      %%T1, %%T7, [rel POLY], 0x10
        vpshufd         %%T5, %%T7, 01001110b
        vpxor           %%T1, %%T1, %%T4
        vpxor           %%T1, %%T1, %%T5
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i 0
%assign j 1
%rep 8
%assign skip_store 0
%ifnidn %%FULL_PARTIAL, full
%if i >= 7
;; if partial case and dealing with the last block then skip store
%assign skip_store 1
%endif
%endif

%if skip_store == 0
                VXSTR           [%%CIPH_PLAIN_OUT + %%DATA_OFFSET + 16*i], reg(j)
%ifidn %%ENC_DEC, DEC
%if i == 0
                vmovdqa         reg(j), %%T6
%else
                vmovdqa         reg(j), [rsp + TMP %+ j]
%endif ; i
%endif ; DEC
%endif ; skip_store

%assign i (i + 1)
%assign j (j + 1)
%endrep

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

        vmovdqa         %%T5, [%%GDATA + HashKeyK_8]
        vmovdqa         %%T6, [%%GDATA + HashKey_8]
        vpclmulqdq      %%T1, %%XMM1, %%T5, 0x00        ; T1 = DATA_L * KK_L
        vpclmulqdq      %%T2, %%XMM1, %%T5, 0x10        ; T2 = DATA_L * KK_H
        vpclmulqdq      %%T3, %%XMM1, %%T6, 0x01        ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T4, %%XMM1, %%T6, 0x11        ; T4 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T2, %%T2, %%T4                ; T2 += T4

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%assign k 7
%assign i 2
%rep 7
        vmovdqa         %%T5, [%%GDATA + HashKeyK_ %+ k]
        vmovdqa         %%T6, [%%GDATA + HashKey_ %+ k]
        vpclmulqdq      %%T3, %%XMM %+ i, %%T5, 0x00    ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T4, %%XMM %+ i, %%T5, 0x10    ; T4 = DATA_L * KK_H
        vpclmulqdq      %%T5, %%XMM %+ i, %%T6, 0x01    ; T5 = DATA_H * HK_L
        vpclmulqdq      %%T6, %%XMM %+ i, %%T6, 0x11    ; T6 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T2, %%T2, %%T4                ; T2 += T4
        vpxor           %%T1, %%T1, %%T5                ; T1 += T5
        vpxor           %%T2, %%T2, %%T6                ; T2 += T6

%assign k (k - 1)
%assign i (i + 1)
%endrep

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction T1(low):T2(high), result in %%T6
        vpclmulqdq      %%T6, %%T1, [rel POLY], 0x10
        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T6, %%T6, %%T2
        vpxor           %%T6, %%T6, %%T3
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


        vmovdqa         %%T5, [%%GDATA + HashKeyK_7]
        vmovdqa         %%T6, [%%GDATA + HashKey_7]
        vpclmulqdq      %%T1, %%XMM1, %%T5, 0x00        ; T1 = DATA_L * KK_L
        vpclmulqdq      %%T2, %%XMM1, %%T5, 0x10        ; T2 = DATA_L * KK_H
        vpclmulqdq      %%T3, %%XMM1, %%T6, 0x01        ; T3 = DATA_H * HK_L
        vpclmulqdq      %%T4, %%XMM1, %%T6, 0x11        ; T4 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T2, %%T2, %%T4                ; T2 += T4

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%assign k 6
%assign i 2
%rep 6
        vmovdqa         %%T5, [%%GDATA + HashKeyK_ %+ k]
        vmovdqa         %%T6, [%%GDATA + HashKey_ %+ k]
        vpclmulqdq      %%T3, %%XMM %+ i, %%T5, 0x00    ; T3 = DATA_L * KK_L
        vpclmulqdq      %%T4, %%XMM %+ i, %%T5, 0x10    ; T4 = DATA_L * KK_H
        vpclmulqdq      %%T5, %%XMM %+ i, %%T6, 0x01    ; T5 = DATA_H * HK_L
        vpclmulqdq      %%T6, %%XMM %+ i, %%T6, 0x11    ; T6 = DATA_H * HK_H
        vpxor           %%T1, %%T1, %%T3                ; T1 += T3
        vpxor           %%T2, %%T2, %%T4                ; T2 += T4
        vpxor           %%T1, %%T1, %%T5                ; T1 += T5
        vpxor           %%T2, %%T2, %%T6                ; T2 += T6

%assign k (k - 1)
%assign i (i + 1)
%endrep

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction T1(low):T2(high), result in %%T6
        vpclmulqdq      %%T6, %%T1, [rel POLY], 0x10
        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T6, %%T6, %%T2
        vpxor           %%T6, %%T6, %%T3
%endmacro

;;; Handle encryption of the final partial block
;;; IN:
;;;   r13  - Number of bytes to read
;;; MODIFIES:
;;;   KEY  - Key for encrypting the partial block
;;;   HASH - Current hash value
;;; SMASHES:
;;;   r10, r12, r15, rax
;;;   T1, T2
;;; Note AVX2:
;;;   PLAIN_CIPH_LEN, %7, is passed only to determine
;;;   if buffer is big enough to do a 16 byte read & shift.
;;;     'LT16' is passed here only if buffer is known to be smaller
;;;     than 16 bytes.
;;;     Any other value passed here will result in 16 byte read
;;;     code path.
;;; Note AVX512:
;;;   PLAIN_CIPH_LEN and T2 are unused at this stage.
%macro  ENCRYPT_FINAL_PARTIAL_BLOCK 8
%define %%KEY             %1
%define %%T1              %2
%define %%T2              %3
%define %%CIPH_PLAIN_OUT  %4
%define %%PLAIN_CIPH_IN   %5
%define %%PLAIN_CIPH_LEN  %6
%define %%ENC_DEC         %7
%define %%DATA_OFFSET     %8

%ifdef IS_AVX2_GCM

        ;; NOTE: type of read tuned based %%PLAIN_CIPH_LEN setting
%ifidn %%PLAIN_CIPH_LEN, LT16
        ;; Handle the case where the message is < 16 bytes
        lea      r10, [%%PLAIN_CIPH_IN + %%DATA_OFFSET]

        ;; T1            - packed output
        ;; r10           - input data address
        ;; r13           - input data length
        ;; r12, r15, rax - temp registers
        READ_SMALL_DATA_INPUT_AVX   %%T1, r10, r13, r12

        lea      r12, [SHIFT_MASK + 16]
        sub      r12, r13
%else
        ;; Handle the case where the message is >= 16 bytes
        sub      %%DATA_OFFSET, 16
        add      %%DATA_OFFSET, r13
        ;; Receive the last <16 Byte block
        vmovdqu  %%T1, [%%PLAIN_CIPH_IN+%%DATA_OFFSET]
        sub      %%DATA_OFFSET, r13
        add      %%DATA_OFFSET, 16

        lea      r12, [SHIFT_MASK + 16]
        ;; Adjust the shuffle mask pointer to be able to shift 16-r13 bytes
        ;; (r13 is the number of bytes in plaintext mod 16)
        sub      r12, r13
        ;; Get the appropriate shuffle mask
        vmovdqu  %%T2, [r12]
        ;; shift right 16-r13 bytes
        vpshufb  %%T1, %%T2
%endif                          ; %%PLAIN_CIPH_LEN, LT16

        ;; At this point T1 contains the partial block data
%ifidn  %%ENC_DEC, DEC
        ;; Plaintext XOR E(K, Yn)
        ;; Set aside the ciphertext
        vmovdqa  %%T2, %%T1
        vpxor    %%KEY, %%KEY, %%T1
        ;; Get the appropriate mask to mask out top 16-r13 bytes of ciphertext
        vmovdqu  %%T1, [r12 + ALL_F - SHIFT_MASK]
        ;; Mask out top 16-r13 bytes of ciphertext
        vpand    %%KEY, %%KEY, %%T1

        ;; Prepare the ciphertext for the hash
        ;; mask out top 16-r13 bytes of the plaintext
        vpand    %%T2, %%T2, %%T1
%else
        ;; Plaintext XOR E(K, Yn)
        vpxor    %%KEY, %%KEY, %%T1
        ;; Get the appropriate mask to mask out top 16-r13 bytes of %%KEY
        vmovdqu  %%T1, [r12 + ALL_F - SHIFT_MASK]
        ;; Mask out top 16-r13 bytes of %%KEY
        vpand    %%KEY, %%KEY, %%T1
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; Output r13 Bytes
        vmovdqa         %%T1, %%KEY
        simd_store_avx  %%CIPH_PLAIN_OUT, %%T1, r13, rax, r12, %%DATA_OFFSET
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifidn  %%ENC_DEC, DEC
        ;; If decrypt, restore the ciphertext into %%KEY
        vmovdqa %%KEY, %%T2
%endif

%else ;; IS_AVX512_GCM

        ;; %%PLAIN_CIPH_IN + %%DATA_OFFSET
        ;;               - input data address
        ;; r13           - input data length
        ;; rax           - temp registers
        ;; out:
        ;; T1            - packed output
        ;; k1            - valid byte mask
        READ_SMALL_DATA_INPUT_AVX512   %%T1, {%%PLAIN_CIPH_IN + %%DATA_OFFSET}, r13, rax, k1

        ;; At this point T1 contains the partial block data
        ;; Plaintext XOR E(K, Yn)
        vpxorq          %%KEY, %%KEY, %%T1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; Output r13 Bytes
        vmovdqu8        [%%CIPH_PLAIN_OUT + %%DATA_OFFSET]{k1}, %%KEY

%ifidn  %%ENC_DEC, DEC
        ;; If decrypt, restore the ciphertext into %%KEY
        vmovdqa64       %%KEY, %%T1
%else
        vmovdqu8        %%KEY{k1}{z}, %%KEY
%endif

%endif ;; IS_AVX512_GCM

%endmacro                       ; ENCRYPT_FINAL_PARTIAL_BLOCK

; Encryption of a single block
%macro  ENCRYPT_SINGLE_BLOCK 2
%define %%GDATA %1
%define %%XMM0  %2

                vpxor    %%XMM0, %%XMM0, [%%GDATA+16*0]
%assign i 1
%rep NROUNDS
                vaesenc  %%XMM0, [%%GDATA+16*i]
%assign i (i+1)
%endrep
                vaesenclast      %%XMM0, [%%GDATA+16*i]
%endmacro

;; Start of Stack Setup

%macro FUNC_SAVE 0-1
	;; Required for Update/GCM_ENC
        mov     rax, rsp

%if %0 == 0
	sub     rsp, VARIABLE_OFFSET
%else
%ifidni %1, alloc_context
        sub     rsp, VARIABLE_OFFSET + CONTEXT_SIZE
%endif
%endif
	and     rsp, ~63

        mov     [rsp + GP_OFFSET + 0*8], rax ; original rsp pointer
        mov     [rsp + GP_OFFSET + 1*8], r12
        mov     [rsp + GP_OFFSET + 2*8], r13
        mov     [rsp + GP_OFFSET + 3*8], r14
        mov     [rsp + GP_OFFSET + 4*8], r15

        mov     r14, rax

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        vmovdqu [rsp + LOCAL_STORAGE + 0*16], xmm6
        vmovdqu [rsp + LOCAL_STORAGE + 1*16], xmm7
        vmovdqu [rsp + LOCAL_STORAGE + 2*16], xmm8
        vmovdqu [rsp + LOCAL_STORAGE + 3*16], xmm9
        vmovdqu [rsp + LOCAL_STORAGE + 4*16], xmm10
        vmovdqu [rsp + LOCAL_STORAGE + 5*16], xmm11
        vmovdqu [rsp + LOCAL_STORAGE + 6*16], xmm12
        vmovdqu [rsp + LOCAL_STORAGE + 7*16], xmm13
        vmovdqu [rsp + LOCAL_STORAGE + 8*16], xmm14
        vmovdqu [rsp + LOCAL_STORAGE + 9*16], xmm15
%endif
%endmacro

%macro FUNC_RESTORE 0

%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif
%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm15, [rsp + LOCAL_STORAGE + 9*16]
        vmovdqu xmm14, [rsp + LOCAL_STORAGE + 8*16]
        vmovdqu xmm13, [rsp + LOCAL_STORAGE + 7*16]
        vmovdqu xmm12, [rsp + LOCAL_STORAGE + 6*16]
        vmovdqu xmm11, [rsp + LOCAL_STORAGE + 5*16]
        vmovdqu xmm10, [rsp + LOCAL_STORAGE + 4*16]
        vmovdqu xmm9,  [rsp + LOCAL_STORAGE + 3*16]
        vmovdqu xmm8,  [rsp + LOCAL_STORAGE + 2*16]
        vmovdqu xmm7,  [rsp + LOCAL_STORAGE + 1*16]
        vmovdqu xmm6,  [rsp + LOCAL_STORAGE + 0*16]
%endif

        ;; Required for Update/GCM_ENC
        mov     r12, [rsp + GP_OFFSET + 1*8]
        mov     r13, [rsp + GP_OFFSET + 2*8]
        mov     r14, [rsp + GP_OFFSET + 3*8]
        mov     r15, [rsp + GP_OFFSET + 4*8]
        mov     rsp, [rsp + GP_OFFSET + 0*8]
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%macro CALC_J0 3
%define %%KEY           %1 ;; [in] Pointer to GCM KEY structure
%define %%IV            %2 ;; [in] Pointer to IV
%define %%IV_LEN        %3 ;; [in] IV length

%define %%J0            xmm0 ;; [out] XMM reg to contain J0

%define %%XTMP0         xmm1 ;; [clobbered] Temporary XMM reg
%define %%XTMP1         xmm2 ;; [clobbered] Temporary XMM reg
%define %%XTMP2         xmm3 ;; [clobbered] Temporary XMM reg
%define %%XTMP3         xmm4 ;; [clobbered] Temporary XMM reg
%define %%XTMP4         xmm5 ;; [clobbered] Temporary XMM reg
%define %%XTMP5         xmm6 ;; [clobbered] Temporary XMM reg

        ;; J0 = GHASH(IV || 0s+64 || len(IV)64)
        ;; s = 16 * RoundUp(len(IV)/16) -  len(IV) */

        ;; Calculate GHASH of (IV || 0s)
        vpxor   %%J0, %%J0, %%J0
        ;; arg1 = key pointer
        mov     r12, %%IV
        mov     r13, %%IV_LEN
        call    ghash_internal_avx_gen4

        ;; Calculate GHASH of last 16-byte block (0 || len(IV)64)
        vmovq   %%XTMP2, %%IV_LEN
        vpsllq  %%XTMP2, %%XTMP2, 3     ;; IV length in bits
        vmovdqu %%XTMP0, [%%KEY + HashKey_1]
        vmovdqu %%XTMP1, [%%KEY + HashKeyK_1]
        vpxor   %%J0, %%J0, %%XTMP2
        GHASH_MUL2 %%J0, %%XTMP0, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5

        vpshufb %%J0, %%J0, [rel SHUF_MASK] ; perform a 16Byte swap
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_INIT initializes a gcm_context_data struct to prepare for encoding/decoding.
; Input: gcm_key_data * (GDATA_KEY), gcm_context_data *(GDATA_CTX), IV, IV_LEN,
; Additional Authentication data (A_IN), Additional Data length (A_LEN).
; Output: Updated GDATA_CTX with the hash of A_IN (AadHash=xmm14) and
;         initialized other parts of GDATA.
;         xmm2 - holds counter block (LE format)
; Clobbers: rax, r10-r13 and xmm0-xmm6
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_INIT        5-6
%define %%GDATA_KEY     %1      ; [in] GCM expanded keys pointer
%define %%GDATA_CTX     %2      ; [in] GCM context pointer
%define %%IV            %3      ; [in] IV pointer
%define %%A_IN          %4      ; [in] AAD pointer
%define %%A_LEN         %5      ; [in] AAD length in bytes
%define %%IV_LEN        %6      ; [in] IV length

%define %%GPR1          r10     ; temp GPR
%define %%GPR2          r11     ; temp GPR
%define %%GPR3          rax     ; temp GPR

%define %%AAD_HASH      xmm14

        ;; IV may be different than 12 bytes
        cmp     %%A_LEN, 12
        je      %%_aad_len_is_12

        vpxor   %%AAD_HASH, %%AAD_HASH, %%AAD_HASH
        CALC_AAD_HASH %%A_IN, %%A_LEN, %%AAD_HASH, %%GDATA_KEY, \
                      xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, %%GPR1, %%GPR2, %%GPR3
        jmp     %%_aad_is_done

%%_aad_len_is_12:
        ;; GHASH 12 bytes of AAD
        mov     %%GPR1, %%A_IN
        vmovq   %%AAD_HASH, [%%GPR1]
        vpinsrd %%AAD_HASH, [%%GPR1 + 8], 2
        vmovdqa xmm1, [%%GDATA_KEY + HashKey_1]
        vmovdqa xmm2, [%%GDATA_KEY + HashKey_1 + HKeyGap]
        vpshufb %%AAD_HASH, %%AAD_HASH, [rel SHUF_MASK]

        GHASH_MUL2 %%AAD_HASH, xmm1, xmm2, xmm6, xmm5, xmm4, xmm3

%%_aad_is_done:
        mov     %%GPR1, %%A_LEN
        vmovdqu [%%GDATA_CTX + AadHash], %%AAD_HASH         ; ctx_data.aad hash = aad_hash
        mov     [%%GDATA_CTX + AadLen], %%GPR1              ; ctx_data.aad_length = aad_length

        xor     %%GPR1, %%GPR1
        mov     [%%GDATA_CTX + InLen], %%GPR1               ; ctx_data.in_length = 0
        mov     [%%GDATA_CTX + PBlockLen], %%GPR1           ; ctx_data.partial_block_length = 0

%if %0 == 6
        ;; IV may be different than 12 bytes
        cmp     %%IV_LEN, 12
        je      %%_iv_len_is_12

        ;; uses xmm0-xmm6, r10-r13, rax
        CALC_J0 %%GDATA_KEY, %%IV, %%IV_LEN
        jmp     %%_iv_is_done

%%_iv_len_is_12:
%endif

        ;; IV is 12 bytes
        ;; read 12 IV bytes and pad with 0x00000001
        mov     %%GPR2, %%IV
        vmovq   xmm0, [%%GPR2]
        vpinsrd xmm0, [%%GPR2 + 8], 2
        vpinsrd xmm0, [rel ONEf + 12], 3                   ; read 12 IV bytes and pad with 0x00000001

%%_iv_is_done:
        vmovdqu [%%GDATA_CTX + OrigIV], xmm0                ; ctx_data.orig_IV = iv

        ;; store IV as counter in LE format
        vpshufb xmm2, xmm0, [rel SHUF_MASK]
        vmovdqu [%%GDATA_CTX + CurCount], xmm2              ; ctx_data.current_counter = iv
        ;; @note: xmm2 - needs to return counter block
%endmacro

%macro  GCM_ENC_DEC_SMALL   12
%define %%GDATA_KEY         %1
%define %%GDATA_CTX         %2
%define %%CIPH_PLAIN_OUT    %3
%define %%PLAIN_CIPH_IN     %4
%define %%PLAIN_CIPH_LEN    %5
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
        cmp     %%NUM_BLOCKS, 7
        je      %%_small_initial_num_blocks_is_7
        ja      %%_small_initial_num_blocks_is_8
        cmp     %%NUM_BLOCKS, 5
        je      %%_small_initial_num_blocks_is_5
        ja      %%_small_initial_num_blocks_is_6
        cmp     %%NUM_BLOCKS, 3
        je      %%_small_initial_num_blocks_is_3
        ja      %%_small_initial_num_blocks_is_4
        cmp     %%NUM_BLOCKS, 2
        je      %%_small_initial_num_blocks_is_2

        jmp     %%_small_initial_num_blocks_is_1

%%_small_initial_num_blocks_is_8:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 8, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_7:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 7, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_6:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 6, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_5:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 5, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_4:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 4, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_3:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 3, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_2:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 2, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_1:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 1, \
                xmm12, xmm13, %%HASH_OUT, xmm15, xmm11, %%CTR, \
                xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, \
                xmm10, xmm0, %%ENC_DEC, %%INSTANCE_TYPE
%%_small_initial_blocks_encrypted:

        ;; Note: zero initial blocks not allowed.

%endmacro                       ; GCM_ENC_DEC_SMALL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_ENC_DEC Encodes/Decodes given data. Assumes that the passed gcm_context_data struct
; has been initialized by GCM_INIT
; Requires the input data be at least 1 byte long because of READ_SMALL_INPUT_DATA.
; Input: gcm_key_data struct* (GDATA_KEY), gcm_context_data *(GDATA_CTX), input text (PLAIN_CIPH_IN),
; input text length (PLAIN_CIPH_LEN) and whether encoding or decoding (ENC_DEC).
; Output: A cipher of the given plain text (CIPH_PLAIN_OUT), and updated GDATA_CTX
; Clobbers rax, r10-r15, and xmm0-xmm15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_ENC_DEC         7
%define %%GDATA_KEY         %1
%define %%GDATA_CTX         %2
%define %%CIPH_PLAIN_OUT    %3
%define %%PLAIN_CIPH_IN     %4
%define %%PLAIN_CIPH_LEN    %5
%define %%ENC_DEC           %6
%define %%INSTANCE_TYPE     %7
%define %%DATA_OFFSET       r11

; Macro flow:
; calculate the number of 16byte blocks in the message
; process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
; process 8 16 byte blocks at a time until all are done '%%_encrypt_by_8_new .. %%_eight_cipher_left'
; if there is a block of less than 16 bytes process it '%%_zero_cipher_left .. %%_multiple_of_16_bytes'

%ifidn __OUTPUT_FORMAT__, win64
        cmp     %%PLAIN_CIPH_LEN, 0
%else
        or      %%PLAIN_CIPH_LEN, %%PLAIN_CIPH_LEN
%endif
        je      %%_enc_dec_done

        xor     %%DATA_OFFSET, %%DATA_OFFSET
        ;; Update length of data processed
%ifidn __OUTPUT_FORMAT__, win64
        mov     rax, %%PLAIN_CIPH_LEN
       	add     [%%GDATA_CTX + InLen], rax
%else
        add    [%%GDATA_CTX + InLen], %%PLAIN_CIPH_LEN
%endif
        vmovdqu xmm8, [%%GDATA_CTX + AadHash]

%ifidn %%INSTANCE_TYPE, multi_call
        ;; NOTE: partial block processing makes only sense for multi_call here.
        ;; Used for the update flow - if there was a previous partial
        ;; block fill the remaining bytes here.
        PARTIAL_BLOCK %%GDATA_CTX, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%PLAIN_CIPH_LEN, %%DATA_OFFSET, xmm8, %%GDATA_KEY, %%ENC_DEC
%endif

        ;;  lift CTR set from initial_blocks to here
%ifidn %%INSTANCE_TYPE, single_call
        vmovdqa xmm9, xmm2
%else
        vmovdqu xmm9, [%%GDATA_CTX + CurCount]
%endif

        ;; Save the amount of data left to process in r10
        mov     r13, %%PLAIN_CIPH_LEN
%ifidn %%INSTANCE_TYPE, multi_call
        ;; NOTE: %%DATA_OFFSET is zero in single_call case.
        ;;      Consequently PLAIN_CIPH_LEN will never be zero after
        ;;      %%DATA_OFFSET subtraction below.
        sub     r13, %%DATA_OFFSET

        ;; There may be no more data if it was consumed in the partial block.
        or      r13, r13
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

        GCM_ENC_DEC_SMALL %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%PLAIN_CIPH_LEN, %%ENC_DEC, %%DATA_OFFSET, r13, r12, xmm9, xmm14, %%INSTANCE_TYPE
        jmp     %%_ghash_done

%%_large_message_path:
        and     r12, 0x7    ; Still, don't allow 8 INITIAL blocks since this will
                            ; can be handled by the x8 partial loop.

        je      %%_initial_num_blocks_is_0
        cmp     r12, 6
        ja      %%_initial_num_blocks_is_7
        je      %%_initial_num_blocks_is_6
        cmp     r12, 4
        ja      %%_initial_num_blocks_is_5
        je      %%_initial_num_blocks_is_4
        cmp     r12, 2
        ja      %%_initial_num_blocks_is_3
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
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 7, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_6:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 6, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_5:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 5, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_4:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 4, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_3:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 3, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_2:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 2, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_1:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 1, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_0:
        INITIAL_BLOCKS  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, r13, %%DATA_OFFSET, 0, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC

%%_initial_blocks_encrypted:
        ;; The entire message was encrypted processed in initial and now need to be hashed
        or      r13, r13
        je      %%_encrypt_done

        ;; Encrypt the final <16 byte (partial) block, then hash
        cmp     r13, 16
        jb      %%_encrypt_final_partial

        ;; Process 7 full blocks plus a partial block
        cmp     r13, 128
        jb      %%_encrypt_by_8_partial

%%_encrypt_by_8_parallel:
        ;; in_order vs. out_order is an optimization to increment the counter without shuffling
        ;; it back into little endian. r15d keeps track of when we need to increent in order so
        ;; that the carry is handled correctly.
        vmovd   r15d, xmm9
        and     r15d, 255
        vpshufb xmm9, [rel SHUF_MASK]

align 32
%%_encrypt_by_8_new:
        cmp     r15d, 255-8
        ja      %%_encrypt_by_8

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
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, out_order, %%ENC_DEC, full
        add     %%DATA_OFFSET, 128
        sub     r13, 128
        cmp     r13, 128
        jge     %%_encrypt_by_8_new

        vpshufb xmm9, [rel SHUF_MASK]
        jmp     %%_encrypt_by_8_parallel_done

align 32
%%_encrypt_by_8:
        vpshufb xmm9, [rel SHUF_MASK]
        add     r15b, 8
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, in_order, %%ENC_DEC, full
        vpshufb  xmm9, [rel SHUF_MASK]
        add     %%DATA_OFFSET, 128
        sub     r13, 128
        cmp     r13, 128
        jge     %%_encrypt_by_8_new
        vpshufb  xmm9, [rel SHUF_MASK]

%%_encrypt_by_8_parallel_done:
        ;; Test to see if we need a by 8 with partial block. At this point
        ;; bytes remaining should be either zero or between 113-127.
        or      r13, r13
        je      %%_encrypt_done

%%_encrypt_by_8_partial:
        ;; Shuffle needed to align key for partial block xor. out_order
        ;; is a little faster because it avoids extra shuffles.
        ;; TBD: Might need to account for when we don't have room to increment the counter.

        ;; Process parallel buffers with a final partial block.
        GHASH_8_ENCRYPT_8_PARALLEL  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, in_order, %%ENC_DEC, partial

        add     %%DATA_OFFSET, 128-16
        sub     r13, 128-16

%%_encrypt_final_partial:

        vpshufb  xmm8, [rel SHUF_MASK]
        mov     [%%GDATA_CTX + PBlockLen], r13
        vmovdqu [%%GDATA_CTX + PBlockEncKey], xmm8

        ;; xmm8  - Final encrypted counter - need to hash with partial or full block ciphertext
        ;;                            GDATA,  KEY,   T1,    T2
        ENCRYPT_FINAL_PARTIAL_BLOCK xmm8, xmm0, xmm10, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%PLAIN_CIPH_LEN, %%ENC_DEC, %%DATA_OFFSET

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
        or      r13, r13
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

%endmacro       ; GCM_ENC_DEC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_COMPLETE Finishes Encryption/Decryption of last partial block after GCM_UPDATE finishes.
; Input: A gcm_key_data * (GDATA_KEY), gcm_context_data (GDATA_CTX).
; Output: Authorization Tag (AUTH_TAG) and Authorization Tag length (AUTH_TAG_LEN)
; Clobbers rax, r10-r12, and xmm0-xmm2, xmm5-xmm6, xmm9-xmm11, xmm13-xmm15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_COMPLETE            5
%define %%GDATA_KEY             %1
%define %%GDATA_CTX             %2
%define %%AUTH_TAG              %3
%define %%AUTH_TAG_LEN          %4
%define %%INSTANCE_TYPE         %5
%define %%PLAIN_CIPH_LEN        rax

        vmovdqu xmm13, [%%GDATA_KEY + HashKey_1]
        vmovdqu xmm0, [%%GDATA_KEY + HashKeyK_1]
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
	or	r12, r12

	je %%_partial_done

	GHASH_MUL2 xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6 ;GHASH computation for the last <16 Byte block

%%_partial_done:

%endif

        mov     r12, [%%GDATA_CTX + AadLen]     ; r12 = aadLen (number of bytes)
        mov     %%PLAIN_CIPH_LEN, [%%GDATA_CTX + InLen]

        shl     r12, 3                      ; convert into number of bits
        vmovq   xmm15, r12                  ; len(A) in xmm15

        shl     %%PLAIN_CIPH_LEN, 3         ; len(C) in bits  (*128)
        vmovq   xmm1, %%PLAIN_CIPH_LEN
        vpslldq xmm15, xmm15, 8             ; xmm15 = len(A)|| 0x0000000000000000
        vpxor   xmm15, xmm15, xmm1          ; xmm15 = len(A)||len(C)

        vpxor   xmm14, xmm15
        GHASH_MUL2 xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6
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
        vmovq   rax, xmm9
        mov     [r10], rax
        jmp     %%_return_T_done
%%_T_12:
        vmovq   rax, xmm9
        mov     [r10], rax
        vpsrldq xmm9, xmm9, 8
        vmovd   eax, xmm9
        mov     [r10 + 8], eax
        jmp     %%_return_T_done
%%_T_16:
        vmovdqu  [r10], xmm9

%%_return_T_done:

%ifdef SAFE_DATA
        ;; Clear sensitive data from context structure
        vpxor   xmm0, xmm0
        vmovdqu [%%GDATA_CTX + AadHash], xmm0
        vmovdqu [%%GDATA_CTX + PBlockEncKey], xmm0
%endif
%endmacro ; GCM_COMPLETE

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; PARTIAL_BLOCK_GMAC: Handles the tag partial blocks between update calls.
; Requires the input data be at least 1 byte long.
; Input: gcm_context_data (GDATA_CTX), input text (PLAIN_IN), hash subkey (HASH_SUBKEY)
; input text length (PLAIN_LEN).
; Output: Updated GDATA_CTX
; Clobbers rax, r10, r12, r13, r15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PARTIAL_BLOCK_GMAC       16
%define %%GDATA_CTX             %1      ;; [in/out] GPR pointer to GCM context
%define %%PLAIN_IN              %2      ;; [in] GPR pointer to plain/cipher text
%define %%PLAIN_LEN             %3      ;; [in] text length in bytes, GPR or memory location (win64)
%define %%DATA_OFFSET           %4      ;; [out] GPR data offset
%define %%AAD_HASH              %5      ;; [in/out] xmm with hash value
%define %%HASH_SUBKEY           %6      ;; [in] hash key
%define %%HASHK_SUBKEY          %7      ;; [in] hash-K key
%define %%XMM0                  %8      ;; [clobbered] xmm register
%define %%XMM1                  %9      ;; [clobbered] xmm register
%define %%XMM2                  %10     ;; [clobbered] xmm register
%define %%XMM3                  %11     ;; [clobbered] xmm register
%define %%XMM5                  %12     ;; [clobbered] xmm register
%define %%XMM6                  %13     ;; [clobbered] xmm register
%define %%XMM9                  %14     ;; [clobbered] xmm register
%define %%XMM10                 %15     ;; [clobbered] xmm register
%define %%XMM11                 %16     ;; [clobbered] xmm register

        ;; @note PBlockLen must not be zero
        mov	r13, [%%GDATA_CTX + PBlockLen]

        ; Read in input data without over reading
%ifdef IS_AVX2_GCM
	cmp	%%PLAIN_LEN, 16
	jl	%%_fewer_than_16_bytes
        ; If more than 16 bytes of data, just fill the xmm register
	VXLDR   %%XMM1, [%%PLAIN_IN]
	jmp	%%_data_read

%%_fewer_than_16_bytes:
	lea	r10, [%%PLAIN_IN]
	READ_SMALL_DATA_INPUT_AVX	%%XMM1, r10, %%PLAIN_LEN, rax
%else
        ; Read in input data without over reading
        READ_SMALL_DATA_INPUT_LEN_BT16_AVX512	%%XMM1, %%PLAIN_IN, %%PLAIN_LEN, r12, rax, k1
%endif
        ; Finished reading in data
%%_data_read:

	lea	r12, [rel SHIFT_MASK]
        ; Adjust the shuffle mask pointer to be able to shift r13 bytes
        ; (16-r13 is the number of bytes in plaintext mod 16)
	add	r12, r13
        ; Get the appropriate shuffle mask
	vmovdqu	%%XMM2, [r12]
	vmovdqa	%%XMM3, %%XMM1

	mov	r15, %%PLAIN_LEN
	add	r15, r13
        ; Set r15 to be the amount of data left in PLAIN_IN after filling the block
	sub	r15, 16
        ; Determine if partial block is not being filled and shift mask accordingly
	jge	%%_no_extra_mask_1
	sub	r12, r15
%%_no_extra_mask_1:

        ; Get the appropriate mask to mask out bottom r13 bytes of %%XMM3
	vmovdqu	%%XMM1, [r12 + ALL_F-SHIFT_MASK]

	vpand	%%XMM3, %%XMM3, %%XMM1
	vpshufb	%%XMM3, %%XMM3, [rel SHUF_MASK]
	vpshufb	%%XMM3, %%XMM3, %%XMM2
	vpxor	%%AAD_HASH, %%AAD_HASH, %%XMM3

	cmp	r15, 0
	jl	%%_partial_incomplete_1

        ; GHASH computation for the last <16 Byte block
	GHASH_MUL2      %%AAD_HASH, %%HASH_SUBKEY, %%HASHK_SUBKEY, %%XMM0, %%XMM10, %%XMM11, %%XMM5
	xor	rax, rax
	mov	[%%GDATA_CTX + PBlockLen], rax
	jmp	%%_ghash_done
%%_partial_incomplete_1:
%ifidn __OUTPUT_FORMAT__, win64
        mov     rax, %%PLAIN_LEN
        add     [%%GDATA_CTX + PBlockLen], rax
%else
        add     [%%GDATA_CTX + PBlockLen], %%PLAIN_LEN
%endif
%%_ghash_done:
	vmovdqu	[%%GDATA_CTX + AadHash], %%AAD_HASH

        or      r15, r15
        jl      %%_partial_fill

        mov     r12, 16
        ; Set r12 to be the number of bytes to skip after this macro
        sub     r12, r13

        jmp     %%offset_set
%%_partial_fill:
        mov     r12, %%PLAIN_LEN
%%offset_set:
        mov     %%DATA_OFFSET, r12

%endmacro ; PARTIAL_BLOCK_GMAC
