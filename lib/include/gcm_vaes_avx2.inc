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
; TLen (tag length):
;       from the definition of the spec, TLen can only be 8, 12 or 16 bytes.
;       The code additionally supports any tag length.
;
; poly = x^128 + x^127 + x^126 + x^121 + 1
; throughout the code, one tab and two tab indentations are used. one tab is for GHASH part, two tabs is for AES part.
;

%use smartalign
alignmode nop

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/aes_common.inc"
%include "include/gcm_context.inc"
%include "include/gcm_defines.inc"
%include "include/gcm_keys_vaes_avx2.inc"
%include "include/gcm_common.inc"
%include "include/memcpy.inc"
%include "include/cet.inc"
%include "include/error.inc"
%include "include/imb_job.inc"
%include "include/gcm_data_vaes_avx2.inc"
%include "include/align_avx.inc"

%ifndef GHASH_API_IMPLEMENTATION
extern ghash_1_vaes_avx2
extern ghash_2_vaes_avx2
extern ghash_3_vaes_avx2
extern ghash_4_vaes_avx2
extern ghash_5_vaes_avx2
extern ghash_6_vaes_avx2
extern ghash_7_vaes_avx2
extern ghash_8_vaes_avx2
extern ghash_9_vaes_avx2
extern ghash_10_vaes_avx2
extern ghash_11_vaes_avx2
extern ghash_12_vaes_avx2
extern ghash_13_vaes_avx2
extern ghash_14_vaes_avx2
extern ghash_15_vaes_avx2
extern ghash_16_vaes_avx2
%endif

%ifndef GCM_UTIL_IMPLEMENTATION
extern gcm_enc_final_partial_block_vaes_avx2
extern gcm_dec_final_partial_block_vaes_avx2
extern gcm_initial_blocks_enc_vaes_avx2
extern gcm_initial_blocks_dec_vaes_avx2
extern gcm_aes_ctr_1_vaes_avx2
extern gcm_aes_ctr_2_vaes_avx2
extern gcm_aes_ctr_3_vaes_avx2
extern gcm_aes_ctr_4_vaes_avx2
extern gcm_aes_ctr_5_vaes_avx2
extern gcm_aes_ctr_6_vaes_avx2
extern gcm_aes_ctr_7_vaes_avx2
extern gcm_aes_ctr_8_vaes_avx2
extern gcm_aes_ctr_9_vaes_avx2
extern gcm_aes_ctr_10_vaes_avx2
extern gcm_aes_ctr_11_vaes_avx2
extern gcm_aes_ctr_12_vaes_avx2
extern gcm_aes_ctr_13_vaes_avx2
extern gcm_aes_ctr_14_vaes_avx2
extern gcm_aes_ctr_15_vaes_avx2
extern gcm_aes_ctr_16_vaes_avx2
%endif

%ifndef GCM128_MODE
%ifndef GCM192_MODE
%ifndef GCM256_MODE
%error "No GCM mode selected for gcm_vaes_avx2.inc!"
%endif
%endif
%endif

;; Decide on AES-GCM key size to compile for
%ifdef GCM128_MODE
%define NROUNDS 9
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _128 %+ y %+ vaes_avx2
%define GMAC_FN_NAME(x) imb_aes_gmac_ %+ x %+ _128_ %+ vaes_avx2
%endif

%ifdef GCM192_MODE
%define NROUNDS 11
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _192 %+ y %+ vaes_avx2
%define GMAC_FN_NAME(x) imb_aes_gmac_ %+ x %+ _192_ %+ vaes_avx2
%endif

%ifdef GCM256_MODE
%define NROUNDS 13
%define FN_NAME(x,y) aes_gcm_ %+ x %+ _256 %+ y %+ vaes_avx2
%define GMAC_FN_NAME(x) imb_aes_gmac_ %+ x %+ _256_ %+ vaes_avx2
%endif

%define TMP1    16*0    ; Temporary storage for AES State 1
%define TMP2    16*1    ; Temporary storage for AES State 2
%define TMP3    16*2    ; Temporary storage for AES State 3
%define TMP4    16*3    ; Temporary storage for AES State 4
%define TMP5    16*4    ; Temporary storage for AES State 5
%define TMP6    16*5    ; Temporary storage for AES State 6
%define TMP7    16*6    ; Temporary storage for AES State 7
%define TMP8    16*7    ; Temporary storage for AES State 8
%define TMP9    16*8    ; Temporary storage for AES State 9
%define TMP10   16*9    ; Temporary storage for AES State 10
%define TMP11   16*10   ; Temporary storage for AES State 11
%define TMP12   16*11   ; Temporary storage for AES State 12
%define TMP13   16*12   ; Temporary storage for AES State 13
%define TMP14   16*13   ; Temporary storage for AES State 14
%define TMP15   16*14   ; Temporary storage for AES State 15
%define TMP16   16*15   ; Temporary storage for AES State 16

; need to store 5 GP registers on stack (align to 16 bytes)
; @note: the last 8-byte slot is used in JOB API to save/restore a register
%define GP_STORAGE 8*6

%define LOCAL_STORAGE   16*16

%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     16*10
%else
        %define XMM_STORAGE     0
%endif

%define GP_OFFSET (LOCAL_STORAGE + XMM_STORAGE)

%define VARIABLE_OFFSET (GP_STORAGE + LOCAL_STORAGE + XMM_STORAGE)

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
;;; Carry out four multiplications first, to achieve partially reduced product
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
%rep 15
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
; CALC_AAD_HASH: Calculates the hash of the data which will not be encrypted.
; Input: The input data (A_IN), that data's length (A_LEN), and the hash key (HASH_KEY).
; Output: The hash of the data (AAD_HASH).
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  CALC_AAD_HASH   13
%define %%A_IN          %1      ;; [in] message pointer
%define %%A_LEN         %2      ;; [in] message length
%define %%AAD_HASH      %3      ;; [in] input hash value (XMM)
%define %%GDATA_KEY     %4      ;; [in] pointer to GCM key data
%define %%XT0           %5      ;; [clobbered] temporary XMM
%define %%XT1           %6      ;; [clobbered] temporary XMM
%define %%XT2           %7      ;; [clobbered] temporary XMM
%define %%XT3           %8      ;; [clobbered] temporary XMM
%define %%XT4           %9      ;; [clobbered] temporary XMM
%define %%XT5           %10     ;; [clobbered] temporary XMM
%define %%T1            %11     ;; [clobbered] temporary GP register
%define %%T2            %12     ;; [clobbered] temporary GP register
%define %%T3            %13     ;; [clobbered] temporary GP register

%xdefine %%YT0 YWORD(%%XT0)
%xdefine %%YT1 YWORD(%%XT1)
%xdefine %%YT2 YWORD(%%XT2)
%xdefine %%YT3 YWORD(%%XT3)
%xdefine %%YT4 YWORD(%%XT4)
%xdefine %%YT5 YWORD(%%XT5)

%xdefine %%XSTATE_00 %%XT4
%xdefine %%XSTATE_11 %%XT5

%xdefine %%STATE_00 %%YT4
%xdefine %%STATE_11 %%YT5

%xdefine %%YHASH YWORD(%%AAD_HASH)
%xdefine %%XHASH %%AAD_HASH

        mov             %%T1, %%A_IN            ; T1 = AAD
        mov             %%T2, %%A_LEN           ; T2 = aadLen

        cmp             %%T2, 256
        jb              %%_AAD_below_256

align_loop
%%_get_AAD_loop256:

        vmovdqu         %%YT0, [%%T1 + 16*0]
        vpshufb         %%YT0, %%YT0, [rel SHUF_MASK]
        vpxor           %%YT0, %%YT0, %%YHASH

        vmovdqu         %%YT1, [%%GDATA_KEY + HashKeyK_16]
        vpclmulqdq      %%STATE_00, %%YT0, %%YT1, 0x00          ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%STATE_11, %%YT0, %%YT1, 0x10          ; STATE_11 = DATA_L * KK_H
        vmovdqu         %%YT1, [%%GDATA_KEY + HashKey_16]
        vpclmulqdq      %%YT2, %%YT0, %%YT1, 0x01               ; YT2 = DATA_H * HK_L
        vpclmulqdq      %%YT3, %%YT0, %%YT1, 0x11               ; YT3 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3

%assign i 2
%assign j 14
%rep 7
        vmovdqu         %%YT0, [%%T1 + 16*i]
        vpshufb         %%YT0, %%YT0, [rel SHUF_MASK]

        vmovdqu         %%YT1, [%%GDATA_KEY + HashKeyK_ %+ j]
        vpclmulqdq      %%YT2, %%YT0, %%YT1, 0x00               ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%YT3, %%YT0, %%YT1, 0x10               ; STATE_11 = DATA_L * KK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3
        vmovdqu         %%YT1, [%%GDATA_KEY + HashKey_ %+ j]
        vpclmulqdq      %%YT2, %%YT0, %%YT1, 0x01               ; YT2 = DATA_H * HK_L
        vpclmulqdq      %%YT3, %%YT0, %%YT1, 0x11               ; YT3 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3
%assign i (i + 2)
%assign j (j - 2)
%endrep

        ;; combine 2x128-bits hash states into 128-bit hash state
        vextracti128    %%XT0, %%STATE_00, 1
        vextracti128    %%XT1, %%STATE_11, 1
        vpxor           %%XSTATE_00, %%XSTATE_00, %%XT0
        vpxor           %%XSTATE_11, %%XSTATE_11, %%XT1

        ;; new reduction
        vpclmulqdq      %%XHASH, %%XSTATE_00, [rel POLY], 0x10
        vpshufd         %%XT0, %%XSTATE_00, 01001110b
        vpxor           %%XHASH, %%XHASH, %%XSTATE_11
        vpxor           %%XHASH, %%XHASH, %%XT0

        add             %%T1, 256
        sub             %%T2, 256
        je              %%_CALC_AAD_done
        cmp             %%T2, 256
        jae             %%_get_AAD_loop256

align_label
%%_AAD_below_256:
        cmp             DWORD(%%T2), 16
        jb              %%_AAD_partial_block

        cmp             DWORD(%%T2), 32
        jb              %%_AAD_1_full_block_left

        ;; calculate hash_key position to start with
        mov             %%T3, %%T2
        and             %%T3, -16       ; 1 to 15 blocks possible here
        neg             %%T3
        add             %%T3, HashKey_1 + 16
        lea             %%T3, [%%GDATA_KEY + %%T3]

%assign gh_offset (HashKeyK_1 - HashKey_1)
        vmovdqu         %%YT0, [%%T1]
        vpshufb         %%YT0, %%YT0, [rel SHUF_MASK]
        vpxor           %%YT0, %%YT0, %%YHASH

        vmovdqu         %%YT1, [%%T3 + gh_offset]
        vpclmulqdq      %%STATE_00, %%YT0, %%YT1, 0x00          ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%STATE_11, %%YT0, %%YT1, 0x10          ; STATE_11 = DATA_L * KK_H
        vmovdqu         %%YT1, [%%T3]
        vpclmulqdq      %%YT2, %%YT0, %%YT1, 0x01               ; YT2 = DATA_H * HK_L
        vpclmulqdq      %%YT3, %%YT0, %%YT1, 0x11               ; YT3 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3

        add             %%T3, 32        ; move to the next two hashkeys
        add             %%T1, 32        ; move to the next two data blocks
        sub             DWORD(%%T2), 32 ; decrement message length

align_loop
%%_AAD_2_blocks_loop:
        cmp             DWORD(%%T2), 32
        jb              %%_end_AAD_2_blocks_loop

        vmovdqu         %%YT0, [%%T1]
        vpshufb         %%YT0, %%YT0, [rel SHUF_MASK]

        vmovdqu         %%YT1, [%%T3 + gh_offset]
        vpclmulqdq      %%YT2, %%YT0, %%YT1, 0x00               ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%YT3, %%YT0, %%YT1, 0x10               ; STATE_11 = DATA_L * KK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3
        vmovdqu         %%YT1, [%%T3]
        vpclmulqdq      %%YT2, %%YT0, %%YT1, 0x01               ; YT2 = DATA_H * HK_L
        vpclmulqdq      %%YT3, %%YT0, %%YT1, 0x11               ; YT3 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3

        add             %%T3, 32        ; move to the next two hashkeys
        add             %%T1, 32        ; move to the next two data blocks
        sub             DWORD(%%T2), 32 ; decrement message length
        jz              %%_AAD_reduce
        jmp             %%_AAD_2_blocks_loop

align_label
%%_AAD_1_full_block_left:
        vmovdqu         %%XT0, [%%T1]
        vpshufb         %%XT0, %%XT0, [rel SHUF_MASK]
        vpxor           %%XT0, %%XT0, %%AAD_HASH

        vmovdqu         %%XT1, [%%GDATA_KEY + HashKeyK_1]
        vpclmulqdq      %%XSTATE_00, %%XT0, %%XT1, 0x00         ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%XSTATE_11, %%XT0, %%XT1, 0x10         ; STATE_11 = DATA_L * KK_H
        vmovdqu         %%XT1, [%%GDATA_KEY + HashKey_1]
        vpclmulqdq      %%XT2, %%XT0, %%XT1, 0x01               ; YT2 = DATA_H * HK_L
        vpclmulqdq      %%XT3, %%XT0, %%XT1, 0x11               ; YT3 = DATA_H * HK_H
        vpxor           %%XSTATE_00, %%XSTATE_00, %%XT2         ; STATE_00 += YT2
        vpxor           %%XSTATE_11, %%XSTATE_11, %%XT3         ; STATE_11 += YT3

        vpclmulqdq      %%AAD_HASH, %%XSTATE_00, [rel POLY], 0x10
        vpshufd         %%XT0, %%XSTATE_00, 01001110b
        vpxor           %%AAD_HASH, %%AAD_HASH, %%XSTATE_11
        vpxor           %%AAD_HASH, %%AAD_HASH, %%XT0

        add             %%T1, 16
        sub             DWORD(%%T2), 16

        jmp             %%_AAD_partial_block

align_label
%%_end_AAD_2_blocks_loop:
        cmp             DWORD(%%T2), 16
        jb              %%_AAD_reduce

        ;; there is one more block to do
        vmovdqu         %%XT0, [%%T1]
        vpshufb         %%XT0, %%XT0, [rel SHUF_MASK]

        vmovdqu         %%XT1, [%%T3 + gh_offset]
        vpclmulqdq      %%XT2, %%XT0, %%XT1, 0x00               ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%XT3, %%XT0, %%XT1, 0x10               ; STATE_11 = DATA_L * KK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3
        vmovdqu         %%XT1, [%%T3]
        vpclmulqdq      %%XT2, %%XT0, %%XT1, 0x01               ; XT2 = DATA_H * HK_L
        vpclmulqdq      %%XT3, %%XT0, %%XT1, 0x11               ; XT3 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%YT2           ; STATE_00 += YT2
        vpxor           %%STATE_11, %%STATE_11, %%YT3           ; STATE_11 += YT3

        add             %%T1, 16
        sub             DWORD(%%T2), 16

        ;; fall through to reduce

align_label
%%_AAD_reduce:
        ;; combine 2x128-bits hash states into 128-bit hash state
        vextracti128    %%XT0, %%STATE_00, 1
        vextracti128    %%XT1, %%STATE_11, 1
        vpxor           %%XSTATE_00, %%XSTATE_00, %%XT0
        vpxor           %%XSTATE_11, %%XSTATE_11, %%XT1

        ;; new reduction
        vpclmulqdq      %%XHASH, %%XSTATE_00, [rel POLY], 0x10
        vpshufd         %%XT0, %%XSTATE_00, 01001110b
        vpxor           %%XHASH, %%XHASH, %%XSTATE_11
        vpxor           %%XHASH, %%XHASH, %%XT0

        ;; fall through to check for partial block
align_label
%%_AAD_partial_block:
        or              DWORD(%%T2), DWORD(%%T2)
        je              %%_CALC_AAD_done

        vmovdqu         %%XT0, [%%GDATA_KEY + HashKey_1]
        vmovdqu         %%XT2, [%%GDATA_KEY + HashKeyK_1]
        READ_SMALL_DATA_INPUT_AVX   %%XT1, %%T1, %%T2, %%T3
        ; byte-reflect the input data
        vpshufb         %%XT1, %%XT1, [rel SHUF_MASK]
        vpxor           %%AAD_HASH, %%AAD_HASH, %%XT1
        GHASH_MUL2      %%AAD_HASH, %%XT0, %%XT2, %%XT1, %%XT3, %%XT4, %%XT5

align_label
%%_CALC_AAD_done:

%endmacro ; CALC_AAD_HASH


;; GHASH N blocks of data
%macro GHASH_N_BLOCKS 2
%define %%GDATA         %1      ; [in] pointer key structure
%define %%NBLOCKS       %2      ; [in] numerical value - number of blocks to GHASH
                                ; [in] ymm1:ymm8 - input data
                                ; [out] xmm14 - GHASH value
                                ; [clobbered] ymm0, ymm10-ymm13

%if %%NBLOCKS >= 2

%assign i %%NBLOCKS

        GHASH_SINGLE_MUL %%GDATA, i, ymm1, ymm10, ymm11, ymm12, ymm13, ymm0, first

%assign j 2
%rep ((%%NBLOCKS - 2) / 2)
%assign i (i - 2)
%xdefine %%ymmN ymm %+ j
        GHASH_SINGLE_MUL %%GDATA, i, %%ymmN, ymm10, ymm11, ymm12, ymm13, ymm0, not_first
%undef %%ymmN
%assign j (j + 1)
%endrep

        ;; consolidate the products
        vextracti128    xmm12, ymm10, 1
        vextracti128    xmm13, ymm11, 1
        vpxor           xmm10, xmm10, xmm12
        vpxor           xmm11, xmm11, xmm13

%if ((%%NBLOCKS % 2) == 1)
%assign i (i - 2)
%xdefine %%xmmN xmm %+ j
        GHASH_SINGLE_MUL %%GDATA, i, %%xmmN, xmm10, xmm11, xmm12, xmm13, xmm0, not_first
%endif
        ;; xmm10:xmm11 hold the product

%elif %%NBLOCKS == 1
        GHASH_SINGLE_MUL %%GDATA, 1, xmm1, xmm10, xmm11, xmm12, xmm13, xmm0, first
        ;; xmm10:xmm11 hold the product
%endif

%if %%NBLOCKS > 0
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; new reduction xmm11(low):xmm10(high), result in xmm14
        vpclmulqdq      xmm14, xmm11, [rel POLY], 0x10
        vpshufd         xmm12, xmm11, 01001110b
        vpxor           xmm14, xmm14, xmm10
        vpxor           xmm14, xmm14, xmm12
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endif

%endmacro ;; GHASH_N_BLOCKS


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

        cmp     %%PLAIN_CIPH_LEN, 16            ;Read in input data without over reading
        jl      %%_fewer_than_16_bytes
        VXLDR   xmm1, [%%PLAIN_CIPH_IN]         ;If more than 16 bytes of data, just fill the xmm register
        jmp     %%_data_read

align_label
%%_fewer_than_16_bytes:
        lea     r10, [%%PLAIN_CIPH_IN + %%DATA_OFFSET]
        READ_SMALL_DATA_INPUT_AVX   xmm1, r10, %%PLAIN_CIPH_LEN, rax

align_label
%%_data_read:                           ;Finished reading in data
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
align_label
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

align_label
%%_partial_incomplete:
%ifidn __OUTPUT_FORMAT__, win64
        mov     rax, %%PLAIN_CIPH_LEN
        add     [%%GDATA_CTX + PBlockLen], rax
%else
        add     [%%GDATA_CTX + PBlockLen], %%PLAIN_CIPH_LEN
%endif
align_label
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
align_label
%%_partial_fill:
        mov     r13, %%PLAIN_CIPH_LEN
align_label
%%_count_set:

        simd_store_avx  %%CIPH_PLAIN_OUT, xmm9, r13, rax, r12, %%DATA_OFFSET
        add             %%DATA_OFFSET, r13
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align_label
%%_partial_block_done:
%endmacro ; PARTIAL_BLOCK

%macro GHASH_SINGLE_MUL 9
%define %%GDATA                 %1      ;; [in] GHASH key pointer
%define %%HASHKEY               %2      ;; [in] Hash key power (1, 2, 3, etc.)
%define %%CIPHER                %3      ;; [in] xmm with cipher text block
%define %%STATE_11              %4      ;; [in/out] GHASH product state (hi)
%define %%STATE_00              %5      ;; [in/out] GHASH product state (lo)
%define %%T1                    %6      ;; [clobbered] temporary xmm - (it was STATE_MID)
%define %%T2                    %7      ;; [clobbered] temporary xmm
%define %%T3                    %8      ;; [clobbered] temporary xmm
%define %%FIRST                 %9      ;; [in] "first" time or not ("update") selector

%assign HK  HashKey_ %+ %%HASHKEY
%assign HKK HashKeyK_ %+ %%HASHKEY

%ifidn %%FIRST, first
        vmovdqu         %%T1, [%%GDATA + HKK]
        vmovdqu         %%T2, [%%GDATA + HK]
        vpclmulqdq      %%STATE_00, %%CIPHER, %%T1, 0x00        ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%STATE_11, %%CIPHER, %%T1, 0x10        ; STATE_11 = DATA_L * KK_H
        vpclmulqdq      %%T1, %%CIPHER, %%T2, 0x01              ; T1 = DATA_H * HK_L
        vpclmulqdq      %%T2, %%CIPHER, %%T2, 0x11              ; T2 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%T1            ; STATE_00 += T1
        vpxor           %%STATE_11, %%STATE_11, %%T2            ; STATE_11 += T2
%else
        vmovdqu         %%T3, [%%GDATA + HKK]
        vpclmulqdq      %%T1, %%CIPHER, %%T3, 0x00              ; STATE_00 = DATA_L * KK_L
        vpclmulqdq      %%T2, %%CIPHER, %%T3, 0x10              ; STATE_11 = DATA_L * KK_H
        vpxor           %%STATE_00, %%STATE_00, %%T1            ; STATE_00 += T1
        vpxor           %%STATE_11, %%STATE_11, %%T2            ; STATE_11 += T2
        vmovdqu         %%T3, [%%GDATA + HK]
        vpclmulqdq      %%T1, %%CIPHER, %%T3, 0x01              ; T1 = DATA_H * HK_L
        vpclmulqdq      %%T2, %%CIPHER, %%T3, 0x11              ; T2 = DATA_H * HK_H
        vpxor           %%STATE_00, %%STATE_00, %%T1            ; STATE_00 += T1
        vpxor           %%STATE_11, %%STATE_11, %%T2            ; STATE_11 += T2
%endif

%endmacro

;; =============================================================================
;; Encrypt N blocks, then Encrypt 16 blocks anf GHASH N blocks
;; If:
;;     A = message size in bytes
;; Then:
;;     B = Int((A + 15) / 16)
;;     %%num_initial_blocks = B mod 16
%macro INITIAL_BLOCKS 7
%define %%GDATA_KEY             %1      ;; [in] AES key and hash key pointer
%define %%CIPH_PLAIN_OUT        %2      ;; [in] cipher/plain text pointer
%define %%PLAIN_CIPH_IN         %3      ;; [in] plain/cipher text pointer
%define %%LENGTH                %4      ;; [in/out] register with message length
%define %%DATA_OFFSET           %5      ;; [in/out] register current offset within the message
%define %%num_initial_blocks    %6      ;; [in] can be 0, 1, 2, 3, 4, 5, 6, 7 ... 15
%define %%ENC_DEC               %7      ;; [in] 'ENC' - encrypt, 'DEC' - decrypt direction selection
;;      xmm9                            ;; [in/out] most recent counter block
;;                                      ;;     NOTE: in some sections ymm9/xmm9 is used as a temporary register.
;;      r10                             ;; [in] number of AESENC rounds (9, 11 or 13)
;;      r15                             ;; [in] pointer to store encrypted blocks for GHASH
;;      xmm8                            ;; [in] current GHASH value
;;      ymm1-ymm8                       ;; [out] cipher text blocks ready for GHASH (shuffled & added HASH value to block 0)
;;      ymm0, ymm10-ymm15               ;; [clobbered] temporary registers

%define %%T1    xmm10
%define %%T2    xmm11
%define %%T3    xmm12
%define %%T4    xmm13
%define %%T5    xmm14
%define %%T6    xmm15
%define %%T7    xmm0
%define %%T8    xmm9

%xdefine %%YT1  YWORD(%%T1)
%xdefine %%YT2  YWORD(%%T2)
%xdefine %%YT3  YWORD(%%T3)
%xdefine %%YT4  YWORD(%%T4)
%xdefine %%YT5  YWORD(%%T5)
%xdefine %%YT6  YWORD(%%T6)
%xdefine %%YT7  YWORD(%%T7)
%xdefine %%YT8  YWORD(%%T8)

%if %%num_initial_blocks > 0
                ;; Temporarily store GHASH value onto stack
                vmovdqa xmm8, xmm8              ;; clear top 128-bits of ymm8
                vmovdqa [r15 + TMP1], ymm8

                ;; prepare counter blocks and do AES encryption on them
%xdefine %%FN gcm_aes_ctr_ %+ %%num_initial_blocks %+ _vaes_avx2
                call            %%FN
%undef %%FN
                ;; save last counter block (LE)
                vmovdqa         [r15 + TMP3], xmm9

                ;; load plain/cipher text blocks
                YMM_LOAD_BLOCKS_AVX2_0_16 \
                                %%num_initial_blocks, %%PLAIN_CIPH_IN, %%DATA_OFFSET, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                %%num_initial_blocks, vpxor, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                ;; store cipher/plain text blocks
                YMM_STORE_BLOCKS_AVX2_0_16 \
                                %%num_initial_blocks, %%CIPH_PLAIN_OUT, %%DATA_OFFSET, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Prepare cipher text for GHASH
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifidn %%ENC_DEC, ENC
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                %%num_initial_blocks, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%else
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                %%num_initial_blocks, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%endif

        vmovdqa xmm9, [r15 + TMP3]
        vpxor   ymm1, ymm1, [r15 + TMP1]

        YMM_STORE_BLOCKS_AVX2_0_16 \
                %%num_initial_blocks, r15, 0, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8

        ;; Update data offset with the number of blocks processed
        add     %%DATA_OFFSET, %%num_initial_blocks * 16

%else  ;; %%num_initial_blocks > 0
        vmovdqa %%T2, xmm8
%endif ;; %%num_initial_blocks == 0

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; %%num_initial_blocks have been encrypted.
        ;; Encrypt 16 blocks (potentially last block is partial) and
        ;; GHASH already encrypted %%num_initial_blocks.

                ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
                ;; Prepare 16 counter blocks and perform rounds of AES cipher on
                ;; them, load plain/cipher text and store cipher/plain text.
                ;; Stitch GHASH computation in between AES rounds.
                vinserti128     ymm9, xmm9, 1
                YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                                16, vpaddd, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm9, ymm9, ymm9, ymm9, ymm1, ymm2, ymm3, ymm4,  \
                                {[rel ddq_add_1234 + 0*32]}, {[rel ddq_add_1234 + 1*32]}, \
                                {[rel ddq_add_5678 + 0*32]}, {[rel ddq_add_5678 + 1*32]}, \
                                {[rel ddq_add_8888]}, {[rel ddq_add_8888]}, \
                                {[rel ddq_add_8888]}, {[rel ddq_add_8888]}

                vextracti128    xmm9, ymm8, 1       ; last counter block (LE)

                vbroadcasti128  ymm0, [rel SHUF_MASK]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vpshufb, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*0]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vpxor, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*1]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0


        ;; it is used to indicate GHASH was computed using YMM registers (2 pair of products)
%assign ghash_on_ymm 0
        ;; it is used to indicate GHASH was consolidated from YMM to XMM
%assign ghash_consolidated 0

%assign i 0
%assign k (%%num_initial_blocks)

        ;; GHASH block 1 & 2
%if ((i + 1) < %%num_initial_blocks)
        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, first
%assign i (i + 2)
%assign k (k - 2)
%assign ghash_on_ymm 1
%elif (i < %%num_initial_blocks)
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, first
%assign i (i + 1)
%assign k (k - 1)
%assign ghash_consolidated 1
%endif ;; (i < %%num_initial_blocks)

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*2]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

        ;; GHASH block 3 & 4
%if ((i + 1) < %%num_initial_blocks)
        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, not_first
%assign i (i + 2)
%assign k (k - 2)
%elif (i < %%num_initial_blocks)
%if ghash_on_ymm != 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%endif
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, not_first
%assign i (i + 1)
%assign k (k - 1)
%endif ;; (i < %%num_initial_blocks)

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*3]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

        ;; GHASH block 5 & 6
%if ((i + 1) < %%num_initial_blocks)

        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, not_first
%assign i (i + 2)
%assign k (k - 2)

%elif (i < %%num_initial_blocks)

%if ghash_on_ymm != 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%assign ghash_consolidated 1
%assign ghash_on_ymm 0
%endif
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, not_first
%assign i (i + 1)
%assign k (k - 1)

%endif ;; (i < %%num_initial_blocks)

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*4]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

        ;; 7 & 8
%if ((i + 1) < %%num_initial_blocks)

        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, not_first
%assign i (i + 2)
%assign k (k - 2)

%elif (i < %%num_initial_blocks)

%if ghash_on_ymm != 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%assign ghash_consolidated 1
%assign ghash_on_ymm 0
%endif
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, not_first
%assign i (i + 1)
%assign k (k - 1)

%endif ;; (i < %%num_initial_blocks)

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*5]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0


        ;; GHASH block 9 & 10
%if ((i + 1) < %%num_initial_blocks)

        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, not_first
%assign i (i + 2)
%assign k (k - 2)

%elif (i < %%num_initial_blocks)

%if ghash_on_ymm != 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%endif
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, not_first
%assign i (i + 1)
%assign k (k - 1)

%endif ;; (i < %%num_initial_blocks)

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*6]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

        ;; GHASH block 11 & 12
%if ((i + 1) < %%num_initial_blocks)

        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, not_first
%assign i (i + 2)
%assign k (k - 2)

%elif (i < %%num_initial_blocks)

%if ghash_on_ymm != 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%assign ghash_consolidated 1
%assign ghash_on_ymm 0
%endif
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, not_first
%assign i (i + 1)
%assign k (k - 1)

%endif ;; (i < %%num_initial_blocks)

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*7]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0


        ;; GHASH block 13 & 14
%if ((i + 1) < %%num_initial_blocks)
        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, not_first
%assign i (i + 2)
%assign k (k - 2)
%elif (i < %%num_initial_blocks)
%if ghash_on_ymm != 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%assign ghash_consolidated 1
%assign ghash_on_ymm 0
%endif
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, not_first
%assign i (i + 1)
%assign k (k - 1)
%endif ;; (i < %%num_initial_blocks)

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*8]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

        ;; GHASH block 15 & 16
%if ((i + 1) < %%num_initial_blocks)
        vmovdqu         %%YT2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%YT2, %%YT1, %%YT4, %%YT6, %%YT5, %%YT3, not_first
%assign i (i + 2)
%assign k (k - 2)
%elif (i < %%num_initial_blocks)
%if ghash_on_ymm != 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%assign ghash_consolidated 1
%assign ghash_on_ymm 0
%endif
        vmovdqu         %%T2, [r15 + i*16]
        GHASH_SINGLE_MUL %%GDATA_KEY, k, %%T2, %%T1, %%T4, %%T6, %%T5, %%T3, not_first
%assign i (i + 1)
%assign k (k - 1)
%endif ;; (i < %%num_initial_blocks)

%if ghash_on_ymm != 0 && ghash_consolidated == 0
        vextracti128    %%T6, %%YT1, 1
        vextracti128    %%T5, %%YT4, 1
        vpxor           %%T1, %%T1, %%T6
        vpxor           %%T4, %%T4, %%T5
%assign ghash_consolidated 1
%assign ghash_on_ymm 0
%endif

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*9]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

%if (%%num_initial_blocks > 0)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; new reduction T4(low):T1(high), result in TMP1
        vpclmulqdq      %%T3, %%T4, [rel POLY], 0x10
        vpshufd         %%T6, %%T4, 01001110b
        vpxor           %%T3, %%T3, %%T1
        vpxor           %%T3, %%T3, %%T6
        vmovdqa         [r15 + TMP1], YWORD(%%T3)
%else
        ;; The hash should end up in TMP1, TMP2 = 0
        vmovdqa         [r15 + TMP1], YWORD(%%T2)
%endif
        ;; Final hash is now in TMP1 and Y0 in TMP3
        vmovdqa         [r15 + TMP3], xmm9

        cmp     r10d, 11
        jb      %%_initial_blocks2_aesenclast_128
        je      %%_initial_blocks2_aesenclast_192

        ;; 256-bit
                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*10]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*11]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*12]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*13]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*14]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenclast, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                jmp     %%_initial_blocks2_aesenclast_done

align_label
%%_initial_blocks2_aesenclast_192:
                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*10]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*11]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenc, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*12]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenclast, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

                jmp     %%_initial_blocks2_aesenclast_done

align_label
%%_initial_blocks2_aesenclast_128:
                vbroadcasti128  ymm0, [%%GDATA_KEY + 16*10]
                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vaesenclast, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

align_label
%%_initial_blocks2_aesenclast_done:

%if %%num_initial_blocks > 0
                ;; NOTE: obsolete in case %%num_initial_blocks = 0
                sub     %%LENGTH, 16 * %%num_initial_blocks

                ;; NOTE: 'jb' is never taken for %%num_initial_blocks = 0
                ;; If the last block is partial then the xor will be done later
                ;; in ENCRYPT_FINAL_PARTIAL_BLOCK.
                ;; We know it's partial if LENGTH - 16*num_initial_blocks < 256
                cmp     %%LENGTH, 256
                jb      %%_initial_skip_last_word_write
%endif

                ;; Load 16 plain/cipher text blocks and XOR them against AES blocks
                YMM_LOAD_BLOCKS_AVX2_0_16 \
                                16, %%PLAIN_CIPH_IN, %%DATA_OFFSET, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vpxor, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                ;; store cipher/plain text blocks minus 1
                YMM_STORE_BLOCKS_AVX2_0_16 \
                                16, %%CIPH_PLAIN_OUT, %%DATA_OFFSET, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Prepare cipher text for GHASH
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifidn %%ENC_DEC, ENC
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                16, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%else
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                16, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%endif

                ;; Update %%LENGTH with the number of blocks processed
                sub     %%LENGTH, 16*16
                add     %%DATA_OFFSET, 16*16

%if %%num_initial_blocks > 0
                ;; jmp and %%_initial_skip_last_word_write not required for %%num_initial_blocks=0 case
                jmp     %%_initial_words_done

align_label
%%_initial_skip_last_word_write:
                ;; Load 15 plain/cipher text blocks and XOR them against AES blocks
                YMM_LOAD_BLOCKS_AVX2_0_16 \
                                15, %%PLAIN_CIPH_IN, %%DATA_OFFSET, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                16, vpxor, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                ;; store cipher/plain text blocks minus 1
                YMM_STORE_BLOCKS_AVX2_0_16 \
                                15, %%CIPH_PLAIN_OUT, %%DATA_OFFSET, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Prepare cipher text for GHASH
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifidn %%ENC_DEC, ENC
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                16, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%else
        vperm2i128      %%YT8, ymm8, %%YT8, 0x12        ;; insert the last encrypted counter block into block 8 index 1
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                16, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%endif

                ;; Update %%LENGTH with the number of blocks processed
                sub     %%LENGTH, 15*16
                add     %%DATA_OFFSET, 15*16

align_label
%%_initial_words_done:
%endif ;; %%num_initial_blocks > 0

                vmovdqa xmm9, [r15 + TMP3]              ;; restore counter block in xmm9
                vpxor   ymm1, ymm1, [r15 + TMP1]        ;; add current GHASH value to block 0
                vmovdqa [r15 + TMP1], ymm1
                vmovdqa [r15 + TMP3], ymm2
                vmovdqa [r15 + TMP5], ymm3
                vmovdqa [r15 + TMP7], ymm4
                vmovdqa [r15 + TMP9], ymm5
                vmovdqa [r15 + TMP11], ymm6
                vmovdqa [r15 + TMP13], ymm7
                vmovdqa [r15 + TMP15], ymm8

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align_label
%%_initial_blocks_done:

%endmacro

;;; INITIAL_BLOCKS macro with support for a partial final block.
;;; num_initial_blocks is expected to include the partial final block
;;;     in the count.
%macro INITIAL_BLOCKS_PARTIAL 9
%define %%GDATA_KEY             %1      ;; [in] pointer to GCM key data
%define %%GDATA_CTX             %2      ;; [in] pointer to GCM context data
%define %%CIPH_PLAIN_OUT        %3      ;; [in] pointer to destination buffer
%define %%PLAIN_CIPH_IN         %4      ;; [in] pointer to source buffer
%define %%LENGTH                %5      ;; [in] message length
%define %%DATA_OFFSET           %6      ;; [in/out] buffer offset
%define %%num_initial_blocks    %7      ;; [in] numeric value, number of blocks can be from 1 to 7 (not 0)
%define %%ENC_DEC               %8      ;; [in] selection for "ENC" encrypt or "DEC" for decrypt directions
%define %%INSTANCE_TYPE         %9      ;; [in] "multi_call" or "single_call" API type selection
;;      xmm9                            ;; [in/out] most recent counter block
;;                                      ;;     NOTE: in some sections ymm9/xmm9 is used as a temporary register.
;;      r10                             ;; [in] number of AESENC rounds (9, 11 or 13)
;;      xmm8                            ;; [in] current GHASH value
;;      xmm14                           ;; [out] updated GHASH value
;;      ymm0, ymm1-ymm8, ymm10-ymm13,
;;          ymm15                       ;; [clobbered] temporary registers

%define %%T1    xmm10
%define %%T2    xmm11
%define %%T3    xmm12
%define %%T4    xmm13
%define %%T5    xmm14
%define %%T6    xmm15
%define %%T7    xmm0
%define %%T8    xmm9

%xdefine %%YT1  YWORD(%%T1)
%xdefine %%YT2  YWORD(%%T2)
%xdefine %%YT3  YWORD(%%T3)
%xdefine %%YT4  YWORD(%%T4)
%xdefine %%YT5  YWORD(%%T5)
%xdefine %%YT6  YWORD(%%T6)
%xdefine %%YT7  YWORD(%%T7)
%xdefine %%YT8  YWORD(%%T8)

%assign j (((%%num_initial_blocks - 1) / 2) + 1)
%xdefine %%LAST_YMM ymm %+ j
%assign j ((%%num_initial_blocks - 1) % 2)
%xdefine %%LAST_IDX j

                ;; Temporarily store GHASH value onto stack
                vmovdqa         xmm8, xmm8              ;; clear top 128-bits of ymm8
                vmovdqa         [rsp + TMP1], ymm8

                ;; prepare counter blocks and do AES encryption on them
%xdefine %%FN gcm_aes_ctr_ %+ %%num_initial_blocks %+ _vaes_avx2
                mov             r10d, NROUNDS
                call            %%FN
%undef %%FN
                ;; save last counter block (LE)
                vmovdqa         [rsp + TMP3], xmm9

                ;; extract the last cipher block
                vextracti128    [rsp + TMP4], %%LAST_YMM, %%LAST_IDX

%assign j (%%num_initial_blocks - 1)

                ;; load plain/cipher text blocks minus 1
                YMM_LOAD_BLOCKS_AVX2_0_16 \
                                j, %%PLAIN_CIPH_IN, %%DATA_OFFSET, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                                j, vpxor, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8

                ;; store cipher/plain text blocks minus 1
                YMM_STORE_BLOCKS_AVX2_0_16 \
                                j, %%CIPH_PLAIN_OUT, %%DATA_OFFSET, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Prepare cipher text for GHASH minus the last block
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifidn %%ENC_DEC, ENC
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                j, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%else
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                j, vpshufb, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                %%YT1, %%YT2, %%YT3, %%YT4, %%YT5, %%YT6, %%YT7, %%YT8, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, \
                {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}, {[rel SHUF_MASK]}
%endif

%if %%num_initial_blocks > 1
        add     DWORD(%%DATA_OFFSET), (16 * j)
        sub     DWORD(%%LENGTH), (16 * j)
%endif

%if %%num_initial_blocks < 16
                ;; NOTE: the 'jb' is always taken for num_initial_blocks = 16.
                ;;      This is run in the context of GCM_ENC_DEC_SMALL for length < 256.
                cmp     DWORD(%%LENGTH), 16
                jb      %%_small_initial_partial_block

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;; Handle a full length final block - encrypt and hash all blocks
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                sub     DWORD(%%LENGTH), 16
                mov     [%%GDATA_CTX + PBlockLen], %%LENGTH

                ;; Encrypt the last block of the message
                VXLDR   %%T1, [%%PLAIN_CIPH_IN + %%DATA_OFFSET]
                vpxor   %%T2, %%T1, [rsp + TMP4]
                VXSTR   [%%CIPH_PLAIN_OUT + %%DATA_OFFSET], %%T2
                add     DWORD(%%DATA_OFFSET), 16
                ;; Prepare cipher text block for GHASH computations
%ifidn  %%ENC_DEC, DEC
                vpshufb %%T2, %%T1, [rel SHUF_MASK]
%else
                vpshufb %%T2, %%T2, [rel SHUF_MASK]
%endif

%if %%num_initial_blocks > 1
        vpxor           ymm1, ymm1, [rsp + TMP1]    ;; add current GHASH to cipher text block 0
        vinserti128     %%LAST_YMM, %%T2, %%LAST_IDX    ;; append last cipher text block
%else
        vpxor           xmm1, %%T2, [rsp + TMP1]
%endif

        ;; Hash all of the data
%xdefine %%FN ghash_ %+ %%num_initial_blocks %+ _vaes_avx2
        call            %%FN
%undef %%FN
        ;; xmm14 - reduced already
        jmp      %%_small_initial_compute_hash

%endif                          ; %if %%num_initial_blocks < 8

align_label
%%_small_initial_partial_block:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Handle encrypt & ghash for a <16B final block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;; In this case if it's a single call to encrypt we can
        ;; hash all of the data but if it's an init / update / finalize
        ;; series of call we need to leave the last block if it's
        ;; less than a full block of data.

        vmovdqa         xmm15, [rsp + TMP4]
        mov             [%%GDATA_CTX + PBlockLen], %%LENGTH
        vmovdqu         [%%GDATA_CTX + PBlockEncKey], xmm15

        ;; Handle a partial final block
        ;; r13 - length, r11 - data offset
        ;; xmm15 - encrypted counter block
%ifidn %%ENC_DEC, DEC
        call    gcm_dec_final_partial_block_vaes_avx2
%else
        call    gcm_enc_final_partial_block_vaes_avx2
%endif
        vpshufb         xmm15, xmm15, [rel SHUF_MASK]

%if %%num_initial_blocks > 1
        vpxor           ymm1, ymm1, [rsp + TMP1]    ;; add current GHASH to cipher text block 0
%else
        vpxor           xmm1, xmm15, [rsp + TMP1]
%endif

%ifidn %%INSTANCE_TYPE, multi_call
%assign k (%%num_initial_blocks - 1)
%assign min_blocks_to_hash 1
%else
%assign k (%%num_initial_blocks)
%assign min_blocks_to_hash 0
%if %%num_initial_blocks > 1
        vinserti128     %%LAST_YMM, xmm15, %%LAST_IDX    ;; append last cipher text block
%endif ;; %%num_initial_blocks > 1
%endif ;; %%INSTANCE_TYPE

%if (%%num_initial_blocks > min_blocks_to_hash)

%xdefine %%FN ghash_ %+ k %+ _vaes_avx2
        call            %%FN
%undef %%FN

%ifidn %%INSTANCE_TYPE, multi_call
        vpxor           xmm14, xmm14, xmm15
%endif

%else
        vmovdqa         xmm14, xmm1
%endif

align_label
%%_small_initial_compute_hash:
        ;; Final hash is now in xmm14
        vmovdqa         [rsp + TMP1], xmm14     ;; @todo overwrite this location with current hash value
        vmovdqa         xmm9, [rsp + TMP3]      ;; keep last counter block into xmm9
%endmacro                       ; INITIAL_BLOCKS_PARTIAL

;; =============================================================================
;; Encrypt 16 blocks at a time & GHASH the 16 previously encrypted cipher text blocks
%macro  GHASH_16_ENCRYPT_16_PARALLEL 7
%define %%GDATA                 %1      ;; [in] AES key and hash key pointer
%define %%CIPH_PLAIN_OUT        %2      ;; [in] plain/cipher text pointer
%define %%PLAIN_CIPH_IN         %3      ;; [in] cipher/plain text pointer
%define %%DATA_OFFSET           %4      ;; [in/out] current offset within the message
%define %%ENC_DEC               %5      ;; [in] 'ENC' - encrypt, 'DEC' - decrypt direction selection
%define %%FULL_PARTIAL          %6      ;; [in] 'full' - process 16 blocks, 'partial' - encrypt 16 blocks but load/store 15
%define %%CTR_CHECK             %7      ;; [in/out] GP register with counter check
;;      ymm9                            ;; [in/out] 2x128-bit most recent counter block
;;      ymm1-ymm8                       ;; [out] cipher text blocks ready for GHASH (shuffled & added HASH value to block 0)
;;      ymm0, ymm10-ymm15               ;; [clobbered] temporary registers
;;      r12                             ;; [in] pointer to store cipher text blocks for GHASH (stack frame)

%define %%T1    xmm0
%define %%T2    xmm10
%define %%T3    xmm11
%define %%T4    xmm12
%define %%T5    xmm13
%define %%T6    xmm14
%define %%T7    xmm15
%define %%CTR   xmm9

%define %%YT1   ymm0
%define %%YT2   ymm10
%define %%YT3   ymm11
%define %%YT4   ymm12
%define %%YT5   ymm13
%define %%YT6   ymm14
%define %%YT7   ymm15
%define %%YCTR  ymm9

                cmp     DWORD(%%CTR_CHECK), (255 - 16)
                ja      %%_counter_overflow16
                ;; Increment CTR in big endian
                YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                                16, vpaddd, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                %%YCTR, %%YCTR, %%YCTR, %%YCTR, ymm1, ymm2, ymm3, ymm4,  \
                                {[rel ddq_addbe_1234 + 0*32]}, {[rel ddq_addbe_1234 + 1*32]}, \
                                {[rel ddq_addbe_5678 + 0*32]}, {[rel ddq_addbe_5678 + 1*32]}, \
                                {[rel ddq_addbe_8888]}, {[rel ddq_addbe_8888]}, \
                                {[rel ddq_addbe_8888]}, {[rel ddq_addbe_8888]}
                jmp             %%_end_overflow16_check

align_label
%%_counter_overflow16:
                ;; Increment CTR in little endian
                vpshufb         %%YCTR, %%YCTR, [rel SHUF_MASK]
                YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                                16, vpaddd, \
                                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                                %%YCTR, %%YCTR, %%YCTR, %%YCTR, ymm1, ymm2, ymm3, ymm4,  \
                                {[rel ddq_add_1234 + 0*32]}, {[rel ddq_add_1234 + 1*32]}, \
                                {[rel ddq_add_5678 + 0*32]}, {[rel ddq_add_5678 + 1*32]}, \
                                {[rel ddq_add_8888]}, {[rel ddq_add_8888]}, \
                                {[rel ddq_add_8888]}, {[rel ddq_add_8888]}

                vmovdqa         %%YT5, [rel SHUF_MASK]
                vpshufb         ymm1, ymm1, %%YT5
                vpshufb         ymm2, ymm2, %%YT5
                vpshufb         ymm3, ymm3, %%YT5
                vpshufb         ymm4, ymm4, %%YT5
                vpshufb         ymm5, ymm5, %%YT5
                vpshufb         ymm6, ymm6, %%YT5
                vpshufb         ymm7, ymm7, %%YT5
                vpshufb         ymm8, ymm8, %%YT5
                ;; CTR left in big endian
align_label
%%_end_overflow16_check:
                vperm2i128      %%YCTR, ymm8, ymm8, 0x11
                add             BYTE(%%CTR_CHECK), 16

                ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqa         %%YT2, [r12 + TMP1]

                vbroadcasti128  %%YT1, [%%GDATA + 16*0]
                vpxor           ymm1, ymm1, %%YT1
                vpxor           ymm2, ymm2, %%YT1
                vpxor           ymm3, ymm3, %%YT1
                vpxor           ymm4, ymm4, %%YT1
                vpxor           ymm5, ymm5, %%YT1
                vpxor           ymm6, ymm6, %%YT1
                vpxor           ymm7, ymm7, %%YT1
                vpxor           ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 16, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, first
        vmovdqa         %%YT2, [r12 + TMP3]

                vbroadcasti128  %%YT1, [%%GDATA + 16*1]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 14, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, not_first
        vmovdqa         %%YT2, [r12 + TMP5]

                vbroadcasti128  %%YT1, [%%GDATA + 16*2]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 12, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, not_first
        vmovdqa         %%YT2, [r12 + TMP7]

                vbroadcasti128  %%YT1, [%%GDATA + 16*3]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 10, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, not_first
        vmovdqa         %%YT2, [r12 + TMP9]

                vbroadcasti128  %%YT1, [%%GDATA + 16*4]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 8, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, not_first
        vmovdqa         %%YT2, [r12 + TMP11]

                vbroadcasti128  %%YT1, [%%GDATA + 16*5]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 6, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, not_first
        vmovdqa         %%YT2, [r12 + TMP13]

                vbroadcasti128  %%YT1, [%%GDATA + 16*6]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 4, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, not_first
        vmovdqa         %%YT2, [r12 + TMP15]

                vbroadcasti128  %%YT1, [%%GDATA + 16*7]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        GHASH_SINGLE_MUL %%GDATA, 2, %%YT2, %%YT4, %%YT5, %%YT3, %%YT6, %%YT7, not_first

                vbroadcasti128  %%YT1, [%%GDATA + 16*8]
                vaesenc         ymm1, ymm1, %%YT1
                vaesenc         ymm2, ymm2, %%YT1
                vaesenc         ymm3, ymm3, %%YT1
                vaesenc         ymm4, ymm4, %%YT1
                vaesenc         ymm5, ymm5, %%YT1
                vaesenc         ymm6, ymm6, %%YT1
                vaesenc         ymm7, ymm7, %%YT1
                vaesenc         ymm8, ymm8, %%YT1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vextracti128    %%T6, %%YT4, 1
        vextracti128    %%T7, %%YT5, 1
        vpxor           %%T4, %%T4, %%T6
        vpxor           %%T5, %%T5, %%T7

        ;; new reduction %%T5(low):%%T4(high), result in %%T1
        vpclmulqdq      %%T1, %%T5, [rel POLY], 0x10
        vpshufd         %%T2, %%T5, 01001110b
        vpxor           %%T1, %%T1, %%T4
        vpxor           %%T1, %%T1, %%T2
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                vbroadcasti128  %%YT5, [%%GDATA + 16*9]
                vaesenc         ymm1, ymm1, %%YT5
                vaesenc         ymm2, ymm2, %%YT5
                vaesenc         ymm3, ymm3, %%YT5
                vaesenc         ymm4, ymm4, %%YT5
                vaesenc         ymm5, ymm5, %%YT5
                vaesenc         ymm6, ymm6, %%YT5
                vaesenc         ymm7, ymm7, %%YT5
                vaesenc         ymm8, ymm8, %%YT5

                vbroadcasti128  %%YT5, [%%GDATA + 16*10]
%ifndef GCM128_MODE            ; GCM192 or GCM256
                vaesenc         ymm1, ymm1, %%YT5
                vaesenc         ymm2, ymm2, %%YT5
                vaesenc         ymm3, ymm3, %%YT5
                vaesenc         ymm4, ymm4, %%YT5
                vaesenc         ymm5, ymm5, %%YT5
                vaesenc         ymm6, ymm6, %%YT5
                vaesenc         ymm7, ymm7, %%YT5
                vaesenc         ymm8, ymm8, %%YT5

                vbroadcasti128  %%YT5, [%%GDATA + 16*11]
                vaesenc         ymm1, ymm1, %%YT5
                vaesenc         ymm2, ymm2, %%YT5
                vaesenc         ymm3, ymm3, %%YT5
                vaesenc         ymm4, ymm4, %%YT5
                vaesenc         ymm5, ymm5, %%YT5
                vaesenc         ymm6, ymm6, %%YT5
                vaesenc         ymm7, ymm7, %%YT5
                vaesenc         ymm8, ymm8, %%YT5

                vbroadcasti128  %%YT5, [%%GDATA + 16*12]
%endif
%ifdef GCM256_MODE
                vaesenc         ymm1, ymm1, %%YT5
                vaesenc         ymm2, ymm2, %%YT5
                vaesenc         ymm3, ymm3, %%YT5
                vaesenc         ymm4, ymm4, %%YT5
                vaesenc         ymm5, ymm5, %%YT5
                vaesenc         ymm6, ymm6, %%YT5
                vaesenc         ymm7, ymm7, %%YT5
                vaesenc         ymm8, ymm8, %%YT5

                vbroadcasti128  %%YT5, [%%GDATA + 16*13]
                vaesenc         ymm1, ymm1, %%YT5
                vaesenc         ymm2, ymm2, %%YT5
                vaesenc         ymm3, ymm3, %%YT5
                vaesenc         ymm4, ymm4, %%YT5
                vaesenc         ymm5, ymm5, %%YT5
                vaesenc         ymm6, ymm6, %%YT5
                vaesenc         ymm7, ymm7, %%YT5
                vaesenc         ymm8, ymm8, %%YT5

                vbroadcasti128  %%YT5, [%%GDATA + 16*14]
%endif                          ; GCM256

                vmovdqu %%YT2, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*0]
                vmovdqu %%YT3, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*2]
                vmovdqu %%YT4, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*4]
                vmovdqu %%YT6, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*6]

                ;; the last round, %%T5 holds the key
                vaesenclast     ymm1, ymm1, %%YT5
                vaesenclast     ymm2, ymm2, %%YT5
                vaesenclast     ymm3, ymm3, %%YT5
                vaesenclast     ymm4, ymm4, %%YT5
                vaesenclast     ymm5, ymm5, %%YT5
                vaesenclast     ymm6, ymm6, %%YT5
                vaesenclast     ymm7, ymm7, %%YT5
                vaesenclast     ymm8, ymm8, %%YT5

        vmovdqu         %%YT7, [rel SHUF_MASK]

%ifidn %%ENC_DEC, ENC
                vpxor           ymm1, ymm1, %%YT2
                vpxor           ymm2, ymm2, %%YT3
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*0], ymm1
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*2], ymm2
        vpshufb         ymm1, ymm1, %%YT7
        vpshufb         ymm2, ymm2, %%YT7
        vpxor           ymm1, ymm1, %%YT1       ; add hash value to cipher text block 0
        vmovdqa         [r12 + TMP1], ymm1
        vmovdqa         [r12 + TMP3], ymm2

                vpxor           ymm3, ymm3, %%YT4
                vpxor           ymm4, ymm4, %%YT6
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*4], ymm3
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*6], ymm4
        vpshufb         ymm3, ymm3, %%YT7
        vpshufb         ymm4, ymm4, %%YT7
        vmovdqa         [r12 + TMP5], ymm3
        vmovdqa         [r12 + TMP7], ymm4

                vmovdqu         %%YT2, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*8]
                vmovdqu         %%YT3, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*10]
                vpxor           ymm5, ymm5, %%YT2
                vpxor           ymm6, ymm6, %%YT3
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*8], ymm5
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*10], ymm6
        vpshufb         ymm5, ymm5, %%YT7
        vpshufb         ymm6, ymm6, %%YT7
        vmovdqa         [r12 + TMP9], ymm5
        vmovdqa         [r12 + TMP11], ymm6

                vmovdqu         %%YT4, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*12]
%ifidn %%FULL_PARTIAL, full
                vmovdqu         %%YT6, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*14]
%else
                vmovdqu         %%T6, [%%PLAIN_CIPH_IN + %%DATA_OFFSET + 16*14]
%endif
                vpxor           ymm7, ymm7, %%YT4
                vpxor           ymm8, ymm8, %%YT6
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*12], ymm7
%ifidn %%FULL_PARTIAL, full
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*14], ymm8
%else
                vmovdqu         [%%CIPH_PLAIN_OUT + %%DATA_OFFSET+16*14], xmm8
%endif
        vpshufb         ymm7, ymm7, %%YT7
        vpshufb         ymm8, ymm8, %%YT7
        vmovdqa         [r12 + TMP13], ymm7
        vmovdqa         [r12 + TMP15], ymm8

%else
        ;; decrypt direction
                vpxor           ymm1, ymm1, %%YT2
                vpxor           ymm2, ymm2, %%YT3
                vmovdqu         [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*0], ymm1
                vmovdqu         [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*2], ymm2
        vpshufb         ymm1, %%YT2, %%YT7
        vpshufb         ymm2, %%YT3, %%YT7
        vpxor           ymm1, ymm1, %%YT1       ; add hash value to cipher text block 0
        vmovdqa         [r12 + TMP1], ymm1
        vmovdqa         [r12 + TMP3], ymm2

                vpxor           ymm3, ymm3, %%YT4
                vpxor           ymm4, ymm4, %%YT6
                vmovdqu         [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*4], ymm3
                vmovdqu         [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*6], ymm4
        vpshufb         ymm3, %%YT4, %%YT7
        vpshufb         ymm4, %%YT6, %%YT7
        vmovdqa         [r12 + TMP5], ymm3
        vmovdqa         [r12 + TMP7], ymm4

                vmovdqu         %%YT2, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*8]
                vmovdqu         %%YT3, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*10]
                vpxor           ymm5, ymm5, %%YT2
                vpxor           ymm6, ymm6, %%YT3
                vmovdqu         [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*8],  ymm5
                vmovdqu         [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*10], ymm6
        vpshufb         ymm5, %%YT2, %%YT7
        vpshufb         ymm6, %%YT3, %%YT7
        vmovdqa         [r12 + TMP9], ymm5
        vmovdqa         [r12 + TMP11], ymm6

                vmovdqu         %%YT2, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*12]
%ifidn %%FULL_PARTIAL, full
                vmovdqu         %%YT3, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*14]
%else
                vmovdqu         %%T3, [%%PLAIN_CIPH_IN+%%DATA_OFFSET+16*14]
%endif
                vpxor           ymm7, ymm7, %%YT2
                vpxor           ymm8, ymm8, %%YT3
                vmovdqu         [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*12], ymm7
%ifidn %%FULL_PARTIAL, full
                vmovdqu [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*14], ymm8
%else
                vmovdqu [%%CIPH_PLAIN_OUT+%%DATA_OFFSET+16*14], xmm8
                vperm2i128      %%YT3, ymm8, %%YT3, 0x12  ;; insert the last encrypted counter block into block 8 index 1
%endif
        vpshufb         ymm7, %%YT2, %%YT7
        vpshufb         ymm8, %%YT3, %%YT7
        vmovdqa         [r12 + TMP13], ymm7
        vmovdqa         [r12 + TMP15], ymm8

%endif  ;; encrypt/decrypt

%endmacro ; GHASH_16_ENCRYPT_16_PARALLEL

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
        and     rsp, ~31

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
        call    ghash_internal_vaes_avx2

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

        vpxor   xmm0, xmm0, xmm0        ;; prepare hash in
        ;; arg1 = key pointer
        mov     r12, %%A_IN
        mov     r13, %%A_LEN
        call    ghash_internal_vaes_avx2
        vmovdqa %%AAD_HASH, xmm0        ;; put hash out into xmm14
        jmp     %%_aad_is_done

align_label
%%_aad_len_is_12:
        ;; GHASH 12 bytes of AAD
        mov     %%GPR1, %%A_IN
        vmovq   %%AAD_HASH, [%%GPR1]
        vpinsrd %%AAD_HASH, [%%GPR1 + 8], 2
        vmovdqa xmm1, [%%GDATA_KEY + HashKey_1]
        vmovdqa xmm2, [%%GDATA_KEY + HashKeyK_1]
        vpshufb %%AAD_HASH, %%AAD_HASH, [rel SHUF_MASK]

        GHASH_MUL2 %%AAD_HASH, xmm1, xmm2, xmm6, xmm5, xmm4, xmm3

align_label
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

align_label
%%_iv_len_is_12:
%endif

        ;; IV is 12 bytes
        ;; read 12 IV bytes and pad with 0x00000001
        mov     %%GPR2, %%IV
        vmovq   xmm0, [%%GPR2]
        vpinsrd xmm0, [%%GPR2 + 8], 2
        vpinsrd xmm0, [rel ONEf + 12], 3                   ; read 12 IV bytes and pad with 0x00000001

align_label
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

        ;; NOTE: check for 0 blocks is obsolete in current implementation.
        ;;       Zero length check is already done in GCM_ENC_DEC.
        cmp     DWORD(%%NUM_BLOCKS), 15
        je      %%_small_initial_num_blocks_is_15
        ja      %%_small_initial_num_blocks_is_16
        cmp     DWORD(%%NUM_BLOCKS), 2
        je      %%_small_initial_num_blocks_is_2
        jb      %%_small_initial_num_blocks_is_1
        cmp     DWORD(%%NUM_BLOCKS), 13
        je      %%_small_initial_num_blocks_is_13
        ja      %%_small_initial_num_blocks_is_14
        cmp     DWORD(%%NUM_BLOCKS), 4
        je      %%_small_initial_num_blocks_is_4
        jb      %%_small_initial_num_blocks_is_3
        cmp     DWORD(%%NUM_BLOCKS), 11
        je      %%_small_initial_num_blocks_is_11
        ja      %%_small_initial_num_blocks_is_12
        cmp     DWORD(%%NUM_BLOCKS), 6
        je      %%_small_initial_num_blocks_is_6
        jb      %%_small_initial_num_blocks_is_5
        cmp     DWORD(%%NUM_BLOCKS), 9
        je      %%_small_initial_num_blocks_is_9
        ja      %%_small_initial_num_blocks_is_10
        cmp     DWORD(%%NUM_BLOCKS), 8
        je      %%_small_initial_num_blocks_is_8
        jmp     %%_small_initial_num_blocks_is_7

%assign n 16
%rep 15
align_label
%%_small_initial_num_blocks_is_ %+ n :
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, n, \
                %%ENC_DEC, %%INSTANCE_TYPE
        jmp     %%_small_initial_blocks_encrypted
%assign n (n - 1)
%endrep

align_label
%%_small_initial_num_blocks_is_1:
        INITIAL_BLOCKS_PARTIAL  %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, \
                %%PLAIN_CIPH_IN, %%LENGTH, %%DATA_OFFSET, 1, \
                %%ENC_DEC, %%INSTANCE_TYPE
align_label
%%_small_initial_blocks_encrypted:

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

        xor     DWORD(%%DATA_OFFSET), DWORD(%%DATA_OFFSET)
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

        ;; Save the amount of data left to process in r13
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
        ;; Determine how many blocks to process in INITIAL
        mov     r12, r13
        add     r12, 15
        shr     r12, 4

        ;;      Less than 256 bytes will be handled by the small message code, which
        ;;      can process up to 7 16B blocks.
        cmp     r13, 256
        jae     %%_large_message_path

        GCM_ENC_DEC_SMALL %%GDATA_KEY, %%GDATA_CTX, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%PLAIN_CIPH_LEN, %%ENC_DEC, %%DATA_OFFSET, r13, r12, xmm9, xmm14, %%INSTANCE_TYPE
        jmp     %%_ghash_done

align_label
%%_large_message_path:
        mov     r10d, NROUNDS
        mov     r15, rsp
%ifidn %%ENC_DEC, ENC
        call    gcm_initial_blocks_enc_vaes_avx2
%else
        call    gcm_initial_blocks_dec_vaes_avx2
%endif

align_label
%%_initial_blocks_encrypted:
        ;; in_order vs. out_order is an optimization to increment the counter without shuffling
        ;; it back into little endian. r15d keeps track of when we need to increent in order so
        ;; that the carry is handled correctly.
        vmovd   r15d, xmm9
        and     r15d, 255
        vperm2i128 ymm9, ymm9, ymm9, 0x00
        vpshufb ymm9, ymm9, [rel SHUF_MASK]

        ;; The entire message was encrypted processed in initial and now need to be hashed
        or      r13, r13
        je      %%_encrypt_done

        ;; Encrypt the final <16 byte (partial) block, then hash
        cmp     r13, 16
        jb      %%_encrypt_final_partial

        mov     r12, rsp        ;; pointer to the blocks for GHASH

        ;; Process 15 full blocks plus a partial block
        cmp     r13, 256
        jb      %%_encrypt_by_16_partial

align_loop
%%_encrypt_by_16_new:
        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%DATA_OFFSET, %%ENC_DEC, full, r15
        add     %%DATA_OFFSET, 256
        sub     r13, 256
        jz      %%_encrypt_done
        cmp     r13, 256
        jae     %%_encrypt_by_16_new

align_label
%%_encrypt_by_16_partial:
        GHASH_16_ENCRYPT_16_PARALLEL  %%GDATA_KEY, %%CIPH_PLAIN_OUT, %%PLAIN_CIPH_IN, %%DATA_OFFSET, %%ENC_DEC, partial, r15
        add     %%DATA_OFFSET, 256 - 16
        sub     r13, 256 - 16

align_label
%%_encrypt_final_partial:
        ;; TMP16  - Final encrypted counter - need to hash with partial or full block ciphertext
        vmovdqa xmm15, [rsp + TMP16]
        vpshufb xmm15, xmm15, [rel SHUF_MASK]
        mov     [%%GDATA_CTX + PBlockLen], r13
        vmovdqu [%%GDATA_CTX + PBlockEncKey], xmm15

        ;; Handle a partial final block
        ;; xmm15 encrypted counter block
%ifidn %%ENC_DEC, DEC
        call    gcm_dec_final_partial_block_vaes_avx2
%else
        call    gcm_enc_final_partial_block_vaes_avx2
%endif
        vpshufb xmm15, xmm15, [rel SHUF_MASK]
        vinserti128 ymm8, xmm15, 1

align_label
%%_encrypt_done:
        vpshufb xmm9, xmm9, [rel SHUF_MASK]

        ;; Register contents at this stage:
        ;;   xmm9 contains the counter block
        ;;   xmm1 - xmm8 contain the cipher text blocks
        ;;   xmm14 contains the final hash
%ifidn %%INSTANCE_TYPE, multi_call
        mov     r13, [%%GDATA_CTX + PBlockLen]
        or      r13, r13
        jz      %%_hash_last_16
        call    ghash_15_vaes_avx2
        ;; XOR the partial word into the hash
        vpxor   xmm14, xmm14, xmm15
        jmp     %%_ghash_done
%endif
align_label
%%_hash_last_16:
        call    ghash_16_vaes_avx2

align_label
%%_ghash_done:
        vmovdqu [%%GDATA_CTX + CurCount], xmm9  ; my_ctx_data.current_counter = xmm9
        vmovdqu [%%GDATA_CTX + AadHash], xmm14  ; my_ctx_data.aad hash = xmm14

align_label
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
        mov     r12, [%%GDATA_CTX + PBlockLen]
        or      r12, r12

        je %%_partial_done

        GHASH_MUL2 xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6 ;GHASH computation for the last <16 Byte block

align_label
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

align_label
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
align_label
%%_T_8:
        vmovq   rax, xmm9
        mov     [r10], rax
        jmp     %%_return_T_done
align_label
%%_T_12:
        vmovq   rax, xmm9
        mov     [r10], rax
        vpsrldq xmm9, xmm9, 8
        vmovd   eax, xmm9
        mov     [r10 + 8], eax
        jmp     %%_return_T_done
align_label
%%_T_16:
        vmovdqu  [r10], xmm9

align_label
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
        mov     r13, [%%GDATA_CTX + PBlockLen]

        ; Read in input data without over reading
        cmp     %%PLAIN_LEN, 16
        jl      %%_fewer_than_16_bytes
        ; If more than 16 bytes of data, just fill the xmm register
        VXLDR   %%XMM1, [%%PLAIN_IN]
        jmp     %%_data_read

align_label
%%_fewer_than_16_bytes:
        lea     r10, [%%PLAIN_IN]
        READ_SMALL_DATA_INPUT_AVX       %%XMM1, r10, %%PLAIN_LEN, rax
        ; Finished reading in data
align_label
%%_data_read:

        lea     r12, [rel SHIFT_MASK]
        ; Adjust the shuffle mask pointer to be able to shift r13 bytes
        ; (16-r13 is the number of bytes in plaintext mod 16)
        add     r12, r13
        ; Get the appropriate shuffle mask
        vmovdqu %%XMM2, [r12]
        vmovdqa %%XMM3, %%XMM1

        mov     r15, %%PLAIN_LEN
        add     r15, r13
        ; Set r15 to be the amount of data left in PLAIN_IN after filling the block
        sub     r15, 16
        ; Determine if partial block is not being filled and shift mask accordingly
        jge     %%_no_extra_mask_1
        sub     r12, r15
align_label
%%_no_extra_mask_1:

        ; Get the appropriate mask to mask out bottom r13 bytes of %%XMM3
        vmovdqu %%XMM1, [r12 + ALL_F-SHIFT_MASK]

        vpand   %%XMM3, %%XMM3, %%XMM1
        vpshufb %%XMM3, %%XMM3, [rel SHUF_MASK]
        vpshufb %%XMM3, %%XMM3, %%XMM2
        vpxor   %%AAD_HASH, %%AAD_HASH, %%XMM3

        or      r15, r15
        jl      %%_partial_incomplete_1

        ; GHASH computation for the last <16 Byte block
        GHASH_MUL2      %%AAD_HASH, %%HASH_SUBKEY, %%HASHK_SUBKEY, %%XMM0, %%XMM10, %%XMM11, %%XMM5
        xor     rax, rax
        mov     [%%GDATA_CTX + PBlockLen], rax
        jmp     %%_ghash_done
align_label
%%_partial_incomplete_1:
%ifidn __OUTPUT_FORMAT__, win64
        mov     rax, %%PLAIN_LEN
        add     [%%GDATA_CTX + PBlockLen], rax
%else
        add     [%%GDATA_CTX + PBlockLen], %%PLAIN_LEN
%endif
align_label
%%_ghash_done:
        vmovdqu [%%GDATA_CTX + AadHash], %%AAD_HASH

        or      r15, r15
        jl      %%_partial_fill

        mov     r12, 16
        ; Set r12 to be the number of bytes to skip after this macro
        sub     r12, r13

        jmp     %%offset_set
align_label
%%_partial_fill:
        mov     r12, %%PLAIN_LEN
align_label
%%offset_set:
        mov     %%DATA_OFFSET, r12

%endmacro ; PARTIAL_BLOCK_GMAC
