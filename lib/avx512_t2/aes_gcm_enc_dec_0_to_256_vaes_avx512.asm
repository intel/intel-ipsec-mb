;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2025, Intel Corporation All rights reserved.
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
%define GCM128_MODE 1
%include "include/align_avx512.inc"
%include "include/gcm_vaes_avx512.inc"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; External symbols
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
extern ghash_internal_vaes_avx512

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; GCM_ENC_DEC_0_TO_256
;; - combines and optimizes functionality of three macros:
;;   - GCM_INIT
;;   - GCM_ENC_DEC
;;   - GCM_COMPLETE
;; - works for packet sizes between 0 and 256 bytes
;; - it is limited to single_call case only
;; - works with AAD size
;; - works with IV size provided IV length is provided
;; Output: C and T
;; Clobbers rax, r12, r13, zmm0-zmm23, zmm26-zmm29, zmm30, zmm31, k1, k2, r11 (windows)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_ENC_DEC_0_TO_256 12
%define %%GDATA_KEY         %1  ; [in] key pointer
%define %%CIPH_PLAIN_OUT    %2  ; [in] output buffer pointer
%define %%PLAIN_CIPH_IN     %3  ; [in] input buffer pointer
%define %%PLAIN_CIPH_LEN    %4  ; [in] buffer length
%define %%IV                %5  ; [in] IV pointer
%define %%A_IN              %6  ; [in] AAD pointer
%define %%A_LEN             %7  ; [in] AAD length in bytes
%define %%AUTH_TAG          %8  ; [in] pointer to store auth tag into (GP or mem)
%define %%AUTH_TAG_LEN      %9  ; [in] length in bytes of auth tag (GP or mem)
%define %%ENC_DEC           %10 ; [in] cipher direction
%define %%ROUNDS            %11 ; [in] number of rounds
%define %%IV_LEN            %12 ; [in] IV length

%define %%IA0               rax
%define %%IA1               r12
%define %%IA2               r13
%define %%IA3               r11

%define %%CTR_BLOCKz            zmm0
%define %%CTR_BLOCKx            xmm0 ; hardcoded in GCM_INIT

%define %%AAD_HASHz             zmm1
%define %%AAD_HASHy             ymm1
%define %%AAD_HASHx             xmm1 ; hardcoded in GCM_COMPLETE

%define %%SHUF_MASK             zmm30
%define %%SHUF_MASKy            ymm30
%define %%SHUF_MASKx            xmm30

%define %%ORIG_IV               zmm31
%define %%ORIG_IVx              xmm31

%define %%ZTMP0                 zmm2
%define %%ZTMP1                 zmm3
%define %%ZTMP2                 zmm4
%define %%ZTMP3                 zmm5
%define %%ZTMP4                 zmm6
%define %%ZTMP5                 zmm7
%define %%ZTMP6                 zmm8
%define %%ZTMP7                 zmm9
%define %%ZTMP8                 zmm10 ; used by ghash()
%define %%ZTMP9                 zmm11 ; used by ghash()
%define %%ZTMP10                zmm12
%define %%ZTMP11                zmm13
%define %%ZTMP12                zmm14
%define %%ZTMP13                zmm15
%define %%ZTMP14                zmm16
%define %%ZTMP15                zmm17
%define %%ZTMP16                zmm18
%define %%ZTMP17                zmm19
%define %%ZTMP18                zmm20
%define %%ZTMP19                zmm21
%define %%ZTMP20                zmm22
%define %%ZTMP21                zmm23
%define %%ZTMP22                zmm24 ; not used
%define %%ZTMP23                zmm25 ; not used
%define %%ZTMP24                zmm26
%define %%ZTMP25                zmm27
%define %%ZTMP26                zmm28
%define %%ZTMP27                zmm29

%define %%DAT0                  %%ZTMP24
%define %%DAT1                  %%ZTMP25
%define %%DAT2                  %%ZTMP26
%define %%DAT3                  %%ZTMP27

%define %%MASK_TEXT             k1
%define %%MASK_TAG              k1
%define %%MASK_IVAAD            k2

        ;; ===================================================================
        ;; prepare IV
        ;; IV may be different than 12 bytes
        cmp     %%IV_LEN, 12
        je      %%_iv_length_is_12_bytes

        CALC_J0 %%GDATA_KEY, %%IV, %%IV_LEN, %%ORIG_IVx
        jmp     %%_iv_prep_is_done

align_label
%%_iv_length_is_12_bytes:
        ;; read 12 IV bytes and pad with 0x00000001
        vmovdqa64       %%ORIG_IVx, [rel ONEf]
        mov             %%IA2, %%IV
        mov             DWORD(%%IA1), 0x0000_0fff
        kmovd           %%MASK_IVAAD, DWORD(%%IA1)
        vmovdqu8        %%ORIG_IVx{%%MASK_IVAAD}, [%%IA2]      ; ctr = IV | 0x1

align_label
%%_iv_prep_is_done:
        ;; set up context fields
        vpshufb %%CTR_BLOCKx, %%ORIG_IVx, [rel SHUF_MASK]

        ;; ===================================================================
        ;; check for zero message length

%ifidn __OUTPUT_FORMAT__, win64
        cmp     %%PLAIN_CIPH_LEN, 0
%else
        or      %%PLAIN_CIPH_LEN, %%PLAIN_CIPH_LEN
%endif
        je      %%_small_initial_num_blocks_is_0

        ;; ===================================================================
        ;; Prepare %%LENGTH register
%ifidn __OUTPUT_FORMAT__, win64
%define %%LENGTH            %%IA3
        mov     %%LENGTH, %%PLAIN_CIPH_LEN
%else
%define %%LENGTH %%PLAIN_CIPH_LEN        ;; PLAIN_CIPH_LEN is a register on linux
%endif
        ;; ===================================================================
        ;; Determine how many blocks to process
        ;; - process one additional block if there is a partial block (round up)

%define %%NUM_BLOCKS        %%IA1

        mov     DWORD(%%NUM_BLOCKS), DWORD(%%LENGTH)
        add     DWORD(%%NUM_BLOCKS), 15
        shr     DWORD(%%NUM_BLOCKS), 4
        ;; %%NUM_BLOCKS can be in the range from 0 to 16

        cmp     DWORD(%%NUM_BLOCKS), 8
        je      %%_small_initial_num_blocks_is_8
        jb      %%_small_initial_num_blocks_is_7_1

        cmp     DWORD(%%NUM_BLOCKS), 12
        je      %%_small_initial_num_blocks_is_12
        jb      %%_small_initial_num_blocks_is_11_9

        ;; 16, 15, 14 or 13
        cmp     DWORD(%%NUM_BLOCKS), 15
        ja      %%_small_initial_num_blocks_is_16
        je      %%_small_initial_num_blocks_is_15
        cmp     DWORD(%%NUM_BLOCKS), 14
        je      %%_small_initial_num_blocks_is_14
        jmp     %%_small_initial_num_blocks_is_13

align_label
%%_small_initial_num_blocks_is_11_9:
        ;; 11, 10 or 9
        cmp     DWORD(%%NUM_BLOCKS), 10
        ja      %%_small_initial_num_blocks_is_11
        je      %%_small_initial_num_blocks_is_10
        jmp     %%_small_initial_num_blocks_is_9

align_label
%%_small_initial_num_blocks_is_7_1:
        cmp     DWORD(%%NUM_BLOCKS), 4
        je      %%_small_initial_num_blocks_is_4
        jb      %%_small_initial_num_blocks_is_3_1
        ;; 7, 6 or 5
        cmp     DWORD(%%NUM_BLOCKS), 6
        ja      %%_small_initial_num_blocks_is_7
        je      %%_small_initial_num_blocks_is_6
        jmp     %%_small_initial_num_blocks_is_5

align_label
%%_small_initial_num_blocks_is_3_1:
        ;; 3, 2 or 1
        cmp     DWORD(%%NUM_BLOCKS), 2
        ja      %%_small_initial_num_blocks_is_3
        je      %%_small_initial_num_blocks_is_2

        ;; for %%NUM_BLOCKS == 1, just fall through and no 'jmp' needed

        ;; ===================================================================
        ;; Use rep to generate different optimized code for block size variants
        ;; - one block size variant has to be the first one

%assign num_blocks 1
%rep 16

        ;; ===================================================================
        ;; ===================================================================
        ;; Optimized small packet AES-GCM generation
        ;; - at this stage, IV is ready
        ;; - prepare counter blocks
        ;; - do AES-CTR & encryption of original IV
        ;; - do AAD, GHASH of message and block with sizes

align_label
%%_small_initial_num_blocks_is_ %+ num_blocks :

%define %%CTR0                  %%ZTMP0
%define %%CTR1                  %%ZTMP1
%define %%CTR2                  %%ZTMP2
%define %%CTR3                  %%ZTMP3

        ;; ===================================================================
        ;; - load shuffle mask
        ;; - retrieve 32-bit counter in BE format
%if num_blocks == 1
        vmovdqa64       %%SHUF_MASKx, [rel SHUF_MASK]
%elif num_blocks == 2
        vmovdqa64       %%SHUF_MASKy, [rel SHUF_MASK]
%else
        vmovdqa64       %%SHUF_MASK, [rel SHUF_MASK]
%endif
        vmovd           DWORD(%%IA2), %%CTR_BLOCKx

        ;; ===================================================================
        ;; get load/store mask for plain/cipher text
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
%if num_blocks > 12
        sub             %%IA1, 3 * 64
%elif num_blocks > 8
        sub             %%IA1, 2 * 64
%elif num_blocks > 4
        sub             %%IA1, 64
%endif
        kmovq           %%MASK_TEXT, [%%IA0 + %%IA1*8]

        ;; ===================================================================
        ;; Check if counter blocks can be prepared in BE format or
        ;; LE format is required
        cmp             BYTE(%%IA2), 256 - num_blocks
        jae             %%_ctr_overflow_ %+ num_blocks

        ;; ===================================================================
        ;; Prepare AES counter blocks (BE format, no byte overflow)
%if num_blocks == 1
        vpaddd          XWORD(%%CTR0), %%ORIG_IVx, [rel ONEf]
%elif num_blocks == 2
        vshufi64x2      YWORD(%%CTR0), YWORD(%%ORIG_IV), YWORD(%%ORIG_IV), 0
        vpaddd          YWORD(%%CTR0), YWORD(%%CTR0), [rel ddq_addbe_1234]
%else
        vshufi64x2      %%CTR_BLOCKz, %%ORIG_IV, %%ORIG_IV, 0
        vpaddd          %%CTR0, %%CTR_BLOCKz, [rel ddq_addbe_1234]
%if num_blocks > 4
        vpaddd          %%CTR1, %%CTR_BLOCKz, [rel ddq_addbe_5678]
%endif
%if num_blocks > 8
        vpaddd          %%CTR2, %%CTR0, [rel ddq_addbe_8888]
%endif
%if num_blocks > 12
        vpaddd          %%CTR3, %%CTR1, [rel ddq_addbe_8888]
%endif
%endif
        jmp             %%_ctr_ready_ %+ num_blocks

align_label
%%_ctr_overflow_ %+ num_blocks :
        ;; ===================================================================
        ;; Prepare AES counter blocks (LE format, byte overflow)
%if num_blocks == 1
        vpaddd          XWORD(%%CTR0), %%CTR_BLOCKx, [rel ONE]
%elif num_blocks == 2
        vshufi64x2      YWORD(%%CTR0), YWORD(%%CTR_BLOCKz), YWORD(%%CTR_BLOCKz), 0
        vpaddd          YWORD(%%CTR0), YWORD(%%CTR0), [rel ddq_add_1234]
%else
        vshufi64x2      %%CTR_BLOCKz, %%CTR_BLOCKz, %%CTR_BLOCKz, 0
        vpaddd          %%CTR0, %%CTR_BLOCKz, [rel ddq_add_1234]
%if num_blocks > 4
        vpaddd          %%CTR1, %%CTR_BLOCKz, [rel ddq_add_5678]
%endif
%if num_blocks > 8
        vpaddd          %%CTR2, %%CTR0, [rel ddq_add_8888]
%endif
%if num_blocks > 12
        vpaddd          %%CTR3, %%CTR1, [rel ddq_add_8888]
%endif
%endif

        ;; ===================================================================
        ;; shuffle the counter blocks for AES rounds
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks, vpshufb, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%SHUF_MASK, %%SHUF_MASK, %%SHUF_MASK, %%SHUF_MASK

align_label
%%_ctr_ready_ %+ num_blocks :

        ;; ===================================================================
        ;; append original IV to message blocks for AES encryption, if possible

%if (num_blocks % 4) != 0
%assign num_blocks_aes (num_blocks + 1)
%assign blend_orig_iv_aes 1

%if (num_blocks >= 14) && (num_blocks <= 15)
        vinserti64x2    %%CTR3, %%ORIG_IVx, num_blocks - 12
%elif (num_blocks == 13)
        vinserti64x2    YWORD(%%CTR3), %%ORIG_IVx, num_blocks - 12
%elif (num_blocks >= 10) && (num_blocks <= 11)
        vinserti64x2    %%CTR2, %%ORIG_IVx, num_blocks - 8
%elif (num_blocks == 9)
        vinserti64x2    YWORD(%%CTR2), %%ORIG_IVx, num_blocks - 8
%elif (num_blocks >= 6) && (num_blocks <= 7)
        vinserti64x2    %%CTR1, %%ORIG_IVx, num_blocks - 4
%elif (num_blocks == 5)
        vinserti64x2    YWORD(%%CTR1), %%ORIG_IVx, num_blocks - 4
%elif (num_blocks >= 2) && (num_blocks <= 3)
        vinserti64x2    %%CTR0, %%ORIG_IVx, num_blocks
%else ; (num_blocks == 1)
        vinserti64x2    YWORD(%%CTR0), %%ORIG_IVx, num_blocks
%endif

%else
        ;; 16, 12, 8, 4 or 0 block cases
%assign num_blocks_aes num_blocks
%assign blend_orig_iv_aes 0
%endif

        ;; ===================================================================
        ;; load plain/cipher text
        ZMM_LOAD_MASKED_BLOCKS_0_16 num_blocks, %%PLAIN_CIPH_IN, 0, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, %%MASK_TEXT


        ;; ===================================================================
        ;; AES rounds and XOR with plain/cipher text

        vbroadcastf64x2 %%ZTMP10, [%%GDATA_KEY]
%if blend_orig_iv_aes == 0
        vpxorq          %%ORIG_IVx, %%ORIG_IVx, XWORD(%%ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_aes, vpxorq, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%ZTMP10, %%ZTMP10, %%ZTMP10, %%ZTMP10

        lea             %%IA1, [%%GDATA_KEY + 16]

align_loop
%%_aesenc_loop %+ num_blocks :

        vbroadcastf64x2 %%ZTMP10, [%%IA1]
%if blend_orig_iv_aes == 0
        vaesenc          %%ORIG_IVx, %%ORIG_IVx, XWORD(%%ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_aes, vaesenc, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%ZTMP10, %%ZTMP10, %%ZTMP10, %%ZTMP10

        add             %%IA1, 16 ; increment key pointer
        dec             %%ROUNDS ; decrement rounds counter
        jnz             %%_aesenc_loop %+ num_blocks

        ;; last round
        vbroadcastf64x2 %%ZTMP10, [%%IA1]
%if blend_orig_iv_aes == 0
        vaesenclast     %%ORIG_IVx, %%ORIG_IVx, XWORD(%%ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_aes, vaesenclast, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%ZTMP10, %%ZTMP10, %%ZTMP10, %%ZTMP10

        ;; ===================================================================
        ;; Extract encrypted original IV
%if blend_orig_iv_aes != 0
%if num_blocks >= 12
        vextracti32x4   %%ORIG_IVx, %%CTR3, num_blocks - 12
%elif num_blocks >= 8
        vextracti32x4   %%ORIG_IVx, %%CTR2, num_blocks - 8
%elif num_blocks >= 4
        vextracti32x4   %%ORIG_IVx, %%CTR1, num_blocks - 4
%else
        vextracti32x4   %%ORIG_IVx, %%CTR0, num_blocks
%endif
%endif

        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks, vpxorq, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3

        ;; ===================================================================
        ;; write cipher/plain text back to output and
        ZMM_STORE_MASKED_BLOCKS_0_16 num_blocks, %%CIPH_PLAIN_OUT, 0, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, %%MASK_TEXT

        ;; ===================================================================
        ;; Shuffle the cipher text blocks for hashing part
        ;; - GHASH always works on cipher text
%ifidn  %%ENC_DEC, DEC
        ;; Decrypt case
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks, vpshufb, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%SHUF_MASK, %%SHUF_MASK, %%SHUF_MASK, %%SHUF_MASK
%else
        ;; Encrypt case

        ;; - zero bytes outside the mask before hashing
%if num_blocks <= 4
        vmovdqu8        %%CTR0{%%MASK_TEXT}{z}, %%CTR0
%elif num_blocks <= 8
        vmovdqu8        %%CTR1{%%MASK_TEXT}{z}, %%CTR1
%elif num_blocks <= 12
        vmovdqu8        %%CTR2{%%MASK_TEXT}{z}, %%CTR2
%else
        vmovdqu8        %%CTR3{%%MASK_TEXT}{z}, %%CTR3
%endif

        ;; - cipher blocks are in CTR0-CTR3
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks, vpshufb, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%SHUF_MASK, %%SHUF_MASK, %%SHUF_MASK, %%SHUF_MASK
%endif                          ; Encrypt

        ;; ===================================================================
        ;; Calculate AAD hash
        cmp             %%A_LEN, 12
        jne             %%_aad_is_not_12_bytes_ %+ num_blocks

        ;; ===================================================================
        ;; load 12 bytes of AAD (most common case)
        ;; - AAD and block with sizes get hashed together
        ;; - one reduction for everything (AAD + message + length block)

        ;; IV may be different than 12 bytes and %%MASK_IVAAD not set
        mov             DWORD(%%IA1), 0x0000_0fff
        kmovd           %%MASK_IVAAD, DWORD(%%IA1)

        mov             %%IA1, %%A_IN
        vmovdqu8        %%AAD_HASHx{%%MASK_IVAAD}{z}, [%%IA1]
        vpshufb         %%AAD_HASHx, %%AAD_HASHx, %%SHUF_MASKx

        vmovq           XWORD(%%ZTMP15), %%PLAIN_CIPH_LEN
        vpinsrq         XWORD(%%ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(%%ZTMP15), XWORD(%%ZTMP15), 3     ; convert bytes into bits
        vinserti64x2    %%AAD_HASHy, XWORD(%%ZTMP15), 1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; GHASH 12 byte AAD with length block using respective GHASH key powers
        ;; AAD_HASHy = [ AAD: 0-127 | LENGTH: 128-255 ]
        ;; HASH_KEY  = [ HK ^ (N + 2) | HK ^ 1 ]

%assign num_blocks2 (num_blocks + 2)
%define %%HKeyN2 HashKey_ %+ num_blocks2

        vmovdqu8        XWORD(%%ZTMP13), [%%GDATA_KEY + %%HKeyN2 + HKeyGap]
        vinserti64x2    YWORD(%%ZTMP13), [%%GDATA_KEY + HashKey_1 + HKeyGap], 1
        vpclmulqdq      YWORD(%%ZTMP14), %%AAD_HASHy, YWORD(%%ZTMP13), 0x00     ; TLL = GH_L * KK_L
        vpclmulqdq      YWORD(%%ZTMP15), %%AAD_HASHy, YWORD(%%ZTMP13), 0x10     ; TLH = GH_L * KK_H
        vmovdqu8        XWORD(%%ZTMP13), [%%GDATA_KEY + %%HKeyN2]
        vinserti64x2    YWORD(%%ZTMP13), [%%GDATA_KEY + HashKey_1], 1
        vpclmulqdq      YWORD(%%ZTMP16), %%AAD_HASHy, YWORD(%%ZTMP13), 0x01     ; THL = GH_H * HK_L
        vpclmulqdq      YWORD(%%ZTMP17), %%AAD_HASHy, YWORD(%%ZTMP13), 0x11     ; THH = GH_H * HK_H

%undef %%HKeyN2

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; add products

        vpxorq          YWORD(%%ZTMP14), YWORD(%%ZTMP14), YWORD(%%ZTMP16)       ;; TLL += THL
        vpxorq          YWORD(%%ZTMP15), YWORD(%%ZTMP15), YWORD(%%ZTMP17)       ;; TLH += THH

        ;; ===================================================================
        ;; continue with message GHASH followed by reduction
        ;;
        ;; Hash key powers and corresponding message blocks:
        ;;   HASH_KEY  = [ HK ^ (N + 1), HK ^ N, ... HK ^ 2 ]
        ;;   MSG       = [ MSG1,         MSG2,   ... MSGN ]

        GHASH_1_TO_16 %%GDATA_KEY, %%AAD_HASHx, \
                        %%ZTMP10, %%ZTMP11, %%ZTMP12, %%ZTMP13, %%ZTMP20, \
                        %%ZTMP21, %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, \
                        1, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, num_blocks, %%ZTMP15, %%ZTMP14

        jmp             %%_small_initial_blocks_encrypted

align_label
%%_aad_is_not_12_bytes_ %+ num_blocks:
        ;; ===================================================================
        ;; Calculate AAD hash (different than 12 bytes)

        vpxor           xmm0, xmm0, xmm0
        ;; arg1 - GDATA_KEY
        ;; r12 - message pointer
        ;; r13 - message length
        ;; xmm0 - hash in/out
        mov             r12, %%A_IN
        mov             r13, %%A_LEN
        call            ghash_internal_vaes_avx512
        vmovdqa64       %%AAD_HASHx, xmm0

%if num_blocks == 16
        ;; ===================================================================
        ;; message GHASH compute
        GHASH_1_TO_16 %%GDATA_KEY, %%AAD_HASHx, \
                        %%ZTMP10, %%ZTMP11, %%ZTMP12, %%ZTMP13, %%ZTMP14, \
                        %%ZTMP15, %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, %%AAD_HASHz, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, num_blocks

        ;; ===================================================================
        ;; GHASH length block
        vmovdqu8        XWORD(%%ZTMP13), [%%GDATA_KEY + HashKey_1]
        vmovdqu8        XWORD(%%ZTMP14), [%%GDATA_KEY + HashKey_1 + HKeyGap]

        vmovq           XWORD(%%ZTMP15), %%PLAIN_CIPH_LEN
        vpinsrq         XWORD(%%ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(%%ZTMP15), XWORD(%%ZTMP15), 3     ; convert bytes into bits

        vpxorq          %%AAD_HASHx, %%AAD_HASHx, XWORD(%%ZTMP15)
        GHASH_MUL2      %%AAD_HASHx, XWORD(%%ZTMP13), XWORD(%%ZTMP14), XWORD(%%ZTMP16), XWORD(%%ZTMP17), XWORD(%%ZTMP18), XWORD(%%ZTMP19)

%else
        ;; ===================================================================
        ;; create & append length block into message for GHASH
        vmovq           XWORD(%%ZTMP15), %%PLAIN_CIPH_LEN
        vpinsrq         XWORD(%%ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(%%ZTMP15), XWORD(%%ZTMP15), 3     ; convert bytes into bits

%if num_blocks == 12
        vmovdqa64       XWORD(%%DAT3), XWORD(%%ZTMP15)
%elif num_blocks > 12
        vinserti64x2    %%DAT3, XWORD(%%ZTMP15), num_blocks - 12
%elif num_blocks == 8
        vmovdqa64       XWORD(%%DAT2), XWORD(%%ZTMP15)
%elif num_blocks > 8
        vinserti64x2    %%DAT2, XWORD(%%ZTMP15), num_blocks - 8
%elif num_blocks == 4
        vmovdqa64       XWORD(%%DAT1), XWORD(%%ZTMP15)
%elif num_blocks > 4
        vinserti64x2    %%DAT1, XWORD(%%ZTMP15), num_blocks - 4
%else
        vinserti64x2    %%DAT0, XWORD(%%ZTMP15), num_blocks
%endif

        ;; ===================================================================
        ;; message + length block GHASH compute

%assign num_blocks2 (num_blocks + 1)

        GHASH_1_TO_16 %%GDATA_KEY, %%AAD_HASHx, \
                        %%ZTMP10, %%ZTMP11, %%ZTMP12, %%ZTMP13, %%ZTMP14, \
                        %%ZTMP15, %%ZTMP16, %%ZTMP17, %%ZTMP18, %%ZTMP19, %%AAD_HASHz, \
                        %%DAT0, %%DAT1, %%DAT2, %%DAT3, num_blocks2

%endif
        jmp             %%_small_initial_blocks_encrypted

        ;; ===================================================================
        ;; increment number of blocks and repeat code generation
%assign num_blocks (num_blocks + 1)

%endrep

        ;; ===================================================================
        ;; Zero message size case (not optimized, not used very often)
align_label
%%_small_initial_num_blocks_is_0:
        vmovdqa64       %%SHUF_MASKx, [rel SHUF_MASK]

        ;; ===================================================================
        ;; calculate AAD hash for 0 message length case
        vpxor           xmm0, xmm0, xmm0
        ;; arg1 - GDATA_KEY
        ;; r12 - message pointer
        ;; r13 - message length
        ;; xmm0 - hash in/out
        mov             r12, %%A_IN
        mov             r13, %%A_LEN
        call            ghash_internal_vaes_avx512
        vmovdqa64       %%AAD_HASHx, xmm0

        ;; ===================================================================
        ;; encrypt original IV
        vpxorq          %%ORIG_IVx, %%ORIG_IVx, [%%GDATA_KEY]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*1]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*2]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*3]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*4]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*5]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*6]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*7]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*8]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*9]

        cmp             %%ROUNDS, 11
        jb              %%_single_block_128
        je              %%_single_block_192

        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*10]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*11]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*12]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*13]
        vaesenclast     %%ORIG_IVx, [%%GDATA_KEY + 16*14]
        jmp             %%_ghash_length_block

align_label
%%_single_block_192:
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*10]
        vaesenc         %%ORIG_IVx, [%%GDATA_KEY + 16*11]
        vaesenclast     %%ORIG_IVx, [%%GDATA_KEY + 16*12]
        jmp             %%_ghash_length_block

align_label
%%_single_block_128:
        vaesenclast     %%ORIG_IVx, [%%GDATA_KEY + 16*10]

        ;; ===================================================================
        ;; GHASH length block
align_label
%%_ghash_length_block:
        vmovdqu8        XWORD(%%ZTMP13), [%%GDATA_KEY + HashKey_1]
        vmovdqu8        XWORD(%%ZTMP14), [%%GDATA_KEY + HashKey_1 + HKeyGap]

        vpxorq          XWORD(%%ZTMP15), XWORD(%%ZTMP15), XWORD(%%ZTMP15)       ; len(C) = 0
        vpinsrq         XWORD(%%ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(%%ZTMP15), XWORD(%%ZTMP15), 3     ; convert bytes into bits

        vpxorq          %%AAD_HASHx, %%AAD_HASHx, XWORD(%%ZTMP15)
        GHASH_MUL2      %%AAD_HASHx, XWORD(%%ZTMP13), XWORD(%%ZTMP14), XWORD(%%ZTMP16), XWORD(%%ZTMP17), XWORD(%%ZTMP18), XWORD(%%ZTMP19)

align_label
%%_small_initial_blocks_encrypted:
        ;; ===================================================================
        ;; Complete GMAC computation
        ;;     S => %%AAD_HASHx
        ;;     CIPHER(J0) => %%ORIG_IVx
        ;; T = MSB(GCTR(J0,S))
        vpshufb         %%AAD_HASHx, %%AAD_HASHx, %%SHUF_MASKx
        vpxorq          %%ORIG_IVx, %%ORIG_IVx, %%AAD_HASHx

        ;; ===================================================================
        ;; Store the tag T
        mov             %%IA0, %%AUTH_TAG
        mov             %%IA1, %%AUTH_TAG_LEN

        lea             %%IA2, [rel byte64_len_to_mask_table]
        kmovq           %%MASK_TAG, [%%IA2 + %%IA1*8]
        vmovdqu8        [%%IA0]{%%MASK_TAG}, %%ORIG_IVx

%endmacro                       ; GCM_ENC_DEC_0_TO_256

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; gcm_0_to_256_enc_wrapper_<mode>
;; Wrapper function for GCM_ENC_DEC_0_TO_256 macro - encryption case
;; Parameters:
;;   arg1 (rdi/rcx) = GDATA_KEY (const struct gcm_key_data *key_data)
;;   arg2 (rsi/rdx) = context_data (not used by 0-256 macro)
;;   arg3 (rdx/r8)  = CIPH_PLAIN_OUT (u8 *out)
;;   arg4 (rcx/r9)  = PLAIN_CIPH_IN (const u8 *in)
;;   arg5 (r8/stack) = PLAIN_CIPH_LEN (u64 msg_len)
;;   arg6 (r9/stack) = IV (u8 *iv)
;;   arg7 (stack)    = A_IN (const u8 *aad)
;;   arg8 (stack)    = A_LEN (u64 aad_len)
;;   arg9 (stack)    = AUTH_TAG (u8 *auth_tag)
;;   arg10 (stack)   = AUTH_TAG_LEN (u64 auth_tag_len)
;;   arg11 (r10)   = ROUNDS (number of AES rounds)
;;   arg12 (r11)   = IV_LEN (u64 iv_len)
;; Output: Encrypted data and auth tag
;; Clobbers: rax, r12, r13, zmm0-zmm23, zmm26-zmm31, k1, k2, r11 (windows)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(gcm_0_to_256_enc_wrapper_asm,function,internal)
gcm_0_to_256_enc_wrapper_asm:

        ;; Call the macro directly
        GCM_ENC_DEC_0_TO_256 arg1, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, ENC, r10, r11

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; gcm_0_to_256_dec_wrapper_<mode>
;; Wrapper function for GCM_ENC_DEC_0_TO_256 macro - decryption case
;; Parameters:
;;   arg1 (rdi/rcx) = GDATA_KEY (const struct gcm_key_data *key_data)
;;   arg2 (rsi/rdx) = context_data (not used by 0-256 macro)
;;   arg3 (rdx/r8)  = CIPH_PLAIN_OUT (u8 *out)
;;   arg4 (rcx/r9)  = PLAIN_CIPH_IN (const u8 *in)
;;   arg5 (r8/stack) = PLAIN_CIPH_LEN (u64 msg_len)
;;   arg6 (r9/stack) = IV (u8 *iv)
;;   arg7 (stack)    = A_IN (const u8 *aad)
;;   arg8 (stack)    = A_LEN (u64 aad_len)
;;   arg9 (stack)    = AUTH_TAG (u8 *auth_tag)
;;   arg10 (stack)   = AUTH_TAG_LEN (u64 auth_tag_len)
;;   arg11 (r10)   = ROUNDS (number of AES rounds)
;;   arg12 (r11)   = IV_LEN (u64 iv_len)
;; Output: Decrypted data and auth tag
;; Clobbers: rax, r12, r13, zmm0-zmm23, zmm26-zmm31, k1, k2, r11 (windows)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(gcm_0_to_256_dec_wrapper_asm,function,internal)
gcm_0_to_256_dec_wrapper_asm:

        ;; Call the macro directly
        GCM_ENC_DEC_0_TO_256 arg1, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, DEC, r10, r11

        ret
