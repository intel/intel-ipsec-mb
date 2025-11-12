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

mksection .rodata

align 4
byte_mask_12bytes:
        dw 0xfff

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Module register definitions to be used in standalone functions
;; (Not used within macros - macros use their own %% prefixed versions)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%define G_IA0                   rax
%define G_IA1                   rbx

%define GDATA_KEY               arg1
%define ROUNDS                  r10


%define G_CTR_BLOCKz            zmm0
%define G_CTR_BLOCKx            xmm0

%define G_AAD_HASHz             zmm1
%define G_AAD_HASHy             ymm1
%define G_AAD_HASHx             xmm1

%define G_SHUF_MASK             zmm30
%define G_SHUF_MASKy            ymm30
%define G_SHUF_MASKx            xmm30

%define G_ORIG_IV               zmm31
%define G_ORIG_IVx              xmm31

%define G_ZTMP0                 zmm2
%define G_ZTMP1                 zmm3
%define G_ZTMP2                 zmm4
%define G_ZTMP3                 zmm5
%define G_ZTMP4                 zmm6
%define G_ZTMP5                 zmm7
%define G_ZTMP6                 zmm8
%define G_ZTMP7                 zmm9
%define G_ZTMP8                 zmm10
%define G_ZTMP9                 zmm11
%define G_ZTMP10                zmm12
%define G_ZTMP11                zmm13
%define G_ZTMP12                zmm14
%define G_ZTMP13                zmm15
%define G_ZTMP14                zmm16
%define G_ZTMP15                zmm17
%define G_ZTMP16                zmm18
%define G_ZTMP17                zmm19
%define G_ZTMP18                zmm20
%define G_ZTMP19                zmm21
%define G_ZTMP20                zmm22
%define G_ZTMP21                zmm23
%define G_ZTMP22                zmm26
%define G_ZTMP23                zmm27
%define G_ZTMP24                zmm28
%define G_ZTMP25                zmm29

%define G_DAT0                  G_ZTMP22
%define G_DAT1                  G_ZTMP23
%define G_DAT2                  G_ZTMP24
%define G_DAT3                  G_ZTMP25

%define G_MASK_TEXT             k1
%define G_MASK_TAG              k1
%define G_MASK_IVAAD            k1

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate gcm_aes_ctr functions for different block counts and blend modes
;; Functions follow pattern: gcm_aes_ctr_N where:
;;   N = number of blocks (1-17)
;;
;; IN:
;;   arg1 (GDATA_KEY) - key pointer
;;   r10 (ROUNDS)     - number of AES rounds (9, 11, or 13)
;;   G_ZTMP0-G_ZTMP3  - counter blocks
;;   G_ORIG_IVx       - original IV if blend_orig_iv == 0
;;
;; OUT:
;;   G_ZTMP0-G_ZTMP3        - encrypted counter blocks
;;   G_ORIG_IVx            - encrypted original IV (if blend_orig_iv == 0)
;;
;; CLOBBERED:
;;   zmm12 (G_ZTMP10)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align_function
gcm_aes_ctr_1_vaes_avx512:
        vpxor           XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*0]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*1]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*2]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*3]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*4]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*5]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*6]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*7]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*8]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*9]
        cmp             DWORD(ROUNDS), 11
        jb              .encrypt_128bit_key_1
        je              .encrypt_192bit_key_1
        ;; fall through for 256bit key
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*10]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*11]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*12]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*13]
        vaesenclast     XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*14]
        ret

align_label
.encrypt_192bit_key_1:
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*10]
        vaesenc         XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*11]
        vaesenclast     XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*12]
        ret

align_label
.encrypt_128bit_key_1:
        vaesenclast     XWORD(G_ZTMP0), XWORD(G_ZTMP0), [GDATA_KEY + 16*10]
        ret


%assign num_blocks_outer 2
%rep 15
%if num_blocks_outer % 4 == 0
%assign blend_orig_iv_aes 0
%else 
%assign blend_orig_iv_aes 1
%endif

align_function
gcm_aes_ctr_ %+ num_blocks_outer %+ _vaes_avx512 :

        vbroadcasti64x2 G_ZTMP10, [GDATA_KEY]
%if blend_orig_iv_aes == 0
        vpxorq          G_ORIG_IVx, G_ORIG_IVx, XWORD(G_ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_outer, vpxorq, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP10, G_ZTMP10, G_ZTMP10, G_ZTMP10

%assign aesenc_round 1
%rep 9
        vbroadcasti64x2 G_ZTMP10, [GDATA_KEY + aesenc_round * 16]
%if blend_orig_iv_aes == 0
        vaesenc         G_ORIG_IVx, G_ORIG_IVx, XWORD(G_ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_outer, vaesenc, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP10, G_ZTMP10, G_ZTMP10, G_ZTMP10
%assign aesenc_round (aesenc_round + 1)
%endrep

        cmp     DWORD(ROUNDS), 11
        jb      .encrypt_128bit_key_ %+ num_blocks_outer
        je      .encrypt_192bit_key_ %+ num_blocks_outer
        ;; fall through for 256bit key

%assign aesenc_round 10
%rep 4
        vbroadcasti32x4 G_ZTMP10, [GDATA_KEY + aesenc_round * 16]
%if blend_orig_iv_aes == 0
        vaesenc         G_ORIG_IVx, G_ORIG_IVx, XWORD(G_ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_outer, vaesenc, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP10, G_ZTMP10, G_ZTMP10, G_ZTMP10
%assign aesenc_round (aesenc_round + 1)
%endrep

        vbroadcasti32x4 G_ZTMP10, [GDATA_KEY + aesenc_round * 16]
%if blend_orig_iv_aes == 0
        vaesenclast     G_ORIG_IVx, G_ORIG_IVx, XWORD(G_ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_outer, vaesenclast, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP10, G_ZTMP10, G_ZTMP10, G_ZTMP10
        ret

align_label
.encrypt_192bit_key_ %+ num_blocks_outer :
%assign aesenc_round 10
%rep 2
        vbroadcasti32x4 G_ZTMP10, [GDATA_KEY + aesenc_round * 16]
%if blend_orig_iv_aes == 0
        vaesenc         G_ORIG_IVx, G_ORIG_IVx, XWORD(G_ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_outer, vaesenc, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP10, G_ZTMP10, G_ZTMP10, G_ZTMP10
%assign aesenc_round (aesenc_round + 1)
%endrep

        vbroadcasti32x4 G_ZTMP10, [GDATA_KEY + aesenc_round * 16]
%if blend_orig_iv_aes == 0
        vaesenclast     G_ORIG_IVx, G_ORIG_IVx, XWORD(G_ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_outer, vaesenclast, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP10, G_ZTMP10, G_ZTMP10, G_ZTMP10
        ret

align_label
.encrypt_128bit_key_ %+ num_blocks_outer :
        vbroadcasti32x4 G_ZTMP10, [GDATA_KEY + 10 * 16]
%if blend_orig_iv_aes == 0
        vaesenclast     G_ORIG_IVx, G_ORIG_IVx, XWORD(G_ZTMP10)
%endif
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks_outer, vaesenclast, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP0, G_ZTMP1, G_ZTMP2, G_ZTMP3, \
                        G_ZTMP10, G_ZTMP10, G_ZTMP10, G_ZTMP10
        ret

%assign num_blocks_outer (num_blocks_outer + 1)
%endrep

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate gcm_ghash_ functions for different block counts
;; Functions follow pattern: gcm_ghash_N where:
;;   N = number of message blocks (1-16)
;;
;; IN:
;;   arg1 (GDATA_KEY) - key pointer (rdi on Linux, rcx on Windows)
;;   r12              - AAD pointer (12 bytes)
;;   r8               - message length in bytes
;;   r13              - AAD length in bytes (12)
;;   G_DAT0-G_DAT3      - shuffled cipher text blocks for GHASH
;;   G_SHUF_MASKx      - shuffle mask
;;
;; OUT:
;;   G_AAD_HASHx       - final GHASH result
;;
;; CLOBBERED:
;;   G_ZTMP10-G_ZTMP21
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%assign num_blocks_ghash 1
%rep 16

align_function
gcm_ghash_common_ %+ num_blocks_ghash %+ _vaes_avx512:

        GHASH_1_TO_16 GDATA_KEY, G_AAD_HASHx, \
        G_ZTMP10, G_ZTMP11, G_ZTMP12, G_ZTMP13, G_ZTMP20, \
        G_ZTMP21, G_ZTMP16, G_ZTMP17, G_ZTMP18, G_ZTMP19, \
        1, \
        G_DAT0, G_DAT1, G_DAT2, G_DAT3, num_blocks_ghash, G_ZTMP15, G_ZTMP14

        ret

align_function
gcm_ghash_ %+ num_blocks_ghash %+ _vaes_avx512:
%assign num_blocks2_ghash (num_blocks_ghash + 1)
%if num_blocks_ghash == 16

        GHASH_1_TO_16 GDATA_KEY, G_AAD_HASHx, \
                        G_ZTMP10, G_ZTMP11, G_ZTMP12, G_ZTMP13, G_ZTMP14, \
                        G_ZTMP15, G_ZTMP16, G_ZTMP17, G_ZTMP18, G_ZTMP19, G_AAD_HASHz, \
                        G_DAT0, G_DAT1, G_DAT2, G_DAT3, num_blocks_ghash

%else
        GHASH_1_TO_16 GDATA_KEY, G_AAD_HASHx, \
                        G_ZTMP10, G_ZTMP11, G_ZTMP12, G_ZTMP13, G_ZTMP14, \
                        G_ZTMP15, G_ZTMP16, G_ZTMP17, G_ZTMP18, G_ZTMP19, G_AAD_HASHz, \
                        G_DAT0, G_DAT1, G_DAT2, G_DAT3, num_blocks2_ghash

%endif
        ret
%assign num_blocks_ghash (num_blocks_ghash + 1)
%endrep

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
;; Clobbers rax, rbx, A_IN, zmm0-zmm23, zmm26-zmm31, k1, r11 (windows)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GCM_ENC_DEC_0_TO_256 12
%define %%GDATA_KEY         %1  ; [in] key pointer
%define %%CIPH_PLAIN_OUT    %2  ; [in] output buffer pointer
%define %%PLAIN_CIPH_IN     %3  ; [in] input buffer pointer
%define %%LENGTH            %4  ; [in] buffer length
%define %%IV                %5  ; [in] IV pointer
%define %%A_IN              %6  ; [in] AAD pointer
%define %%A_LEN             %7  ; [in] AAD length in bytes
%define %%AUTH_TAG          %8  ; [in] pointer to store auth tag into (GP or mem)
%define %%AUTH_TAG_LEN      %9  ; [in] length in bytes of auth tag (GP or mem)
%define %%ENC_DEC           %10 ; [in] cipher direction
%define %%ROUNDS            %11 ; [in] number of rounds
%define %%IV_LEN            %12 ; [in] IV length

        ;; ===================================================================
        ;; prepare IV
        ;; IV may be different than 12 bytes
        cmp     %%IV_LEN, 12
        je      %%_iv_length_is_12_bytes

        mov     rbx, r12        ; save A_IN
        mov     r14, r13        ; save A_LEN

        CALC_J0 %%GDATA_KEY, %%IV, %%IV_LEN, G_ORIG_IVx

        mov     r12, rbx        ; restore A_IN
        mov     r13, r14        ; restore A_LEN

        jmp     %%_iv_prep_is_done

align_label
%%_iv_length_is_12_bytes:
        ;; read 12 IV bytes and pad with 0x00000001
        vmovdqa64       G_ORIG_IVx, [rel ONEf]
        kmovd           G_MASK_IVAAD, [rel byte_mask_12bytes]
        vmovdqu8        G_ORIG_IVx{G_MASK_IVAAD}, [%%IV]      ; ctr = IV | 0x1

align_label
%%_iv_prep_is_done:
        ;; set up context fields
        vpshufb G_CTR_BLOCKx, G_ORIG_IVx, [rel SHUF_MASK]

        ;; ===================================================================
        ;; check for zero message length

        or      %%LENGTH, %%LENGTH
        je      %%_small_initial_num_blocks_is_0

        ;; ===================================================================
        ;; Determine how many blocks to process
        ;; - process one additional block if there is a partial block (round up)

%define %%NUM_BLOCKS        G_IA0

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

%define %%CTR0                  G_ZTMP0
%define %%CTR1                  G_ZTMP1
%define %%CTR2                  G_ZTMP2
%define %%CTR3                  G_ZTMP3

        ;; ===================================================================
        ;; get load/store mask for plain/cipher text
        lea             G_IA0, [rel byte64_len_to_mask_table]
        lea             G_IA0, [G_IA0 + %%LENGTH*8]
%if num_blocks > 12
        sub             G_IA0, 3 * 64 * 8
%elif num_blocks > 8
        sub             G_IA0, 2 * 64 * 8
%elif num_blocks > 4
        sub             G_IA0, 1 * 64 * 8
%endif
        kmovq           G_MASK_TEXT, [G_IA0]

        ;; ===================================================================
        ;; - load shuffle mask
        ;; - retrieve 32-bit counter in BE format
%if num_blocks == 1
        vmovdqa64       G_SHUF_MASKx, [rel SHUF_MASK]
%elif num_blocks == 2
        vmovdqa64       G_SHUF_MASKy, [rel SHUF_MASK]
%else
        vmovdqa64       G_SHUF_MASK, [rel SHUF_MASK]
%endif
        vmovd           DWORD(G_IA0), G_CTR_BLOCKx

        ;; ===================================================================
        ;; Check if counter blocks can be prepared in BE format or
        ;; LE format is required
        cmp             BYTE(G_IA0), 256 - num_blocks
        jae             %%_ctr_overflow_ %+ num_blocks

        ;; ===================================================================
        ;; Prepare AES counter blocks (BE format, no byte overflow)
%if num_blocks == 1
        vpaddd          XWORD(%%CTR0), G_ORIG_IVx, [rel ONEf]
%elif num_blocks == 2
        vshufi64x2      YWORD(%%CTR0), YWORD(G_ORIG_IV), YWORD(G_ORIG_IV), 0
        vpaddd          YWORD(%%CTR0), YWORD(%%CTR0), [rel ddq_addbe_1234]
%else
        vshufi64x2      G_CTR_BLOCKz, G_ORIG_IV, G_ORIG_IV, 0
        vpaddd          %%CTR0, G_CTR_BLOCKz, [rel ddq_addbe_1234]
%if num_blocks > 4
        vpaddd          %%CTR1, G_CTR_BLOCKz, [rel ddq_addbe_5678]
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
        vpaddd          XWORD(%%CTR0), G_CTR_BLOCKx, [rel ONE]
%elif num_blocks == 2
        vshufi64x2      YWORD(%%CTR0), YWORD(G_CTR_BLOCKz), YWORD(G_CTR_BLOCKz), 0
        vpaddd          YWORD(%%CTR0), YWORD(%%CTR0), [rel ddq_add_1234]
%else
        vshufi64x2      G_CTR_BLOCKz, G_CTR_BLOCKz, G_CTR_BLOCKz, 0
        vpaddd          %%CTR0, G_CTR_BLOCKz, [rel ddq_add_1234]
%if num_blocks > 4
        vpaddd          %%CTR1, G_CTR_BLOCKz, [rel ddq_add_5678]
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
                        G_SHUF_MASK, G_SHUF_MASK, G_SHUF_MASK, G_SHUF_MASK

align_label
%%_ctr_ready_ %+ num_blocks :

        ;; ===================================================================
        ;; append original IV to message blocks for AES encryption, if possible

%if (num_blocks % 4) != 0
%assign num_blocks_aes (num_blocks + 1)
%assign blend_orig_iv_aes 1

%if (num_blocks >= 14) && (num_blocks <= 15)
        vinserti64x2    %%CTR3, G_ORIG_IVx, num_blocks - 12
%elif (num_blocks == 13)
        vinserti64x2    YWORD(%%CTR3), G_ORIG_IVx, num_blocks - 12
%elif (num_blocks >= 10) && (num_blocks <= 11)
        vinserti64x2    %%CTR2, G_ORIG_IVx, num_blocks - 8
%elif (num_blocks == 9)
        vinserti64x2    YWORD(%%CTR2), G_ORIG_IVx, num_blocks - 8
%elif (num_blocks >= 6) && (num_blocks <= 7)
        vinserti64x2    %%CTR1, G_ORIG_IVx, num_blocks - 4
%elif (num_blocks == 5)
        vinserti64x2    YWORD(%%CTR1), G_ORIG_IVx, num_blocks - 4
%elif (num_blocks >= 2) && (num_blocks <= 3)
        vinserti64x2    %%CTR0, G_ORIG_IVx, num_blocks
%else ; (num_blocks == 1)
        vinserti64x2    YWORD(%%CTR0), G_ORIG_IVx, num_blocks
%endif

%else
        ;; 16, 12, 8, 4 or 0 block cases
%assign num_blocks_aes num_blocks
%assign blend_orig_iv_aes 0
%endif

        ;; ===================================================================
        ;; load plain/cipher text
        ZMM_LOAD_MASKED_BLOCKS_0_16 num_blocks, %%PLAIN_CIPH_IN, 0, \
                        G_DAT0, G_DAT1, G_DAT2, G_DAT3, G_MASK_TEXT


        ;; ===================================================================
        ;; AES rounds and XOR with plain/cipher text

        call    gcm_aes_ctr_ %+ num_blocks_aes %+ _vaes_avx512

align_label
%%_encrypt_end %+ num_blocks :

        ;; ===================================================================
        ;; Extract encrypted original IV
%if blend_orig_iv_aes != 0
%if num_blocks >= 12
        vextracti32x4   G_ORIG_IVx, %%CTR3, num_blocks - 12
%elif num_blocks >= 8
        vextracti32x4   G_ORIG_IVx, %%CTR2, num_blocks - 8
%elif num_blocks >= 4
        vextracti32x4   G_ORIG_IVx, %%CTR1, num_blocks - 4
%else
        vextracti32x4   G_ORIG_IVx, %%CTR0, num_blocks
%endif
%endif

        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks, vpxorq, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        G_DAT0, G_DAT1, G_DAT2, G_DAT3

        ;; ===================================================================
        ;; write cipher/plain text back to output and
        ZMM_STORE_MASKED_BLOCKS_0_16 num_blocks, %%CIPH_PLAIN_OUT, 0, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, G_MASK_TEXT

        ;; ===================================================================
        ;; Shuffle the cipher text blocks for hashing part
        ;; - GHASH always works on cipher text
%ifidn  %%ENC_DEC, DEC
        ;; Decrypt case
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks, vpshufb, \
                        G_DAT0, G_DAT1, G_DAT2, G_DAT3, \
                        G_DAT0, G_DAT1, G_DAT2, G_DAT3, \
                        G_SHUF_MASK, G_SHUF_MASK, G_SHUF_MASK, G_SHUF_MASK
%else
        ;; Encrypt case

        ;; - zero bytes outside the mask before hashing
%if num_blocks <= 4
        vmovdqu8        %%CTR0{G_MASK_TEXT}{z}, %%CTR0
%elif num_blocks <= 8
        vmovdqu8        %%CTR1{G_MASK_TEXT}{z}, %%CTR1
%elif num_blocks <= 12
        vmovdqu8        %%CTR2{G_MASK_TEXT}{z}, %%CTR2
%else
        vmovdqu8        %%CTR3{G_MASK_TEXT}{z}, %%CTR3
%endif

        ;; - cipher blocks are in CTR0-CTR3
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 num_blocks, vpshufb, \
                        G_DAT0, G_DAT1, G_DAT2, G_DAT3, \
                        %%CTR0, %%CTR1, %%CTR2, %%CTR3, \
                        G_SHUF_MASK, G_SHUF_MASK, G_SHUF_MASK, G_SHUF_MASK
%endif                          ; Encrypt

        ;; ===================================================================
        ;; Calculate AAD hash
        cmp             %%A_LEN, 12
        jne             %%_aad_is_not_12_bytes_ %+ num_blocks

        ;; ===================================================================
        ;; load 12 bytes of AAD (most common case)
        ;; - AAD and block with sizes get hashed together
        ;; - one reduction for everything (AAD + message + length block)

        ;; IV may be different than 12 bytes and G_MASK_IVAAD not set
        kmovd           G_MASK_IVAAD, [rel byte_mask_12bytes]

        vmovdqu8        G_AAD_HASHx{G_MASK_IVAAD}{z}, [%%A_IN]
        vpshufb         G_AAD_HASHx, G_AAD_HASHx, G_SHUF_MASKx

        vmovq           XWORD(G_ZTMP15), %%LENGTH
        vpinsrq         XWORD(G_ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(G_ZTMP15), XWORD(G_ZTMP15), 3     ; convert bytes into bits
        vinserti64x2    G_AAD_HASHy, XWORD(G_ZTMP15), 1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; GHASH 12 byte AAD with length block using respective GHASH key powers
        ;; AAD_HASHy = [ AAD: 0-127 | LENGTH: 128-255 ]
        ;; HASH_KEY  = [ HK ^ (N + 2) | HK ^ 1 ]

%assign num_blocks2 (num_blocks + 2)
%define %%HKeyN2 HashKey_ %+ num_blocks2

        vmovdqu8        XWORD(G_ZTMP13), [%%GDATA_KEY + %%HKeyN2 + HKeyGap]
        vinserti64x2    YWORD(G_ZTMP13), [%%GDATA_KEY + HashKey_1 + HKeyGap], 1
        vpclmulqdq      YWORD(G_ZTMP14), G_AAD_HASHy, YWORD(G_ZTMP13), 0x00     ; TLL = GH_L * KK_L
        vpclmulqdq      YWORD(G_ZTMP15), G_AAD_HASHy, YWORD(G_ZTMP13), 0x10     ; TLH = GH_L * KK_H
        vmovdqu8        XWORD(G_ZTMP13), [%%GDATA_KEY + %%HKeyN2]
        vinserti64x2    YWORD(G_ZTMP13), [%%GDATA_KEY + HashKey_1], 1
        vpclmulqdq      YWORD(G_ZTMP16), G_AAD_HASHy, YWORD(G_ZTMP13), 0x01     ; THL = GH_H * HK_L
        vpclmulqdq      YWORD(G_ZTMP17), G_AAD_HASHy, YWORD(G_ZTMP13), 0x11     ; THH = GH_H * HK_H

%undef %%HKeyN2

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; add products

        vpxorq          YWORD(G_ZTMP14), YWORD(G_ZTMP14), YWORD(G_ZTMP16)       ;; TLL += THL
        vpxorq          YWORD(G_ZTMP15), YWORD(G_ZTMP15), YWORD(G_ZTMP17)       ;; TLH += THH

        ;; ===================================================================
        ;; continue with message GHASH followed by reduction
        ;;
        ;; Hash key powers and corresponding message blocks:
        ;;   HASH_KEY  = [ HK ^ (N + 1), HK ^ N, ... HK ^ 2 ]
        ;;   MSG       = [ MSG1,         MSG2,   ... MSGN ]

        call    gcm_ghash_common_ %+ num_blocks %+ _vaes_avx512

        jmp             %%_small_initial_blocks_encrypted

align_label
%%_aad_is_not_12_bytes_ %+ num_blocks:
        ;; ===================================================================
        ;; Calculate AAD hash (different than 12 bytes)

        vpxor           xmm0, xmm0, xmm0
        ;; arg1 - GDATA_KEY
        ;; r12 - message pointer - %%A_IN
        ;; r13 - message length - %%A_LEN
        ;; xmm0 - hash in/out

        mov             G_IA1, %%A_LEN
        call            ghash_internal_vaes_avx512
        vmovdqa64       G_AAD_HASHx, xmm0
        mov             %%A_LEN, G_IA1

%if num_blocks == 16
        ;; ===================================================================
        ;; message GHASH compute
        call   gcm_ghash_16_vaes_avx512

        ;; ===================================================================
        ;; GHASH length block
        vmovdqu8        XWORD(G_ZTMP13), [%%GDATA_KEY + HashKey_1]
        vmovdqu8        XWORD(G_ZTMP14), [%%GDATA_KEY + HashKey_1 + HKeyGap]

        vmovq           XWORD(G_ZTMP15), %%LENGTH
        vpinsrq         XWORD(G_ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(G_ZTMP15), XWORD(G_ZTMP15), 3     ; convert bytes into bits

        vpxorq          G_AAD_HASHx, G_AAD_HASHx, XWORD(G_ZTMP15)
        GHASH_MUL2      G_AAD_HASHx, XWORD(G_ZTMP13), XWORD(G_ZTMP14), XWORD(G_ZTMP16), XWORD(G_ZTMP17), XWORD(G_ZTMP18), XWORD(G_ZTMP19)

%else
        ;; ===================================================================
        ;; create & append length block into message for GHASH
        vmovq           XWORD(G_ZTMP15), %%LENGTH
        vpinsrq         XWORD(G_ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(G_ZTMP15), XWORD(G_ZTMP15), 3     ; convert bytes into bits

%if num_blocks == 12
        vmovdqa64       XWORD(G_DAT3), XWORD(G_ZTMP15)
%elif num_blocks > 12
        vinserti64x2    G_DAT3, XWORD(G_ZTMP15), num_blocks - 12
%elif num_blocks == 8
        vmovdqa64       XWORD(G_DAT2), XWORD(G_ZTMP15)
%elif num_blocks > 8
        vinserti64x2    G_DAT2, XWORD(G_ZTMP15), num_blocks - 8
%elif num_blocks == 4
        vmovdqa64       XWORD(G_DAT1), XWORD(G_ZTMP15)
%elif num_blocks > 4
        vinserti64x2    G_DAT1, XWORD(G_ZTMP15), num_blocks - 4
%else
        vinserti64x2    G_DAT0, XWORD(G_ZTMP15), num_blocks
%endif

        ;; ===================================================================
        ;; message + length block GHASH compute

%assign num_blocks2 (num_blocks + 1)

        call   gcm_ghash_ %+ num_blocks %+ _vaes_avx512

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
        vmovdqa64       G_SHUF_MASKx, [rel SHUF_MASK]

        ;; ===================================================================
        ;; calculate AAD hash for 0 message length case
        vpxor           xmm0, xmm0, xmm0
        ;; arg1 - GDATA_KEY
        ;; r12 - message pointer - %%A_IN
        ;; r13 - message length - %%A_LEN
        ;; xmm0 - hash in/out

        mov             G_IA1, %%A_LEN
        call            ghash_internal_vaes_avx512
        vmovdqa64       G_AAD_HASHx, xmm0
        mov             %%A_LEN, G_IA1

        ;; ===================================================================
        ;; encrypt original IV
        vpxorq          G_ORIG_IVx, G_ORIG_IVx, [%%GDATA_KEY]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*1]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*2]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*3]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*4]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*5]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*6]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*7]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*8]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*9]

        cmp             DWORD(%%ROUNDS), 11
        jb              %%_single_block_128
        je              %%_single_block_192

        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*10]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*11]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*12]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*13]
        vaesenclast     G_ORIG_IVx, [%%GDATA_KEY + 16*14]
        jmp             %%_ghash_length_block

align_label
%%_single_block_192:
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*10]
        vaesenc         G_ORIG_IVx, [%%GDATA_KEY + 16*11]
        vaesenclast     G_ORIG_IVx, [%%GDATA_KEY + 16*12]
        jmp             %%_ghash_length_block

align_label
%%_single_block_128:
        vaesenclast     G_ORIG_IVx, [%%GDATA_KEY + 16*10]

        ;; ===================================================================
        ;; GHASH length block
align_label
%%_ghash_length_block:
        vmovdqu8        XWORD(G_ZTMP13), [%%GDATA_KEY + HashKey_1]
        vmovdqu8        XWORD(G_ZTMP14), [%%GDATA_KEY + HashKey_1 + HKeyGap]

        vpxorq          XWORD(G_ZTMP15), XWORD(G_ZTMP15), XWORD(G_ZTMP15)       ; len(C) = 0
        vpinsrq         XWORD(G_ZTMP15), %%A_LEN, 1             ; ZTMP15 = len(A)||len(C)
        vpsllq          XWORD(G_ZTMP15), XWORD(G_ZTMP15), 3     ; convert bytes into bits

        vpxorq          G_AAD_HASHx, G_AAD_HASHx, XWORD(G_ZTMP15)
        GHASH_MUL2      G_AAD_HASHx, XWORD(G_ZTMP13), XWORD(G_ZTMP14), XWORD(G_ZTMP16), XWORD(G_ZTMP17), XWORD(G_ZTMP18), XWORD(G_ZTMP19)

align_label
%%_small_initial_blocks_encrypted:
        ;; ===================================================================
        ;; Complete GMAC computation
        ;;     S => G_AAD_HASHx
        ;;     CIPHER(J0) => G_ORIG_IVx
        ;; T = MSB(GCTR(J0,S))
        vpshufb         G_AAD_HASHx, G_AAD_HASHx, G_SHUF_MASKx
        vpxorq          G_ORIG_IVx, G_ORIG_IVx, G_AAD_HASHx

        ;; ===================================================================
        ;; Store the tag T
        lea             G_IA0, [rel byte64_len_to_mask_table]
        kmovq           G_MASK_TAG, [G_IA0 + %%AUTH_TAG_LEN*8]
        vmovdqu8        [%%AUTH_TAG]{G_MASK_TAG}, G_ORIG_IVx

%endmacro                       ; GCM_ENC_DEC_0_TO_256

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; gcm_0_to_256_enc_wrapper_<mode>
;; Wrapper function for GCM_ENC_DEC_0_TO_256 macro - encryption case
;; Parameters:
;;   arg1 (rdi/rcx) = GDATA_KEY (const struct gcm_key_data *key_data)
;;   -- arg2 (rsi/rdx) = context_data (not used by 0-256 macro)
;;   arg3 (rdx/r8)  = CIPH_PLAIN_OUT (u8 *out)
;;   arg4 (rcx/r9)  = PLAIN_CIPH_IN (const u8 *in)
;;   arg5 (r8/rdi) = PLAIN_CIPH_LEN (u64 msg_len)
;;   arg6 (r9/rsi) = IV (u8 *iv)
;;   arg7 (r12)    = A_IN (const u8 *aad)
;;   arg8 (r13)      = A_LEN (u64 aad_len)
;;   arg9 (rbp)      = AUTH_TAG (u8 *auth_tag)
;;   arg10 (r15)     = AUTH_TAG_LEN (u64 auth_tag_len)
;;   arg11 (r10)     = ROUNDS (number of AES rounds)
;;   arg12 (r11)     = IV_LEN (u64 iv_len)
;; Output: Encrypted data and auth tag
;; Clobbers: rax, r12, r13, zmm0-zmm23, zmm26-zmm31, k1, r11 (windows)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(gcm_0_to_256_enc_wrapper_asm,function,internal)
gcm_0_to_256_enc_wrapper_asm:

%ifdef LINUX
        GCM_ENC_DEC_0_TO_256 rdi,  rdx,  rcx,  r8,  r9, r12, r13, rbp, r15, ENC, r10, r11
%else
        GCM_ENC_DEC_0_TO_256 rcx,  r8,  r9,  rdi,  rsi, r12, r13, rbp, r15, ENC, r10, r11
%endif

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; gcm_0_to_256_dec_wrapper_<mode>
;; Wrapper function for GCM_ENC_DEC_0_TO_256 macro - decryption case
;; Parameters:
;;   arg1 (rdi/rcx) = GDATA_KEY (const struct gcm_key_data *key_data)
;;   -- arg2 (rsi/rdx) = context_data (not used by 0-256 macro)
;;   arg3 (rdx/r8)  = CIPH_PLAIN_OUT (u8 *out)
;;   arg4 (rcx/r9)  = PLAIN_CIPH_IN (const u8 *in)
;;   arg5 (r8/rdi) = PLAIN_CIPH_LEN (u64 msg_len)
;;   arg6 (r9/rsi) = IV (u8 *iv)
;;   arg7 (r12)    = A_IN (const u8 *aad)
;;   arg8 (r13)      = A_LEN (u64 aad_len)
;;   arg9 (rbp)      = AUTH_TAG (u8 *auth_tag)
;;   arg10 (r15)     = AUTH_TAG_LEN (u64 auth_tag_len)
;;   arg11 (r10)     = ROUNDS (number of AES rounds)
;;   arg12 (r11)     = IV_LEN (u64 iv_len)
;; Output: Decrypted data and auth tag
;; Clobbers: rax, r12, r13, zmm0-zmm23, zmm26-zmm31, k1, r11 (windows)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(gcm_0_to_256_dec_wrapper_asm,function,internal)
gcm_0_to_256_dec_wrapper_asm:

%ifdef LINUX
        GCM_ENC_DEC_0_TO_256 rdi,  rdx,  rcx,  r8, r9, r12, r13, rbp, r15, DEC, r10, r11
%else
        GCM_ENC_DEC_0_TO_256 rcx,  r8,  r9,  rdi, rsi, r12, r13, rbp, r15, DEC, r10, r11
%endif

        ret
