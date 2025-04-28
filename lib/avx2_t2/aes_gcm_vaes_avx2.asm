;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2024, Intel Corporation All rights reserved.
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

%define GCM128_MODE

%use smartalign

%include "include/aes_common.inc"

%define GCM_UTIL_IMPLEMENTATION
%include "include/gcm_vaes_avx2.inc"
%include "include/align_avx.inc"

mksection .text
default rel

;; Prepare N counter blocks and encrypt them
;;
;; IN:
;;   arg1  - key pointer
;;   r10   - number of AES rounds (9, 11 or 13)
;;   xmm9  - counter block (LE)
;;
;; OUT:
;;   ymm1 - ymm8  - encrypted blocks
;;   xmm9         - updated counter block (LE)
;;
;; CLOBBERED:
;;   xmm0, xmm10-xmm13, xmm15
align_function
MKGLOBAL(gcm_aes_ctr_1_vaes_avx2,function,internal)
gcm_aes_ctr_1_vaes_avx2:
        vpaddd          xmm9, xmm9, [rel ONE]
        vpshufb         xmm1, xmm9, [rel SHUF_MASK]
        vpxor           xmm1, xmm1, [arg1 + 16*0]
        vaesenc         xmm1, xmm1, [arg1 + 16*1]
        vaesenc         xmm1, xmm1, [arg1 + 16*2]
        vaesenc         xmm1, xmm1, [arg1 + 16*3]
        vaesenc         xmm1, xmm1, [arg1 + 16*4]
        vaesenc         xmm1, xmm1, [arg1 + 16*5]
        vaesenc         xmm1, xmm1, [arg1 + 16*6]
        vaesenc         xmm1, xmm1, [arg1 + 16*7]
        vaesenc         xmm1, xmm1, [arg1 + 16*8]
        vaesenc         xmm1, xmm1, [arg1 + 16*9]
        cmp             r10d, 11
        jb              .aes128
        je              .aes192
        vaesenc         xmm1, xmm1, [arg1 + 16*10]
        vaesenc         xmm1, xmm1, [arg1 + 16*11]
        vaesenc         xmm1, xmm1, [arg1 + 16*12]
        vaesenc         xmm1, xmm1, [arg1 + 16*13]
        vaesenclast     xmm1, xmm1, [arg1 + 16*14]
        ret

align_label
.aes192:
        vaesenc         xmm1, xmm1, [arg1 + 16*10]
        vaesenc         xmm1, xmm1, [arg1 + 16*11]
        vaesenclast     xmm1, xmm1, [arg1 + 16*12]
        ret

align_label
.aes128:
        vaesenclast     xmm1, xmm1, [arg1 + 16*10]
        ret

%assign NB 2

%rep 15

align_function
MKGLOBAL(gcm_aes_ctr_ %+ NB %+ _vaes_avx2,function,internal)
gcm_aes_ctr_ %+ NB %+ _vaes_avx2:

        vinserti128     ymm9, xmm9, 1

%assign NJ (((NB - 1) / 2) + 1)
%xdefine _LAST_YMM ymm %+ NJ
%assign NJ ((NB - 1) % 2)
%xdefine _LAST_IDX NJ

        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16 \
                NB, vpaddd, \
                ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                ymm9, ymm9, ymm9, ymm9, ymm1, ymm2, ymm3, ymm4,  \
                {[rel ddq_add_1234 + 0*32]}, {[rel ddq_add_1234 + 1*32]}, \
                {[rel ddq_add_5678 + 0*32]}, {[rel ddq_add_5678 + 1*32]}, \
                {[rel ddq_add_8888]}, {[rel ddq_add_8888]}, \
                {[rel ddq_add_8888]}, {[rel ddq_add_8888]} \

        vextracti128    xmm9, _LAST_YMM, _LAST_IDX    ; last counter block (LE)

        vbroadcasti128  ymm0, [rel SHUF_MASK]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vpshufb, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

        vbroadcasti128  ymm0, [arg1 + 16*0]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vpxor, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0

%assign NJ 1
%rep 9
        vbroadcasti128  ymm0, [arg1 + 16*NJ]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vaesenc, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0
%assign NJ (NJ + 1)
%endrep

        cmp             r10d, 11
        jb              .aes128
        je              .aes192

%assign NJ 10
%rep 4
        vbroadcasti128  ymm0, [arg1 + 16*NJ]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vaesenc, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0
%assign NJ (NJ + 1)
%endrep
        vbroadcasti128  ymm0, [arg1 + 16*14]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vaesenclast, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0
        ret

align_label
.aes192:
%assign NJ 10
%rep 2
        vbroadcasti128  ymm0, [arg1 + 16*NJ]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vaesenc, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0
%assign NJ (NJ + 1)
%endrep
        vbroadcasti128  ymm0, [arg1 + 16*12]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vaesenclast, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0
        ret

align_label
.aes128:
        vbroadcasti128  ymm0, [arg1 + 16*10]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 \
                        NB, vaesenclast, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, \
                        ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0, ymm0
        ret

%undef _LAST_YMM
%undef _LAST_IDX
%assign NB (NB + 1)
%endrep


;; IN:
;;   arg1  - key pointer
;;   arg3  - destination buffer
;;   arg4  - source buffer
;;   r15   - pointer to store cipher text for GHASH
;;   r10   - number of AESENC rounds (9, 11 or 13)
;;   r11   - data offset
;;   r12   - number of blocks to process
;;   r13   - length in bytes
;;   xmm8  - AAD HASH IN
;;   xmm9  - CTR block
;;
;; OUT:
;;   ymm1 to ymm8 - [out] cipher text blocks for GHASH which are also stored at [r15]
;;                  - hash is added to block 0 already
;;
;; CLOBBERED:
;;   xmm0, xmm10-xmm13, xmm15
align_function
MKGLOBAL(gcm_initial_blocks_enc_vaes_avx2,function,internal)
gcm_initial_blocks_enc_vaes_avx2:
        and     r12d, 15    ; don't allow 16 initial blocks
        je      .initial_num_blocks_is_0
        cmp     r12d, 14
        ja      .initial_num_blocks_is_15
        je      .initial_num_blocks_is_14
        cmp     r12d, 2
        jb      .initial_num_blocks_is_1
        je      .initial_num_blocks_is_2
        cmp     r12d, 12
        ja      .initial_num_blocks_is_13
        je      .initial_num_blocks_is_12
        cmp     r12d, 4
        jb      .initial_num_blocks_is_3
        je      .initial_num_blocks_is_4
        cmp     r12d, 10
        ja      .initial_num_blocks_is_11
        je      .initial_num_blocks_is_10
        cmp     r12d, 6
        jb      .initial_num_blocks_is_5
        je      .initial_num_blocks_is_6
        cmp     r12d, 8
        ja      .initial_num_blocks_is_9
        je      .initial_num_blocks_is_8
        jmp     .initial_num_blocks_is_7

%assign NB 15
%rep 16
align_label
.initial_num_blocks_is_ %+ NB :
        INITIAL_BLOCKS  arg1, arg3, arg4, r13, r11, NB, ENC
        ret
%assign NB (NB - 1)
%endrep

;; IN:
;;   arg1  - key pointer
;;   arg3  - destination buffer
;;   arg4  - source buffer
;;   r15   - pointer to store cipher text for GHASH
;;   r10   - number of AESENC rounds (9, 11 or 13)
;;   r11   - data offset
;;   r12   - number of blocks to process
;;   r13   - length in bytes
;;   xmm8  - AAD HASH IN
;;   xmm9  - CTR block
;;
;; OUT:
;;   ymm1 to ymm8 - [out] cipher text blocks for GHASH which are also stored at [r15]
;;                  - hash is added to block 0 already
;;
;; CLOBBERED:
;;   xmm0, xmm10-xmm13, xmm15
align_function
MKGLOBAL(gcm_initial_blocks_dec_vaes_avx2,function,internal)
gcm_initial_blocks_dec_vaes_avx2:
        and     r12d, 15    ; don't allow 16 initial blocks
        je      .initial_num_blocks_is_0
        cmp     r12d, 14
        ja      .initial_num_blocks_is_15
        je      .initial_num_blocks_is_14
        cmp     r12d, 2
        jb      .initial_num_blocks_is_1
        je      .initial_num_blocks_is_2
        cmp     r12d, 12
        ja      .initial_num_blocks_is_13
        je      .initial_num_blocks_is_12
        cmp     r12d, 4
        jb      .initial_num_blocks_is_3
        je      .initial_num_blocks_is_4
        cmp     r12d, 10
        ja      .initial_num_blocks_is_11
        je      .initial_num_blocks_is_10
        cmp     r12d, 6
        jb      .initial_num_blocks_is_5
        je      .initial_num_blocks_is_6
        cmp     r12d, 8
        ja      .initial_num_blocks_is_9
        je      .initial_num_blocks_is_8
        jmp     .initial_num_blocks_is_7

%assign NB 15
%rep 16
align_label
.initial_num_blocks_is_ %+ NB :
        INITIAL_BLOCKS  arg1, arg3, arg4, r13, r11, NB, DEC
        ret
%assign NB (NB - 1)
%endrep

;;
;; Encrypt of the final partial block
;;
;; IN:
;;   arg1  - key pointer
;;   arg3  - destination buffer
;;   arg4  - source buffer
;;   r11   - data offset
;;   r13   - length in bytes
;;   xmm15 - encrypted counter block
;;
;; OUT:
;;   xmm15 - encrypted counter block
;;
;; CLOBBERED:
;;   xmm10, xmm11
;;   r10, r12, r15, rax
align_function
MKGLOBAL(gcm_enc_final_partial_block_vaes_avx2,function,internal)
gcm_enc_final_partial_block_vaes_avx2:
        ENCRYPT_FINAL_PARTIAL_BLOCK \
                        xmm15, xmm10, xmm11, arg3, arg4, LT16, ENC, r11
        ret

;;
;; Decrypt of the final partial block
;;
;; IN:
;;   arg1  - key pointer
;;   arg3  - destination buffer
;;   arg4  - source buffer
;;   r11   - data offset
;;   r13   - length in bytes
;;   xmm15 - encrypted counter block
;;
;; OUT:
;;   xmm15 - encrypted counter block
;;
;; CLOBBERED:
;;   xmm10, xmm11
;;   r10, r12, r15, rax
align_function
MKGLOBAL(gcm_dec_final_partial_block_vaes_avx2,function,internal)
gcm_dec_final_partial_block_vaes_avx2:
        ENCRYPT_FINAL_PARTIAL_BLOCK \
                        xmm15, xmm10, xmm11, arg3, arg4, LT16, DEC, r11
        ret

mksection stack-noexec
