;;
;; Copyright (c) 2024, Intel Corporation
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

%use smartalign

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/aes_common.inc"
%include "include/clear_regs.inc"
%include "include/align_avx.inc"

struc STACK
_PREV_BLOCK_YMM_SAVE:      resy    1       ; Space to store 1 temporary YMM register
endstruc

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rdx
%define arg4	rcx
%define arg5    r8
%else
%define arg1	rcx
%define arg2	rdx
%define arg3	r8
%define arg4	r9
%define arg5    rax
%endif

%define RSP_SAVE                r11
%define AES_ROUND_KEYS          arg4

%define BLOCK_0_1               ymm0
%define BLOCK_2_3               ymm1
%define BLOCK_4_5               ymm2
%define BLOCK_6_7               ymm3
%define BLOCK_8_9               ymm4
%define BLOCK_10_11             ymm5
%define BLOCK_12_13             ymm6
%define BLOCK_14_15             ymm7
%define TMP_0                   ymm8
%define TMP_1                   ymm9
%define TMP_2                   ymm10
%define TMP_3                   ymm11
%define TMP_4                   ymm12
%define TMP_5                   ymm13
%define TMP_6                   ymm14
%define TMP_7                   ymm15

%define CIPHER_PLAIN_0_15       BLOCK_0_1, BLOCK_2_3, BLOCK_4_5, BLOCK_6_7,    \
                                BLOCK_8_9, BLOCK_10_11, BLOCK_12_13, BLOCK_14_15
%define Y_TEMP_0_7              TMP_0, TMP_1, TMP_2, TMP_3, TMP_4, TMP_5,      \
                                TMP_6, TMP_7

;; =============================================================================
;; This macro is used to "cool down" pipeline after DECRYPT_16_PARALLEL macro
;; code as the number of final blocks is variable.
;; Processes the last %%NUM_FINAL_BLOCKS blocks (1 to 16, can't be 0)
%macro CFB_BLOCKS 4-5
%define %%PLAIN_OUT             %1      ; [in] output buffer
%define %%CIPH_IN               %2      ; [in] input buffer
%define %%NUM_FINAL_BLOCKS      %3      ; [in/out] ymm with IV/last cipher blk (in idx 3)
%define %%NROUNDS               %4      ; [in] number of rounds; numerical value
%if %%NUM_FINAL_BLOCKS == 16
%define %%LENGTH                %5      ; [in/out] number of bytes to process
%endif
        ;; load plain/cipher text
        YMM_LOAD_BLOCKS_AVX2_0_16 %%NUM_FINAL_BLOCKS, %%CIPH_IN, 0, CIPHER_PLAIN_0_15

        vperm2i128      TMP_0, BLOCK_0_1, [rsp + _PREV_BLOCK_YMM_SAVE], 3
%if %%NUM_FINAL_BLOCKS > 2
        vperm2i128      TMP_1, BLOCK_2_3, BLOCK_0_1, 3
%endif
%if %%NUM_FINAL_BLOCKS > 4
        vperm2i128      TMP_2, BLOCK_4_5, BLOCK_2_3, 3
%endif
%if %%NUM_FINAL_BLOCKS > 6
        vperm2i128      TMP_3, BLOCK_6_7, BLOCK_4_5, 3
%endif
%if %%NUM_FINAL_BLOCKS > 8
        vperm2i128      TMP_4, BLOCK_8_9, BLOCK_6_7, 3
%endif
%if %%NUM_FINAL_BLOCKS > 10
        vperm2i128      TMP_5, BLOCK_10_11, BLOCK_8_9, 3
%endif
%if %%NUM_FINAL_BLOCKS > 12
        vperm2i128      TMP_6, BLOCK_12_13, BLOCK_10_11, 3
%endif
%if %%NUM_FINAL_BLOCKS > 14
        vperm2i128      TMP_7, BLOCK_14_15, BLOCK_12_13, 3
        vmovdqa         [rsp + _PREV_BLOCK_YMM_SAVE], BLOCK_14_15
%endif

        ;; AES rounds
%assign ROUND 0
%rep (%%NROUNDS + 2)
        vbroadcasti128      BLOCK_14_15, [AES_ROUND_KEYS + ROUND*16]
        YMM_AESENC_ROUND_BLOCKS_AVX2_0_16 Y_TEMP_0_7, BLOCK_14_15, ROUND,      \
                                          no_data, no_data, no_data, no_data,  \
                                          no_data, no_data, no_data, no_data,  \
                                          %%NUM_FINAL_BLOCKS, %%NROUNDS

%assign ROUND (ROUND + 1)
%endrep

        ;; XOR with decrypted blocks to get plain text
%assign NUM_BLOCKS %%NUM_FINAL_BLOCKS

%if %%NUM_FINAL_BLOCKS > 14
        %assign NUM_BLOCKS 14
%endif
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 NUM_BLOCKS, vpxor,            \
                                                 CIPHER_PLAIN_0_15,            \
                                                 CIPHER_PLAIN_0_15, Y_TEMP_0_7

%if %%NUM_FINAL_BLOCKS > 14
        vpxor           BLOCK_14_15, TMP_7, [rsp + _PREV_BLOCK_YMM_SAVE]
%endif

        ;; write plain text back to output
        YMM_STORE_BLOCKS_AVX2_0_16 %%NUM_FINAL_BLOCKS, %%PLAIN_OUT, 0, CIPHER_PLAIN_0_15

%if %%NUM_FINAL_BLOCKS == 16
        ;; adjust input pointer and length
        sub             %%LENGTH, (16 * 16)
        add             %%CIPH_IN, (16 * 16)
        add             %%PLAIN_OUT, (16 * 16)
%endif

%endmacro       ; CFB_BLOCKS

;; =============================================================================
;; AES_CFB_DEC macro decrypts given data.
;; Flow:
;; - Decrypt all blocks (multiple of 16) up to final 1-15 blocks
;; - Decrypt final blocks (1-15 blocks)
%macro AES_CFB_DEC 6
%define %%CIPH_IN       %1 ;; [in] pointer to input buffer
%define %%PLAIN_OUT     %2 ;; [in] pointer to output buffer
%define %%KEYS          %3 ;; [in] pointer to expanded keys
%define %%IV            %4 ;; [in] pointer to IV
%define %%LENGTH        %5 ;; [in/clobbered] GP register with length in bytes
%define %%NROUNDS       %6 ;; [in] Number of AES rounds; numerical value

%ifndef LINUX
        mov             %%LENGTH, [rsp + 8*5]
%endif
        mov             RSP_SAVE, rsp
        sub             rsp, STACK_size
        and             rsp, -32

        cmp             %%LENGTH, 0
        je              %%cfb_dec_done 

        vinserti128     TMP_0, TMP_0, [%%IV], 1
        vmovdqa         [rsp + _PREV_BLOCK_YMM_SAVE], TMP_0

align_loop
%%decrypt_16_parallel:
        cmp     %%LENGTH, 256
        jb      %%final_blocks

        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, 16, %%NROUNDS, %%LENGTH

        jmp     %%decrypt_16_parallel

align_label
%%final_blocks:
        ;; get num final blocks
        shr     %%LENGTH, 4
        and     %%LENGTH, 0xf
        je      %%cfb_dec_done

        cmp     %%LENGTH, 8
        je      %%final_num_blocks_is_8
        jb      %%final_blocks_is_1_7

        ; Final blocks 9-15
        cmp     %%LENGTH, 12
        je      %%final_num_blocks_is_12
        jb      %%final_blocks_is_9_11

        cmp     %%LENGTH, 14
        je      %%final_num_blocks_is_14
        jb      %%final_num_blocks_is_13

;; final num blocks is 15:
        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, 15, %%NROUNDS
        jmp     %%cfb_dec_done
align_label
%%final_blocks_is_9_11:
        cmp     %%LENGTH, 10
        je      %%final_num_blocks_is_10
        jb      %%final_num_blocks_is_9

;; final num blocks is 11:
        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, 11, %%NROUNDS
        jmp     %%cfb_dec_done
align_label
%%final_blocks_is_1_7:
        cmp     %%LENGTH, 4
        je      %%final_num_blocks_is_4
        jb      %%final_blocks_is_1_3

        ; Final blocks 5-7
        cmp     %%LENGTH, 6
        je      %%final_num_blocks_is_6
        jb      %%final_num_blocks_is_5

;; final num blocks is 7:
        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, 7, %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_blocks_is_1_3:
        cmp     %%LENGTH, 2
        je      %%final_num_blocks_is_2
        jb      %%final_num_blocks_is_1

;; final num blocks is 3:
        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, 3, %%NROUNDS
        jmp     %%cfb_dec_done

;; Create labels with CFB_BLOCKS macro calls for [14:12], [10:8], [6:4] BLOCKS
;; Skip 15, 11 and 7 defined above and for 2, 1 defined later
%assign TOTAL_NUM_BLOCKS 14
%rep 3
%assign NUM_BLOCKS TOTAL_NUM_BLOCKS
%rep 3
align_label
%%final_num_blocks_is_ %+ NUM_BLOCKS:
        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, NUM_BLOCKS, %%NROUNDS
        jmp     %%cfb_dec_done
%assign NUM_BLOCKS (NUM_BLOCKS - 1)
%endrep
%assign TOTAL_NUM_BLOCKS (TOTAL_NUM_BLOCKS - 4)
%endrep

align_label
%%final_num_blocks_is_2:
        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, 2, %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_1:
        CFB_BLOCKS %%PLAIN_OUT, %%CIPH_IN, 1, %%NROUNDS

align_label
%%cfb_dec_done:
%ifdef SAFE_DATA
	clear_all_ymms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA

        mov             rsp, RSP_SAVE

%endmacro ;; AES_CFB_DEC


;; =============================================================================
;; void aes_cfb_/*128/192/256*/_dec_vaes_avx2
;;(void *out, void *in, void *iv, void *keys, uint64_t len)
;; arg 1: OUT : addr to put clear/cipher text out
;; arg 2: IN  : addr to take cipher/clear text from
;; arg 3: IV  : initialization vector
;; arg 4: KEYS: pointer to expanded keys structure (16 byte aligned)
;; arg 5: LEN:  length of the text to encrypt/decrypt

;; =============================================================================
;; void aes_cfb_128_dec_vaes_avx2
mksection .text
align_function
MKGLOBAL(aes_cfb_dec_128_vaes_avx2,function,internal)
aes_cfb_dec_128_vaes_avx2:
        AES_CFB_DEC arg2, arg1, AES_ROUND_KEYS, arg3, arg5, 9
        ret

;; =============================================================================
;; void aes_cfb_192_dec_vaes_avx2
align_function
MKGLOBAL(aes_cfb_dec_192_vaes_avx2,function,internal)
aes_cfb_dec_192_vaes_avx2:
        AES_CFB_DEC arg2, arg1, AES_ROUND_KEYS, arg3, arg5, 11
        ret

;; =============================================================================
;; void aes_cfb_256_dec_vaes_avx2
align_function
MKGLOBAL(aes_cfb_dec_256_vaes_avx2,function,internal)
aes_cfb_dec_256_vaes_avx2:
        AES_CFB_DEC arg2, arg1, AES_ROUND_KEYS, arg3, arg5, 13

        ret

mksection stack-noexec

