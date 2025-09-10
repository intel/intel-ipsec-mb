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

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/aes_common.inc"
%include "include/clear_regs.inc"
%include "include/align_avx512.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    rax
%endif

%define zIV        zmm0
%define zBLK_0_3   zmm1
%define zBLK_4_7   zmm2
%define zBLK_8_11  zmm3
%define zBLK_12_15 zmm4
%define zTMP0      zmm5
%define zTMP1      zmm6
%define zTMP2      zmm7
%define zTMP3      zmm8

%define ZKEY0      zmm17
%define ZKEY1      zmm18
%define ZKEY2      zmm19
%define ZKEY3      zmm20
%define ZKEY4      zmm21
%define ZKEY5      zmm22
%define ZKEY6      zmm23
%define ZKEY7      zmm24
%define ZKEY8      zmm25
%define ZKEY9      zmm26
%define ZKEY10     zmm27
%define ZKEY11     zmm28
%define ZKEY12     zmm29
%define ZKEY13     zmm30
%define ZKEY14     zmm31


;; =============================================================================
;; Macro used to preload keys. Uses ZKEY[0-14] registers (ZMM)
%macro LOAD_KEYS 2
%define %%KEYS          %1      ; [in] key pointer
%define %%NROUNDS       %2      ; [in] numerical value, number of AES rounds

%assign i 0
; round 0 keys are used for xor, round (%%NROUNDS + 1) used for aesenclast
%rep (%%NROUNDS + 2)
        vbroadcastf64x2 ZKEY %+ i, [%%KEYS + 16*i]
%assign i (i + 1)
%endrep

%endmacro

;; =============================================================================
;; This macro is used to "cool down" pipeline after DECRYPT_16_PARALLEL macro
;; code as the number of final blocks is variable.
;; Processes the last %%num_final_blocks blocks (1 to 15, can't be 0)
%macro FINAL_BLOCKS 13
%define %%PLAIN_OUT             %1      ; [in] output buffer
%define %%CIPH_IN               %2      ; [in] input buffer
%define %%LAST_CIPH_BLK         %3      ; [in/out] ZMM with IV/last cipher blk (in idx 3)
%define %%num_final_blocks      %4      ; [in] numerical value (1 - 15)
%define %%CIPHER_PLAIN_0_3      %5      ; [out] ZMM next 0-3 cipher blocks
%define %%CIPHER_PLAIN_4_7      %6      ; [out] ZMM next 4-7 cipher blocks
%define %%CIPHER_PLAIN_8_11     %7      ; [out] ZMM next 8-11 cipher blocks
%define %%CIPHER_PLAIN_12_15    %8      ; [out] ZMM next 12-15 cipher blocks
%define %%ZT1                   %9      ; [clobbered] ZMM temporary
%define %%ZT2                   %10     ; [clobbered] ZMM temporary
%define %%ZT3                   %11     ; [clobbered] ZMM temporary
%define %%ZT4                   %12     ; [clobbered] ZMM temporary
%define %%NROUNDS               %13     ; [in] number of rounds; numerical value

        ;; load cipher text
        ZMM_LOAD_BLOCKS_0_16 %%num_final_blocks, %%CIPH_IN, 0, \
                %%CIPHER_PLAIN_0_3, %%CIPHER_PLAIN_4_7, \
                %%CIPHER_PLAIN_8_11, %%CIPHER_PLAIN_12_15

        valignq         %%ZT1, %%CIPHER_PLAIN_0_3, %%LAST_CIPH_BLK, 6
%if %%num_final_blocks > 4
        valignq         %%ZT2, %%CIPHER_PLAIN_4_7, %%CIPHER_PLAIN_0_3, 6
%endif
%if %%num_final_blocks > 8
        valignq         %%ZT3, %%CIPHER_PLAIN_8_11, %%CIPHER_PLAIN_4_7, 6
%endif
%if %%num_final_blocks > 12
        valignq         %%ZT4, %%CIPHER_PLAIN_12_15, %%CIPHER_PLAIN_8_11, 6
%endif

        ;; AES rounds
%assign j 0
%rep (%%NROUNDS + 2)
        ZMM_AESENC_ROUND_BLOCKS_0_16 %%ZT1, %%ZT2, \
                        %%ZT3, %%ZT4, \
                        ZKEY %+ j, j, no_data, no_data, no_data, no_data, \
                        %%num_final_blocks, %%NROUNDS
%assign j (j + 1)
%endrep

        ;; XOR with decrypted blocks to get plain text
        vpxorq          %%CIPHER_PLAIN_0_3, %%CIPHER_PLAIN_0_3, %%ZT1
%if %%num_final_blocks > 4
        vpxorq          %%CIPHER_PLAIN_4_7, %%CIPHER_PLAIN_4_7, %%ZT2
%endif
%if %%num_final_blocks > 8
        vpxorq          %%CIPHER_PLAIN_8_11, %%CIPHER_PLAIN_8_11, %%ZT3
%endif
%if %%num_final_blocks > 12
        vpxorq          %%CIPHER_PLAIN_12_15, %%CIPHER_PLAIN_12_15, %%ZT4
%endif

        ;; write plain text back to output
        ZMM_STORE_BLOCKS_0_16 %%num_final_blocks, %%PLAIN_OUT, 0, \
                %%CIPHER_PLAIN_0_3, %%CIPHER_PLAIN_4_7, \
                %%CIPHER_PLAIN_8_11, %%CIPHER_PLAIN_12_15

%endmacro       ; FINAL_BLOCKS

;; =============================================================================
;; Main AES-CFB decrypt macro
;; - operates on single stream
;; - decrypts 16 blocks at a time
%macro DECRYPT_16_PARALLEL 13
%define %%PLAIN_OUT             %1      ; [in] output buffer
%define %%CIPH_IN               %2      ; [in] input buffer
%define %%LENGTH                %3      ; [in/out] number of bytes to process
%define %%LAST_CIPH_BLK         %4      ; [in/out] ZMM with IV (first block) or last cipher block (idx 3)
%define %%CIPHER_PLAIN_0_3      %5      ; [out] ZMM next 0-3 cipher blocks
%define %%CIPHER_PLAIN_4_7      %6      ; [out] ZMM next 4-7 cipher blocks
%define %%CIPHER_PLAIN_8_11     %7      ; [out] ZMM next 8-11 cipher blocks
%define %%CIPHER_PLAIN_12_15    %8      ; [out] ZMM next 12-15 cipher blocks
%define %%ZT1                   %9      ; [clobbered] ZMM temporary
%define %%ZT2                   %10     ; [clobbered] ZMM temporary
%define %%ZT3                   %11     ; [clobbered] ZMM temporary
%define %%ZT4                   %12     ; [clobbered] ZMM temporary
%define %%NROUNDS               %13     ; [in] number of rounds; numerical value

        vmovdqu8        %%CIPHER_PLAIN_0_3, [%%CIPH_IN]
        vmovdqu8        %%CIPHER_PLAIN_4_7, [%%CIPH_IN + 64]
        vmovdqu8        %%CIPHER_PLAIN_8_11, [%%CIPH_IN + 128]
        vmovdqu8        %%CIPHER_PLAIN_12_15, [%%CIPH_IN + 192]
        ;; prepare first set of cipher blocks for later XOR'ing
        valignq         %%ZT1, %%CIPHER_PLAIN_0_3, %%LAST_CIPH_BLK, 6
        valignq         %%ZT2, %%CIPHER_PLAIN_4_7, %%CIPHER_PLAIN_0_3, 6
        valignq         %%ZT3, %%CIPHER_PLAIN_8_11, %%CIPHER_PLAIN_4_7, 6
        valignq         %%ZT4, %%CIPHER_PLAIN_12_15, %%CIPHER_PLAIN_8_11, 6

        ;; store last cipher text block to be used for next 16 blocks
        vmovdqa64       %%LAST_CIPH_BLK, %%CIPHER_PLAIN_12_15

        ;; AES rounds
%assign j 0
%rep (%%NROUNDS + 2)
        ZMM_AESENC_ROUND_BLOCKS_0_16 %%ZT1, %%ZT2, \
                        %%ZT3, %%ZT4, \
                        ZKEY %+ j, j, no_data, no_data, no_data, no_data, \
                        16, %%NROUNDS
%assign j (j + 1)
%endrep

        ;; XOR with decrypted blocks to get plain text
        vpxorq          %%CIPHER_PLAIN_0_3, %%CIPHER_PLAIN_0_3, %%ZT1
        vpxorq          %%CIPHER_PLAIN_4_7, %%CIPHER_PLAIN_4_7, %%ZT2
        vpxorq          %%CIPHER_PLAIN_8_11, %%CIPHER_PLAIN_8_11, %%ZT3
        vpxorq          %%CIPHER_PLAIN_12_15, %%CIPHER_PLAIN_12_15, %%ZT4

        ;; write plain text back to output
        vmovdqu8        [%%PLAIN_OUT], %%CIPHER_PLAIN_0_3
        vmovdqu8        [%%PLAIN_OUT + 64], %%CIPHER_PLAIN_4_7
        vmovdqu8        [%%PLAIN_OUT + 128], %%CIPHER_PLAIN_8_11
        vmovdqu8        [%%PLAIN_OUT + 192], %%CIPHER_PLAIN_12_15

        ;; adjust input pointer and length
        sub             %%LENGTH, (16 * 16)
        add             %%CIPH_IN, (16 * 16)
        add             %%PLAIN_OUT, (16 * 16)

%endmacro       ; DECRYPT_16_PARALLEL

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
%define %%LENGTH        %5 ;; [in/out] GP register with length in bytes
%define %%NROUNDS       %6 ;; [in] Number of AES rounds; numerical value

%ifndef LINUX
        mov     %%LENGTH, [rsp + 8*5]
%endif
        cmp     %%LENGTH, 0
        je      %%cfb_dec_done

        vinserti64x2 zIV, zIV, [%%IV], 3

        ;; preload keys
        LOAD_KEYS %%KEYS, %%NROUNDS

align_loop
%%decrypt_16_parallel:
        cmp     %%LENGTH, 256
        jb      %%final_blocks

        DECRYPT_16_PARALLEL %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, \
                                zBLK_0_3, zBLK_4_7, zBLK_8_11, zBLK_12_15, \
                                zTMP0, zTMP1, zTMP2, zTMP3, %%NROUNDS
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
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 15, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done
align_label
%%final_blocks_is_9_11:
        cmp     %%LENGTH, 10
        je      %%final_num_blocks_is_10
        jb      %%final_num_blocks_is_9

;; final num blocks is 11:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 11, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
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
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 7, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_blocks_is_1_3:
        cmp     %%LENGTH, 2
        je      %%final_num_blocks_is_2
        jb      %%final_num_blocks_is_1

;; final num blocks is 3:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 3, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_14:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 14, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_13:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 13, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_12:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 12, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_10:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 10, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_9:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 9, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_8:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 8, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_6:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 6, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_5:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 5, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_4:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 4, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_2:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 2, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS
        jmp     %%cfb_dec_done

align_label
%%final_num_blocks_is_1:
        FINAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, zIV, 1, zBLK_0_3, zBLK_4_7, \
                        zBLK_8_11, zBLK_12_15, zTMP0, zTMP1, zTMP2, zTMP3, \
                        %%NROUNDS

align_label
%%cfb_dec_done:
%ifdef SAFE_DATA
        clear_all_zmms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA

%endmacro ;; AES_CFB_DEC


;; =============================================================================
;; void aes_cfb_/*128/192/256*/_dec_vaes_avx512
;;(void *out, void *in, void *iv, void *keys, uint64_t len)
;; arg 1: OUT : addr to put clear/cipher text out
;; arg 2: IN  : addr to take cipher/clear text from
;; arg 3: IV  : initialization vector
;; arg 4: KEYS: pointer to expanded keys structure (16 byte aligned)
;; arg 5: LEN:  length of the text to encrypt/decrypt

;; =============================================================================
;; void aes_cfb_128_dec_vaes_avx512
mksection .text
align_function
MKGLOBAL(aes_cfb_dec_128_vaes_avx512,function,internal)
aes_cfb_dec_128_vaes_avx512:
        AES_CFB_DEC arg2, arg1, arg4, arg3, arg5, 9
        ret

;; =============================================================================
;; void aes_cfb_192_dec_vaes_avx512
align_function
MKGLOBAL(aes_cfb_dec_192_vaes_avx512,function,internal)
aes_cfb_dec_192_vaes_avx512:
        AES_CFB_DEC arg2, arg1, arg4, arg3, arg5, 11
        ret

;; =============================================================================
;; void aes_cfb_256_dec_vaes_avx512
align_function
MKGLOBAL(aes_cfb_dec_256_vaes_avx512,function,internal)
aes_cfb_dec_256_vaes_avx512:
        AES_CFB_DEC arg2, arg1, arg4, arg3, arg5, 13

        ret

mksection stack-noexec
