;;
;; Copyright (c) 2019, Intel Corporation
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

%include "include/os.asm"
%include "include/reg_sizes.asm"

%define zIV     zmm0
%define zBLK03  zmm1
%define zBLK47  zmm2
%define zTMP0   zmm3
%define zTMP1   zmm4
%define xTMP0   xmm5

%define ZKEY0   zmm17
%define ZKEY1   zmm18
%define ZKEY2   zmm19
%define ZKEY3   zmm20
%define ZKEY4   zmm21
%define ZKEY5   zmm22
%define ZKEY6   zmm23
%define ZKEY7   zmm24
%define ZKEY8   zmm25
%define ZKEY9   zmm26
%define ZKEY10  zmm27
%define ZKEY11  zmm28
%define ZKEY12  zmm29
%define ZKEY13  zmm30
%define ZKEY14  zmm31

%ifdef LINUX
%define p_in    rdi
%define p_IV    rsi
%define p_keys  rdx
%define p_out   rcx
%define num_bytes r8
%else
%define p_in    rcx
%define p_IV    rdx
%define p_keys  r8
%define p_out   r9
%define num_bytes rax
%endif

%define tmp     r10

;; macro to preload keys
%macro LOAD_KEYS 2
%define %%KEYS          %1
%define %%NROUNDS       %2

%assign i 0
%rep (%%NROUNDS + 2)
        vbroadcastf64x2 ZKEY %+ i, [%%KEYS + 16*i]
%assign i (i + 1)
%endrep

%endmacro

;;; ===========================================================================
;;; AESDEC_ROUND_1_TO_8_BLOCKS macro to perform a single round of aesdec
;;; - 1 lane, 1 to 8 blocks per lane
;;; - it handles special cases: the last and zero rounds
;;; Uses NROUNDS macro defined at the top of the file to check the last round
%macro AESDEC_ROUND_1_TO_8_BLOCKS 6
%define %%BLK03   %1      ; [in/out] zmm; cipher text blocks 0-3
%define %%BLK47   %2      ; [in/out] zmm; cipher text blocks 4-7
%define %%NUMBL   %3      ; [in] number of blocks; numerical value
%define %%ROUND   %4      ; [in] round number
%define %%KEY     %5      ; [in] ZMM containing round keys
%define %%NROUNDS %6      ; [in] number of rounds; numerical value


;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vpxorq          %%BLK03, %%BLK03, %%KEY
        vpxorq          %%BLK47, %%BLK47, %%KEY
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vpxorq          %%BLK03, %%BLK03, %%KEY
        vpxorq          YWORD(%%BLK47), YWORD(%%BLK47), YWORD(%%KEY)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vpxorq          %%BLK03, %%BLK03, %%KEY
        vpxorq          XWORD(%%BLK47), XWORD(%%BLK47), XWORD(%%KEY)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vpxorq          %%BLK03, %%BLK03, %%KEY
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vpxorq          YWORD(%%BLK03), YWORD(%%BLK03), YWORD(%%KEY)
%else
        ;; 1 block
        vpxorq          XWORD(%%BLK03), XWORD(%%BLK03), XWORD(%%KEY)
%endif                  ; NUM BLOCKS
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vaesdec         %%BLK03, %%BLK03, %%KEY
        vaesdec         %%BLK47, %%BLK47, %%KEY
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vaesdec         %%BLK03, %%BLK03, %%KEY
        vaesdec         YWORD(%%BLK47), YWORD(%%BLK47), YWORD(%%KEY)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vaesdec         %%BLK03, %%BLK03, %%KEY
        vaesdec         XWORD(%%BLK47), XWORD(%%BLK47), XWORD(%%KEY)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vaesdec         %%BLK03, %%BLK03, %%KEY
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vaesdec         YWORD(%%BLK03), YWORD(%%BLK03), YWORD(%%KEY)
%else
        ;; 1 block
        vaesdec         XWORD(%%BLK03), XWORD(%%BLK03), XWORD(%%KEY)
%endif                  ; NUM BLOCKS
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vaesdeclast     %%BLK03, %%BLK03, %%KEY
        vaesdeclast     %%BLK47, %%BLK47, %%KEY
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vaesdeclast     %%BLK03, %%BLK03, %%KEY
        vaesdeclast     YWORD(%%BLK47), YWORD(%%BLK47), YWORD(%%KEY)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vaesdeclast     %%BLK03, %%BLK03, %%KEY
        vaesdeclast     XWORD(%%BLK47), XWORD(%%BLK47), XWORD(%%KEY)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vaesdeclast     %%BLK03, %%BLK03, %%KEY
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vaesdeclast     YWORD(%%BLK03), YWORD(%%BLK03), YWORD(%%KEY)
%else
        ;; 1 block
        vaesdeclast     XWORD(%%BLK03), XWORD(%%BLK03), XWORD(%%KEY)
%endif                  ; NUM BLOCKS
%endif                  ; The last round

%endmacro               ; AESROUND_1_TO_8_BLOCKS


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; This macro is used to "warm-up" pipeline for DECRYPT_8_PARALLEL macro code
;;; as first blocks are treated differently (XOR first block with IV).
;;; Processes the first initial %%num_initial_blocks blocks (1 to 8, can't be 0)

%macro INITIAL_BLOCKS 12
%define %%PLAIN_OUT             %1      ; [in] output buffer
%define %%CIPH_IN               %2      ; [in] input buffer
%define %%LENGTH                %3      ; [in/out] number of bytes to process
%define %%IV                    %4      ; [in/out] ZMM with IV and to store last cipher blk (in idx 3)
%define %%num_initial_blocks    %5      ; [in] 1, 2, 3, 4, 5, 6, 7 or 8
%define %%CIPHER_PLAIN_03       %6      ; [out] ZMM next 0-3 cipher blocks
%define %%CIPHER_PLAIN_47       %7      ; [out] ZMM next 4-7 cipher blocks
%define %%ZT1                   %8      ; [clobbered] ZMM temporary
%define %%ZT2                   %9      ; [clobbered] ZMM temporary
%define %%XT1                   %10     ; [clobbered] XMM temporary
%define %%IA0                   %11     ; [clobbered] GP temporary
%define %%NROUNDS               %12     ; [in] number of rounds; numerical value

%define %%xCIPHER_PLAIN_03 XWORD(%%CIPHER_PLAIN_03)
%define %%xCIPHER_PLAIN_47 XWORD(%%CIPHER_PLAIN_47)
%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)

%if %%num_initial_blocks > 0

        ;; load plain/cipher text
%if %%num_initial_blocks == 1
        vmovdqu8        %%xCIPHER_PLAIN_03, [%%CIPH_IN]
%elif %%num_initial_blocks == 2
        vmovdqu8        YWORD(%%CIPHER_PLAIN_03), [%%CIPH_IN]
%elif %%num_initial_blocks == 3
        vmovdqu8        YWORD(%%CIPHER_PLAIN_03), [%%CIPH_IN]
        vinserti64x2    %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_03, [%%CIPH_IN + 32], 2
%elif %%num_initial_blocks == 4
        vmovdqu8        %%CIPHER_PLAIN_03, [%%CIPH_IN]
%elif %%num_initial_blocks == 5
        vmovdqu8        %%CIPHER_PLAIN_03, [%%CIPH_IN]
        vmovdqu8        %%xCIPHER_PLAIN_47, [%%CIPH_IN + 64]
%elif %%num_initial_blocks == 6
        vmovdqu8        %%CIPHER_PLAIN_03, [%%CIPH_IN]
        vmovdqu8        YWORD(%%CIPHER_PLAIN_47), [%%CIPH_IN + 64]
%elif %%num_initial_blocks == 7
        vmovdqu8        %%CIPHER_PLAIN_03, [%%CIPH_IN]
        vmovdqu8        YWORD(%%CIPHER_PLAIN_47), [%%CIPH_IN + 64]
        vinserti64x2    %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_47, [%%CIPH_IN + 96], 2
%else   ;; 8 blocks
        vmovdqu8        %%CIPHER_PLAIN_03, [%%CIPH_IN]
        vmovdqu8        %%CIPHER_PLAIN_47, [%%CIPH_IN + 64]
%endif

        ;; Prepare first IV + cipher text blocks to
        ;; be XOR'd later after AESDEC
        valignq         %%ZT1, %%CIPHER_PLAIN_03, %%IV, 6
%if %%num_initial_blocks > 4
        ;; prepare second set of cipher blocks for later XOR'ing
        valignq         %%ZT2, %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_03, 6
%endif

        ;; Update IV XMM register with last cipher block
        ;; to be used later in DECRYPT_8_PARALLEL
%if %%num_initial_blocks == 1
        valignq         %%IV, %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_03, 2
%elif %%num_initial_blocks == 2
        valignq         %%IV, %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_03, 4
%elif %%num_initial_blocks == 3
        valignq         %%IV, %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_03, 6
%elif %%num_initial_blocks == 4
        vmovdqa64       %%IV, %%CIPHER_PLAIN_03
%elif %%num_initial_blocks == 5
        valignq         %%IV, %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_47, 2
%elif %%num_initial_blocks == 6
        valignq         %%IV, %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_47, 4
%elif %%num_initial_blocks == 7
        valignq         %%IV, %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_47, 6
%elif %%num_initial_blocks == 8
        vmovdqa64       %%IV, %%CIPHER_PLAIN_47
%endif

        ;; AES rounds
%assign j 0
%rep (%%NROUNDS + 2)
        AESDEC_ROUND_1_TO_8_BLOCKS %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_47, \
                                   %%num_initial_blocks, j, ZKEY %+ j, %%NROUNDS
%assign j (j + 1)
%endrep

        ;; XOR with decrypted blocks to get plain text
        vpxorq          %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_03, %%ZT1
%if %%num_initial_blocks > 4
        vpxorq          %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_47, %%ZT2
%endif

        ;; write plain text back to output
%if %%num_initial_blocks == 1
        vmovdqu8        [%%PLAIN_OUT], %%xCIPHER_PLAIN_03
%elif %%num_initial_blocks == 2
        vmovdqu8        [%%PLAIN_OUT], YWORD(%%CIPHER_PLAIN_03)
%elif %%num_initial_blocks == 3
        ;; Blocks 3
        vmovdqu8        [%%PLAIN_OUT], YWORD(%%CIPHER_PLAIN_03)
        vextracti64x2   [%%PLAIN_OUT + 32], %%CIPHER_PLAIN_03, 2
%elif %%num_initial_blocks == 4
        ;; Blocks 4
        vmovdqu8        [%%PLAIN_OUT], %%CIPHER_PLAIN_03
%elif %%num_initial_blocks == 5
        vmovdqu8        [%%PLAIN_OUT], %%CIPHER_PLAIN_03
        vmovdqu8        [%%PLAIN_OUT + 64], %%xCIPHER_PLAIN_47
%elif %%num_initial_blocks == 6
        vmovdqu8        [%%PLAIN_OUT], %%CIPHER_PLAIN_03
        vmovdqu8        [%%PLAIN_OUT + 64], YWORD(%%CIPHER_PLAIN_47)
%elif %%num_initial_blocks == 7
        ;; Blocks 7
        vmovdqu8        [%%PLAIN_OUT], %%CIPHER_PLAIN_03
        vmovdqu8        [%%PLAIN_OUT + 64], YWORD(%%CIPHER_PLAIN_47)
        vextracti64x2   [%%PLAIN_OUT + 96], %%CIPHER_PLAIN_47, 2

%else   ;; Blocks 8
        vmovdqu8        [%%PLAIN_OUT], %%CIPHER_PLAIN_03
        vmovdqu8        [%%PLAIN_OUT + 64], %%CIPHER_PLAIN_47
%endif

        ;; adjust data offset and length
        sub             %%LENGTH, (%%num_initial_blocks * 16)
        add             %%CIPH_IN, (%%num_initial_blocks * 16)
        add             %%PLAIN_OUT, (%%num_initial_blocks * 16)
%endif          ;  %%num_initial_blocks > 0

%endmacro       ; INITIAL_BLOCKS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Main AES-CBC decrypt macro
;;; - operates on single stream
;;; - decrypts 8 blocks at a time
%macro DECRYPT_8_PARALLEL 11
%define %%PLAIN_OUT             %1      ; [in] output buffer
%define %%CIPH_IN               %2      ; [in] input buffer
%define %%LENGTH                %3      ; [in/out] number of bytes to process
%define %%LAST_CIPH_BLK         %4      ; [in/out] ZMM to maintain last ciphertext block
%define %%CIPHER_PLAIN_03       %5      ; [out] ZMM next 0-3 cipher blocks
%define %%CIPHER_PLAIN_47       %6      ; [out] ZMM next 4-7 cipher blocks
%define %%ZT1                   %7      ; [clobbered] ZMM temporary
%define %%ZT2                   %8      ; [clobbered] ZMM temporary
%define %%XT1                   %9      ; [clobbered] XMM temporary
%define %%NROUNDS               %10     ; [in] number of rounds; numerical value
%define %%IA0                   %11     ; [clobbered] GP temporary

%define %%xCIPHER_PLAIN_03 XWORD(%%CIPHER_PLAIN_03)
%define %%xCIPHER_PLAIN_47 XWORD(%%CIPHER_PLAIN_47)
%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)

        vmovdqu8        %%CIPHER_PLAIN_03, [%%CIPH_IN]
        vmovdqu8        %%CIPHER_PLAIN_47, [%%CIPH_IN + 64]

        ;; prepare first set of cipher blocks for later XOR'ing
        valignq         %%ZT1, %%CIPHER_PLAIN_03, %%LAST_CIPH_BLK, 6
        valignq         %%ZT2, %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_03, 6

        ;; store last cipher text block to be used for 8 blocks
        vmovdqa64       %%LAST_CIPH_BLK, %%CIPHER_PLAIN_47

        ;; AES rounds
%assign j 0
%rep (%%NROUNDS + 2)
        AESDEC_ROUND_1_TO_8_BLOCKS %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_47, \
                                   8, j, ZKEY %+ j, %%NROUNDS
%assign j (j + 1)
%endrep

        ;; XOR with decrypted blocks to get plain text
        vpxorq          %%CIPHER_PLAIN_03, %%CIPHER_PLAIN_03, %%ZT1
        vpxorq          %%CIPHER_PLAIN_47, %%CIPHER_PLAIN_47, %%ZT2

        ;; write plain text back to output
        vmovdqu8        [%%PLAIN_OUT], %%CIPHER_PLAIN_03
        vmovdqu8        [%%PLAIN_OUT + 64], %%CIPHER_PLAIN_47

        ;; adjust input pointer and length
        sub             %%LENGTH, (8 * 16)
        add             %%CIPH_IN, (8 * 16)
        add             %%PLAIN_OUT, (8 * 16)

%endmacro       ; INITIAL_BLOCKS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; AES_CBC_DEC macro decrypts given data.
;;; Flow:
;;; - Decrypt initial 1 to 8 blocks
;;; - Decrypt the following blocks (multiple of 8)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro AES_CBC_DEC 7
%define %%CIPH_IN       %1 ;; [in] pointer to input buffer
%define %%PLAIN_OUT     %2 ;; [in] pointer to output buffer
%define %%KEYS          %3 ;; [in] pointer to expanded keys
%define %%IV            %4 ;; [in] pointer to IV
%define %%LENGTH        %5 ;; [in/out] GP register with length in bytes
%define %%NROUNDS       %6 ;; [in] Number of AES rounds; numerical value
%define %%TMP           %7 ;; [clobbered] GP register

        cmp     %%LENGTH, 0
        je      %%cbc_dec_done

        vinserti64x2 zIV, zIV, [%%IV], 3

        ;; preload keys
        LOAD_KEYS %%KEYS, %%NROUNDS

        mov     %%TMP, %%LENGTH

        ;; get num initial blocks (0 assumes 8 blocks)
        shr     %%TMP, 4
        and     %%TMP, 0x7
        je      %%initial_num_blocks_is_8
        cmp     %%TMP, 7
        je      %%initial_num_blocks_is_7
        cmp     %%TMP, 6
        je      %%initial_num_blocks_is_6
        cmp     %%TMP, 5
        je      %%initial_num_blocks_is_5
        cmp     %%TMP, 4
        je      %%initial_num_blocks_is_4
        cmp     %%TMP, 3
        je      %%initial_num_blocks_is_3
        cmp     %%TMP, 2
        je      %%initial_num_blocks_is_2
        jmp     %%initial_num_blocks_is_1

%%initial_num_blocks_is_8:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 8, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS
        jmp     %%decrypt_8_parallel

%%initial_num_blocks_is_7:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 7, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS
        jmp     %%decrypt_8_parallel

%%initial_num_blocks_is_6:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 6, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS
        jmp     %%decrypt_8_parallel

%%initial_num_blocks_is_5:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 5, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS
        jmp     %%decrypt_8_parallel

%%initial_num_blocks_is_4:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 4, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS
        jmp     %%decrypt_8_parallel

%%initial_num_blocks_is_3:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 3, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS
        jmp     %%decrypt_8_parallel

%%initial_num_blocks_is_2:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 2, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS
        jmp     %%decrypt_8_parallel

%%initial_num_blocks_is_1:
        INITIAL_BLOCKS %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, 1, \
                       zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%TMP, %%NROUNDS

%%decrypt_8_parallel:
        cmp     %%LENGTH, 0
        je      %%cbc_dec_done

        DECRYPT_8_PARALLEL %%PLAIN_OUT, %%CIPH_IN, %%LENGTH, zIV, \
                           zBLK03, zBLK47, zTMP0, zTMP1, xTMP0, %%NROUNDS, %%TMP
        jmp     %%decrypt_8_parallel

%%cbc_dec_done:
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; aes_cbc_dec_128_vaes_avx512(void *in, void *IV, void *keys, void *out, UINT64 num_bytes)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cbc_dec_128_vaes_avx512,function,internal)
aes_cbc_dec_128_vaes_avx512:
%ifndef LINUX
        mov     num_bytes, [rsp + 8*5]
%endif
        AES_CBC_DEC p_in, p_out, p_keys, p_IV, num_bytes, 9, tmp

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; aes_cbc_dec_192_vaes_avx512(void *in, void *IV, void *keys, void *out, UINT64 num_bytes)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cbc_dec_192_vaes_avx512,function,internal)
aes_cbc_dec_192_vaes_avx512:
%ifndef LINUX
        mov     num_bytes, [rsp + 8*5]
%endif
        AES_CBC_DEC p_in, p_out, p_keys, p_IV, num_bytes, 11, tmp

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; aes_cbc_dec_256_vaes_avx512(void *in, void *IV, void *keys, void *out, UINT64 num_bytes)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cbc_dec_256_vaes_avx512,function,internal)
aes_cbc_dec_256_vaes_avx512:
%ifndef LINUX
        mov     num_bytes, [rsp + 8*5]
%endif
        AES_CBC_DEC p_in, p_out, p_keys, p_IV, num_bytes, 13, tmp

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif

