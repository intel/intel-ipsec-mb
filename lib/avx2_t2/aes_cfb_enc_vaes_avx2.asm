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

;;; routines to do 128/192/256 bit CFB AES encrypt

%include "include/os.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/aes_common.inc"

%ifdef LINUX
%define arg1            rdi
%define arg2            rsi
%else
%define arg1            rcx
%define arg2            rdx
%endif

%define AES_ARGS        arg1
%define LEN             arg2
%define INDEX           rbx

%define I0_0            r8
%define I0_1            r9
%define I0_2            r10
%define I0_3            r11
%define I0_4            r12
%define I0_5            r13
%define I0_6            r14
%define I0_7            r15
%define IN_OUT_0_7      I0_0, I0_1, I0_2, I0_3, I0_4, I0_5, I0_6, I0_7

%define LANE_0_1        ymm0
%define LANE_2_3        ymm1
%define LANE_4_5        ymm2
%define LANE_6_7        ymm3
%define LANE_8_9        ymm4
%define LANE_10_11      ymm5
%define LANE_12_13      ymm6
%define LANE_14_15      ymm7
%define LANE_0_7        LANE_0_1, LANE_2_3, LANE_4_5, LANE_6_7
%define LANE_8_15       LANE_8_9, LANE_10_11, LANE_12_13, LANE_14_15

%define TMP_0           ymm8
%define TMP_1           ymm9
%define TMP_2           ymm10
%define TMP_3           ymm11
%define TMP_4           ymm12
%define TMP_5           ymm13
%define TMP_6           ymm14
%define TMP_7           ymm15
%define TMP_0_3         TMP_0, TMP_1, TMP_2, TMP_3
%define TMP_4_7         TMP_4, TMP_5, TMP_6, TMP_7

%define KP              AES_ARGS + _aes_args_key_tab
%define IV              AES_ARGS + _aes_args_IV
%define IN_PTRS         AES_ARGS + _aes_args_in
%define OUT_PTRS        AES_ARGS + _aes_args_out

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Load (input or output) pointers to defined GPs:
; IO_(0...7) starting from %1 + 8 * %2
%macro LOAD_PTRx8 2
%define %%BASE_PTR        %1  ;;
%define %%LANE_START_ID   %2  ;;
        mov     I0_0, [%%BASE_PTR + 8 * %%LANE_START_ID]
        mov     I0_1, [%%BASE_PTR + 8 * (%%LANE_START_ID + 1)]
        mov     I0_2, [%%BASE_PTR + 8 * (%%LANE_START_ID + 2)]
        mov     I0_3, [%%BASE_PTR + 8 * (%%LANE_START_ID + 3)]
        mov     I0_4, [%%BASE_PTR + 8 * (%%LANE_START_ID + 4)]
        mov     I0_5, [%%BASE_PTR + 8 * (%%LANE_START_ID + 5)]
        mov     I0_6, [%%BASE_PTR + 8 * (%%LANE_START_ID + 6)]
        mov     I0_7, [%%BASE_PTR + 8 * (%%LANE_START_ID + 7)]
%endmacro ;; LOAD_PTRx8

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; AESENC_ROUNDS_x16 macro
; - 16 lanes, 1 block per lane
; - performs AES encrypt rounds 1-NROUNDS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro AESENC_ROUNDS_x16 9
%define %%LANE_0_1      %1      ; [out] ymm lanes 0-1 blocks
%define %%LANE_2_3      %2      ; [out] ymm lanes 2-3 blocks
%define %%LANE_4_5      %3      ; [out] ymm lanes 4-5 blocks
%define %%LANE_6_7      %4      ; [out] ymm lanes 6-7 blocks
%define %%LANE_8_9      %5      ; [out] ymm lanes 8-9 blocks
%define %%LANE_10_11    %6      ; [out] ymm lanes 10-11 blocks
%define %%LANE_12_13    %7      ; [out] ymm lanes 12-13 blocks
%define %%LANE_14_15    %8      ; [out] ymm lanes 14-15 blocks
%define %%NROUNDS       %9      ; [in] number of aes rounds

%assign %%ROUND 0
%rep    (%%NROUNDS)
%assign %%lane1 0

%rep    8
%assign %%lane2 (%%lane1 + 1)
        %if %%ROUND == 0
        vpxor           %%LANE_%+%%lane1%+_%+%%lane2, %%LANE_%+%%lane1%+_%+%%lane2,    \
                        [KP + %%lane1 * 16]
        %elif %%ROUND == (%%NROUNDS - 1)
        vaesenclast     %%LANE_%+%%lane1%+_%+%%lane2, %%LANE_%+%%lane1%+_%+%%lane2,    \
                        [KP + %%lane1 * 16 + %%ROUND * (16 * 16)]
        %else
        vaesenc         %%LANE_%+%%lane1%+_%+%%lane2, %%LANE_%+%%lane1%+_%+%%lane2,    \
                        [KP + %%lane1 * 16 + %%ROUND * (16 * 16)]
        %endif
%assign %%lane1 (%%lane1 + 2)
%endrep

%assign %%ROUND (%%ROUND + 1)
%endrep
%endmacro       ; AESENC_ROUNDS_x16

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; For last block processing read only 128bits from input, put data into
;; LANE_ (0 - 15)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro RD_SINGLE_BLOCK 9
%define %%IDX           %1      ; [in] offset to read data from
%define %%LANE_0_1      %2      ; [out] ymm lanes 0-1 blocks
%define %%LANE_2_3      %3      ; [out] ymm lanes 2-3 blocks
%define %%LANE_4_5      %4      ; [out] ymm lanes 4-5 blocks
%define %%LANE_6_7      %5      ; [out] ymm lanes 6-7 blocks
%define %%LANE_8_9      %6      ; [out] ymm lanes 8-9 blocks
%define %%LANE_10_11    %7      ; [out] ymm lanes 10-11 blocks
%define %%LANE_12_13    %8      ; [out] ymm lanes 12-13 blocks
%define %%LANE_14_15    %9      ; [out] ymm lanes 14-15 blocks
        LOAD_PTRx8 IN_PTRS, 0
        vmovdqu         XWORD(%%LANE_0_1), [I0_0 + %%IDX]
        vmovdqu         XWORD(%%LANE_2_3), [I0_2 + %%IDX]
        vmovdqu         XWORD(%%LANE_4_5), [I0_4 + %%IDX]
        vmovdqu         XWORD(%%LANE_6_7), [I0_6 + %%IDX]
        vinserti128     %%LANE_0_1, [I0_1 + %%IDX], 1
        vinserti128     %%LANE_2_3, [I0_3 + %%IDX], 1
        vinserti128     %%LANE_4_5, [I0_5 + %%IDX], 1
        vinserti128     %%LANE_6_7, [I0_7 + %%IDX], 1

        LOAD_PTRx8 IN_PTRS, 8
        vmovdqu         XWORD(%%LANE_8_9), [I0_0 + %%IDX]
        vmovdqu         XWORD(%%LANE_10_11), [I0_2 + %%IDX]
        vmovdqu         XWORD(%%LANE_12_13), [I0_4 + %%IDX]
        vmovdqu         XWORD(%%LANE_14_15), [I0_6 + %%IDX]
        vinserti128     %%LANE_8_9, [I0_1 + %%IDX], 1
        vinserti128     %%LANE_10_11, [I0_3 + %%IDX], 1
        vinserti128     %%LANE_12_13, [I0_5 + %%IDX], 1
        vinserti128     %%LANE_14_15, [I0_7 + %%IDX], 1
%endmacro ;; RD_SINGLE_BLOCK

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; write out single block per from %1-%4:
;; [I0_0 + %%IDX] <- %1 low 128 bits
;; [I0_1 + %%IDX] <- %1 high 128 bits
;; ...
;; [I0_6 + %%IDX] <- %4 low 128 bits
;; [I0_7 + %%IDX] <- %4 high 128 bits
;; Assume IO_* ptrs are set to correct lanes outputs
%macro  WRITE_OUT_1BLOCK 5
%define %%LANE_0_1        %1      ; [in] ymm lanes 0 and 1 encrypted blocks
%define %%LANE_2_3        %2      ; [in] ymm lanes 2 and 3 encrypted blocks
%define %%LANE_4_5        %3      ; [in] ymm lanes 4 and 5 encrypted blocks
%define %%LANE_6_7        %4      ; [in] ymm lanes 6 and 7 encrypted blocks
%define %%IDX             %5      ; [in] offset to store data

        ;; Write out results from LANE_0_7, LANE_8_15
        vmovdqu         [I0_0 + %%IDX], XWORD(%%LANE_0_1)
        vmovdqu         [I0_2 + %%IDX], XWORD(%%LANE_2_3)
        vmovdqu         [I0_4 + %%IDX], XWORD(%%LANE_4_5)
        vmovdqu         [I0_6 + %%IDX], XWORD(%%LANE_6_7)
        vextracti128    [I0_1 + %%IDX], %%LANE_0_1, 1
        vextracti128    [I0_3 + %%IDX], %%LANE_2_3, 1
        vextracti128    [I0_5 + %%IDX], %%LANE_4_5, 1
        vextracti128    [I0_7 + %%IDX], %%LANE_6_7, 1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Encrypt 1 block for 16 lanes at a time.
;; Assume previous ciphertext / IV blocks are in LANE_0-15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro ENCRYPT_1_BLOCK_16_LANES 3
%define %%IDX           %1      ; [in] offset to read data from
%define %%NROUNDS       %2      ; [in] number of AES rounds to perform
%define %%MODE          %3      ; [in] flag to indicate mode (CFB or CBC)

        ;; read 1 block per each lane
        RD_SINGLE_BLOCK         %%IDX, TMP_0_3, TMP_4_7
 
%ifidn %%MODE, CFB
        ;; encrypt previous ciphertext/IV
        AESENC_ROUNDS_x16       LANE_0_7, LANE_8_15, %%NROUNDS
%endif
        ;; XOR with plaintext
        YMM_OPCODE3_DSTR_SRC1R_SRC2M_BLOCKS_0_16        16, vpxor,              \
                LANE_0_7, LANE_8_15, LANE_0_7, LANE_8_15, TMP_0_3, TMP_4_7

%ifidn %%MODE, CBC
        ;; encrypt previous ciphertext/IV XOR plaintext
        AESENC_ROUNDS_x16       LANE_0_7, LANE_8_15, %%NROUNDS
%endif

        ;; Write out results from LANE_0_7, LANE_8_15
        LOAD_PTRx8 OUT_PTRS, 0
        WRITE_OUT_1BLOCK        LANE_0_7, %%IDX

        LOAD_PTRx8 OUT_PTRS, 8
        WRITE_OUT_1BLOCK        LANE_8_15, %%IDX

%endmacro ;; ENCRYPT_1_BLOCK_16_LANES

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Encrypt data for 16 lanes (process only lengths that are multiples of
; 16 bytes)
;   - loop encrypting LEN bytes of input data
;   - each loop encrypts 1 block across 16 lanes
; clobbers GP registers r8 - r15, rbx and arg2 (Linux:rsi/Windows rdx)
; clobbers ymm0:ymm15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro AES_ENC_16 2
%define %%NROUNDS       %1  ;; [in] Number of AES rounds; numerical value
%define %%MODE          %2  ;; [in] flag to indicate mode (CFB or CBC)

        ;; load IVs / prev ciphertexts per lane
        vmovdqa         LANE_0_1, [IV + 32 * 0]
        vmovdqa         LANE_2_3, [IV + 32 * 1]
        vmovdqa         LANE_4_5, [IV + 32 * 2]
        vmovdqa         LANE_6_7, [IV + 32 * 3]
        vmovdqa         LANE_8_9, [IV + 32 * 4]
        vmovdqa         LANE_10_11, [IV + 32 * 5]
        vmovdqa         LANE_12_13, [IV + 32 * 6]
        vmovdqa         LANE_14_15, [IV + 32 * 7]
        xor             INDEX, INDEX

align 32
%%encrypt_16_start:
        cmp             LEN, 16
        jb              %%encrypt_end

        ENCRYPT_1_BLOCK_16_LANES INDEX, %%NROUNDS, %%MODE
        sub             LEN, 16
        add             INDEX, 16
        jmp             %%encrypt_16_start

%%encrypt_end:
        ;; Store last cipher block for next blocks processing in case job per
        ;; lane is not yet completed
        vmovdqa         [IV + 16 * 0], LANE_0_1
        vmovdqa         [IV + 16 * 2], LANE_2_3
        vmovdqa         [IV + 16 * 4], LANE_4_5
        vmovdqa         [IV + 16 * 6], LANE_6_7
        vmovdqa         [IV + 16 * 8], LANE_8_9
        vmovdqa         [IV + 16 * 10], LANE_10_11
        vmovdqa         [IV + 16 * 12], LANE_12_13
        vmovdqa         [IV + 16 * 14], LANE_14_15

        ;; update input and output ptrs in AES_ARGS
        vmovq           XWORD(TMP_0), INDEX
        vpbroadcastq    TMP_0, XWORD(TMP_0)

        ;; calculate new pointers by adding number of bytes processed
        vpaddq          TMP_1, TMP_0, [IN_PTRS]
        vpaddq          TMP_2, TMP_0, [IN_PTRS + 32 * 1]
        vpaddq          TMP_3, TMP_0, [IN_PTRS + 32 * 2]
        vpaddq          TMP_4, TMP_0, [IN_PTRS + 32 * 3]

        vpaddq          TMP_5, TMP_0, [OUT_PTRS]
        vpaddq          TMP_6, TMP_0, [OUT_PTRS + 32 * 1]
        vpaddq          TMP_7, TMP_0, [OUT_PTRS + 32 * 2]
        vpaddq          TMP_0, TMP_0, [OUT_PTRS + 32 * 3]

        ;; write new pointers to AES_ARGS
        vmovdqa          [IN_PTRS], TMP_1
        vmovdqa          [IN_PTRS + 32 * 1], TMP_2
        vmovdqa          [IN_PTRS + 32 * 2], TMP_3
        vmovdqa          [IN_PTRS + 32 * 3], TMP_4

        vmovdqa          [OUT_PTRS], TMP_5
        vmovdqa          [OUT_PTRS + 32 * 1], TMP_6
        vmovdqa          [OUT_PTRS + 32 * 2], TMP_7
        vmovdqa          [OUT_PTRS + 32 * 3], TMP_0
%%encrypt_16_done:
%endmacro ;; AES_ENC_16

%ifndef AES_CBC_CMAC

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cfb_enc_128_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(aes_cfb_enc_128_vaes_avx2,function,internal)
aes_cfb_enc_128_vaes_avx2:
        AES_ENC_16 11, CFB
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cfb_enc_192_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(aes_cfb_enc_192_vaes_avx2,function,internal)
aes_cfb_enc_192_vaes_avx2:
        AES_ENC_16 13, CFB
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cfb_enc_256_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(aes_cfb_enc_256_vaes_avx2,function,internal)
aes_cfb_enc_256_vaes_avx2:
        AES_ENC_16 15, CFB
        ret
%endif ;; AES_CBC_CMAC

mksection stack-noexec
