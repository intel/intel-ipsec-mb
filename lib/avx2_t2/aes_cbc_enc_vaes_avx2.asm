;;
;; Copyright (c) 2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;;; routines to do 128/192/256 bit CBC AES encrypt

%define AES_CBC_CMAC
%include "avx2_t2/aes_cfb_enc_vaes_avx2.asm"
%include "include/align_avx.inc"

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cbc_enc_128_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes_cbc_enc_128_vaes_avx2,function,internal)
aes_cbc_enc_128_vaes_avx2:
        AES_ENC_16 11, CBC
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cbc_enc_192_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes_cbc_enc_192_vaes_avx2,function,internal)
aes_cbc_enc_192_vaes_avx2:
        AES_ENC_16 13, CBC
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cbc_enc_256_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes_cbc_enc_256_vaes_avx2,function,internal)
aes_cbc_enc_256_vaes_avx2:
        AES_ENC_16 15, CBC
        ret

mksection stack-noexec
