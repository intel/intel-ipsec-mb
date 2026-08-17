;;
;; Copyright (c) 2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;;; routines to do 128/256 bit AES-CMAC

%define AES_CBC_CMAC
%define AES_CMAC
%define KP              AES_ARGS + _aes_cmac_args_key_tab
%define IV              AES_ARGS + _aes_cmac_args_IV
%define IN_PTRS         AES_ARGS + _aes_cmac_args_in

%include "avx2_t2/aes_cfb_enc_vaes_avx2.asm"
%include "include/align_avx.inc"

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes128_cbc_mac_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes128_cbc_mac_vaes_avx2,function,internal)
aes128_cbc_mac_vaes_avx2:
        push    rbp
        push    r15
        AES_ENC_16 11, CMAC
        pop     r15
        pop     rbp
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes256_cbc_mac_vaes_avx2(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes256_cbc_mac_vaes_avx2,function,internal)
aes256_cbc_mac_vaes_avx2:
        push    rbp
        push    r15
        AES_ENC_16 15, CMAC
        pop     r15
        pop     rbp
        ret

mksection stack-noexec
