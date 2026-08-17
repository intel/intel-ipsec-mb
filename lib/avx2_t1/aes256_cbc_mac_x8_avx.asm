;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; AES-CMAC-256

%include "include/aes_cbc_enc_x8_avx.inc"
%include "include/align_avx.inc"

mksection .text

align_function
MKGLOBAL(aes256_cbc_mac_x8,function,internal)
aes256_cbc_mac_x8:
        AES_CBC_X8 CBC_XCBC_MAC, 13, 16, {arg1 + _aesarg_IV}, {arg1 + _aesarg_keys}, {arg1 + _aesarg_in}
        ret

mksection stack-noexec
