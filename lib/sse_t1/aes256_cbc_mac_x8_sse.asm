;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; AES-CMAC-256

%include "include/aes_cbc_enc_x8_sse.inc"
%include "include/align_sse.inc"

mksection .text

MKGLOBAL(aes256_cbc_mac_x8_sse,function,internal)
align_function
aes256_cbc_mac_x8_sse:
        AES_CBC_X8 CBC_XCBC_MAC, 13, 16, {arg1 + _aesarg_IV}, {arg1 + _aesarg_keys}, {arg1 + _aesarg_in}
        ret

mksection stack-noexec
