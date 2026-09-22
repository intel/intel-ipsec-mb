;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; AES-XCBC-128

%include "include/aes_cbc_enc_x8_avx.inc"
%include "include/align_avx.inc"

mksection .text

align_function
MKGLOBAL(aes_xcbc_mac_128_x8,function,internal)
aes_xcbc_mac_128_x8:
        AES_CBC_X8 CBC_XCBC_MAC, 9, 16, {arg1 + _aesxcbcarg_ICV}, {arg1 + _aesxcbcarg_keys}, {arg1 + _aesxcbcarg_in}
        ret

mksection stack-noexec
