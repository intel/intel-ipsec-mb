;;
;; Copyright (c) 2012-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; AES-CBC-256

%include "include/aes_cbc_enc_x8_avx.inc"
%include "include/align_avx.inc"

mksection .text

align_function
MKGLOBAL(aes_cbc_enc_256_x8,function,internal)
aes_cbc_enc_256_x8:
        AES_CBC_X8 CBC, 13, 16, {arg1 + _aesarg_IV}, {arg1 + _aesarg_keys}, {arg1 + _aesarg_in}, {arg1 + _aesarg_out}
        ret

mksection stack-noexec
