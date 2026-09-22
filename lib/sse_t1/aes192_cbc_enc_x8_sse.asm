;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; AES-CBC-192

%include "include/aes_cbc_enc_x8_sse.inc"
%include "include/align_sse.inc"

mksection .text

MKGLOBAL(aes_cbc_enc_192_x8_sse,function,internal)
align_function
aes_cbc_enc_192_x8_sse:
        AES_CBC_X8 CBC, 11, 16, {arg1 + _aesarg_IV}, {arg1 + _aesarg_keys}, {arg1 + _aesarg_in}, {arg1 + _aesarg_out}
        ret

mksection stack-noexec
