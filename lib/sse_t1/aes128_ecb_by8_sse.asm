;;
;; Copyright (c) 2021-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

; routine to do AES ECB 128 encrypt/decrypt on 16n bytes doing AES by 8

%define AES_ECB_NROUNDS 10

%include "include/os.inc"
%include "include/aes_ecb_by8_sse.inc"
