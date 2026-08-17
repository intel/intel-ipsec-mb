;;
;; Copyright (c) 2022-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

; routine to do AES ECB 256 encrypt/decrypt on 16n bytes doing AES by 8

%define AES_ECB_NROUNDS 14

%include "include/os.inc"
%include "avx2_t1/aes128_ecb_by8_avx.asm"
