;;
;; Copyright (c) 2022-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define USE_GFNI 1
%define ZUC_CIPHER_8 asm_ZucCipher_8_gfni_avx2
%define ZUC128_INIT_8 asm_ZucInitialization_8_gfni_avx2
%define ZUCNEA6_INIT_8 asm_ZucNEA6Initialization_8_gfni_avx2
%define ZUC_KEYGEN32B_8 asm_ZucGenKeystream32B_8_gfni_avx2
%define ZUC_KEYGEN16B_8 asm_ZucGenKeystream16B_8_gfni_avx2
%define ZUC_KEYGEN8B_8 asm_ZucGenKeystream8B_8_gfni_avx2
%define ZUC_KEYGEN4B_8 asm_ZucGenKeystream4B_8_gfni_avx2
%include "avx2_t1/zuc_x8_avx2.asm"
