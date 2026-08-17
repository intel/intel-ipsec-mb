;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define USE_GFNI 1
%define ZUC_CIPHER_4 asm_ZucCipher_4_gfni_sse
%define ZUC128_INIT_4 asm_ZucInitialization_4_gfni_sse
%define ZUCNEA6_INIT_4 asm_ZucNEA6Initialization_4_gfni_sse
%define ZUC_KEYGEN16B_4 asm_ZucGenKeystream16B_4_gfni_sse
%define ZUC_KEYGEN8B_4 asm_ZucGenKeystream8B_4_gfni_sse
%define ZUC_KEYGEN4B_4 asm_ZucGenKeystream4B_4_gfni_sse
%define ZUC_EIA3ROUND16B asm_Eia3Round16B_gfni_sse
%define ZUC_EIA3REMAINDER asm_Eia3Remainder_gfni_sse
%include "sse_t1/zuc_x4_sse.asm"
