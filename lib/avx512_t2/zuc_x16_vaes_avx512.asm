;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2026, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define USE_GFNI_VAES_VPCLMUL 1
%define CIPHER_16 asm_ZucCipher_16_gfni_avx512
%define CIPHER_INIT_16 asm_ZucCipherInit_16_gfni_avx512
%define ZUC128_INIT asm_ZucInitialization_16_gfni_avx512
%define ZUCNEA6_INIT asm_ZucNEA6Initialization_16_gfni_avx512
%define ZUC128_LFSR_LOAD asm_ZucLfsrLoad_gfni_avx512
%define ZUCNEA6_LFSR_LOAD asm_ZucNEA6LfsrLoad_gfni_avx512
%define ZUC128_REMAINDER_16 asm_Eia3RemainderAVX512_16_VPCLMUL
%define ZUC_KEYGEN64B_16 asm_ZucGenKeystream64B_16_gfni_avx512
%define ZUC_KEYGEN8B_16 asm_ZucGenKeystream8B_16_gfni_avx512
%define ZUC_KEYGEN_16 asm_ZucGenKeystream_16_gfni_avx512
%define ZUC_KEYGEN64B_SKIP8_16 asm_ZucGenKeystream64B_16_skip8_gfni_avx512
%define ZUC_KEYGEN_SKIP8_16 asm_ZucGenKeystream_16_skip8_gfni_avx512
%define ZUC_ROUND64B_16 asm_Eia3Round64B_16_VPCLMUL
%define ZUC_EIA3_N64B asm_Eia3_Nx64B_AVX512_16_VPCLMUL
%include "avx512_t1/zuc_x16_avx512.asm"
