;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;
%define SUBMIT_JOB_ZUC128_EEA3 submit_job_zuc_eea3_gfni_avx512
%define FLUSH_JOB_ZUC128_EEA3 flush_job_zuc_eea3_gfni_avx512
%define SUBMIT_JOB_ZUC_NEA6 submit_job_zuc_nea6_gfni_avx512
%define FLUSH_JOB_ZUC_NEA6 flush_job_zuc_nea6_gfni_avx512
%define SUBMIT_JOB_ZUC128_EIA3 submit_job_zuc_eia3_gfni_avx512
%define FLUSH_JOB_ZUC128_EIA3 flush_job_zuc_eia3_gfni_avx512
%define ZUC128_INIT_16        asm_ZucInitialization_16_gfni_avx512
%define ZUC_CIPHER         asm_ZucCipher_16_gfni_avx512
%define ZUC_CIPHER_INIT    asm_ZucCipherInit_16_gfni_avx512
%define ZUC128_LFSR_LOAD_16  asm_ZucLfsrLoad_gfni_avx512
%define ZUCNEA6_LFSR_LOAD_16 asm_ZucNEA6LfsrLoad_gfni_avx512
%define ZUCNEA6_INIT_16     asm_ZucNEA6Initialization_16_gfni_avx512
%define ZUC_REMAINDER_16   asm_Eia3RemainderAVX512_16_VPCLMUL
%define ZUC_KEYGEN_SKIP8_16 asm_ZucGenKeystream_16_skip8_gfni_avx512
%define ZUC_KEYGEN64B_SKIP8_16 asm_ZucGenKeystream64B_16_skip8_gfni_avx512
%define ZUC_KEYGEN_16      asm_ZucGenKeystream_16_gfni_avx512
%define ZUC_KEYGEN64B_16   asm_ZucGenKeystream64B_16_gfni_avx512
%define ZUC_ROUND64B       asm_Eia3Round64B_16_VPCLMUL
%define ZUC_EIA3_N64B      asm_Eia3_Nx64B_AVX512_16_VPCLMUL
%define ZUC_NIA6_16_BUFFER zuc_nia6_16_buffer_job_gfni_avx512
%define SUBMIT_JOB_ZUC_NIA6 submit_job_zuc_nia6_gfni_avx512
%define FLUSH_JOB_ZUC_NIA6 flush_job_zuc_nia6_gfni_avx512
%define ZUC_NCA6_16_BUFFER zuc_nca6_16_buffer_job_gfni_avx512
%define SUBMIT_JOB_ZUC_NCA6 submit_job_zuc_nca6_gfni_avx512
%define FLUSH_JOB_ZUC_NCA6 flush_job_zuc_nca6_gfni_avx512
%define USE_GFNI 1
%include "avx512_t1/mb_mgr_zuc_submit_flush_avx512.asm"
