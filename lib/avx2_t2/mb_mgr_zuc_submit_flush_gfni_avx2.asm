;;
;; Copyright (c) 2022-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;
%define SUBMIT_JOB_ZUC128_EEA3 submit_job_zuc_eea3_gfni_avx2
%define FLUSH_JOB_ZUC128_EEA3 flush_job_zuc_eea3_gfni_avx2
%define SUBMIT_JOB_ZUC_NEA6 submit_job_zuc_nea6_gfni_avx2
%define FLUSH_JOB_ZUC_NEA6 flush_job_zuc_nea6_gfni_avx2
%define SUBMIT_JOB_ZUC128_EIA3 submit_job_zuc_eia3_gfni_avx2
%define FLUSH_JOB_ZUC128_EIA3 flush_job_zuc_eia3_gfni_avx2
%define ZUC128_INIT_8        asm_ZucInitialization_8_gfni_avx2
%define ZUCNEA6_INIT_8       asm_ZucNEA6Initialization_8_gfni_avx2
%define ZUC_EIA3_8_BUFFER    zuc_eia3_8_buffer_job_gfni_avx2
%define ZUC_CIPHER_8      asm_ZucCipher_8_gfni_avx2
%include "avx2_t1/mb_mgr_zuc_submit_flush_avx2.asm"
