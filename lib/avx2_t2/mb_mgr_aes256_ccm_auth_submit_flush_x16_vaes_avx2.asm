;;
;; Copyright (c) 2025-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef AES_CBC_MAC
%define AES_CBC_MAC aes256_cbc_mac_vaes_avx2
%define NUM_KEYS 15
%define NROUNDS 13
%define SUBMIT_JOB_AES_CCM_AUTH submit_job_aes256_ccm_auth_vaes_avx2
%define FLUSH_JOB_AES_CCM_AUTH flush_job_aes256_ccm_auth_vaes_avx2
%endif

%include "avx2_t2/mb_mgr_aes128_ccm_auth_submit_flush_x16_vaes_avx2.asm"
