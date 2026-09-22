;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef AES_CBC_MAC
%define NROUNDS 13
%define AES_CBC_MAC aes256_cbc_mac_x8
%define SUBMIT_JOB_AES_CCM_AUTH submit_job_aes256_ccm_auth_avx
%define FLUSH_JOB_AES_CCM_AUTH flush_job_aes256_ccm_auth_avx
%endif

%include "avx2_t1/mb_mgr_aes128_ccm_auth_submit_flush_x8_avx.asm"
