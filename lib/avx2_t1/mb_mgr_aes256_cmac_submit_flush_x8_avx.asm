;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define AES_CBC_MAC aes256_cbc_mac_x8
%define SUBMIT_JOB_AES_CMAC_AUTH submit_job_aes256_cmac_auth_avx
%define FLUSH_JOB_AES_CMAC_AUTH flush_job_aes256_cmac_auth_avx

%include "avx2_t1/mb_mgr_aes128_cmac_submit_flush_x8_avx.asm"
