;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef AES_CBC_MAC
%define AES_CBC_MAC aes256_cbc_mac_vaes_avx512
%define AES_CBC_MAC_FLUSH aes256_cbc_mac_flush_vaes_avx512
%define SUBMIT_JOB_AES_CMAC_AUTH submit_job_aes256_cmac_auth_vaes_avx512
%define FLUSH_JOB_AES_CMAC_AUTH flush_job_aes256_cmac_auth_vaes_avx512
%define NUM_KEYS 15
%endif

%include "avx512_t2/mb_mgr_aes128_cmac_submit_flush_x16_vaes_avx512.asm"
