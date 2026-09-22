;;
;; Copyright (c) 2024-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define AES_CFB_ENC_X16 aes_cfb_enc_256_flush_vaes_avx512
%define FLUSH_JOB_AES_CFB_ENC flush_job_aes256_cfb_enc_vaes_avx512
%define NUM_KEYS 15
%include "avx512_t2/mb_mgr_aes128_cfb_enc_flush_vaes_avx512.asm"
