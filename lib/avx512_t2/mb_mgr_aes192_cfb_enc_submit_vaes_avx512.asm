;;
;; Copyright (c) 2024-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define AES_CFB_ENC_X16 aes_cfb_enc_192_vaes_avx512
%define SUBMIT_JOB_AES_CFB_ENC submit_job_aes192_cfb_enc_vaes_avx512
%define NUM_KEYS 13
%include "avx512_t2/mb_mgr_aes128_cfb_enc_submit_vaes_avx512.asm"
