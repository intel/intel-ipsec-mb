;;
;; Copyright (c) 2019-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define AES_CBC_ENC_X16 aes_cbc_enc_256_vaes_avx512
%define SUBMIT_JOB_AES_ENC submit_job_aes256_enc_vaes_avx512
%define NUM_KEYS 15
%include "avx512_t2/mb_mgr_aes128_cbc_enc_submit_avx512.asm"
