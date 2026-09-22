;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define AES_CBC_ENC_X8 aes_cbc_enc_192_x8
%define FLUSH_JOB_AES_ENC flush_job_aes192_cbc_enc_avx
%include "avx2_t1/mb_mgr_aes128_cbc_enc_flush_avx.asm"
