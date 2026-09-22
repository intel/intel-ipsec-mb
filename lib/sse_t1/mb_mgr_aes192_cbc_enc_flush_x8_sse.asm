;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define NUM_LANES 8
%define AES_CBC_ENC_X8 aes_cbc_enc_192_x8_sse
%define FLUSH_JOB_AES_ENC flush_job_aes192_enc_x8_sse

%include "include/mb_mgr_aes_cbc_enc_flush_x8_sse.inc"
