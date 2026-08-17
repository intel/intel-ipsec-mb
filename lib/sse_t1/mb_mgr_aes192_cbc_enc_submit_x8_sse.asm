;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define NUM_LANES 8
%define AES_CBC_ENC_X4 aes_cbc_enc_192_x8_sse
%define SUBMIT_JOB_AES_ENC submit_job_aes192_enc_x8_sse

%include "include/mb_mgr_aes_cbc_enc_submit_sse.inc"
