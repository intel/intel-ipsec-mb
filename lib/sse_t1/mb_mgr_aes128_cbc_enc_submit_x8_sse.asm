;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define AES_CBC_ENC_X8 aes_cbc_enc_128_x8_sse
%define SUBMIT_JOB_AES_ENC submit_job_aes128_enc_x8_sse

%include "include/mb_mgr_aes_cbc_enc_submit_x8_sse.inc"
