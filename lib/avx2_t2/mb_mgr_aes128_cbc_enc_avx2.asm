;;
;; Copyright (c) 2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/const.inc"
%include "include/clear_regs.inc"

%ifndef AES_ENC_X16
%define AES_ENC_X16 aes_cbc_enc_128_vaes_avx2
%define MODE CBC
%define NUM_KEYS 11
%define SUBMIT_JOB_AES_ENC submit_job_aes128_cbc_enc_vaes_avx2
%define FLUSH_JOB_AES_ENC flush_job_aes128_cbc_enc_vaes_avx2
%endif

%include "avx2_t2/mb_mgr_aes128_cfb_enc_avx2.asm"
