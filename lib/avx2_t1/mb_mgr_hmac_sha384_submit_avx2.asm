;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define FUNC submit_job_hmac_sha_384_avx2
%define SHA_X_DIGEST_SIZE 384

%include "avx2_t1/mb_mgr_hmac_sha512_submit_avx2.asm"
