;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define FUNC submit_job_hmac_sha_224_avx2
%define SHA224

%include "avx2_t1/mb_mgr_hmac_sha256_submit_avx2.asm"
