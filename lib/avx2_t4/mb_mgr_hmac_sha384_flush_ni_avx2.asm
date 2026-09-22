;;
;; Copyright (c) 2024-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define FUNC flush_job_hmac_sha_384_ni_avx2
%define SHA_X_DIGEST_SIZE 384

%include "avx2_t4/mb_mgr_hmac_sha512_flush_ni_avx2.asm"
