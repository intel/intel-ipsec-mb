;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define FUNC flush_job_hmac_sha_384_sse
%define SHA_X_DIGEST_SIZE 384

%include "sse_t1/mb_mgr_hmac_sha512_flush_sse.asm"
