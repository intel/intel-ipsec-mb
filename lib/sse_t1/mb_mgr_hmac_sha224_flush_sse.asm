;;
;; Copyright (c) 2012-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define FUNC flush_job_hmac_sha_224_sse
%define SHA224

%include "sse_t1/mb_mgr_hmac_sha256_flush_sse.asm"
