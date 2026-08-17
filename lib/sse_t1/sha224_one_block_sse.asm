;;
;; Copyright (c) 2012-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

; This code schedules 1 blocks at a time, with 4 lanes per block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define FUNC sha224_block_sse

%define UPDATE sha224_update_sse

%include "sse_t1/sha256_one_block_sse.asm"
