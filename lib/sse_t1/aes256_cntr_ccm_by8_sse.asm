;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define CNTR_CCM_SSE
%ifndef AES_CNTR_CCM_256
%define AES_CNTR_CCM_256 aes_cntr_ccm_256_sse
%endif
%include "sse_t1/aes256_cntr_by8_sse.asm"
