;;
;; Copyright (c) 2019-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%define CNTR_CCM_SSE
%ifndef AES_CNTR_CCM_128
%define AES_CNTR_CCM_128 aes_cntr_ccm_128_sse
%endif
%include "sse_t1/aes128_cntr_by8_sse.asm"
