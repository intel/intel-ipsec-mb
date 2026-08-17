;;
;; Copyright (c) 2023-2025, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%use smartalign
%include "include/aes_cntr_by16_vaes_avx2.inc"
%include "include/align_avx.inc"

%include "include/cet.inc"

;; aes_cntr_192_vaes_avx2(void *in, void *IV, void *keys, void *out, UINT64 num_bytes,
;;                        UINT64 iv_len)
align_function
MKGLOBAL(aes_cntr_192_vaes_avx2,function,internal)
aes_cntr_192_vaes_avx2:
        endbranch64
        DO_CNTR 192, CNTR
        ret

mksection stack-noexec
