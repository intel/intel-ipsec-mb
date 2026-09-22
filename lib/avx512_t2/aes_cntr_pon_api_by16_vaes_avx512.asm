;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019-2026, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


%include "include/aes_cntr_by16_vaes_avx512.inc"
%include "include/align_avx512.inc"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_pon_enc_128_vaes_avx512 (void *src, void *dst, void *iv, void *keys, uint64_t length, uint32_t *bip)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_pon_enc_128_vaes_avx512,function,internal)
align_function
aes_cntr_pon_enc_128_vaes_avx512:
        CNTR_PON_ENC_DEC ENCRYPT

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_pon_dec_128_vaes_avx512 (void *src, void *dst, void *iv, void *keys, uint64_t length, uint32_t *bip)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_pon_dec_128_vaes_avx512,function,internal)
align_function
aes_cntr_pon_dec_128_vaes_avx512:
        CNTR_PON_ENC_DEC DECRYPT

        ret

mksection stack-noexec
