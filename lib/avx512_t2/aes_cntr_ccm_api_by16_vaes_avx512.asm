;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019-2024, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%include "include/aes_cntr_by16_vaes_avx512.inc"
%include "include/cet.inc"
%include "include/align_avx512.inc"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;IMB_JOB * aes_cntr_ccm_128_vaes_avx512(IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_ccm_128_vaes_avx512,function,internal)
align_function
aes_cntr_ccm_128_vaes_avx512:
        endbranch64
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CCM)
        CNTR_ENC_DEC arg1, 9, CCM
        FUNC_RESTORE CNTR

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;IMB_JOB * aes_cntr_ccm_256_vaes_avx512(IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_ccm_256_vaes_avx512,function,internal)
align_function
aes_cntr_ccm_256_vaes_avx512:
        endbranch64
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CCM)
        CNTR_ENC_DEC arg1, 13, CCM
        FUNC_RESTORE CNTR

        ret

mksection stack-noexec
