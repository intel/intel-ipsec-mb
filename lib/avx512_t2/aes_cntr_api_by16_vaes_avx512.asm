;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019-2026, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%include "include/aes_cntr_by16_vaes_avx512.inc"
%include "include/align_avx512.inc"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_128_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_128_submit_vaes_avx512,function,internal)
align_function
aes_cntr_128_submit_vaes_avx512:
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CCM)
        CNTR_ENC_DEC arg1, 9, CNTR
        FUNC_RESTORE CNTR

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_192_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_192_submit_vaes_avx512,function,internal)
align_function
aes_cntr_192_submit_vaes_avx512:
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CCM)
        CNTR_ENC_DEC arg1, 11, CNTR
        FUNC_RESTORE CNTR

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_256_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_256_submit_vaes_avx512,function,internal)
align_function
aes_cntr_256_submit_vaes_avx512:
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CCM)
        CNTR_ENC_DEC arg1, 13, CNTR
        FUNC_RESTORE CNTR

        ret

mksection stack-noexec
