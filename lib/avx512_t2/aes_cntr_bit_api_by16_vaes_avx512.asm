;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019-2024, Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%include "include/aes_cntr_by16_vaes_avx512.inc"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_bit_128_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_bit_128_submit_vaes_avx512,function,internal)
aes_cntr_bit_128_submit_vaes_avx512:
        FUNC_SAVE CNTR_BIT
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 9, CNTR_BIT
        FUNC_RESTORE CNTR_BIT

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_bit_192_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_bit_192_submit_vaes_avx512,function,internal)
aes_cntr_bit_192_submit_vaes_avx512:
        FUNC_SAVE CNTR_BIT
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 11, CNTR_BIT
        FUNC_RESTORE CNTR_BIT

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_bit_256_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_bit_256_submit_vaes_avx512,function,internal)
aes_cntr_bit_256_submit_vaes_avx512:
        FUNC_SAVE CNTR_BIT
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 13, CNTR_BIT
        FUNC_RESTORE CNTR_BIT

        ret

mksection stack-noexec
