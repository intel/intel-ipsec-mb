;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2025, Intel Corporation All rights reserved.
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

%define GCM128_MODE
%include "include/gcm_vaes_avx512.inc"

%include "include/error.inc"
%include "include/clear_regs.inc"
%include "include/align_avx512.inc"

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_finalize_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;        Expects NROUNDS value (9, 11, 13) in r10
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes_gcm_enc_finalize_vaes_avx512,function,internal)
aes_gcm_enc_finalize_vaes_avx512:
;; All parameters are passed through registers
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      error_enc_fin

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      error_enc_fin

        ;; Check auth_tag != NULL
        cmp     arg3, 0
        jz      error_enc_fin

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg4, 0
        jz      error_enc_fin

        cmp     arg4, 16
        ja      error_enc_fin
%endif

        FUNC_SAVE small_frame
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call, k1, r13, r11, r12, r10
%ifdef SAFE_DATA
        ;; **xmm5, xmm6, xmm11, xmm13, xmm14 and xmm16 may contain sensitive data
        clear_zmms_avx512 xmm5, xmm6, xmm11, xmm13, xmm14, xmm16
%endif
        FUNC_RESTORE
align_label
exit_enc_fin:
        ret

%ifdef SAFE_PARAM
align_label
error_enc_fin:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check auth_tag != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_AUTH

        ;; Check auth_tag_len == 0 or > 16
        IMB_ERR_CHECK_ZERO arg4, rax, IMB_ERR_AUTH_TAG_LEN

        IMB_ERR_CHECK_ABOVE arg4, 16, rax, IMB_ERR_AUTH_TAG_LEN

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_enc_fin
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_finalize_vaes_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;        Expects NROUNDS value (9, 11, 13) in r10
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes_gcm_dec_finalize_vaes_avx512,function,internal)
aes_gcm_dec_finalize_vaes_avx512:
;; All parameters are passed through registers
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      error_dec_fin

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      error_dec_fin

        ;; Check auth_tag != NULL
        cmp     arg3, 0
        jz      error_dec_fin

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg4, 0
        jz      error_dec_fin

        cmp     arg4, 16
        ja      error_dec_fin
%endif

        FUNC_SAVE small_frame
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call, k1, r13, r11, r12, r10

%ifdef SAFE_DATA
        ;; **xmm5, xmm6, xmm11, xmm13, xmm14 and xmm16 may contain sensitive data
        clear_zmms_avx512 xmm5, xmm6, xmm11, xmm13, xmm14, xmm16
%endif

        FUNC_RESTORE
align_label
exit_dec_fin:
        ret

%ifdef SAFE_PARAM
align_label
error_dec_fin:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check auth_tag != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_AUTH

        ;; Check auth_tag_len == 0 or > 16
        IMB_ERR_CHECK_ZERO arg4, rax, IMB_ERR_AUTH_TAG_LEN

        IMB_ERR_CHECK_ABOVE arg4, 16, rax, IMB_ERR_AUTH_TAG_LEN

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_dec_fin
%endif
