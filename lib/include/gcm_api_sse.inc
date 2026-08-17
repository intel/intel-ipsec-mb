;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2024 Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;

%include "include/gcm_sse.inc"
%include "include/imb_job.inc"
%include "include/align_sse.inc"

%ifndef GCM_API_SSE_INC
%define GCM_API_SSE_INC

section .text
default rel

extern aes_gcm_enc_sse
extern aes_gcm_dec_sse
extern aes_gcm_enc_var_iv_sse
extern aes_gcm_dec_var_iv_sse
extern aes_gcm_precomp_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_precomp_128_sse / aes_gcm_precomp_192_sse / aes_gcm_precomp_256_sse
;        (struct gcm_key_data *key_data);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(precomp,_),function,)
FN_NAME(precomp,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_precomp_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_sse / aes_gcm_enc_192_sse / aes_gcm_enc_256_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *out,
;        const   u8 *in,
;        u64     msg_len,
;        u8      *iv,
;        const   u8 *aad,
;        u64     aad_len,
;        u8      *auth_tag,
;        u64     auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_),function,)
FN_NAME(enc,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_sse / aes_gcm_dec_192_sse / aes_gcm_dec_256_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *out,
;        const   u8 *in,
;        u64     msg_len,
;        u8      *iv,
;        const   u8 *aad,
;        u64     aad_len,
;        u8      *auth_tag,
;        u64     auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_),function,)
FN_NAME(dec,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB *aes_gcm_enc_var_iv_128_sse / aes_gcm_enc_var_iv_192_sse /
;       aes_gcm_enc_var_iv_256_sse(IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc_var_iv,_),function,internal)
FN_NAME(enc_var_iv,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_var_iv_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB *aes_gcm_dec_var_iv_128_sse / aes_gcm_dec_var_iv_192_sse /
;       aes_gcm_dec_var_iv_256_sse(IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec_var_iv,_),function,internal)
FN_NAME(dec_var_iv,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_var_iv_sse

mksection stack-noexec
%endif ; GCM_API_SSE_INC
