;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2024 Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%include "include/gcm_sse.inc"
%include "include/align_sse.inc"

%ifndef GCM_SGL_API_SSE_INC
%define GCM_SGL_API_SSE_INC

section .text
default rel

extern aes_gcm_enc_finalize_sse
extern aes_gcm_dec_finalize_sse
extern aes_gcm_enc_update_sse
extern aes_gcm_dec_update_sse
extern aes_gcm_init_sse
extern aes_gcm_init_var_iv_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_128_sse / aes_gcm_init_192_sse / aes_gcm_init_256_sse (
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *iv,
;        const   u8 *aad,
;        u64     aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(init,_),function,)
FN_NAME(init,_):
        endbranch64
        jmp aes_gcm_init_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_var_iv_128_sse / aes_gcm_init_var_iv_192_sse /
;       aes_gcm_init_var_iv_256_sse (
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8        *iv,
;        const u64 iv_len,
;        const u8  *aad,
;        const u64 aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(init_var_iv,_),function,)
FN_NAME(init_var_iv,_):
        endbranch64
        jmp aes_gcm_init_var_iv_sse


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_update_sse / aes_gcm_enc_192_update_sse / aes_gcm_enc_256_update_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *out,
;        const   u8 *in,
;        u64     msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_update_),function,)
FN_NAME(enc,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_update_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_update_sse / aes_gcm_dec_192_update_sse / aes_gcm_dec_256_update_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *out,
;        const   u8 *in,
;        u64     msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_update_),function,)
FN_NAME(dec,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_update_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_finalize_sse / aes_gcm_enc_192_finalize_sse / aes_gcm_enc_256_finalize_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *auth_tag,
;        u64     auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_finalize_),function,)
FN_NAME(enc,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_finalize_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_finalize_sse / aes_gcm_dec_192_finalize_sse / aes_gcm_dec_256_finalize_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *auth_tag,
;        u64     auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_finalize_),function,)
FN_NAME(dec,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_finalize_sse

mksection stack-noexec
%endif ; GCM_SGL_API_SSE_INC
