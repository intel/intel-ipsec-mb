;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2024, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%use smartalign

%include "include/gcm_vaes_avx2.inc"
%include "include/align_avx.inc"

mksection .text
default rel

extern aes_gcm_enc_finalize
extern aes_gcm_dec_finalize
extern aes_gcm_enc_update
extern aes_gcm_dec_update
extern aes_gcm_enc_vaes_avx2
extern aes_gcm_dec_vaes_avx2
extern aes_gcm_enc_var_iv
extern aes_gcm_dec_var_iv
extern aes_gcm_precomp_vaes_avx2
extern aes_gcm_init_vaes_avx2
extern aes_gcm_init_var_iv_vaes_avx2
extern aes_gmac_update_vaes_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_precomp_128_vaes_avx2 /
;       aes_gcm_precomp_192_vaes_avx2 /
;       aes_gcm_precomp_256_vaes_avx2 /
;       (struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(precomp,_),function,)
FN_NAME(precomp,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_precomp_vaes_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_128_vaes_avx2 / aes_gcm_init_192_vaes_avx2 / aes_gcm_init_256_vaes_avx2 /
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(init,_),function,)
FN_NAME(init,_):
        endbranch64
        jmp aes_gcm_init_vaes_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_var_iv_128_vaes_avx2 / aes_gcm_init_var_iv_192_vaes_avx2 /
;       aes_gcm_init_var_iv_256_vaes_avx2
;       (const struct gcm_key_data *key_data,
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
        jmp aes_gcm_init_var_iv_vaes_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_update_vaes_avx2 / aes_gcm_enc_192_update_vaes_avx2 /
;       aes_gcm_enc_128_update_vaes_avx2 /
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_update_),function,)
FN_NAME(enc,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_update

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_update_vaes_avx2 / aes_gcm_dec_192_update_vaes_avx2 /
;       aes_gcm_dec_256_update_vaes_avx2 /
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_update_),function,)
FN_NAME(dec,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_update

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_finalize_vaes_avx2 / aes_gcm_enc_192_finalize_vaes_avx2 /
;       aes_gcm_enc_256_finalize_vaes_avx2 /
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_finalize_),function,)
FN_NAME(enc,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_finalize

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_finalize_vaes_avx2 / aes_gcm_dec_192_finalize_vaes_avx2
;       aes_gcm_dec_256_finalize_vaes_avx2 /
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_finalize_),function,)
FN_NAME(dec,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_finalize

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_vaes_avx2 / aes_gcm_enc_192_vaes_avx2 / aes_gcm_enc_256_vaes_avx2 /
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_),function,)
FN_NAME(enc,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_vaes_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_vaes_avx2 / aes_gcm_dec_192_vaes_avx2 / aes_gcm_dec_256_vaes_avx2 /
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_),function,)
FN_NAME(dec,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_vaes_avx2
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB * aes_gcm_enc_var_iv_128_vaes_avx2 / aes_gcm_enc_var_iv_192_vaes_avx2 /
;       aes_gcm_enc_var_iv_256_vaes_avx2 /
;       (IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc_var_iv,_),function,internal)
FN_NAME(enc_var_iv,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_var_iv

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB *aes_gcm_dec_var_iv_128_vaes_avx2 / aes_gcm_dec_var_iv_192_vaes_avx2 /
;       aes_gcm_dec_var_iv_256_vaes_avx2 /
;       (IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec_var_iv,_),function,internal)
FN_NAME(dec_var_iv,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_var_iv

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   imb_aes_gmac_update_128_vaes_avx2 / imb_aes_gmac_update_192_vaes_avx2 /
;       imb_aes_gmac_update_256_vaes_avx2
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        const   u8 *in,
;        const   u64 msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(GMAC_FN_NAME(update),function,)
GMAC_FN_NAME(update):
        endbranch64
        jmp aes_gmac_update_vaes_avx2

mksection stack-noexec
