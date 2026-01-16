;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2024, Intel Corporation All rights reserved.
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

%use smartalign

%include "include/gcm_common_avx2_avx512.inc"
%include "include/align_avx512.inc"

mksection .text
default rel

extern ghash_internal_avx_gen4
extern partial_block_gmac_avx_gen4
extern aes_gcm_enc_finalize_avx2
extern aes_gcm_dec_finalize_avx2
extern aes_gcm_enc_update_avx2
extern aes_gcm_dec_update_avx2
extern aes_gcm_enc_avx2
extern aes_gcm_dec_avx2
extern aes_gcm_enc_var_iv_avx2
extern aes_gcm_dec_var_iv_avx2
extern aes_gcm_init_avx2
extern aes_gcm_init_var_iv_avx2
extern aes_gcm_precomp_avx2
extern imb_aes_gmac_update_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_precomp_128_avx_gen4 /
;       aes_gcm_precomp_192_avx_gen4 /
;       aes_gcm_precomp_256_avx_gen4 /
;       aes_gcm_precomp_128_avx512 /
;       aes_gcm_precomp_192_avx512 /
;       aes_gcm_precomp_256_avx512
;       (struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(precomp,_),function,)
MKGLOBAL(FN_NAME_AVX512(precomp,_),function,)
FN_NAME(precomp,_):
FN_NAME_AVX512(precomp,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_precomp_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_128_avx_gen4 / aes_gcm_init_192_avx_gen4 / aes_gcm_init_256_avx_gen4 /
;       aes_gcm_init_128_avx512 / aes_gcm_init_192_avx512 / aes_gcm_init_256_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(init,_),function,)
MKGLOBAL(FN_NAME_AVX512(init,_),function,)
FN_NAME(init,_):
FN_NAME_AVX512(init,_):
        endbranch64
        jmp aes_gcm_init_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_var_iv_128_avx_gen4 / aes_gcm_init_var_iv_192_avx_gen4 /
;       aes_gcm_init_var_iv_256_avx_gen4
;       aes_gcm_init_var_iv_128_avx512 / aes_gcm_init_var_iv_192_avx512 /
;       aes_gcm_init_var_iv_256_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8        *iv,
;        const u64 iv_len,
;        const u8  *aad,
;        const u64 aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(init_var_iv,_),function,)
MKGLOBAL(FN_NAME_AVX512(init_var_iv,_),function,)
FN_NAME(init_var_iv,_):
FN_NAME_AVX512(init_var_iv,_):
        endbranch64
        jmp aes_gcm_init_var_iv_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_update_avx_gen4 / aes_gcm_enc_192_update_avx_gen4 /
;       aes_gcm_enc_128_update_avx_gen4 /
;       aes_gcm_enc_128_update_avx512 / aes_gcm_enc_192_update_avx512 /
;       aes_gcm_enc_256_update_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_update_),function,)
MKGLOBAL(FN_NAME_AVX512(enc,_update_),function,)
FN_NAME(enc,_update_):
FN_NAME_AVX512(enc,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_update_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_update_avx_gen4 / aes_gcm_dec_192_update_avx_gen4 /
;       aes_gcm_dec_256_update_avx_gen4 /
;       aes_gcm_dec_128_update_avx512 / aes_gcm_dec_192_update_avx512 /
;       aes_gcm_dec_256_update_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_update_),function,)
MKGLOBAL(FN_NAME_AVX512(dec,_update_),function,)
FN_NAME(dec,_update_):
FN_NAME_AVX512(dec,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_update_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_finalize_avx_gen4 / aes_gcm_enc_192_finalize_avx_gen4 /
;       aes_gcm_enc_256_finalize_avx_gen4 /
;       aes_gcm_enc_128_finalize_avx512 / aes_gcm_enc_192_finalize_avx512 /
;       aes_gcm_enc_256_finalize_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_finalize_),function,)
MKGLOBAL(FN_NAME_AVX512(enc,_finalize_),function,)
FN_NAME(enc,_finalize_):
FN_NAME_AVX512(enc,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_finalize_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_finalize_avx_gen4 / aes_gcm_dec_192_finalize_avx_gen4
;       aes_gcm_dec_256_finalize_avx_gen4 /
;       aes_gcm_dec_128_finalize_avx512 / aes_gcm_dec_192_finalize_avx512
;       aes_gcm_dec_256_finalize_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_finalize_),function,)
MKGLOBAL(FN_NAME_AVX512(dec,_finalize_),function,)
FN_NAME(dec,_finalize_):
FN_NAME_AVX512(dec,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_finalize_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_avx_gen4 / aes_gcm_enc_192_avx_gen4 / aes_gcm_enc_256_avx_gen4 /
;       aes_gcm_enc_128_avx512 / aes_gcm_enc_192_avx512 / aes_gcm_enc_256_avx512
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
MKGLOBAL(FN_NAME_AVX512(enc,_),function,)
FN_NAME(enc,_):
FN_NAME_AVX512(enc,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_avx_gen4 / aes_gcm_dec_192_avx_gen4 / aes_gcm_dec_256_avx_gen4 /
;       aes_gcm_dec_128_avx512 / aes_gcm_dec_192_avx512 / aes_gcm_dec_256_avx512
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
MKGLOBAL(FN_NAME_AVX512(dec,_),function,)
FN_NAME(dec,_):
FN_NAME_AVX512(dec,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB * aes_gcm_enc_var_iv_128_avx_gen4 / aes_gcm_enc_var_iv_192_avx_gen4 /
;       aes_gcm_enc_var_iv_256_avx_gen4 /
;       aes_gcm_enc_var_iv_128_avx512 / aes_gcm_enc_var_iv_192_avx512 /
;       aes_gcm_enc_var_iv_256_avx512
;       (IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc_var_iv,_),function,internal)
MKGLOBAL(FN_NAME_AVX512(enc_var_iv,_),function,internal)
FN_NAME(enc_var_iv,_):
FN_NAME_AVX512(enc_var_iv,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_var_iv_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB *aes_gcm_dec_var_iv_128_avx_gen4 / aes_gcm_dec_var_iv_192_avx_gen4 /
;       aes_gcm_dec_var_iv_256_avx_gen4 /
;       aes_gcm_dec_var_iv_128_avx512 / aes_gcm_dec_var_iv_192_avx512 /
;       aes_gcm_dec_var_iv_256_avx512
;       (IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec_var_iv,_),function,internal)
MKGLOBAL(FN_NAME_AVX512(dec_var_iv,_),function,internal)
FN_NAME(dec_var_iv,_):
FN_NAME_AVX512(dec_var_iv,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_var_iv_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   imb_aes_gmac_update_128_avx_gen4 / imb_aes_gmac_update_192_avx_gen4 /
;       imb_aes_gmac_update_256_avx_gen4
;       imb_aes_gmac_update_128_avx512 / imb_aes_gmac_update_192_avx512 /
;       imb_aes_gmac_update_256_avx512 (
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        const   u8 *in,
;        const   u64 msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(GMAC_FN_NAME(update),function,)
MKGLOBAL(GMAC_FN_NAME_AVX512(update),function,)
GMAC_FN_NAME(update):
GMAC_FN_NAME_AVX512(update):
        endbranch64
        jmp imb_aes_gmac_update_avx2

mksection stack-noexec
