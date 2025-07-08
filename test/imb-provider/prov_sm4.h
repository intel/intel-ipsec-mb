/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#ifndef PROV_SM4_H
#define PROV_SM4_H

#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/modes.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <intel-ipsec-mb.h>
#include "prov_sw_request.h"
#include "prov_sw_submit.h"
#include "prov_cipher_generic.h"

/* Define missing NID if not available in OpenSSL */
#ifndef NID_sm4_gcm
#define NID_sm4_gcm 1248
#endif

#ifndef NID_sm4_ctr
#define NID_sm4_ctr 1139
#endif

#define SM4_BLOCK_SIZE        16
#define SM4_KEY_SIZE          16
#define SM4_IV_SIZE           16
#define SM4_GCM_IV_SIZE       12
#define SM4_GCM_IV_MAX_SIZE   16
#define PROV_ENC_DEC_KEY_SIZE (4 * 15)

#define PROV_SM4_BASE_FLAGS                                                                        \
        (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_PIPELINE | EVP_CIPH_CUSTOM_COPY)

#define PROV_SM4_ECB_FLAGS (PROV_SM4_BASE_FLAGS | EVP_CIPH_ECB_MODE)
#define PROV_SM4_CBC_FLAGS (PROV_SM4_BASE_FLAGS | EVP_CIPH_CBC_MODE)
#define PROV_SM4_CTR_FLAGS (PROV_SM4_BASE_FLAGS | EVP_CIPH_CTR_MODE)
#define PROV_SM4_GCM_FLAGS (PROV_SM4_BASE_FLAGS | EVP_CIPH_GCM_MODE | EVP_CIPH_FLAG_AEAD_CIPHER)

/* Function declarations for SM4 */
int
sm4_async_init(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
               const unsigned char *iv, const size_t ivlen, const int enc);
int
sm4_async_cleanup(ALG_CTX *ctx);

/* Provider interface functions */
void *
prov_sm4_ecb_newctx(void *provctx);
void *
prov_sm4_cbc_newctx(void *provctx);
void *
prov_sm4_gcm_newctx(void *provctx);
void *
prov_sm4_ctr_newctx(void *provctx);
void
prov_sm4_freectx(void *vctx);
int
prov_sm4_encrypt_init(void *vctx, const unsigned char *key, const int keylen,
                      const unsigned char *iv, const int ivlen, const int enc);
int
prov_sm4_decrypt_init(void *vctx, const unsigned char *key, const int keylen,
                      const unsigned char *iv, const int ivlen, const int enc);
int
prov_sm4_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, const size_t inl);
int
prov_sm4_final(void *vctx, unsigned char *out, size_t *outl, const size_t outsize);
int
prov_sm4_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, size_t inl);
int
prov_sm4_get_params(OSSL_PARAM params[], const int nid, const int mode);
int
prov_sm4_get_ctx_params(void *vctx, OSSL_PARAM params[]);
int
prov_sm4_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/* Macros for cipher definition */
#define PROV_sm4_cipher(alg, lc, UCMODE, flags, blkbits, ivbits, nid)                              \
        static OSSL_FUNC_cipher_get_params_fn alg##lc##_get_params;                                \
        static int alg##lc##_get_params(OSSL_PARAM params[])                                       \
        {                                                                                          \
                return prov_sm4_get_params(params, nid, EVP_CIPH_##UCMODE##_MODE);                 \
        }                                                                                          \
        static OSSL_FUNC_cipher_newctx_fn alg##lc##_newctx;                                        \
        static void *alg##lc##_newctx(void *provctx) { return prov_sm4_##lc##_newctx(provctx); }   \
        const OSSL_DISPATCH alg##lc##_functions[] = {                                              \
                { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##lc##_newctx },                    \
                { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) prov_sm4_freectx },                   \
                { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) prov_sm4_encrypt_init },         \
                { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) prov_sm4_decrypt_init },         \
                { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) prov_sm4_update },                     \
                { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) prov_sm4_final },                       \
                { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) prov_sm4_cipher },                     \
                { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) alg##lc##_get_params },            \
                { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) prov_sm4_get_ctx_params },     \
                { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) prov_sm4_set_ctx_params },     \
                { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) prov_cipher_generic_gettable_params },                          \
                { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) prov_cipher_generic_gettable_ctx_params },                      \
                { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) prov_cipher_generic_settable_ctx_params },                      \
                { 0, NULL }                                                                        \
        }

#endif /* PROV_SM4_H */
