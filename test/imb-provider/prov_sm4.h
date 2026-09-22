/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
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

#define SM4_BLOCK_SIZE      16
#define SM4_KEY_SIZE        16
#define SM4_IV_SIZE         16
#define SM4_GCM_IV_SIZE     12
#define SM4_GCM_IV_MAX_SIZE 16
#define SM4_GCM_TAG_SIZE    16

/* Starting size of the SM4-GCM message buffers, doubled as needed. */
#define SM4_GCM_MSG_ALLOC_MIN 64

/*
 * ipsec-mb ciphers SM4 from an expanded key schedule, never from the raw key:
 * 32 rounds of 4 bytes for ECB/CBC/CTR. SM4-GCM instead wants a whole
 * struct gcm_key_data.
 */
#define SM4_KEY_SCHED_SIZE (IMB_SM4_KEY_SCHEDULE_ROUNDS * sizeof(uint32_t))

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
void *
prov_sm4_dupctx(void *vctx);
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
        /* Only the AEAD table carries the tag parameters, so a mode that does                     \
         * not advertise it can never be handed a tag. */                                          \
        static OSSL_FUNC_cipher_gettable_ctx_params_fn alg##lc##_gettable_ctx_params;              \
        static const OSSL_PARAM *alg##lc##_gettable_ctx_params(void *cctx, void *provctx)          \
        {                                                                                          \
                return (nid) == NID_sm4_gcm                                                        \
                               ? prov_cipher_aead_gettable_ctx_params(cctx, provctx)               \
                               : prov_cipher_generic_gettable_ctx_params(cctx, provctx);           \
        }                                                                                          \
        static OSSL_FUNC_cipher_settable_ctx_params_fn alg##lc##_settable_ctx_params;              \
        static const OSSL_PARAM *alg##lc##_settable_ctx_params(void *cctx, void *provctx)          \
        {                                                                                          \
                return (nid) == NID_sm4_gcm                                                        \
                               ? prov_cipher_aead_settable_ctx_params(cctx, provctx)               \
                               : prov_cipher_generic_settable_ctx_params(cctx, provctx);           \
        }                                                                                          \
        const OSSL_DISPATCH alg##lc##_functions[] = {                                              \
                { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##lc##_newctx },                    \
                { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) prov_sm4_freectx },                   \
                { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) prov_sm4_dupctx },                     \
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
                  (void (*)(void)) alg##lc##_gettable_ctx_params },                                \
                { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) alg##lc##_settable_ctx_params },                                \
                { 0, NULL }                                                                        \
        }

#endif /* PROV_SM4_H */
