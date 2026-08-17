/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_PROV_AES_CCM_H
#define PROV_PROV_AES_CCM_H

#include <string.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/modes.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>

#include "e_prov.h"
#include "prov_sw_ccm.h"
#define IV_STATE_UNINITIALISED 0

#define PROV_CIPHER_FLAG_AEAD            0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV       0x0002
#define PROV_CIPHER_FLAG_CTS             0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK 0x0008
#define PROV_CIPHER_FLAG_RAND_KEY        0x0010

size_t
prov_aes_ccm_get_ivlen(ALG_CTX *ctx);
void
prov_aes_ccm_init_ctx(void *provctx, ALG_CTX *ctx, const size_t keybits);
int
prov_aes_ccm_get_ctx_params(ALG_CTX *ctx, OSSL_PARAM params[]);
int
prov_aes_ccm_set_ctx_params(ALG_CTX *ctx, const OSSL_PARAM params[]);
int
prov_aes_ccm_einit(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
                   const unsigned char *iv, const size_t ivlen);
int
prov_aes_ccm_dinit(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
                   const unsigned char *iv, const size_t ivlen);
int
prov_aes_ccm_stream_update(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                           const unsigned char *in, const size_t inl);
int
prov_aes_ccm_stream_final(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize);
int
prov_aes_ccm_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                       const unsigned char *in, const size_t inl);

#define PROV_aes_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits, nid)                       \
        static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;                   \
        static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])                          \
        {                                                                                          \
                return prov_aes_ccm_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,    \
                                                       kbits, blkbits, ivbits);                    \
        }                                                                                          \
        static OSSL_FUNC_cipher_newctx_fn alg##_##kbits##_##lc##_newctx;                           \
        static void *alg##_##kbits##_##lc##_newctx(void *provctx)                                  \
        {                                                                                          \
                return alg##_##lc##_newctx(provctx, kbits, nid);                                   \
        }                                                                                          \
        const OSSL_DISPATCH alg##kbits##lc##_functions[] = {                                       \
                { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##_##kbits##_##lc##_newctx },       \
                { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_##lc##_freectx },               \
                { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) alg##_##lc##_einit },            \
                { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) alg##_##lc##_dinit },            \
                { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) alg##_##lc##_stream_update },          \
                { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) alg##_##lc##_stream_final },            \
                { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) alg##_##lc##_do_cipher },              \
                { OSSL_FUNC_CIPHER_GET_PARAMS,                                                     \
                  (void (*)(void)) alg##_##kbits##_##lc##_get_params },                            \
                { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) alg##_##lc##_get_ctx_params }, \
                { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) alg##_##lc##_set_ctx_params }, \
                { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) alg##_##lc##_generic_gettable_params },                         \
                { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) alg##_##lc##_aead_gettable_ctx_params },                        \
                { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) alg##_##lc##_aead_settable_ctx_params },                        \
                { 0, NULL }                                                                        \
        }
#endif /* PROV_PROV_AES_CCM_H */