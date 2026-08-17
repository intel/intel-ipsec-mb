/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_SW_CHACHA20_POLY1305_H
#define PROV_SW_CHACHA20_POLY1305_H

#include <openssl/core.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <intel-ipsec-mb.h>

#include "e_prov.h"
#include "prov_provider.h"
#include "prov_sw_request.h"

#define CHACHA20_POLY1305_KEY_SIZE 32
#define CHACHA20_POLY1305_IV_SIZE  12
#define CHACHA20_POLY1305_TAG_SIZE 16

int
chacha20_poly1305_async_init(ALG_CTX *ctx, const unsigned char *key, const size_t keylen,
                             const unsigned char *iv, const size_t ivlen, const int enc);
int
chacha20_poly1305_async_update(ALG_CTX *ctx, const unsigned char *in, const size_t len);
int
chacha20_poly1305_async_final(ALG_CTX *ctx, unsigned char *out);
void
chacha20_poly1305_async_cleanup(ALG_CTX *ctx);

void *
prov_chacha20_poly1305_newctx(void *provctx);
void
prov_chacha20_poly1305_freectx(void *ctx);
int
prov_chacha20_poly1305_einit(void *ctx, const unsigned char *key, const int keylen,
                             const unsigned char *iv, const int ivlen, const int enc);
int
prov_chacha20_poly1305_dinit(void *ctx, const unsigned char *key, const int keylen,
                             const unsigned char *iv, const int ivlen, const int enc);
int
prov_chacha20_poly1305_stream_update(void *ctx, unsigned char *out, size_t *outl,
                                     const size_t outsize, const unsigned char *in,
                                     const size_t inl);
int
prov_chacha20_poly1305_stream_final(void *ctx, unsigned char *out, size_t *outl,
                                    const size_t outsize);
int
prov_chacha20_poly1305_cipher(void *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                              const unsigned char *in, const size_t inl);

int
prov_chacha20_poly1305_get_params(OSSL_PARAM params[]);
const OSSL_PARAM *
prov_chacha20_poly1305_gettable_params(void *provctx);
int
prov_chacha20_poly1305_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
int
prov_chacha20_poly1305_get_ctx_params(void *ctx, OSSL_PARAM params[]);
const OSSL_PARAM *
prov_chacha20_poly1305_settable_ctx_params(void *ctx, void *provctx);
const OSSL_PARAM *
prov_chacha20_poly1305_gettable_ctx_params(void *ctx, void *provctx);

#endif /* PROV_SW_CHACHA20_POLY1305_H */
