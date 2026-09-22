/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_CHACHA20_POLY1305_H
#define PROV_CHACHA20_POLY1305_H

#include "prov_sw_chacha20_poly1305.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "prov_provider.h"
#include "prov_ciphers.h"

void *
chacha20_poly1305_newctx(void *provctx);
void
chacha20_poly1305_freectx(void *ctx);
int
chacha20_poly1305_einit(void *ctx, const unsigned char *key, const int keylen,
                        const unsigned char *iv, const int ivlen);
int
chacha20_poly1305_dinit(void *ctx, const unsigned char *key, const int keylen,
                        const unsigned char *iv, const int ivlen);
int
chacha20_poly1305_stream_update(void *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                                const unsigned char *in, const size_t inl);
int
chacha20_poly1305_stream_final(void *ctx, unsigned char *out, size_t *outl, const size_t outsize);
int
chacha20_poly1305_cipher(void *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                         const unsigned char *in, const size_t inl);

/* Parameter handling functions */
int
chacha20_poly1305_get_params(OSSL_PARAM params[]);
const OSSL_PARAM *
chacha20_poly1305_gettable_params(void *provctx);
int
chacha20_poly1305_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
int
chacha20_poly1305_get_ctx_params(void *ctx, OSSL_PARAM params[]);
const OSSL_PARAM *
chacha20_poly1305_settable_ctx_params(void *ctx, void *provctx);
const OSSL_PARAM *
chacha20_poly1305_gettable_ctx_params(void *ctx, void *provctx);

#endif /* PROV_CHACHA20_POLY1305_H */
