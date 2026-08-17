/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_POLY1305_H
#define PROV_POLY1305_H

#include <string.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>

#include "e_prov.h"

#define POLY1305_BLOCK_SIZE 16
#define POLY1305_KEY_SIZE   32
#define POLY1305_TAG_SIZE   16

/* Provider interface functions */
void *
prov_poly1305_newctx(void *provctx);
void
prov_poly1305_freectx(void *vctx);
int
prov_poly1305_init(void *vctx, const unsigned char *key, const int keylen, const unsigned char *iv,
                   const int ivlen, const int enc);
int
prov_poly1305_update(void *vctx, unsigned char *out, size_t *outl, const size_t outsize,
                     const unsigned char *in, const size_t inl);
int
prov_poly1305_final(void *vctx, unsigned char *out, size_t *outl, const size_t outsize);
int
prov_poly1305_cipher(void *vctx, unsigned char *out, size_t *outl, const size_t outsize,
                     const unsigned char *in, const size_t inl);

/* Getter/setter functions */
int
prov_poly1305_get_params(OSSL_PARAM params[]);
int
prov_poly1305_get_ctx_params(void *vctx, OSSL_PARAM params[]);
int
prov_poly1305_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
const OSSL_PARAM *
prov_poly1305_gettable_params(void *provctx);
const OSSL_PARAM *
prov_poly1305_gettable_ctx_params(void *cctx, void *provctx);
const OSSL_PARAM *
prov_poly1305_settable_ctx_params(void *cctx, void *provctx);

/* Initialize context helper */
void
prov_poly1305_init_ctx(void *provctx, ALG_CTX *ctx);

#endif /* PROV_POLY1305_H */
