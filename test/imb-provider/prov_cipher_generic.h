/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_CIPHER_GENERIC_H
#define PROV_CIPHER_GENERIC_H

#include <openssl/params.h>

extern const OSSL_PARAM *
prov_cipher_generic_gettable_params(void *provctx);

extern const OSSL_PARAM *
prov_cipher_generic_gettable_ctx_params(void *ctx, void *provctx);

extern const OSSL_PARAM *
prov_cipher_generic_settable_ctx_params(void *ctx, void *provctx);

/* As above, but for AEAD modes: adds the tag, tag length and TLS parameters. */
extern const OSSL_PARAM *
prov_cipher_aead_gettable_ctx_params(void *ctx, void *provctx);

extern const OSSL_PARAM *
prov_cipher_aead_settable_ctx_params(void *ctx, void *provctx);

extern int
prov_cipher_generic_get_params(OSSL_PARAM params[], unsigned int mode, size_t flags, size_t kbits,
                               size_t blkbits, size_t ivbits);

#endif /* PROV_CIPHER_GENERIC_H */
