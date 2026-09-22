/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_CHACHA20_H
#define PROV_CHACHA20_H

/* Standard Includes */
#include <string.h>

/* OpenSSL Includes */
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/modes.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

#include "prov_ciphers.h"

int
chacha20_get_ctx_params(ALG_CTX *ctx, OSSL_PARAM params[]);
int
chacha20_set_ctx_params(ALG_CTX *ctx, const OSSL_PARAM params[]);
int
chacha20_initiv(ALG_CTX *ctx, const unsigned char *iv, const size_t ivlen);
void
chacha20_freectx(ALG_CTX *ctx);

int
chacha20_stream_update_cha(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                           const unsigned char *in, size_t inl);
int
chacha20_stream_final(void *vctx, unsigned char *out, size_t *outl, const size_t outsize);
int
chacha20_cipher_cha(void *vctx, unsigned char *out, size_t *outl, const size_t outsize,
                    const unsigned char *in, const size_t inl);

#endif /* PROV_CHACHA20_H */
