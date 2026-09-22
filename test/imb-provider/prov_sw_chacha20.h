/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_SW_CHACHA20_H
#define PROV_SW_CHACHA20_H

#include <openssl/evp.h>
#include "prov_ciphers.h"

void
chacha20_async_cleanup(ALG_CTX *ctx);
int
chacha20_async_init(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
                    const unsigned char *iv, const size_t ivlen, const int enc);
int
chacha20_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                         const unsigned char *in, const size_t len);

#endif /* PROV_SW_CHACHA20_H */
