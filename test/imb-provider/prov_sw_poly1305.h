/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_SW_POLY1305_H
#define PROV_SW_POLY1305_H

#include <openssl/evp.h>
#include <intel-ipsec-mb.h>
#include "prov_sw_freelist.h"
#include "prov_sw_request.h"
#include "prov_poly1305.h"

#define POLY1305_STATE_SIZE 32
#define MAX_POLY1305_JOBS   32

const char *
prov_poly1305_name(void);

/* Async operations */
int
poly1305_async_init(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen);
int
poly1305_async_do_mac(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                      const unsigned char *in, const size_t len);
void
poly1305_async_cleanup(ALG_CTX *ctx);

#endif /* PROV_SW_POLY1305_H */
