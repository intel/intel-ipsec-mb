/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>
#include <openssl/modes.h>
#include <openssl/sha.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>

#include "e_prov.h"
#include "prov_sw_freelist.h"
#include <intel-ipsec-mb.h>

#define PROV_DIGEST_FLAG_XOF          0x0001
#define PROV_DIGEST_FLAG_ALGID_ABSENT 0x0002
#define SHA_FLAGS                     PROV_DIGEST_FLAG_ALGID_ABSENT

int
sha_async_init(ALG_CTX *ctx);
int
sha_async_update(ALG_CTX *ctx, const unsigned char *actual_data, size_t len);
int
sha_async_final(ALG_CTX *ctx, unsigned char *md);
int
sha_async_cleanup(ALG_CTX *ctx);
