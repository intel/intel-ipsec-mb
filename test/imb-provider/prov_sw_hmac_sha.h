/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_SW_HMAC_SHA_H
#define PROV_SW_HMAC_SHA_H

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>
#include <openssl/modes.h>
#include <openssl/sha.h>
#include <openssl/ossl_typ.h>

#include "prov_sw_freelist.h"
#include <intel-ipsec-mb.h>

#define PROV_PROV_DIGEST_FLAG_XOF          0x0001
#define PROV_PROV_DIGEST_FLAG_ALGID_ABSENT 0x0002

#define HMAC_SHA_FLAGS  PROV_PROV_DIGEST_FLAG_ALGID_ABSENT
#define EVP_MAX_MD_SIZE 64

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef __int64 i64;
typedef unsigned __int64 u64;
#define U64(C) C##UI64
#elif defined(__arch64__)
typedef long i64;
typedef unsigned long u64;
#define U64(C) C##UL
#else
typedef long long i64;
typedef unsigned long long u64;
#define U64(C) C##ULL
#endif

int
hmac_sha_async_init(ALG_CTX *ctx);
int
hmac_sha_async_update(ALG_CTX *ctx, const unsigned char *actual_data, const size_t len);
int
hmac_sha_async_final(ALG_CTX *ctx, unsigned char *md);
int
hmac_sha_async_cleanup(ALG_CTX *ctx);

#endif /* PROV_SW_HMAC_SHA_H */