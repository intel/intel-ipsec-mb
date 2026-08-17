/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef SIG_TEST_H
#define SIG_TEST_H

#include <stddef.h>

/*
 * Generic signature-scheme test vectors (Wycheproof-style sign/verify
 * schemas). Fields cover any FIPS-style signature API taking an optional
 * context string and either a raw private key or a seed to derive one
 * (e.g. ML-DSA/FIPS 204, and future signature algorithms such as
 * SLH-DSA/FIPS 205), so this struct is not ML-DSA-specific and may be
 * reused by other signature test modules.
 */
struct sig_sign_test {
        size_t tcId;
        const char *comment;
        const char *msg;
        size_t msgLen;
        const char *ctx;
        size_t ctxLen;
        int hasCtx;
        const char *rnd;
        size_t rndLen;
        int hasRnd;
        const char *mu;
        size_t muLen;
        int hasMu;
        const char *sig;
        size_t sigLen;
        int resultValid;
        const char *privateSeed;
        size_t privateSeedLen;
        const char *privateKey;
        size_t privateKeyLen;
        const char *publicKey;
        size_t publicKeyLen;
};

struct sig_verify_test {
        size_t tcId;
        const char *comment;
        const char *msg;
        size_t msgLen;
        const char *ctx;
        size_t ctxLen;
        int hasCtx;
        const char *sig;
        size_t sigLen;
        int resultValid;
        const char *publicKey;
        size_t publicKeyLen;
};

#endif /* SIG_TEST_H */
