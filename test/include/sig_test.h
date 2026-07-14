/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
      * Neither the name of Intel Corporation nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
