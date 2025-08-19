/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

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
