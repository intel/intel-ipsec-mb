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
