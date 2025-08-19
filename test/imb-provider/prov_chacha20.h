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
