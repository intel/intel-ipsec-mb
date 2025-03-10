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

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_gcm.h"
#include "prov_ciphers.h"

#include "prov_sw_sha2.h"

int
prov_imb_sha2(int nid, unsigned char hash_type, const void *data, size_t len, unsigned char *out);

int
prov_sha2_ctx_get_nid(PROV_SHA2_CTX *ctx)
{
        return ctx->md_type;
}

int
mb_prov_SHA2_init(PROV_SHA2_CTX *ctx)
{
        if (NULL == ctx) {
                fprintf(stderr, "ctx is NULL\n");
                return 0;
        }
        if (ctx->md_type == NID_sha224) {
                ctx->md_len = SHA224_DIGEST_LENGTH;
                return 1;
        }

        if (ctx->md_type == NID_sha256) {
                ctx->md_len = SHA256_DIGEST_LENGTH;
                return 1;
        }

        if (ctx->md_type == NID_sha384) {
                ctx->md_len = SHA384_DIGEST_LENGTH;
                return 1;
        }

        if (ctx->md_type == NID_sha512) {
                ctx->md_len = SHA512_DIGEST_LENGTH;
                return 1;
        }
        return 0;
}

int
mb_prov_SHA2_update(PROV_SHA2_CTX *ctx, const void *actual_data, size_t len)
{
        unsigned char *data = (unsigned char *) actual_data;
        unsigned char *p = NULL;
        size_t n;
        int nid = 0;
        unsigned long long data_size = 0;
        if (ctx->md_type == NID_sha256 || ctx->md_type == NID_sha224) {
                p = ctx->u.small_data;
        }

        if (ctx->md_type == NID_sha384 || ctx->md_type == NID_sha512) {
                p = ctx->u.large_data;
        }
        data_size = PROV_SHA_MAX_SIZE;
        nid = prov_sha2_ctx_get_nid(ctx);
        n = ctx->num;

        if (n != 0) {
                /* Offload threshold met */
                if (len >= data_size || len + n >= data_size) {
                        /* Use part of new packet filling the packet buffer */
                        data_size += data_size;
                        memcpy(p + n, data, len);
                        ctx->num += (unsigned int) len;

                        return 1;
                } else {
                        /* Append the new packets to buffer */
                        memcpy(p + n, data, len);
                        ctx->num += (unsigned int) len;

                        return 1;
                }
        }
        n = len / data_size;
        if (n > 0) {
                n *= data_size;

                prov_imb_sha2(nid, ctx->md_type, data, n, ctx->digest_data1);
                data += n;
                len -= n;
        }

        /* Save the bytes into buffer if there're some bytes left
         * after the previous update. */
        if (len != 0) {
                if (ctx->md_type == NID_sha256 || ctx->md_type == NID_sha224) {
                        p = ctx->u.small_data;
                }

                if (ctx->md_type == NID_sha384 || ctx->md_type == NID_sha512) {
                        p = ctx->u.large_data;
                }
                ctx->num = (unsigned int) len;
                memcpy(p, data, len);
        }

        return 1;
}

int
mb_prov_SHA2_final(PROV_SHA2_CTX *ctx, unsigned char *md)
{
        int nid = 0;
        unsigned char *p = NULL;
        nid = prov_sha2_ctx_get_nid(ctx);
        if (ctx->md_type == NID_sha256 || ctx->md_type == NID_sha224) {
                p = ctx->u.small_data;
        }

        if (ctx->md_type == NID_sha384 || ctx->md_type == NID_sha512) {
                p = ctx->u.large_data;
        }

        prov_imb_sha2(nid, ctx->md_type, p, ctx->num, ctx->digest_data1);
        memcpy(md, ctx->digest_data1, ctx->md_size);

        return 1;
}

int
mb_prov_sha2_cleanup(PROV_SHA2_CTX *ctx)
{
        PROV_SHA2_CTX *sha_ctx = (PROV_SHA2_CTX *) ctx;
        memset(sha_ctx, 0, sizeof(PROV_SHA2_CTX));
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return 1;
}