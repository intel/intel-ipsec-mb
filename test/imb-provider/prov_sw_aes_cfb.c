/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/
/* Standard Includes */
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_aes_cfb.h"

#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_submit.h"

const char *
prov_aes_cfb_cipher_name(int nid)
{
        switch (nid) {
        case NID_aes_128_cfb128:
                return LN_aes_128_cfb128;
        case NID_aes_192_cfb128:
                return LN_aes_192_cfb128;
        case NID_aes_256_cfb128:
                return LN_aes_256_cfb128;
        default:
                return NULL;
        }
}

void
aes_cfb_async_cleanup(ALG_CTX *ctx)
{
        if (ctx) {
                if (ctx->enc_keys)
                        OPENSSL_free(ctx->enc_keys);
                if (ctx->dec_keys)
                        OPENSSL_free(ctx->dec_keys);
                ctx->enc_keys = NULL;
                ctx->dec_keys = NULL;
        }
}

int
aes_cfb_async_init(ALG_CTX *ctx, const unsigned char *inkey, size_t keylen, const unsigned char *iv,
                   size_t ivlen, int enc)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        ctx->ivlen = 16;

        if (!ctx->enc_keys)
                ctx->enc_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE * 16);
        if (!ctx->dec_keys)
                ctx->dec_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE * 16);

        switch (keylen) {
        case 16:
                IMB_AES_KEYEXP_128(tlv->imb_mgr, (const char *) inkey, ctx->enc_keys,
                                   ctx->dec_keys);
                break;
        case 24:
                IMB_AES_KEYEXP_192(tlv->imb_mgr, (const char *) inkey, ctx->enc_keys,
                                   ctx->dec_keys);
                break;
        case 32:
                IMB_AES_KEYEXP_256(tlv->imb_mgr, (const char *) inkey, ctx->enc_keys,
                                   ctx->dec_keys);
                break;
        default:
                return 0;
        }

        return 1;
}

/*
 * cfb_submit - run one whole-block AES-CFB job through ipsec-mb.
 */
static int
cfb_submit(ALG_CTX *ctx, mb_thread_data *tlv, ASYNC_JOB *async_job, unsigned char *out,
           const unsigned char *in, size_t len, const unsigned char *iv, int dir)
{
        struct IMB_JOB *imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);

        /* Job slots are recycled, so stale fields have to be cleared. */
        memset(imb_job, 0, sizeof(*imb_job));

        imb_job->dst = out;
        imb_job->src = in;
        imb_job->cipher_direction = dir;
        imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
        imb_job->cipher_mode = IMB_CIPHER_CFB;
        imb_job->hash_alg = IMB_AUTH_NULL;
        imb_job->enc_keys = ctx->enc_keys;
        /* AES-CFB mode uses the AES *encrypt* key schedule for both encrypt
         * and decrypt directions. */
        imb_job->dec_keys = ctx->enc_keys;
        imb_job->key_len_in_bytes = ctx->keylen;
        imb_job->iv = iv;
        imb_job->iv_len_in_bytes = ctx->ivlen;
        imb_job->cipher_start_src_offset_in_bytes = 0;
        imb_job->msg_len_to_cipher_in_bytes = len;
        imb_job->user_data2 = async_job;

        if (async_update(tlv, ctx, async_job, imb_job) == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        return 1;
}

/*
 * aes_cfb_async_do_cipher - CFB128 over an arbitrary number of bytes.
 *
 * The mismatch this function exists to hide:
 *   - CFB128 is a stream mode, so EVP_CipherUpdate() may be called with any
 *     length, at any offset, and the result must match a single call over the
 *     whole message. libcrypto does no buffering on the provider's behalf.
 *   - ipsec-mb's CFB job API only ciphers whole blocks: a job length that is
 *     zero or not a multiple of 16 is rejected with IMB_ERR_JOB_CIPH_LEN.
 */
int
aes_cfb_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t len)
{
        static const unsigned char zeroes[GENERIC_BLOCK_SIZE] = { 0 };
        mb_thread_data *tlv = mb_check_thread_local();
        unsigned int n;
        size_t l = 0;

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL) {
                fprintf(stderr, "AES-CFB ctx is NULL.\n");
                return 0;
        }

        if (out == NULL || in == NULL)
                return 0;

        if (outsize < len) {
                fprintf(stderr, "Output buffer too small: %zu < %zu\n", outsize, len);
                return 0;
        }

        if (ctx->nid != NID_aes_128_cfb128 && ctx->nid != NID_aes_192_cfb128 &&
            ctx->nid != NID_aes_256_cfb128)
                return 0;

        ASYNC_JOB *async_job = ASYNC_get_current_job();
        if (async_job == NULL) {
                fprintf(stderr, "Not running asynchronously, exit\n");
                return 0;
        }

        n = ctx->num;

        if (len == 0) {
                *outl = 0;
                return 1;
        }

        /* Fast path for the common aligned full-block case. */
        if (n == 0 && (len % GENERIC_BLOCK_SIZE) == 0) {
                unsigned char last[GENERIC_BLOCK_SIZE];

                if (!ctx->enc)
                        memcpy(last, in + len - GENERIC_BLOCK_SIZE, GENERIC_BLOCK_SIZE);

                if (!cfb_submit(ctx, tlv, async_job, out, in, len, ctx->next_iv,
                                ctx->enc ? IMB_DIR_ENCRYPT : IMB_DIR_DECRYPT))
                        return 0;

                if (ctx->enc)
                        memcpy(ctx->next_iv, out + len - GENERIC_BLOCK_SIZE, GENERIC_BLOCK_SIZE);
                else
                        memcpy(ctx->next_iv, last, GENERIC_BLOCK_SIZE);

                ctx->num = 0;
                memcpy(ctx->iv, ctx->next_iv, ctx->ivlen);
                *outl = len;
                return 1;
        }

        while (l < len) {
                if (n == 0) {
                        const size_t nblocks = (len - l) / GENERIC_BLOCK_SIZE;

                        if (nblocks > 0) {
                                const size_t bulk = nblocks * GENERIC_BLOCK_SIZE;
                                unsigned char last[GENERIC_BLOCK_SIZE];

                                /* The chaining value is the last ciphertext
                                 * block; when decrypting in place the job is
                                 * about to overwrite it, so keep a copy. */
                                if (!ctx->enc)
                                        memcpy(last, in + l + bulk - GENERIC_BLOCK_SIZE,
                                               GENERIC_BLOCK_SIZE);

                                if (!cfb_submit(ctx, tlv, async_job, out + l, in + l, bulk,
                                                ctx->next_iv,
                                                ctx->enc ? IMB_DIR_ENCRYPT : IMB_DIR_DECRYPT))
                                        return 0;

                                if (ctx->enc)
                                        memcpy(ctx->next_iv, out + l + bulk - GENERIC_BLOCK_SIZE,
                                               GENERIC_BLOCK_SIZE);
                                else
                                        memcpy(ctx->next_iv, last, GENERIC_BLOCK_SIZE);

                                l += bulk;
                                continue;
                        }

                        /* Less than a block left: fetch its keystream. */
                        if (!cfb_submit(ctx, tlv, async_job, ctx->buf, zeroes, GENERIC_BLOCK_SIZE,
                                        ctx->next_iv, IMB_DIR_ENCRYPT))
                                return 0;
                }

                {
                        /* Read the input before writing the output: the two may
                         * be the same buffer. */
                        const unsigned char c = in[l];

                        out[l] = c ^ ctx->buf[n];
                        /* Build the next chaining value out of the ciphertext. */
                        ctx->next_iv[n] = ctx->enc ? out[l] : c;
                }

                l++;
                n = (n + 1) & (GENERIC_BLOCK_SIZE - 1);
        }

        ctx->num = n;
        memcpy(ctx->iv, ctx->next_iv, ctx->ivlen);
        *outl = len;

        return 1;
}
