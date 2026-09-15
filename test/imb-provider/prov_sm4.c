/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* Standard Includes */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_ciphers.h"
#include "prov_sm4.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_submit.h"

/* Forward declaration */
static int
prov_sm4_init(void *vctx, const unsigned char *key, int keylen, const unsigned char *iv,
              const int ivlen, const int enc);

int
sm4_async_cleanup(ALG_CTX *ctx)
{
        if (ctx) {
                if (ctx->enc_keys)
                        OPENSSL_free(ctx->enc_keys);
                if (ctx->dec_keys)
                        OPENSSL_free(ctx->dec_keys);
                if (ctx->aad)
                        OPENSSL_free(ctx->aad);
                if (ctx->tag)
                        OPENSSL_clear_free(ctx->tag, sizeof(ctx->auths));
                if (ctx->gcm_msg)
                        OPENSSL_clear_free(ctx->gcm_msg, ctx->gcm_alloc);
                if (ctx->gcm_buf)
                        OPENSSL_clear_free(ctx->gcm_buf, ctx->gcm_alloc);
                ctx->enc_keys = NULL;
                ctx->dec_keys = NULL;
                ctx->aad = NULL;
                ctx->aad_len = 0;
                ctx->tag = NULL;
                ctx->tag_set = 0;
                ctx->gcm_msg = NULL;
                ctx->gcm_buf = NULL;
                ctx->gcm_len = 0;
                ctx->gcm_alloc = 0;
        }
        return 1;
}

/*
 * Bytes of key material ipsec-mb needs for |nid|. Only SM4-GCM has a GHASH key
 * to precompute; the other modes need nothing but the round keys.
 */
static size_t
sm4_key_sched_size(const int nid)
{
        return nid == NID_sm4_gcm ? sizeof(struct gcm_key_data) : SM4_KEY_SCHED_SIZE;
}

int
sm4_async_init(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
               const unsigned char *iv, const size_t ivlen, const int enc)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        /* Set common parameters */
        ctx->keylen = keylen;
        ctx->enc = enc;

        /* Handle NULL key case (re-initialization) */
        if (inkey == NULL) {
                if (!ctx->key_set) {
                        fprintf(stderr, "No key previously set for %d\n", ctx->nid);
                        return 0;
                }

                if (iv != NULL) {
                        /* IV validation based on cipher mode */
                        switch (ctx->nid) {
                        case NID_sm4_ecb:
                                /* ECB doesn't use IV */
                                break;
                        case NID_sm4_cbc:
                        case NID_sm4_ctr:
                                if (ivlen != SM4_IV_SIZE) {
                                        fprintf(stderr,
                                                "Invalid SM4-CBC or SM4-CTR IV length: %zu "
                                                "(expected %d)\n",
                                                ivlen, SM4_IV_SIZE);
                                        return 0;
                                }
                                memcpy(ctx->iv, iv, SM4_IV_SIZE);
                                memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                                ctx->iv_set = 1;
                                break;
                        case NID_sm4_gcm:
                                if (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE) {
                                        fprintf(stderr,
                                                "Invalid SM4-GCM IV length: %zu (expected 1-%d)\n",
                                                ivlen, SM4_GCM_IV_MAX_SIZE);
                                        return 0;
                                }
                                memcpy(ctx->iv, iv, ivlen);
                                memcpy(ctx->oiv, iv, ivlen);
                                ctx->ivlen = ivlen;
                                ctx->iv_set = 1;
                                break;
                        }
                }
                return 1;
        }

        /* Key length validation */
        if (keylen != SM4_KEY_SIZE) {
                fprintf(stderr, "Invalid SM4 key length: %zu (expected %d)\n", keylen,
                        SM4_KEY_SIZE);
                return 0;
        }

        /* Set mode-specific parameters */
        switch (ctx->nid) {
        case NID_sm4_ecb:
                ctx->blocksize = SM4_BLOCK_SIZE;
                ctx->ivlen = 0;  /* ECB doesn't use IV */
                ctx->iv_set = 1; /* ECB always considered IV set */
                break;
        case NID_sm4_cbc:
                ctx->blocksize = SM4_BLOCK_SIZE;
                ctx->ivlen = SM4_IV_SIZE;
                ctx->iv_set = 0;
                if (iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %zu (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                }
                break;
        case NID_sm4_ctr:
                ctx->blocksize = 1; /* CTR can handle any input size */
                ctx->ivlen = SM4_IV_SIZE;
                ctx->iv_set = 0;
                if (iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %zu (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                }
                break;
        case NID_sm4_gcm:
                ctx->blocksize = 1;           /* GCM can handle any input size */
                ctx->ivlen = SM4_GCM_IV_SIZE; /* Default IV size */
                ctx->iv_set = 0;
                if (iv != NULL) {
                        if (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE) {
                                fprintf(stderr, "Invalid SM4-GCM IV length: %zu (expected 1-%d)\n",
                                        ivlen, SM4_GCM_IV_MAX_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, ivlen);
                        memcpy(ctx->oiv, iv, ivlen);
                        ctx->ivlen = ivlen;
                        ctx->iv_set = 1;
                }
                break;
        }

        const size_t ks_size = sm4_key_sched_size(ctx->nid);
        const int need_dec_keys = (ctx->nid != NID_sm4_gcm);

        if (!ctx->enc_keys)
                ctx->enc_keys = OPENSSL_zalloc(ks_size);
        if (need_dec_keys && !ctx->dec_keys)
                ctx->dec_keys = OPENSSL_zalloc(ks_size);

        if (!ctx->enc_keys || (need_dec_keys && !ctx->dec_keys)) {
                fprintf(stderr, "Failed to allocate SM4 key memory\n");
                OPENSSL_free(ctx->enc_keys);
                OPENSSL_free(ctx->dec_keys);
                ctx->enc_keys = NULL;
                ctx->dec_keys = NULL;
                return 0;
        }

        if (ctx->nid == NID_sm4_gcm)
                imb_sm4_gcm_pre(tlv->imb_mgr, inkey, (struct gcm_key_data *) ctx->enc_keys);
        else
                IMB_SM4_KEYEXP(tlv->imb_mgr, inkey, ctx->enc_keys, ctx->dec_keys);

        ctx->key_set = 1;

        return 1;
}

/*
 * sm4_submit - run one SM4 job through ipsec-mb.
 *
 * |len| has to satisfy the mode's own length rule: a non-zero multiple of the
 * block size for ECB and CBC, any non-zero length for CTR and GCM.
 */
static int
sm4_submit(ALG_CTX *ctx, mb_thread_data *tlv, ASYNC_JOB *async_job, unsigned char *out,
           const unsigned char *in, const size_t len, const unsigned char *iv)
{
        struct IMB_JOB *imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);

        /* Job slots are recycled, so stale fields have to be cleared. */
        memset(imb_job, 0, sizeof(*imb_job));

        imb_job->dst = out;
        imb_job->src = in;
        imb_job->cipher_direction = ctx->enc ? IMB_DIR_ENCRYPT : IMB_DIR_DECRYPT;
        imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
        imb_job->hash_alg = IMB_AUTH_NULL;
        imb_job->enc_keys = ctx->enc_keys;
        imb_job->dec_keys = ctx->dec_keys;
        imb_job->key_len_in_bytes = ctx->keylen;
        imb_job->iv = iv;
        imb_job->iv_len_in_bytes = ctx->ivlen;
        imb_job->cipher_start_src_offset_in_bytes = 0;
        imb_job->msg_len_to_cipher_in_bytes = len;
        imb_job->user_data2 = async_job;

        switch (ctx->nid) {
        case NID_sm4_ecb:
                imb_job->cipher_mode = IMB_CIPHER_SM4_ECB;
                break;

        case NID_sm4_cbc:
                imb_job->cipher_mode = IMB_CIPHER_SM4_CBC;
                break;

        case NID_sm4_ctr:
                imb_job->cipher_mode = IMB_CIPHER_SM4_CTR;
                /* Keystream mode: decrypting is encrypting, so both directions
                 * use the encrypt schedule. */
                imb_job->dec_keys = ctx->enc_keys;
                break;

        case NID_sm4_gcm:
                imb_job->cipher_mode = IMB_CIPHER_SM4_GCM;
                imb_job->hash_alg = IMB_AUTH_SM4_GCM;
                imb_job->chain_order = ctx->enc ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;
                /* Both directions read the precomputed gcm_key_data. */
                imb_job->dec_keys = ctx->enc_keys;
                imb_job->u.GCM.aad = ctx->aad;
                imb_job->u.GCM.aad_len_in_bytes = ctx->aad_len;
                imb_job->auth_tag_output = ctx->auths;
                imb_job->auth_tag_output_len_in_bytes = ctx->tag_len;
                break;
        }

        if (async_update(tlv, ctx, async_job, imb_job) == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        /* ipsec-mb has written a tag into ctx->auths; it can now be read back on
         * encrypt, or compared with the caller's on decrypt. */
        if (ctx->nid == NID_sm4_gcm)
                ctx->tag_calculated = 1;

        return 1;
}

/*
 * sm4_block_update - ECB/CBC over an arbitrary byte count.
 *
 * ipsec-mb ciphers whole blocks only, while EVP_CipherUpdate() may be handed any
 * length and does no buffering on the provider's behalf. Bytes that do not fill
 * a block are therefore held in |ctx->buf| until a later call completes it, and
 * |*outl| reports what was actually written rather than what came in.
 *
 * For CBC the chaining value also has to be carried forward by hand: the job API
 * reads job->iv but never writes it back.
 */
static int
sm4_block_update(ALG_CTX *ctx, mb_thread_data *tlv, ASYNC_JOB *async_job, unsigned char *out,
                 size_t *outl, const unsigned char *in, size_t len)
{
        const int cbc = (ctx->nid == NID_sm4_cbc);
        unsigned char last[SM4_BLOCK_SIZE];
        size_t written = 0;

        /* Top up a block held over from an earlier call. */
        if (ctx->bufsz > 0) {
                const size_t want = SM4_BLOCK_SIZE - ctx->bufsz;
                const size_t take = len < want ? len : want;

                memcpy(ctx->buf + ctx->bufsz, in, take);
                ctx->bufsz += take;
                in += take;
                len -= take;

                if (ctx->bufsz < SM4_BLOCK_SIZE) {
                        *outl = 0;
                        return 1;
                }

                /* |ctx->buf| is a private copy, so on decrypt the next chaining
                 * value can be read from it even when |out| aliases the input. */
                if (cbc && !ctx->enc)
                        memcpy(last, ctx->buf, SM4_BLOCK_SIZE);

                if (!sm4_submit(ctx, tlv, async_job, out, ctx->buf, SM4_BLOCK_SIZE, ctx->iv))
                        return 0;

                if (cbc)
                        memcpy(ctx->iv, ctx->enc ? out : last, SM4_BLOCK_SIZE);

                ctx->bufsz = 0;
                out += SM4_BLOCK_SIZE;
                written += SM4_BLOCK_SIZE;
        }

        const size_t bulk = (len / SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE;

        if (bulk > 0) {
                /* The chaining value is the last ciphertext block. When
                 * decrypting that is an input block, which an in-place job is
                 * about to overwrite, so keep a copy. */
                if (cbc && !ctx->enc)
                        memcpy(last, in + bulk - SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);

                if (!sm4_submit(ctx, tlv, async_job, out, in, bulk, ctx->iv))
                        return 0;

                if (cbc)
                        memcpy(ctx->iv, ctx->enc ? out + bulk - SM4_BLOCK_SIZE : last,
                               SM4_BLOCK_SIZE);

                in += bulk;
                len -= bulk;
                written += bulk;
        }

        /* Hold the tail until a later call completes the block. */
        if (len > 0) {
                memcpy(ctx->buf, in, len);
                ctx->bufsz = len;
        }

        *outl = written;
        return 1;
}

/*
 * sm4_gcm_append_aad - collect additional authenticated data.
 *
 * AAD may arrive over multiple update calls; keep a private contiguous copy
 * so the job sees aad1 || aad2 || ... in order.
 */
static int
sm4_gcm_append_aad(ALG_CTX *ctx, const unsigned char *in, const size_t len)
{
        if (len == 0)
                return 1;

        if (in == NULL)
                return 0;

        if (ctx->aad_len < 0 || len > ((size_t) INT_MAX - (size_t) ctx->aad_len))
                return 0;

        size_t total = (size_t) ctx->aad_len + len;
        unsigned char *aad = OPENSSL_realloc(ctx->aad, total);

        if (aad == NULL) {
                fprintf(stderr, "Failed to allocate SM4-GCM AAD buffer\n");
                return 0;
        }

        memcpy(aad + ctx->aad_len, in, len);
        ctx->aad = aad;
        ctx->aad_len = (int) total;

        return 1;
}

/*
 * sm4_gcm_grow - make room for |need| bytes in both GCM message buffers.
 */
static int
sm4_gcm_grow(ALG_CTX *ctx, const size_t need)
{
        unsigned char *p;
        size_t alloc;

        if (need <= ctx->gcm_alloc)
                return 1;

        alloc = ctx->gcm_alloc != 0 ? ctx->gcm_alloc : SM4_GCM_MSG_ALLOC_MIN;
        while (alloc < need)
                alloc *= 2;

        p = OPENSSL_realloc(ctx->gcm_msg, alloc);
        if (p == NULL)
                return 0;
        ctx->gcm_msg = p;

        p = OPENSSL_realloc(ctx->gcm_buf, alloc);
        if (p == NULL)
                return 0;
        ctx->gcm_buf = p;

        ctx->gcm_alloc = alloc;

        return 1;
}

/*
 * sm4_gcm_update - GCM over a message that may arrive in pieces.
 *
 */
static int
sm4_gcm_update(ALG_CTX *ctx, mb_thread_data *tlv, ASYNC_JOB *async_job, unsigned char *out,
               size_t *outl, const unsigned char *in, const size_t len)
{
        if (len == 0) {
                *outl = 0;
                return 1;
        }

        if (!sm4_gcm_grow(ctx, ctx->gcm_len + len)) {
                fprintf(stderr, "Failed to allocate SM4-GCM message buffer\n");
                return 0;
        }

        memcpy(ctx->gcm_msg + ctx->gcm_len, in, len);
        ctx->gcm_len += len;

        if (!sm4_submit(ctx, tlv, async_job, ctx->gcm_buf, ctx->gcm_msg, ctx->gcm_len, ctx->iv))
                return 0;

        memcpy(out, ctx->gcm_buf + ctx->gcm_len - len, len);
        *outl = len;

        return 1;
}

/*
 * sm4_ctr_inc - advance an SM4-CTR counter block by |blocks|.
 *
 * ipsec-mb reads a 16-byte SM4-CTR IV as a 12-byte nonce followed by a 32-bit
 * big-endian block counter and steps it with paddd, so it wraps inside those
 * four bytes and never carries into the nonce. Chained calls have to reproduce
 * that, because the job API does not write the counter back.
 */
static void
sm4_ctr_inc(unsigned char *iv, const uint32_t blocks)
{
        unsigned char *c = iv + SM4_IV_SIZE - 4;
        uint32_t v = ((uint32_t) c[0] << 24) | ((uint32_t) c[1] << 16) | ((uint32_t) c[2] << 8) |
                     (uint32_t) c[3];

        v += blocks;

        c[0] = (unsigned char) (v >> 24);
        c[1] = (unsigned char) (v >> 16);
        c[2] = (unsigned char) (v >> 8);
        c[3] = (unsigned char) v;
}

/*
 * sm4_ctr_update - CTR over an arbitrary byte count.
 *
 * A single job handles any length, including a short trailing block, but it
 * always starts at the counter it is given. Splitting a message across calls
 * therefore needs the counter advanced here, and a partly used keystream block
 * kept in |ctx->buf| with the offset into it in |ctx->num|.
 */
static int
sm4_ctr_update(ALG_CTX *ctx, mb_thread_data *tlv, ASYNC_JOB *async_job, unsigned char *out,
               size_t *outl, const unsigned char *in, const size_t len)
{
        static const unsigned char zeroes[SM4_BLOCK_SIZE] = { 0 };
        unsigned int n = ctx->num;
        size_t l = 0;

        /* Spend what is left of the block the previous call generated. The
         * counter only moves on once that block is used up. */
        while (n != 0 && l < len) {
                out[l] = in[l] ^ ctx->buf[n];
                l++;
                n = (n + 1) & (SM4_BLOCK_SIZE - 1);
                if (n == 0)
                        sm4_ctr_inc(ctx->iv, 1);
        }

        const size_t bulk = ((len - l) / SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE;

        if (bulk > 0) {
                if (!sm4_submit(ctx, tlv, async_job, out + l, in + l, bulk, ctx->iv))
                        return 0;
                sm4_ctr_inc(ctx->iv, (uint32_t) (bulk / SM4_BLOCK_SIZE));
                l += bulk;
        }

        /* A tail shorter than a block: keep its whole keystream block so the
         * next call can carry on inside the same counter block. Running zeroes
         * through CTR yields the keystream itself. */
        if (l < len) {
                if (!sm4_submit(ctx, tlv, async_job, ctx->buf, zeroes, SM4_BLOCK_SIZE, ctx->iv))
                        return 0;

                do {
                        out[l] = in[l] ^ ctx->buf[n];
                        l++;
                        n++;
                } while (l < len);
        }

        ctx->num = n;
        *outl = len;

        return 1;
}

static int
sm4_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                    const unsigned char *in, const size_t len)
{
        ASYNC_JOB *async_job;
        size_t need;
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        /* A NULL output means the input is AAD rather than payload. */
        if (out == NULL) {
                if (ctx->nid != NID_sm4_gcm) {
                        fprintf(stderr, "SM4: AAD supplied to a non-AEAD mode\n");
                        return 0;
                }

                if (len == 0) {
                        *outl = 0;
                        return 1;
                }

                if (in == NULL)
                        return 0;

                if (!sm4_gcm_append_aad(ctx, in, len))
                        return 0;
                *outl = len;
                return 1;
        }

        /* EVP permits NULL input pointers on zero-length data updates. */
        if (len == 0) {
                *outl = 0;
                return 1;
        }

        if (in == NULL)
                return 0;

        async_job = ASYNC_get_current_job();
        if (async_job == NULL) {
                fprintf(stderr, "Not running asynchronously, exit\n");
                return 0;
        }

        /*
         * Ensure the output buffer can accommodate the maximum output for this
         * update call. ECB/CBC may output up to len + (block_size - 1) due to
         * internal buffering of partial blocks.
         */
        need = len;
        if ((ctx->nid == NID_sm4_ecb || ctx->nid == NID_sm4_cbc) && len > 0) {
                if (need + (SM4_BLOCK_SIZE - 1) < need)
                        return 0;
                need += (SM4_BLOCK_SIZE - 1);
        }
        if (outsize < need) {
                fprintf(stderr, "Output buffer too small: %zu < %zu\n", outsize, need);
                return 0;
        }

        switch (ctx->nid) {
        case NID_sm4_ecb:
        case NID_sm4_cbc:
                return sm4_block_update(ctx, tlv, async_job, out, outl, in, len);

        case NID_sm4_ctr:
                return sm4_ctr_update(ctx, tlv, async_job, out, outl, in, len);

        case NID_sm4_gcm:
                return sm4_gcm_update(ctx, tlv, async_job, out, outl, in, len);

        default:
                fprintf(stderr, "Unsupported SM4 cipher mode: %d\n", ctx->nid);
                return 0;
        }
}

/* Provider interface functions */
void *
prov_sm4_ecb_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_ecb;
        ctx->blocksize = SM4_BLOCK_SIZE;
        ctx->ivlen = 0; /* ECB doesn't use IV */
        ctx->keylen = SM4_KEY_SIZE;

        return ctx;
}

void *
prov_sm4_cbc_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_cbc;
        ctx->blocksize = SM4_BLOCK_SIZE;
        ctx->ivlen = SM4_IV_SIZE;
        ctx->keylen = SM4_KEY_SIZE;

        return ctx;
}

void *
prov_sm4_gcm_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_gcm;
        ctx->blocksize = 1; /* GCM can handle any input size */
        ctx->ivlen = SM4_GCM_IV_SIZE;
        ctx->keylen = SM4_KEY_SIZE;
        /* Announcing a shorter tag is optional, so a default is needed: the job
         * is rejected outright if the tag length is left at zero. */
        ctx->tag_len = SM4_GCM_TAG_SIZE;

        return ctx;
}

void *
prov_sm4_ctr_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_ctr;
        ctx->blocksize = 1; /* CTR can handle any input size */
        ctx->ivlen = SM4_IV_SIZE;
        ctx->keylen = SM4_KEY_SIZE;

        return ctx;
}

void
prov_sm4_freectx(void *vctx)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        if (ctx != NULL) {
                sm4_async_cleanup(ctx);
                OPENSSL_clear_free(ctx, sizeof(ALG_CTX));
        }
}

void *
prov_sm4_dupctx(void *vctx)
{
        ALG_CTX *in = (ALG_CTX *) vctx;
        ALG_CTX *ret = prov_alg_ctx_dup_base(in);

        if (ret == NULL)
                return NULL;

        const size_t ks_size = sm4_key_sched_size(in->nid);

        if (!prov_cipher_dup_buf(&ret->enc_keys, in->enc_keys, ks_size) ||
            !prov_cipher_dup_buf(&ret->dec_keys, in->dec_keys, ks_size)) {
                prov_sm4_freectx(ret);
                return NULL;
        }

        if (in->aad_len > 0 && !prov_cipher_dup_buf(&ret->aad, in->aad, in->aad_len)) {
                prov_sm4_freectx(ret);
                return NULL;
        }

        /* The expected tag is set on the base context before it is duplicated
         * for each sub-case, so the copy has to carry it too. */
        if (!prov_cipher_dup_buf(&ret->tag, in->tag, sizeof(in->auths))) {
                prov_sm4_freectx(ret);
                return NULL;
        }

        /*
         * A partly consumed SM4-GCM message has to come across as well, or the
         * copy would re-cipher from the wrong starting point. The inherited
         * allocation size describes buffers the copy does not own yet, so it has
         * to be cleared before anything is grown.
         */
        ret->gcm_alloc = 0;

        if (in->gcm_len > 0) {
                if (!sm4_gcm_grow(ret, in->gcm_len)) {
                        prov_sm4_freectx(ret);
                        return NULL;
                }
                memcpy(ret->gcm_msg, in->gcm_msg, in->gcm_len);
        }

        return ret;
}

int
prov_sm4_encrypt_init(void *vctx, const unsigned char *key, const int keylen,
                      const unsigned char *iv, const int ivlen, const int enc)
{
        return prov_sm4_init(vctx, key, keylen, iv, ivlen, 1);
}

int
prov_sm4_decrypt_init(void *vctx, const unsigned char *key, const int keylen,
                      const unsigned char *iv, const int ivlen, const int enc)
{
        return prov_sm4_init(vctx, key, keylen, iv, ivlen, 0);
}

static int
prov_sm4_init(void *vctx, const unsigned char *key, const int keylen, const unsigned char *iv,
              const int ivlen, const int enc)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return 0;

        /*
         * A context may be re-initialised and reused, so the state the update
         * path carries between calls - a held-back partial block for ECB/CBC, a
         * partly spent keystream block for CTR, collected AAD and the tag for
         * GCM - has to be dropped here. The AAD allocation is kept for reuse.
         */
        ctx->bufsz = 0;
        ctx->num = 0;
        ctx->aad_len = 0;
        ctx->gcm_len = 0;
        ctx->tag_calculated = 0;

        /* If key is NULL, we're doing a re-init with the same key */
        if (key == NULL) {
                /* Use existing key, just update enc flag */
                ctx->enc = enc;

                /* Handle IV for re-init */
                if (ctx->nid == NID_sm4_cbc && iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %d (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                } else if (ctx->nid == NID_sm4_ctr && iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %d (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                } else if (ctx->nid == NID_sm4_gcm && iv != NULL) {
                        if (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE) {
                                fprintf(stderr, "Invalid SM4-GCM IV length: %d (expected 1-%d)\n",
                                        ivlen, SM4_GCM_IV_MAX_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, ivlen);
                        memcpy(ctx->oiv, iv, ivlen);
                        ctx->ivlen = ivlen;
                        ctx->iv_set = 1;
                } else if (ctx->nid == NID_sm4_cbc && iv == NULL && ctx->iv_set) {
                        /* Restore original IV for CBC */
                        memcpy(ctx->iv, ctx->oiv, SM4_IV_SIZE);
                } else if (ctx->nid == NID_sm4_ctr && iv == NULL && ctx->iv_set) {
                        /* Restore original IV for CTR */
                        memcpy(ctx->iv, ctx->oiv, SM4_IV_SIZE);
                } else if (ctx->nid == NID_sm4_gcm && iv == NULL && ctx->iv_set) {
                        /* Restore original IV for GCM */
                        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);
                }

                return 1;
        }

        /* Normal initialization with new key - use unified function */
        return sm4_async_init(ctx, key, keylen, iv, ivlen, enc);
}

int
prov_sm4_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, const size_t inl)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return 0;

        if (ctx->nid == NID_sm4_ecb || ctx->nid == NID_sm4_cbc || ctx->nid == NID_sm4_ctr ||
            ctx->nid == NID_sm4_gcm) {
                return sm4_async_do_cipher(ctx, out, outl, outsize, in, inl);
        }

        return 0;
}

int
prov_sm4_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return 0;

        /*
         * Padding is not implemented, so a block the update path is still
         * holding cannot be completed and its input would silently vanish.
         */
        if (ctx->bufsz > 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
                return 0;
        }

        /*
         * ipsec-mb only ever writes the tag it computed; comparing it with the
         * one the caller supplied is the provider's job, and failing here is how
         * a forgery is reported.
         */
        if (ctx->nid == NID_sm4_gcm && !ctx->enc) {
                if (!ctx->tag_set || !ctx->tag_calculated) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
                        return 0;
                }
                if (CRYPTO_memcmp(ctx->tag, ctx->auths, (size_t) ctx->tag_len) != 0) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
                        return 0;
                }
        }

        *outl = 0;

        return 1;
}

int
prov_sm4_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, const size_t inl)
{
        return prov_sm4_update(vctx, out, outl, outsize, in, inl);
}

int
prov_sm4_get_params(OSSL_PARAM params[], const int nid, const int mode)
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
        if (p != NULL && !OSSL_PARAM_set_uint(p, mode)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, SM4_KEY_SIZE)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, SM4_BLOCK_SIZE)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        /*
         * These two are what makes a cipher an AEAD as far as libcrypto is
         * concerned: they are where EVP_CIPH_FLAG_AEAD_CIPHER and
         * EVP_CIPH_CUSTOM_IV_LENGTH come from. Leaving them unanswered means no
         * caller can pass AAD or a tag, whatever the mode is.
         */
        const int aead = (nid == NID_sm4_gcm);

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
        if (p != NULL && !OSSL_PARAM_set_int(p, aead)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if (p != NULL && !OSSL_PARAM_set_int(p, aead)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL) {
                size_t ivlen;
                if (nid == NID_sm4_ecb) {
                        ivlen = 0;
                } else if (nid == NID_sm4_cbc) {
                        ivlen = SM4_IV_SIZE;
                } else if (nid == NID_sm4_ctr) {
                        ivlen = SM4_IV_SIZE;
                } else if (nid == NID_sm4_gcm) {
                        ivlen = SM4_GCM_IV_SIZE;
                } else {
                        ivlen = 0;
                }
                if (!OSSL_PARAM_set_size_t(p, ivlen)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                        return 0;
                }
        }

        return 1;
}

int
prov_sm4_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        OSSL_PARAM *p;

        if (ctx == NULL)
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, ctx->oiv, ctx->ivlen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        /* The tag ipsec-mb computed, which is only meaningful once a job has
         * actually run and only ever read back by the encrypting side. */
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
                if (!ctx->enc || !ctx->tag_calculated || p->data_size > sizeof(ctx->auths)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
                        return 0;
                }
                if (!OSSL_PARAM_set_octet_string(p, ctx->auths, p->data_size)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                        return 0;
                }
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, (size_t) ctx->tag_len)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        return 1;
}

int
prov_sm4_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        const OSSL_PARAM *p;

        if (ctx == NULL)
                return 0;

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL) {
                size_t keylen;
                if (!OSSL_PARAM_get_size_t(p, &keylen)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }
                if (keylen != SM4_KEY_SIZE) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                        return 0;
                }
                ctx->keylen = keylen;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL) {
                if (ctx->nid == NID_sm4_ecb) {
                        /* ECB mode doesn't use IV */
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                        return 0;
                }
                size_t ivlen;
                const void *iv = NULL;
                if (!OSSL_PARAM_get_octet_string_ptr(p, &iv, &ivlen)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }

                /* Validate IV length based on cipher mode */
                if (ctx->nid == NID_sm4_cbc && ivlen != SM4_IV_SIZE) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                        return 0;
                } else if (ctx->nid == NID_sm4_ctr && ivlen != SM4_IV_SIZE) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                        return 0;
                } else if (ctx->nid == NID_sm4_gcm && (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                        return 0;
                }

                memcpy(ctx->iv, iv, ivlen);
                memcpy(ctx->oiv, iv, ivlen);
                ctx->ivlen = ivlen;
                ctx->iv_set = 1;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
        if (p != NULL) {
                size_t ivlen;

                if (!OSSL_PARAM_get_size_t(p, &ivlen)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }
                if (ctx->nid != NID_sm4_gcm || ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                        return 0;
                }
                ctx->ivlen = ivlen;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
                if (ctx->nid != NID_sm4_gcm || p->data_type != OSSL_PARAM_OCTET_STRING ||
                    p->data_size == 0 || p->data_size > sizeof(ctx->auths)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
                        return 0;
                }

                /*
                 * A NULL value only announces the tag length, which is what the
                 * encrypting side does; an actual tag is supplied for decryption
                 * only, and is kept for final() to check against.
                 */
                if (p->data != NULL) {
                        if (ctx->enc) {
                                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                                return 0;
                        }

                        if (ctx->tag == NULL) {
                                ctx->tag = OPENSSL_zalloc(sizeof(ctx->auths));
                                if (ctx->tag == NULL)
                                        return 0;
                        }

                        memcpy(ctx->tag, p->data, p->data_size);
                        ctx->tag_set = 1;
                }

                ctx->tag_len = (int) p->data_size;
        }

        return 1;
}

/* Generate the cipher function tables using the macro */
PROV_sm4_cipher(prov_sm4, ecb, ECB, PROV_SM4_ECB_FLAGS, 128, 0, NID_sm4_ecb);
PROV_sm4_cipher(prov_sm4, cbc, CBC, PROV_SM4_CBC_FLAGS, 128, 128, NID_sm4_cbc);
PROV_sm4_cipher(prov_sm4, ctr, CTR, PROV_SM4_CTR_FLAGS, 8, 128, NID_sm4_ctr);
PROV_sm4_cipher(prov_sm4, gcm, GCM, PROV_SM4_GCM_FLAGS, 8, 96, NID_sm4_gcm);
