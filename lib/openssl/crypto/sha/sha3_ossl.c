/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "openssl_compat.h"
#include "internal/sha3.h"

void
SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next);

void
ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
        memset(ctx->A, 0, sizeof(ctx->A));
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_INIT;
}

int
ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen)
{
        size_t bsz = SHA3_BLOCKSIZE(bitlen);

        if (bsz <= sizeof(ctx->buf)) {
                ossl_sha3_reset(ctx);
                ctx->block_size = bsz;
                ctx->md_size = bitlen / 8;
                ctx->pad = pad;
                return 1;
        }

        return 0;
}

int
ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen, size_t mdlen)
{
        int ret = ossl_sha3_init(ctx, pad, bitlen);

        if (ret)
                ctx->md_size = mdlen / 8;
        return ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
int
ossl_sha3_absorb(KECCAK1600_CTX *ctx, const unsigned char *inp, size_t len)
{
        const size_t bsz = ctx->block_size;
        size_t num, rem;

        if (ossl_unlikely(len == 0))
                return 1;

        if (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
                return 0;

        /* Is there anything in the buffer already ? */
        if ((num = ctx->bufsz) != 0) {
                /* Calculate how much space is left in the buffer */
                rem = bsz - num;
                /* If the new input does not fill the buffer then just add it */
                if (len < rem) {
                        memcpy(ctx->buf + num, inp, len);
                        ctx->bufsz += len;
                        return 1;
                }
                /* otherwise fill up the buffer and absorb the buffer */
                memcpy(ctx->buf + num, inp, rem);
                /* Update the input pointer */
                inp += rem;
                len -= rem;
                ctx->meth.absorb(ctx, ctx->buf, bsz);
                ctx->bufsz = 0;
                ctx->xof_state = XOF_STATE_ABSORB;
        }
        /* Absorb the input - rem = leftover part of the input < blocksize) */
        rem = ctx->meth.absorb(ctx, inp, len);
        if (len >= bsz)
                ctx->xof_state = XOF_STATE_ABSORB;
        /* Copy the leftover bit of the input into the buffer */
        if (ossl_likely(rem > 0)) {
                memcpy(ctx->buf, inp + len - rem, rem);
                ctx->bufsz = rem;
        }
        return 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
int
ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
        int ret;

        if (ctx->xof_state == XOF_STATE_SQUEEZE || ctx->xof_state == XOF_STATE_FINAL)
                return 0;
        if (outlen == 0)
                return 1;

        ret = ctx->meth.final(ctx, out, outlen);
        ctx->xof_state = XOF_STATE_FINAL;
        return ret;
}

/* Calls a platform specific squeeze method */
int
ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
        int ret = 0;

        if (ctx->xof_state == XOF_STATE_FINAL)
                return 0;
        ret = ctx->meth.squeeze(ctx, out, outlen);
        ctx->xof_state = XOF_STATE_SQUEEZE;
        return ret;
}

/* Default version of the absorb() */
size_t
ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, const unsigned char *inp, size_t len)
{
        return SHA3_absorb(ctx->A, inp, len, ctx->block_size);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
int
ossl_sha3_final_default(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
        size_t bsz = ctx->block_size;
        size_t num = ctx->bufsz;

        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + num, 0, bsz - num);
        ctx->buf[num] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;

        (void) SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

        SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
        return 1;
}

/*
 * This method can be called multiple times.
 * Rather than heavily modifying assembler for SHA3_squeeze(),
 * we instead just use the limitations of the existing function.
 * i.e. Only request multiples of the ctx->block_size when calling
 * SHA3_squeeze(). For output length requests smaller than the
 * ctx->block_size just request a single ctx->block_size bytes and
 * buffer the results. The next request will use the buffer first
 * to grab output bytes.
 */
int
ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
        size_t bsz = ctx->block_size;
        size_t num = ctx->bufsz;
        size_t len;
        int next = 1;

        /*
         * On the first squeeze call, finish the absorb process,
         * by adding the trailing padding and then doing
         * a final absorb.
         */
        if (ctx->xof_state != XOF_STATE_SQUEEZE) {
                /*
                 * Pad the data with 10*1. Note that |num| can be |bsz - 1|
                 * in which case both byte operations below are performed on
                 * same byte...
                 */
                memset(ctx->buf + num, 0, bsz - num);
                ctx->buf[num] = ctx->pad;
                ctx->buf[bsz - 1] |= 0x80;
                (void) SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
                num = ctx->bufsz = 0;
                next = 0;
        }

        /*
         * Step 1. Consume any bytes left over from a previous squeeze
         * (See Step 4 below).
         */
        if (num != 0) {
                if (outlen > ctx->bufsz)
                        len = ctx->bufsz;
                else
                        len = outlen;
                memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
                out += len;
                outlen -= len;
                ctx->bufsz -= len;
        }
        if (outlen == 0)
                return 1;

        /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
        if (outlen >= bsz) {
                len = bsz * (outlen / bsz);
                SHA3_squeeze(ctx->A, out, len, bsz, next);
                next = 1;
                out += len;
                outlen -= len;
        }
        if (outlen > 0) {
                /* Step 3. Squeeze one more block into a buffer */
                SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, next);
                memcpy(out, ctx->buf, outlen);
                /* Step 4. Remember the leftover part of the squeezed block */
                ctx->bufsz = bsz - outlen;
        }
        return 1;
}

static PROV_SHA3_METHOD shake_generic_meth = { ossl_sha3_absorb_default, ossl_sha3_final_default,
                                               ossl_shake_squeeze_default };

KECCAK1600_CTX *
ossl_shake256_new(void)
{
        KECCAK1600_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

        if (ctx == NULL)
                return NULL;
        ossl_keccak_init(ctx, '\x1f', 256, 0);
        ctx->md_size = SIZE_MAX;
        ctx->meth = shake_generic_meth;
        return ctx;
}
