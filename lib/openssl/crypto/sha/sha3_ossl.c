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
#include "memcpy.h"

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
 * A buffered absorb function that calls the absorb function of the
 * context's method.
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
                        safe_memcpy(ctx->buf + num, inp, len);
                        ctx->bufsz += len;
                        return 1;
                }
                /* otherwise fill up the buffer and absorb the buffer */
                safe_memcpy(ctx->buf + num, inp, rem);
                /* Update the input pointer */
                inp += rem;
                len -= rem;
                ctx->meth.absorb(ctx->A, ctx->buf, bsz, bsz);
                ctx->bufsz = 0;
                ctx->xof_state = XOF_STATE_ABSORB;
        }
        /* Absorb the input - rem = leftover part of the input < blocksize) */
        rem = ctx->meth.absorb(ctx->A, inp, len, bsz);
        if (len >= bsz)
                ctx->xof_state = XOF_STATE_ABSORB;
        /* Copy the leftover bit of the input into the buffer */
        if (ossl_likely(rem > 0)) {
                safe_memcpy(ctx->buf, inp + len - rem, rem);
                ctx->bufsz = rem;
        }
        return 1;
}

static int
sha3_final(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);
static int
shake_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);

/*
 * Single shot final.
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

        ret = sha3_final(ctx, out, outlen);
        ctx->xof_state = XOF_STATE_FINAL;
        return ret;
}

/* Squeeze that can be called multiple times */
int
ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
        int ret = 0;

        if (ctx->xof_state == XOF_STATE_FINAL)
                return 0;
        ret = shake_squeeze(ctx, out, outlen);
        ctx->xof_state = XOF_STATE_SQUEEZE;
        return ret;
}

/* Pad the buffered input with 10*1 and absorb it as the last block */
static void
sha3_pad_absorb(KECCAK1600_CTX *ctx)
{
        const size_t bsz = ctx->block_size;
        const size_t num = ctx->bufsz;

        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + num, 0, bsz - num);
        ctx->buf[num] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;

        (void) ctx->meth.absorb(ctx->A, ctx->buf, bsz, bsz);
}

/*
 * Single shot final
 * (Use shake_squeeze() for multiple calls).
 */
static int
sha3_final(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
        sha3_pad_absorb(ctx);
        ctx->meth.squeeze(ctx->A, out, outlen, ctx->block_size, 0);
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
static int
shake_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
        const size_t bsz = ctx->block_size;
        size_t num = ctx->bufsz;
        size_t len;
        int next = 1;

        /*
         * On the first squeeze call, finish the absorb process,
         * by adding the trailing padding and then doing
         * a final absorb.
         */
        if (ctx->xof_state != XOF_STATE_SQUEEZE) {
                sha3_pad_absorb(ctx);
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
                safe_memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
                out += len;
                outlen -= len;
                ctx->bufsz -= len;
        }
        if (outlen == 0)
                return 1;

        /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
        if (outlen >= bsz) {
                len = bsz * (outlen / bsz);
                ctx->meth.squeeze(ctx->A, out, len, bsz, next);
                next = 1;
                out += len;
                outlen -= len;
        }
        if (outlen > 0) {
                /* Step 3. Squeeze one more block into a buffer */
                ctx->meth.squeeze(ctx->A, ctx->buf, bsz, bsz, next);
                safe_memcpy(out, ctx->buf, outlen);
                /* Step 4. Remember the leftover part of the squeezed block */
                ctx->bufsz = bsz - outlen;
        }
        return 1;
}

const PROV_SHA3_METHOD ossl_sha3_default_meth = { SHA3_absorb, SHA3_squeeze };

const PROV_SHA3_METHOD ossl_sha3_avx512_meth = { SHA3_absorb_avx512, SHA3_squeeze_avx512 };
