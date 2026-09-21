/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
******************************************************************************/

/*
 * SHAKE x4 AVX2 - C implementation over the AVX2 keccak_f1600_x4_avx2 kernel.
 *
 * State: A[w*4 + lane] for w in 0..24, lane in 0..3 (interleaved 4-lane).
 * A[100]: absorb = bytes consumed in block (0..rate-1);
 *         squeeze = bytes remaining in block (0..rate).
 */

#include "openssl_compat.h"
#include "internal/sha3.h"
#include <intel-ipsec-mb.h>
#include <stdint.h>
#include <string.h>

/*
 * C-callable wrapper around the private-convention keccak_f1600_x4_avx2 kernel
 * (sha3_mb_avx2.asm). The _ossl variant handles ABI differences.
 */
extern void
keccak_f1600_x4_avx2_ossl(uint64_t *state);
#define keccak_f1600_x4_avx2 keccak_f1600_x4_avx2_ossl

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/* Load/store a 64-bit word from/to a caller supplied byte stream.
 *
 * x86 performs misaligned loads and stores without complaint, so this is not
 * a correctness issue for this x86-only library. However, dereferencing a
 * misaligned uint64_t pointer is undefined behaviour in C and UBSan reports
 * it, so memcpy() is used to express the same access. It compiles down to the
 * very same single unaligned mov. */
static inline uint64_t
load_u64(const uint8_t *p)
{
        uint64_t v;

        memcpy(&v, p, sizeof(v));
        return v;
}

static inline void
store_u64(uint8_t *p, const uint64_t v)
{
        memcpy(p, &v, sizeof(v));
}

/* Absorb n bytes one at a time; used for unaligned head and tail.
 * Reads pos from ctx->A[100] and writes back the updated value.
 * in0..in3 - input byte streams for lanes 0-3
 * n        - number of bytes to absorb */
static void
absorb_bytes_x4(KECCAK1600_X4_CTX *ctx, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2,
                const uint8_t *in3, size_t n)
{
        size_t pos = (size_t) ctx->A[100];

        while (n-- > 0) {
                const size_t word = pos >> 3;
                const size_t shift = (pos & 7) << 3;

                ctx->A[word * 4 + 0] ^= (uint64_t) *in0++ << shift;
                ctx->A[word * 4 + 1] ^= (uint64_t) *in1++ << shift;
                ctx->A[word * 4 + 2] ^= (uint64_t) *in2++ << shift;
                ctx->A[word * 4 + 3] ^= (uint64_t) *in3++ << shift;

                if (++pos == ctx->rate) {
                        keccak_f1600_x4_avx2(ctx->A);
                        pos = 0;
                }
        }
        ctx->A[100] = (uint64_t) pos;
}

/* Absorb inlen bytes from four inputs: byte head, word body, byte tail.
 * Reads pos from ctx->A[100] and writes back the updated value.
 * in0..in3 - input byte streams for lanes 0-3
 * inlen    - number of bytes to absorb */
static void
absorb_x4_avx2(KECCAK1600_X4_CTX *ctx, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2,
               const uint8_t *in3, size_t inlen)
{
        size_t pos = (size_t) ctx->A[100];

        /* Head: align pos to a word boundary */
        if ((pos & 7) != 0 && inlen > 0) {
                size_t head = 8 - (pos & 7);

                if (head > inlen)
                        head = inlen;
                absorb_bytes_x4(ctx, in0, in1, in2, in3, head);
                pos = (size_t) ctx->A[100];
                in0 += head;
                in1 += head;
                in2 += head;
                in3 += head;
                inlen -= head;
        }

        /* Body: one word at a time */
        while (inlen >= sizeof(uint64_t)) {
                const size_t word = pos >> 3;

                ctx->A[word * 4 + 0] ^= load_u64(in0);
                ctx->A[word * 4 + 1] ^= load_u64(in1);
                ctx->A[word * 4 + 2] ^= load_u64(in2);
                ctx->A[word * 4 + 3] ^= load_u64(in3);
                in0 += 8;
                in1 += 8;
                in2 += 8;
                in3 += 8;
                inlen -= 8;
                pos += 8;

                if (pos == ctx->rate) {
                        keccak_f1600_x4_avx2(ctx->A);
                        pos = 0;
                }
        }

        /* Tail: sync pos to ctx->A[100] before calling absorb_bytes_x4 */
        ctx->A[100] = (uint64_t) pos;
        if (inlen > 0)
                absorb_bytes_x4(ctx, in0, in1, in2, in3, inlen);
}

/* Apply SHAKE padding (0x1F / 0x80) to all four lanes and permute.
 * Reads pos from ctx->A[100]; sets ctx->A[100] = rate (avail for squeeze). */
static void
finalize_x4_avx2(KECCAK1600_X4_CTX *ctx)
{
        const size_t pos = (size_t) ctx->A[100];
        const size_t word = pos >> 3;
        const size_t shift = (pos & 7) << 3;
        const size_t end_word = (ctx->rate >> 3) - 1; /* last word in rate block */

        ctx->A[word * 4 + 0] ^= UINT64_C(0x1F) << shift; /* SHAKE domain */
        ctx->A[word * 4 + 1] ^= UINT64_C(0x1F) << shift;
        ctx->A[word * 4 + 2] ^= UINT64_C(0x1F) << shift;
        ctx->A[word * 4 + 3] ^= UINT64_C(0x1F) << shift;

        ctx->A[end_word * 4 + 0] ^= UINT64_C(0x8000000000000000); /* terminator */
        ctx->A[end_word * 4 + 1] ^= UINT64_C(0x8000000000000000);
        ctx->A[end_word * 4 + 2] ^= UINT64_C(0x8000000000000000);
        ctx->A[end_word * 4 + 3] ^= UINT64_C(0x8000000000000000);

        keccak_f1600_x4_avx2(ctx->A);
        ctx->A[100] = (uint64_t) ctx->rate; /* avail = rate for squeeze */
}

/* Extract outlen bytes from all four lanes; may be called repeatedly.
 * ctx->A[100] holds bytes remaining in the current rate block.
 * out0..out3 - output byte buffers for lanes 0-3
 * outlen     - number of bytes to squeeze per lane */
static void
squeeze_x4_avx2(KECCAK1600_X4_CTX *ctx, uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
                size_t outlen)
{
        size_t avail = (size_t) ctx->A[100];

        while (outlen > 0) {
                size_t todo, done, pos;

                if (avail == 0) {
                        keccak_f1600_x4_avx2(ctx->A);
                        avail = ctx->rate;
                }

                pos = ctx->rate - avail;
                todo = (avail < outlen) ? avail : outlen;
                done = 0;

                while (done < todo) {
                        const size_t cur = pos + done;
                        const size_t word = cur >> 3;
                        const size_t shift = (cur & 7) << 3;

                        if (shift == 0 && (todo - done) >= sizeof(uint64_t)) {
                                store_u64(out0 + done, ctx->A[word * 4 + 0]);
                                store_u64(out1 + done, ctx->A[word * 4 + 1]);
                                store_u64(out2 + done, ctx->A[word * 4 + 2]);
                                store_u64(out3 + done, ctx->A[word * 4 + 3]);
                                done += sizeof(uint64_t);
                        } else {
                                *(out0 + done) = (uint8_t) (ctx->A[word * 4 + 0] >> shift);
                                *(out1 + done) = (uint8_t) (ctx->A[word * 4 + 1] >> shift);
                                *(out2 + done) = (uint8_t) (ctx->A[word * 4 + 2] >> shift);
                                *(out3 + done) = (uint8_t) (ctx->A[word * 4 + 3] >> shift);
                                done++;
                        }
                }

                out0 += todo;
                out1 += todo;
                out2 += todo;
                out3 += todo;
                outlen -= todo;
                avail -= todo;
        }

        ctx->A[100] = (uint64_t) avail;
}

/* ------------------------------------------------------------------ */
/* SHAKE-128 x4                                                         */
/* ------------------------------------------------------------------ */

void
ossl_sha3_shake128_x4_inc_init_avx2(KECCAK1600_X4_CTX *ctx)
{
        memset(ctx->A, 0, sizeof(ctx->A));
        ctx->rate = SHA3_BLOCKSIZE(128);
        ctx->finalized = 0;
}

void
ossl_sha3_shake128_x4_inc_absorb_avx2(KECCAK1600_X4_CTX *ctx, const void *in0, const void *in1,
                                      const void *in2, const void *in3, size_t inlen)
{
        if (ctx->finalized)
                return; /* error: cannot absorb after finalize */

        absorb_x4_avx2(ctx, (const uint8_t *) in0, (const uint8_t *) in1, (const uint8_t *) in2,
                       (const uint8_t *) in3, inlen);
}

void
ossl_sha3_shake128_x4_inc_cleanup_avx2(KECCAK1600_X4_CTX *ctx)
{
        OPENSSL_cleanse(ctx, sizeof(*ctx));
}

static void
ossl_sha3_shake128_x4_inc_finalize_avx2(KECCAK1600_X4_CTX *ctx)
{
        if (ctx->finalized)
                return;

        finalize_x4_avx2(ctx);
        ctx->finalized = 1;
}

void
ossl_sha3_shake128_x4_inc_squeeze_avx2(void *out0, void *out1, void *out2, void *out3,
                                       size_t outlen, KECCAK1600_X4_CTX *ctx)
{
        if (!ctx->finalized)
                ossl_sha3_shake128_x4_inc_finalize_avx2(ctx);

        squeeze_x4_avx2(ctx, (uint8_t *) out0, (uint8_t *) out1, (uint8_t *) out2, (uint8_t *) out3,
                        outlen);
}

/* ------------------------------------------------------------------ */
/* SHAKE-256 x4                                                         */
/* ------------------------------------------------------------------ */

void
ossl_sha3_shake256_x4_inc_init_avx2(KECCAK1600_X4_CTX *ctx)
{
        memset(ctx->A, 0, sizeof(ctx->A));
        ctx->rate = SHA3_BLOCKSIZE(256);
        ctx->finalized = 0;
}

void
ossl_sha3_shake256_x4_inc_absorb_avx2(KECCAK1600_X4_CTX *ctx, const void *in0, const void *in1,
                                      const void *in2, const void *in3, size_t inlen)
{
        if (ctx->finalized)
                return; /* error: cannot absorb after finalize */

        absorb_x4_avx2(ctx, (const uint8_t *) in0, (const uint8_t *) in1, (const uint8_t *) in2,
                       (const uint8_t *) in3, inlen);
}

void
ossl_sha3_shake256_x4_inc_cleanup_avx2(KECCAK1600_X4_CTX *ctx)
{
        OPENSSL_cleanse(ctx, sizeof(*ctx));
}

static void
ossl_sha3_shake256_x4_inc_finalize_avx2(KECCAK1600_X4_CTX *ctx)
{
        if (ctx->finalized)
                return;

        finalize_x4_avx2(ctx);
        ctx->finalized = 1;
}

void
ossl_sha3_shake256_x4_inc_squeeze_avx2(void *out0, void *out1, void *out2, void *out3,
                                       size_t outlen, KECCAK1600_X4_CTX *ctx)
{
        if (!ctx->finalized)
                ossl_sha3_shake256_x4_inc_finalize_avx2(ctx);

        squeeze_x4_avx2(ctx, (uint8_t *) out0, (uint8_t *) out1, (uint8_t *) out2, (uint8_t *) out3,
                        outlen);
}

/* ------------------------------------------------------------------ */
/* One-shot wrappers                                                    */
/* ------------------------------------------------------------------ */

void
ossl_sha3_shake128_x4_avx2(void *out0, void *out1, void *out2, void *out3, size_t outlen,
                           const void *in0, const void *in1, const void *in2, const void *in3,
                           size_t inlen)
{
        KECCAK1600_X4_CTX ctx;

        ossl_sha3_shake128_x4_inc_init_avx2(&ctx);
        ossl_sha3_shake128_x4_inc_absorb_avx2(&ctx, in0, in1, in2, in3, inlen);
        ossl_sha3_shake128_x4_inc_squeeze_avx2(out0, out1, out2, out3, outlen, &ctx);
        ossl_sha3_shake128_x4_inc_cleanup_avx2(&ctx);
}

void
ossl_sha3_shake256_x4_avx2(void *out0, void *out1, void *out2, void *out3, size_t outlen,
                           const void *in0, const void *in1, const void *in2, const void *in3,
                           size_t inlen)
{
        KECCAK1600_X4_CTX ctx;

        ossl_sha3_shake256_x4_inc_init_avx2(&ctx);
        ossl_sha3_shake256_x4_inc_absorb_avx2(&ctx, in0, in1, in2, in3, inlen);
        ossl_sha3_shake256_x4_inc_squeeze_avx2(out0, out1, out2, out3, outlen, &ctx);
        ossl_sha3_shake256_x4_inc_cleanup_avx2(&ctx);
}
