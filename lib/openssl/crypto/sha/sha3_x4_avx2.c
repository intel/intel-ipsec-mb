/*
 * Copyright (c) 2026 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * SHAKE x4 AVX2 — C implementation over the AVX2 keccak_f1600_x4_avx2 kernel.
 *
 * State: A[w*4 + lane] for w in 0..24, lane in 0..3 (interleaved 4-lane).
 * A[100]: absorb = bytes consumed in block (0..rate-1);
 *         squeeze = bytes remaining in block (0..rate).
 */

#include "openssl_compat.h"
#include "internal/sha3.h"
#include <stdint.h>

/* Unaligned 64-bit load alias — avoids memcpy while remaining alias-safe. */
typedef uint64_t u64_alias __attribute__((__may_alias__));

/* AVX2 Keccak-f[1600] x4 permutation (sha3_mb_avx2.asm). */
extern void keccak_f1600_x4_avx2(uint64_t *state);

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/* Absorb n bytes one at a time; used for unaligned head and tail. */
static size_t
absorb_bytes_x4(uint64_t *A, size_t rate, size_t pos,
                const uint8_t *in0, const uint8_t *in1,
                const uint8_t *in2, const uint8_t *in3,
                size_t n)
{
        while (n-- > 0) {
                const size_t word  = pos >> 3;
                const size_t shift = (pos & 7) << 3;

                A[word * 4 + 0] ^= (uint64_t)*in0++ << shift;
                A[word * 4 + 1] ^= (uint64_t)*in1++ << shift;
                A[word * 4 + 2] ^= (uint64_t)*in2++ << shift;
                A[word * 4 + 3] ^= (uint64_t)*in3++ << shift;

                if (++pos == rate) {
                        keccak_f1600_x4_avx2(A);
                        pos = 0;
                }
        }
        return pos;
}

/* Absorb inlen bytes from four inputs: byte head, word body, byte tail. */
static size_t
absorb_x4_avx2(uint64_t *A, size_t rate, size_t pos,
               const uint8_t *in0, const uint8_t *in1,
               const uint8_t *in2, const uint8_t *in3,
               size_t inlen)
{
        /* Head: align pos to a word boundary */
        if ((pos & 7) != 0 && inlen > 0) {
                size_t head = 8 - (pos & 7);

                if (head > inlen)
                        head = inlen;
                pos    = absorb_bytes_x4(A, rate, pos, in0, in1, in2, in3, head);
                in0   += head;
                in1   += head;
                in2   += head;
                in3   += head;
                inlen -= head;
        }

        /* Body: one word at a time */
        while (inlen >= 8) {
                const size_t word = pos >> 3;

                A[word * 4 + 0] ^= *(const u64_alias *)in0;
                A[word * 4 + 1] ^= *(const u64_alias *)in1;
                A[word * 4 + 2] ^= *(const u64_alias *)in2;
                A[word * 4 + 3] ^= *(const u64_alias *)in3;
                in0   += 8;
                in1   += 8;
                in2   += 8;
                in3   += 8;
                inlen -= 8;
                pos   += 8;

                if (pos == rate) {
                        keccak_f1600_x4_avx2(A);
                        pos = 0;
                }
        }

        /* Tail */
        if (inlen > 0)
                pos = absorb_bytes_x4(A, rate, pos, in0, in1, in2, in3, inlen);

        return pos;
}

/* Apply SHAKE padding (0x1F / 0x80) to all four lanes and permute. */
static void
finalize_x4_avx2(uint64_t *A, size_t rate, size_t pos)
{
        size_t word     = pos >> 3;
        size_t shift    = (pos & 7) << 3;
        size_t end_word = (rate >> 3) - 1;   /* last word in rate block */

        A[word * 4 + 0] ^= UINT64_C(0x1F) << shift;  /* SHAKE domain */
        A[word * 4 + 1] ^= UINT64_C(0x1F) << shift;
        A[word * 4 + 2] ^= UINT64_C(0x1F) << shift;
        A[word * 4 + 3] ^= UINT64_C(0x1F) << shift;

        A[end_word * 4 + 0] ^= UINT64_C(0x8000000000000000);  /* terminator */
        A[end_word * 4 + 1] ^= UINT64_C(0x8000000000000000);
        A[end_word * 4 + 2] ^= UINT64_C(0x8000000000000000);
        A[end_word * 4 + 3] ^= UINT64_C(0x8000000000000000);

        keccak_f1600_x4_avx2(A);
        A[100] = (uint64_t)rate;
}

/* Extract outlen bytes from all four lanes; may be called repeatedly. */
static void
squeeze_x4_avx2(uint64_t *A, size_t rate,
                uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
                size_t outlen)
{
        size_t avail = (size_t)A[100];

        while (outlen > 0) {
                size_t todo, done, pos;

                if (avail == 0) {
                        keccak_f1600_x4_avx2(A);
                        avail = rate;
                }

                pos  = rate - avail;
                todo = (avail < outlen) ? avail : outlen;
                done = 0;

                while (done < todo) {
                        size_t cur   = pos + done;
                        size_t word  = cur >> 3;
                        size_t shift = (cur & 7) << 3;

                        if (shift == 0 && (todo - done) >= 8) {
                                memcpy(out0 + done, &A[word * 4 + 0], 8);
                                memcpy(out1 + done, &A[word * 4 + 1], 8);
                                memcpy(out2 + done, &A[word * 4 + 2], 8);
                                memcpy(out3 + done, &A[word * 4 + 3], 8);
                                done += 8;
                        } else {
                                *(out0 + done) = (uint8_t)(A[word * 4 + 0] >> shift);
                                *(out1 + done) = (uint8_t)(A[word * 4 + 1] >> shift);
                                *(out2 + done) = (uint8_t)(A[word * 4 + 2] >> shift);
                                *(out3 + done) = (uint8_t)(A[word * 4 + 3] >> shift);
                                done++;
                        }
                }

                out0   += todo;
                out1   += todo;
                out2   += todo;
                out3   += todo;
                outlen -= todo;
                avail  -= todo;
        }

        A[100] = (uint64_t)avail;
}

/* ------------------------------------------------------------------ */
/* SHAKE-128 x4                                                         */
/* ------------------------------------------------------------------ */

void
ossl_sha3_shake128_x4_inc_init_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
        memset(ctx->A, 0, sizeof(ctx->A));
        ctx->rate      = SHA3_BLOCKSIZE(128);
        ctx->finalized = 0;
}

void
ossl_sha3_shake128_x4_inc_absorb_avx2(KECCAK1600_X4_AVX2_CTX *ctx,
                                      const void *in0, const void *in1,
                                      const void *in2, const void *in3,
                                      size_t inlen)
{
        if (ctx->finalized)
                return; /* error: cannot absorb after finalize */

        ctx->A[100] = (uint64_t)absorb_x4_avx2(ctx->A, ctx->rate,
                                                (size_t)ctx->A[100],
                                                (const uint8_t *)in0,
                                                (const uint8_t *)in1,
                                                (const uint8_t *)in2,
                                                (const uint8_t *)in3,
                                                inlen);
}

void
ossl_sha3_shake128_x4_inc_cleanup_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
        OPENSSL_cleanse(ctx, sizeof(*ctx));
}

static void
ossl_sha3_shake128_x4_inc_finalize_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
        if (ctx->finalized)
                return;

        finalize_x4_avx2(ctx->A, ctx->rate, (size_t)ctx->A[100]);
        ctx->finalized = 1;
}

void
ossl_sha3_shake128_x4_inc_squeeze_avx2(void *out0, void *out1,
                                       void *out2, void *out3,
                                       size_t outlen,
                                       KECCAK1600_X4_AVX2_CTX *ctx)
{
        if (!ctx->finalized)
                ossl_sha3_shake128_x4_inc_finalize_avx2(ctx);

        squeeze_x4_avx2(ctx->A, ctx->rate,
                        (uint8_t *)out0, (uint8_t *)out1,
                        (uint8_t *)out2, (uint8_t *)out3,
                        outlen);
}

/* ------------------------------------------------------------------ */
/* SHAKE-256 x4                                                         */
/* ------------------------------------------------------------------ */

void
ossl_sha3_shake256_x4_inc_init_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
        memset(ctx->A, 0, sizeof(ctx->A));
        ctx->rate      = SHA3_BLOCKSIZE(256);
        ctx->finalized = 0;
}

void
ossl_sha3_shake256_x4_inc_absorb_avx2(KECCAK1600_X4_AVX2_CTX *ctx,
                                      const void *in0, const void *in1,
                                      const void *in2, const void *in3,
                                      size_t inlen)
{
        if (ctx->finalized)
                return; /* error: cannot absorb after finalize */

        ctx->A[100] = (uint64_t)absorb_x4_avx2(ctx->A, ctx->rate,
                                                (size_t)ctx->A[100],
                                                (const uint8_t *)in0,
                                                (const uint8_t *)in1,
                                                (const uint8_t *)in2,
                                                (const uint8_t *)in3,
                                                inlen);
}

void
ossl_sha3_shake256_x4_inc_cleanup_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
        OPENSSL_cleanse(ctx, sizeof(*ctx));
}

static void
ossl_sha3_shake256_x4_inc_finalize_avx2(KECCAK1600_X4_AVX2_CTX *ctx)
{
        if (ctx->finalized)
                return;

        finalize_x4_avx2(ctx->A, ctx->rate, (size_t)ctx->A[100]);
        ctx->finalized = 1;
}

void
ossl_sha3_shake256_x4_inc_squeeze_avx2(void *out0, void *out1,
                                       void *out2, void *out3,
                                       size_t outlen,
                                       KECCAK1600_X4_AVX2_CTX *ctx)
{
        if (!ctx->finalized)
                ossl_sha3_shake256_x4_inc_finalize_avx2(ctx);

        squeeze_x4_avx2(ctx->A, ctx->rate,
                        (uint8_t *)out0, (uint8_t *)out1,
                        (uint8_t *)out2, (uint8_t *)out3,
                        outlen);
}

/* ------------------------------------------------------------------ */
/* One-shot wrappers                                                    */
/* ------------------------------------------------------------------ */

void
ossl_sha3_shake128_x4_avx2(void *out0, void *out1, void *out2, void *out3,
                            size_t outlen,
                            const void *in0, const void *in1,
                            const void *in2, const void *in3,
                            size_t inlen)
{
        KECCAK1600_X4_AVX2_CTX ctx;

        ossl_sha3_shake128_x4_inc_init_avx2(&ctx);
        ossl_sha3_shake128_x4_inc_absorb_avx2(&ctx, in0, in1, in2, in3, inlen);
        ossl_sha3_shake128_x4_inc_squeeze_avx2(out0, out1, out2, out3, outlen, &ctx);
        ossl_sha3_shake128_x4_inc_cleanup_avx2(&ctx);
}

void
ossl_sha3_shake256_x4_avx2(void *out0, void *out1, void *out2, void *out3,
                            size_t outlen,
                            const void *in0, const void *in1,
                            const void *in2, const void *in3,
                            size_t inlen)
{
        KECCAK1600_X4_AVX2_CTX ctx;

        ossl_sha3_shake256_x4_inc_init_avx2(&ctx);
        ossl_sha3_shake256_x4_inc_absorb_avx2(&ctx, in0, in1, in2, in3, inlen);
        ossl_sha3_shake256_x4_inc_squeeze_avx2(out0, out1, out2, out3, outlen, &ctx);
        ossl_sha3_shake256_x4_inc_cleanup_avx2(&ctx);
}
