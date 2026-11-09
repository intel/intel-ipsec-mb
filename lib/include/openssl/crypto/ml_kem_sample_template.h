/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Generic x4-SHAKE ML-KEM sampling template.
 *
 * NOT a self-contained header - include it at the bottom of an
 * arch-specific .c file after defining:
 *
 *   ML_KEM_X4_CTX                       x4 Keccak context type
 *
 *   ML_KEM_SHA3_SHAKE128_X4_INC_INIT    \
 *   ML_KEM_SHA3_SHAKE128_X4_INC_ABSORB   \
 *   ML_KEM_SHA3_SHAKE128_X4_INC_SQUEEZE  / x4 SHAKE-128 incremental API
 *   ML_KEM_SHA3_SHAKE128_X4_INC_CLEANUP /
 *
 *   ML_KEM_SHA3_SHAKE256_X4             one-shot x4 SHAKE-256
 *
 *   ML_KEM_SAMPLE_NTT_X4                static helper name (unique within the TU)
 *
 *   ML_KEM_MATRIX_EXPAND               \ static sampling function names
 *   ML_KEM_GENCBD                      /
 *
 *   ML_KEM_SAMPLE_INIT_FN               exported ossl_ml_kem_sample_init_* name
 *
 * See ml_kem_sample_hw_x86_64_avx512.c and ml_kem_sample_hw_x86_64_avx2.c
 * for example instantiations. Both use the AVX2 rejection sampling and
 * SamplePolyCBD kernels.
 */

#define ML_KEM_X4_LANES              4
#define ML_KEM_SHAKE128_X4_BLOCKSIZE SHA3_BLOCKSIZE(128)
#define ML_KEM_SHAKE_X4_DONE_MASK    ((1u << ML_KEM_X4_LANES) - 1)

/*
 * SampleNTT of up to four polynomials at once: the four SHAKE128 streams are
 * squeezed in parallel with the x4 Keccak and each of the first count lanes
 * is consumed by the AVX2 rejection sampler until its polynomial is complete.
 */
static void
ML_KEM_SAMPLE_NTT_X4(struct ossl_ml_kem_scalar_st *out[ML_KEM_X4_LANES],
                     const uint8_t *seeds[ML_KEM_X4_LANES], const unsigned count)
{
        ML_KEM_X4_CTX ctx;
        uint8_t blocks[ML_KEM_X4_LANES][ML_KEM_SHAKE128_X4_BLOCKSIZE];
        uint32_t n[ML_KEM_X4_LANES] = { 0, 0, 0, 0 };
        unsigned done = ML_KEM_SHAKE_X4_DONE_MASK & ~((1u << count) - 1), lane;

        ML_KEM_SHA3_SHAKE128_X4_INC_INIT(&ctx);
        ML_KEM_SHA3_SHAKE128_X4_INC_ABSORB(&ctx, seeds[0], seeds[1], seeds[2], seeds[3],
                                           ML_KEM_RANDOM_BYTES + 2);

        while (done != ML_KEM_SHAKE_X4_DONE_MASK) {
                ML_KEM_SHA3_SHAKE128_X4_INC_SQUEEZE(blocks[0], blocks[1], blocks[2], blocks[3],
                                                    sizeof(blocks[0]), &ctx);

                for (lane = 0; lane < ML_KEM_X4_LANES; lane++) {
                        if (done & (1u << lane))
                                continue;

                        n[lane] += ml_kem_rej_uniform_block_avx2(
                                out[lane]->c + n[lane], ML_KEM_DEGREE - n[lane], blocks[lane]);

                        if (n[lane] >= ML_KEM_DEGREE)
                                done |= 1u << lane;
                }
        }

        ML_KEM_SHA3_SHAKE128_X4_INC_CLEANUP(&ctx);
}

/*
 * Expands the public matrix from key->rho, four polynomials at a time.
 * Matrix entry k is sampled from rho || k / rank || k % rank, matching the
 * scalar expansion order.
 */
static int
ML_KEM_MATRIX_EXPAND(const IMB_ML_KEM *self, EVP_MD_CTX *mdctx, ML_KEM_KEY *key)
{
        uint8_t input[ML_KEM_X4_LANES][ML_KEM_RANDOM_BYTES + 2];
        const uint8_t *seeds[ML_KEM_X4_LANES];
        struct ossl_ml_kem_scalar_st *outs[ML_KEM_X4_LANES];
        const unsigned rank = (unsigned) key->vinfo->rank;
        const unsigned total = rank * rank;
        unsigned k, b, count;

        (void) self;
        (void) mdctx;

        for (b = 0; b < ML_KEM_X4_LANES; b++) {
                memcpy(input[b], key->rho, ML_KEM_RANDOM_BYTES);
                seeds[b] = input[b];
                outs[b] = key->m;
        }

        for (k = 0; k < total; k += count) {
                count = total - k < ML_KEM_X4_LANES ? total - k : ML_KEM_X4_LANES;

                for (b = 0; b < count; b++) {
                        input[b][ML_KEM_RANDOM_BYTES] = (uint8_t) ((k + b) / rank);
                        input[b][ML_KEM_RANDOM_BYTES + 1] = (uint8_t) ((k + b) % rank);
                        outs[b] = key->m + k + b;
                }

                ML_KEM_SAMPLE_NTT_X4(outs, seeds, count);
        }

        return 1;
}

/*
 * Samples out[i] with SamplePolyCBD from PRF(seed, i), using eta1 for the
 * first n1 polynomials and eta2 for the rest, four PRF calls at a time.
 */
static int
ML_KEM_GENCBD(const IMB_ML_KEM *self, struct ossl_ml_kem_scalar_st *const out[], const int n,
              const int n1, const int eta1, const int eta2, const uint8_t *seed, EVP_MD_CTX *mdctx,
              const ML_KEM_KEY *key)
{
        uint8_t input[ML_KEM_X4_LANES][ML_KEM_RANDOM_BYTES + 1];
        uint8_t randbuf[ML_KEM_X4_LANES][6 * ML_KEM_DEGREE / 8]; /* 64 * max(eta) slots */
        int i, b, count, eta;

        (void) self;
        (void) mdctx;
        (void) key;

        for (b = 0; b < ML_KEM_X4_LANES; b++)
                memcpy(input[b], seed, ML_KEM_RANDOM_BYTES);

        for (i = 0; i < n; i += count) {
                count = n - i < ML_KEM_X4_LANES ? n - i : ML_KEM_X4_LANES;

                for (b = 0; b < count; b++)
                        input[b][ML_KEM_RANDOM_BYTES] = (uint8_t) (i + b);

                /*
                 * A shorter SHAKE256 output is a prefix of a longer one, so the
                 * largest eta in the batch covers a batch spanning both
                 */
                eta = i < n1 ? eta1 : eta2;
                if (i + count > n1 && eta2 > eta)
                        eta = eta2;
                ML_KEM_SHA3_SHAKE256_X4(randbuf[0], randbuf[1], randbuf[2], randbuf[3], 64 * eta,
                                        input[0], input[1], input[2], input[3], sizeof(input[0]));

                for (b = 0; b < count; b++) {
                        if ((i + b < n1 ? eta1 : eta2) == 3)
                                ml_kem_poly_cbd3_avx2(out[i + b], randbuf[b]);
                        else
                                ml_kem_poly_cbd2_avx2(out[i + b], randbuf[b]);
                }
        }

        OPENSSL_cleanse(input, sizeof(input));
        OPENSSL_cleanse(randbuf, sizeof(randbuf));
        return 1;
}

void
ML_KEM_SAMPLE_INIT_FN(IMB_ML_KEM *self)
{
        self->matrix_expand = ML_KEM_MATRIX_EXPAND;
        self->gencbd = ML_KEM_GENCBD;
}
