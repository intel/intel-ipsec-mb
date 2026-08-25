/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* ML-DSA (FIPS 204) known-answer tests loaded from JSON vector files. */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "vector_utils.h"
#include "sig_test.h"
#include <ml_dsa/ml_dsa_internal_api.h>

int
ml_dsa_test(struct IMB_MGR *mb_mgr);

#define ML_DSA_MAX_PUBKEY  IMB_ML_DSA_87_PUBKEY_BYTES
#define ML_DSA_MAX_PRIVKEY IMB_ML_DSA_87_PRIVKEY_BYTES
#define ML_DSA_MAX_SIG     IMB_ML_DSA_87_SIG_BYTES
#define ML_DSA_SEED_BYTES  32
#define ML_DSA_RND_BYTES   32
#define ML_DSA_MAX_MSG     8192
#define ML_DSA_MAX_CTX     256
#define ML_DSA_MAX_MPRIME  (2 + ML_DSA_MAX_CTX + ML_DSA_MAX_MSG)
#define ML_DSA_MU_BYTES    64

struct ml_dsa_variant {
        IMB_ML_DSA_ALG alg;
        const char *name;
        const char *sign_seed_file;
        const char *sign_noseed_file;
        const char *verify_file;
};

static const struct ml_dsa_variant variants[] = {
        { IMB_ML_DSA_44, "ML-DSA-44", "mldsa_44_sign_seed_test.json",
          "mldsa_44_sign_noseed_test.json", "mldsa_44_verify_test.json" },
        { IMB_ML_DSA_65, "ML-DSA-65", "mldsa_65_sign_seed_test.json",
          "mldsa_65_sign_noseed_test.json", "mldsa_65_verify_test.json" },
        { IMB_ML_DSA_87, "ML-DSA-87", "mldsa_87_sign_seed_test.json",
          "mldsa_87_sign_noseed_test.json", "mldsa_87_verify_test.json" },
};

static uint8_t buf_pk[ML_DSA_MAX_PUBKEY];
static uint8_t buf_sk[ML_DSA_MAX_PRIVKEY];
static uint8_t buf_sig[ML_DSA_MAX_SIG];
static uint8_t exp_pk[ML_DSA_MAX_PUBKEY];
static uint8_t exp_sig[ML_DSA_MAX_SIG];
static uint8_t buf_mprime[ML_DSA_MAX_MPRIME];
static uint8_t alt_pk[ML_DSA_MAX_PUBKEY];
static uint8_t alt_sk[ML_DSA_MAX_PRIVKEY];
static uint8_t alt_sig[ML_DSA_MAX_SIG];
static const uint8_t zero_rnd[ML_DSA_RND_BYTES] = { 0 };

static const char *
ml_dsa_alg_name(const IMB_ML_DSA_ALG alg)
{
        switch (alg) {
        case IMB_ML_DSA_44:
                return "ML-DSA-44";
        case IMB_ML_DSA_65:
                return "ML-DSA-65";
        case IMB_ML_DSA_87:
                return "ML-DSA-87";
        default:
                return "ML-DSA-?";
        }
}

static int
ml_dsa_alg_sizes(const IMB_ML_DSA_ALG alg, size_t *pk_bytes, size_t *sk_bytes, size_t *sig_bytes)
{
        switch (alg) {
        case IMB_ML_DSA_44:
                *pk_bytes = IMB_ML_DSA_44_PUBKEY_BYTES;
                *sk_bytes = IMB_ML_DSA_44_PRIVKEY_BYTES;
                *sig_bytes = IMB_ML_DSA_44_SIG_BYTES;
                return 0;
        case IMB_ML_DSA_65:
                *pk_bytes = IMB_ML_DSA_65_PUBKEY_BYTES;
                *sk_bytes = IMB_ML_DSA_65_PRIVKEY_BYTES;
                *sig_bytes = IMB_ML_DSA_65_SIG_BYTES;
                return 0;
        case IMB_ML_DSA_87:
                *pk_bytes = IMB_ML_DSA_87_PUBKEY_BYTES;
                *sk_bytes = IMB_ML_DSA_87_PRIVKEY_BYTES;
                *sig_bytes = IMB_ML_DSA_87_SIG_BYTES;
                return 0;
        default:
                return -1;
        }
}

static struct test_suite_context *
ml_dsa_ctx_for_alg(const IMB_ML_DSA_ALG alg, struct test_suite_context ctxs[3])
{
        switch (alg) {
        case IMB_ML_DSA_44:
                return &ctxs[0];
        case IMB_ML_DSA_65:
                return &ctxs[1];
        default:
                return &ctxs[2];
        }
}

static int
ml_dsa_build_mprime(const void *msg, const size_t msg_len, const void *ctx, const size_t ctx_len,
                    size_t *mprime_len)
{
        if (ctx_len > 255 || (2 + ctx_len + msg_len) > sizeof(buf_mprime))
                return -1;

        buf_mprime[0] = 0x00;
        buf_mprime[1] = (uint8_t) ctx_len;
        if (ctx_len != 0 && ctx != NULL)
                memcpy(&buf_mprime[2], ctx, ctx_len);
        if (msg_len != 0 && msg != NULL)
                memcpy(&buf_mprime[2 + ctx_len], msg, msg_len);
        *mprime_len = 2 + ctx_len + msg_len;

        return 0;
}

static int
ml_dsa_check_internal_sign(IMB_ML_DSA *self, const IMB_ML_DSA_ALG alg, const size_t tcId,
                           const void *msg, const size_t msg_len, const void *ctx,
                           const size_t ctx_len, const void *rnd_ptr, const void *expected_sig,
                           const size_t expected_sig_len, const int expect_valid)
{
        size_t sig_len = sizeof(exp_sig);
        size_t mprime_len = 0;
        int rc;

        if (ctx_len > 255)
                return 0;
        if (ml_dsa_build_mprime(msg, msg_len, ctx, ctx_len, &mprime_len) < 0) {
                printf("ML-DSA Sign_internal M' construction failed (%s tcId=%zu)\n",
                       ml_dsa_alg_name(alg), tcId);
                return 1;
        }

        rc = imb_ml_dsa_sign_internal(self, exp_sig, &sig_len, buf_mprime, mprime_len, rnd_ptr,
                                      ML_DSA_RND_BYTES);
        if (expect_valid) {
                if (rc == 0 && sig_len == expected_sig_len &&
                    memcmp(exp_sig, expected_sig, sig_len) == 0)
                        return 0;

                printf("ML-DSA Sign_internal mismatch (%s tcId=%zu rc=%d sig_len=%zu exp=%zu)\n",
                       ml_dsa_alg_name(alg), tcId, rc, sig_len, expected_sig_len);
                return 1;
        }

        if (rc != 0)
                return 0;

        printf("ML-DSA Sign_internal unexpectedly succeeded (%s tcId=%zu)\n", ml_dsa_alg_name(alg),
               tcId);
        return 1;
}

static int
ml_dsa_check_internal_verify(IMB_ML_DSA *self, const IMB_ML_DSA_ALG alg, const size_t tcId,
                             const void *msg, const size_t msg_len, const void *ctx,
                             const size_t ctx_len, const void *sig, const size_t sig_len,
                             const int external_rc)
{
        size_t mprime_len = 0;
        int internal_rc;

        if (ctx_len > 255)
                return 0;
        if (ml_dsa_build_mprime(msg, msg_len, ctx, ctx_len, &mprime_len) < 0) {
                printf("ML-DSA Verify_internal M' construction failed (%s tcId=%zu)\n",
                       ml_dsa_alg_name(alg), tcId);
                return 1;
        }

        internal_rc = imb_ml_dsa_verify_internal(self, buf_mprime, mprime_len, sig, sig_len);
        if ((external_rc == 0) == (internal_rc == 0))
                return 0;

        printf("ML-DSA Verify_internal verdict mismatch (%s tcId=%zu ext_rc=%d int_rc=%d)\n",
               ml_dsa_alg_name(alg), tcId, external_rc, internal_rc);
        return 1;
}

static int
ml_dsa_sign_seed_vector(struct IMB_MGR *mb_mgr, const IMB_ML_DSA_ALG alg,
                        const struct sig_sign_test *v)
{
        size_t pk_bytes = 0, sk_bytes = 0, sig_bytes = 0;
        const void *ctx_ptr = NULL;
        /*
         * A vector without an explicit "rnd" field is a deterministic test
         * case (implied all-zero randomizer); default to zero_rnd rather
         * than NULL since imb_ml_dsa_sign()'s NULL means auto-random.
         */
        const void *rnd_ptr = zero_rnd;
        IMB_ML_DSA *self = NULL;
        size_t sig_len = 0;
        int rc;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;
        if (v->msgLen > ML_DSA_MAX_MSG || v->ctxLen > ML_DSA_MAX_CTX)
                return 1;
        if (v->resultValid && v->privateSeedLen != ML_DSA_SEED_BYTES)
                return 1;
        if (v->hasRnd) {
                if (v->rndLen != ML_DSA_RND_BYTES)
                        return 1;
                rnd_ptr = v->rnd;
        }
        if (v->hasCtx)
                ctx_ptr = v->ctx;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        IMB_ML_DSA_KEYGEN_PARAMS keygen_params;

        IMB_ML_DSA_KEYGEN_PARAMS_INIT(&keygen_params);
        /*
         * A NULL seed asks the library for a random one, so a vector
         * carrying an empty seed is handed over as a non-NULL buffer.
         */
        keygen_params.xi_32 =
                (v->privateSeed != NULL) ? (const void *) v->privateSeed : (const void *) zero_rnd;
        keygen_params.xi_len = v->privateSeedLen;
        rc = imb_ml_dsa_keypair(self, buf_pk, sizeof(buf_pk), buf_sk, sizeof(buf_sk),
                                &keygen_params);
        if (!v->resultValid && rc != 0) {
                /* the key generation seed was rejected, as expected */
                ret = 0;
                goto exit;
        }
        if (rc != 0 || (v->publicKey != NULL && memcmp(buf_pk, v->publicKey, pk_bytes) != 0)) {
                printf("ML-DSA keyGen KAT mismatch (%s tcId=%zu rc=%d)\n", ml_dsa_alg_name(alg),
                       v->tcId, rc);
                goto exit;
        }

        if (v->msg != NULL) {
                IMB_ML_DSA_SIGN_PARAMS sign_params;

                IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);

                sign_params.ctx = ctx_ptr;
                sign_params.ctx_len = v->ctxLen;
                sign_params.rnd_32 = rnd_ptr;
                sign_params.rnd_len = ML_DSA_RND_BYTES;
                sig_len = sizeof(buf_sig);
                rc = imb_ml_dsa_sign(self, buf_sig, &sig_len, v->msg, v->msgLen, &sign_params);
        }
        if (v->resultValid) {
                IMB_ML_DSA_VERIFY_PARAMS verify_params;

                IMB_ML_DSA_VERIFY_PARAMS_INIT(&verify_params);

                if (v->msg != NULL) {
                        if (v->sigLen != sig_bytes || rc != 0 || sig_len != sig_bytes ||
                            memcmp(buf_sig, v->sig, sig_bytes) != 0) {
                                printf("ML-DSA sigGen KAT mismatch (%s tcId=%zu rc=%d sig_len=%zu "
                                       "exp=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId, rc, sig_len, v->sigLen);
                                goto exit;
                        }
                        verify_params.ctx = ctx_ptr;
                        verify_params.ctx_len = v->ctxLen;
                        if (imb_ml_dsa_verify(self, v->msg, v->msgLen, buf_sig, sig_len,
                                              &verify_params) != 0) {
                                printf("ML-DSA sigGen verify failed (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        if (ml_dsa_check_internal_sign(self, alg, v->tcId, v->msg, v->msgLen,
                                                       ctx_ptr, v->ctxLen, rnd_ptr, v->sig,
                                                       v->sigLen, 1) != 0)
                                goto exit;
                }

                /* msg_is_mu path: sign pre-computed mu directly, expect same sig */
                if (v->hasMu) {
                        IMB_ML_DSA_SIGN_PARAMS mu_params;
                        IMB_ML_DSA_VERIFY_PARAMS mu_verify_params;
                        size_t mu_sig_len = sizeof(buf_sig);

                        IMB_ML_DSA_SIGN_PARAMS_INIT(&mu_params);
                        IMB_ML_DSA_VERIFY_PARAMS_INIT(&mu_verify_params);

                        if (v->muLen != ML_DSA_MU_BYTES) {
                                printf("ML-DSA sigGen mu wrong length (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        mu_params.rnd_32 = rnd_ptr;
                        mu_params.rnd_len = ML_DSA_RND_BYTES;
                        mu_params.msg_is_mu = 1;
                        if (v->sigLen != sig_bytes) {
                                printf("ML-DSA sigGen mu sig wrong length (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        if (imb_ml_dsa_sign(self, buf_sig, &mu_sig_len, v->mu, v->muLen,
                                            &mu_params) != 0 ||
                            mu_sig_len != sig_bytes || memcmp(buf_sig, v->sig, sig_bytes) != 0) {
                                printf("ML-DSA sigGen msg_is_mu mismatch (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        mu_verify_params.msg_is_mu = 1;
                        if (imb_ml_dsa_verify(self, v->mu, v->muLen, buf_sig, mu_sig_len,
                                              &mu_verify_params) != 0) {
                                printf("ML-DSA sigGen msg_is_mu verify failed (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                }
        } else {
                if (v->msg != NULL && rc == 0) {
                        printf("ML-DSA sigGen unexpectedly succeeded (%s tcId=%zu)\n",
                               ml_dsa_alg_name(alg), v->tcId);
                        goto exit;
                }
                if (v->msg != NULL &&
                    ml_dsa_check_internal_sign(self, alg, v->tcId, v->msg, v->msgLen, ctx_ptr,
                                               v->ctxLen, rnd_ptr, v->sig, v->sigLen, 0) != 0)
                        goto exit;
        }

        ret = 0;
exit:
        imb_ml_dsa_free(self);
        return ret;
}

static int
ml_dsa_sign_noseed_vector(struct IMB_MGR *mb_mgr, const IMB_ML_DSA_ALG alg,
                          const struct sig_sign_test *v)
{
        size_t pk_bytes = 0, sk_bytes = 0, sig_bytes = 0;
        const void *ctx_ptr = NULL;
        /*
         * A vector without an explicit "rnd" field is a deterministic test
         * case (implied all-zero randomizer); default to zero_rnd rather
         * than NULL since imb_ml_dsa_sign()'s NULL means auto-random.
         */
        const void *rnd_ptr = zero_rnd;
        IMB_ML_DSA *self = NULL;
        size_t sig_len = 0;
        int set_rc;
        int rc = -1;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;
        if (v->msgLen > ML_DSA_MAX_MSG || v->ctxLen > ML_DSA_MAX_CTX)
                return 1;
        if (v->resultValid && v->privateKeyLen != sk_bytes)
                return 1;
        if (v->hasRnd) {
                if (v->rndLen != ML_DSA_RND_BYTES)
                        return 1;
                rnd_ptr = v->rnd;
        }
        if (v->hasCtx)
                ctx_ptr = v->ctx;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        set_rc = imb_ml_dsa_set_privkey(self, v->privateKey, v->privateKeyLen);
        if (set_rc == 0 && v->msg != NULL) {
                IMB_ML_DSA_SIGN_PARAMS sign_params;

                IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);

                sign_params.ctx = ctx_ptr;
                sign_params.ctx_len = v->ctxLen;
                sign_params.rnd_32 = rnd_ptr;
                sign_params.rnd_len = ML_DSA_RND_BYTES;
                sig_len = sizeof(buf_sig);
                rc = imb_ml_dsa_sign(self, buf_sig, &sig_len, v->msg, v->msgLen, &sign_params);
        }

        if (v->resultValid) {
                IMB_ML_DSA_VERIFY_PARAMS verify_params;

                IMB_ML_DSA_VERIFY_PARAMS_INIT(&verify_params);

                if (v->msg != NULL) {
                        if (set_rc != 0 || v->sigLen != sig_bytes || rc != 0 ||
                            sig_len != sig_bytes || memcmp(buf_sig, v->sig, sig_bytes) != 0) {
                                printf("ML-DSA sigGen KAT mismatch (%s tcId=%zu set_rc=%d rc=%d "
                                       "sig_len=%zu exp=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId, set_rc, rc, sig_len,
                                       v->sigLen);
                                goto exit;
                        }
                        verify_params.ctx = ctx_ptr;
                        verify_params.ctx_len = v->ctxLen;
                        if (imb_ml_dsa_verify(self, v->msg, v->msgLen, buf_sig, sig_len,
                                              &verify_params) != 0) {
                                printf("ML-DSA sigGen verify failed (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        if (ml_dsa_check_internal_sign(self, alg, v->tcId, v->msg, v->msgLen,
                                                       ctx_ptr, v->ctxLen, rnd_ptr, v->sig,
                                                       v->sigLen, 1) != 0)
                                goto exit;
                }

                /* msg_is_mu path: sign pre-computed mu directly, expect same sig */
                if (v->hasMu) {
                        IMB_ML_DSA_SIGN_PARAMS mu_params;
                        IMB_ML_DSA_VERIFY_PARAMS mu_verify_params;
                        size_t mu_sig_len = sizeof(buf_sig);

                        IMB_ML_DSA_SIGN_PARAMS_INIT(&mu_params);
                        IMB_ML_DSA_VERIFY_PARAMS_INIT(&mu_verify_params);

                        if (v->muLen != ML_DSA_MU_BYTES) {
                                printf("ML-DSA sigGen mu wrong length (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        mu_params.rnd_32 = rnd_ptr;
                        mu_params.rnd_len = ML_DSA_RND_BYTES;
                        mu_params.msg_is_mu = 1;
                        if (v->sigLen != sig_bytes) {
                                printf("ML-DSA sigGen mu sig wrong length (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        if (imb_ml_dsa_sign(self, buf_sig, &mu_sig_len, v->mu, v->muLen,
                                            &mu_params) != 0 ||
                            mu_sig_len != sig_bytes || memcmp(buf_sig, v->sig, sig_bytes) != 0) {
                                printf("ML-DSA sigGen msg_is_mu mismatch (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                        mu_verify_params.msg_is_mu = 1;
                        if (imb_ml_dsa_verify(self, v->mu, v->muLen, buf_sig, mu_sig_len,
                                              &mu_verify_params) != 0) {
                                printf("ML-DSA sigGen msg_is_mu verify failed (%s tcId=%zu)\n",
                                       ml_dsa_alg_name(alg), v->tcId);
                                goto exit;
                        }
                }
        } else {
                /*
                 * The vector must be rejected either when the private key is
                 * bound to the context or when the signature is produced.
                 */
                const int validate_rc =
                        imb_ml_dsa_privkey_validate(self, v->privateKey, v->privateKeyLen);

                if ((set_rc == 0) != (validate_rc == 0)) {
                        printf("ML-DSA private key validation inconsistent with key set "
                               "(%s tcId=%zu set_rc=%d validate_rc=%d)\n",
                               ml_dsa_alg_name(alg), v->tcId, set_rc, validate_rc);
                        goto exit;
                }
                if (v->msg != NULL && set_rc == 0 && rc == 0) {
                        printf("ML-DSA sigGen unexpectedly succeeded (%s tcId=%zu)\n",
                               ml_dsa_alg_name(alg), v->tcId);
                        goto exit;
                }
                if (v->msg != NULL &&
                    ml_dsa_check_internal_sign(self, alg, v->tcId, v->msg, v->msgLen, ctx_ptr,
                                               v->ctxLen, rnd_ptr, v->sig, v->sigLen, 0) != 0)
                        goto exit;
        }

        ret = 0;
exit:
        imb_ml_dsa_free(self);
        return ret;
}

static int
ml_dsa_verify_vector(struct IMB_MGR *mb_mgr, const IMB_ML_DSA_ALG alg,
                     const struct sig_verify_test *v)
{
        size_t pk_bytes = 0, sk_bytes = 0, sig_bytes = 0;
        const void *ctx_ptr = NULL;
        IMB_ML_DSA *self = NULL;
        int set_rc;
        int rc;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;
        if (v->msgLen > ML_DSA_MAX_MSG || v->ctxLen > ML_DSA_MAX_CTX)
                return 1;
        if (v->resultValid && v->publicKeyLen != pk_bytes)
                return 1;
        if (v->hasCtx)
                ctx_ptr = v->ctx;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        set_rc = imb_ml_dsa_set_pubkey(self, v->publicKey, v->publicKeyLen);
        if (set_rc == 0) {
                IMB_ML_DSA_VERIFY_PARAMS verify_params;

                IMB_ML_DSA_VERIFY_PARAMS_INIT(&verify_params);

                verify_params.ctx = ctx_ptr;
                verify_params.ctx_len = v->ctxLen;
                rc = imb_ml_dsa_verify(self, v->msg, v->msgLen, v->sig, v->sigLen, &verify_params);
        } else {
                rc = -1;
        }
        if ((rc == 0) != (v->resultValid != 0)) {
                printf("ML-DSA sigVer unexpected result (%s tcId=%zu expect_valid=%d set_rc=%d "
                       "rc=%d)\n",
                       ml_dsa_alg_name(alg), v->tcId, v->resultValid, set_rc, rc);
                goto exit;
        }
        if (ml_dsa_check_internal_verify(self, alg, v->tcId, v->msg, v->msgLen, ctx_ptr, v->ctxLen,
                                         v->sig, v->sigLen, rc) != 0)
                goto exit;

        ret = 0;
exit:
        imb_ml_dsa_free(self);
        return ret;
}

static int
ml_dsa_run_sign_seed_vectors(struct IMB_MGR *mb_mgr, const struct ml_dsa_variant *variant,
                             struct test_suite_context *ctx)
{
        struct sig_sign_test *vectors = NULL;
        struct test_json_alloc_ctx *json_ctx = NULL;
        const struct sig_sign_test *v;
        int ret = -1;

        if (load_sig_sign_vectors(kat_vector_dir, variant->sign_seed_file, &vectors, &json_ctx) <
            0) {
                printf("Failed to load ML-DSA sign-seed vectors (%s)\n", variant->sign_seed_file);
                goto exit;
        }

        for (v = vectors; v->comment != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("ML-DSA sign-seed Test Case %zu (%s)\n", v->tcId, v->comment);
#endif
                if (ml_dsa_sign_seed_vector(mb_mgr, variant->alg, v) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }

        ret = 0;
exit:
        json_free_test_ctx(json_ctx);
        return ret;
}

static int
ml_dsa_run_sign_noseed_vectors(struct IMB_MGR *mb_mgr, const struct ml_dsa_variant *variant,
                               struct test_suite_context *ctx)
{
        struct sig_sign_test *vectors = NULL;
        struct test_json_alloc_ctx *json_ctx = NULL;
        const struct sig_sign_test *v;
        int ret = -1;

        if (load_sig_sign_vectors(kat_vector_dir, variant->sign_noseed_file, &vectors, &json_ctx) <
            0) {
                printf("Failed to load ML-DSA sign-noseed vectors (%s)\n",
                       variant->sign_noseed_file);
                goto exit;
        }

        for (v = vectors; v->comment != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("ML-DSA sign-noseed Test Case %zu (%s)\n", v->tcId, v->comment);
#endif
                if (ml_dsa_sign_noseed_vector(mb_mgr, variant->alg, v) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }

        ret = 0;
exit:
        json_free_test_ctx(json_ctx);
        return ret;
}

static int
ml_dsa_run_verify_vectors(struct IMB_MGR *mb_mgr, const struct ml_dsa_variant *variant,
                          struct test_suite_context *ctx)
{
        struct sig_verify_test *vectors = NULL;
        struct test_json_alloc_ctx *json_ctx = NULL;
        const struct sig_verify_test *v;
        int ret = -1;

        if (load_sig_verify_vectors(kat_vector_dir, variant->verify_file, &vectors, &json_ctx) <
            0) {
                printf("Failed to load ML-DSA verify vectors (%s)\n", variant->verify_file);
                goto exit;
        }

        for (v = vectors; v->comment != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("ML-DSA verify Test Case %zu (%s)\n", v->tcId, v->comment);
#endif
                if (ml_dsa_verify_vector(mb_mgr, variant->alg, v) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }

        ret = 0;
exit:
        json_free_test_ctx(json_ctx);
        return ret;
}

/* Random key-generation, signing and verification round-trip including
 * tamper detection and key-derivation/validation helpers. */
static int
ml_dsa_roundtrip(struct IMB_MGR *mb_mgr, const IMB_ML_DSA_ALG alg)
{
        static const uint8_t msg[] = "intel-ipsec-mb ML-DSA self round-trip message";
        static const uint8_t ctx[] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
        const size_t msg_len = sizeof(msg) - 1;
        const size_t ctx_len = sizeof(ctx);
        size_t pk_bytes = 0, sk_bytes = 0, sig_bytes = 0;
        size_t sig_len = sizeof(buf_sig), sig_len2 = sizeof(exp_sig);
        IMB_ML_DSA *self = NULL;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        /* random key pair and its validation / public-key derivation */
        if (imb_ml_dsa_keypair(self, buf_pk, sizeof(buf_pk), buf_sk, sizeof(buf_sk), NULL) != 0)
                goto exit;
        if (imb_ml_dsa_pubkey_validate(self, buf_pk, pk_bytes) != 0)
                goto exit;
        if (imb_ml_dsa_privkey_validate(self, buf_sk, sk_bytes) != 0)
                goto exit;
        if (imb_ml_dsa_pubkey_from_privkey(self, buf_sk, sk_bytes, exp_pk, sizeof(exp_pk)) != 0 ||
            memcmp(exp_pk, buf_pk, pk_bytes) != 0)
                goto exit;

        /*
         * imb_ml_dsa_keypair() above already bound the generated key (both
         * private and public components) to self, so the sign/verify calls
         * below reuse it directly without any further set_privkey()/
         * set_pubkey() call.
         */

        IMB_ML_DSA_SIGN_PARAMS sign_params;
        IMB_ML_DSA_VERIFY_PARAMS verify_params;

        /* hedged sign with context, then verify */
        IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);
        sign_params.ctx = ctx;
        sign_params.ctx_len = ctx_len;
        sign_params.rnd_32 = NULL;
        sign_params.rnd_len = 0;
        if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, &sign_params) != 0 ||
            sig_len != sig_bytes)
                goto exit;

        IMB_ML_DSA_VERIFY_PARAMS_INIT(&verify_params);
        verify_params.ctx = ctx;
        verify_params.ctx_len = ctx_len;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, &verify_params) != 0)
                goto exit;

        /* tampered signature must be rejected */
        buf_sig[sig_bytes / 2] ^= 0x55;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, &verify_params) == 0)
                goto exit;
        buf_sig[sig_bytes / 2] ^= 0x55;

        /* wrong context must be rejected */
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, NULL) == 0)
                goto exit;

        /* deterministic signing is reproducible (explicit all-zero rnd_32) */
        IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);
        sign_params.ctx = NULL;
        sign_params.ctx_len = 0;
        sign_params.rnd_32 = zero_rnd;
        sign_params.rnd_len = sizeof(zero_rnd);
        sig_len = sizeof(buf_sig);
        if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, &sign_params) != 0)
                goto exit;
        sig_len2 = sizeof(exp_sig);
        if (imb_ml_dsa_sign(self, exp_sig, &sig_len2, msg, msg_len, &sign_params) != 0)
                goto exit;
        if (sig_len != sig_len2 || memcmp(buf_sig, exp_sig, sig_len) != 0)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, NULL) != 0)
                goto exit;

        ret = 0;
exit:
        if (ret != 0)
                printf("ML-DSA round-trip failed (%s)\n", ml_dsa_alg_name(alg));
        imb_ml_dsa_free(self);
        return ret;
}

/*
 * Malformed private-key handling, and the deliberate absence of the same for
 * public keys.
 *
 * An encoded ML-DSA private key is rho || K || tr || s1 || s2 || t0
 * (FIPS 204 Algorithm 24, skEncode), with 32-byte rho, 32-byte K and 64-byte
 * tr, so s1 begins at a fixed offset of 128. Two independent things must
 * cause a decode to fail:
 *
 *   - s1/s2 coefficients are bit-packed in the range [-eta, eta], so a
 *     bit pattern outside that range is not a decodable key. eta is 2 for
 *     ML-DSA-44/87 (3 bits per coefficient, values 0..4) and 4 for ML-DSA-65
 *     (4 bits per coefficient, values 0..8); an all-ones byte run is out of
 *     range for both.
 *   - tr is H(pk), so re-deriving the public key from the private one and
 *     comparing against tr detects a key whose halves do not belong together.
 *
 * By contrast a public key is rho || t1 with t1 bit-packed at 10 bits per
 * coefficient, and every 10-bit value is in range. There is therefore no such
 * thing as an undecodable ML-DSA public key, and validation of a corrupted
 * one must still succeed - what changes is that signatures no longer verify
 * under it. Asserting a failure there would encode a wrong expectation, so
 * the opposite is asserted instead.
 */
static int
ml_dsa_key_negative(struct IMB_MGR *mb_mgr, const IMB_ML_DSA_ALG alg)
{
        const size_t tr_off = 64;  /* rho(32) || K(32) || tr(64) || ... */
        const size_t s1_off = 128; /* first coefficient byte of s1 */
        size_t pk_bytes = 0, sk_bytes = 0, sig_bytes = 0;
        size_t sig_len = sizeof(buf_sig);
        IMB_ML_DSA *self = NULL, *fresh = NULL;
        const char *stage = "setup";
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        if (imb_ml_dsa_keypair(self, buf_pk, sizeof(buf_pk), buf_sk, sizeof(buf_sk), NULL) != 0)
                goto exit;

        /* out-of-range s1 coefficients must not decode */
        stage = "s1 coefficient range check";
        memcpy(alt_sk, buf_sk, sk_bytes);
        memset(&alt_sk[s1_off], 0xff, 8);
        if (imb_ml_dsa_privkey_validate(self, alt_sk, sk_bytes) != IMB_ERR_PQC_KEYOP)
                goto exit;
        if (imb_ml_dsa_new(mb_mgr, alg, &fresh) != 0)
                goto exit;
        if (imb_ml_dsa_set_privkey(fresh, alt_sk, sk_bytes) != IMB_ERR_PQC_KEYOP)
                goto exit;
        imb_ml_dsa_free(fresh);
        fresh = NULL;
        /* the same undecodable key cannot yield a public key either */
        if (imb_ml_dsa_pubkey_from_privkey(self, alt_sk, sk_bytes, alt_pk, sizeof(alt_pk)) !=
            IMB_ERR_PQC_KEYOP)
                goto exit;

        /* tr no longer matching H(pk) must be detected */
        stage = "tr consistency check";
        memcpy(alt_sk, buf_sk, sk_bytes);
        alt_sk[tr_off] ^= 0x01;
        if (imb_ml_dsa_privkey_validate(self, alt_sk, sk_bytes) != IMB_ERR_PQC_KEYOP)
                goto exit;
        if (imb_ml_dsa_new(mb_mgr, alg, &fresh) != 0)
                goto exit;
        if (imb_ml_dsa_set_privkey(fresh, alt_sk, sk_bytes) != IMB_ERR_PQC_KEYOP)
                goto exit;
        imb_ml_dsa_free(fresh);
        fresh = NULL;

        /* corrupting rho changes the derived public key, so tr mismatches too */
        stage = "rho consistency check";
        memcpy(alt_sk, buf_sk, sk_bytes);
        alt_sk[0] ^= 0x01;
        if (imb_ml_dsa_privkey_validate(self, alt_sk, sk_bytes) != IMB_ERR_PQC_KEYOP)
                goto exit;

        /* an untouched copy must still validate */
        stage = "pristine key still valid";
        memcpy(alt_sk, buf_sk, sk_bytes);
        if (imb_ml_dsa_privkey_validate(self, alt_sk, sk_bytes) != 0)
                goto exit;

        /*
         * A corrupted public key remains decodable (see the note above), but
         * must no longer verify a signature made under the real key.
         */
        stage = "corrupted public key stays decodable";
        if (imb_ml_dsa_sign(self, buf_sig, &sig_len, (const uint8_t *) "pk corruption probe", 19,
                            NULL) != 0)
                goto exit;

        memcpy(alt_pk, buf_pk, pk_bytes);
        alt_pk[pk_bytes - 1] ^= 0x01;
        if (imb_ml_dsa_pubkey_validate(self, alt_pk, pk_bytes) != 0)
                goto exit;
        if (imb_ml_dsa_new(mb_mgr, alg, &fresh) != 0)
                goto exit;
        if (imb_ml_dsa_set_pubkey(fresh, alt_pk, pk_bytes) != 0)
                goto exit;

        stage = "corrupted public key rejects signature";
        if (imb_ml_dsa_verify(fresh, (const uint8_t *) "pk corruption probe", 19, buf_sig, sig_len,
                              NULL) != IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;

        ret = 0;
exit:
        if (ret != 0)
                printf("ML-DSA malformed-key test failed (%s, stage: %s)\n", ml_dsa_alg_name(alg),
                       stage);
        imb_ml_dsa_free(fresh);
        imb_ml_dsa_free(self);
        return ret;
}

/*
 * Signature rejection paths.
 *
 * The existing round-trip flips a single byte in the middle of a signature;
 * this widens that to each of the three structurally distinct regions of the
 * FIPS 204 sigEncode output (c~ || z || h), to wrong-length and all-zero
 * signatures, to a modified message, and to a signature presented under a
 * different key. All of these must fail closed.
 */
static int
ml_dsa_sig_negative(struct IMB_MGR *mb_mgr, const IMB_ML_DSA_ALG alg)
{
        static const uint8_t msg[] = "intel-ipsec-mb ML-DSA negative test message";
        const size_t msg_len = sizeof(msg) - 1;
        size_t tamper_off[3];
        size_t pk_bytes = 0, sk_bytes = 0, sig_bytes = 0;
        size_t sig_len = sizeof(buf_sig), i;
        IMB_ML_DSA *self = NULL, *other = NULL;
        const char *stage = "setup";
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;
        if (imb_ml_dsa_keypair(self, buf_pk, sizeof(buf_pk), buf_sk, sizeof(buf_sk), NULL) != 0)
                goto exit;
        if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, NULL) != 0 ||
            sig_len != sig_bytes)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, NULL) != 0)
                goto exit;

        /* c~ (commitment hash), z (response) and h (hint) regions in turn */
        stage = "per-region signature tampering";
        tamper_off[0] = 0;
        tamper_off[1] = sig_bytes / 2;
        tamper_off[2] = sig_bytes - 1;

        for (i = 0; i < DIM(tamper_off); i++) {
                memcpy(alt_sig, buf_sig, sig_bytes);
                alt_sig[tamper_off[i]] ^= 0x01;
                if (imb_ml_dsa_verify(self, msg, msg_len, alt_sig, sig_len, NULL) !=
                    IMB_ERR_PQC_VERIFY_FAILED)
                        goto exit;
        }

        /* wrong signature length */
        stage = "signature length check";
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len - 1, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len + 1, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, 0, NULL) != IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;

        /* an all-zero signature must never verify */
        stage = "all-zero signature";
        memset(alt_sig, 0, sig_bytes);
        if (imb_ml_dsa_verify(self, msg, msg_len, alt_sig, sig_len, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;

        /* a modified message must not verify under a signature for the original */
        stage = "modified message";
        memcpy(buf_mprime, msg, msg_len);
        buf_mprime[msg_len / 2] ^= 0x01;
        if (imb_ml_dsa_verify(self, buf_mprime, msg_len, buf_sig, sig_len, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;
        /* nor a truncated or extended one */
        if (imb_ml_dsa_verify(self, msg, msg_len - 1, buf_sig, sig_len, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;

        /* a signature does not transfer to an unrelated key */
        stage = "cross-key verification";
        if (imb_ml_dsa_new(mb_mgr, alg, &other) != 0)
                goto exit;
        if (imb_ml_dsa_keypair(other, alt_pk, sizeof(alt_pk), alt_sk, sizeof(alt_sk), NULL) != 0)
                goto exit;
        if (imb_ml_dsa_verify(other, msg, msg_len, buf_sig, sig_len, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;
        /* ... and the original key still accepts it, proving the above was
         * caused by the key change alone */
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, NULL) != 0)
                goto exit;

        ret = 0;
exit:
        if (ret != 0)
                printf("ML-DSA signature negative test failed (%s, stage: %s)\n",
                       ml_dsa_alg_name(alg), stage);
        imb_ml_dsa_free(other);
        imb_ml_dsa_free(self);
        return ret;
}

/*
 * Context-string handling, hedged-signing behaviour and key rebinding.
 *
 * FIPS 204 Section 5.2 encodes the pure-signature message as
 * M' = 00 || |ctx| || ctx || M with |ctx| stored in a single byte, so a
 * context of exactly 255 bytes is the largest representable one and must
 * still sign and verify (the rejection of an over-length context is covered
 * by the direct API parameter tests). The context also participates in the
 * signature, so signing and verifying under different contexts must fail.
 *
 * Hedged signing (rnd_32 == NULL) draws fresh randomness per call, so two
 * signatures over identical inputs must differ while both remaining valid -
 * the complement of the determinism check already covered by the round-trip.
 */
static int
ml_dsa_ctx_and_hedging(struct IMB_MGR *mb_mgr, const IMB_ML_DSA_ALG alg)
{
        static const uint8_t msg[] = "intel-ipsec-mb ML-DSA context and hedging test";
        static uint8_t big_ctx[256];
        const size_t msg_len = sizeof(msg) - 1;
        IMB_ML_DSA_SIGN_PARAMS sign_params;
        IMB_ML_DSA_VERIFY_PARAMS verify_params;
        size_t pk_bytes = 0, sk_bytes = 0, sig_bytes = 0;
        size_t sig_len = sizeof(buf_sig), sig_len2 = sizeof(alt_sig), i;
        IMB_ML_DSA *self = NULL, *pub_only = NULL;
        const char *stage = "setup";
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;

        for (i = 0; i < sizeof(big_ctx); i++)
                big_ctx[i] = (uint8_t) i;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;
        if (imb_ml_dsa_keypair(self, buf_pk, sizeof(buf_pk), buf_sk, sizeof(buf_sk), NULL) != 0)
                goto exit;

        /* a 255-byte context is the largest the encoding can represent */
        stage = "maximum length context";
        IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);
        IMB_ML_DSA_VERIFY_PARAMS_INIT(&verify_params);
        sign_params.ctx = big_ctx;
        sign_params.ctx_len = IMB_ML_DSA_MAX_CTX_BYTES;
        verify_params.ctx = big_ctx;
        verify_params.ctx_len = IMB_ML_DSA_MAX_CTX_BYTES;
        if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, &sign_params) != 0)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, &verify_params) != 0)
                goto exit;

        /*
         * *sig_len is [in,out]: an entry capacity below the variant's
         * signature size must be refused rather than overflowing the buffer.
         */
        stage = "signature buffer too small";
        sign_params.ctx = NULL;
        sign_params.ctx_len = 0;
        sig_len2 = sig_bytes - 1;
        if (imb_ml_dsa_sign(self, alt_sig, &sig_len2, msg, msg_len, &sign_params) !=
            IMB_ERR_PQC_BUFFER_SIZE)
                goto exit;
        sig_len2 = 0;
        if (imb_ml_dsa_sign(self, alt_sig, &sig_len2, msg, msg_len, NULL) !=
            IMB_ERR_PQC_BUFFER_SIZE)
                goto exit;

        /* a shorter context must not verify a signature made with the long one */
        stage = "context mismatch";
        verify_params.ctx = big_ctx;
        verify_params.ctx_len = IMB_ML_DSA_MAX_CTX_BYTES - 1;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, &verify_params) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;

        /* an empty message is a valid input */
        stage = "empty message";
        IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);
        sig_len = sizeof(buf_sig);
        if (imb_ml_dsa_sign(self, buf_sig, &sig_len, NULL, 0, &sign_params) != 0)
                goto exit;
        if (imb_ml_dsa_verify(self, NULL, 0, buf_sig, sig_len, NULL) != 0)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;

        /*
         * Hedged signing must not be reproducible, yet must stay verifiable.
         * This is the counterpart to the deterministic (all-zero rnd_32)
         * reproducibility already asserted by the round-trip test.
         */
        stage = "hedged signing varies";
        sign_params.rnd_32 = NULL;
        sign_params.rnd_len = 0;
        sig_len = sizeof(buf_sig);
        if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, &sign_params) != 0)
                goto exit;
        sig_len2 = sizeof(alt_sig);
        if (imb_ml_dsa_sign(self, alt_sig, &sig_len2, msg, msg_len, &sign_params) != 0)
                goto exit;
        if (sig_len != sig_len2 || memcmp(buf_sig, alt_sig, sig_len) == 0)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, NULL) != 0 ||
            imb_ml_dsa_verify(self, msg, msg_len, alt_sig, sig_len2, NULL) != 0)
                goto exit;

        /* a caller-supplied randomizer differing from all-zero changes the
         * signature but keeps it valid */
        stage = "caller supplied randomizer";
        {
                uint8_t rnd[ML_DSA_RND_BYTES];

                memset(rnd, 0xa5, sizeof(rnd));
                sign_params.rnd_32 = zero_rnd;
                sign_params.rnd_len = sizeof(zero_rnd);
                sig_len = sizeof(buf_sig);
                if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, &sign_params) != 0)
                        goto exit;
                sign_params.rnd_32 = rnd;
                sign_params.rnd_len = sizeof(rnd);
                sig_len2 = sizeof(alt_sig);
                if (imb_ml_dsa_sign(self, alt_sig, &sig_len2, msg, msg_len, &sign_params) != 0)
                        goto exit;
                if (memcmp(buf_sig, alt_sig, sig_len) == 0)
                        goto exit;
                if (imb_ml_dsa_verify(self, msg, msg_len, alt_sig, sig_len2, NULL) != 0)
                        goto exit;
        }

        /*
         * A context holding only a public key can verify but not sign. As with
         * ML-KEM, the error is the operation-specific IMB_ERR_PQC_SIGNOP and
         * not IMB_ERR_PQC_NO_KEY, which is reserved for a context with no key
         * bound at all (covered by the direct API parameter tests).
         */
        stage = "verify-only context";
        if (imb_ml_dsa_new(mb_mgr, alg, &pub_only) != 0)
                goto exit;
        if (imb_ml_dsa_set_pubkey(pub_only, buf_pk, pk_bytes) != 0)
                goto exit;
        if (imb_ml_dsa_verify(pub_only, msg, msg_len, alt_sig, sig_len2, NULL) != 0)
                goto exit;
        sig_len = sizeof(buf_sig);
        if (imb_ml_dsa_sign(pub_only, buf_sig, &sig_len, msg, msg_len, NULL) != IMB_ERR_PQC_SIGNOP)
                goto exit;

        /*
         * Rebinding replaces the previous key outright: after binding an
         * unrelated key, the earlier signature must stop verifying.
         */
        stage = "key rebinding";
        if (imb_ml_dsa_keypair(self, alt_pk, sizeof(alt_pk), alt_sk, sizeof(alt_sk), NULL) != 0)
                goto exit;
        if (imb_ml_dsa_verify(self, msg, msg_len, alt_sig, sig_len2, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;
        if (imb_ml_dsa_set_pubkey(pub_only, alt_pk, pk_bytes) != 0)
                goto exit;
        if (imb_ml_dsa_verify(pub_only, msg, msg_len, alt_sig, sig_len2, NULL) !=
            IMB_ERR_PQC_VERIFY_FAILED)
                goto exit;

        ret = 0;
exit:
        if (ret != 0)
                printf("ML-DSA context/hedging test failed (%s, stage: %s)\n", ml_dsa_alg_name(alg),
                       stage);
        imb_ml_dsa_free(pub_only);
        imb_ml_dsa_free(self);
        return ret;
}

int
ml_dsa_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctxs[3];
        struct test_suite_context *ctx;
        int errors = 0;
        unsigned i;

        test_suite_start(&ctxs[0], "ML-DSA-44");
        test_suite_start(&ctxs[1], "ML-DSA-65");
        test_suite_start(&ctxs[2], "ML-DSA-87");

        if (!quiet_mode)
                printf("ML-DSA (FIPS 204) known-answer tests:\n");

        for (i = 0; i < DIM(variants); i++) {
                ctx = ml_dsa_ctx_for_alg(variants[i].alg, ctxs);
                if (ml_dsa_run_sign_seed_vectors(mb_mgr, &variants[i], ctx) < 0)
                        test_suite_update(ctx, 0, 1);
                if (ml_dsa_run_sign_noseed_vectors(mb_mgr, &variants[i], ctx) < 0)
                        test_suite_update(ctx, 0, 1);
                if (ml_dsa_run_verify_vectors(mb_mgr, &variants[i], ctx) < 0)
                        test_suite_update(ctx, 0, 1);
                if (ml_dsa_roundtrip(mb_mgr, variants[i].alg) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
                if (ml_dsa_key_negative(mb_mgr, variants[i].alg) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
                if (ml_dsa_sig_negative(mb_mgr, variants[i].alg) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
                if (ml_dsa_ctx_and_hedging(mb_mgr, variants[i].alg) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }

        errors += test_suite_end(&ctxs[0]);
        errors += test_suite_end(&ctxs[1]);
        errors += test_suite_end(&ctxs[2]);

        return errors;
}
