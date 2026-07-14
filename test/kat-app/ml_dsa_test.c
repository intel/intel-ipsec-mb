/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

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
ml_dsa_build_mprime(const uint8_t *msg, const size_t msg_len, const uint8_t *ctx,
                    const size_t ctx_len, size_t *mprime_len)
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
                           const uint8_t *msg, const size_t msg_len, const uint8_t *ctx,
                           const size_t ctx_len, const uint8_t *rnd_ptr,
                           const uint8_t *expected_sig, const size_t expected_sig_len,
                           const int expect_valid)
{
        size_t sig_len = 0;
        size_t mprime_len = 0;
        int rc;

        if (ctx_len > 255)
                return 0;
        if (ml_dsa_build_mprime(msg, msg_len, ctx, ctx_len, &mprime_len) < 0) {
                printf("ML-DSA Sign_internal M' construction failed (%s tcId=%zu)\n",
                       ml_dsa_alg_name(alg), tcId);
                return 1;
        }

        rc = imb_ml_dsa_sign_internal(self, exp_sig, &sig_len, buf_mprime, mprime_len, rnd_ptr);
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
                             const uint8_t *msg, const size_t msg_len, const uint8_t *ctx,
                             const size_t ctx_len, const uint8_t *sig, const size_t sig_len,
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
        size_t pk_bytes, sk_bytes, sig_bytes;
        const uint8_t *ctx_ptr = NULL;
        /*
         * A vector without an explicit "rnd" field is a deterministic test
         * case (implied all-zero randomizer); default to zero_rnd rather
         * than NULL since imb_ml_dsa_sign()'s NULL means auto-random.
         */
        const uint8_t *rnd_ptr = zero_rnd;
        IMB_ML_DSA *self = NULL;
        size_t sig_len = 0;
        int rc;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;
        if (v->privateSeedLen != ML_DSA_SEED_BYTES || v->publicKeyLen != pk_bytes ||
            v->msgLen > ML_DSA_MAX_MSG || v->ctxLen > ML_DSA_MAX_CTX)
                return 1;
        if (v->hasRnd) {
                if (v->rndLen != ML_DSA_RND_BYTES)
                        return 1;
                rnd_ptr = (const uint8_t *) v->rnd;
        }
        if (v->hasCtx)
                ctx_ptr = (const uint8_t *) v->ctx;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        {
                IMB_ML_DSA_KEYGEN_PARAMS keygen_params;

                keygen_params.xi_32 = (const uint8_t *) v->privateSeed;
                rc = imb_ml_dsa_keypair(self, buf_pk, buf_sk, &keygen_params);
        }
        if (rc != 0 || memcmp(buf_pk, v->publicKey, pk_bytes) != 0) {
                printf("ML-DSA keyGen KAT mismatch (%s tcId=%zu rc=%d)\n", ml_dsa_alg_name(alg),
                       v->tcId, rc);
                goto exit;
        }

        {
                IMB_ML_DSA_SIGN_PARAMS sign_params;

                sign_params.ctx = ctx_ptr;
                sign_params.ctx_len = v->ctxLen;
                sign_params.rnd_32 = rnd_ptr;
                rc = imb_ml_dsa_sign(self, buf_sig, &sig_len, (const uint8_t *) v->msg, v->msgLen,
                                     &sign_params);
        }
        if (v->resultValid) {
                IMB_ML_DSA_VERIFY_PARAMS verify_params;

                if (v->sigLen != sig_bytes || rc != 0 || sig_len != sig_bytes ||
                    memcmp(buf_sig, v->sig, sig_bytes) != 0) {
                        printf("ML-DSA sigGen KAT mismatch (%s tcId=%zu rc=%d sig_len=%zu "
                               "exp=%zu)\n",
                               ml_dsa_alg_name(alg), v->tcId, rc, sig_len, v->sigLen);
                        goto exit;
                }
                verify_params.ctx = ctx_ptr;
                verify_params.ctx_len = v->ctxLen;
                if (imb_ml_dsa_verify(self, (const uint8_t *) v->msg, v->msgLen, buf_sig, sig_len,
                                      &verify_params) != 0) {
                        printf("ML-DSA sigGen verify failed (%s tcId=%zu)\n", ml_dsa_alg_name(alg),
                               v->tcId);
                        goto exit;
                }
                if (ml_dsa_check_internal_sign(self, alg, v->tcId, (const uint8_t *) v->msg,
                                               v->msgLen, ctx_ptr, v->ctxLen, rnd_ptr,
                                               (const uint8_t *) v->sig, v->sigLen, 1) != 0)
                        goto exit;
        } else {
                if (rc == 0) {
                        printf("ML-DSA sigGen unexpectedly succeeded (%s tcId=%zu)\n",
                               ml_dsa_alg_name(alg), v->tcId);
                        goto exit;
                }
                if (ml_dsa_check_internal_sign(self, alg, v->tcId, (const uint8_t *) v->msg,
                                               v->msgLen, ctx_ptr, v->ctxLen, rnd_ptr,
                                               (const uint8_t *) v->sig, v->sigLen, 0) != 0)
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
        size_t pk_bytes, sk_bytes, sig_bytes;
        const uint8_t *ctx_ptr = NULL;
        /*
         * A vector without an explicit "rnd" field is a deterministic test
         * case (implied all-zero randomizer); default to zero_rnd rather
         * than NULL since imb_ml_dsa_sign()'s NULL means auto-random.
         */
        const uint8_t *rnd_ptr = zero_rnd;
        IMB_ML_DSA *self = NULL;
        size_t sig_len = 0;
        int set_rc;
        int rc = -1;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;
        if (v->privateKeyLen != sk_bytes || v->publicKeyLen != pk_bytes ||
            v->msgLen > ML_DSA_MAX_MSG || v->ctxLen > ML_DSA_MAX_CTX)
                return 1;
        if (v->hasRnd) {
                if (v->rndLen != ML_DSA_RND_BYTES)
                        return 1;
                rnd_ptr = (const uint8_t *) v->rnd;
        }
        if (v->hasCtx)
                ctx_ptr = (const uint8_t *) v->ctx;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        set_rc = imb_ml_dsa_set_privkey(self, (const uint8_t *) v->privateKey);
        if (set_rc == 0) {
                IMB_ML_DSA_SIGN_PARAMS sign_params;

                sign_params.ctx = ctx_ptr;
                sign_params.ctx_len = v->ctxLen;
                sign_params.rnd_32 = rnd_ptr;
                rc = imb_ml_dsa_sign(self, buf_sig, &sig_len, (const uint8_t *) v->msg, v->msgLen,
                                     &sign_params);
        }

        if (v->resultValid) {
                IMB_ML_DSA_VERIFY_PARAMS verify_params;

                if (set_rc != 0 || v->sigLen != sig_bytes || rc != 0 || sig_len != sig_bytes ||
                    memcmp(buf_sig, v->sig, sig_bytes) != 0) {
                        printf("ML-DSA sigGen KAT mismatch (%s tcId=%zu set_rc=%d rc=%d "
                               "sig_len=%zu exp=%zu)\n",
                               ml_dsa_alg_name(alg), v->tcId, set_rc, rc, sig_len, v->sigLen);
                        goto exit;
                }
                verify_params.ctx = ctx_ptr;
                verify_params.ctx_len = v->ctxLen;
                if (imb_ml_dsa_verify(self, (const uint8_t *) v->msg, v->msgLen, buf_sig, sig_len,
                                      &verify_params) != 0) {
                        printf("ML-DSA sigGen verify failed (%s tcId=%zu)\n", ml_dsa_alg_name(alg),
                               v->tcId);
                        goto exit;
                }
                if (ml_dsa_check_internal_sign(self, alg, v->tcId, (const uint8_t *) v->msg,
                                               v->msgLen, ctx_ptr, v->ctxLen, rnd_ptr,
                                               (const uint8_t *) v->sig, v->sigLen, 1) != 0)
                        goto exit;
        } else {
                if (set_rc == 0 && rc == 0) {
                        printf("ML-DSA sigGen unexpectedly succeeded (%s tcId=%zu)\n",
                               ml_dsa_alg_name(alg), v->tcId);
                        goto exit;
                }
                if (ml_dsa_check_internal_sign(self, alg, v->tcId, (const uint8_t *) v->msg,
                                               v->msgLen, ctx_ptr, v->ctxLen, rnd_ptr,
                                               (const uint8_t *) v->sig, v->sigLen, 0) != 0)
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
        size_t pk_bytes, sk_bytes, sig_bytes;
        const uint8_t *ctx_ptr = NULL;
        IMB_ML_DSA *self = NULL;
        int set_rc;
        int rc;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;
        if (v->publicKeyLen != pk_bytes || v->msgLen > ML_DSA_MAX_MSG || v->ctxLen > ML_DSA_MAX_CTX)
                return 1;
        if (v->hasCtx)
                ctx_ptr = (const uint8_t *) v->ctx;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        set_rc = imb_ml_dsa_set_pubkey(self, (const uint8_t *) v->publicKey);
        if (set_rc == 0) {
                IMB_ML_DSA_VERIFY_PARAMS verify_params;

                verify_params.ctx = ctx_ptr;
                verify_params.ctx_len = v->ctxLen;
                rc = imb_ml_dsa_verify(self, (const uint8_t *) v->msg, v->msgLen,
                                       (const uint8_t *) v->sig, v->sigLen, &verify_params);
        } else {
                rc = -1;
        }
        if ((rc == 0) != (v->resultValid != 0)) {
                printf("ML-DSA sigVer unexpected result (%s tcId=%zu expect_valid=%d set_rc=%d "
                       "rc=%d)\n",
                       ml_dsa_alg_name(alg), v->tcId, v->resultValid, set_rc, rc);
                goto exit;
        }
        if (ml_dsa_check_internal_verify(self, alg, v->tcId, (const uint8_t *) v->msg, v->msgLen,
                                         ctx_ptr, v->ctxLen, (const uint8_t *) v->sig, v->sigLen,
                                         rc) != 0)
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
        size_t pk_bytes, sk_bytes, sig_bytes;
        size_t sig_len = 0, sig_len2 = 0;
        IMB_ML_DSA *self = NULL;
        int ret = 1;

        if (ml_dsa_alg_sizes(alg, &pk_bytes, &sk_bytes, &sig_bytes) < 0)
                return 1;

        if (imb_ml_dsa_new(mb_mgr, alg, &self) != 0)
                return 1;

        /* random key pair and its validation / public-key derivation */
        if (imb_ml_dsa_keypair(self, buf_pk, buf_sk, NULL) != 0)
                goto exit;
        if (imb_ml_dsa_pubkey_validate(self, buf_pk) != 0)
                goto exit;
        if (imb_ml_dsa_privkey_validate(self, buf_sk) != 0)
                goto exit;
        if (imb_ml_dsa_pubkey_from_privkey(self, buf_sk, exp_pk) != 0 ||
            memcmp(exp_pk, buf_pk, pk_bytes) != 0)
                goto exit;

        /*
         * imb_ml_dsa_keypair() above already bound the generated key (both
         * private and public components) to self, so the sign/verify calls
         * below reuse it directly without any further set_privkey()/
         * set_pubkey() call.
         */

        /* hedged sign with context, then verify */
        {
                IMB_ML_DSA_SIGN_PARAMS sign_params;

                sign_params.ctx = ctx;
                sign_params.ctx_len = ctx_len;
                sign_params.rnd_32 = NULL;
                if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, &sign_params) != 0 ||
                    sig_len != sig_bytes)
                        goto exit;
        }
        {
                IMB_ML_DSA_VERIFY_PARAMS verify_params;

                verify_params.ctx = ctx;
                verify_params.ctx_len = ctx_len;
                if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, &verify_params) != 0)
                        goto exit;

                /* tampered signature must be rejected */
                buf_sig[sig_bytes / 2] ^= 0x55;
                if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, &verify_params) == 0)
                        goto exit;
                buf_sig[sig_bytes / 2] ^= 0x55;
        }

        /* wrong context must be rejected */
        if (imb_ml_dsa_verify(self, msg, msg_len, buf_sig, sig_len, NULL) == 0)
                goto exit;

        /* deterministic signing is reproducible (explicit all-zero rnd_32) */
        {
                IMB_ML_DSA_SIGN_PARAMS sign_params;

                sign_params.ctx = NULL;
                sign_params.ctx_len = 0;
                sign_params.rnd_32 = zero_rnd;
                if (imb_ml_dsa_sign(self, buf_sig, &sig_len, msg, msg_len, &sign_params) != 0)
                        goto exit;
                if (imb_ml_dsa_sign(self, exp_sig, &sig_len2, msg, msg_len, &sign_params) != 0)
                        goto exit;
        }
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
        }

        errors += test_suite_end(&ctxs[0]);
        errors += test_suite_end(&ctxs[1]);
        errors += test_suite_end(&ctxs[2]);

        return errors;
}
