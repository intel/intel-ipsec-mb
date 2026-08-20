/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* ML-KEM (FIPS 203) known-answer tests loaded from JSON vector files. */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "vector_utils.h"
#include "kem_test.h"

int
ml_kem_test(struct IMB_MGR *mb_mgr);

#define ML_KEM_MAX_PUBKEY  IMB_ML_KEM_1024_PUBKEY_BYTES
#define ML_KEM_MAX_PRIVKEY IMB_ML_KEM_1024_PRIVKEY_BYTES
#define ML_KEM_MAX_CT      IMB_ML_KEM_1024_CIPHERTEXT_BYTES
#define ML_KEM_SEED_BYTES  64
#define ML_KEM_M_BYTES     32
#define ML_KEM_K_BYTES     IMB_ML_KEM_SHARED_SECRET_BYTES

struct ml_kem_variant {
        IMB_ML_KEM_ALG alg;
        const char *name;
        const char *combined_file;
        const char *encaps_file;
        const char *keygen_seed_file;
        const char *semi_expanded_decaps_file;
};

static const struct ml_kem_variant variants[] = {
        { IMB_ML_KEM_512, "ML-KEM-512", "mlkem_512_test.json", "mlkem_512_encaps_test.json",
          "mlkem_512_keygen_seed_test.json", "mlkem_512_semi_expanded_decaps_test.json" },
        { IMB_ML_KEM_768, "ML-KEM-768", "mlkem_768_test.json", "mlkem_768_encaps_test.json",
          "mlkem_768_keygen_seed_test.json", "mlkem_768_semi_expanded_decaps_test.json" },
        { IMB_ML_KEM_1024, "ML-KEM-1024", "mlkem_1024_test.json", "mlkem_1024_encaps_test.json",
          "mlkem_1024_keygen_seed_test.json", "mlkem_1024_semi_expanded_decaps_test.json" },
};

static uint8_t buf_ek[ML_KEM_MAX_PUBKEY];
static uint8_t buf_dk[ML_KEM_MAX_PRIVKEY];
static uint8_t buf_ct[ML_KEM_MAX_CT];
static uint8_t buf_ss[ML_KEM_K_BYTES];
static uint8_t exp_ek[ML_KEM_MAX_PUBKEY];
static uint8_t exp_dk[ML_KEM_MAX_PRIVKEY];
static uint8_t exp_ct[ML_KEM_MAX_CT];

static const char *
ml_kem_alg_name(const IMB_ML_KEM_ALG alg)
{
        switch (alg) {
        case IMB_ML_KEM_512:
                return "ML-KEM-512";
        case IMB_ML_KEM_768:
                return "ML-KEM-768";
        case IMB_ML_KEM_1024:
                return "ML-KEM-1024";
        default:
                return "ML-KEM-?";
        }
}

static int
ml_kem_alg_sizes(const IMB_ML_KEM_ALG alg, size_t *ek_bytes, size_t *dk_bytes, size_t *ct_bytes)
{
        switch (alg) {
        case IMB_ML_KEM_512:
                *ek_bytes = IMB_ML_KEM_512_PUBKEY_BYTES;
                *dk_bytes = IMB_ML_KEM_512_PRIVKEY_BYTES;
                *ct_bytes = IMB_ML_KEM_512_CIPHERTEXT_BYTES;
                return 0;
        case IMB_ML_KEM_768:
                *ek_bytes = IMB_ML_KEM_768_PUBKEY_BYTES;
                *dk_bytes = IMB_ML_KEM_768_PRIVKEY_BYTES;
                *ct_bytes = IMB_ML_KEM_768_CIPHERTEXT_BYTES;
                return 0;
        case IMB_ML_KEM_1024:
                *ek_bytes = IMB_ML_KEM_1024_PUBKEY_BYTES;
                *dk_bytes = IMB_ML_KEM_1024_PRIVKEY_BYTES;
                *ct_bytes = IMB_ML_KEM_1024_CIPHERTEXT_BYTES;
                return 0;
        default:
                return -1;
        }
}

static struct test_suite_context *
ml_kem_ctx_for_alg(const IMB_ML_KEM_ALG alg, struct test_suite_context ctxs[3])
{
        switch (alg) {
        case IMB_ML_KEM_512:
                return &ctxs[0];
        case IMB_ML_KEM_768:
                return &ctxs[1];
        default:
                return &ctxs[2];
        }
}

/*
 * Combined keygen-from-seed + decap vector ("MLKEMTest" schema,
 * mlkem_*_test.json): drives ML-KEM.KeyGen(seed) -> compare ek,
 * then ML-KEM.Decaps(dk, c) -> compare K.
 * "Invalid" entries carry either a wrong size seed or a wrong size
 * ciphertext. The latter is exercised here and decapsulation is expected to
 * reject it. The former cannot be exercised, as the key generation seed is
 * passed to the library as a plain pointer without a length.
 */
static int
ml_kem_combined_vector(struct IMB_MGR *mb_mgr, const IMB_ML_KEM_ALG alg, const struct kem_test *v)
{
        size_t ek_bytes, dk_bytes, ct_bytes;
        IMB_ML_KEM *self = NULL;
        IMB_ML_KEM_KEYGEN_PARAMS keygen_params;
        int rc;
        int ret = 1;

        if (ml_kem_alg_sizes(alg, &ek_bytes, &dk_bytes, &ct_bytes) < 0)
                return 1;
        (void) dk_bytes;
        if (!v->hasSeed || !v->hasC)
                return 1;

        /*
         * The key generation seed is passed to the library as a plain pointer,
         * so a wrong seed length cannot be handed over to be rejected.
         */
        if (v->seedLen != ML_KEM_SEED_BYTES)
                return v->resultValid ? 1 : 0;

        if (v->resultValid && (v->cLen != ct_bytes || !v->hasK || v->KLen != ML_KEM_K_BYTES))
                return 1;

        if (imb_ml_kem_new(mb_mgr, alg, &self) != 0)
                return 1;

        IMB_ML_KEM_KEYGEN_PARAMS_INIT(&keygen_params);
        keygen_params.seed_d_z = v->seed;
        rc = imb_ml_kem_keypair(self, exp_ek, exp_dk, &keygen_params);
        if (rc != 0 ||
            (v->hasEk && (v->ekLen != ek_bytes || memcmp(exp_ek, v->ek, ek_bytes) != 0))) {
                printf("ML-KEM keyGen KAT mismatch (%s tcId=%zu rc=%d)\n", ml_kem_alg_name(alg),
                       v->tcId, rc);
                goto exit;
        }

        rc = imb_ml_kem_decap(self, buf_ss, v->c, v->cLen, NULL);

        if (v->resultValid) {
                if (rc != 0 || memcmp(buf_ss, v->K, ML_KEM_K_BYTES) != 0) {
                        printf("ML-KEM decap KAT mismatch (%s tcId=%zu rc=%d)\n",
                               ml_kem_alg_name(alg), v->tcId, rc);
                        goto exit;
                }
        } else if (rc == 0) {
                printf("ML-KEM decap unexpectedly succeeded (%s tcId=%zu ct_len=%zu)\n",
                       ml_kem_alg_name(alg), v->tcId, v->cLen);
                goto exit;
        }

        ret = 0;
exit:
        imb_ml_kem_free(self);
        return ret;
}

/*
 * Encapsulation vector ("MLKEMEncapsTest" schema, mlkem_*_encaps_test.json):
 * drives set_pubkey(ek) + ML-KEM.Encaps(m) -> compare c/K.
 * "Invalid" entries mean ek fails the FIPS 203 Section 7.2 encapsulation-key
 * check, which is asserted through the key validation API; some "invalid"
 * vectors may still carry a (meaningless) c/K that is not checked.
 */
static int
ml_kem_encaps_vector(struct IMB_MGR *mb_mgr, const IMB_ML_KEM_ALG alg, const struct kem_test *v)
{
        size_t ek_bytes, dk_bytes, ct_bytes;
        IMB_ML_KEM *self = NULL;
        IMB_ML_KEM_ENCAP_PARAMS encap_params;
        int set_rc;
        int rc = -1;
        int ret = 1;

        if (ml_kem_alg_sizes(alg, &ek_bytes, &dk_bytes, &ct_bytes) < 0)
                return 1;
        (void) dk_bytes;
        if (!v->hasEk || !v->hasM || v->mLen != ML_KEM_M_BYTES)
                return 1;

        if (imb_ml_kem_new(mb_mgr, alg, &self) != 0)
                return 1;

        set_rc = (v->ekLen == ek_bytes) ? imb_ml_kem_set_pubkey(self, v->ek) : -1;
        if (set_rc == 0) {
                IMB_ML_KEM_ENCAP_PARAMS_INIT(&encap_params);
                encap_params.m_32 = v->m;
                rc = imb_ml_kem_encap(self, buf_ct, buf_ss, &encap_params);
        }

        if (v->resultValid) {
                if (set_rc != 0 || rc != 0 ||
                    (v->hasC && (v->cLen != ct_bytes || memcmp(buf_ct, v->c, ct_bytes) != 0)) ||
                    (v->hasK &&
                     (v->KLen != ML_KEM_K_BYTES || memcmp(buf_ss, v->K, ML_KEM_K_BYTES) != 0))) {
                        printf("ML-KEM encaps KAT mismatch (%s tcId=%zu set_rc=%d rc=%d)\n",
                               ml_kem_alg_name(alg), v->tcId, set_rc, rc);
                        goto exit;
                }
        } else {
                /*
                 * The key must fail the FIPS 203 Section 7.2 encapsulation key
                 * check. Keys of a wrong size cannot be handed over to the
                 * library, as the key setting API takes the size implicitly
                 * from the algorithm.
                 */
                if (v->ekLen == ek_bytes && imb_ml_kem_pubkey_validate(self, v->ek) == 0) {
                        printf("ML-KEM encaps key unexpectedly validated (%s tcId=%zu)\n",
                               ml_kem_alg_name(alg), v->tcId);
                        goto exit;
                }
        }

        ret = 0;
exit:
        imb_ml_kem_free(self);
        return ret;
}

/*
 * KeyGen vector ("MLKEMKeyGen" schema, mlkem_*_keygen_seed_test.json):
 * drives ML-KEM.KeyGen(seed) -> compare ek/dk. Direct upstream
 * analogue of the real ACVP "keyGen" AFT vectors.
 */
static int
ml_kem_keygen_seed_vector(struct IMB_MGR *mb_mgr, const IMB_ML_KEM_ALG alg,
                          const struct kem_test *v)
{
        size_t ek_bytes, dk_bytes, ct_bytes;
        IMB_ML_KEM *self = NULL;
        IMB_ML_KEM_KEYGEN_PARAMS keygen_params;
        int rc;
        int ret = 1;

        if (ml_kem_alg_sizes(alg, &ek_bytes, &dk_bytes, &ct_bytes) < 0)
                return 1;
        (void) ct_bytes;
        if (!v->hasSeed || v->seedLen != ML_KEM_SEED_BYTES)
                return 1;

        if (imb_ml_kem_new(mb_mgr, alg, &self) != 0)
                return 1;

        IMB_ML_KEM_KEYGEN_PARAMS_INIT(&keygen_params);
        keygen_params.seed_d_z = v->seed;
        rc = imb_ml_kem_keypair(self, buf_ek, buf_dk, &keygen_params);

        if (v->resultValid) {
                if (rc != 0 || v->ekLen != ek_bytes || v->dkLen != dk_bytes ||
                    memcmp(buf_ek, v->ek, ek_bytes) != 0 || memcmp(buf_dk, v->dk, dk_bytes) != 0) {
                        printf("ML-KEM keyGen KAT mismatch (%s tcId=%zu rc=%d)\n",
                               ml_kem_alg_name(alg), v->tcId, rc);
                        goto exit;
                }
        } else if (rc == 0) {
                printf("ML-KEM keyGen unexpectedly succeeded (%s tcId=%zu)\n", ml_kem_alg_name(alg),
                       v->tcId);
                goto exit;
        }

        ret = 0;
exit:
        imb_ml_kem_free(self);
        return ret;
}

/*
 * Semi-expanded decapsulation vector ("MLKEMSemiExpandedDecapsTest" schema,
 * mlkem_*_semi_expanded_decaps_test.json): drives set_privkey(dk) +
 * ML-KEM.Decaps(c) -> compare K when valid. This is the exact structural
 * analogue of the real ACVP "decapsulation" VAL vectors (explicit dk/c/K
 * triples with valid/invalid reasons: ciphertext-length, decapsulation-key
 * hash mismatch, etc). Note the public API has no length parameter for
 * set_privkey(), so a wrong-length dk cannot be detected inside the library
 * call itself - the harness must pre-check the byte length here before
 * calling set_privkey(), matching the same limitation already accepted for
 * ML-DSA's set_privkey()/set_pubkey().
 */
static int
ml_kem_semi_expanded_decaps_vector(struct IMB_MGR *mb_mgr, const IMB_ML_KEM_ALG alg,
                                   const struct kem_test *v)
{
        size_t ek_bytes, dk_bytes, ct_bytes;
        IMB_ML_KEM *self = NULL;
        int set_rc = -1;
        int rc = -1;
        int ret = 1;

        if (ml_kem_alg_sizes(alg, &ek_bytes, &dk_bytes, &ct_bytes) < 0)
                return 1;
        (void) ek_bytes;
        if (!v->hasDk || !v->hasC)
                return 1;

        if (imb_ml_kem_new(mb_mgr, alg, &self) != 0)
                return 1;

        if (v->dkLen == dk_bytes) {
                set_rc = imb_ml_kem_set_privkey(self, v->dk);
                if (set_rc == 0)
                        rc = imb_ml_kem_decap(self, buf_ss, v->c, v->cLen, NULL);
        }

        if (v->resultValid) {
                if (set_rc != 0 || rc != 0 || v->cLen != ct_bytes ||
                    (v->hasK &&
                     (v->KLen != ML_KEM_K_BYTES || memcmp(buf_ss, v->K, ML_KEM_K_BYTES) != 0))) {
                        printf("ML-KEM semi-expanded decap KAT mismatch (%s tcId=%zu set_rc=%d "
                               "rc=%d)\n",
                               ml_kem_alg_name(alg), v->tcId, set_rc, rc);
                        goto exit;
                }
        } else {
                /* An invalid dk-length or ciphertext-length case is caught by
                 * the harness above/within decap()'s unconditional length
                 * check; an invalid dk hash is caught by set_privkey(). */
                if (v->dkLen == dk_bytes && v->cLen == ct_bytes && set_rc == 0 && rc == 0) {
                        printf("ML-KEM semi-expanded decap unexpectedly succeeded (%s tcId=%zu)\n",
                               ml_kem_alg_name(alg), v->tcId);
                        goto exit;
                }
        }

        ret = 0;
exit:
        imb_ml_kem_free(self);
        return ret;
}

static int
ml_kem_run_combined_vectors(struct IMB_MGR *mb_mgr, const struct ml_kem_variant *variant,
                            struct test_suite_context *ctx)
{
        struct kem_test *vectors = NULL;
        struct test_json_alloc_ctx *json_ctx = NULL;
        const struct kem_test *v;
        int ret = -1;

        if (load_kem_vectors(kat_vector_dir, variant->combined_file, &vectors, &json_ctx) < 0) {
                printf("Failed to load ML-KEM combined vectors (%s)\n", variant->combined_file);
                goto exit;
        }

        for (v = vectors; v->comment != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("ML-KEM combined Test Case %zu (%s)\n", v->tcId, v->comment);
#endif
                if (ml_kem_combined_vector(mb_mgr, variant->alg, v) != 0)
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
ml_kem_run_encaps_vectors(struct IMB_MGR *mb_mgr, const struct ml_kem_variant *variant,
                          struct test_suite_context *ctx)
{
        struct kem_test *vectors = NULL;
        struct test_json_alloc_ctx *json_ctx = NULL;
        const struct kem_test *v;
        int ret = -1;

        if (load_kem_vectors(kat_vector_dir, variant->encaps_file, &vectors, &json_ctx) < 0) {
                printf("Failed to load ML-KEM encaps vectors (%s)\n", variant->encaps_file);
                goto exit;
        }

        for (v = vectors; v->comment != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("ML-KEM encaps Test Case %zu (%s)\n", v->tcId, v->comment);
#endif
                if (ml_kem_encaps_vector(mb_mgr, variant->alg, v) != 0)
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
ml_kem_run_keygen_seed_vectors(struct IMB_MGR *mb_mgr, const struct ml_kem_variant *variant,
                               struct test_suite_context *ctx)
{
        struct kem_test *vectors = NULL;
        struct test_json_alloc_ctx *json_ctx = NULL;
        const struct kem_test *v;
        int ret = -1;

        if (load_kem_vectors(kat_vector_dir, variant->keygen_seed_file, &vectors, &json_ctx) < 0) {
                printf("Failed to load ML-KEM keygen-seed vectors (%s)\n",
                       variant->keygen_seed_file);
                goto exit;
        }

        for (v = vectors; v->comment != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("ML-KEM keygen-seed Test Case %zu (%s)\n", v->tcId, v->comment);
#endif
                if (ml_kem_keygen_seed_vector(mb_mgr, variant->alg, v) != 0)
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
ml_kem_run_semi_expanded_decaps_vectors(struct IMB_MGR *mb_mgr,
                                        const struct ml_kem_variant *variant,
                                        struct test_suite_context *ctx)
{
        struct kem_test *vectors = NULL;
        struct test_json_alloc_ctx *json_ctx = NULL;
        const struct kem_test *v;
        int ret = -1;

        if (load_kem_vectors(kat_vector_dir, variant->semi_expanded_decaps_file, &vectors,
                             &json_ctx) < 0) {
                printf("Failed to load ML-KEM semi-expanded-decaps vectors (%s)\n",
                       variant->semi_expanded_decaps_file);
                goto exit;
        }

        for (v = vectors; v->comment != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("ML-KEM semi-expanded-decaps Test Case %zu (%s)\n", v->tcId,
                               v->comment);
#endif
                if (ml_kem_semi_expanded_decaps_vector(mb_mgr, variant->alg, v) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }

        ret = 0;
exit:
        json_free_test_ctx(json_ctx);
        return ret;
}

/* Random key-generation, encapsulation and decapsulation round-trip
 * including implicit-rejection (tamper) checking and key
 * derivation/validation helpers. */
static int
ml_kem_roundtrip(struct IMB_MGR *mb_mgr, const IMB_ML_KEM_ALG alg)
{
        size_t ek_bytes, dk_bytes, ct_bytes;
        IMB_ML_KEM *self = NULL;
        int ret = 1;

        if (ml_kem_alg_sizes(alg, &ek_bytes, &dk_bytes, &ct_bytes) < 0)
                return 1;

        if (imb_ml_kem_new(mb_mgr, alg, &self) != 0)
                return 1;

        /* random key pair and its validation */
        if (imb_ml_kem_keypair(self, buf_ek, buf_dk, NULL) != 0)
                goto exit;
        if (imb_ml_kem_pubkey_validate(self, buf_ek) != 0)
                goto exit;
        if (imb_ml_kem_privkey_validate(self, buf_dk) != 0)
                goto exit;

        /*
         * imb_ml_kem_keypair() above already bound the generated key (both
         * private and public components) to self, so the encap/decap calls
         * below reuse it directly without any further set_privkey()/
         * set_pubkey() call.
         */

        /* random encapsulation, then decapsulation recovers the same secret */
        if (imb_ml_kem_encap(self, buf_ct, buf_ss, NULL) != 0)
                goto exit;
        if (imb_ml_kem_decap(self, exp_ct /* reuse as scratch shared-secret-sized buf */, buf_ct,
                             ct_bytes, NULL) != 0)
                goto exit;
        if (memcmp(buf_ss, exp_ct, ML_KEM_K_BYTES) != 0)
                goto exit;

        /* tampered (but correctly sized) ciphertext must still succeed via
         * implicit rejection, yielding a different shared secret */
        buf_ct[ct_bytes / 2] ^= 0x55;
        if (imb_ml_kem_decap(self, exp_ct, buf_ct, ct_bytes, NULL) != 0)
                goto exit;
        if (memcmp(buf_ss, exp_ct, ML_KEM_K_BYTES) == 0)
                goto exit;
        buf_ct[ct_bytes / 2] ^= 0x55;

        /* wrong-length ciphertext must be rejected */
        if (imb_ml_kem_decap(self, exp_ct, buf_ct, ct_bytes - 1, NULL) == 0)
                goto exit;

        /* deterministic key generation is reproducible (explicit seed) */
        {
                IMB_ML_KEM_KEYGEN_PARAMS keygen_params;
                static const uint8_t zero_seed[ML_KEM_SEED_BYTES] = { 0 };

                IMB_ML_KEM_KEYGEN_PARAMS_INIT(&keygen_params);
                keygen_params.seed_d_z = zero_seed;
                if (imb_ml_kem_keypair(self, buf_ek, buf_dk, &keygen_params) != 0)
                        goto exit;
                if (imb_ml_kem_keypair(self, exp_ek, exp_dk, &keygen_params) != 0)
                        goto exit;
        }
        if (memcmp(buf_ek, exp_ek, ek_bytes) != 0 || memcmp(buf_dk, exp_dk, dk_bytes) != 0)
                goto exit;

        /* deterministic encapsulation is reproducible (explicit m_32) */
        {
                IMB_ML_KEM_ENCAP_PARAMS encap_params;
                static const uint8_t zero_m[ML_KEM_M_BYTES] = { 0 };
                uint8_t ss2[ML_KEM_K_BYTES];

                IMB_ML_KEM_ENCAP_PARAMS_INIT(&encap_params);
                encap_params.m_32 = zero_m;
                if (imb_ml_kem_encap(self, buf_ct, buf_ss, &encap_params) != 0)
                        goto exit;
                if (imb_ml_kem_encap(self, exp_ct, ss2, &encap_params) != 0)
                        goto exit;
                if (memcmp(buf_ct, exp_ct, ct_bytes) != 0 ||
                    memcmp(buf_ss, ss2, ML_KEM_K_BYTES) != 0)
                        goto exit;
        }

        ret = 0;
exit:
        if (ret != 0)
                printf("ML-KEM round-trip failed (%s)\n", ml_kem_alg_name(alg));
        imb_ml_kem_free(self);
        return ret;
}

/*
 * Malformed encapsulation/decapsulation key handling.
 *
 * Exercises the two structural checks that FIPS 203 requires an
 * implementation to perform when importing a key, plus the layout invariant
 * that ties dk to ek:
 *
 *   - Section 7.2 "modulus check": ek is ByteEncode_12(t) || rho, so every
 *     12-bit coefficient must decode to a value below q = 3329. An encoding
 *     holding an out-of-range coefficient must be rejected.
 *   - Section 7.3 "hash check": dk carries H(ek) so that a decapsulation key
 *     inconsistent with its embedded encapsulation key can be detected.
 *   - dk is dk_PKE || ek || H(ek) || z, so the ek copy embedded in dk must be
 *     byte-identical to the separately returned ek.
 *
 * Note that the trailing z (implicit-rejection secret) is deliberately not
 * covered by any consistency check, so a dk with a modified z stays valid -
 * that property is exercised in ml_kem_decap_negative() instead.
 */
static int
ml_kem_key_negative(struct IMB_MGR *mb_mgr, const IMB_ML_KEM_ALG alg)
{
        size_t ek_bytes, dk_bytes, ct_bytes;
        size_t pkhash_off, ek_off;
        IMB_ML_KEM *self = NULL, *fresh = NULL;
        const char *stage = "setup";
        int ret = 1;

        if (ml_kem_alg_sizes(alg, &ek_bytes, &dk_bytes, &ct_bytes) < 0)
                return 1;

        if (imb_ml_kem_new(mb_mgr, alg, &self) != 0)
                return 1;

        if (imb_ml_kem_keypair(self, buf_ek, buf_dk, NULL) != 0)
                goto exit;

        /* dk = dk_PKE || ek || H(ek) || z, with 32-byte H(ek) and z trailers */
        pkhash_off = dk_bytes - 2 * ML_KEM_K_BYTES;
        ek_off = pkhash_off - ek_bytes;

        stage = "ek embedded in dk";
        if (memcmp(&buf_dk[ek_off], buf_ek, ek_bytes) != 0)
                goto exit;

        /*
         * Modulus check: force the first 12-bit coefficient of t to
         * 0xfff = 4095, which is >= q, leaving every other byte untouched.
         */
        stage = "ek modulus check";
        memcpy(exp_ek, buf_ek, ek_bytes);
        exp_ek[0] = 0xff;
        exp_ek[1] |= 0x0f;
        if (imb_ml_kem_pubkey_validate(self, exp_ek) != IMB_ERR_PQC_KEYOP)
                goto exit;
        if (imb_ml_kem_new(mb_mgr, alg, &fresh) != 0)
                goto exit;
        if (imb_ml_kem_set_pubkey(fresh, exp_ek) != IMB_ERR_PQC_KEYOP)
                goto exit;
        imb_ml_kem_free(fresh);
        fresh = NULL;

        /*
         * The same check applies to dk's own s vector, which occupies the
         * start of dk_PKE. This path is distinct from the embedded ek below:
         * it is reached while parsing the private half of the key.
         */
        stage = "dk s vector modulus check";
        memcpy(exp_dk, buf_dk, dk_bytes);
        exp_dk[0] = 0xff;
        exp_dk[1] |= 0x0f;
        if (imb_ml_kem_privkey_validate(self, exp_dk) != IMB_ERR_PQC_KEYOP)
                goto exit;
        if (imb_ml_kem_new(mb_mgr, alg, &fresh) != 0)
                goto exit;
        if (imb_ml_kem_set_privkey(fresh, exp_dk) != IMB_ERR_PQC_KEYOP)
                goto exit;
        imb_ml_kem_free(fresh);
        fresh = NULL;

        /* the same corruption inside dk's embedded ek must also be caught */
        stage = "dk embedded ek modulus check";
        memcpy(exp_dk, buf_dk, dk_bytes);
        exp_dk[ek_off] = 0xff;
        exp_dk[ek_off + 1] |= 0x0f;
        if (imb_ml_kem_privkey_validate(self, exp_dk) != IMB_ERR_PQC_KEYOP)
                goto exit;

        /* hash check: flip a bit of H(ek) so dk no longer matches its ek */
        stage = "dk hash check";
        memcpy(exp_dk, buf_dk, dk_bytes);
        exp_dk[pkhash_off] ^= 0x01;
        if (imb_ml_kem_privkey_validate(self, exp_dk) != IMB_ERR_PQC_KEYOP)
                goto exit;
        if (imb_ml_kem_new(mb_mgr, alg, &fresh) != 0)
                goto exit;
        if (imb_ml_kem_set_privkey(fresh, exp_dk) != IMB_ERR_PQC_KEYOP)
                goto exit;
        imb_ml_kem_free(fresh);
        fresh = NULL;

        /* an untouched copy must still validate, proving the above rejections
         * came from the injected corruption and not from the copy itself */
        stage = "pristine key still valid";
        memcpy(exp_dk, buf_dk, dk_bytes);
        if (imb_ml_kem_pubkey_validate(self, buf_ek) != 0 ||
            imb_ml_kem_privkey_validate(self, exp_dk) != 0)
                goto exit;

        ret = 0;
exit:
        if (ret != 0)
                printf("ML-KEM malformed-key test failed (%s, stage: %s)\n", ml_kem_alg_name(alg),
                       stage);
        imb_ml_kem_free(fresh);
        imb_ml_kem_free(self);
        return ret;
}

/*
 * Decapsulation behaviour for ciphertexts that are not the ones produced by
 * encapsulation against the bound key.
 *
 * FIPS 203 Section 7.3 gives decapsulation an unusual contract that is easy
 * to get wrong: a correctly sized but content-invalid ciphertext must NOT be
 * reported as an error. Instead the Fujisaki-Okamoto "implicit rejection"
 * path returns K_bar = J(z || c), a shared secret that is pseudorandom but
 * fully determined by the key's z and the ciphertext. Only a length mismatch
 * is a hard error.
 *
 * This checks the parts of that contract that a single tamper-and-compare
 * cannot: that rejection is deterministic, that it is driven by z, that it
 * applies to a ciphertext belonging to a different key, and that the length
 * check covers under-, over- and zero-length inputs.
 */
static int
ml_kem_decap_negative(struct IMB_MGR *mb_mgr, const IMB_ML_KEM_ALG alg)
{
        uint8_t ss_good[ML_KEM_K_BYTES], ss_rej[ML_KEM_K_BYTES], ss_rej2[ML_KEM_K_BYTES];
        size_t ek_bytes, dk_bytes, ct_bytes;
        size_t tamper_off[3];
        size_t i;
        IMB_ML_KEM *self = NULL, *other = NULL;
        const char *stage = "setup";
        int ret = 1;

        if (ml_kem_alg_sizes(alg, &ek_bytes, &dk_bytes, &ct_bytes) < 0)
                return 1;

        if (imb_ml_kem_new(mb_mgr, alg, &self) != 0)
                return 1;
        if (imb_ml_kem_keypair(self, buf_ek, buf_dk, NULL) != 0)
                goto exit;
        if (imb_ml_kem_encap(self, buf_ct, ss_good, NULL) != 0)
                goto exit;

        /* implicit rejection is deterministic and differs from the real secret */
        stage = "implicit rejection determinism";
        tamper_off[0] = 0;
        tamper_off[1] = ct_bytes / 2;
        tamper_off[2] = ct_bytes - 1;

        for (i = 0; i < DIM(tamper_off); i++) {
                const size_t off = tamper_off[i];

                memcpy(exp_ct, buf_ct, ct_bytes);
                exp_ct[off] ^= 0x01;

                if (imb_ml_kem_decap(self, ss_rej, exp_ct, ct_bytes, NULL) != 0)
                        goto exit;
                if (memcmp(ss_rej, ss_good, ML_KEM_K_BYTES) == 0)
                        goto exit;
                /* repeating the same decap must reproduce the same secret */
                if (imb_ml_kem_decap(self, ss_rej2, exp_ct, ct_bytes, NULL) != 0)
                        goto exit;
                if (memcmp(ss_rej, ss_rej2, ML_KEM_K_BYTES) != 0)
                        goto exit;
        }

        /*
         * The rejection secret is keyed by z: re-binding the same key with a
         * modified z must keep valid ciphertexts working while changing the
         * implicit-rejection output. z is the last 32 bytes of dk and is
         * covered by no consistency check, so the modified key stays valid.
         */
        stage = "implicit rejection keyed by z";
        memcpy(exp_ct, buf_ct, ct_bytes);
        exp_ct[ct_bytes / 2] ^= 0x01;
        if (imb_ml_kem_decap(self, ss_rej, exp_ct, ct_bytes, NULL) != 0)
                goto exit;

        memcpy(exp_dk, buf_dk, dk_bytes);
        exp_dk[dk_bytes - 1] ^= 0xff;
        if (imb_ml_kem_new(mb_mgr, alg, &other) != 0)
                goto exit;
        if (imb_ml_kem_set_privkey(other, exp_dk) != 0)
                goto exit;
        /* valid ciphertext still recovers the original shared secret */
        if (imb_ml_kem_decap(other, ss_rej2, buf_ct, ct_bytes, NULL) != 0)
                goto exit;
        if (memcmp(ss_rej2, ss_good, ML_KEM_K_BYTES) != 0)
                goto exit;
        /* but the rejection secret for the tampered ciphertext has changed */
        if (imb_ml_kem_decap(other, ss_rej2, exp_ct, ct_bytes, NULL) != 0)
                goto exit;
        if (memcmp(ss_rej2, ss_rej, ML_KEM_K_BYTES) == 0)
                goto exit;
        imb_ml_kem_free(other);
        other = NULL;

        /* a ciphertext for a different key is rejected implicitly, not by error */
        stage = "cross-key decapsulation";
        if (imb_ml_kem_new(mb_mgr, alg, &other) != 0)
                goto exit;
        if (imb_ml_kem_keypair(other, exp_ek, exp_dk, NULL) != 0)
                goto exit;
        if (imb_ml_kem_decap(other, ss_rej, buf_ct, ct_bytes, NULL) != 0)
                goto exit;
        if (memcmp(ss_rej, ss_good, ML_KEM_K_BYTES) == 0)
                goto exit;

        /* length mismatches are the only hard decapsulation errors */
        stage = "ciphertext length check";
        if (imb_ml_kem_decap(self, ss_rej, buf_ct, ct_bytes - 1, NULL) != IMB_ERR_PQC_KEMOP)
                goto exit;
        if (imb_ml_kem_decap(self, ss_rej, buf_ct, ct_bytes + 1, NULL) != IMB_ERR_PQC_KEMOP)
                goto exit;
        if (imb_ml_kem_decap(self, ss_rej, buf_ct, 0, NULL) != IMB_ERR_PQC_KEMOP)
                goto exit;

        /*
         * A context holding only an encapsulation key can encapsulate but not
         * decapsulate. Note the error is IMB_ERR_PQC_KEMOP rather than
         * IMB_ERR_PQC_NO_KEY: NO_KEY is reserved for a context with no key
         * bound at all (covered by the direct API parameter tests), whereas
         * here a key is bound but lacks the private component, so the failure
         * surfaces from the decapsulation itself.
         */
        stage = "encap-only context";
        imb_ml_kem_free(other);
        other = NULL;
        if (imb_ml_kem_new(mb_mgr, alg, &other) != 0)
                goto exit;
        if (imb_ml_kem_set_pubkey(other, buf_ek) != 0)
                goto exit;
        if (imb_ml_kem_encap(other, exp_ct, ss_rej, NULL) != 0)
                goto exit;
        if (imb_ml_kem_decap(other, ss_rej2, buf_ct, ct_bytes, NULL) != IMB_ERR_PQC_KEMOP)
                goto exit;
        /* the ciphertext it produced does decapsulate under the private key */
        if (imb_ml_kem_decap(self, ss_rej2, exp_ct, ct_bytes, NULL) != 0)
                goto exit;
        if (memcmp(ss_rej, ss_rej2, ML_KEM_K_BYTES) != 0)
                goto exit;

        ret = 0;
exit:
        if (ret != 0)
                printf("ML-KEM decapsulation negative test failed (%s, stage: %s)\n",
                       ml_kem_alg_name(alg), stage);
        imb_ml_kem_free(other);
        imb_ml_kem_free(self);
        return ret;
}

int
ml_kem_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctxs[3];
        struct test_suite_context *ctx;
        int errors = 0;
        unsigned i;

        test_suite_start(&ctxs[0], "ML-KEM-512");
        test_suite_start(&ctxs[1], "ML-KEM-768");
        test_suite_start(&ctxs[2], "ML-KEM-1024");

        if (!quiet_mode)
                printf("ML-KEM (FIPS 203) known-answer tests:\n");

        for (i = 0; i < DIM(variants); i++) {
                ctx = ml_kem_ctx_for_alg(variants[i].alg, ctxs);
                if (ml_kem_run_combined_vectors(mb_mgr, &variants[i], ctx) < 0)
                        test_suite_update(ctx, 0, 1);
                if (ml_kem_run_encaps_vectors(mb_mgr, &variants[i], ctx) < 0)
                        test_suite_update(ctx, 0, 1);
                if (ml_kem_run_keygen_seed_vectors(mb_mgr, &variants[i], ctx) < 0)
                        test_suite_update(ctx, 0, 1);
                if (ml_kem_run_semi_expanded_decaps_vectors(mb_mgr, &variants[i], ctx) < 0)
                        test_suite_update(ctx, 0, 1);
                if (ml_kem_roundtrip(mb_mgr, variants[i].alg) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
                if (ml_kem_key_negative(mb_mgr, variants[i].alg) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
                if (ml_kem_decap_negative(mb_mgr, variants[i].alg) != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }

        errors += test_suite_end(&ctxs[0]);
        errors += test_suite_end(&ctxs[1]);
        errors += test_suite_end(&ctxs[2]);

        return errors;
}
