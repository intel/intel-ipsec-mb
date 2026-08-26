/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_PQC_H
#define PROV_PQC_H

#include <stddef.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <intel-ipsec-mb.h>

/*
 * ML-DSA and ML-KEM support for imb-provider.
 */

extern IMB_MGR *ipsec_mgr;

/*
 * Parameter names introduced by OpenSSL 3.5 for ML-DSA/ML-KEM. Defined here so
 * the provider also builds against older OpenSSL headers.
 */
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif
#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MU
#define OSSL_SIGNATURE_PARAM_MU "mu"
#endif
#ifndef OSSL_SIGNATURE_PARAM_TEST_ENTROPY
#define OSSL_SIGNATURE_PARAM_TEST_ENTROPY "test-entropy"
#endif
#ifndef OSSL_SIGNATURE_PARAM_SIGNATURE
#define OSSL_SIGNATURE_PARAM_SIGNATURE "signature"
#endif
#ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
#define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
#endif
#ifndef OSSL_PKEY_PARAM_ML_KEM_SEED
#define OSSL_PKEY_PARAM_ML_KEM_SEED "seed"
#endif
#ifndef OSSL_KEM_PARAM_IKME
#define OSSL_KEM_PARAM_IKME "ikme"
#endif

/* xi seed and signing randomizer sizes */
#define PROV_ML_DSA_SEED_BYTES 32
#define PROV_ML_DSA_RND_BYTES  32
/* mu length */
#define PROV_ML_DSA_MU_BYTES 64
/* ctx string */
#define PROV_ML_DSA_MAX_CONTEXT_STRING_BYTES 255
/* (d || z) seed and encapsulation randomness sizes */
#define PROV_ML_KEM_SEED_BYTES 64
#define PROV_ML_KEM_M_BYTES    32

/* ------------------------------------------------------------------------- */
/* ML-DSA                                                                    */
/* ------------------------------------------------------------------------- */

typedef struct prov_ml_dsa_variant_st {
        IMB_ML_DSA_ALG alg;
        const char *name;
        size_t pubkey_len;
        size_t privkey_len;
        size_t sig_len;
        int security_bits;
} PROV_ML_DSA_VARIANT;

typedef struct prov_ml_dsa_key_st {
        OSSL_LIB_CTX *libctx;
        const PROV_ML_DSA_VARIANT *v;
        IMB_ML_DSA *imb_ctx; // holds the decoded key
        unsigned char *pub;  // encoded public key
        unsigned char *priv; // encoded private key
        unsigned char seed[PROV_ML_DSA_SEED_BYTES];
        unsigned int has_pub : 1;
        unsigned int has_priv : 1;
        unsigned int has_seed : 1;
        unsigned int bound : 1; // key material already cached in imb_ctx
} PROV_ML_DSA_KEY;

/**
 * Return the static variant descriptor for the given IMB ML-DSA algorithm
 * selector, or NULL.
 */
const PROV_ML_DSA_VARIANT *
prov_ml_dsa_variant(IMB_ML_DSA_ALG alg);

PROV_ML_DSA_KEY *
prov_ml_dsa_key_new(OSSL_LIB_CTX *libctx, const PROV_ML_DSA_VARIANT *v);

void
prov_ml_dsa_key_free(PROV_ML_DSA_KEY *key);

PROV_ML_DSA_KEY *
prov_ml_dsa_key_dup(const PROV_ML_DSA_KEY *key, int selection);

int
prov_ml_dsa_key_generate(PROV_ML_DSA_KEY *key, const unsigned char *seed);

/**
 * Decode the encoded key material held by \a key and cache it inside the key
 * object's IMB context.
 */
int
prov_ml_dsa_key_bind(PROV_ML_DSA_KEY *key);

int
prov_ml_dsa_key_sign(const PROV_ML_DSA_KEY *key, unsigned char *sig, size_t *sig_len,
                     const unsigned char *msg, size_t msg_len, const unsigned char *ctx_string,
                     size_t ctx_string_len, const unsigned char *rnd_32, int msg_is_mu);

int
prov_ml_dsa_key_verify(const PROV_ML_DSA_KEY *key, const unsigned char *msg, size_t msg_len,
                       const unsigned char *sig, size_t sig_len, const unsigned char *ctx_string,
                       size_t ctx_string_len, int msg_is_mu);

/* ------------------------------------------------------------------------- */
/* ML-KEM                                                                    */
/* ------------------------------------------------------------------------- */

typedef struct prov_ml_kem_variant_st {
        IMB_ML_KEM_ALG alg;
        const char *name;
        size_t pubkey_len;
        size_t privkey_len;
        size_t ct_len;
        int security_bits;
} PROV_ML_KEM_VARIANT;

typedef struct prov_ml_kem_key_st {
        OSSL_LIB_CTX *libctx;
        const PROV_ML_KEM_VARIANT *v;
        IMB_ML_KEM *imb_ctx;
        unsigned char *pub;
        unsigned char *priv;
        unsigned char seed[PROV_ML_KEM_SEED_BYTES];
        unsigned int has_pub : 1;
        unsigned int has_priv : 1;
        unsigned int has_seed : 1;
        unsigned int bound : 1;
} PROV_ML_KEM_KEY;

/**
 * Return the static variant descriptor for the given IMB ML-KEM algorithm
 * selector, or NULL.
 */
const PROV_ML_KEM_VARIANT *
prov_ml_kem_variant(IMB_ML_KEM_ALG alg);

PROV_ML_KEM_KEY *
prov_ml_kem_key_new(OSSL_LIB_CTX *libctx, const PROV_ML_KEM_VARIANT *v);

void
prov_ml_kem_key_free(PROV_ML_KEM_KEY *key);

PROV_ML_KEM_KEY *
prov_ml_kem_key_dup(const PROV_ML_KEM_KEY *key, int selection);

int
prov_ml_kem_key_generate(PROV_ML_KEM_KEY *key, const unsigned char *seed);

int
prov_ml_kem_key_bind(PROV_ML_KEM_KEY *key);

/**
 * Allocate and return a fresh IMB_ML_KEM context with the key material.
 */
IMB_ML_KEM *
prov_ml_kem_op_ctx_new(const PROV_ML_KEM_KEY *key);

/**
 * @brief Copy an octet string parameter of exactly \a len bytes into \a out.
 *
 * Shared helper used by both prov_mldsa.c and prov_mlkem.c to validate and
 * extract fixed-size OSSL_PARAM octet strings.
 *
 * @param [in]  p   Parameter to read from.
 * @param [out] out Destination buffer of at least \a len bytes.
 * @param [in]  len Expected exact data size in bytes.
 * @return 1 on success, 0 on type mismatch, NULL data, or wrong size.
 */
static inline int
prov_get_fixed_octets(const OSSL_PARAM *p, unsigned char *out, size_t len)
{
        if (p->data_type != OSSL_PARAM_OCTET_STRING || p->data == NULL || p->data_size != len) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                return 0;
        }
        memcpy(out, p->data, len);
        return 1;
}

#endif /* PROV_PQC_H */
