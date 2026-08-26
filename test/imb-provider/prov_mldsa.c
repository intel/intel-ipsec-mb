/*******************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * ML-DSA KEYMGMT and SIGNATURE operations for imb-provider,
 * backed by the IMB imb_ml_dsa_*() API.
 *
 * Key material is decoded once - during key generation or key import - and
 * cached inside the key object's IMB context. Every sign/verify call
 * reuses the cached key.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "prov_pqc.h"
#include "prov_provider.h"

/* ========================================================================= */
/* KEYMGMT                                                                   */
/* ========================================================================= */

/** Key generation context: one parameter set plus an optional keygen seed */
typedef struct prov_ml_dsa_gen_ctx_st {
        OSSL_LIB_CTX *libctx;
        const PROV_ML_DSA_VARIANT *v;
        unsigned char seed[PROV_ML_DSA_SEED_BYTES];
        unsigned int seed_set : 1;
        IMB_ML_DSA *imb_ctx;
} PROV_ML_DSA_GEN_CTX;

static void
prov_ml_dsa_freekey(void *keydata)
{
        prov_ml_dsa_key_free((PROV_ML_DSA_KEY *) keydata);
}

static void *
prov_ml_dsa_dupkey(const void *keydata, int selection)
{
        if (!prov_is_running())
                return NULL;

        return prov_ml_dsa_key_dup((const PROV_ML_DSA_KEY *) keydata, selection);
}

static int
prov_ml_dsa_has(const void *keydata, int selection)
{
        const PROV_ML_DSA_KEY *key = (const PROV_ML_DSA_KEY *) keydata;

        if (key == NULL)
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return 1; /* keypair not selected, nothing to check */
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && !key->has_pub)
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !key->has_priv)
                return 0;
        return 1;
}

static int
prov_ml_dsa_match(const void *keydata1, const void *keydata2, int selection)
{
        const PROV_ML_DSA_KEY *k1 = (const PROV_ML_DSA_KEY *) keydata1;
        const PROV_ML_DSA_KEY *k2 = (const PROV_ML_DSA_KEY *) keydata2;

        if (k1 == NULL || k2 == NULL)
                return 0;
        if (k1->v != k2->v)
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return 1;
        /* only compare pub keys */
        if (k1->has_pub && k2->has_pub)
                return CRYPTO_memcmp(k1->pub, k2->pub, k1->v->pubkey_len) == 0;
        return 0;
}

static int
prov_ml_dsa_validate(const void *keydata, int selection, int checktype)
{
        const PROV_ML_DSA_KEY *key = (const PROV_ML_DSA_KEY *) keydata;

        (void) checktype; /* full/quick distinction not implemented */

        if (key == NULL || key->imb_ctx == NULL)
                return 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
                if (!key->has_priv)
                        return 0;
                if (imb_ml_dsa_privkey_validate(key->imb_ctx, key->priv, key->v->privkey_len) != 0)
                        return 0;
        }
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
                if (!key->has_pub)
                        return 0;
                if (imb_ml_dsa_pubkey_validate(key->imb_ctx, key->pub, key->v->pubkey_len) != 0)
                        return 0;
        }
        return 1;
}

static int
prov_ml_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
        PROV_ML_DSA_KEY *key = (PROV_ML_DSA_KEY *) keydata;
        const OSSL_PARAM *p_priv, *p_pub, *p_seed;

        if (key == NULL || !prov_is_running())
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return 0;
        if (params == NULL)
                return 0;

        p_priv = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        p_pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        p_seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
                p_priv = NULL;
                p_seed = NULL;
        }

        if (p_priv != NULL) {
                if (key->priv == NULL) {
                        key->priv = OPENSSL_malloc(key->v->privkey_len);
                        if (key->priv == NULL)
                                return 0;
                }
                if (!prov_get_fixed_octets(p_priv, key->priv, key->v->privkey_len))
                        return 0;
                key->has_priv = 1;
        }

        if (p_pub != NULL) {
                if (key->pub == NULL) {
                        key->pub = OPENSSL_malloc(key->v->pubkey_len);
                        if (key->pub == NULL)
                                return 0;
                }
                if (!prov_get_fixed_octets(p_pub, key->pub, key->v->pubkey_len))
                        return 0;
                key->has_pub = 1;
        }

        if (p_priv == NULL && p_pub == NULL && p_seed != NULL) {
                /* Seed-only import: regenerate the key pair from the seed */
                if (!prov_get_fixed_octets(p_seed, key->seed, sizeof(key->seed)))
                        return 0;
                if (!prov_ml_dsa_key_generate(key, key->seed)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
                        return 0;
                }
                return 1;
        }

        if (!key->has_priv && !key->has_pub) {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
                return 0;
        }

        if (p_seed != NULL) {
                if (!prov_get_fixed_octets(p_seed, key->seed, sizeof(key->seed)))
                        return 0;
                key->has_seed = 1;
        }

        if (key->has_priv) {
                /* Ensure the IMB context exists for pubkey derivation */
                if (key->imb_ctx == NULL &&
                    imb_ml_dsa_new(ipsec_mgr, key->v->alg, &key->imb_ctx) != 0)
                        return 0;

                if (key->has_pub) {
                        /*
                         * Both components were supplied: verify that the public
                         * key is consistent with the private key rather than
                         * silently accepting a mismatched pair.
                         */
                        unsigned char *derived = OPENSSL_malloc(key->v->pubkey_len);
                        if (derived == NULL)
                                return 0;
                        if (imb_ml_dsa_pubkey_from_privkey(key->imb_ctx, key->priv,
                                                           key->v->privkey_len, derived,
                                                           key->v->pubkey_len) != 0) {
                                OPENSSL_free(derived);
                                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                                return 0;
                        }
                        if (CRYPTO_memcmp(key->pub, derived, key->v->pubkey_len) != 0) {
                                OPENSSL_free(derived);
                                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                                return 0;
                        }
                        OPENSSL_free(derived);
                } else {
                        /* Derive and store the public key from the private one */
                        if (key->pub == NULL) {
                                key->pub = OPENSSL_malloc(key->v->pubkey_len);
                                if (key->pub == NULL)
                                        return 0;
                        }
                        if (imb_ml_dsa_pubkey_from_privkey(key->imb_ctx, key->priv,
                                                           key->v->privkey_len, key->pub,
                                                           key->v->pubkey_len) != 0) {
                                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                                return 0;
                        }
                        key->has_pub = 1;
                }
        }

        /* Decode and cache the key inside the IMB context - done exactly once */
        if (!prov_ml_dsa_key_bind(key)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return 0;
        }
        return 1;
}

static int
prov_ml_dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
        PROV_ML_DSA_KEY *key = (PROV_ML_DSA_KEY *) keydata;
        OSSL_PARAM params[4], *p = params;

        if (key == NULL || !prov_is_running())
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_pub)
                *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, key->pub,
                                                         key->v->pubkey_len);
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_priv) {
                *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, key->priv,
                                                         key->v->privkey_len);
                if (key->has_seed)
                        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                                 key->seed, sizeof(key->seed));
        }

        if (p == params)
                return 0;

        *p = OSSL_PARAM_construct_end();
        return param_cb(params, cbarg);
}

static const OSSL_PARAM prov_ml_dsa_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_dsa_imexport_types(int selection)
{
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return NULL;
        return prov_ml_dsa_key_types;
}

static const OSSL_PARAM prov_ml_dsa_gettable_params_list[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
        OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_dsa_gettable_params(void *provctx)
{
        return prov_ml_dsa_gettable_params_list;
}

static int
prov_ml_dsa_get_params(void *keydata, OSSL_PARAM params[])
{
        PROV_ML_DSA_KEY *key = (PROV_ML_DSA_KEY *) keydata;
        OSSL_PARAM *p;

        if (key == NULL)
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, (int) (key->v->pubkey_len * 8)))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, key->v->security_bits))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL && !OSSL_PARAM_set_int(p, (int) key->v->sig_len))
                return 0;

        if (key->has_pub) {
                p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
                if (p != NULL && !OSSL_PARAM_set_octet_string(p, key->pub, key->v->pubkey_len))
                        return 0;
                p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
                if (p != NULL && !OSSL_PARAM_set_octet_string(p, key->pub, key->v->pubkey_len))
                        return 0;
        }
        if (key->has_priv) {
                p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
                if (p != NULL && !OSSL_PARAM_set_octet_string(p, key->priv, key->v->privkey_len))
                        return 0;
        }
        if (key->has_seed) {
                p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
                if (p != NULL && !OSSL_PARAM_set_octet_string(p, key->seed, sizeof(key->seed)))
                        return 0;
        }
        return 1;
}

static const OSSL_PARAM prov_ml_dsa_settable_params_list[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_dsa_settable_params(void *provctx)
{
        return prov_ml_dsa_settable_params_list;
}

static int
prov_ml_dsa_set_params(void *keydata, const OSSL_PARAM params[])
{
        PROV_ML_DSA_KEY *key = (PROV_ML_DSA_KEY *) keydata;
        const OSSL_PARAM *p;

        if (key == NULL)
                return 0;
        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p != NULL) {
                if (key->pub == NULL) {
                        key->pub = OPENSSL_malloc(key->v->pubkey_len);
                        if (key->pub == NULL)
                                return 0;
                }
                if (!prov_get_fixed_octets(p, key->pub, key->v->pubkey_len))
                        return 0;

                /*
                 * Replacing the key material is an explicit key change, so the
                 * IMB context is re-populated here (once) rather than per
                 * operation. Any previously held private key is dropped.
                 */
                OPENSSL_clear_free(key->priv, key->v->privkey_len);
                key->priv = NULL;
                key->has_priv = 0;
                key->has_seed = 0;
                key->has_pub = 1;
                key->bound = 0;
                if (!prov_ml_dsa_key_bind(key)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                        return 0;
                }
        }
        return 1;
}

static int
prov_ml_dsa_gen_set_params(void *vgenctx, const OSSL_PARAM params[])
{
        PROV_ML_DSA_GEN_CTX *genctx = (PROV_ML_DSA_GEN_CTX *) vgenctx;
        const OSSL_PARAM *p;

        if (genctx == NULL)
                return 0;
        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
        if (p != NULL) {
                if (!prov_get_fixed_octets(p, genctx->seed, sizeof(genctx->seed)))
                        return 0;
                genctx->seed_set = 1;
        }
        return 1;
}

static const OSSL_PARAM prov_ml_dsa_gen_settable_params_list[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_dsa_gen_settable_params(void *vgenctx, void *provctx)
{
        return prov_ml_dsa_gen_settable_params_list;
}

static void *
prov_ml_dsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[], IMB_ML_DSA_ALG alg)
{
        PROV_ML_DSA_GEN_CTX *genctx;
        const PROV_ML_DSA_VARIANT *v = prov_ml_dsa_variant(alg);

        if (!prov_is_running() || v == NULL)
                return NULL;

        genctx = OPENSSL_zalloc(sizeof(*genctx));
        if (genctx == NULL)
                return NULL;

        genctx->libctx = prov_libctx_of((PROV_CTX *) provctx);
        genctx->v = v;

        if (!prov_ml_dsa_gen_set_params(genctx, params)) {
                OPENSSL_free(genctx);
                return NULL;
        }

        /*
         * Pre-allocate one IMB context for the lifetime of this gen context.
         * prov_ml_dsa_gen() steals it into the key and replenishes genctx
         * afterwards, keeping allocation off the keygen hot path. A NULL
         * result here is non-fatal: prov_ml_dsa_key_generate() will fall back
         * to lazy allocation when genctx->imb_ctx is NULL.
         */
        (void) imb_ml_dsa_new(ipsec_mgr, v->alg, &genctx->imb_ctx);

        return genctx;
}

static void *
prov_ml_dsa_gen(void *vgenctx, OSSL_CALLBACK *cb, void *cbarg)
{
        PROV_ML_DSA_GEN_CTX *genctx = (PROV_ML_DSA_GEN_CTX *) vgenctx;
        PROV_ML_DSA_KEY *key;

        (void) cb;
        (void) cbarg;

        if (genctx == NULL || !prov_is_running())
                return NULL;

        key = prov_ml_dsa_key_new(genctx->libctx, genctx->v);
        if (key == NULL)
                return NULL;

        /*
         * Steal the pre-allocated IMB context into the key. The key retains
         * it permanently for sign/verify. If genctx->imb_ctx is NULL (the
         * pre-allocation in gen_init failed, or the last gen call failed and
         * left it NULL), key_generate falls back to lazy allocation.
         */
        key->imb_ctx = genctx->imb_ctx;
        genctx->imb_ctx = NULL;

        if (!prov_ml_dsa_key_generate(key, genctx->seed_set ? genctx->seed : NULL)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
                /*
                 * Return whatever IMB context key_generate left in the key
                 * back to genctx so the next gen call stays on the fast path.
                 */
                genctx->imb_ctx = key->imb_ctx;
                key->imb_ctx = NULL;
                prov_ml_dsa_key_free(key);
                return NULL;
        }

        /* Replenish genctx for the next gen call (non-fatal if it fails) */
        (void) imb_ml_dsa_new(ipsec_mgr, genctx->v->alg, &genctx->imb_ctx);

        return key;
}

static void
prov_ml_dsa_gen_cleanup(void *vgenctx)
{
        PROV_ML_DSA_GEN_CTX *genctx = (PROV_ML_DSA_GEN_CTX *) vgenctx;

        if (genctx == NULL)
                return;
        imb_ml_dsa_free(genctx->imb_ctx);
        OPENSSL_clear_free(vgenctx, sizeof(PROV_ML_DSA_GEN_CTX));
}

/* ========================================================================= */
/* SIGNATURE                                                                 */
/* ========================================================================= */

typedef struct prov_ml_dsa_sig_ctx_st {
        const PROV_ML_DSA_VARIANT *v;
        /*
         * Key object holding the cached decoded key. Borrowed from the EVP_PKEY
         * at sign_init()/verify_init() time.
         */
        PROV_ML_DSA_KEY *key;
        unsigned char ctx_string[PROV_ML_DSA_MAX_CONTEXT_STRING_BYTES];
        size_t ctx_string_len;
        /* Caller-supplied signing randomizer */
        unsigned char test_entropy[PROV_ML_DSA_RND_BYTES];
        unsigned int test_entropy_set : 1;
        unsigned int deterministic : 1;
        unsigned int msg_is_mu : 1;
        /* Message buffer used by the streaming sign/verify-message path */
        unsigned char *msg;
        size_t msg_len;
        size_t msg_alloc;
        /*
         * Signature stored for the OpenSSL 3.5+ verify_message_final ABI where
         * verify_message_final takes only (void *ctx) and the signature to
         * verify against must be supplied beforehand via OSSL_PARAM.
         */
        unsigned char *verify_sig;
        size_t verify_sig_len;
} PROV_ML_DSA_SIG_CTX;

static void *
prov_ml_dsa_sig_newctx(void *provctx, const char *propq, IMB_ML_DSA_ALG alg)
{
        PROV_ML_DSA_SIG_CTX *ctx;
        const PROV_ML_DSA_VARIANT *v = prov_ml_dsa_variant(alg);

        if (!prov_is_running() || v == NULL)
                return NULL;

        ctx = OPENSSL_zalloc(sizeof(*ctx));
        if (ctx == NULL)
                return NULL;

        ctx->v = v;
        return ctx;
}

static void
prov_ml_dsa_sig_freectx(void *vctx)
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;

        if (ctx == NULL)
                return;
        OPENSSL_free(ctx->msg); /* message is not secret key material */
        OPENSSL_free(ctx->verify_sig);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static int
prov_ml_dsa_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static void *
prov_ml_dsa_sig_dupctx(void *vctx)
{
        PROV_ML_DSA_SIG_CTX *src = (PROV_ML_DSA_SIG_CTX *) vctx;
        PROV_ML_DSA_SIG_CTX *dst;

        if (src == NULL || !prov_is_running())
                return NULL;

        dst = OPENSSL_malloc(sizeof(*dst));
        if (dst == NULL)
                return NULL;

        *dst = *src;
        dst->msg = NULL;
        dst->msg_alloc = 0;
        dst->msg_len = 0;
        dst->verify_sig = NULL;
        dst->verify_sig_len = 0;

        if (src->msg_len != 0) {
                dst->msg = OPENSSL_memdup(src->msg, src->msg_len);
                if (dst->msg == NULL) {
                        OPENSSL_free(dst);
                        return NULL;
                }
                dst->msg_alloc = src->msg_len;
                dst->msg_len = src->msg_len;
        }

        if (src->verify_sig != NULL && src->verify_sig_len != 0) {
                dst->verify_sig = OPENSSL_memdup(src->verify_sig, src->verify_sig_len);
                if (dst->verify_sig == NULL) {
                        OPENSSL_free(dst->msg);
                        OPENSSL_free(dst);
                        return NULL;
                }
                dst->verify_sig_len = src->verify_sig_len;
        }
        return dst;
}

static int
prov_ml_dsa_sig_init(void *vctx, void *vkey, const OSSL_PARAM params[], int need_priv)
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;
        PROV_ML_DSA_KEY *key = (PROV_ML_DSA_KEY *) vkey;

        if (ctx == NULL || !prov_is_running())
                return 0;

        if (key != NULL) {
                if (key->v != ctx->v) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                        return 0;
                }
                ctx->key = key;
        }

        if (ctx->key == NULL) {
                ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
                return 0;
        }
        if (need_priv && !ctx->key->has_priv) {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
                return 0;
        }
        if (!need_priv && !ctx->key->has_pub) {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
                return 0;
        }
        if (!ctx->key->bound) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return 0;
        }

        ctx->msg_len = 0;
        ctx->ctx_string_len = 0;
        ctx->test_entropy_set = 0;
        ctx->deterministic = 0;
        ctx->msg_is_mu = 0;
        ctx->verify_sig_len = 0;

        return prov_ml_dsa_sig_set_ctx_params(ctx, params);
}

/* All-zero randomizer requests deterministic signing */
static const unsigned char prov_ml_dsa_zero_rnd[PROV_ML_DSA_RND_BYTES] = { 0 };

static const unsigned char *
prov_ml_dsa_sig_randomizer(const PROV_ML_DSA_SIG_CTX *ctx)
{
        if (ctx->test_entropy_set)
                return ctx->test_entropy;
        if (ctx->deterministic)
                return prov_ml_dsa_zero_rnd;
        return NULL;
}

static int
prov_ml_dsa_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                 const unsigned char *tbs, size_t tbslen)
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;
        size_t produced = sigsize;

        if (ctx == NULL || ctx->key == NULL || siglen == NULL)
                return 0;

        /* Size query */
        if (sig == NULL) {
                *siglen = ctx->v->sig_len;
                return 1;
        }
        if (sigsize < ctx->v->sig_len) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE);
                return 0;
        }
        if (ctx->msg_is_mu && tbslen != PROV_ML_DSA_MU_BYTES) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return 0;
        }

        if (!prov_ml_dsa_key_sign(ctx->key, sig, &produced, tbs, tbslen, ctx->ctx_string,
                                  ctx->ctx_string_len, prov_ml_dsa_sig_randomizer(ctx),
                                  ctx->msg_is_mu))
                return 0;

        *siglen = produced;
        return 1;
}

static int
prov_ml_dsa_verify(void *vctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs,
                   size_t tbslen)
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;

        if (ctx == NULL || ctx->key == NULL)
                return 0;
        if (ctx->msg_is_mu && tbslen != PROV_ML_DSA_MU_BYTES) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return 0;
        }

        return prov_ml_dsa_key_verify(ctx->key, tbs, tbslen, sig, siglen, ctx->ctx_string,
                                      ctx->ctx_string_len, ctx->msg_is_mu);
}

static const OSSL_PARAM prov_ml_dsa_sig_gettable_ctx_params_list[] = {
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_dsa_sig_gettable_ctx_params(void *vctx, void *provctx)
{
        return prov_ml_dsa_sig_gettable_ctx_params_list;
}

static int
prov_ml_dsa_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;
        OSSL_PARAM *p;

        if (ctx == NULL)
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        if (p != NULL && ctx->msg_is_mu && !OSSL_PARAM_set_size_t(p, PROV_ML_DSA_MU_BYTES))
                return 0;
        return 1;
}

static const OSSL_PARAM prov_ml_dsa_sig_settable_ctx_params_list[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, NULL),
#ifdef OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL
        /* Signature to verify against, required before verify_message_final() */
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
        OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_dsa_sig_settable_ctx_params(void *vctx, void *provctx)
{
        return prov_ml_dsa_sig_settable_ctx_params_list;
}

static int
prov_ml_dsa_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;
        const OSSL_PARAM *p;

        if (ctx == NULL)
                return 0;
        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_OCTET_STRING ||
                    p->data_size > sizeof(ctx->ctx_string)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                        return 0;
                }
                if (p->data_size != 0) {
                        if (p->data == NULL) {
                                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                                return 0;
                        }
                        memcpy(ctx->ctx_string, p->data, p->data_size);
                }
                ctx->ctx_string_len = p->data_size;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
        if (p != NULL) {
                if (!prov_get_fixed_octets(p, ctx->test_entropy, sizeof(ctx->test_entropy)))
                        return 0;
                ctx->test_entropy_set = 1;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
        if (p != NULL) {
                int deterministic = 0;

                if (!OSSL_PARAM_get_int(p, &deterministic))
                        return 0;
                ctx->deterministic = (deterministic != 0);
        }

        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU);
        if (p != NULL) {
                int msg_is_mu = 0;

                if (!OSSL_PARAM_get_int(p, &msg_is_mu))
                        return 0;
                ctx->msg_is_mu = (msg_is_mu != 0);
        }

#ifdef OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL
        /*
         * OpenSSL 3.5+ verify_message_final ABI: the signature to verify
         * against is passed via OSSL_PARAM before calling verify_message_final.
         */
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
        if (p != NULL) {
                void *tmp = NULL;
                size_t len = 0;

                if (!OSSL_PARAM_get_octet_string(p, &tmp, 0, &len) || tmp == NULL)
                        return 0;
                OPENSSL_free(ctx->verify_sig);
                ctx->verify_sig = tmp;
                ctx->verify_sig_len = len;
        }
#endif
        return 1;
}

#define PROV_ML_DSA_MAX_MSG_BYTES (16u * 1024u * 1024u)

#ifdef OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL
/*
 * Message-streaming helpers (OpenSSL 3.5+, ID 28-32 all present).
 */
static int
prov_ml_dsa_sig_msg_update(void *vctx, const unsigned char *in, size_t inlen)
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;

        if (ctx == NULL)
                return 0;
        if (inlen == 0)
                return 1;

        if (inlen > PROV_ML_DSA_MAX_MSG_BYTES || ctx->msg_len > PROV_ML_DSA_MAX_MSG_BYTES - inlen) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
                return 0;
        }

        if (ctx->msg_len + inlen > ctx->msg_alloc) {
                /* Overflow-safe capacity doubling */
                size_t newsz = (ctx->msg_alloc != 0) ? ctx->msg_alloc : inlen;
                unsigned char *tmp;

                while (newsz < ctx->msg_len + inlen) {
                        if (newsz > PROV_ML_DSA_MAX_MSG_BYTES / 2) {
                                newsz = ctx->msg_len + inlen;
                                break;
                        }
                        newsz *= 2;
                }

                /* The message is not secret: plain realloc is fine */
                tmp = OPENSSL_realloc(ctx->msg, newsz);
                if (tmp == NULL)
                        return 0;
                ctx->msg = tmp;
                ctx->msg_alloc = newsz;
        }

        memcpy(ctx->msg + ctx->msg_len, in, inlen);
        ctx->msg_len += inlen;
        return 1;
}

static int
prov_ml_dsa_sig_msg_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;

        if (ctx == NULL)
                return 0;
        return prov_ml_dsa_sign(ctx, sig, siglen, sigsize, ctx->msg, ctx->msg_len);
}

static int
prov_ml_dsa_sig_msg_verify_final(void *vctx)
{
        PROV_ML_DSA_SIG_CTX *ctx = (PROV_ML_DSA_SIG_CTX *) vctx;

        if (ctx == NULL)
                return 0;
        if (ctx->verify_sig == NULL || ctx->verify_sig_len == 0) {
                /* Signature must be set via OSSL_SIGNATURE_PARAM_SIGNATURE first */
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                return 0;
        }
        return prov_ml_dsa_verify(ctx, ctx->verify_sig, ctx->verify_sig_len, ctx->msg,
                                  ctx->msg_len);
}

#define PROV_ML_DSA_SIG_MESSAGE_DISPATCH(variant)                                                  \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                                                   \
          (void (*)(void)) prov_ml_dsa_##variant##_sign_init },                                    \
                { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                                         \
                  (void (*)(void)) prov_ml_dsa_##variant##_verify_init },                          \
                { OSSL_FUNC_SIGNATURE_MESSAGE_UPDATE,                                              \
                  (void (*)(void)) prov_ml_dsa_sig_msg_update },                                   \
                { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,                                          \
                  (void (*)(void)) prov_ml_dsa_sig_msg_sign_final },                               \
                { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,                                        \
                  (void (*)(void)) prov_ml_dsa_sig_msg_verify_final },
#else
#define PROV_ML_DSA_SIG_MESSAGE_DISPATCH(variant)
#endif /* OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL */

/* ========================================================================= */
/* Per parameter set dispatch tables                                         */
/* ========================================================================= */

#define PROV_ML_DSA_IMPLEMENT(variant, imbalg)                                                     \
        static void *prov_ml_dsa_##variant##_new_key(void *provctx)                                \
        {                                                                                          \
                if (!prov_is_running())                                                            \
                        return NULL;                                                               \
                return prov_ml_dsa_key_new(prov_libctx_of((PROV_CTX *) provctx),                   \
                                           prov_ml_dsa_variant(imbalg));                           \
        }                                                                                          \
        static void *prov_ml_dsa_##variant##_gen_init(void *provctx, int selection,                \
                                                      const OSSL_PARAM params[])                   \
        {                                                                                          \
                return prov_ml_dsa_gen_init(provctx, selection, params, imbalg);                   \
        }                                                                                          \
        static const char *prov_ml_dsa_##variant##_query_operation_name(int operation_id)          \
        {                                                                                          \
                return (operation_id == OSSL_OP_SIGNATURE) ? "ML-DSA-" #variant : NULL;            \
        }                                                                                          \
        static void *prov_ml_dsa_##variant##_sig_newctx(void *provctx, const char *propq)          \
        {                                                                                          \
                return prov_ml_dsa_sig_newctx(provctx, propq, imbalg);                             \
        }                                                                                          \
        static int prov_ml_dsa_##variant##_sign_init(void *vctx, void *vkey,                       \
                                                     const OSSL_PARAM params[])                    \
        {                                                                                          \
                return prov_ml_dsa_sig_init(vctx, vkey, params, 1);                                \
        }                                                                                          \
        static int prov_ml_dsa_##variant##_verify_init(void *vctx, void *vkey,                     \
                                                       const OSSL_PARAM params[])                  \
        {                                                                                          \
                return prov_ml_dsa_sig_init(vctx, vkey, params, 0);                                \
        }                                                                                          \
        const OSSL_DISPATCH prov_ml_dsa_##variant##_keymgmt_functions[] = {                        \
                { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) prov_ml_dsa_##variant##_new_key },       \
                { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) prov_ml_dsa_freekey },                  \
                { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void)) prov_ml_dsa_dupkey },                    \
                { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) prov_ml_dsa_##variant##_gen_init }, \
                { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) prov_ml_dsa_gen_set_params }, \
                { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                           \
                  (void (*)(void)) prov_ml_dsa_gen_settable_params },                              \
                { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) prov_ml_dsa_gen },                       \
                { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) prov_ml_dsa_gen_cleanup },       \
                { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) prov_ml_dsa_get_params },         \
                { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                               \
                  (void (*)(void)) prov_ml_dsa_gettable_params },                                  \
                { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void)) prov_ml_dsa_set_params },         \
                { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                               \
                  (void (*)(void)) prov_ml_dsa_settable_params },                                  \
                { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) prov_ml_dsa_has },                       \
                { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) prov_ml_dsa_match },                   \
                { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void)) prov_ml_dsa_validate },             \
                { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) prov_ml_dsa_import },                 \
                { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) prov_ml_dsa_imexport_types },   \
                { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) prov_ml_dsa_export },                 \
                { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) prov_ml_dsa_imexport_types },   \
                { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                          \
                  (void (*)(void)) prov_ml_dsa_##variant##_query_operation_name },                 \
                { 0, NULL }                                                                        \
        };                                                                                         \
        const OSSL_DISPATCH prov_ml_dsa_##variant##_signature_functions[] = {                      \
                { OSSL_FUNC_SIGNATURE_NEWCTX,                                                      \
                  (void (*)(void)) prov_ml_dsa_##variant##_sig_newctx },                           \
                { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) prov_ml_dsa_sig_freectx },         \
                { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) prov_ml_dsa_sig_dupctx },           \
                { OSSL_FUNC_SIGNATURE_SIGN_INIT,                                                   \
                  (void (*)(void)) prov_ml_dsa_##variant##_sign_init },                            \
                { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) prov_ml_dsa_sign },                   \
                { OSSL_FUNC_SIGNATURE_VERIFY_INIT,                                                 \
                  (void (*)(void)) prov_ml_dsa_##variant##_verify_init },                          \
                { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) prov_ml_dsa_verify },               \
                PROV_ML_DSA_SIG_MESSAGE_DISPATCH(variant){                                         \
                        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                        \
                        (void (*)(void)) prov_ml_dsa_sig_get_ctx_params },                         \
                { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                                         \
                  (void (*)(void)) prov_ml_dsa_sig_gettable_ctx_params },                          \
                { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                              \
                  (void (*)(void)) prov_ml_dsa_sig_set_ctx_params },                               \
                { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                                         \
                  (void (*)(void)) prov_ml_dsa_sig_settable_ctx_params },                          \
                { 0, NULL }                                                                        \
        };

/* prov_ml_dsa_44_keymgmt_functions / prov_ml_dsa_44_signature_functions */
PROV_ML_DSA_IMPLEMENT(44, IMB_ML_DSA_44)
/* prov_ml_dsa_65_keymgmt_functions / prov_ml_dsa_65_signature_functions */
PROV_ML_DSA_IMPLEMENT(65, IMB_ML_DSA_65)
/* prov_ml_dsa_87_keymgmt_functions / prov_ml_dsa_87_signature_functions */
PROV_ML_DSA_IMPLEMENT(87, IMB_ML_DSA_87)
