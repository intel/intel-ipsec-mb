/*******************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * ML-KEM (FIPS 203) KEYMGMT and KEM operations for imb-provider, backed by the
 * IMB imb_ml_kem_*() API.
 *
 * Key material is decoded once - during key generation or key import - and
 * cached inside the key object's IMB context. encapsulate_init()/
 * decapsulate_init() only latch onto that already populated key object, and
 * every encapsulate/decapsulate call reuses the cached key. See prov_pqc.h for
 * the full lifecycle description.
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

#define PROV_ML_KEM_KEY_POOL 4

/* Key generation context: one parameter set plus an optional keygen seed */
typedef struct prov_ml_kem_gen_ctx_st {
        OSSL_LIB_CTX *libctx;
        const PROV_ML_KEM_VARIANT *v;
        unsigned char seed[PROV_ML_KEM_SEED_BYTES];
        unsigned int seed_set : 1;
        IMB_ML_KEM *imb_ctx;
        PROV_ML_KEM_KEY *key_pool[PROV_ML_KEM_KEY_POOL];
        int key_pool_count;
} PROV_ML_KEM_GEN_CTX;

static void
prov_ml_kem_recycle_key(PROV_ML_KEM_GEN_CTX *genctx, PROV_ML_KEM_KEY *key)
{
        if (genctx == NULL || key == NULL)
                return;

        key->owner_gen = genctx;
        key->in_pool = 1;
        key->bound = 0;
        key->imb_ctx = NULL;

        /*
         * Keep the pooled backing store live for the next generation and avoid
         * zeroizing that storage on every recycle. The next generation call
         * overwrites the same public/private key material, while prov_ml_kem_key_free()
         * still scrubs once when the object is actually discarded.
         */
        if (genctx->key_pool_count < PROV_ML_KEM_KEY_POOL) {
                genctx->key_pool[genctx->key_pool_count++] = key;
                return;
        }

        key->owner_gen = NULL;
        key->in_pool = 0;
        prov_ml_kem_key_free(key);
}

static PROV_ML_KEM_KEY *
prov_ml_kem_get_reusable_key(PROV_ML_KEM_GEN_CTX *genctx)
{
        PROV_ML_KEM_KEY *key;

        if (genctx == NULL || genctx->key_pool_count == 0)
                return NULL;

        key = genctx->key_pool[--genctx->key_pool_count];
        key->in_pool = 0;
        key->owner_gen = genctx;
        key->bound = 0;
        key->imb_ctx = NULL;
        key->pub = key->buf_storage;
        key->priv = key->buf_storage + key->v->pubkey_len;
        return key;
}

static void
prov_ml_kem_freekey(void *keydata)
{
        PROV_ML_KEM_KEY *key = (PROV_ML_KEM_KEY *) keydata;

        if (key == NULL)
                return;

        if (key->owner_gen != NULL) {
                prov_ml_kem_recycle_key((PROV_ML_KEM_GEN_CTX *) key->owner_gen, key);
                return;
        }

        prov_ml_kem_key_free(key);
}

static void *
prov_ml_kem_dupkey(const void *keydata, int selection)
{
        if (!prov_is_running())
                return NULL;

        return prov_ml_kem_key_dup((const PROV_ML_KEM_KEY *) keydata, selection);
}

static int
prov_ml_kem_has(const void *keydata, int selection)
{
        const PROV_ML_KEM_KEY *key = (const PROV_ML_KEM_KEY *) keydata;

        if (key == NULL)
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return 1;
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && !key->has_pub)
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !key->has_priv)
                return 0;
        return 1;
}

static int
prov_ml_kem_match(const void *keydata1, const void *keydata2, int selection)
{
        const PROV_ML_KEM_KEY *k1 = (const PROV_ML_KEM_KEY *) keydata1;
        const PROV_ML_KEM_KEY *k2 = (const PROV_ML_KEM_KEY *) keydata2;

        if (k1 == NULL || k2 == NULL)
                return 0;
        if (k1->v != k2->v)
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return 1;

        /*
         * A decapsulation key embeds its encapsulation key, so comparing the
         * public component is enough to decide whether two keys match.
         */
        if (k1->has_pub && k2->has_pub)
                return CRYPTO_memcmp(k1->pub, k2->pub, k1->v->pubkey_len) == 0;
        return 0;
}

static int
prov_ml_kem_validate(const void *keydata, int selection, int checktype)
{
        const PROV_ML_KEM_KEY *key = (const PROV_ML_KEM_KEY *) keydata;
        IMB_ML_KEM *ctx;
        IMB_ML_KEM *tmp = NULL;
        int ret = 0;

        (void) checktype; /* full/quick distinction not implemented */

        if (key == NULL)
                return 0;

        ctx = key->imb_ctx;
        if (ctx == NULL) {
                /*
                 * Generated keys have no cached IMB context (keygen borrows
                 * the genctx's shared context and clears it afterwards).
                 */
                if (ipsec_mgr == NULL || imb_ml_kem_new(ipsec_mgr, key->v->alg, &tmp) != 0)
                        return 0;
                ctx = tmp;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
                if (!key->has_priv)
                        goto out;
                if (imb_ml_kem_privkey_validate(ctx, key->priv, key->v->privkey_len) != 0)
                        goto out;
        }
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
                if (!key->has_pub)
                        goto out;
                if (imb_ml_kem_pubkey_validate(ctx, key->pub, key->v->pubkey_len) != 0)
                        goto out;
        }
        ret = 1;
out:
        imb_ml_kem_free(tmp);
        return ret;
}

static int
prov_ml_kem_import(void *keydata, int selection, const OSSL_PARAM params[])
{
        PROV_ML_KEM_KEY *key = (PROV_ML_KEM_KEY *) keydata;
        const OSSL_PARAM *p_priv, *p_pub, *p_seed;

        if (key == NULL || !prov_is_running())
                return 0;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return 0;
        if (params == NULL)
                return 0;

        p_priv = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        p_pub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        p_seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED);

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
                p_priv = NULL;
                p_seed = NULL;
        }

        if (p_priv != NULL) {
                if (!prov_get_fixed_octets(p_priv, key->priv, key->v->privkey_len))
                        return 0;
                key->has_priv = 1;
                /*
                 * FIPS 203 stores the encapsulation key inside the decapsulation
                 * key: bytes [384*k .. 768*k+32) of dk. Always recover it here
                 * so that it can be compared against any separately supplied
                 * public key bytes rather than silently overwritten.
                 */
                memcpy(key->pub,
                       key->priv + (key->v->privkey_len - key->v->pubkey_len -
                                    2 * IMB_ML_KEM_SHARED_SECRET_BYTES),
                       key->v->pubkey_len);
                key->has_pub = 1;
        }

        if (p_pub != NULL) {
                if (key->has_pub) {
                        /*
                         * The public key was already recovered from the private
                         * key bytes.  Verify the supplied value matches rather
                         * than silently replacing it: a mismatch indicates an
                         * inconsistent key pair.
                         */
                        unsigned char *supplied = OPENSSL_malloc(key->v->pubkey_len);
                        if (supplied == NULL)
                                return 0;
                        if (!prov_get_fixed_octets(p_pub, supplied, key->v->pubkey_len)) {
                                OPENSSL_free(supplied);
                                return 0;
                        }
                        if (CRYPTO_memcmp(key->pub, supplied, key->v->pubkey_len) != 0) {
                                OPENSSL_free(supplied);
                                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                                return 0;
                        }
                        OPENSSL_free(supplied);
                } else {
                        if (!prov_get_fixed_octets(p_pub, key->pub, key->v->pubkey_len))
                                return 0;
                        key->has_pub = 1;
                }
        }

        if (p_priv == NULL && p_pub == NULL && p_seed != NULL) {
                /* Seed-only import: regenerate the key pair from (d || z) */
                if (!prov_get_fixed_octets(p_seed, key->seed, sizeof(key->seed)))
                        return 0;
                if (!prov_ml_kem_key_generate(key, key->seed)) {
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

        /* Decode and cache the key inside the IMB context - done exactly once */
        if (!prov_ml_kem_key_bind(key)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return 0;
        }
        return 1;
}

static int
prov_ml_kem_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
        PROV_ML_KEM_KEY *key = (PROV_ML_KEM_KEY *) keydata;
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
                        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                                                 key->seed, sizeof(key->seed));
        }

        if (p == params)
                return 0;

        *p = OSSL_PARAM_construct_end();
        return param_cb(params, cbarg);
}

static const OSSL_PARAM prov_ml_kem_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_kem_imexport_types(int selection)
{
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
                return NULL;
        return prov_ml_kem_key_types;
}

static const OSSL_PARAM prov_ml_kem_gettable_params_list[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, NULL, 0),
        OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_kem_gettable_params(void *provctx)
{
        return prov_ml_kem_gettable_params_list;
}

static int
prov_ml_kem_get_params(void *keydata, OSSL_PARAM params[])
{
        PROV_ML_KEM_KEY *key = (PROV_ML_KEM_KEY *) keydata;
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
        if (p != NULL && !OSSL_PARAM_set_int(p, (int) key->v->ct_len))
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
                p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_KEM_SEED);
                if (p != NULL && !OSSL_PARAM_set_octet_string(p, key->seed, sizeof(key->seed)))
                        return 0;
        }
        return 1;
}

static const OSSL_PARAM prov_ml_kem_settable_params_list[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_kem_settable_params(void *provctx)
{
        return prov_ml_kem_settable_params_list;
}

static int
prov_ml_kem_set_params(void *keydata, const OSSL_PARAM params[])
{
        PROV_ML_KEM_KEY *key = (PROV_ML_KEM_KEY *) keydata;
        const OSSL_PARAM *p;

        if (key == NULL)
                return 0;
        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p != NULL) {
                if (!prov_get_fixed_octets(p, key->pub, key->v->pubkey_len))
                        return 0;

                /*
                 * Replacing the key material is an explicit key change, so the
                 * IMB context is re-populated here (once) rather than per
                 * operation. Any previously held private key is dropped.
                 */
                OPENSSL_cleanse(key->priv, key->v->privkey_len);
                key->priv = key->buf_storage + key->v->pubkey_len;
                key->has_priv = 0;
                key->has_seed = 0;
                key->has_pub = 1;
                key->bound = 0;
                if (!prov_ml_kem_key_bind(key)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                        return 0;
                }
        }
        return 1;
}

static int
prov_ml_kem_gen_set_params(void *vgenctx, const OSSL_PARAM params[])
{
        PROV_ML_KEM_GEN_CTX *genctx = (PROV_ML_KEM_GEN_CTX *) vgenctx;
        const OSSL_PARAM *p;

        if (genctx == NULL)
                return 0;
        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED);
        if (p != NULL) {
                if (!prov_get_fixed_octets(p, genctx->seed, sizeof(genctx->seed)))
                        return 0;
                genctx->seed_set = 1;
        }
        return 1;
}

static const OSSL_PARAM prov_ml_kem_gen_settable_params_list[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_kem_gen_settable_params(void *vgenctx, void *provctx)
{
        return prov_ml_kem_gen_settable_params_list;
}

static void *
prov_ml_kem_gen_init(void *provctx, int selection, const OSSL_PARAM params[], IMB_ML_KEM_ALG alg)
{
        PROV_ML_KEM_GEN_CTX *genctx;
        const PROV_ML_KEM_VARIANT *v = prov_ml_kem_variant(alg);

        if (!prov_is_running() || v == NULL)
                return NULL;

        genctx = OPENSSL_zalloc(sizeof(*genctx));
        if (genctx == NULL)
                return NULL;

        genctx->libctx = prov_libctx_of((PROV_CTX *) provctx);
        genctx->v = v;

        if (!prov_ml_kem_gen_set_params(genctx, params)) {
                OPENSSL_free(genctx);
                return NULL;
        }

        /*
         * Pre-allocate one IMB context for the lifetime of this gen context.
         * prov_ml_kem_gen() borrows it for each keypair call and returns it
         * afterwards so the hot path does not fall back to lazy allocation on
         * every generation. Treat an allocation failure as fatal here: a silent
         * fallback would turn the provider back into the slower per-call path.
         */
        if (imb_ml_kem_new(ipsec_mgr, v->alg, &genctx->imb_ctx) != 0) {
                OPENSSL_free(genctx);
                return NULL;
        }

        return genctx;
}

static void
prov_ml_kem_gen_reclaim_pool(PROV_ML_KEM_GEN_CTX *genctx)
{
        int i;

        if (genctx == NULL)
                return;

        for (i = 0; i < genctx->key_pool_count; i++) {
                PROV_ML_KEM_KEY *key = genctx->key_pool[i];
                if (key == NULL)
                        continue;
                key->owner_gen = NULL;
                key->in_pool = 0;
                prov_ml_kem_key_free(key);
        }
        genctx->key_pool_count = 0;
}

/**
 * Generate the key pair. imb_ml_kem_keypair() also caches the freshly generated
 * key inside the key object's IMB context, so this is the only place key
 * material is decoded for a generated key.
 */
static void *
prov_ml_kem_gen(void *vgenctx, OSSL_CALLBACK *cb, void *cbarg)
{
        PROV_ML_KEM_GEN_CTX *genctx = (PROV_ML_KEM_GEN_CTX *) vgenctx;
        PROV_ML_KEM_KEY *key;

        (void) cb;
        (void) cbarg;

        if (genctx == NULL || !prov_is_running())
                return NULL;

        key = prov_ml_kem_get_reusable_key(genctx);
        if (key == NULL)
                key = prov_ml_kem_key_new(genctx->libctx, genctx->v);
        if (key == NULL)
                return NULL;

        key->owner_gen = genctx;
        if (!prov_ml_kem_key_alloc(key, 1, 1)) {
                prov_ml_kem_freekey(key);
                return NULL;
        }

        /*
         * Borrow the pre-allocated IMB context for the keypair call. The key
         * does not take ownership: encap/decap each get their own per-operation
         * context via prov_ml_kem_op_ctx_new(). The context is returned to
         * genctx on both the success and failure paths below.
         */
        key->imb_ctx = genctx->imb_ctx;
        genctx->imb_ctx = NULL;

        if (!prov_ml_kem_key_generate(key, genctx->seed_set ? genctx->seed : NULL)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
                genctx->imb_ctx = key->imb_ctx;
                key->imb_ctx = NULL;
                prov_ml_kem_key_free(key);
                return NULL;
        }

        /*
         * Return the borrowed IMB context to the generation context so the next
         * call stays on the cached fast path. If the context was unexpectedly
         * dropped by an earlier failure path, create a replacement before the
         * next generation request lands.
         */
        genctx->imb_ctx = key->imb_ctx;
        key->imb_ctx = NULL;
        if (genctx->imb_ctx == NULL && ipsec_mgr != NULL)
                (void) imb_ml_kem_new(ipsec_mgr, genctx->v->alg, &genctx->imb_ctx);
        return key;
}

static void
prov_ml_kem_gen_cleanup(void *vgenctx)
{
        PROV_ML_KEM_GEN_CTX *genctx = (PROV_ML_KEM_GEN_CTX *) vgenctx;

        if (genctx == NULL)
                return;
        prov_ml_kem_gen_reclaim_pool(genctx);
        imb_ml_kem_free(genctx->imb_ctx);
        OPENSSL_clear_free(vgenctx, sizeof(PROV_ML_KEM_GEN_CTX));
}

/* ========================================================================= */
/* KEM                                                                       */
/* ========================================================================= */

#define PROV_ML_KEM_OP_ENCAP 1
#define PROV_ML_KEM_OP_DECAP 2

/** ML-KEM encapsulate/decapsulate operation context */
typedef struct prov_ml_kem_ctx_st {
        const PROV_ML_KEM_VARIANT *v;
        /*
         * Key object holding the cached decoded key. Borrowed from the EVP_PKEY
         * at encapsulate_init()/decapsulate_init() time - never re-decoded here.
         */
        PROV_ML_KEM_KEY *key;
        int op;
        /* Caller-supplied encapsulation randomness (FIPS 203 "m") */
        unsigned char ikme[PROV_ML_KEM_M_BYTES];
        unsigned int ikme_set : 1;
        /* Per-operation IMB_ML_KEM context. */
        IMB_ML_KEM *op_imb_ctx;
} PROV_ML_KEM_CTX;

static void *
prov_ml_kem_newctx(void *provctx, IMB_ML_KEM_ALG alg)
{
        PROV_ML_KEM_CTX *ctx;
        const PROV_ML_KEM_VARIANT *v = prov_ml_kem_variant(alg);

        if (!prov_is_running() || v == NULL)
                return NULL;

        ctx = OPENSSL_zalloc(sizeof(*ctx));
        if (ctx == NULL)
                return NULL;

        ctx->v = v;
        return ctx;
}

static void
prov_ml_kem_freectx(void *vctx)
{
        PROV_ML_KEM_CTX *ctx = (PROV_ML_KEM_CTX *) vctx;

        if (ctx == NULL)
                return;
        imb_ml_kem_free(ctx->op_imb_ctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *
prov_ml_kem_dupctx(void *vctx)
{
        PROV_ML_KEM_CTX *src = (PROV_ML_KEM_CTX *) vctx;
        PROV_ML_KEM_CTX *dst;

        if (src == NULL || !prov_is_running())
                return NULL;

        dst = OPENSSL_memdup(src, sizeof(*src));
        if (dst == NULL)
                return NULL;
        dst->op_imb_ctx = NULL;

        if (src->op_imb_ctx != NULL) {
                dst->op_imb_ctx = prov_ml_kem_op_ctx_new(src->key);
                if (dst->op_imb_ctx == NULL) {
                        OPENSSL_free(dst);
                        return NULL;
                }
        }
        return dst;
}

static int
prov_ml_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int
prov_ml_kem_init(void *vctx, void *vkey, const OSSL_PARAM params[], int op)
{
        PROV_ML_KEM_CTX *ctx = (PROV_ML_KEM_CTX *) vctx;
        PROV_ML_KEM_KEY *key = (PROV_ML_KEM_KEY *) vkey;

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
        if (op == PROV_ML_KEM_OP_ENCAP && !ctx->key->has_pub) {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
                return 0;
        }
        if (op == PROV_ML_KEM_OP_DECAP && !ctx->key->has_priv) {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
                return 0;
        }
        if (!ctx->key->bound) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return 0;
        }

        /*
         * Create a fresh per-operation IMB context so that concurrent
         * EVP_PKEY_CTXs sharing the same EVP_PKEY do not race on key->imb_ctx.
         */
        imb_ml_kem_free(ctx->op_imb_ctx);
        ctx->op_imb_ctx = prov_ml_kem_op_ctx_new(ctx->key);
        if (ctx->op_imb_ctx == NULL) {
                ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
                return 0;
        }

        ctx->op = op;
        return prov_ml_kem_set_ctx_params(ctx, params);
}

static int
prov_ml_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
        return prov_ml_kem_init(vctx, vkey, params, PROV_ML_KEM_OP_ENCAP);
}

static int
prov_ml_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
        return prov_ml_kem_init(vctx, vkey, params, PROV_ML_KEM_OP_DECAP);
}

static int
prov_ml_kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen, unsigned char *secret,
                        size_t *secretlen)
{
        PROV_ML_KEM_CTX *ctx = (PROV_ML_KEM_CTX *) vctx;

        if (ctx == NULL || ctx->key == NULL)
                return 0;
        if (ctx->op != PROV_ML_KEM_OP_ENCAP) {
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                return 0;
        }

        /* Size query: either output buffer may be absent */
        if (out == NULL) {
                if (outlen == NULL)
                        return 0;
                *outlen = ctx->v->ct_len;
                if (secretlen != NULL)
                        *secretlen = IMB_ML_KEM_SHARED_SECRET_BYTES;
                return 1;
        }
        if (secret == NULL) {
                if (secretlen == NULL)
                        return 0;
                *secretlen = IMB_ML_KEM_SHARED_SECRET_BYTES;
                if (outlen != NULL)
                        *outlen = ctx->v->ct_len;
                return 1;
        }

        if (outlen != NULL && *outlen < ctx->v->ct_len) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
        }
        if (secretlen != NULL && *secretlen < IMB_ML_KEM_SHARED_SECRET_BYTES) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
        }

        {
                IMB_ML_KEM_ENCAP_PARAMS p;
                int rc;

                IMB_ML_KEM_ENCAP_PARAMS_INIT(&p);
                p.m_32 = ctx->ikme_set ? ctx->ikme : NULL;
                p.m_len = ctx->ikme_set ? IMB_ML_KEM_ENCAP_SEED_BYTES : 0;
                rc = imb_ml_kem_encap(ctx->op_imb_ctx, out, ctx->v->ct_len, secret,
                                      IMB_ML_KEM_SHARED_SECRET_BYTES, &p);
                if (ctx->ikme_set) {
                        OPENSSL_cleanse(ctx->ikme, sizeof(ctx->ikme));
                        ctx->ikme_set = 0;
                }
                if (rc != 0)
                        return 0;
        }

        if (outlen != NULL)
                *outlen = ctx->v->ct_len;
        if (secretlen != NULL)
                *secretlen = IMB_ML_KEM_SHARED_SECRET_BYTES;
        return 1;
}

static int
prov_ml_kem_decapsulate(void *vctx, unsigned char *out, size_t *outlen, const unsigned char *in,
                        size_t inlen)
{
        PROV_ML_KEM_CTX *ctx = (PROV_ML_KEM_CTX *) vctx;

        if (ctx == NULL || ctx->key == NULL)
                return 0;
        if (ctx->op != PROV_ML_KEM_OP_DECAP) {
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
                return 0;
        }

        /* Size query */
        if (out == NULL) {
                if (outlen == NULL)
                        return 0;
                *outlen = IMB_ML_KEM_SHARED_SECRET_BYTES;
                return 1;
        }
        if (outlen != NULL && *outlen < IMB_ML_KEM_SHARED_SECRET_BYTES) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
        }
        if (inlen != ctx->v->ct_len) {
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
                return 0;
        }

        if (imb_ml_kem_decap(ctx->op_imb_ctx, out, IMB_ML_KEM_SHARED_SECRET_BYTES, in, inlen,
                             NULL) != 0)
                return 0;

        if (outlen != NULL)
                *outlen = IMB_ML_KEM_SHARED_SECRET_BYTES;
        return 1;
}

static const OSSL_PARAM prov_ml_kem_gettable_ctx_params_list[] = { OSSL_PARAM_END };

static const OSSL_PARAM *
prov_ml_kem_gettable_ctx_params(void *vctx, void *provctx)
{
        return prov_ml_kem_gettable_ctx_params_list;
}

static int
prov_ml_kem_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
        return vctx != NULL;
}

static const OSSL_PARAM prov_ml_kem_settable_ctx_params_list[] = {
        OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_ml_kem_settable_ctx_params(void *vctx, void *provctx)
{
        return prov_ml_kem_settable_ctx_params_list;
}

static int
prov_ml_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        PROV_ML_KEM_CTX *ctx = (PROV_ML_KEM_CTX *) vctx;
        const OSSL_PARAM *p;

        if (ctx == NULL)
                return 0;
        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
        if (p != NULL) {
                if (p->data == NULL) {
                        ctx->ikme_set = 0;
                } else {
                        if (!prov_get_fixed_octets(p, ctx->ikme, sizeof(ctx->ikme)))
                                return 0;
                        ctx->ikme_set = 1;
                }
        }
        return 1;
}

/* ========================================================================= */
/* Per parameter set dispatch tables                                         */
/* ========================================================================= */

#define PROV_ML_KEM_IMPLEMENT(variant, imbalg)                                                     \
        static void *prov_ml_kem_##variant##_new_key(void *provctx)                                \
        {                                                                                          \
                if (!prov_is_running())                                                            \
                        return NULL;                                                               \
                return prov_ml_kem_key_new(prov_libctx_of((PROV_CTX *) provctx),                   \
                                           prov_ml_kem_variant(imbalg));                           \
        }                                                                                          \
        static void *prov_ml_kem_##variant##_gen_init(void *provctx, int selection,                \
                                                      const OSSL_PARAM params[])                   \
        {                                                                                          \
                return prov_ml_kem_gen_init(provctx, selection, params, imbalg);                   \
        }                                                                                          \
        static const char *prov_ml_kem_##variant##_query_operation_name(int operation_id)          \
        {                                                                                          \
                return (operation_id == OSSL_OP_KEM) ? "ML-KEM-" #variant : NULL;                  \
        }                                                                                          \
        static void *prov_ml_kem_##variant##_newctx(void *provctx)                                 \
        {                                                                                          \
                return prov_ml_kem_newctx(provctx, imbalg);                                        \
        }                                                                                          \
        const OSSL_DISPATCH prov_ml_kem_##variant##_keymgmt_functions[] = {                        \
                { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) prov_ml_kem_##variant##_new_key },       \
                { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) prov_ml_kem_freekey },                  \
                { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void)) prov_ml_kem_dupkey },                    \
                { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) prov_ml_kem_##variant##_gen_init }, \
                { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) prov_ml_kem_gen_set_params }, \
                { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                           \
                  (void (*)(void)) prov_ml_kem_gen_settable_params },                              \
                { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) prov_ml_kem_gen },                       \
                { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) prov_ml_kem_gen_cleanup },       \
                { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) prov_ml_kem_get_params },         \
                { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                               \
                  (void (*)(void)) prov_ml_kem_gettable_params },                                  \
                { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void)) prov_ml_kem_set_params },         \
                { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                               \
                  (void (*)(void)) prov_ml_kem_settable_params },                                  \
                { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) prov_ml_kem_has },                       \
                { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) prov_ml_kem_match },                   \
                { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void)) prov_ml_kem_validate },             \
                { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) prov_ml_kem_import },                 \
                { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) prov_ml_kem_imexport_types },   \
                { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) prov_ml_kem_export },                 \
                { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) prov_ml_kem_imexport_types },   \
                { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                          \
                  (void (*)(void)) prov_ml_kem_##variant##_query_operation_name },                 \
                { 0, NULL }                                                                        \
        };                                                                                         \
        const OSSL_DISPATCH prov_ml_kem_##variant##_kem_functions[] = {                            \
                { OSSL_FUNC_KEM_NEWCTX, (void (*)(void)) prov_ml_kem_##variant##_newctx },         \
                { OSSL_FUNC_KEM_FREECTX, (void (*)(void)) prov_ml_kem_freectx },                   \
                { OSSL_FUNC_KEM_DUPCTX, (void (*)(void)) prov_ml_kem_dupctx },                     \
                { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void)) prov_ml_kem_encapsulate_init }, \
                { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void)) prov_ml_kem_encapsulate },           \
                { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void)) prov_ml_kem_decapsulate_init }, \
                { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void)) prov_ml_kem_decapsulate },           \
                { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void)) prov_ml_kem_get_ctx_params },     \
                { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,                                               \
                  (void (*)(void)) prov_ml_kem_gettable_ctx_params },                              \
                { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void)) prov_ml_kem_set_ctx_params },     \
                { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,                                               \
                  (void (*)(void)) prov_ml_kem_settable_ctx_params },                              \
                { 0, NULL }                                                                        \
        };

/* prov_ml_kem_512_keymgmt_functions / prov_ml_kem_512_kem_functions */
PROV_ML_KEM_IMPLEMENT(512, IMB_ML_KEM_512)
/* prov_ml_kem_768_keymgmt_functions / prov_ml_kem_768_kem_functions */
PROV_ML_KEM_IMPLEMENT(768, IMB_ML_KEM_768)
/* prov_ml_kem_1024_keymgmt_functions / prov_ml_kem_1024_kem_functions */
PROV_ML_KEM_IMPLEMENT(1024, IMB_ML_KEM_1024)
