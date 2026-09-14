/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * IMB backend glue for the provider's ML-DSA and ML-KEM implementations:
 * key object lifecycle plus thin wrappers over the imb_ml_dsa_*()/imb_ml_kem_*()
 * entry points. The key decode/bind step lives here and runs exactly once per
 * key object - see prov_pqc.h for the caching model.
 */

#include <string.h>
#include <openssl/crypto.h>

#include "prov_pqc.h"

/* ------------------------------------------------------------------------- */
/* Parameter set tables                                                      */
/* ------------------------------------------------------------------------- */

static const PROV_ML_DSA_VARIANT prov_ml_dsa_variants[] = {
        { IMB_ML_DSA_44, "ML-DSA-44", IMB_ML_DSA_44_PUBKEY_BYTES, IMB_ML_DSA_44_PRIVKEY_BYTES,
          IMB_ML_DSA_44_SIG_BYTES, 128 },
        { IMB_ML_DSA_65, "ML-DSA-65", IMB_ML_DSA_65_PUBKEY_BYTES, IMB_ML_DSA_65_PRIVKEY_BYTES,
          IMB_ML_DSA_65_SIG_BYTES, 192 },
        { IMB_ML_DSA_87, "ML-DSA-87", IMB_ML_DSA_87_PUBKEY_BYTES, IMB_ML_DSA_87_PRIVKEY_BYTES,
          IMB_ML_DSA_87_SIG_BYTES, 256 },
};

static const PROV_ML_KEM_VARIANT prov_ml_kem_variants[] = {
        { IMB_ML_KEM_512, "ML-KEM-512", IMB_ML_KEM_512_PUBKEY_BYTES, IMB_ML_KEM_512_PRIVKEY_BYTES,
          IMB_ML_KEM_512_CIPHERTEXT_BYTES, 128 },
        { IMB_ML_KEM_768, "ML-KEM-768", IMB_ML_KEM_768_PUBKEY_BYTES, IMB_ML_KEM_768_PRIVKEY_BYTES,
          IMB_ML_KEM_768_CIPHERTEXT_BYTES, 192 },
        { IMB_ML_KEM_1024, "ML-KEM-1024", IMB_ML_KEM_1024_PUBKEY_BYTES,
          IMB_ML_KEM_1024_PRIVKEY_BYTES, IMB_ML_KEM_1024_CIPHERTEXT_BYTES, 256 },
};

const PROV_ML_DSA_VARIANT *
prov_ml_dsa_variant(IMB_ML_DSA_ALG alg)
{
        size_t i;

        for (i = 0; i < IMB_DIM(prov_ml_dsa_variants); i++)
                if (prov_ml_dsa_variants[i].alg == alg)
                        return &prov_ml_dsa_variants[i];
        return NULL;
}

const PROV_ML_KEM_VARIANT *
prov_ml_kem_variant(IMB_ML_KEM_ALG alg)
{
        size_t i;

        for (i = 0; i < IMB_DIM(prov_ml_kem_variants); i++)
                if (prov_ml_kem_variants[i].alg == alg)
                        return &prov_ml_kem_variants[i];
        return NULL;
}

/* ------------------------------------------------------------------------- */
/* ML-DSA                                                                    */
/* ------------------------------------------------------------------------- */

PROV_ML_DSA_KEY *
prov_ml_dsa_key_new(OSSL_LIB_CTX *libctx, const PROV_ML_DSA_VARIANT *v)
{
        PROV_ML_DSA_KEY *key;

        if (v == NULL || ipsec_mgr == NULL)
                return NULL;

        key = OPENSSL_zalloc(sizeof(*key));
        if (key == NULL)
                return NULL;

        key->libctx = libctx;
        key->v = v;
        /* imb_ctx is allocated on first generate */
        return key;
}

void
prov_ml_dsa_key_free(PROV_ML_DSA_KEY *key)
{
        if (key == NULL)
                return;

        if (key->imb_ctx != NULL)
                imb_ml_dsa_free(key->imb_ctx);
        OPENSSL_clear_free(key->buf_storage, key->v->pubkey_len + key->v->privkey_len);
        OPENSSL_cleanse(key->seed, sizeof(key->seed));
        OPENSSL_free(key);
}

/* Allocate the encoded key buffers the requested selection needs */
static int
prov_ml_dsa_key_alloc(PROV_ML_DSA_KEY *key, int want_pub, int want_priv)
{
        if (!want_pub && !want_priv)
                return 1;
        if (key->buf_storage == NULL) {
                key->buf_storage = OPENSSL_zalloc(key->v->pubkey_len + key->v->privkey_len);
                if (key->buf_storage == NULL)
                        return 0;
                key->pub = key->buf_storage;
                key->priv = key->buf_storage + key->v->pubkey_len;
        }
        if (want_pub && key->pub == NULL)
                key->pub = key->buf_storage;
        if (want_priv && key->priv == NULL)
                key->priv = key->buf_storage + key->v->pubkey_len;
        return 1;
}

int
prov_ml_dsa_key_generate(PROV_ML_DSA_KEY *key, const unsigned char *seed)
{
        IMB_ML_DSA_KEYGEN_PARAMS params;

        IMB_ML_DSA_KEYGEN_PARAMS_INIT(&params);

        if (key == NULL)
                return 0;

        /* Create the IMB context if not already provided by the caller */
        if (key->imb_ctx == NULL) {
                if (ipsec_mgr == NULL)
                        return 0;
                if (imb_ml_dsa_new(ipsec_mgr, key->v->alg, &key->imb_ctx) != 0)
                        return 0;
        }

        if (!prov_ml_dsa_key_alloc(key, 1, 1))
                return 0;

        if (seed != NULL) {
                params.xi_32 = seed;
                params.xi_len = IMB_ML_DSA_KEYGEN_SEED_BYTES;
        }

        if (imb_ml_dsa_keypair(key->imb_ctx, key->pub, key->v->pubkey_len, key->priv,
                               key->v->privkey_len, &params) != 0)
                return 0;

        if (seed != NULL) {
                memcpy(key->seed, seed, sizeof(key->seed));
                key->has_seed = 1;
        }
        key->has_pub = 1;
        key->has_priv = 1;
        key->bound = 1;
        return 1;
}

int
prov_ml_dsa_key_bind(PROV_ML_DSA_KEY *key)
{
        if (key == NULL)
                return 0;

        /* Clear bound flag to allow re-binding on import */
        key->bound = 0;

        /* Create the IMB context for imported keys */
        if (key->imb_ctx == NULL) {
                if (ipsec_mgr == NULL)
                        return 0;
                if (imb_ml_dsa_new(ipsec_mgr, key->v->alg, &key->imb_ctx) != 0)
                        return 0;
        }

        /*
         * A private key carries the public component too, so binding it covers
         * both the sign and the verify path.
         */
        if (key->has_priv) {
                if (imb_ml_dsa_set_privkey(key->imb_ctx, key->priv, key->v->privkey_len) != 0)
                        return 0;
        } else if (key->has_pub) {
                if (imb_ml_dsa_set_pubkey(key->imb_ctx, key->pub, key->v->pubkey_len) != 0)
                        return 0;
        } else {
                return 0;
        }

        key->bound = 1;
        return 1;
}

PROV_ML_DSA_KEY *
prov_ml_dsa_key_dup(const PROV_ML_DSA_KEY *key, int selection)
{
        PROV_ML_DSA_KEY *ret;
        int want_pub, want_priv;

        if (key == NULL)
                return NULL;

        want_pub = key->has_pub && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
        want_priv = key->has_priv && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

        ret = prov_ml_dsa_key_new(key->libctx, key->v);
        if (ret == NULL)
                return NULL;

        if (!prov_ml_dsa_key_alloc(ret, want_pub, want_priv))
                goto err;

        if (want_pub) {
                memcpy(ret->pub, key->pub, key->v->pubkey_len);
                ret->has_pub = 1;
        }
        if (want_priv) {
                memcpy(ret->priv, key->priv, key->v->privkey_len);
                ret->has_priv = 1;
                if (key->has_seed) {
                        memcpy(ret->seed, key->seed, sizeof(ret->seed));
                        ret->has_seed = 1;
                }
        }

        /* The copy gets its own IMB context, so bind the key material into it */
        if ((want_pub || want_priv) && !prov_ml_dsa_key_bind(ret))
                goto err;

        return ret;
err:
        prov_ml_dsa_key_free(ret);
        return NULL;
}

int
prov_ml_dsa_key_sign(const PROV_ML_DSA_KEY *key, unsigned char *sig, size_t *sig_len,
                     const unsigned char *msg, size_t msg_len, const unsigned char *ctx_string,
                     size_t ctx_string_len, const unsigned char *rnd_32, int msg_is_mu)
{
        IMB_ML_DSA_SIGN_PARAMS params;

        IMB_ML_DSA_SIGN_PARAMS_INIT(&params);

        if (key == NULL || !key->bound || !key->has_priv)
                return 0;

        /* As in OpenSSL, a pre-computed mu already binds the context string */
        params.ctx = (!msg_is_mu && ctx_string_len != 0) ? ctx_string : NULL;
        params.ctx_len = msg_is_mu ? 0 : ctx_string_len;
        params.rnd_32 = rnd_32;
        params.rnd_len = (rnd_32 != NULL) ? IMB_ML_DSA_SIGN_RND_BYTES : 0;
        params.msg_is_mu = msg_is_mu;

        return imb_ml_dsa_sign(key->imb_ctx, sig, sig_len, msg, msg_len, &params) == 0;
}

int
prov_ml_dsa_key_verify(const PROV_ML_DSA_KEY *key, const unsigned char *msg, size_t msg_len,
                       const unsigned char *sig, size_t sig_len, const unsigned char *ctx_string,
                       size_t ctx_string_len, int msg_is_mu)
{
        IMB_ML_DSA_VERIFY_PARAMS params;

        IMB_ML_DSA_VERIFY_PARAMS_INIT(&params);

        if (key == NULL || !key->bound || !key->has_pub)
                return 0;

        /* As in OpenSSL, a pre-computed mu already binds the context string */
        params.ctx = (!msg_is_mu && ctx_string_len != 0) ? ctx_string : NULL;
        params.ctx_len = msg_is_mu ? 0 : ctx_string_len;
        params.msg_is_mu = msg_is_mu;

        return imb_ml_dsa_verify(key->imb_ctx, msg, msg_len, sig, sig_len, &params) == 0;
}

/* ------------------------------------------------------------------------- */
/* ML-KEM                                                                    */
/* ------------------------------------------------------------------------- */

PROV_ML_KEM_KEY *
prov_ml_kem_key_new(OSSL_LIB_CTX *libctx, const PROV_ML_KEM_VARIANT *v)
{
        PROV_ML_KEM_KEY *key;

        if (v == NULL || ipsec_mgr == NULL)
                return NULL;

        key = OPENSSL_zalloc(sizeof(*key));
        if (key == NULL)
                return NULL;

        key->libctx = libctx;
        key->v = v;
        key->pub = key->buf_storage;
        key->priv = key->buf_storage + key->v->pubkey_len;
        /* imb_ctx is allocated on first bind/generate */
        return key;
}

void
prov_ml_kem_key_free(PROV_ML_KEM_KEY *key)
{
        if (key == NULL)
                return;

        if (key->imb_ctx != NULL)
                imb_ml_kem_free(key->imb_ctx);
        OPENSSL_cleanse(key->buf_storage, key->v->pubkey_len + key->v->privkey_len);
        OPENSSL_cleanse(key->seed, sizeof(key->seed));
        OPENSSL_free(key);
}

int
prov_ml_kem_key_alloc(PROV_ML_KEM_KEY *key, int want_pub, int want_priv)
{
        if (key == NULL)
                return 0;
        if (!want_pub && !want_priv)
                return 1;
        /* Storage is inline in the key object; just (re)point field aliases. */
        if (want_pub && key->pub == NULL)
                key->pub = key->buf_storage;
        if (want_priv && key->priv == NULL)
                key->priv = key->buf_storage + key->v->pubkey_len;
        return 1;
}

int
prov_ml_kem_key_generate(PROV_ML_KEM_KEY *key, const unsigned char *seed)
{
        IMB_ML_KEM_KEYGEN_PARAMS params;

        IMB_ML_KEM_KEYGEN_PARAMS_INIT(&params);

        if (key == NULL)
                return 0;

        /* Create the IMB context if not already provided by the caller */
        if (key->imb_ctx == NULL) {
                if (ipsec_mgr == NULL)
                        return 0;
                if (imb_ml_kem_new(ipsec_mgr, key->v->alg, &key->imb_ctx) != 0)
                        return 0;
        }

        if (!prov_ml_kem_key_alloc(key, 1, 1))
                return 0;

        if (seed != NULL) {
                params.seed_d_z = seed;
                params.seed_d_z_len = IMB_ML_KEM_KEYGEN_SEED_BYTES;
        }

        if (imb_ml_kem_keypair(key->imb_ctx, key->pub, key->v->pubkey_len, key->priv,
                               key->v->privkey_len, &params) != 0)
                return 0;

        if (seed != NULL) {
                memcpy(key->seed, seed, sizeof(key->seed));
                key->has_seed = 1;
        }
        key->has_pub = 1;
        key->has_priv = 1;
        key->bound = 1;
        return 1;
}

int
prov_ml_kem_key_bind(PROV_ML_KEM_KEY *key)
{
        if (key == NULL)
                return 0;

        /* Clear bound flag to allow re-binding on import */
        key->bound = 0;

        /* Create the IMB context for imported keys */
        if (key->imb_ctx == NULL) {
                if (ipsec_mgr == NULL)
                        return 0;
                if (imb_ml_kem_new(ipsec_mgr, key->v->alg, &key->imb_ctx) != 0)
                        return 0;
        }

        /*
         * A decapsulation key carries the encapsulation key too, so binding it
         * covers both the encapsulate and the decapsulate path.
         */
        if (key->has_priv) {
                if (imb_ml_kem_set_privkey(key->imb_ctx, key->priv, key->v->privkey_len) != 0)
                        return 0;
        } else if (key->has_pub) {
                if (imb_ml_kem_set_pubkey(key->imb_ctx, key->pub, key->v->pubkey_len) != 0)
                        return 0;
        } else {
                return 0;
        }

        key->bound = 1;
        return 1;
}

IMB_ML_KEM *
prov_ml_kem_op_ctx_new(const PROV_ML_KEM_KEY *key)
{
        IMB_ML_KEM *op_ctx = NULL;

        if (key == NULL || !key->bound)
                return NULL;

        if (imb_ml_kem_new(ipsec_mgr, key->v->alg, &op_ctx) != 0)
                return NULL;

        /*
         * A decapsulation key carries the encapsulation key too, so binding it
         * covers both the encapsulate and the decapsulate path.
         */
        if (key->has_priv) {
                if (imb_ml_kem_set_privkey(op_ctx, key->priv, key->v->privkey_len) != 0)
                        goto err;
        } else if (key->has_pub) {
                if (imb_ml_kem_set_pubkey(op_ctx, key->pub, key->v->pubkey_len) != 0)
                        goto err;
        } else {
                goto err;
        }
        return op_ctx;
err:
        imb_ml_kem_free(op_ctx);
        return NULL;
}

PROV_ML_KEM_KEY *
prov_ml_kem_key_dup(const PROV_ML_KEM_KEY *key, int selection)
{
        PROV_ML_KEM_KEY *ret;
        int want_pub, want_priv;

        if (key == NULL)
                return NULL;

        want_pub = key->has_pub && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
        want_priv = key->has_priv && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

        ret = prov_ml_kem_key_new(key->libctx, key->v);
        if (ret == NULL)
                return NULL;

        if (!prov_ml_kem_key_alloc(ret, want_pub, want_priv))
                goto err;

        if (want_pub) {
                memcpy(ret->pub, key->pub, key->v->pubkey_len);
                ret->has_pub = 1;
        }
        if (want_priv) {
                memcpy(ret->priv, key->priv, key->v->privkey_len);
                ret->has_priv = 1;
                if (key->has_seed) {
                        memcpy(ret->seed, key->seed, sizeof(ret->seed));
                        ret->has_seed = 1;
                }
        }

        if ((want_pub || want_priv) && !prov_ml_kem_key_bind(ret))
                goto err;

        return ret;
err:
        prov_ml_kem_key_free(ret);
        return NULL;
}
