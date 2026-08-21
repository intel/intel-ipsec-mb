/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Portable C backend for the IMB ML-KEM (FIPS 203) API. Each operation is a
 * thin, self-contained adapter over the vendored OpenSSL ML-KEM core
 * (ossl_ml_kem_*).
 *
 * The decoded/generated ML_KEM_KEY is cached in self->key across calls:
 * keypair() generates it once, set_privkey()/set_pubkey() decode it once, and
 * every encap/decap call reuses that cached key instead of re-decoding and
 * re-expanding the public matrix. This matches the key-lifecycle model used
 * by OpenSSL's own ML-KEM provider (decode/import once at keymgmt time, reuse
 * the cached key for every KEM operation), and is also what FIPS 203 Section
 * 3.3 "Destruction of intermediate values" exception 2 (the expanded public
 * matrix) is built on: the vendored key object already caches key->rho/
 * key->m across calls, so simply not re-deriving a fresh ML_KEM_KEY per
 * operation is sufficient to realise that exception. All glue-level
 * sensitive locals are wiped on every return path; the vendored core's own
 * OPENSSL_cleanse()/CONSTTIME_* calls (already covering every other
 * intermediate value per exception 1, the retained KeyGen seed) are left
 * untouched.
 *
 * The decoders below use self->ek_len / self->dk_len as the caller's buffer
 * length; imb_ml_kem_api.c rejects a mismatched size before dispatching here.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>

#include "ml_kem_internal.h"

#include "crypto/ml_kem.h" /* ossl_ml_kem_* core entry points */
#include "imb_rand.h"
#include "clear_regs_mem.h"

#define ML_KEM_SEED_D_Z_BYTES 64
#define ML_KEM_M_BYTES        32

/* ------------------------------------------------------------------------- */
/* Key binding helpers                                                       */
/* ------------------------------------------------------------------------- */
static void
key_unbind(IMB_ML_KEM *self)
{
        ossl_ml_kem_key_free(self->key);
        self->key = NULL;
}

void
imb_ml_kem_backend_free_key(IMB_ML_KEM *self)
{
        if (self == NULL)
                return;
        ossl_ml_kem_key_free(self->key);
        self->key = NULL;
}

/* ------------------------------------------------------------------------- */
/* Key generation                                                            */
/* ------------------------------------------------------------------------- */
static int
op_keypair(IMB_ML_KEM *self, void *ek, void *dk, const void *seed_64_or_null)
{
        ML_KEM_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_kem_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /* A non-NULL seed requests deterministic generation from (d, z); a
         * NULL seed leaves the key's seedbuf unset, so ossl_ml_kem_genkey()
         * draws fresh randomness internally. Either way, ek is encoded
         * directly by genkey() as an efficiency side effect. */
        if (seed_64_or_null != NULL &&
            ossl_ml_kem_set_seed(seed_64_or_null, ML_KEM_SEED_D_Z_BYTES, key) == NULL)
                goto end;

        if (!ossl_ml_kem_genkey(self, ek, self->ek_len, key))
                goto end;

        if (!ossl_ml_kem_encode_private_key(dk, self->dk_len, key))
                goto end;

        /* Bind the freshly generated key (both components) to the context. */
        key_unbind(self);
        self->key = key;
        key = NULL;
        rc = 0;
end:
        ossl_ml_kem_key_free(key);
        return rc;
}

/* ------------------------------------------------------------------------- */
/* Key binding (decode once, cache, reuse for every subsequent operation)    */
/* ------------------------------------------------------------------------- */
static int
op_set_privkey(IMB_ML_KEM *self, const void *dk)
{
        ML_KEM_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_kem_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /* parse_private_key also derives/checks the public component and
         * the embedded pubkey-hash consistency check (FIPS 203 Section 7.3
         * decapsulation key check). */
        if (!ossl_ml_kem_parse_private_key(dk, self->dk_len, key))
                goto end;

        key_unbind(self);
        self->key = key;
        key = NULL;
        rc = 0;
end:
        ossl_ml_kem_key_free(key);
        return rc;
}

static int
op_set_pubkey(IMB_ML_KEM *self, const void *ek)
{
        ML_KEM_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_kem_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /* parse_public_key enforces the encoded length and coefficient
         * ranges (FIPS 203 Section 7.2 encapsulation key check). */
        if (!ossl_ml_kem_parse_public_key(ek, self->ek_len, key))
                goto end;

        key_unbind(self);
        self->key = key;
        key = NULL;
        rc = 0;
end:
        ossl_ml_kem_key_free(key);
        return rc;
}

/* ------------------------------------------------------------------------- */
/* Encapsulation                                                             */
/* ------------------------------------------------------------------------- */
static int
op_encap(IMB_ML_KEM *self, void *ct, void *shared_secret, const void *m_32_or_null)
{
        if (self->key == NULL || !ossl_ml_kem_have_pubkey(self->key))
                return -1;

        if (m_32_or_null != NULL)
                return ossl_ml_kem_encap_seed(self, ct, self->ct_len, shared_secret,
                                              IMB_ML_KEM_SHARED_SECRET_BYTES, m_32_or_null,
                                              ML_KEM_M_BYTES, self->key)
                               ? 0
                               : -1;

        return ossl_ml_kem_encap_rand(self, ct, self->ct_len, shared_secret,
                                      IMB_ML_KEM_SHARED_SECRET_BYTES, self->key)
                       ? 0
                       : -1;
}

/* ------------------------------------------------------------------------- */
/* Decapsulation                                                             */
/* ------------------------------------------------------------------------- */
static int
op_decap(IMB_ML_KEM *self, void *shared_secret, const void *ct, size_t ct_len)
{
        if (self->key == NULL || !ossl_ml_kem_have_prvkey(self->key))
                return -1;

        /*
         * ossl_ml_kem_decap() unconditionally rejects a ciphertext whose
         * length does not match the bound parameter set (FIPS 203 Section
         * 7.3 "ciphertext type check", which "shall be performed with every
         * execution", unlike the two key checks above). ct_len is passed
         * through verbatim from the caller so that check can never be
         * bypassed - do not substitute self->ct_len here.
         */
        return ossl_ml_kem_decap(self, shared_secret, IMB_ML_KEM_SHARED_SECRET_BYTES, ct, ct_len,
                                 self->key)
                       ? 0
                       : -1;
}

/* ------------------------------------------------------------------------- */
/* Key validation (stateless: do not touch self->key)                       */
/* ------------------------------------------------------------------------- */
static int
op_pubkey_validate(IMB_ML_KEM *self, const void *ek)
{
        ML_KEM_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_kem_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        if (!ossl_ml_kem_parse_public_key(ek, self->ek_len, key))
                goto end;

        rc = 0;
end:
        ossl_ml_kem_key_free(key);
        return rc;
}

static int
op_privkey_validate(IMB_ML_KEM *self, const void *dk)
{
        ML_KEM_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_kem_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /*
         * parse_private_key rebuilds the public key from the private key
         * and checks that the embedded public-key hash matches, i.e. it is a
         * full consistency check (FIPS 203 Section 7.3 decapsulation key
         * check, the "modified H" ACVP negative case).
         */
        if (!ossl_ml_kem_parse_private_key(dk, self->dk_len, key))
                goto end;

        rc = 0;
end:
        ossl_ml_kem_key_free(key);
        return rc;
}

/* ------------------------------------------------------------------------- */
/* Backend selection                                                         */
/* ------------------------------------------------------------------------- */
int
imb_ml_kem_backend_init_portable(IMB_ML_KEM *self)
{
        switch (self->alg) {
        case IMB_ML_KEM_512:
                self->evp_type = EVP_PKEY_ML_KEM_512;
                self->ek_len = IMB_ML_KEM_512_PUBKEY_BYTES;
                self->dk_len = IMB_ML_KEM_512_PRIVKEY_BYTES;
                self->ct_len = IMB_ML_KEM_512_CIPHERTEXT_BYTES;
                break;
        case IMB_ML_KEM_768:
                self->evp_type = EVP_PKEY_ML_KEM_768;
                self->ek_len = IMB_ML_KEM_768_PUBKEY_BYTES;
                self->dk_len = IMB_ML_KEM_768_PRIVKEY_BYTES;
                self->ct_len = IMB_ML_KEM_768_CIPHERTEXT_BYTES;
                break;
        case IMB_ML_KEM_1024:
                self->evp_type = EVP_PKEY_ML_KEM_1024;
                self->ek_len = IMB_ML_KEM_1024_PUBKEY_BYTES;
                self->dk_len = IMB_ML_KEM_1024_PRIVKEY_BYTES;
                self->ct_len = IMB_ML_KEM_1024_CIPHERTEXT_BYTES;
                break;
        default:
                return -1;
        }

        self->key = NULL;
        self->keypair = op_keypair;
        self->set_privkey = op_set_privkey;
        self->set_pubkey = op_set_pubkey;
        self->encap = op_encap;
        self->decap = op_decap;
        self->pubkey_validate = op_pubkey_validate;
        self->privkey_validate = op_privkey_validate;
        return 0;
}
