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

/*
 * Portable C backend for the IMB ML-DSA (FIPS 204) API. Each operation is a
 * thin, self-contained adapter over the vendored OpenSSL ML-DSA core
 * (ossl_ml_dsa_*).
 *
 * Unlike the previous design, the decoded/generated ML_DSA_KEY is cached in
 * self->key across calls: keypair() generates it once,
 * set_privkey()/set_pubkey() decode (and, for private keys, fully validate)
 * it once, and every sign/verify call reuses that cached key instead of
 * re-decoding and re-validating it. This matches the key-lifecycle model
 * used by OpenSSL's own ML-DSA provider (decode/import once at keymgmt time,
 * reuse the cached key for every signature operation), avoiding the
 * redundant matrix-expand-and-NTT work that a decode-per-call design would
 * otherwise repeat on every sign/verify. All sensitive locals are wiped on
 * every return path.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>

#include "ml_dsa_internal.h"

#include "crypto/ml_dsa.h" /* ossl_ml_dsa_* core entry points */
#include "ml_dsa_local.h"  /* ossl_ml_dsa_pk_encode / sk_encode */
#include "imb_rand.h"
#include "clear_regs_mem.h"

#define ML_DSA_RND_BYTES 32

/* ------------------------------------------------------------------------- */
/* Key binding helpers                                                       */
/* ------------------------------------------------------------------------- */
static void
key_unbind(IMB_ML_DSA *self)
{
        ossl_ml_dsa_key_free(self->key);
        self->key = NULL;
}

void
imb_ml_dsa_backend_free_key(IMB_ML_DSA *self)
{
        if (self == NULL)
                return;
        ossl_ml_dsa_key_free(self->key);
        self->key = NULL;
}

/* ------------------------------------------------------------------------- */
/* Key generation                                                            */
/* ------------------------------------------------------------------------- */
static int
op_keypair(IMB_ML_DSA *self, void *pk, void *sk, const void *xi_32_or_null)
{
        ML_DSA_KEY *key = NULL;
        uint8_t xi[ML_DSA_RND_BYTES] = { 0 };
        const uint8_t *xi_32 = xi_32_or_null;
        const uint8_t *enc;
        int rc = -1;

        /* A NULL seed requests fresh-random key generation. */
        if (xi_32 == NULL) {
                if (imb_get_random(xi, sizeof(xi)) != 0)
                        goto end;
                xi_32 = xi;
        }

        key = ossl_ml_dsa_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /* Seed the key with the caller-supplied 32-byte xi, then derive. */
        if (!ossl_ml_dsa_set_prekey(key, 0, 0, xi_32, ML_DSA_SEED_BYTES, NULL, 0))
                goto end;
        if (!ossl_ml_dsa_generate_key(key))
                goto end;

        enc = ossl_ml_dsa_key_get_pub(key);
        if (enc == NULL || ossl_ml_dsa_key_get_pub_len(key) != self->pk_len)
                goto end;
        memcpy(pk, enc, self->pk_len);

        enc = ossl_ml_dsa_key_get_priv(key);
        if (enc == NULL || ossl_ml_dsa_key_get_priv_len(key) != self->sk_len)
                goto end;
        memcpy(sk, enc, self->sk_len);

        /* Bind the freshly generated key (both components) to the context. */
        key_unbind(self);
        self->key = key;
        key = NULL;
        rc = 0;
end:
        clear_mem(xi, sizeof(xi));
        ossl_ml_dsa_key_free(key);
        return rc;
}

/* ------------------------------------------------------------------------- */
/* Key binding (decode once, cache, reuse for every subsequent operation)    */
/* ------------------------------------------------------------------------- */
static int
op_set_privkey(IMB_ML_DSA *self, const void *sk)
{
        ML_DSA_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_dsa_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /* sk_decode also computes the public part and validates |tr|. */
        if (!ossl_ml_dsa_sk_decode(key, sk, self->sk_len))
                goto end;

        key_unbind(self);
        self->key = key;
        key = NULL;
        rc = 0;
end:
        ossl_ml_dsa_key_free(key);
        return rc;
}

static int
op_set_pubkey(IMB_ML_DSA *self, const void *pk)
{
        ML_DSA_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_dsa_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        if (!ossl_ml_dsa_pk_decode(key, pk, self->pk_len))
                goto end;

        key_unbind(self);
        self->key = key;
        key = NULL;
        rc = 0;
end:
        ossl_ml_dsa_key_free(key);
        return rc;
}

/* ------------------------------------------------------------------------- */
/* Signing                                                                   */
/* ------------------------------------------------------------------------- */
static int
op_sign_ctx(IMB_ML_DSA *self, void *sig, size_t *sig_len, const void *msg, size_t msg_len,
            const void *ctx, size_t ctx_len, const void *rnd_32_or_null, int msg_is_mu)
{
        uint8_t rnd[ML_DSA_RND_BYTES] = { 0 };
        size_t out_len = 0;
        int rc = -1;

        if (self->key == NULL || ossl_ml_dsa_key_get_priv(self->key) == NULL)
                return -1;

        if (rnd_32_or_null != NULL)
                memcpy(rnd, rnd_32_or_null, sizeof(rnd));
        else if (imb_get_random(rnd, sizeof(rnd)) != 0)
                goto end;

        /* When msg_is_mu=1, ctx is already baked into mu - pass NULL/0. */
        const void *sign_ctx = msg_is_mu ? NULL : ctx;
        const size_t sign_ctx_len = msg_is_mu ? 0 : ctx_len;

        if (!ossl_ml_dsa_sign(self->key, msg_is_mu, msg, msg_len, sign_ctx, sign_ctx_len, rnd,
                              sizeof(rnd), 1 /* encode */, sig, &out_len, self->sig_len))
                goto end;

        if (sig_len != NULL)
                *sig_len = out_len;
        rc = 0;
end:
        clear_mem(rnd, sizeof(rnd));
        return rc;
}

/* ------------------------------------------------------------------------- */
/* Verification                                                              */
/* ------------------------------------------------------------------------- */
static int
op_verify_ctx(IMB_ML_DSA *self, const void *msg, size_t msg_len, const void *ctx, size_t ctx_len,
              const void *sig, size_t sig_len, int msg_is_mu)
{
        if (self->key == NULL || ossl_ml_dsa_key_get_pub(self->key) == NULL)
                return -1;

        /* When msg_is_mu=1, ctx is already baked into mu - pass NULL/0. */
        const void *verify_ctx = msg_is_mu ? NULL : ctx;
        const size_t verify_ctx_len = msg_is_mu ? 0 : ctx_len;

        if (!ossl_ml_dsa_verify(self->key, msg_is_mu, msg, msg_len, verify_ctx, verify_ctx_len,
                                1 /* encode */, sig, sig_len))
                return -1;

        return 0;
}

/* ------------------------------------------------------------------------- */
/* FIPS 204 internal interface (Sign_internal / Verify_internal)             */
/* ------------------------------------------------------------------------- */
static int
op_sign_internal(IMB_ML_DSA *self, void *sig, size_t *sig_len, const void *msg, size_t msg_len,
                 const void *rnd_32_or_null)
{
        uint8_t rnd[ML_DSA_RND_BYTES] = { 0 };
        size_t out_len = 0;
        int rc = -1;

        if (self->key == NULL || ossl_ml_dsa_key_get_priv(self->key) == NULL)
                return -1;

        if (rnd_32_or_null != NULL)
                memcpy(rnd, rnd_32_or_null, sizeof(rnd));
        /* Hedged signing: derive a fresh per-signature randomizer. */
        else if (imb_get_random(rnd, sizeof(rnd)) != 0)
                goto end;

        /* No context string, no message encoding: encode = 0. */
        if (!ossl_ml_dsa_sign(self->key, 0 /* msg_is_mu */, msg, msg_len, NULL, 0, rnd, sizeof(rnd),
                              0 /* encode */, sig, &out_len, self->sig_len))
                goto end;

        if (sig_len != NULL)
                *sig_len = out_len;
        rc = 0;
end:
        clear_mem(rnd, sizeof(rnd));
        return rc;
}

static int
op_verify_internal(IMB_ML_DSA *self, const void *msg, size_t msg_len, const void *sig,
                   size_t sig_len)
{
        if (self->key == NULL || ossl_ml_dsa_key_get_pub(self->key) == NULL)
                return -1;

        /* No context string, no message encoding: encode = 0. */
        if (!ossl_ml_dsa_verify(self->key, 0 /* msg_is_mu */, msg, msg_len, NULL, 0, 0 /* encode */,
                                sig, sig_len))
                return -1;

        return 0;
}

/* ------------------------------------------------------------------------- */
/* Key validation and derivation (stateless: do not touch self->key)        */
/* ------------------------------------------------------------------------- */
static int
op_pubkey_validate(IMB_ML_DSA *self, const void *pk)
{
        ML_DSA_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_dsa_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /* Decoding enforces the encoded length and coefficient ranges. */
        if (!ossl_ml_dsa_pk_decode(key, pk, self->pk_len))
                goto end;

        rc = 0;
end:
        ossl_ml_dsa_key_free(key);
        return rc;
}

static int
op_privkey_validate(IMB_ML_DSA *self, const void *sk)
{
        ML_DSA_KEY *key = NULL;
        int rc = -1;

        key = ossl_ml_dsa_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /*
         * sk_decode rebuilds the public key from the private key and checks
         * that the embedded |tr| matches, i.e. it is a full consistency check.
         */
        if (!ossl_ml_dsa_sk_decode(key, sk, self->sk_len))
                goto end;

        rc = 0;
end:
        ossl_ml_dsa_key_free(key);
        return rc;
}

static int
op_pubkey_from_privkey(IMB_ML_DSA *self, const void *sk, void *pk)
{
        ML_DSA_KEY *key = NULL;
        const uint8_t *enc;
        int rc = -1;

        key = ossl_ml_dsa_key_new(NULL, NULL, self->evp_type);
        if (key == NULL)
                goto end;

        /* sk_decode computes and caches the encoded public key. */
        if (!ossl_ml_dsa_sk_decode(key, sk, self->sk_len))
                goto end;

        enc = ossl_ml_dsa_key_get_pub(key);
        if (enc == NULL || ossl_ml_dsa_key_get_pub_len(key) != self->pk_len)
                goto end;
        memcpy(pk, enc, self->pk_len);

        rc = 0;
end:
        ossl_ml_dsa_key_free(key);
        return rc;
}

/* ------------------------------------------------------------------------- */
/* Backend selection                                                         */
/* ------------------------------------------------------------------------- */
int
imb_ml_dsa_backend_init_portable(IMB_ML_DSA *self)
{
        switch (self->alg) {
        case IMB_ML_DSA_44:
                self->evp_type = EVP_PKEY_ML_DSA_44;
                self->pk_len = ML_DSA_44_PUB_LEN;
                self->sk_len = ML_DSA_44_PRIV_LEN;
                self->sig_len = ML_DSA_44_SIG_LEN;
                break;
        case IMB_ML_DSA_65:
                self->evp_type = EVP_PKEY_ML_DSA_65;
                self->pk_len = ML_DSA_65_PUB_LEN;
                self->sk_len = ML_DSA_65_PRIV_LEN;
                self->sig_len = ML_DSA_65_SIG_LEN;
                break;
        case IMB_ML_DSA_87:
                self->evp_type = EVP_PKEY_ML_DSA_87;
                self->pk_len = ML_DSA_87_PUB_LEN;
                self->sk_len = ML_DSA_87_PRIV_LEN;
                self->sig_len = ML_DSA_87_SIG_LEN;
                break;
        default:
                return -1;
        }

        self->key = NULL;
        self->keypair = op_keypair;
        self->set_privkey = op_set_privkey;
        self->set_pubkey = op_set_pubkey;
        self->sign_ctx = op_sign_ctx;
        self->verify_ctx = op_verify_ctx;
        self->sign_internal = op_sign_internal;
        self->verify_internal = op_verify_internal;
        self->pubkey_validate = op_pubkey_validate;
        self->privkey_validate = op_privkey_validate;
        self->pubkey_from_privkey = op_pubkey_from_privkey;
        return 0;
}
