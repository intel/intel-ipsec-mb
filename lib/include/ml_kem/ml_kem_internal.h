/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/**
 * Internal definition of the opaque IMB_ML_KEM context and its backend
 * dispatch (vtable). The vtable keeps a single portable backend today but
 * allows future ISA-specific backends to be selected at imb_ml_kem_new()
 * time based on detected CPU features.
 *
 * This header only references IMB and standard C types (plus an opaque
 * forward-declared ML_KEM_KEY pointer) so that it can be included by both
 * the IMB-facing API layer and the ported OpenSSL ML-KEM backend without
 * leaking OpenSSL compatibility types.
 *
 * Key lifecycle: a context is bound to at most one decoded/generated key at
 * a time, cached in the "key" field below. The key is created once, by
 * imb_ml_kem_keypair() (fresh generation, optionally seeded) or by
 * imb_ml_kem_set_privkey()/imb_ml_kem_set_pubkey() (decode caller-supplied
 * encoded key bytes), and reused by every subsequent encap/decap call on the
 * same context - mirroring how an OpenSSL provider decodes/imports a key
 * once (keymgmt) and reuses it across many KEM operations (kem provider).
 * Re-binding a context (calling any of the above again) replaces the
 * previously cached key. A key produced by keypair() or set_privkey() carries
 * both the private and public components (the public part is always derived
 * as part of decoding/generating the private key) and so may be used for
 * both encapsulation and decapsulation; a key produced by set_pubkey() only
 * carries the public component and may only be used for encapsulation.
 *
 * FIPS 203 Section 3.3 "Destruction of intermediate values" permits exactly
 * two categories of retained state across calls: the KeyGen seed (d, z), and
 * the expanded public matrix. The vendored ML_KEM_KEY object already
 * implements both (key->d/key->z and key->rho/key->m respectively); caching
 * that single key object here for reuse across encap()/decap() calls is
 * what gives us the matrix-reuse exception "for free", and the seed is only
 * ever retained when a caller explicitly supplies one (keygen from seed), not
 * on ordinary fresh-random key generation.
 */

#ifndef IMB_ML_KEM_INTERNAL_H
#define IMB_ML_KEM_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque vendored OpenSSL ML-KEM key object (see crypto/ml_kem.h). Only a
 * pointer to it is referenced here, so the full definition is not needed.
 * A plain struct-tag forward declaration (rather than a duplicate "typedef
 * ... ML_KEM_KEY" here) is used deliberately: translation units that include
 * both this header and the real crypto/ml_kem.h (e.g. the backend
 * implementation) would otherwise see the ML_KEM_KEY typedef declared twice,
 * which some compilers/standard versions warn/error on outside of C11.
 */
struct ossl_ml_kem_key_st;

/**
 * Opaque vendored OpenSSL polynomial type referenced by the ISA specific
 * function pointers below. Only pointers to it are used here, so a forward
 * declaration is enough and this header stays free of the vendored ML-KEM
 * include tree.
 */
struct ossl_ml_kem_scalar_st;

/* ISA specific polynomial (NTT domain) primitives */
typedef void(ML_KEM_POLY_NTT_FN)(struct ossl_ml_kem_scalar_st *s);
typedef void(ML_KEM_POLY_ARITH_FN)(struct ossl_ml_kem_scalar_st *lhs,
                                   const struct ossl_ml_kem_scalar_st *rhs);
typedef void(ML_KEM_POLY_MULT_FN)(struct ossl_ml_kem_scalar_st *out,
                                  const struct ossl_ml_kem_scalar_st *lhs,
                                  const struct ossl_ml_kem_scalar_st *rhs);

struct IMB_ML_KEM {
        IMB_MGR *mgr;
        IMB_ML_KEM_ALG alg;
        int evp_type; /* OpenSSL EVP_PKEY_ML_KEM_* identifier */

        /* Encoded sizes for the bound parameter set */
        size_t ek_len;
        size_t dk_len;
        size_t ct_len;

        /* Cached decoded/generated key bound to this context (see above). */
        struct ossl_ml_kem_key_st *key;

        /*
         * ISA specific primitives, selected once at context creation from the
         * IMB_MGR architecture (mgr->used_arch), following the same init-time
         * dispatch model used by IMB_MGR itself.
         */
        ML_KEM_POLY_NTT_FN *poly_ntt;
        ML_KEM_POLY_NTT_FN *poly_ntt_inverse;
        ML_KEM_POLY_ARITH_FN *poly_add;
        ML_KEM_POLY_ARITH_FN *poly_sub;
        ML_KEM_POLY_MULT_FN *poly_mult;
        ML_KEM_POLY_MULT_FN *poly_mult_add;

        /**
         * Backend dispatch table (0 on success, <0 on error).
         * keypair()/encap() accept optional randomness (NULL = internal RNG).
         * decap() takes no randomness input.
         *
         * Key/seed args carry no length: the public wrappers reject a
         * mismatched size first, so these ops read exactly self->ek_len /
         * self->dk_len bytes. decap() is the exception, explained below.
         */
        int (*keypair)(IMB_ML_KEM *self, void *ek, void *dk, const void *seed_64_or_null);
        int (*set_privkey)(IMB_ML_KEM *self, const void *dk);
        int (*set_pubkey)(IMB_ML_KEM *self, const void *ek);
        int (*encap)(IMB_ML_KEM *self, void *ct, void *shared_secret, const void *m_32_or_null);
        /**
         * FIPS 203 Section 7.3 mandates the ciphertext-length ("ciphertext
         * type") check be performed on every single call, unlike the
         * encapsulation/decapsulation key checks (which "need not be
         * performed... with every execution" and are instead enforced once,
         * structurally, by set_pubkey()/set_privkey()/keypair() routing
         * through the vendored parse_public_key()/parse_private_key()
         * decoders). decap() takes ct_len explicitly so that this
         * unconditional check (already implemented, unconditionally, inside
         * the vendored ossl_ml_kem_decap()) is never bypassed.
         */
        int (*decap)(IMB_ML_KEM *self, void *shared_secret, const void *ct, size_t ct_len);
        int (*pubkey_validate)(IMB_ML_KEM *self, const void *ek);
        int (*privkey_validate)(IMB_ML_KEM *self, const void *dk);
};

/**
 * @brief Populate \a self with the portable C backend dispatch table.
 *
 * Fills in the vtable entries and the encoded size fields from
 * \a self->evp_type. The caller must have already set mgr/alg/evp_type.
 *
 * @param [in,out] self  ML-KEM context with mgr/alg/evp_type already set
 * @return Status code.
 * @retval 0 success
 * @retval <0 failure (e.g. unknown parameter set)
 */
IMB_DLL_LOCAL int
imb_ml_kem_backend_init_portable(IMB_ML_KEM *self);

/**
 * @brief Release the ML_KEM_KEY cached in \a self->key, if any.
 *
 * Used by imb_ml_kem_free() so the API layer does not need to reference the
 * opaque vendored OpenSSL key type directly. Releasing the key also
 * zeroizes any retained seed/private key material (see
 * ossl_ml_kem_key_reset()).
 *
 * @param [in,out] self  ML-KEM context (may be NULL)
 */
IMB_DLL_LOCAL void
imb_ml_kem_backend_free_key(IMB_ML_KEM *self);

#ifdef __cplusplus
}
#endif

#endif /* IMB_ML_KEM_INTERNAL_H */
