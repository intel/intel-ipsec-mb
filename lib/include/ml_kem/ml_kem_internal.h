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
#include "imb_ossl_ia32cap.h"

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

        /**
         * Backend dispatch table (0 on success, <0 on error).
         * keypair()/encap() accept optional randomness (NULL = internal RNG).
         * decap() takes no randomness input.
         */
        int (*keypair)(IMB_ML_KEM *self, uint8_t *ek, uint8_t *dk,
                       const uint8_t seed_64_or_null[64]);
        int (*set_privkey)(IMB_ML_KEM *self, const uint8_t *dk);
        int (*set_pubkey)(IMB_ML_KEM *self, const uint8_t *ek);
        int (*encap)(IMB_ML_KEM *self, uint8_t *ct, uint8_t *shared_secret,
                     const uint8_t m_32_or_null[32]);
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
        int (*decap)(IMB_ML_KEM *self, uint8_t *shared_secret, const uint8_t *ct, size_t ct_len);
        int (*pubkey_validate)(IMB_ML_KEM *self, const uint8_t *ek);
        int (*privkey_validate)(IMB_ML_KEM *self, const uint8_t *dk);
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
