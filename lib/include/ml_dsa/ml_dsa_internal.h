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
 * Internal definition of the opaque IMB_ML_DSA context and its backend
 * dispatch (vtable). The vtable keeps a single portable backend today but
 * allows future ISA-specific backends to be selected at imb_ml_dsa_new()
 * time based on detected CPU features.
 *
 * This header only references IMB and standard C types (plus an opaque
 * forward-declared ML_DSA_KEY pointer) so that it can be included by both
 * the IMB-facing API layer and the ported OpenSSL ML-DSA backend without
 * leaking OpenSSL compatibility types.
 *
 * Key lifecycle: a context is bound to at most one decoded/generated key at
 * a time, cached in the "key" field below. The key is created once, by
 * imb_ml_dsa_keypair() (fresh generation, optionally seeded) or by
 * imb_ml_dsa_set_privkey()/imb_ml_dsa_set_pubkey() (decode caller-supplied
 * encoded key bytes), and reused by every subsequent sign/verify call on the
 * same context - mirroring how an OpenSSL provider decodes/imports a key
 * once (keymgmt) and reuses it across many signature operations (signature
 * provider). Re-binding a context (calling any of the above again) replaces
 * the previously cached key. A key produced by keypair()
 * or set_privkey() carries both the private and public components (the
 * public part is always derived as part of decoding/generating the private
 * key) and so may be used for both signing and verification; a key produced
 * by set_pubkey() only carries the public component and may only be used
 * for verification.
 */

#ifndef IMB_ML_DSA_INTERNAL_H
#define IMB_ML_DSA_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>
#include "imb_ossl_ia32cap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque vendored OpenSSL ML-DSA key object (see crypto/ml_dsa.h). Only a
 * pointer to it is referenced here, so the full definition is not needed.
 * A plain struct-tag forward declaration (rather than a duplicate "typedef
 * ... ML_DSA_KEY" here) is used deliberately: translation units that include
 * both this header and the real crypto/ml_dsa.h (e.g. the backend
 * implementation) would otherwise see the ML_DSA_KEY typedef declared twice,
 * which some compilers/standard versions warn/error on outside of C11.
 */
struct ml_dsa_key_st;

struct IMB_ML_DSA {
        IMB_MGR *mgr;
        IMB_ML_DSA_ALG alg;
        int evp_type; /* OpenSSL EVP_PKEY_ML_DSA_* identifier */

        /* Encoded sizes for the bound parameter set */
        size_t pk_len;
        size_t sk_len;
        size_t sig_len;

        /* Cached decoded/generated key bound to this context (see above). */
        struct ml_dsa_key_st *key;

        /* Backend dispatch table. All ops return 0 on success, <0 on error. */
        int (*keypair)(IMB_ML_DSA *self, uint8_t *pk, uint8_t *sk, const uint8_t xi_32_or_null[32]);
        int (*set_privkey)(IMB_ML_DSA *self, const uint8_t *sk);
        int (*set_pubkey)(IMB_ML_DSA *self, const uint8_t *pk);
        int (*sign_ctx)(IMB_ML_DSA *self, uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                        size_t msg_len, const uint8_t *ctx, size_t ctx_len,
                        const uint8_t *rnd_32_or_null, int msg_is_mu);
        int (*verify_ctx)(IMB_ML_DSA *self, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                          size_t ctx_len, const uint8_t *sig, size_t sig_len, int msg_is_mu);
        /**
         * FIPS 204 internal interface (ML-DSA.Sign_internal /
         * ML-DSA.Verify_internal): no context string, no message encoding
         * (equivalent to sign_ctx/verify_ctx with ctx = NULL, ctx_len = 0 and
         * encode = 0).
         */
        int (*sign_internal)(IMB_ML_DSA *self, uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                             size_t msg_len, const uint8_t *rnd_32_or_null);
        int (*verify_internal)(IMB_ML_DSA *self, const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);
        int (*pubkey_validate)(IMB_ML_DSA *self, const uint8_t *pk);
        int (*privkey_validate)(IMB_ML_DSA *self, const uint8_t *sk);
        int (*pubkey_from_privkey)(IMB_ML_DSA *self, const uint8_t *sk, uint8_t *pk);
};

/**
 * @brief Populate \a self with the portable C backend dispatch table.
 *
 * Fills in the vtable entries and the encoded size fields from
 * \a self->evp_type. The caller must have already set mgr/alg/evp_type.
 *
 * @param [in,out] self  ML-DSA context with mgr/alg/evp_type already set
 * @return 0 on success, negative on failure (e.g. unknown parameter set)
 */
IMB_DLL_LOCAL int
imb_ml_dsa_backend_init_portable(IMB_ML_DSA *self);

/**
 * @brief Release the ML_DSA_KEY cached in \a self->key, if any.
 *
 * Used by imb_ml_dsa_free() so the API layer does not need to reference the
 * opaque vendored OpenSSL key type directly.
 *
 * @param [in,out] self  ML-DSA context (may be NULL)
 */
IMB_DLL_LOCAL void
imb_ml_dsa_backend_free_key(IMB_ML_DSA *self);

#ifdef __cplusplus
}
#endif

#endif /* IMB_ML_DSA_INTERNAL_H */
