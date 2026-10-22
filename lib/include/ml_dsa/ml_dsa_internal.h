/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
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

/**
 * Opaque vendored OpenSSL types referenced by the ISA specific function
 * pointers below.
 */
struct poly_st;
struct vector_st;
struct matrix_st;
struct evp_md_st;
struct evp_md_ctx_st;

/* ISA specific sampling (SHAKE based) primitives */
typedef int(ML_DSA_MATRIX_EXPAND_A_FN)(struct evp_md_ctx_st *g_ctx, const struct evp_md_st *md,
                                       const uint8_t *rho, struct matrix_st *out);
typedef int(ML_DSA_VECTOR_EXPAND_S_FN)(struct evp_md_ctx_st *h_ctx, const struct evp_md_st *md,
                                       int eta, const uint8_t *seed, struct vector_st *s1,
                                       struct vector_st *s2);
typedef void(ML_DSA_VECTOR_EXPAND_MASK_FN)(struct vector_st *out, const uint8_t rho_prime[64],
                                           uint32_t kappa, uint32_t gamma1,
                                           struct evp_md_ctx_st *h_ctx, const struct evp_md_st *md);

/* ISA specific NTT primitives */
typedef void(ML_DSA_POLY_NTT_FN)(struct poly_st *p);
typedef void(ML_DSA_POLY_NTT_INVERSE_FN)(struct poly_st *p);
typedef void(ML_DSA_POLY_NTT_MULT_FN)(const struct poly_st *lhs, const struct poly_st *rhs,
                                      struct poly_st *out);
/*
 * Polynomial kernels process exactly 256 coefficients, with uint32_t alignment.
 * Arithmetic inputs/outputs are canonical [0,q); LowBits/Decompose store signed
 * low parts as uint32_t bit patterns. In-place output is supported; Decompose's
 * two outputs must be distinct. Norm checks return 0/1 after scanning the entire
 * polynomial (canonical or signed coefficients, respectively). Count expects
 * 0/1 hints. Packers write exactly 128 (4-bit w1) or 640 (20-bit z) bytes.
 * Rounding kernels (HighBits/LowBits/Decompose/MakeHint) take no gamma2
 * argument: the init function selects the gamma2 specialization from the
 * parameter set.
 */
typedef void(ML_DSA_POLY_MAP_FN)(const struct poly_st *in, struct poly_st *out);
typedef void(ML_DSA_POLY_DECOMPOSE_FN)(const struct poly_st *in, struct poly_st *high,
                                       struct poly_st *low);
typedef void(ML_DSA_POLY_HINT_FN)(const struct poly_st *ct0, const struct poly_st *cs2,
                                  const struct poly_st *w, struct poly_st *out);
typedef uint32_t(ML_DSA_POLY_CHKNORM_FN)(const struct poly_st *p, uint32_t bound);
/*
 * Return 1 if any |low - centered(cs2)| >= bound, 0 otherwise. low holds signed
 * Decompose output, cs2 is canonical. Neither input is modified.
 */
typedef uint32_t(ML_DSA_POLY_SUB_CHKNORM_FN)(const struct poly_st *low, const struct poly_st *cs2,
                                             uint32_t bound);
typedef uint32_t(ML_DSA_POLY_COUNT_FN)(const struct poly_st *p);
typedef void(ML_DSA_POLY_PACK_FN)(const struct poly_st *p, uint8_t *out);

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

        /*
         * ISA specific primitives, selected once at context creation from the
         * IMB_MGR architecture (mgr->used_arch), following the same init-time
         * dispatch model used by IMB_MGR itself.
         */
        ML_DSA_MATRIX_EXPAND_A_FN *matrix_expand_A;
        ML_DSA_VECTOR_EXPAND_S_FN *vector_expand_S;
        ML_DSA_VECTOR_EXPAND_MASK_FN *vector_expand_mask;
        ML_DSA_POLY_NTT_FN *poly_ntt;
        ML_DSA_POLY_NTT_INVERSE_FN *poly_ntt_inverse;
        ML_DSA_POLY_NTT_MULT_FN *poly_ntt_mult;
        ML_DSA_POLY_MAP_FN *poly_high_bits;
        ML_DSA_POLY_MAP_FN *poly_low_bits;
        ML_DSA_POLY_DECOMPOSE_FN *poly_decompose;
        ML_DSA_POLY_HINT_FN *poly_make_hint;
        ML_DSA_POLY_NTT_MULT_FN *poly_add;
        ML_DSA_POLY_NTT_MULT_FN *poly_sub;
        ML_DSA_POLY_CHKNORM_FN *poly_chknorm;
        ML_DSA_POLY_CHKNORM_FN *poly_chknorm_signed;
        ML_DSA_POLY_SUB_CHKNORM_FN *poly_sub_chknorm;
        ML_DSA_POLY_COUNT_FN *poly_count_ones;
        ML_DSA_POLY_PACK_FN *poly_pack_w1_4;
        ML_DSA_POLY_PACK_FN *poly_pack_z_20;

        /**
         * Backend dispatch table. All ops return 0 on success, <0 on error,
         * except verify_ctx/verify_internal - see their comment below.
         *
         * Key/seed args carry no length: the public wrappers reject a
         * mismatched size first, so these ops read exactly self->pk_len /
         * self->sk_len bytes.
         */
        int (*keypair)(IMB_ML_DSA *self, void *pk, void *sk, const void *xi_32_or_null);
        int (*set_privkey)(IMB_ML_DSA *self, const void *sk);
        int (*set_pubkey)(IMB_ML_DSA *self, const void *pk);
        int (*sign_ctx)(IMB_ML_DSA *self, void *sig, size_t *sig_len, const void *msg,
                        size_t msg_len, const void *ctx, size_t ctx_len, const void *rnd_32_or_null,
                        int msg_is_mu);
        /**
         * Returns 0 if the signature is valid, -1 if it is cryptographically
         * invalid (or malformed), or -2 on an operational failure (e.g. no
         * key bound, allocation or hashing failure) unrelated to the
         * signature's validity.
         */
        int (*verify_ctx)(IMB_ML_DSA *self, const void *msg, size_t msg_len, const void *ctx,
                          size_t ctx_len, const void *sig, size_t sig_len, int msg_is_mu);
        /**
         * FIPS 204 internal interface (ML-DSA.Sign_internal /
         * ML-DSA.Verify_internal): no context string, no message encoding
         * (equivalent to sign_ctx/verify_ctx with ctx = NULL, ctx_len = 0 and
         * encode = 0).
         */
        int (*sign_internal)(IMB_ML_DSA *self, void *sig, size_t *sig_len, const void *msg,
                             size_t msg_len, const void *rnd_32_or_null);
        /** Return convention: see verify_ctx above. */
        int (*verify_internal)(IMB_ML_DSA *self, const void *msg, size_t msg_len, const void *sig,
                               size_t sig_len);
        int (*pubkey_validate)(IMB_ML_DSA *self, const void *pk);
        int (*privkey_validate)(IMB_ML_DSA *self, const void *sk);
        int (*pubkey_from_privkey)(IMB_ML_DSA *self, const void *sk, void *pk);
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
