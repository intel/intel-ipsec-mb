/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Public IMB ML-KEM (FIPS 203) API: context lifecycle plus the exported
 * one-line wrappers. Each wrapper performs optional SAFE_PARAM validation
 * then forwards to the backend dispatch table installed at imb_ml_kem_new()
 * time. imb_ml_kem_new() reads mgr->used_arch to install the ISA specific
 * primitives matching the dispatch level the caller selected via
 * init_mb_mgr_*(). The selection is per context and read-only afterwards,
 * so contexts created from different managers, on different threads, run
 * independently.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>

#include "ml_kem_internal.h"
#include "crypto/ml_kem.h"
#include "mb_mgr.h"

/* ------------------------------------------------------------------------- */
/* Context lifecycle                                                         */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_new(IMB_MGR *mgr, IMB_ML_KEM_ALG alg, IMB_ML_KEM **new_self)
{
        IMB_ML_KEM *self;

#ifdef SAFE_PARAM
        if (new_self == NULL)
                return IMB_ERR_NULL_CTX;
#endif
        *new_self = NULL;
#ifdef SAFE_PARAM
        if (mgr == NULL)
                return IMB_ERR_NULL_MBMGR;
#endif
        if (alg != IMB_ML_KEM_512 && alg != IMB_ML_KEM_768 && alg != IMB_ML_KEM_1024)
                return IMB_ERR_PQC_ALG;

        self = (IMB_ML_KEM *) calloc(1, sizeof(*self));
        if (self == NULL)
                return IMB_ERR_PQC_INIT;

        self->mgr = mgr;
        self->alg = alg;

        /*
         * Install the ISA specific primitives for the architecture the
         * manager was initialized with (init_mb_mgr_*() has already checked
         * that the CPU supports it).
         */
        switch ((IMB_ARCH) mgr->used_arch) {
        case IMB_ARCH_AVX2:
        case IMB_ARCH_AVX512:
        case IMB_ARCH_AVX10:
                ossl_ml_kem_poly_init_avx2(self);
                break;
        default:
                ossl_ml_kem_poly_init_base(self);
                break;
        }

        if (imb_ml_kem_backend_init_portable(self) != 0) {
                free(self);
                return IMB_ERR_PQC_INIT;
        }
        *new_self = self;
        return 0;
}

IMB_DLL_EXPORT void
imb_ml_kem_free(IMB_ML_KEM *self)
{
        if (self == NULL)
                return;
        /* Release any key cached by imb_ml_kem_keypair()/set_privkey()/
         * set_pubkey() before wiping the handle. */
        imb_ml_kem_backend_free_key(self);
        imb_clear_mem(self, sizeof(*self));
        free(self);
}

/* ------------------------------------------------------------------------- */
/* Key generation                                                            */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_keypair(IMB_ML_KEM *self, void *ek, void *dk, const IMB_ML_KEM_KEYGEN_PARAMS *params)
{
        const void *seed_d_z = (params != NULL) ? params->seed_d_z : NULL;

#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (ek == NULL || dk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->keypair(self, ek, dk, seed_d_z);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key binding                                                               */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_set_privkey(IMB_ML_KEM *self, const void *dk)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (dk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->set_privkey(self, dk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_kem_set_pubkey(IMB_ML_KEM *self, const void *ek)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (ek == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->set_pubkey(self, ek);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Encapsulation                                                             */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_encap(IMB_ML_KEM *self, void *ct, void *shared_secret,
                 const IMB_ML_KEM_ENCAP_PARAMS *params)
{
        const void *m_32 = (params != NULL) ? params->m_32 : NULL;

#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (ct == NULL || shared_secret == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
#endif
        const int rc = self->encap(self, ct, shared_secret, m_32);

        return (rc != 0) ? IMB_ERR_PQC_KEMOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Decapsulation                                                             */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_decap(IMB_ML_KEM *self, void *shared_secret, const void *ct, size_t ct_len,
                 const IMB_ML_KEM_DECAP_PARAMS *params)
{
        (void) params; /* reserved for future use; decap has no randomness input */
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (shared_secret == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (ct == NULL)
                return IMB_ERR_NULL_SRC;
#endif
        /*
         * The ciphertext-length check itself is unconditional inside the
         * vendored backend (FIPS 203 Section 7.3 requires it on every call,
         * unlike SAFE_PARAM-gated checks elsewhere in this repo) - see
         * ml_kem_internal.h's decap() vtable entry comment.
         */
        const int rc = self->decap(self, shared_secret, ct, ct_len);

        return (rc != 0) ? IMB_ERR_PQC_KEMOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key validation                                                            */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_pubkey_validate(IMB_ML_KEM *self, const void *ek)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (ek == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->pubkey_validate(self, ek);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_kem_privkey_validate(IMB_ML_KEM *self, const void *dk)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (dk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->privkey_validate(self, dk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}
