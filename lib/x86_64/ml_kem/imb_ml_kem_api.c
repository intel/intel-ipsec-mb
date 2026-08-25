/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Public IMB ML-KEM (FIPS 203) API: context lifecycle plus the exported
 * one-line wrappers. Each wrapper validates all of its arguments, so that
 * no build of the library can be made to write past a caller supplied
 * buffer, then forwards to the backend dispatch table installed at
 * imb_ml_kem_new() time. imb_ml_kem_new() reads mgr->used_arch to install the
 * ISA specific primitives matching the dispatch level the caller selected
 * via init_mb_mgr_*(). The selection is per context and read-only
 * afterwards, so contexts created from different managers, on different
 * threads, run independently.
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

        if (new_self == NULL)
                return IMB_ERR_NULL_CTX;
        *new_self = NULL;
        if (mgr == NULL)
                return IMB_ERR_NULL_MBMGR;
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
imb_ml_kem_keypair(IMB_ML_KEM *self, void *ek, size_t ek_len, void *dk, size_t dk_len,
                   const IMB_ML_KEM_KEYGEN_PARAMS *params)
{
        const void *seed_d_z = NULL;

        if (self == NULL)
                return IMB_ERR_NULL_CTX;

        /*
         * The params structure size check is done before any other field is
         * read, so that fields of a mismatching structure are never accessed.
         */
        if (params != NULL) {
                if (params->size != sizeof(*params))
                        return IMB_ERR_PQC_PARAMS;
                seed_d_z = params->seed_d_z;

                /*
                 * A NULL seed asks for a random one and takes no length,
                 * otherwise the size is fixed by FIPS 203.
                 */
                const size_t exp_seed_len = (seed_d_z != NULL) ? IMB_ML_KEM_KEYGEN_SEED_BYTES : 0;

                if (params->seed_d_z_len != exp_seed_len)
                        return IMB_ERR_PQC_BUFFER_SIZE;
        }
        if (ek == NULL || dk == NULL)
                return IMB_ERR_NULL_KEY;
        /*
         * keypair() below always writes exactly self->ek_len / self->dk_len
         * bytes - an undersized caller-supplied capacity would otherwise
         * result in an out-of-bounds write.
         */
        if (ek_len < self->ek_len || dk_len < self->dk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->keypair(self, ek, dk, seed_d_z);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key binding                                                               */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_set_privkey(IMB_ML_KEM *self, const void *dk, size_t dk_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (dk == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (dk_len != self->dk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->set_privkey(self, dk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_kem_set_pubkey(IMB_ML_KEM *self, const void *ek, size_t ek_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (ek == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (ek_len != self->ek_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->set_pubkey(self, ek);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Encapsulation                                                             */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_encap(IMB_ML_KEM *self, void *ct, size_t ct_len, void *shared_secret, size_t ss_len,
                 const IMB_ML_KEM_ENCAP_PARAMS *params)
{
        const void *m_32 = NULL;
        size_t m_len = 0;

        if (self == NULL)
                return IMB_ERR_NULL_CTX;

        /*
         * The params structure size check is done before any other field is
         * read, so that fields of a mismatching structure are never accessed.
         */
        if (params != NULL) {
                if (params->size != sizeof(*params))
                        return IMB_ERR_PQC_PARAMS;
                m_32 = params->m_32;
                m_len = params->m_len;
        }
        if (ct == NULL || shared_secret == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        /*
         * A NULL randomness pointer asks for a random value and takes no
         * length, otherwise the size is fixed by FIPS 203.
         */
        if (m_len != ((m_32 != NULL) ? IMB_ML_KEM_ENCAP_SEED_BYTES : 0))
                return IMB_ERR_PQC_BUFFER_SIZE;

        /* encap() below writes exactly self->ct_len and shared-secret bytes */
        if (ct_len < self->ct_len || ss_len < IMB_ML_KEM_SHARED_SECRET_BYTES)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->encap(self, ct, shared_secret, m_32);

        return (rc != 0) ? IMB_ERR_PQC_KEMOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Decapsulation                                                             */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_decap(IMB_ML_KEM *self, void *shared_secret, size_t ss_len, const void *ct,
                 size_t ct_len, const IMB_ML_KEM_DECAP_PARAMS *params)
{
        (void) params; /* reserved for future use; decap has no randomness input */
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (shared_secret == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (ct == NULL)
                return IMB_ERR_NULL_SRC;
        /* decap() below writes exactly IMB_ML_KEM_SHARED_SECRET_BYTES bytes */
        if (ss_len < IMB_ML_KEM_SHARED_SECRET_BYTES)
                return IMB_ERR_PQC_BUFFER_SIZE;

        /*
         * The ciphertext length is validated inside the vendored backend,
         * which rejects anything other than the parameter set's ciphertext
         * size as required by FIPS 203 Section 7.3. A wrong length is a
         * malformed-input verdict there rather than a caller error, so it
         * surfaces as IMB_ERR_PQC_KEMOP - see ml_kem_internal.h's decap()
         * vtable entry comment.
         */
        const int rc = self->decap(self, shared_secret, ct, ct_len);

        return (rc != 0) ? IMB_ERR_PQC_KEMOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key validation                                                            */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_pubkey_validate(IMB_ML_KEM *self, const void *ek, size_t ek_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (ek == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (ek_len != self->ek_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->pubkey_validate(self, ek);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_kem_privkey_validate(IMB_ML_KEM *self, const void *dk, size_t dk_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (dk == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (dk_len != self->dk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->privkey_validate(self, dk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}
