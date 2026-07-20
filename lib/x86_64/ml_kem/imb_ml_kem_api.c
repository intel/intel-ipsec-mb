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
 * Public IMB ML-KEM (FIPS 203) API: context lifecycle plus the exported
 * one-line wrappers. Each wrapper performs optional SAFE_PARAM validation
 * then forwards to the backend dispatch table installed at imb_ml_kem_new()
 * time. imb_ml_kem_new() reads mgr->used_arch (in addition to
 * imb_get_features()) to cap the ISA level exposed to the vendored OpenSSL
 * ML-KEM code at the dispatch level the caller selected via
 * init_mb_mgr_*().
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>

#include "ml_kem_internal.h"
#include "mb_mgr.h"

/* ------------------------------------------------------------------------- */
/* Context lifecycle                                                         */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_kem_new(IMB_MGR *mgr, IMB_ML_KEM_ALG alg, IMB_ML_KEM **new_self)
{
        IMB_ML_KEM *self;
        uint64_t features = 0;

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

        /*
         * Features are queried so a future ISA-specific backend can be
         * chosen here.
         */
        (void) imb_get_features(mgr, &features);

        /*
         * Cap the features passed to the OpenSSL ia32cap shim at the ISA
         * level the caller explicitly selected via init_mb_mgr_*() (recorded
         * in mgr->used_arch). Without this, an explicit init_mb_mgr_avx2()
         * call would still let ML-KEM use AVX512 SHAKEx4 sampling on
         * AVX512-capable hardware, since mgr->features reflects the raw CPU
         * capability rather than the manager's selected dispatch level.
         */
        if (mgr->used_arch < IMB_ARCH_AVX512)
                features &= ~(IMB_FEATURE_AVX512F | IMB_FEATURE_AVX512DQ | IMB_FEATURE_AVX512BW |
                              IMB_FEATURE_AVX512VL);
        if (mgr->used_arch < IMB_ARCH_AVX2)
                features &= ~IMB_FEATURE_AVX2;

        imb_ossl_ia32cap_init(features);

        self = (IMB_ML_KEM *) calloc(1, sizeof(*self));
        if (self == NULL)
                return IMB_ERR_PQC_INIT;

        self->mgr = mgr;
        self->alg = alg;
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
imb_ml_kem_keypair(IMB_ML_KEM *self, uint8_t *ek, uint8_t *dk,
                   const IMB_ML_KEM_KEYGEN_PARAMS *params)
{
        const uint8_t *seed_d_z = (params != NULL) ? params->seed_d_z : NULL;

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
imb_ml_kem_set_privkey(IMB_ML_KEM *self, const uint8_t *dk)
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
imb_ml_kem_set_pubkey(IMB_ML_KEM *self, const uint8_t *ek)
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
imb_ml_kem_encap(IMB_ML_KEM *self, uint8_t *ct, uint8_t *shared_secret,
                 const IMB_ML_KEM_ENCAP_PARAMS *params)
{
        const uint8_t *m_32 = (params != NULL) ? params->m_32 : NULL;

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
imb_ml_kem_decap(IMB_ML_KEM *self, uint8_t *shared_secret, const uint8_t *ct, size_t ct_len,
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
imb_ml_kem_pubkey_validate(IMB_ML_KEM *self, const uint8_t *ek)
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
imb_ml_kem_privkey_validate(IMB_ML_KEM *self, const uint8_t *dk)
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
