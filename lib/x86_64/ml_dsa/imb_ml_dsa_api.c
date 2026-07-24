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
 * Public IMB ML-DSA (FIPS 204) API: context lifecycle plus the exported
 * one-line wrappers. Each wrapper performs optional SAFE_PARAM validation
 * then forwards to the backend dispatch table installed at imb_ml_dsa_new()
 * time. imb_ml_dsa_new() reads mgr->used_arch (in addition to
 * imb_get_features()) to cap the ISA level exposed to the vendored OpenSSL
 * ML-DSA code at the dispatch level the caller selected via
 * init_mb_mgr_*().
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>

#include "ml_dsa_internal.h"
#include "ml_dsa_internal_api.h"
#include "mb_mgr.h"

/* ------------------------------------------------------------------------- */
/* Context lifecycle                                                         */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_new(IMB_MGR *mgr, IMB_ML_DSA_ALG alg, IMB_ML_DSA **new_self)
{
        IMB_ML_DSA *self;
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
        if (alg != IMB_ML_DSA_44 && alg != IMB_ML_DSA_65 && alg != IMB_ML_DSA_87)
                return IMB_ERR_PQC_ALG;

        /**
         * Features are queried so a future ISA-specific backend can be chosen
         * here.
         */
        (void) imb_get_features(mgr, &features);

        /**
         * Cap the features passed to the OpenSSL ia32cap shim at the ISA
         * level the caller explicitly selected via init_mb_mgr_*() (recorded
         * in mgr->used_arch). Without this, an explicit init_mb_mgr_avx2()
         * call would still let ML-DSA use AVX512 SHAKEx4 sampling on
         * AVX512-capable hardware, since mgr->features reflects the raw CPU
         * capability rather than the manager's selected dispatch level.
         */
        if (mgr->used_arch < IMB_ARCH_AVX512)
                features &= ~(IMB_FEATURE_AVX512F | IMB_FEATURE_AVX512DQ | IMB_FEATURE_AVX512BW |
                              IMB_FEATURE_AVX512VL);
        if (mgr->used_arch < IMB_ARCH_AVX2)
                features &= ~IMB_FEATURE_AVX2;

        imb_ossl_ia32cap_init(features);

        self = (IMB_ML_DSA *) calloc(1, sizeof(*self));
        if (self == NULL)
                return IMB_ERR_PQC_INIT;

        self->mgr = mgr;
        self->alg = alg;
        if (imb_ml_dsa_backend_init_portable(self) != 0) {
                free(self);
                return IMB_ERR_PQC_INIT;
        }
        *new_self = self;
        return 0;
}

IMB_DLL_EXPORT void
imb_ml_dsa_free(IMB_ML_DSA *self)
{
        if (self == NULL)
                return;
        /**
         * Release any key cached by imb_ml_dsa_keypair()/set_privkey()/
         * set_pubkey() before wiping the handle.
         */
        imb_ml_dsa_backend_free_key(self);
        imb_clear_mem(self, sizeof(*self));
        free(self);
}

/* ------------------------------------------------------------------------- */
/* Key generation                                                            */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_keypair(IMB_ML_DSA *self, uint8_t *pk, uint8_t *sk,
                   const IMB_ML_DSA_KEYGEN_PARAMS *params)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (pk == NULL || sk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const uint8_t *xi_32 = (params != NULL) ? params->xi_32 : NULL;
        const int rc = self->keypair(self, pk, sk, xi_32);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key binding                                                               */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_set_privkey(IMB_ML_DSA *self, const uint8_t *sk)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (sk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->set_privkey(self, sk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_set_pubkey(IMB_ML_DSA *self, const uint8_t *pk)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (pk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->set_pubkey(self, pk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Signing                                                                   */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_sign(IMB_ML_DSA *self, uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                const IMB_ML_DSA_SIGN_PARAMS *params)
{
        const uint8_t *ctx = NULL;
        size_t ctx_len = 0;
        const uint8_t *rnd_32 = NULL;

        if (params != NULL) {
                ctx = params->ctx;
                ctx_len = params->ctx_len;
                rnd_32 = params->rnd_32;
        }
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (sig == NULL || sig_len == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
        if (ctx == NULL && ctx_len != 0)
                return IMB_ERR_NULL_SRC;
#endif
        int rc;

        rc = self->sign_ctx(self, sig, sig_len, msg, msg_len, ctx, ctx_len, rnd_32);

        return (rc != 0) ? IMB_ERR_PQC_SIGNOP : 0;
}

/**
 * ------------------------------------------------------------------------
 * FIPS 204 internal interface (ML-DSA.Sign_internal / ML-DSA.Verify_internal):
 * no context string, no message encoding. Intended for callers that perform
 * their own external-interface encoding (e.g. a composite scheme), and for
 * ACVP/CAVP conformance testing of the internal interface.
 * ------------------------------------------------------------------------
 */
IMB_DLL_EXPORT int
imb_ml_dsa_sign_internal(IMB_ML_DSA *self, uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                         size_t msg_len, const uint8_t *rnd_32_or_null)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (sig == NULL || sig_len == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
#endif
        const int rc = self->sign_internal(self, sig, sig_len, msg, msg_len, rnd_32_or_null);

        return (rc != 0) ? IMB_ERR_PQC_SIGNOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Verification                                                              */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_verify(IMB_ML_DSA *self, const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                  size_t sig_len, const IMB_ML_DSA_VERIFY_PARAMS *params)
{
        const uint8_t *ctx = NULL;
        size_t ctx_len = 0;

        if (params != NULL) {
                ctx = params->ctx;
                ctx_len = params->ctx_len;
        }
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (sig == NULL)
                return IMB_ERR_NULL_SRC;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
        if (ctx == NULL && ctx_len != 0)
                return IMB_ERR_NULL_SRC;
#endif
        const int rc = self->verify_ctx(self, msg, msg_len, ctx, ctx_len, sig, sig_len);

        return (rc != 0) ? IMB_ERR_PQC_SIGNOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_verify_internal(IMB_ML_DSA *self, const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                           size_t sig_len)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (sig == NULL)
                return IMB_ERR_NULL_SRC;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
#endif
        const int rc = self->verify_internal(self, msg, msg_len, sig, sig_len);

        return (rc != 0) ? IMB_ERR_PQC_SIGNOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key validation and derivation                                             */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_pubkey_validate(IMB_ML_DSA *self, const uint8_t *pk)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (pk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->pubkey_validate(self, pk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_privkey_validate(IMB_ML_DSA *self, const uint8_t *sk)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (sk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const int rc = self->privkey_validate(self, sk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_pubkey_from_privkey(IMB_ML_DSA *self, const uint8_t *sk, uint8_t *pk)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (sk == NULL)
                return IMB_ERR_NULL_KEY;
        if (pk == NULL)
                return IMB_ERR_NULL_DST;
#endif
        const int rc = self->pubkey_from_privkey(self, sk, pk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}
