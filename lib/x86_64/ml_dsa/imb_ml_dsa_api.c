/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/**
 * Public IMB ML-DSA (FIPS 204) API: context lifecycle plus the exported
 * one-line wrappers. Each wrapper performs optional SAFE_PARAM validation
 * then forwards to the backend dispatch table installed at imb_ml_dsa_new()
 * time. imb_ml_dsa_new() reads mgr->used_arch to install the ISA specific
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

#include "ml_dsa_internal.h"
#include "ml_dsa_local.h"
#include "ml_dsa_internal_api.h"
#include "mb_mgr.h"

/* ------------------------------------------------------------------------- */
/* Context lifecycle                                                         */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_new(IMB_MGR *mgr, IMB_ML_DSA_ALG alg, IMB_ML_DSA **new_self)
{
        IMB_ML_DSA *self;

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

        self = (IMB_ML_DSA *) calloc(1, sizeof(*self));
        if (self == NULL)
                return IMB_ERR_PQC_INIT;

        self->mgr = mgr;
        self->alg = alg;

        /**
         * Install the ISA specific primitives for the architecture the
         * manager was initialized with (init_mb_mgr_*() has already checked
         * that the CPU supports it).
         */
        switch ((IMB_ARCH) mgr->used_arch) {
        case IMB_ARCH_AVX512:
        case IMB_ARCH_AVX10:
                ossl_ml_dsa_sample_init_avx512(self);
                ossl_ml_dsa_ntt_init_avx2(self);
                break;
        case IMB_ARCH_AVX2:
                ossl_ml_dsa_sample_init_base(self);
                ossl_ml_dsa_ntt_init_avx2(self);
                break;
        default:
                ossl_ml_dsa_sample_init_base(self);
                ossl_ml_dsa_ntt_init_base(self);
                break;
        }

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
imb_ml_dsa_keypair(IMB_ML_DSA *self, void *pk, void *sk, const IMB_ML_DSA_KEYGEN_PARAMS *params)
{
#ifdef SAFE_PARAM
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (pk == NULL || sk == NULL)
                return IMB_ERR_NULL_KEY;
#endif
        const void *xi_32 = (params != NULL) ? params->xi_32 : NULL;
        const int rc = self->keypair(self, pk, sk, xi_32);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key binding                                                               */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_set_privkey(IMB_ML_DSA *self, const void *sk)
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
imb_ml_dsa_set_pubkey(IMB_ML_DSA *self, const void *pk)
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
imb_ml_dsa_sign(IMB_ML_DSA *self, void *sig, size_t *sig_len, const void *msg, size_t msg_len,
                const IMB_ML_DSA_SIGN_PARAMS *params)
{
        const void *ctx = NULL;
        size_t ctx_len = 0;
        const void *rnd_32 = NULL;
        int msg_is_mu = 0;

        if (params != NULL) {
                ctx = params->ctx;
                ctx_len = params->ctx_len;
                rnd_32 = params->rnd_32;
                msg_is_mu = params->msg_is_mu;
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
        if (msg_is_mu && msg_len != 64)
                return IMB_ERR_NULL_SRC;
        if (!msg_is_mu && ctx == NULL && ctx_len != 0)
                return IMB_ERR_NULL_SRC;
#endif
        /*
         * *sig_len is [in,out]: on entry it must hold the caller's buffer
         * capacity. This check runs unconditionally (regardless of
         * SAFE_PARAM) since sign_ctx() below always writes exactly
         * self->sig_len bytes into sig - an undersized caller-supplied
         * capacity would otherwise result in an out-of-bounds write.
         */
        if (*sig_len < self->sig_len)
                return IMB_ERR_PQC_BUFFER_TOO_SMALL;

        int rc;

        rc = self->sign_ctx(self, sig, sig_len, msg, msg_len, ctx, ctx_len, rnd_32, msg_is_mu);

        return (rc != 0) ? IMB_ERR_PQC_SIGNOP : 0;
}

/**
 * ------------------------------------------------------------------------
 * FIPS 204 internal interface (ML-DSA.Sign_internal / ML-DSA.Verify_internal):
 * no context string, no message encoding. Exported ONLY to support ACVP/CAVP
 * conformance testing of the internal interface - not declared in the public
 * intel-ipsec-mb.h header, and MUST NOT be used by other applications (see
 * lib/include/ml_dsa/ml_dsa_internal_api.h).
 * ------------------------------------------------------------------------
 */
IMB_DLL_EXPORT int
imb_ml_dsa_sign_internal(IMB_ML_DSA *self, void *sig, size_t *sig_len, const void *msg,
                         size_t msg_len, const void *rnd_32_or_null)
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
        /* See imb_ml_dsa_sign() above: unconditional buffer-capacity check. */
        if (*sig_len < self->sig_len)
                return IMB_ERR_PQC_BUFFER_TOO_SMALL;

        const int rc = self->sign_internal(self, sig, sig_len, msg, msg_len, rnd_32_or_null);

        return (rc != 0) ? IMB_ERR_PQC_SIGNOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Verification                                                              */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_verify(IMB_ML_DSA *self, const void *msg, size_t msg_len, const void *sig,
                  size_t sig_len, const IMB_ML_DSA_VERIFY_PARAMS *params)
{
        const void *ctx = NULL;
        size_t ctx_len = 0;
        int msg_is_mu = 0;

        if (params != NULL) {
                ctx = params->ctx;
                ctx_len = params->ctx_len;
                msg_is_mu = params->msg_is_mu;
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
        if (msg_is_mu && msg_len != 64)
                return IMB_ERR_NULL_SRC;
        if (!msg_is_mu && ctx == NULL && ctx_len != 0)
                return IMB_ERR_NULL_SRC;
#endif
        const int rc = self->verify_ctx(self, msg, msg_len, ctx, ctx_len, sig, sig_len, msg_is_mu);

        return (rc != 0) ? IMB_ERR_PQC_SIGNOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_verify_internal(IMB_ML_DSA *self, const void *msg, size_t msg_len, const void *sig,
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
imb_ml_dsa_pubkey_validate(IMB_ML_DSA *self, const void *pk)
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
imb_ml_dsa_privkey_validate(IMB_ML_DSA *self, const void *sk)
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
imb_ml_dsa_pubkey_from_privkey(IMB_ML_DSA *self, const void *sk, void *pk)
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
