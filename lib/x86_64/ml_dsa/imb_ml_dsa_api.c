/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/**
 * Public IMB ML-DSA (FIPS 204) API: context lifecycle plus the exported
 * one-line wrappers. Each wrapper validates all of its arguments, so that
 * no build of the library can be made to write past a caller supplied
 * buffer, then forwards to the backend dispatch table installed at
 * imb_ml_dsa_new() time. imb_ml_dsa_new() reads mgr->used_arch to install the
 * ISA specific primitives matching the dispatch level the caller selected
 * via init_mb_mgr_*(). The selection is per context and read-only
 * afterwards, so contexts created from different managers, on different
 * threads, run independently. The context keeps the manager pointer and
 * every operation checks its self-test state, so the manager must outlive
 * the context.
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

/**
 * @brief Check whether a reserved parameter field holds a non-zero value.
 *
 * The reserved fields let future options be added without changing sizeof()
 * of the parameter structure, so the \a size check alone cannot detect them.
 *
 * The field is copied out rather than cast in place because it is only
 * 4-byte aligned within both parameter structures; the copy is folded into a
 * single compare by the compiler.
 *
 * @param [in] rsvd      Reserved field
 * @param [in] rsvd_size Size of the reserved field in bytes
 *
 * @return Zero if the field is all zero, non-zero otherwise
 */
static int
ml_dsa_reserved_is_set(const void *rsvd, const size_t rsvd_size)
{
        uint64_t v;

        IMB_ASSERT(rsvd_size == sizeof(v));
        (void) rsvd_size;

        memcpy(&v, rsvd, sizeof(v));

        return v != 0;
}

/* ------------------------------------------------------------------------- */
/* Context lifecycle                                                         */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_new(IMB_MGR *mgr, IMB_ML_DSA_ALG alg, IMB_ML_DSA **new_self)
{
        IMB_ML_DSA *self;

        if (new_self == NULL)
                return IMB_ERR_NULL_CTX;
        *new_self = NULL;
        if (mgr == NULL)
                return IMB_ERR_NULL_MBMGR;
        if (self_test_failed(mgr))
                return IMB_ERR_SELFTEST;
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
                ossl_ml_dsa_sample_init_avx2(self);
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
imb_ml_dsa_keypair(IMB_ML_DSA *self, void *pk, size_t pk_len, void *sk, size_t sk_len,
                   const IMB_ML_DSA_KEYGEN_PARAMS *params)
{
        const void *xi_32 = NULL;

        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;

        /*
         * The params structure size check is done before any other field is
         * read, so that fields of a mismatching structure are never accessed.
         */
        if (params != NULL) {
                if (params->size != sizeof(*params))
                        return IMB_ERR_PQC_PARAMS;
                xi_32 = params->xi_32;

                /*
                 * A NULL seed asks for a random one and takes no length,
                 * otherwise the size is fixed by FIPS 204.
                 */
                const size_t exp_seed_len = (xi_32 != NULL) ? IMB_ML_DSA_KEYGEN_SEED_BYTES : 0;

                if (params->xi_len != exp_seed_len)
                        return IMB_ERR_PQC_BUFFER_SIZE;
        }

        if (pk == NULL || sk == NULL)
                return IMB_ERR_NULL_KEY;

        /*
         * keypair() below always writes exactly self->pk_len / self->sk_len
         * bytes - an undersized caller-supplied capacity would otherwise
         * result in an out-of-bounds write.
         */
        if (pk_len < self->pk_len || sk_len < self->sk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->keypair(self, pk, sk, xi_32);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

/* ------------------------------------------------------------------------- */
/* Key binding                                                               */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_set_privkey(IMB_ML_DSA *self, const void *sk, size_t sk_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;
        if (sk == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (sk_len != self->sk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->set_privkey(self, sk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_set_pubkey(IMB_ML_DSA *self, const void *pk, size_t pk_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;
        if (pk == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (pk_len != self->pk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

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

        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;

        /*
         * The params structure size check is done before any other field is
         * read, so that fields of a mismatching structure are never accessed.
         */
        if (params != NULL) {
                if (params->size != sizeof(*params) ||
                    ml_dsa_reserved_is_set(params->reserved, sizeof(params->reserved)))
                        return IMB_ERR_PQC_PARAMS;
                ctx = params->ctx;
                ctx_len = params->ctx_len;
                rnd_32 = params->rnd_32;
                msg_is_mu = params->msg_is_mu;

                /*
                 * A NULL randomizer asks for a hedged (auto-random) signature
                 * and takes no length, otherwise the size is fixed by FIPS 204.
                 */
                const size_t exp_rnd_len = (rnd_32 != NULL) ? IMB_ML_DSA_SIGN_RND_BYTES : 0;

                if (params->rnd_len != exp_rnd_len)
                        return IMB_ERR_PQC_BUFFER_SIZE;
        }
        if (sig == NULL || sig_len == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
        if (msg_is_mu && msg_len != IMB_ML_DSA_MU_BYTES)
                return IMB_ERR_PQC_MSG_LEN;
        /*
         * A pre-computed mu already binds the context string, so a ctx
         * supplied alongside it cannot be honoured - reject rather than
         * silently ignore it.
         */
        if (msg_is_mu && (ctx != NULL || ctx_len != 0))
                return IMB_ERR_PQC_PARAMS;
        if (ctx == NULL && ctx_len != 0)
                return IMB_ERR_NULL_SRC;
        if (ctx_len > IMB_ML_DSA_MAX_CTX_BYTES)
                return IMB_ERR_PQC_CTX_LEN;
        /*
         * *sig_len is [in,out]: on entry it must hold the caller's buffer
         * capacity. sign_ctx() below always writes exactly self->sig_len
         * bytes into sig - an undersized caller-supplied capacity would
         * otherwise result in an out-of-bounds write.
         */
        if (*sig_len < self->sig_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

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
                         size_t msg_len, const void *rnd_32_or_null, size_t rnd_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;
        if (sig == NULL || sig_len == NULL)
                return IMB_ERR_NULL_DST;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
        /* See imb_ml_dsa_sign() above: randomizer-length check. */
        if (rnd_len != ((rnd_32_or_null != NULL) ? IMB_ML_DSA_SIGN_RND_BYTES : 0))
                return IMB_ERR_PQC_BUFFER_SIZE;

        /* See imb_ml_dsa_sign() above: output buffer-capacity check. */
        if (*sig_len < self->sig_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

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

        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;

        /*
         * The params structure size check is done before any other field is
         * read, so that fields of a mismatching structure are never accessed.
         */
        if (params != NULL) {
                if (params->size != sizeof(*params) ||
                    ml_dsa_reserved_is_set(params->reserved, sizeof(params->reserved)))
                        return IMB_ERR_PQC_PARAMS;
                ctx = params->ctx;
                ctx_len = params->ctx_len;
                msg_is_mu = params->msg_is_mu;
        }
        if (sig == NULL)
                return IMB_ERR_NULL_SRC;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
        if (msg_is_mu && msg_len != IMB_ML_DSA_MU_BYTES)
                return IMB_ERR_PQC_MSG_LEN;
        /* See imb_ml_dsa_sign(): ctx cannot be combined with a pre-computed mu. */
        if (msg_is_mu && (ctx != NULL || ctx_len != 0))
                return IMB_ERR_PQC_PARAMS;
        if (ctx == NULL && ctx_len != 0)
                return IMB_ERR_NULL_SRC;
        if (ctx_len > IMB_ML_DSA_MAX_CTX_BYTES)
                return IMB_ERR_PQC_CTX_LEN;
        const int rc = self->verify_ctx(self, msg, msg_len, ctx, ctx_len, sig, sig_len, msg_is_mu);

        if (rc == 0)
                return 0;
        return (rc == -1) ? IMB_ERR_PQC_VERIFY_FAILED : IMB_ERR_PQC_SIGNOP;
}

IMB_DLL_EXPORT int
imb_ml_dsa_verify_internal(IMB_ML_DSA *self, const void *msg, size_t msg_len, const void *sig,
                           size_t sig_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;
        if (sig == NULL)
                return IMB_ERR_NULL_SRC;
        if (self->key == NULL)
                return IMB_ERR_PQC_NO_KEY;
        if (msg == NULL && msg_len != 0)
                return IMB_ERR_NULL_SRC;
        const int rc = self->verify_internal(self, msg, msg_len, sig, sig_len);

        if (rc == 0)
                return 0;
        return (rc == -1) ? IMB_ERR_PQC_VERIFY_FAILED : IMB_ERR_PQC_SIGNOP;
}

/* ------------------------------------------------------------------------- */
/* Key validation and derivation                                             */
/* ------------------------------------------------------------------------- */
IMB_DLL_EXPORT int
imb_ml_dsa_pubkey_validate(IMB_ML_DSA *self, const void *pk, size_t pk_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;
        if (pk == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (pk_len != self->pk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->pubkey_validate(self, pk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_privkey_validate(IMB_ML_DSA *self, const void *sk, size_t sk_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;
        if (sk == NULL)
                return IMB_ERR_NULL_KEY;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (sk_len != self->sk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->privkey_validate(self, sk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}

IMB_DLL_EXPORT int
imb_ml_dsa_pubkey_from_privkey(IMB_ML_DSA *self, const void *sk, size_t sk_len, void *pk,
                               size_t pk_len)
{
        if (self == NULL)
                return IMB_ERR_NULL_CTX;
        if (self_test_failed(self->mgr))
                return IMB_ERR_SELFTEST;
        if (sk == NULL)
                return IMB_ERR_NULL_KEY;
        if (pk == NULL)
                return IMB_ERR_NULL_DST;
        /* the encoded key size is fixed by the parameter set, reject anything else */
        if (sk_len != self->sk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        /*
         * pubkey_from_privkey() below always writes exactly self->pk_len
         * bytes into pk.
         */
        if (pk_len < self->pk_len)
                return IMB_ERR_PQC_BUFFER_SIZE;

        const int rc = self->pubkey_from_privkey(self, sk, pk);

        return (rc != 0) ? IMB_ERR_PQC_KEYOP : 0;
}
