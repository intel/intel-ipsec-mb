/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

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

/* macros defined to allow use of the cpu get and set affinity functions */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov_provider.h"
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_bio.h"

#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_gcm.h"
#include "prov_sw_sha.h"
#include "prov_sw_hmac_sha.h"

OSSL_PROVIDER *prov = NULL;

int
prov_is_running(void)
{
        return 1;
}

OSSL_LIB_CTX *
prov_libctx_of(PROV_CTX *ctx)
{
        if (ctx == NULL)
                return NULL;
        return ctx->libctx;
}

void
prov_ctx_set_core_bio_method(PROV_CTX *ctx, PROV_BIO_METHOD *corebiometh)
{
        if (ctx != NULL)
                ctx->corebiometh = corebiometh;
}

extern const OSSL_DISPATCH prov_aes128gcm_functions[];
extern const OSSL_DISPATCH prov_aes192gcm_functions[];
extern const OSSL_DISPATCH prov_aes256gcm_functions[];

extern const OSSL_DISPATCH prov_sha1_functions[];
extern const OSSL_DISPATCH prov_sha224_functions[];
extern const OSSL_DISPATCH prov_sha256_functions[];
extern const OSSL_DISPATCH prov_sha384_functions[];
extern const OSSL_DISPATCH prov_sha512_functions[];

extern const OSSL_DISPATCH prov_aes128cfb_functions[];
extern const OSSL_DISPATCH prov_aes192cfb_functions[];
extern const OSSL_DISPATCH prov_aes256cfb_functions[];

extern const OSSL_DISPATCH prov_hmac_sha_functions[];

extern const OSSL_DISPATCH prov_aes128ccm_functions[];
extern const OSSL_DISPATCH prov_aes256ccm_functions[];

extern const OSSL_DISPATCH prov_sm4ecb_functions[];
extern const OSSL_DISPATCH prov_sm4cbc_functions[];
extern const OSSL_DISPATCH prov_sm4ctr_functions[];
extern const OSSL_DISPATCH prov_sm4gcm_functions[];

PROV_PARAMS prov_params;

static void
prov_teardown(void *provctx)
{
        free_ipsec_mb_mgr();
        if (provctx) {
                PROV_CTX *prov_ctx = (PROV_CTX *) provctx;
                BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(prov_ctx));
                OPENSSL_free(prov_ctx);
                OSSL_PROVIDER_unload(prov);
        }
}

static const OSSL_PARAM prov_param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_gettable_params(void *provctx)
{
        return prov_param_types;
}

static int
prov_get_params(void *provctx, OSSL_PARAM params[])
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
        if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PROV_PROVIDER_NAME_STR))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
        if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PROV_PROVIDER_VERSION_STR))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
        if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PROV_PROVIDER_FULL_VERSION_STR))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
        if (p != NULL && !OSSL_PARAM_set_int(p, 1))
                return 0;
        return 1;
}

static const OSSL_ALGORITHM_CAPABLE prov_deflt_ciphers[] = {
        ALG(PROV_NAMES_AES_128_GCM, prov_aes128gcm_functions),
        ALG(PROV_NAMES_AES_256_GCM, prov_aes256gcm_functions),
        ALG(PROV_NAMES_AES_192_GCM, prov_aes192gcm_functions),
        ALG(PROV_NAMES_AES_128_CFB, prov_aes128cfb_functions),
        ALG(PROV_NAMES_AES_192_CFB, prov_aes192cfb_functions),
        ALG(PROV_NAMES_AES_256_CFB, prov_aes256cfb_functions),
        ALG(PROV_NAMES_AES_128_CCM, prov_aes128ccm_functions),
        ALG(PROV_NAMES_AES_256_CCM, prov_aes256ccm_functions),
        ALG(PROV_NAMES_SM4_ECB, prov_sm4ecb_functions),
        ALG(PROV_NAMES_SM4_CBC, prov_sm4cbc_functions),
        ALG(PROV_NAMES_SM4_CTR, prov_sm4ctr_functions),
        ALG(PROV_NAMES_SM4_GCM, prov_sm4gcm_functions),
        { { NULL, NULL, NULL }, NULL }
};

static OSSL_ALGORITHM prov_exported_ciphers[IMB_DIM(prov_deflt_ciphers)];

static const OSSL_ALGORITHM prov_keyexch[] = { { NULL, NULL, NULL } };

static const OSSL_ALGORITHM prov_keymgmt[] = { { NULL, NULL, NULL } };

static const OSSL_ALGORITHM prov_signature[] = { { NULL, NULL, NULL } };

static const OSSL_ALGORITHM prov_digests[] = {
        { PROV_NAMES_SHA1, PROV_DEFAULT_PROPERTIES, prov_sha1_functions },
        { PROV_NAMES_SHA2_224, PROV_DEFAULT_PROPERTIES, prov_sha224_functions },
        { PROV_NAMES_SHA2_256, PROV_DEFAULT_PROPERTIES, prov_sha256_functions },
        { PROV_NAMES_SHA2_384, PROV_DEFAULT_PROPERTIES, prov_sha384_functions },
        { PROV_NAMES_SHA2_512, PROV_DEFAULT_PROPERTIES, prov_sha512_functions },
        { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM prov_macs[] = { { PROV_NAMES_HMAC, PROV_DEFAULT_PROPERTIES,
                                              prov_hmac_sha_functions },
                                            { NULL, NULL, NULL } };

static const OSSL_ALGORITHM *
prov_query(void *provctx, int operation_id, int *no_cache)
{
        static int prov_init = 0;
        prov = OSSL_PROVIDER_load(NULL, "default");

        if (!prov_init) {
                prov_init = 1;
                /* provider takes the highest priority
                 * and overwrite the openssl.cnf property. */
                EVP_set_default_properties(NULL, "?provider=imb-provider");
        }

        *no_cache = 0;
        switch (operation_id) {
        case OSSL_OP_DIGEST:
                return prov_digests;
        case OSSL_OP_MAC:
                return prov_macs;
        case OSSL_OP_CIPHER:
                return prov_exported_ciphers;
        case OSSL_OP_SIGNATURE:
                return prov_signature;
        case OSSL_OP_KEYMGMT:
                return prov_keymgmt;
        case OSSL_OP_KEYEXCH:
                return prov_keyexch;
        }
        return OSSL_PROVIDER_query_operation(prov, operation_id, no_cache);
}

static const OSSL_DISPATCH prov_dispatch_table[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) prov_teardown },
        { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) prov_gettable_params },
        { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void)) prov_get_params },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) prov_query },
        { 0, NULL }
};

static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

int
prov_get_params_from_core(const OSSL_CORE_HANDLE *handle)
{
        OSSL_PARAM core_params[10], *p = core_params;

        *p++ = OSSL_PARAM_construct_utf8_ptr("enable_inline_polling",
                                             (char **) &prov_params.enable_inline_polling, 0);

        *p++ = OSSL_PARAM_construct_utf8_ptr("prov_poll_interval",
                                             (char **) &prov_params.prov_poll_interval, 0);

        *p++ = OSSL_PARAM_construct_utf8_ptr("prov_epoll_timeout",
                                             (char **) &prov_params.prov_epoll_timeout, 0);

        *p++ = OSSL_PARAM_construct_utf8_ptr("enable_event_driven_polling",
                                             (char **) &prov_params.enable_event_driven_polling, 0);

        *p++ = OSSL_PARAM_construct_utf8_ptr("enable_instance_for_thread",
                                             (char **) &prov_params.enable_instance_for_thread, 0);

        *p++ = OSSL_PARAM_construct_utf8_ptr("prov_max_retry_count",
                                             (char **) &prov_params.prov_max_retry_count, 0);

        *p = OSSL_PARAM_construct_end();

        if (!c_get_params(handle, core_params)) {
                fprintf(stderr, "Get parameters from core is failed.\n");
                return 0;
        }
        return 1;
}

void
prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in, OSSL_ALGORITHM *out)
{
        int i, j;
        if (out[0].algorithm_names == NULL) {
                for (i = j = 0; in[i].alg.algorithm_names != NULL; ++i) {
                        if (in[i].capable == NULL || in[i].capable())
                                out[j++] = in[i].alg;
                }
                out[j++] = in[i].alg;
        }
}

int
OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                   const OSSL_DISPATCH **out, void **provctx)
{
        PROV_CTX *prov_ctx = NULL;
        BIO_METHOD *corebiometh = NULL;

        if (!ossl_prov_bio_from_dispatch(in))
                return 0;

        for (; in->function_id != 0; in++) {
                switch (in->function_id) {
                case OSSL_FUNC_CORE_GETTABLE_PARAMS:
                        c_gettable_params = OSSL_FUNC_core_gettable_params(in);
                        break;
                case OSSL_FUNC_CORE_GET_PARAMS:
                        c_get_params = OSSL_FUNC_core_get_params(in);
                        break;
                case OSSL_FUNC_CORE_GET_LIBCTX:
                        c_get_libctx = OSSL_FUNC_core_get_libctx(in);
                        break;
                default:
                        /* Just ignore anything we don't understand */
                        break;
                }
        }

        if (!prov_get_params_from_core(handle)) {
                return 0;
        }

        if (!bind_prov()) {
                goto err;
        }

        prov_ctx = OPENSSL_zalloc(sizeof(PROV_CTX));
        if (prov_ctx == NULL) {
                goto err;
        }

        prov_ctx->handle = handle;
        prov_ctx->libctx = (OSSL_LIB_CTX *) c_get_libctx(handle);

        *provctx = (void *) prov_ctx;
        corebiometh = ossl_bio_prov_init_bio_method();
        prov_ctx_set_core_bio_method(*provctx, corebiometh);
        *out = prov_dispatch_table;
        prov_cache_exported_algorithms(prov_deflt_ciphers, prov_exported_ciphers);

        fprintf(stderr, "Gathering benchmarks using IPSecMB imb-provider!\n");
        return 1;

err:
        fprintf(stderr, "IPSecMB imb-provider initialization failed\n");
        prov_teardown(prov_ctx);
        return 0;
}