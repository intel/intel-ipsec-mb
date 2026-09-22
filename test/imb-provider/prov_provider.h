/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_PROVIDER_H
#define PROV_PROVIDER_H

#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>

#define PROV_PROVIDER_VERSION_STR      "v1.0"
#define PROV_PROVIDER_FULL_VERSION_STR "imb-provider v1.0"
#define PROV_PROVIDER_NAME_STR         "imb-provider"

#define PROV_NAMES_AES_128_GCM "AES-128-GCM"
#define PROV_NAMES_AES_192_GCM "AES-192-GCM"
#define PROV_NAMES_AES_256_GCM "AES-256-GCM"

#define PROV_NAMES_CHACHA20_POLY1305 "ChaCha20-Poly1305"

#define PROV_NAMES_HMAC "HMAC"

#define PROV_NAMES_AES_128_CFB "AES-128-CFB"
#define PROV_NAMES_AES_192_CFB "AES-192-CFB"
#define PROV_NAMES_AES_256_CFB "AES-256-CFB"

#define PROV_NAMES_SM4_ECB "SM4-ECB"
#define PROV_NAMES_SM4_CBC "SM4-CBC"
#define PROV_NAMES_SM4_CTR "SM4-CTR"
#define PROV_NAMES_SM4_GCM "SM4-GCM"

#define PROV_NAMES_SHA1     "SHA1:SHA-1:1.3.14.3.2.26"
#define PROV_NAMES_SHA2_224 "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define PROV_NAMES_SHA2_256 "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define PROV_NAMES_SHA2_384 "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define PROV_NAMES_SHA2_512 "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"

#define PROV_NAMES_SHA3_224 "SHA3-224:id-sha3-224:2.16.840.1.101.3.4.2.7"
#define PROV_NAMES_SHA3_256 "SHA3-256:id-sha3-256:2.16.840.1.101.3.4.2.8"
#define PROV_NAMES_SHA3_384 "SHA3-384:id-sha3-384:2.16.840.1.101.3.4.2.9"
#define PROV_NAMES_SHA3_512 "SHA3-512:id-sha3-512:2.16.840.1.101.3.4.2.10"
#define PROV_NAMES_SHAKE128 "SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11"
#define PROV_NAMES_SHAKE256 "SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12"

/* SHA3/SHAKE block sizes = Keccak absorption rate in bytes */
#define PROV_SHA3_224_BLOCK_SIZE          144
#define PROV_SHA3_256_BLOCK_SIZE          136
#define PROV_SHA3_384_BLOCK_SIZE          104
#define PROV_SHA3_512_BLOCK_SIZE          72
#define PROV_SHAKE128_BLOCK_SIZE          168
#define PROV_SHAKE256_BLOCK_SIZE          136
#define PROV_SHAKE128_DEFAULT_DIGEST_SIZE 32
#define PROV_SHAKE256_DEFAULT_DIGEST_SIZE 64

#define PROV_NAMES_AES_128_CCM "AES-128-CCM"
#define PROV_NAMES_AES_256_CCM "AES-256-CCM"

#define PROV_NAMES_CHACHA20 "chacha20"
#define PROV_NAMES_POLY1305 "POLY1305"

/* ML-DSA */
#define PROV_NAMES_ML_DSA_44 "ML-DSA-44:id-ml-dsa-44:2.16.840.1.101.3.4.3.17"
#define PROV_NAMES_ML_DSA_65 "ML-DSA-65:id-ml-dsa-65:2.16.840.1.101.3.4.3.18"
#define PROV_NAMES_ML_DSA_87 "ML-DSA-87:id-ml-dsa-87:2.16.840.1.101.3.4.3.19"

/* ML-KEM */
#define PROV_NAMES_ML_KEM_512  "ML-KEM-512:id-alg-ml-kem-512:2.16.840.1.101.3.4.4.1"
#define PROV_NAMES_ML_KEM_768  "ML-KEM-768:id-alg-ml-kem-768:2.16.840.1.101.3.4.4.2"
#define PROV_NAMES_ML_KEM_1024 "ML-KEM-1024:id-alg-ml-kem-1024:2.16.840.1.101.3.4.4.3"

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, PROV_DEFAULT_PROPERTIES, FUNC }, CHECK }
#define ALG(NAMES, FUNC)         ALGC(NAMES, FUNC, NULL)

static const char PROV_DEFAULT_PROPERTIES[] = "provider=imb-provider";

typedef struct bio_method_st {
        int type;
        char *name;
        int (*bwrite)(BIO *, const char *, size_t, size_t *);
        int (*bwrite_old)(BIO *, const char *, int);
        int (*bread)(BIO *, char *, size_t, size_t *);
        int (*bread_old)(BIO *, char *, int);
        int (*bputs)(BIO *, const char *);
        int (*bgets)(BIO *, char *, int);
        long (*ctrl)(BIO *, int, long, void *);
        int (*create)(BIO *);
        int (*destroy)(BIO *);
        long (*callback_ctrl)(BIO *, int, BIO_info_cb *);
} PROV_BIO_METHOD;

typedef struct prov_provider_ctx_st {
        const OSSL_CORE_HANDLE *handle;
        OSSL_LIB_CTX *libctx;
        PROV_BIO_METHOD *corebiometh;
} PROV_CTX;

typedef struct prov_provider_params_st {
        char *enable_inline_polling;
        char *prov_poll_interval;
        char *prov_epoll_timeout;
        char *enable_event_driven_polling;
        char *enable_instance_for_thread;
        char *prov_max_retry_count;
} PROV_PARAMS;

typedef struct prov_ag_capable_st {
        OSSL_ALGORITHM alg;
        int (*capable)(void);
} OSSL_ALGORITHM_CAPABLE;
void
prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in, OSSL_ALGORITHM *out);
int
prov_is_running(void);
OSSL_LIB_CTX *
prov_libctx_of(PROV_CTX *ctx);

int
prov_securitycheck_enabled(OSSL_LIB_CTX *libctx);

#endif /* PROV_PROVIDER_H */
