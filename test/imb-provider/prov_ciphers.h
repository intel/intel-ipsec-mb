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

#include <string.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/modes.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "e_prov.h"
#include <intel-ipsec-mb.h>

#define IV_STATE_UNINITIALISED 0 /* initial state is not initialized */
#define GCM_TAG_MAX_SIZE       16

#define PROV_CIPHER_FLAG_AEAD            0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV       0x0002
#define PROV_CIPHER_FLAG_CTS             0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK 0x0008
#define PROV_CIPHER_FLAG_RAND_KEY        0x0010

#define GCM_IV_MAX_SIZE     (1024 / 8)
#define PROV_AES_BLOCK_SIZE 16

typedef struct {
        _Atomic int val;
} CRYPTO_REF_COUNT;

typedef struct prov_evp_aes_cbc_cipher_st {
        int nid;

        int block_size;
        /* Default value for variable length ciphers */
        int key_len;
        int iv_len;

        /* Legacy structure members */
        /* Various flags */
        unsigned long flags;
        /* How the EVP_CIPHER was created. */
        int origin;
        /* init key */
        int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv,
                    int enc);
        /* encrypt/decrypt data */
        int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
                         size_t inl);
        /* cleanup ctx */
        int (*cleanup)(EVP_CIPHER_CTX *);
        /* how big ctx->cipher_data needs to be */
        int ctx_size;
        /* Populate a ASN1_TYPE with parameters */
        int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
        /* Get parameters from a ASN1_TYPE */
        int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
        /* Miscellaneous operations */
        int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr);
        /* Application data */
        void *app_data;
        /* New structure members */
        /* Above comment to be removed when legacy has gone */
        int name_id;
        char *type_name;
        const char *description;
        OSSL_PROVIDER *prov;
        CRYPTO_REF_COUNT references;
        OSSL_FUNC_cipher_newctx_fn *newctx;
        OSSL_FUNC_cipher_encrypt_init_fn *einit;
        OSSL_FUNC_cipher_decrypt_init_fn *dinit;
        OSSL_FUNC_cipher_update_fn *cupdate;
        OSSL_FUNC_cipher_final_fn *cfinal;
        OSSL_FUNC_cipher_cipher_fn *ccipher;
        OSSL_FUNC_cipher_freectx_fn *freectx;
        OSSL_FUNC_cipher_dupctx_fn *dupctx;
        OSSL_FUNC_cipher_get_params_fn *get_params;
        OSSL_FUNC_cipher_get_ctx_params_fn *get_ctx_params;
        OSSL_FUNC_cipher_set_ctx_params_fn *set_ctx_params;
        OSSL_FUNC_cipher_gettable_params_fn *gettable_params;
        OSSL_FUNC_cipher_gettable_ctx_params_fn *gettable_ctx_params;
        OSSL_FUNC_cipher_settable_ctx_params_fn *settable_ctx_params;
} PROV_EVP_CIPHER;

#pragma pack(push, 16)
typedef struct prov_gcm_ctx_st {
        /* gcm_key_data to be at the top for 64 byte alignment
         * needed by IPsec_mb library */
        struct gcm_key_data key_data;
        struct gcm_context_data gcm_ctx;
        int init_flags;
        unsigned int ckey_set;
        unsigned char *tls_aad;
        unsigned int tls_aad_set;
        unsigned char *tag;
        unsigned char *calculated_tag;
        unsigned int tag_calculated;
        EVP_CIPHER_CTX *sw_ctx;
        int sw_tls_ctrl;
        int tls_aad_len;
        int tag_len;
        int iv_len;
        unsigned int iv_set;
        unsigned int tag_set;
        int iv_gen;
        unsigned char *next_iv;
        unsigned char *iv;
        unsigned int mode; /* The mode that we are using */
        size_t keylen;
        size_t ivlen_min;
        size_t tls_aad_pad_sz;
        uint64_t tls_enc_records; /* Number of TLS records encrypted */

        /*
         * num contains the number of bytes of |iv| which are valid for modes that
         * manage partial blocks themselves.
         */
        size_t num;
        size_t bufsz; /* Number of bytes in buf */

        unsigned int enc : 1;         /* Set to 1 if we are encrypting or 0 otherwise */
        unsigned int pad : 1;         /* Whether padding should be used or not */
        unsigned int iv_gen_rand : 1; /* No IV was specified, so generate a rand IV */
        unsigned char
                buf[PROV_AES_BLOCK_SIZE]; /* Buffer of partial blocks processed via update calls */
        OSSL_LIB_CTX *libctx;             /* needed for rand calls */
        ctr128_f ctr;
} __attribute__((aligned(64))) PROV_GCM_CTX;
#pragma pack(pop)

typedef struct prov_aes_gcm_ctx_st {
        PROV_GCM_CTX base;
        PROV_EVP_CIPHER *cipher;
} PROV_AES_GCM_CTX;

int
prov_aes_gcm_ctx_get_nid(const PROV_AES_GCM_CTX *ctx);
void
prov_gcm_initctx(void *provctx, PROV_GCM_CTX *ctx, size_t keybits, size_t ivlen_min);
int
prov_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[]);
int
prov_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
int
prov_gcm_einit(void *ctx, const unsigned char *inkey, int keylen, const unsigned char *iv,
               int ivlen, int enc);
int
prov_gcm_dinit(void *ctx, const unsigned char *inkey, int keylen, const unsigned char *iv,
               int ivlen, int enc);
int
prov_gcm_stream_update(void *ctx, unsigned char *out, size_t *outl, size_t outsize,
                       const unsigned char *in, size_t inl);
int
prov_gcm_stream_final(void *ctx, unsigned char *out, size_t *outl, size_t outsize);
int
prov_gcm_cipher(void *ctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, size_t inl);
PROV_EVP_CIPHER
get_default_cipher_aes_gcm(int nid);

#define PROV_aes_gcm_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits, nid)                   \
        static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;                   \
        static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])                          \
        {                                                                                          \
                return prov_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,     \
                                                      kbits, blkbits, ivbits);                     \
        }                                                                                          \
        static OSSL_FUNC_cipher_newctx_fn alg##kbits##lc##_newctx;                                 \
        static void *alg##kbits##lc##_newctx(void *provctx)                                        \
        {                                                                                          \
                return alg##_##lc##_newctx(provctx, kbits, nid);                                   \
        }                                                                                          \
        const OSSL_DISPATCH alg##kbits##lc##_functions[] = {                                       \
                { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##kbits##lc##_newctx },             \
                { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_##lc##_freectx },               \
                { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) prov_##lc##_einit },             \
                { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) prov_##lc##_dinit },             \
                { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) prov_##lc##_stream_update },           \
                { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) prov_##lc##_stream_final },             \
                { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) prov_##lc##_cipher },                  \
                { OSSL_FUNC_CIPHER_GET_PARAMS,                                                     \
                  (void (*)(void)) alg##_##kbits##_##lc##_get_params },                            \
                { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) prov_##lc##_get_ctx_params },  \
                { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) prov_##lc##_set_ctx_params },  \
                { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) prov_cipher_generic_gettable_params },                          \
                { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) prov_cipher_aead_gettable_ctx_params },                         \
                { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) prov_cipher_aead_settable_ctx_params },                         \
                { 0, NULL }                                                                        \
        }
