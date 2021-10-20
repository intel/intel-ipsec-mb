/*****************************************************************************
 Copyright (c) 2021, Intel Corporation

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
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"

#define BUF_SIZE ((uint32_t)sizeof(struct gcm_key_data))
#define NUM_BUFS 8

#define ZUC_MAX_BITLEN     65504
#define ZUC_MAX_BYTELEN    (ZUC_MAX_BITLEN / 8)

#ifdef _WIN32
#define __func__ __FUNCTION__
#endif

int
direct_api_param_test(struct IMB_MGR *mb_mgr);

/* Used to restore environment after potential segfaults */
jmp_buf dir_api_param_env;

#ifndef DEBUG
#ifndef _WIN32
static void seg_handler(int signum) __attribute__((noreturn));
#endif
/* Signal handler to handle segfaults */
static void
seg_handler(int signum)
{
        (void) signum; /* unused */

        signal(SIGSEGV, seg_handler); /* reset handler */
        longjmp(dir_api_param_env, 1); /* reset dir_api_param_env */
}
#endif /* DEBUG */


/* Check if imb_errno contains unexpected value */
static int
unexpected_err(IMB_MGR *mgr, const IMB_ERR expected_err, const char *func_desc)
{
        const IMB_ERR err = imb_get_errno(mgr);

        if (err != expected_err) {
                printf("%s error: expected %s, got %s\n",
                       func_desc, imb_get_strerror(expected_err),
                       imb_get_strerror(err));
                return 1;
        }
        return 0;
}

/* GCM Encrypt and Decrypt tests */
static int
test_gcm_enc_dec(struct IMB_MGR *mgr, uint8_t *in, uint8_t *out,
                 const uint64_t len, struct gcm_key_data *key,
                 struct gcm_context_data *ctx, const uint8_t *iv,
                 const uint8_t *aad, uint8_t *tag)
{
        uint64_t i;
        const uint64_t aad_len = 28;
        const uint64_t tag_len = 16;
        const uint64_t invalid_msg_len = ((1ULL << 39) - 256);

        struct gcm_enc_dec_fn {
                aes_gcm_enc_dec_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gcm128_enc, "GCM-128 ENC" },
             { mgr->gcm192_enc, "GCM-192 ENC" },
             { mgr->gcm256_enc, "GCM-256 ENC" },
             { mgr->gcm128_dec, "GCM-128 DEC" },
             { mgr->gcm192_dec, "GCM-192 DEC" },
             { mgr->gcm256_dec, "GCM-256 DEC" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                uint8_t *out;
                uint8_t *in;
                const uint64_t len;
                const uint8_t *iv;
                const uint8_t *aad;
                const uint64_t aad_len;
                uint8_t *tag;
                const uint64_t tag_len;
                const IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, out, in, len, iv, aad,
                 aad_len, tag, tag_len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, out, in, len, iv, aad,
                 aad_len, tag, tag_len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, in, len, iv, aad,
                 aad_len, tag, tag_len, IMB_ERR_NULL_DST },
                { key, ctx, out, NULL, len, iv, aad,
                 aad_len, tag, tag_len, IMB_ERR_NULL_SRC },
                { key, ctx, out, in, len, NULL, aad,
                 aad_len, tag, tag_len, IMB_ERR_NULL_IV },
                { key, ctx, out, in, len, iv, NULL,
                 aad_len, tag, tag_len, IMB_ERR_NULL_AAD },
                { key, ctx, out, in, len, iv, aad,
                 aad_len, NULL, tag_len, IMB_ERR_NULL_AUTH },
                { key, ctx, out, in, len, iv, aad,
                  aad_len, tag, 0, IMB_ERR_AUTH_TAG_LEN },
                { key, ctx, out, in, len, iv, aad,
                  aad_len, tag, 17, IMB_ERR_AUTH_TAG_LEN },
                { key, ctx, out, in, invalid_msg_len, iv, aad,
                  aad_len, tag, tag_len, IMB_ERR_CIPH_LEN }
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                memset(out, 0, len);
                memset(in, 0, len);

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->out, ap->in,
                                        ap->len, ap->iv, ap->aad, ap->aad_len,
                                        ap->tag, ap->tag_len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                                return 1;
                }
                /* Verify buffers not modified */
                if (memcmp(out, in, len) != 0) {
                        printf("%s: %s, invalid param test failed!\n",
                               __func__, fn_ptrs[i].func_name);
                        return 1;
                }
                printf(".");
        }
        return 0;
}

/* GCM key data pre-processing tests */
static int
test_gcm_precomp(struct IMB_MGR *mgr)
{
        uint64_t i;

        struct gcm_precomp_fn {
                aes_gcm_precomp_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gcm128_precomp, "GCM-128 PRECOMP" },
             { mgr->gcm192_precomp, "GCM-192 PRECOMP" },
             { mgr->gcm256_precomp, "GCM-256 PRECOMP" },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {

                /* NULL key pointer test */
                fn_ptrs[i].func(NULL);
                if (unexpected_err(mgr, IMB_ERR_NULL_EXP_KEY,
                                   fn_ptrs[i].func_name))
                        return 1;
                printf(".");
        }
        return 0;
}

/* GHASH key data pre-processing tests */
static int
test_gcm_pre(struct IMB_MGR *mgr,
             struct gcm_key_data *key_data,
             uint8_t *key)
{
        uint64_t i;

        struct gcm_pre_fn {
                aes_gcm_pre_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gcm128_pre, "GCM-128 PRE" },
             { mgr->gcm192_pre, "GCM-192 PRE" },
             { mgr->gcm256_pre, "GCM-256 PRE" },
             { mgr->ghash_pre,  "GHASH-PRE"   },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {

                memset(key, 0, sizeof(*key_data));
                memset(key_data, 0, sizeof(*key_data));

                /* NULL key pointer test */
                fn_ptrs[i].func(NULL, key_data);
                if (unexpected_err(mgr, IMB_ERR_NULL_KEY,
                                   fn_ptrs[i].func_name))
                        return 1;

                /* NULL key data pointer test */
                fn_ptrs[i].func(key, NULL);
                if (unexpected_err(mgr, IMB_ERR_NULL_EXP_KEY,
                                   fn_ptrs[i].func_name))
                        return 1;

                /* Verify no buffers have been modified */
                if (memcmp(key, key_data, sizeof(*key_data)) != 0) {
                        printf("%s: %s, invalid param test failed!\n",
                               __func__, fn_ptrs[i].func_name);
                        return 1;
                }

                /* Pass valid params to reset imb_errno */
                fn_ptrs[i].func(key, key_data);
                if (unexpected_err(mgr, 0, fn_ptrs[i].func_name))
                        return 1;
                printf(".");
        }
        return 0;
}


/* GCM Init tests */
static int
test_gcm_init(struct IMB_MGR *mgr, struct gcm_key_data *key,
              struct gcm_context_data *ctx, const uint8_t *iv,
              const uint8_t *aad)
{
        uint64_t i;
        const uint64_t aad_len = 28;

        struct gcm_init_fn {
                aes_gcm_init_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gcm128_init, "GCM-128 INIT" },
             { mgr->gcm192_init, "GCM-192 INIT" },
             { mgr->gcm256_init, "GCM-256 INIT" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                const uint8_t *iv;
                const uint8_t *aad;
                uint64_t aad_len;
                IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, iv, aad, aad_len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, iv, aad, aad_len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, aad, aad_len, IMB_ERR_NULL_IV },
                { key, ctx, iv, NULL, aad_len, IMB_ERR_NULL_AAD },
                { key, ctx, iv, aad, 0, 0 },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->iv,
                                        ap->aad, ap->aad_len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                                return 1;
                }
                printf(".");
        }
        return 0;
}

/* GCM Init variable IV len tests */
static int
test_gcm_init_var_iv(struct IMB_MGR *mgr, struct gcm_key_data *key,
                     struct gcm_context_data *ctx, const uint8_t *iv,
                     const uint8_t *aad)
{
        uint64_t i;
        const uint64_t aad_len = 28;
        const uint64_t iv_len = 16;

        struct gcm_init_var_iv_fn {
                aes_gcm_init_var_iv_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gcm128_init_var_iv, "GCM-128 INIT VAR IV" },
             { mgr->gcm192_init_var_iv, "GCM-192 INIT VAR IV" },
             { mgr->gcm256_init_var_iv, "GCM-256 INIT VAR IV" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                const uint8_t *iv;
                const uint64_t iv_len;
                const uint8_t *aad;
                uint64_t aad_len;
                IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, iv, iv_len, aad, aad_len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, iv, iv_len, aad, aad_len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, iv_len, aad, aad_len, IMB_ERR_NULL_IV },
                { key, ctx, iv, 0, aad, aad_len, IMB_ERR_IV_LEN },
                { key, ctx, iv, iv_len, NULL, aad_len, IMB_ERR_NULL_AAD },
                { key, ctx, iv, iv_len, aad, 0, 0 },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->iv,
                                        ap->iv_len, ap->aad, ap->aad_len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                                return 1;
                }
                printf(".");
        }
        return 0;
}

/* GCM Encrypt and Decrypt Update tests */
static int
test_gcm_enc_dec_update(struct IMB_MGR *mgr, uint8_t *in, uint8_t *out,
                        const uint64_t len, struct gcm_context_data *ctx,
                        struct gcm_key_data *key)
{
        uint64_t i;
        const uint64_t invalid_msg_len = ((1ULL << 39) - 256);

        struct gcm_enc_dec_update_fn {
                aes_gcm_enc_dec_update_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gcm128_enc_update, "GCM-128 ENC UPDATE" },
             { mgr->gcm192_enc_update, "GCM-192 ENC UPDATE" },
             { mgr->gcm256_enc_update, "GCM-256 ENC UPDATE" },
             { mgr->gcm128_dec_update, "GCM-128 DEC UPDATE" },
             { mgr->gcm192_dec_update, "GCM-192 DEC UPDATE" },
             { mgr->gcm256_dec_update, "GCM-256 DEC UPDATE" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                uint8_t *out;
                uint8_t *in;
                const uint64_t len;
                const IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, out, in, len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, out, in, len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, in, len, IMB_ERR_NULL_DST },
                { key, ctx, out, NULL, len, IMB_ERR_NULL_SRC },
                { key, ctx, out, in, invalid_msg_len, IMB_ERR_CIPH_LEN },
                { key, ctx, out, in, 0, 0 },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                memset(out, 0, len);
                memset(in, 0, len);

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->out,
                                        ap->in, ap->len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                                return 1;
                }

                /* Verify buffers not modified */
                if (memcmp(out, in, len) != 0) {
                        printf("%s: %s, invalid param test failed!\n",
                               __func__, fn_ptrs[i].func_name);
                        return 1;
                }
                printf(".");
        }
        return 0;
}

/* GCM Encrypt and Decrypt Finalize tests */
static int
test_gcm_enc_dec_finalize(struct IMB_MGR *mgr, struct gcm_key_data *key,
                          struct gcm_context_data *ctx, uint8_t *tag,
                          uint8_t *zero_buf)
{
        uint64_t i;
        const uint64_t tag_len = 16;

        struct gcm_enc_dec_finalize_fn {
                aes_gcm_enc_dec_finalize_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gcm128_enc_finalize, "GCM-128 ENC FINALIZE" },
             { mgr->gcm192_enc_finalize, "GCM-192 ENC FINALIZE" },
             { mgr->gcm256_enc_finalize, "GCM-256 ENC FINALIZE" },
             { mgr->gcm128_dec_finalize, "GCM-128 DEC FINALIZE" },
             { mgr->gcm192_dec_finalize, "GCM-192 DEC FINALIZE" },
             { mgr->gcm256_dec_finalize, "GCM-256 DEC FINALIZE" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                uint8_t *tag;
                const uint64_t tag_len;
                IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, tag, tag_len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, tag, tag_len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, tag_len, IMB_ERR_NULL_AUTH },
                { key, ctx, tag, 0, IMB_ERR_AUTH_TAG_LEN },
                { key, ctx, tag, 17, IMB_ERR_AUTH_TAG_LEN },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                memset(tag, 0, tag_len);
                memset(zero_buf, 0, tag_len);

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->tag, ap->tag_len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                        return 1;
                }

                /* Verify tag buffer not modified */
                if (memcmp(tag, zero_buf, tag_len) != 0) {
                        printf("%s: %s, invalid param test failed!\n",
                               __func__,
                               fn_ptrs[i].func_name);
                        return 1;
                }
                printf(".");
        }
        return 0;
}

/* GMAC init tests */
static int
test_gmac_init(struct IMB_MGR *mgr,
               struct gcm_key_data *key,
               struct gcm_context_data *ctx,
               const uint8_t *iv)
{
        uint64_t i;
        const uint64_t iv_len = 16;

        struct gmac_init_fn {
                aes_gmac_init_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gmac128_init, "GMAC-128 INIT" },
             { mgr->gmac192_init, "GMAC-192 INIT" },
             { mgr->gmac256_init, "GMAC-256 INIT" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                const uint8_t *iv;
                uint64_t iv_len;
                IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, iv, iv_len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, iv, iv_len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, iv_len, IMB_ERR_NULL_IV },
                { key, ctx, iv, 0, IMB_ERR_IV_LEN },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->iv,
                                        ap->iv_len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                                return 1;
                }
                printf(".");
        }
        return 0;
}

/* GMAC Update tests */
static int
test_gmac_update(struct IMB_MGR *mgr, uint8_t *in,
                 const uint64_t len, struct gcm_context_data *ctx,
                 struct gcm_key_data *key)
{
        uint64_t i;

        struct gmac_update_fn {
                aes_gmac_update_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gmac128_update, "GMAC-128 UPDATE" },
             { mgr->gmac192_update, "GMAC-192 UPDATE" },
             { mgr->gmac256_update, "GMAC-256 UPDATE" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                uint8_t *in;
                const uint64_t len;
                const IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, in, len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, in, len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, len, IMB_ERR_NULL_SRC },
                { key, ctx, in, 0, 0 },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->in, ap->len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                                return 1;
                }
                printf(".");
        }
        return 0;
}

/* GMAC Finalize tests */
static int
test_gmac_finalize(struct IMB_MGR *mgr, struct gcm_key_data *key,
                   struct gcm_context_data *ctx, uint8_t *tag,
                   uint8_t *zero_buf)
{
        uint64_t i;
        const uint64_t tag_len = 16;

        struct aes_gmac_finalize_fn {
                aes_gmac_finalize_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->gmac128_finalize, "GMAC-128 FINALIZE" },
             { mgr->gmac192_finalize, "GMAC-192 FINALIZE" },
             { mgr->gmac256_finalize, "GMAC-256 FINALIZE" },
        };

        struct fn_args {
                struct gcm_key_data *key;
                struct gcm_context_data *ctx;
                uint8_t *tag;
                const uint64_t tag_len;
                IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, tag, tag_len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, tag, tag_len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, tag_len, IMB_ERR_NULL_AUTH },
                { key, ctx, tag, 0, IMB_ERR_AUTH_TAG_LEN },
                { key, ctx, tag, 17, IMB_ERR_AUTH_TAG_LEN },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                uint64_t j;

                memset(tag, 0, tag_len);
                memset(zero_buf, 0, tag_len);

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->tag, ap->tag_len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                        return 1;
                }

                /* Verify tag buffer not modified */
                if (memcmp(tag, zero_buf, tag_len) != 0) {
                        printf("%s: %s, invalid param test failed!\n",
                               __func__,
                               fn_ptrs[i].func_name);
                        return 1;
                }
                printf(".");
        }
        return 0;
}

/* GHASH tests */
static int
test_ghash(struct IMB_MGR *mgr, struct gcm_key_data *key,
           uint8_t *in, const uint64_t len, uint8_t *tag)
{
        uint64_t i;
        const uint64_t tag_len = 16;

        struct fn_args {
                struct gcm_key_data *key;
                uint8_t *in;
                const uint64_t len;
                uint8_t *tag;
                const uint64_t tag_len;
                const IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, in, len, tag, tag_len, IMB_ERR_NULL_EXP_KEY },
                { key, NULL, len, tag, tag_len, IMB_ERR_NULL_SRC },
                { key, in, 0, tag, tag_len, IMB_ERR_AUTH_LEN },
                { key, in, len, NULL, tag_len, IMB_ERR_NULL_AUTH },
                { key, in, len, tag, 0, IMB_ERR_AUTH_TAG_LEN },
        };

        memset(in, 0, tag_len);
        memset(tag, 0, tag_len);

        /* Iterate over args */
        for (i = 0; i < DIM(fn_args); i++) {
                const struct fn_args *ap = &fn_args[i];

                mgr->ghash(ap->key, ap->in, ap->len,
                           ap->tag, ap->tag_len);
                if (unexpected_err(mgr, ap->exp_err, "GHASH"))
                        return 1;
        }
        /* Verify buffers not modified */
        if (memcmp(tag, in, tag_len) != 0) {
                printf("%s: %s, invalid param test failed!\n",
                       __func__, "GHASH");
                return 1;
        }
        printf(".");

        return 0;
}

/*
 * @brief Performs direct GCM API invalid param tests
 */
static int
test_gcm_api(struct IMB_MGR *mgr)
{
        const uint64_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        struct gcm_key_data *key_data = (struct gcm_key_data *)out_buf;
        struct gcm_context_data *ctx = (struct gcm_context_data *)out_buf;
        const uint8_t *iv = zero_buf;
        const uint8_t *aad = zero_buf;
        uint8_t *tag = out_buf;
        int seg_err; /* segfault flag */

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        /* GCM Encrypt and Decrypt tests */
        if (test_gcm_enc_dec(mgr, zero_buf, out_buf, text_len,
                             key_data, ctx, iv, aad, tag))
                return 1;

        /* GCM key data pre-processing tests */
        if (test_gcm_precomp(mgr))
                return 1;

        if (test_gcm_pre(mgr, key_data, zero_buf))
                return 1;

        /* GCM Init tests */
        if (test_gcm_init(mgr, key_data, ctx, iv, aad))
                return 1;

        /* GCM Init variable IV len tests */
        if (test_gcm_init_var_iv(mgr, key_data, ctx, iv, aad))
                return 1;

        /* GCM Encrypt and Decrypt update tests */
        if (test_gcm_enc_dec_update(mgr, zero_buf, out_buf,
                                    text_len, ctx, key_data))
                return 1;

        /* GCM Encrypt and Decrypt Finalize tests */
        if (test_gcm_enc_dec_finalize(mgr, key_data, ctx, tag, zero_buf))
                return 1;

        /* GMAC Init tests */
        if (test_gmac_init(mgr, key_data, ctx, iv))
                return 1;

	/* GMAC Update tests */
        if (test_gmac_update(mgr, out_buf, text_len, ctx, key_data))
                return 1;

        /* GMAC Finalize tests */
        if (test_gmac_finalize(mgr, key_data, ctx, tag, zero_buf))
                return 1;

        /* GHASH tests */
        if (test_ghash(mgr, key_data, zero_buf, text_len, out_buf))
                return 1;

        printf("\n");
        return 0;
}

/*
 * @brief Performs direct Key expansion and
 *        generation API invalid param tests
 */
static int
test_key_exp_gen_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int seg_err; /* segfault flag */

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        memset(out_buf, 0, text_len);
        memset(zero_buf, 0, text_len);

        /* @todo Add key expansion API tests */
        (void)mgr;

        printf("\n");
        return 0;
}

/*
 * @brief Performs direct hash API invalid param tests
 */
static int
test_hash_api(struct IMB_MGR *mgr)
{
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int seg_err; /* segfault flag */
        unsigned i, j;

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        memset(out_buf, 0, sizeof(out_buf));
        memset(zero_buf, 0, sizeof(zero_buf));

        /* Test hash one block API's */

        struct {
                hash_one_block_t fn;
                const char *name;
        } fn1_ptrs[] = {
                { mgr->sha1_one_block, "SHA1 ONE BLOCK" },
                { mgr->sha224_one_block, "SHA224 ONE BLOCK" },
                { mgr->sha256_one_block, "SHA256 ONE BLOCK" },
                { mgr->sha384_one_block, "SHA384 ONE BLOCK" },
                { mgr->sha512_one_block, "SHA512 ONE BLOCK" },
                { mgr->md5_one_block, "MD5 ONE BLOCK" },
        };

        struct {
                const void *src;
                void *auth;
                IMB_ERR exp_err;
        } fn1_args[] = {
                { NULL, out_buf, IMB_ERR_NULL_SRC },
                { zero_buf, NULL, IMB_ERR_NULL_AUTH },
                { zero_buf, out_buf, 0 },
        };

        for (i = 0; i < DIM(fn1_ptrs); i++) {
                for (j = 0; j < DIM(fn1_args); j++) {
                        fn1_ptrs[i].fn(fn1_args[j].src,
                                       fn1_args[j].auth);

                        if (unexpected_err(mgr, fn1_args[j].exp_err,
                                           fn1_ptrs[i].name))
                        return 1;
                }
        }

        /* Test hash API's */

        struct {
                hash_fn_t fn;
                const char *name;
        } fn2_ptrs[] = {
                { mgr->sha1, "SHA1" },
                { mgr->sha224, "SHA224" },
                { mgr->sha256, "SHA256" },
                { mgr->sha384, "SHA384" },
                { mgr->sha512, "SHA512" },
        };

        struct {
                const void *src;
                uint64_t length;
                void *auth;
                IMB_ERR exp_err;
        } fn2_args[] = {
                { NULL, sizeof(zero_buf), out_buf, IMB_ERR_NULL_SRC },
                { zero_buf, sizeof(zero_buf), NULL, IMB_ERR_NULL_AUTH },
                { zero_buf, 0, out_buf, 0 },
                { zero_buf, sizeof(zero_buf), out_buf, 0 },
        };

        for (i = 0; i < DIM(fn2_ptrs); i++) {
                for (j = 0; j < DIM(fn2_args); j++) {
                        fn2_ptrs[i].fn(fn2_args[j].src,
                                       fn2_args[j].length,
                                       fn2_args[j].auth);

                        if (unexpected_err(mgr, fn2_args[j].exp_err,
                                           fn2_ptrs[i].name))
                        return 1;
                }
        }

        return 0;
}

/*
 * @brief Performs direct AES API invalid param tests
 */
static int
test_aes_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int seg_err; /* segfault flag */

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        memset(out_buf, 0, text_len);
        memset(zero_buf, 0, text_len);

        /* @todo Add AES API tests e.g. CFB */
        (void)mgr;

        printf("\n");
        return 0;
}

/* ZUC-EEA3 1 Buffer tests */
static int
test_zuc_eea3_1_buffer(struct IMB_MGR *mgr, const void *key, const void *iv,
                       const void *in, void *out, const uint32_t len)
{
        unsigned int i;
        const char func_name[] = "ZUC-EEA3 1 BUFFER";

        struct fn_args {
                const void *key;
                const void *iv;
                const void *in;
                void *out;
                const uint32_t len;
                const IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, iv, in, out, len, IMB_ERR_NULL_KEY },
                { key, NULL, in, out, len, IMB_ERR_NULL_IV },
                { key, iv, NULL, out, len, IMB_ERR_NULL_SRC },
                { key, iv, in, NULL, len, IMB_ERR_NULL_DST },
                { key, iv, in, out, 0, IMB_ERR_CIPH_LEN},
                { key, iv, in, out, ZUC_MAX_BYTELEN + 1, IMB_ERR_CIPH_LEN},
                { key, iv, in, out, len, 0},
        };

        /* Iterate over args */
        for (i = 0; i < DIM(fn_args); i++) {
                const struct fn_args *ap = &fn_args[i];

                mgr->eea3_1_buffer(ap->key, ap->iv, ap->in, ap->out, ap->len);
                if (unexpected_err(mgr, ap->exp_err, func_name))
                        return 1;
        }

        return 0;
}

/* ZUC-EEA3 4 Buffer tests */
static int
test_zuc_eea3_4_buffer(struct IMB_MGR *mgr, const void **key, const void **iv,
                       const void **in, void **out,
                       const uint32_t *lens, const uint32_t *zero_lens,
                       const uint32_t *oversized_lens)
{
        unsigned int i;
        const char func_name[] = "ZUC-EEA3 4 BUFFER";

        struct fn_args {
                const void **key;
                const void **iv;
                const void *in;
                void *out;
                const uint32_t *lens;
                const IMB_ERR exp_err;
        } fn_args[] = {
                {NULL, iv, in, out, lens, IMB_ERR_NULL_KEY},
                {key, NULL, in, out, lens, IMB_ERR_NULL_IV},
                {key, iv, NULL, out, lens, IMB_ERR_NULL_SRC},
                {key, iv, in, NULL, lens, IMB_ERR_NULL_DST},
                {key, iv, in, out, zero_lens, IMB_ERR_CIPH_LEN},
                {key, iv, in, out, oversized_lens, IMB_ERR_CIPH_LEN},
                {key, iv, in, out, lens, 0},
        };

        /* Iterate over args */
        for (i = 0; i < DIM(fn_args); i++) {
                const struct fn_args *ap = &fn_args[i];

                mgr->eea3_4_buffer(ap->key, ap->iv, ap->in, ap->out, ap->lens);
                if (unexpected_err(mgr, ap->exp_err, func_name))
                        return 1;
        }

        return 0;
}

/*
 * @brief Performs direct ZUC API invalid param tests
 */
static int
test_zuc_api(struct IMB_MGR *mgr)
{
        int seg_err; /* segfault flag */
        uint8_t in_bufs[NUM_BUFS][BUF_SIZE];
        uint8_t out_bufs[NUM_BUFS][BUF_SIZE];
        uint32_t lens[NUM_BUFS];
        uint32_t zero_lens[NUM_BUFS];
        uint32_t oversized_lens[NUM_BUFS];
        const uint8_t key[NUM_BUFS][16];
        const uint8_t iv[NUM_BUFS][16];
        const void *key_ptrs[NUM_BUFS];
        const void *iv_ptrs[NUM_BUFS];
        const void *in_ptrs[NUM_BUFS];
        void *out_ptrs[NUM_BUFS];
        unsigned int i;

        for (i = 0; i < NUM_BUFS; i++) {
                key_ptrs[i] = key[i];
                iv_ptrs[i] = iv[i];
                in_ptrs[i] = in_bufs[i];
                out_ptrs[i] = out_bufs[i];
                lens[i] = BUF_SIZE;
                zero_lens[i] = 0;
                oversized_lens[i] = ZUC_MAX_BYTELEN + 1;
        }
        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        if (test_zuc_eea3_1_buffer(mgr, key[0], iv[0], in_bufs[0],
                                   out_bufs[0], lens[0]))
                return 1;

        if (test_zuc_eea3_4_buffer(mgr, key_ptrs, iv_ptrs,
                                   in_ptrs, out_ptrs,
                                   lens, zero_lens, oversized_lens))
                return 1;

        return 0;
}

/*
 * @brief Performs direct KASUMI API invalid param tests
 */
static int
test_kasumi_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int i, seg_err; /* segfault flag */
        void *out_bufs[NUM_BUFS];
        uint32_t lens[NUM_BUFS];

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        for (i = 0; i < NUM_BUFS; i++) {
                out_bufs[i] = (void *)&out_buf;
                lens[i] = text_len;
        }

        memset(out_buf, 0, text_len);
        memset(zero_buf, 0, text_len);

        /* @todo Add KASUMI API tests */
        (void)mgr;
        (void)lens;
        (void)out_bufs;

        printf("\n");
        return 0;
}

/*
 * @brief Performs direct SNOW3G API invalid param tests
 */
static int
test_snow3g_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int i, seg_err; /* segfault flag */
        void *out_bufs[NUM_BUFS];
        uint32_t lens[NUM_BUFS];

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        for (i = 0; i < NUM_BUFS; i++) {
                out_bufs[i] = (void *)&out_buf;
                lens[i] = text_len;
        }

        memset(out_buf, 0, text_len);
        memset(zero_buf, 0, text_len);

        /* @todo Add SNOW3G API tests */
        (void)mgr;
        (void)lens;
        (void)out_bufs;

        printf("\n");
        return 0;
}

/*
 * @brief Performs direct hec API invalid param tests
 */
static int
test_hec_api(struct IMB_MGR *mgr)
{
        uint8_t out_buf[8];
        uint8_t zero_buf[8];
        int seg_err; /* segfault flag */

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        memset(out_buf, 0, sizeof(out_buf));
        memset(zero_buf, 0, sizeof(zero_buf));

        /* Test HEC API's */
        IMB_HEC_32(mgr, NULL);
        if (unexpected_err(mgr, IMB_ERR_NULL_SRC, "HEC 32"))
                return 1;

        IMB_HEC_64(mgr, NULL);
        if (unexpected_err(mgr, IMB_ERR_NULL_SRC, "HEC 64"))
                return 1;

        return 0;
}

/*
 * @brief Performs direct CRC API invalid param tests
 */
static int
test_crc_api(struct IMB_MGR *mgr)
{
        uint8_t in_buf[BUF_SIZE];
        int seg_err; /* segfault flag */
        unsigned i, j;

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        /* Test CRC API's */
        struct {
                crc32_fn_t fn;
                const char *name;
        } fn1_ptrs[] = {
                { mgr->crc32_ethernet_fcs, "CRC32 ETHERNET FCS" },
                { mgr->crc32_sctp, "CRC32 SCTP" },
                { mgr->crc32_wimax_ofdma_data, "CRC32 WIMAX OFDMA DATA" },
                { mgr->crc24_lte_a, "CRC24 LTE A" },
                { mgr->crc24_lte_b, "CRC24 LTE B" },
                { mgr->crc16_x25, "CRC16 X25" },
                { mgr->crc16_fp_data, "CRC16 FP DATA" },
                { mgr->crc11_fp_header, "CRC11 FP HEADER" },
                { mgr->crc10_iuup_data, "CRC10 IUUP DATA" },
                { mgr->crc8_wimax_ofdma_hcs, "CRC8 WIMAX OFDMA HCS" },
                { mgr->crc7_fp_header, "CRC7 FP HEADER" },
                { mgr->crc6_iuup_header, "CRC6 IUUP HEADER" },
        };

        struct {
                const void *src;
                const uint64_t len;
                IMB_ERR exp_err;
        } fn1_args[] = {
                { NULL, sizeof(in_buf), IMB_ERR_NULL_SRC },
                { NULL, 0, 0 },
                { in_buf, sizeof(in_buf), 0 },
        };

        for (i = 0; i < DIM(fn1_ptrs); i++) {
                for (j = 0; j < DIM(fn1_args); j++) {
                        fn1_ptrs[i].fn(fn1_args[j].src,
                                       fn1_args[j].len);

                        if (unexpected_err(mgr, fn1_args[j].exp_err,
                                           fn1_ptrs[i].name))
                        return 1;
                }
        }

        return 0;
}

/* CHACHA20-POLY1305 Init tests */
static int
test_chacha_poly_init(struct IMB_MGR *mgr,
                      struct chacha20_poly1305_context_data *ctx,
                      const void *key, const void *iv,
                      const uint8_t *aad)
{
        unsigned int i;
        const uint64_t aad_len = 28;
        const char func_name[] = "CHACHA20-POLY1305 INIT";

        struct fn_args {
                const void *key;
                struct chacha20_poly1305_context_data *ctx;
                const uint8_t *iv;
                const uint8_t *aad;
                uint64_t aad_len;
                IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, iv, aad, aad_len, IMB_ERR_NULL_KEY },
                { key, NULL, iv, aad, aad_len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, aad, aad_len, IMB_ERR_NULL_IV },
                { key, ctx, iv, NULL, aad_len, IMB_ERR_NULL_AAD },
                { key, ctx, iv, aad, 0, 0 },
        };

        /* Iterate over args */
        for (i = 0; i < DIM(fn_args); i++) {
                const struct fn_args *ap = &fn_args[i];

                mgr->chacha20_poly1305_init(ap->key, ap->ctx, ap->iv,
                                            ap->aad, ap->aad_len);
                if (unexpected_err(mgr, ap->exp_err,
                                   func_name))
                        return 1;
        }

        return 0;
}

/* CHACHA20-POLY1305 Enc/dec update tests */
static int
test_chacha_poly_enc_dec_update(struct IMB_MGR *mgr,
                      struct chacha20_poly1305_context_data *ctx,
                      const void *key)
{
        unsigned int i;
        uint8_t in[BUF_SIZE];
        uint8_t out[BUF_SIZE];
        uint32_t len = BUF_SIZE;

        struct chacha_poly_enc_dec_update_fn {
                chacha_poly_enc_dec_update_t func;
                const char *func_name;
        } fn_ptrs[] = {
             { mgr->chacha20_poly1305_enc_update,
               "CHACHA20-POLY1305 ENC UPDATE" },
             { mgr->chacha20_poly1305_dec_update,
               "CHACHA20-POLY1305 DEC UPDATE" },
        };

        struct fn_args {
                const void *key;
                struct chacha20_poly1305_context_data *ctx;
                uint8_t *out;
                uint8_t *in;
                const uint64_t len;
                const IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, ctx, out, in, len, IMB_ERR_NULL_KEY },
                { key, NULL, out, in, len, IMB_ERR_NULL_CTX },
                { key, ctx, NULL, in, len, IMB_ERR_NULL_DST },
                { key, ctx, out, NULL, len, IMB_ERR_NULL_SRC },
                { key, ctx, NULL, NULL, 0, 0 },
                { key, ctx, out, in, 0, 0 },
        };

        /* Iterate over functions */
        for (i = 0; i < DIM(fn_ptrs); i++) {
                unsigned int j;

                /* Iterate over args */
                for (j = 0; j < DIM(fn_args); j++) {
                        const struct fn_args *ap = &fn_args[j];

                        fn_ptrs[i].func(ap->key, ap->ctx, ap->out,
                                        ap->in, ap->len);
                        if (unexpected_err(mgr, ap->exp_err,
                                           fn_ptrs[i].func_name))
                                return 1;
                }
        }

        return 0;
}

/* CHACHA20-POLY1305 Finalize tests */
static int
test_chacha_poly_finalize(struct IMB_MGR *mgr,
                          struct chacha20_poly1305_context_data *ctx)
{
        unsigned int i;
        uint8_t tag[16];
        const uint32_t tag_len = 16;
        const char func_name[] = "CHACHA20-POLY1305 FINALIZE";

        struct fn_args {
                struct chacha20_poly1305_context_data *ctx;
                uint8_t *tag;
                const uint64_t tag_len;
                const IMB_ERR exp_err;
        } fn_args[] = {
                { NULL, tag, tag_len, IMB_ERR_NULL_CTX },
                { ctx, NULL, tag_len, IMB_ERR_NULL_AUTH },
                { ctx, tag, 0, IMB_ERR_AUTH_TAG_LEN },
                { ctx, tag, 17, IMB_ERR_AUTH_TAG_LEN },
        };

        /* Iterate over args */
        for (i = 0; i < DIM(fn_args); i++) {
                const struct fn_args *ap = &fn_args[i];

                mgr->chacha20_poly1305_finalize(ap->ctx,
                                ap->tag, ap->tag_len);
                if (unexpected_err(mgr, ap->exp_err, func_name))
                        return 1;
        }

        return 0;
}

/*
 * @brief Performs direct CHACHA-POLY API invalid param tests
 */
static int
test_chacha_poly_api(struct IMB_MGR *mgr)
{
        const uint8_t key[32];
        const uint8_t iv[12];
        const uint8_t aad[20];
        struct chacha20_poly1305_context_data ctx;
        int seg_err; /* segfault flag */

        seg_err = setjmp(dir_api_param_env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        /* CHACHA20-POLY1305 Init */
        if (test_chacha_poly_init(mgr, &ctx, key, iv, aad))
                return 1;

        /* CHACHA20-POLY1305 Encrypt and Decrypt update */
        if (test_chacha_poly_enc_dec_update(mgr, &ctx, key))
                return 1;

        /* CHACHA20-POLY1305 Finalize */
        if (test_chacha_poly_finalize(mgr, &ctx))
                return 1;

        return 0;
}

int
direct_api_param_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        int errors = 0, run = 0;
#ifndef DEBUG
#if defined(__linux__)
        sighandler_t handler;
#else
        void *handler;
#endif
#endif
        printf("Extended Invalid Direct API arguments test:\n");
        test_suite_start(&ts, "INVALID-DIRECT-API-ARGS");

#ifndef DEBUG
        handler = signal(SIGSEGV, seg_handler);
#endif

        if ((mb_mgr->features & IMB_FEATURE_SAFE_PARAM) == 0) {
                printf("SAFE_PARAM feature disabled, "
                       "skipping remaining tests\n");
                goto dir_api_exit;
        }

        errors += test_gcm_api(mb_mgr);
        run++;

        errors += test_key_exp_gen_api(mb_mgr);
        run++;

        errors += test_hash_api(mb_mgr);
        run++;

        errors += test_aes_api(mb_mgr);
        run++;

        errors += test_zuc_api(mb_mgr);
        run++;

        errors += test_kasumi_api(mb_mgr);
        run++;

        errors += test_snow3g_api(mb_mgr);
        run++;

        errors += test_hec_api(mb_mgr);
        run++;

        errors += test_crc_api(mb_mgr);
        run++;

        errors += test_chacha_poly_api(mb_mgr);
        run++;

        test_suite_update(&ts, run - errors, errors);

 dir_api_exit:
        errors = test_suite_end(&ts);

#ifndef DEBUG
        signal(SIGSEGV, handler);
#endif
	return errors;
}
