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

/* GCM Encrypt and Decrypt Update tests */
static int
test_gcm_enc_dec_update(struct IMB_MGR *mgr, uint8_t *in, uint8_t *out,
                        const uint64_t len, struct gcm_context_data *ctx,
                        struct gcm_key_data *key)
{
        uint64_t i;

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

        /* GCM Encrypt and Decrypt update tests */
        if (test_gcm_enc_dec_update(mgr, zero_buf, out_buf,
                                    text_len, ctx, key_data))
                return 1;

        /* GCM Encrypt and Decrypt Finalize tests */
        if (test_gcm_enc_dec_finalize(mgr, key_data, ctx, tag, zero_buf))
                return 1;

        /* GMAC update tests */
        if (test_gmac_update(mgr, out_buf, text_len, ctx, key_data))
                return 1;

        /* GMAC Finalize tests */
        if (test_gmac_finalize(mgr, key_data, ctx, tag, zero_buf))
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

        /* @todo Add hash API tests e.g. SHA, MD5 etc. */
        (void)mgr;

        printf("\n");
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

/*
 * @brief Performs direct ZUC API invalid param tests
 */
static int
test_zuc_api(struct IMB_MGR *mgr)
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

        /* @todo Add ZUC API tests */
        (void)mgr;
        (void)lens;
        (void)out_bufs;

        printf("\n");
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

        test_suite_update(&ts, run - errors, errors);

 dir_api_exit:
        errors = test_suite_end(&ts);

#ifndef DEBUG
        signal(SIGSEGV, handler);
#endif
	return errors;
}
