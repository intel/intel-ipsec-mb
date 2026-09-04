/*****************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

#define MAX_CTR_JOBS 32

int
aes_nea5_test(struct IMB_MGR *);

static struct cipher_test *aes_nea5_vectors;

static void
free_aes_nea5_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        aes_nea5_vectors = NULL;
}

static void
test_ctr_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                 const struct cipher_test *v)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        printf("AES-NEA5 standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);

                {
                        const struct cipher_test vec = {
                                .msg = (const char *) v->msg,
                                .ct = (const char *) v->ct,
                                .msgSize = v->msgSize,
                        };
                        static const struct kat_cipher_dir_burst_case test_cases[] = {
                                { IMB_DIR_ENCRYPT, KAT_CIPHER_BURST_NONE, "encrypt" },
                                { IMB_DIR_DECRYPT, KAT_CIPHER_BURST_NONE, "decrypt" },
                        };

                        for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
                                const struct kat_cipher_dir_burst_case *t = &test_cases[i];
                                const int order = t->dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH
                                                                            : IMB_ORDER_HASH_CIPHER;

                                if (kat_cipher_test_aes_common(
                                            mb_mgr, expkey, expkey, v->iv, (unsigned) v->ivSize / 8,
                                            &vec, t->dir, order, IMB_CIPHER_AES_NEA5, 0,
                                            (unsigned) v->keySize / 8, 1, t->burst)) {
                                        printf("error #%zu %s\n", v->tcId, t->label);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_ctr_vectors_burst(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                       const struct cipher_test *v, const uint32_t num_jobs)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        if (!quiet_mode)
                printf("AES-NEA5 standard test vectors - Burst API (N jobs = %u):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);

                {
                        const struct cipher_test vec = {
                                .msg = (const char *) v->msg,
                                .ct = (const char *) v->ct,
                                .msgSize = v->msgSize,
                        };
                        static const struct kat_cipher_dir_burst_case test_cases[] = {
                                { IMB_DIR_ENCRYPT, KAT_CIPHER_BURST_GENERIC, "encrypt burst" },
                                { IMB_DIR_DECRYPT, KAT_CIPHER_BURST_GENERIC, "decrypt burst" },
                        };

                        for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
                                const struct kat_cipher_dir_burst_case *t = &test_cases[i];
                                const int order = t->dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH
                                                                            : IMB_ORDER_HASH_CIPHER;

                                if (kat_cipher_test_aes_common(
                                            mb_mgr, expkey, expkey, v->iv, (unsigned) v->ivSize / 8,
                                            &vec, t->dir, order, IMB_CIPHER_AES_NEA5, 0,
                                            (unsigned) v->keySize / 8, num_jobs, t->burst)) {
                                        printf("error #%zu %s\n", v->tcId, t->label);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
aes_nea5_test(struct IMB_MGR *mb_mgr)
{
        uint32_t i;
        int errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "aes_nea5_test.json", &aes_nea5_vectors, &jctx) < 0)
                return 1;

        /* Standard CTR vectors */
        test_suite_start(&ctx, "AES-NEA5");
        test_ctr_vectors(mb_mgr, &ctx, aes_nea5_vectors);
        for (i = 1; i <= MAX_CTR_JOBS; i++)
                test_ctr_vectors_burst(mb_mgr, &ctx, aes_nea5_vectors, i);
        errors += test_suite_end(&ctx);

        free_aes_nea5_vectors(jctx);
        return errors;
}
