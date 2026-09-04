/*****************************************************************************
 Copyright (c) 2023-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

int
cbc_test(struct IMB_MGR *mb_mgr);

static struct cipher_test *cbc_vectors;

/**
 * @brief Free AES-CBC vectors previously loaded by load_cbc_vectors().
 *
 * @param ctx loader context returned by load_cbc_vectors()
 */
static void
free_cbc_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        cbc_vectors = NULL;
}

static void
test_cbc_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                 struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                 const IMB_CIPHER_MODE cipher, const int num_jobs)
{
        const struct cipher_test *v = cbc_vectors;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);

        if (!quiet_mode)
                printf("CBC Test (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("AES-CBC Test Case %zu key_len:%zu\n", v->tcId, v->keySize);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case 16:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ctx128;
                        break;
                case 24:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ctx192;
                        break;
                case 32:
                default:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ctx256;
                        break;
                }

                static const struct kat_cipher_test_case test_cases[] = {
                        { IMB_DIR_ENCRYPT, 0, KAT_CIPHER_BURST_NONE, "encrypt" },
                        { IMB_DIR_ENCRYPT, 0, KAT_CIPHER_BURST_GENERIC, "encrypt burst" },
                        { IMB_DIR_DECRYPT, 0, KAT_CIPHER_BURST_NONE, "decrypt" },
                        { IMB_DIR_DECRYPT, 0, KAT_CIPHER_BURST_GENERIC, "decrypt burst" },
                        { IMB_DIR_ENCRYPT, 1, KAT_CIPHER_BURST_NONE, "encrypt in-place" },
                        { IMB_DIR_ENCRYPT, 1, KAT_CIPHER_BURST_GENERIC, "encrypt burst in-place" },
                        { IMB_DIR_DECRYPT, 1, KAT_CIPHER_BURST_NONE, "decrypt in-place" },
                        { IMB_DIR_DECRYPT, 1, KAT_CIPHER_BURST_GENERIC, "decrypt burst in-place" },
                        { IMB_DIR_ENCRYPT, 0, KAT_CIPHER_BURST_CIPHER, "encrypt cipher burst" },
                        { IMB_DIR_DECRYPT, 0, KAT_CIPHER_BURST_CIPHER, "decrypt cipher burst" },
                        { IMB_DIR_ENCRYPT, 1, KAT_CIPHER_BURST_CIPHER,
                          "encrypt cipher burst in-place" },
                        { IMB_DIR_DECRYPT, 1, KAT_CIPHER_BURST_CIPHER,
                          "decrypt cipher burst in-place" },
                };

                for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
                        const struct kat_cipher_test_case *t = &test_cases[i];
                        const int order = t->dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH
                                                                    : IMB_ORDER_HASH_CIPHER;

                        if (kat_cipher_test_aes_common(
                                    mb_mgr, enc_keys, dec_keys, v->iv, 16, v, t->dir, order, cipher,
                                    t->in_place, (unsigned) v->keySize / 8, num_jobs, t->burst)) {
                                printf("error #%zu %s\n", v->tcId, t->label);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
cbc_test(struct IMB_MGR *mb_mgr)
{
        unsigned i;
        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx192;
        struct test_suite_context ctx256;
        struct test_json_alloc_ctx *ctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "cbc_test.json", &cbc_vectors, &ctx) < 0)
                return 1;

        test_suite_start(&ctx128, "AES-CBC-128");
        test_suite_start(&ctx192, "AES-CBC-192");
        test_suite_start(&ctx256, "AES-CBC-256");
        for (i = 0; i < test_num_jobs_size; i++)
                test_cbc_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, IMB_CIPHER_CBC,
                                 test_num_jobs[i]);
        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        free_cbc_vectors(ctx);

        return errors;
}
