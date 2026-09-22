/*****************************************************************************
 Copyright (c) 2017-2026, Intel Corporation

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
ctr_test(struct IMB_MGR *);

static struct cipher_test *ctr_vectors;

static void
free_ctr_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        ctr_vectors = NULL;
}

static void
test_ctr_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                 struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                 const struct cipher_test *v)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        printf("AES-CTR standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, expkey, dust);
                        ctx = ctx128;
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, expkey, dust);
                        ctx = ctx192;
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);
                        ctx = ctx256;
                        break;
                default:
                        return;
                }

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
                                            &vec, t->dir, order, IMB_CIPHER_CNTR, 0,
                                            (unsigned) v->keySize / 8, 1, t->burst)) {
                                        printf("error #%zu %s\n", v->tcId, t->label);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
                        }
                }

                if (v->ivSize / 8 == 12) {
                        /* IV in the table didn't include block counter (12 bytes).
                         * Let's encrypt & decrypt the same but
                         * with 16 byte IV that includes block counter.
                         */
                        const unsigned new_iv_len = 16;
                        const unsigned orig_iv_len = 12;
                        uint8_t local_iv[16];

                        memcpy(local_iv, v->iv, orig_iv_len);
                        /* 32-bit 0x1 in BE == 0x01000000 in LE */
                        local_iv[12] = 0x00;
                        local_iv[13] = 0x00;
                        local_iv[14] = 0x00;
                        local_iv[15] = 0x01;

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

                                for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]);
                                     i++) {
                                        const struct kat_cipher_dir_burst_case *t = &test_cases[i];
                                        const int order = t->dir == IMB_DIR_ENCRYPT
                                                                  ? IMB_ORDER_CIPHER_HASH
                                                                  : IMB_ORDER_HASH_CIPHER;

                                        if (kat_cipher_test_aes_common(
                                                    mb_mgr, expkey, expkey, local_iv, new_iv_len,
                                                    &vec, t->dir, order, IMB_CIPHER_CNTR, 0,
                                                    (unsigned) v->keySize / 8, 1, t->burst)) {
                                                printf("error #%zu %s\n", v->tcId, t->label);
                                                test_suite_update(ctx, 0, 1);
                                        } else {
                                                test_suite_update(ctx, 1, 0);
                                        }
                                }
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_ctr_vectors_burst(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                       struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                       const struct cipher_test *v, const uint32_t num_jobs)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        if (!quiet_mode)
                printf("AES-CTR standard test vectors - Burst API (N jobs = %u):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, expkey, dust);
                        ctx = ctx128;
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, expkey, dust);
                        ctx = ctx192;
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);
                        ctx = ctx256;
                        break;
                default:
                        return;
                }

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
                                            &vec, t->dir, order, IMB_CIPHER_CNTR, 0,
                                            (unsigned) v->keySize / 8, num_jobs, t->burst)) {
                                        printf("error #%zu %s\n", v->tcId, t->label);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
                        }
                }
                if (v->ivSize / 8 == 12) {
                        /* IV in the table didn't include block counter (12 bytes).
                         * Let's encrypt & decrypt the same but
                         * with 16 byte IV that includes block counter.
                         */
                        const unsigned new_iv_len = 16;
                        const unsigned orig_iv_len = 12;
                        uint8_t local_iv[16];

                        memcpy(local_iv, v->iv, orig_iv_len);
                        /* 32-bit 0x1 in BE == 0x01000000 in LE */
                        local_iv[12] = 0x00;
                        local_iv[13] = 0x00;
                        local_iv[14] = 0x00;
                        local_iv[15] = 0x01;

                        {
                                const struct cipher_test vec = {
                                        .msg = (const char *) v->msg,
                                        .ct = (const char *) v->ct,
                                        .msgSize = v->msgSize,
                                };
                                static const struct kat_cipher_dir_burst_case test_cases[] = {
                                        { IMB_DIR_ENCRYPT, KAT_CIPHER_BURST_GENERIC,
                                          "encrypt burst" },
                                        { IMB_DIR_DECRYPT, KAT_CIPHER_BURST_GENERIC,
                                          "decrypt burst" },
                                };

                                for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]);
                                     i++) {
                                        const struct kat_cipher_dir_burst_case *t = &test_cases[i];
                                        const int order = t->dir == IMB_DIR_ENCRYPT
                                                                  ? IMB_ORDER_CIPHER_HASH
                                                                  : IMB_ORDER_HASH_CIPHER;

                                        if (kat_cipher_test_aes_common(
                                                    mb_mgr, expkey, expkey, local_iv, new_iv_len,
                                                    &vec, t->dir, order, IMB_CIPHER_CNTR, 0,
                                                    (unsigned) v->keySize / 8, num_jobs,
                                                    t->burst)) {
                                                printf("error #%zu %s\n", v->tcId, t->label);
                                                test_suite_update(ctx, 0, 1);
                                        } else {
                                                test_suite_update(ctx, 1, 0);
                                        }
                                }
                        }
                }

                {
                        const struct cipher_test vec = {
                                .msg = (const char *) v->msg,
                                .ct = (const char *) v->ct,
                                .msgSize = v->msgSize,
                        };
                        static const struct kat_cipher_dir_burst_case test_cases[] = {
                                { IMB_DIR_ENCRYPT, KAT_CIPHER_BURST_CIPHER,
                                  "encrypt cipher-only burst" },
                                { IMB_DIR_DECRYPT, KAT_CIPHER_BURST_CIPHER,
                                  "decrypt cipher-only burst" },
                        };

                        for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
                                const struct kat_cipher_dir_burst_case *t = &test_cases[i];
                                const int order = t->dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH
                                                                            : IMB_ORDER_HASH_CIPHER;

                                if (kat_cipher_test_aes_common(
                                            mb_mgr, expkey, expkey, v->iv, (unsigned) v->ivSize / 8,
                                            &vec, t->dir, order, IMB_CIPHER_CNTR, 0,
                                            (unsigned) v->keySize / 8, num_jobs, t->burst)) {
                                        printf("error #%zu %s\n", v->tcId, t->label);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
                        }
                }

                if (v->ivSize / 8 == 12) {
                        /* IV in the table didn't include block counter (12 bytes).
                         * Let's encrypt & decrypt the same but
                         * with 16 byte IV that includes block counter.
                         */
                        const unsigned new_iv_len = 16;
                        const unsigned orig_iv_len = 12;
                        uint8_t local_iv[16];

                        memcpy(local_iv, v->iv, orig_iv_len);
                        /* 32-bit 0x1 in BE == 0x01000000 in LE */
                        local_iv[12] = 0x00;
                        local_iv[13] = 0x00;
                        local_iv[14] = 0x00;
                        local_iv[15] = 0x01;

                        {
                                const struct cipher_test vec = {
                                        .msg = (const char *) v->msg,
                                        .ct = (const char *) v->ct,
                                        .msgSize = v->msgSize,
                                };
                                static const struct kat_cipher_dir_burst_case test_cases[] = {
                                        { IMB_DIR_ENCRYPT, KAT_CIPHER_BURST_CIPHER,
                                          "encrypt cipher-only burst" },
                                        { IMB_DIR_DECRYPT, KAT_CIPHER_BURST_CIPHER,
                                          "decrypt cipher-only burst" },
                                };

                                for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]);
                                     i++) {
                                        const struct kat_cipher_dir_burst_case *t = &test_cases[i];
                                        const int order = t->dir == IMB_DIR_ENCRYPT
                                                                  ? IMB_ORDER_CIPHER_HASH
                                                                  : IMB_ORDER_HASH_CIPHER;

                                        if (kat_cipher_test_aes_common(
                                                    mb_mgr, expkey, expkey, local_iv, new_iv_len,
                                                    &vec, t->dir, order, IMB_CIPHER_CNTR, 0,
                                                    (unsigned) v->keySize / 8, num_jobs,
                                                    t->burst)) {
                                                printf("error #%zu %s\n", v->tcId, t->label);
                                                test_suite_update(ctx, 0, 1);
                                        } else {
                                                test_suite_update(ctx, 1, 0);
                                        }
                                }
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
ctr_test(struct IMB_MGR *mb_mgr)
{
        uint32_t i;
        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx192;
        struct test_suite_context ctx256;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "ctr_test.json", &ctr_vectors, &jctx) < 0)
                return 1;

        /* Standard CTR vectors */
        test_suite_start(&ctx128, "AES-CTR-128");
        test_suite_start(&ctx192, "AES-CTR-192");
        test_suite_start(&ctx256, "AES-CTR-256");
        test_ctr_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, ctr_vectors);
        for (i = 1; i <= MAX_CTR_JOBS; i++)
                test_ctr_vectors_burst(mb_mgr, &ctx128, &ctx192, &ctx256, ctr_vectors, i);
        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        free_ctr_vectors(jctx);
        return errors;
}
