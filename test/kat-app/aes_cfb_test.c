/*****************************************************************************
 Copyright (c) 2024-2026, Intel Corporation

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

#define BYTE_ROUND_UP(x) ((x + 7) / 8)
#define IV_SIZE          16

int
aes_cfb_test(struct IMB_MGR *);

static struct cipher_test *aes_cfb_vectors;

static void
free_aes_cfb_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        aes_cfb_vectors = NULL;
}

static void
test_aes_cfb_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                     struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                     const struct cipher_test *v, const int num_jobs)
{
        const void *input, *output;
        const char encrypt[] = "encrypt";
        const char decrypt[] = "decrypt";
        const char *dir_text;
        DECLARE_ALIGNED(uint32_t enc_keys[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        uint32_t directions[2] = { IMB_DIR_ENCRYPT, IMB_DIR_DECRYPT };
        static const enum kat_cipher_burst_type bursts[] = {
                KAT_CIPHER_BURST_NONE,
                KAT_CIPHER_BURST_GENERIC,
                KAT_CIPHER_BURST_CIPHER,
        };

        printf("aes_cfb standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;
                /* Get number of bytes */
                uint32_t text_byte_len = BYTE_ROUND_UP((unsigned) v->msgSize);
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Vector %zu  KeySize:%zu IVSize:%u MsgSize:%zu\n", v->tcId,
                               v->keySize, IV_SIZE, v->msgSize);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, enc_keys, dust);
                        ctx = ctx128;
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, enc_keys, dust);
                        ctx = ctx192;
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, enc_keys, dust);
                        ctx = ctx256;
                        break;
                default:
                        return;
                }

                for (uint32_t in_place = 0; in_place < 2; in_place++) {
                        for (uint32_t dir = 0; dir < 2; dir++) {
                                if (directions[dir] == IMB_DIR_ENCRYPT) {
                                        input = v->msg;
                                        output = v->ct;
                                        dir_text = encrypt;
                                } else {
                                        input = v->ct;
                                        output = v->msg;
                                        dir_text = decrypt;
                                }

                                const struct cipher_test vec = {
                                        .msg = (const char *) (directions[dir] == IMB_DIR_ENCRYPT
                                                                       ? input
                                                                       : output),
                                        .ct = (const char *) (directions[dir] == IMB_DIR_ENCRYPT
                                                                      ? output
                                                                      : input),
                                        .msgSize = text_byte_len * 8,
                                };

                                for (size_t burst = 0; burst < sizeof(bursts) / sizeof(bursts[0]);
                                     burst++) {
                                        const int order = directions[dir] == IMB_DIR_ENCRYPT
                                                                  ? IMB_ORDER_CIPHER_HASH
                                                                  : IMB_ORDER_HASH_CIPHER;
                                        const char *burst_text =
                                                bursts[burst] == KAT_CIPHER_BURST_NONE ? ""
                                                : bursts[burst] == KAT_CIPHER_BURST_GENERIC
                                                        ? " burst"
                                                        : " cipher-only burst";

                                        if (kat_cipher_test_aes_common(
                                                    mb_mgr, enc_keys, enc_keys, v->iv, IV_SIZE,
                                                    &vec, directions[dir], order, IMB_CIPHER_CFB,
                                                    in_place, (unsigned) v->keySize / 8, num_jobs,
                                                    bursts[burst])) {
                                                printf("error #%zu %s%s, jobs: %i\n", v->tcId,
                                                       dir_text, burst_text, num_jobs);
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
aes_cfb_test(struct IMB_MGR *mb_mgr)
{
        uint32_t i;
        struct test_json_alloc_ctx *jctx = NULL;

        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx192;
        struct test_suite_context ctx256;

        if (load_cipher_vectors(kat_vector_dir, "aes_cfb_test.json", &aes_cfb_vectors, &jctx) < 0)
                return 1;

        /* Standard aes_cfb vectors */
        test_suite_start(&ctx128, "AES-CFB-128");
        test_suite_start(&ctx192, "AES-CFB-192");
        test_suite_start(&ctx256, "AES-CFB-256");

        for (i = 0; i < test_num_jobs_size; i++)
                test_aes_cfb_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, aes_cfb_vectors,
                                     test_num_jobs[i]);

        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        free_aes_cfb_vectors(jctx);
        return errors;
}