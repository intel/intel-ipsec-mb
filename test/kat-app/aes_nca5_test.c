/**********************************************************************
  Copyright(c) 2025-2026 Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcmp() */

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "aead_test.h"
#include "kat_common_aead.h"

int
aes_nca5_test(IMB_MGR *p_mgr);

static struct aead_test *aes_nca5_vectors;

static void
free_aes_nca5_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        aes_nca5_vectors = NULL;
}

struct aes_nca5_job_ctx {
        const uint32_t *exp_key;
};

static int
aes_nca5_job_prepare(IMB_MGR *mb_mgr, IMB_JOB *job, const struct aead_test *vec, const void *ctx)
{
        const struct aes_nca5_job_ctx *job_ctx = ctx;

        (void) mb_mgr;
        job->enc_keys = job_ctx->exp_key;
        job->dec_keys = job_ctx->exp_key;
        job->u.NCA.aad = (const uint8_t *) vec->aad;
        job->u.NCA.aad_len_in_bytes = vec->aadSize / 8;
        return 0;
}

static void
test_aes_nca5_vectors(IMB_MGR *p_mgr, struct aead_test const *vector, struct test_suite_context *ts)
{
        uint32_t *exp_key = test_aligned_alloc(16, 4 * 15 * sizeof(*exp_key));
        uint32_t *dust = test_aligned_alloc(16, 4 * 15 * sizeof(*dust));

        if (exp_key == NULL || dust == NULL) {
                test_suite_update(ts, 0, 1);
                test_aligned_free(exp_key);
                test_aligned_free(dust);
                return;
        }

        IMB_AES_KEYEXP_256(p_mgr, vector->key, exp_key, dust);

        static struct aes_nca5_job_ctx ctx;
        ctx.exp_key = exp_key;

        static const struct kat_aead_job_ops encrypt_ops = {
                .prepare = aes_nca5_job_prepare,
                .ctx = &ctx,
                .cipher_mode = IMB_CIPHER_AES_NCA5,
                .hash_alg = IMB_AUTH_AES_NCA5,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops decrypt_ops = {
                .prepare = aes_nca5_job_prepare,
                .ctx = &ctx,
                .cipher_mode = IMB_CIPHER_AES_NCA5,
                .hash_alg = IMB_AUTH_AES_NCA5,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops encrypt_in_place_ops = {
                .prepare = aes_nca5_job_prepare,
                .ctx = &ctx,
                .cipher_mode = IMB_CIPHER_AES_NCA5,
                .hash_alg = IMB_AUTH_AES_NCA5,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
                .in_place = 1,
        };
        static const struct kat_aead_job_ops decrypt_in_place_ops = {
                .prepare = aes_nca5_job_prepare,
                .ctx = &ctx,
                .cipher_mode = IMB_CIPHER_AES_NCA5,
                .hash_alg = IMB_AUTH_AES_NCA5,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 32,
                .in_place = 1,
        };

        const struct kat_aead_job_ops *ops[] = { &encrypt_ops, &encrypt_in_place_ops, &decrypt_ops,
                                                 &decrypt_in_place_ops };

        for (size_t i = 0; i < DIM(ops); i++) {
                if (kat_aead_test(p_mgr, &vector, 1, 1, ops[i], NULL, KAT_AEAD_SUBMIT_FLUSH)) {
                        test_suite_update(ts, 0, 1);
                        test_aligned_free(exp_key);
                        test_aligned_free(dust);
                        return;
                }
                test_suite_update(ts, 1, 0);
        }

        if (kat_aead_test(p_mgr, &vector, 1, 2, &encrypt_ops, NULL, KAT_AEAD_BURST) < 0 ||
            kat_aead_test(p_mgr, &vector, 1, 2, &decrypt_ops, NULL, KAT_AEAD_BURST) < 0) {
                test_suite_update(ts, 0, 1);
                test_aligned_free(exp_key);
                test_aligned_free(dust);
                return;
        }
        test_suite_update(ts, 1, 0);

        if (kat_aead_test(p_mgr, &vector, 1, 1, &encrypt_ops, &decrypt_ops, KAT_AEAD_ROUND_TRIP)) {
                test_suite_update(ts, 0, 1);
                test_aligned_free(exp_key);
                test_aligned_free(dust);
                return;
        }
        test_suite_update(ts, 1, 0);
        test_aligned_free(exp_key);
        test_aligned_free(dust);
}

static void
test_aes_nca5_std_vectors(IMB_MGR *p_mgr, struct test_suite_context *ts, const struct aead_test *v)
{

        printf("AES-NCA5 (%s API) standard test vectors:\n", "Direct/JOB");
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  Keylen:%zu IVlen:%zu "
                               "PTLen:%zu AADlen:%zu Tlen:%zu\n",
                               v->tcId, v->keySize / 8, v->ivSize / 8, v->msgSize / 8,
                               v->aadSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                test_aes_nca5_vectors(p_mgr, v, ts);
        }
        if (!quiet_mode)
                printf("\n");
}

int
aes_nca5_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts;
        int errors = 0;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_aead_vectors(kat_vector_dir, "aes_nca5_test.json", &aes_nca5_vectors, &jctx) < 0)
                return 1;

        test_suite_start(&ts, "AES-NCA5");
        test_aes_nca5_std_vectors(p_mgr, &ts, aes_nca5_vectors);

        errors += test_suite_end(&ts);

        free_aes_nca5_vectors(jctx);
        return errors;
}
