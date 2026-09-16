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
zuc_nca6_test(IMB_MGR *p_mgr);

static struct aead_test *zuc_nca6_vectors;

static void
free_zuc_nca6_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        zuc_nca6_vectors = NULL;
}

static int
zuc_nca6_job_prepare(IMB_MGR *mb_mgr, IMB_JOB *job, const struct aead_test *vec, const void *ctx)
{
        (void) mb_mgr;
        (void) ctx;
        job->enc_keys = (const void *) vec->key;
        job->dec_keys = (const void *) vec->key;
        job->u.NCA.aad = (const uint8_t *) vec->aad;
        job->u.NCA.aad_len_in_bytes = vec->aadSize / 8;
        return 0;
}

static void
test_zuc_nca6_vectors(IMB_MGR *p_mgr, struct aead_test const *vector, struct test_suite_context *ts)
{
        static const struct kat_aead_job_ops encrypt_ops = {
                .prepare = zuc_nca6_job_prepare,
                .cipher_mode = IMB_CIPHER_ZUC_NCA6,
                .hash_alg = IMB_AUTH_ZUC_NCA6,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops decrypt_ops = {
                .prepare = zuc_nca6_job_prepare,
                .cipher_mode = IMB_CIPHER_ZUC_NCA6,
                .hash_alg = IMB_AUTH_ZUC_NCA6,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops encrypt_in_place_ops = {
                .prepare = zuc_nca6_job_prepare,
                .cipher_mode = IMB_CIPHER_ZUC_NCA6,
                .hash_alg = IMB_AUTH_ZUC_NCA6,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
                .in_place = 1,
        };
        static const struct kat_aead_job_ops decrypt_in_place_ops = {
                .prepare = zuc_nca6_job_prepare,
                .cipher_mode = IMB_CIPHER_ZUC_NCA6,
                .hash_alg = IMB_AUTH_ZUC_NCA6,
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
                        return;
                }
                test_suite_update(ts, 1, 0);
        }
        if (kat_aead_test(p_mgr, &vector, 1, 1, &encrypt_ops, &decrypt_ops, KAT_AEAD_ROUND_TRIP)) {
                test_suite_update(ts, 0, 1);
                return;
        }
        test_suite_update(ts, 1, 0);
}

static void
test_zuc_nca6_std_vectors(IMB_MGR *p_mgr, struct test_suite_context *ts, const struct aead_test *v)
{

        printf("ZUC-NCA6 (%s API) standard test vectors:\n", "Direct/JOB");
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

                test_zuc_nca6_vectors(p_mgr, v, ts);
        }
        if (!quiet_mode)
                printf("\n");
}

/*
 * Test mixing encrypt and decrypt jobs in a single flush:
 * submits one ENCRYPT and one DECRYPT job back-to-back, then flushes,
 * verifying both produce correct ciphertext/plaintext and tag.
 */
static void
test_zuc_nca6_mixed_flush(IMB_MGR *mb_mgr, struct test_suite_context *ts, const struct aead_test *v)
{
        const struct aead_test *vec_tab[2] = { v, v };
        static const struct kat_aead_job_ops encrypt_ops = {
                .prepare = zuc_nca6_job_prepare,
                .cipher_mode = IMB_CIPHER_ZUC_NCA6,
                .hash_alg = IMB_AUTH_ZUC_NCA6,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops decrypt_ops = {
                .prepare = zuc_nca6_job_prepare,
                .cipher_mode = IMB_CIPHER_ZUC_NCA6,
                .hash_alg = IMB_AUTH_ZUC_NCA6,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 32,
        };
        const struct kat_aead_job_ops *ops_tab[] = { &encrypt_ops, &decrypt_ops };

        if (kat_aead_test_submit_flush_mixed(mb_mgr, vec_tab, 2, 2, ops_tab))
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);
}

int
zuc_nca6_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts;
        const struct aead_test *v;
        int errors = 0;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_aead_vectors(kat_vector_dir, "zuc_nca6_test.json", &zuc_nca6_vectors, &jctx) < 0)
                return 1;

        test_suite_start(&ts, "ZUC-NCA6");
        test_zuc_nca6_std_vectors(p_mgr, &ts, zuc_nca6_vectors);

        for (v = zuc_nca6_vectors; v->msg != NULL; v++)
                if (v->msgSize > 0 && v->aadSize > 0)
                        test_zuc_nca6_mixed_flush(p_mgr, &ts, v);

        errors += test_suite_end(&ts);

        free_zuc_nca6_vectors(jctx);
        return errors;
}
