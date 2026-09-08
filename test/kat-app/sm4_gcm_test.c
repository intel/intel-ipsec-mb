/**********************************************************************
  Copyright(c) 2024 Intel Corporation All rights reserved.

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

/* 0 - no extra messages, 1 - additional messages */
#define VERBOSE 0

#define AAD_SZ       24
#define IV_SZ        12
#define DIGEST_SZ    16
#define MAX_KEY_SZ   32
#define GCM_MAX_JOBS 32

int
sm4_gcm_test(IMB_MGR *p_mgr);

static struct aead_test *sm4_gcm_vectors;

static void
free_sm4_gcm_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        sm4_gcm_vectors = NULL;
}

static IMB_MGR *p_gcm_mgr = NULL;

static int
sm4_gcm_job_prepare(IMB_MGR *mb_mgr, IMB_JOB *job, const struct aead_test *vec, const void *ctx)
{
        (void) mb_mgr;
        job->enc_keys = ctx;
        job->dec_keys = ctx;
        job->u.GCM.aad = (const uint8_t *) vec->aad;
        job->u.GCM.aad_len_in_bytes = vec->aadSize / 8;
        return 0;
}

static void
test_gcm_vectors(struct aead_test const *vector, struct test_suite_context *ts)
{
        struct gcm_key_data *gdata_key = test_aligned_alloc(64, sizeof(*gdata_key));

        if (gdata_key == NULL) {
                test_suite_update(ts, 0, 1);
                return;
        }

        imb_sm4_gcm_pre(p_gcm_mgr, vector->key, gdata_key);

        static struct kat_aead_job_ops encrypt_ops = {
                .prepare = sm4_gcm_job_prepare,
                .cipher_mode = IMB_CIPHER_SM4_GCM,
                .hash_alg = IMB_AUTH_SM4_GCM,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 16,
                .in_place = 0,
        };
        static struct kat_aead_job_ops encrypt_in_place_ops = {
                .prepare = sm4_gcm_job_prepare,
                .cipher_mode = IMB_CIPHER_SM4_GCM,
                .hash_alg = IMB_AUTH_SM4_GCM,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 16,
                .in_place = 1,
        };
        static struct kat_aead_job_ops decrypt_ops = {
                .prepare = sm4_gcm_job_prepare,
                .cipher_mode = IMB_CIPHER_SM4_GCM,
                .hash_alg = IMB_AUTH_SM4_GCM,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 16,
                .in_place = 0,
        };
        static struct kat_aead_job_ops decrypt_in_place_ops = {
                .prepare = sm4_gcm_job_prepare,
                .cipher_mode = IMB_CIPHER_SM4_GCM,
                .hash_alg = IMB_AUTH_SM4_GCM,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 16,
                .in_place = 1,
        };

        encrypt_ops.ctx = gdata_key;
        encrypt_in_place_ops.ctx = gdata_key;
        decrypt_ops.ctx = gdata_key;
        decrypt_in_place_ops.ctx = gdata_key;

        const struct kat_aead_job_ops *ops[] = { &encrypt_ops, &encrypt_in_place_ops, &decrypt_ops,
                                                 &decrypt_in_place_ops };

        for (size_t i = 0; i < DIM(ops); i++) {
                if (kat_aead_test_submit_flush(p_gcm_mgr, &vector, 1, 1, ops[i])) {
                        test_suite_update(ts, 0, 1);
                        test_aligned_free(gdata_key);
                        return;
                }
                test_suite_update(ts, 1, 0);
        }

        if (kat_aead_test_round_trip(p_gcm_mgr, vector, &encrypt_ops, &decrypt_ops)) {
                test_suite_update(ts, 0, 1);
                test_aligned_free(gdata_key);
                return;
        }
        test_suite_update(ts, 1, 0);

        test_aligned_free(gdata_key);
}

static void
test_gcm_std_vectors(struct test_suite_context *ts, const struct aead_test *v)
{

        printf("SM4-GCM (%s API) standard test vectors:\n", "Direct/JOB");
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

                test_gcm_vectors(v, ts);
        }
        if (!quiet_mode)
                printf("\n");
}

int
sm4_gcm_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts;
        int errors = 0;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_aead_vectors(kat_vector_dir, "sm4_gcm_test.json", &sm4_gcm_vectors, &jctx) < 0)
                return 1;

        p_gcm_mgr = p_mgr;

        test_suite_start(&ts, "SM4-GCM");
        test_gcm_std_vectors(&ts, sm4_gcm_vectors);

        errors += test_suite_end(&ts);

        free_sm4_gcm_vectors(jctx);
        return errors;
}
