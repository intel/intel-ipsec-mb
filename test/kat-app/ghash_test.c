/**********************************************************************
  Copyright(c) 2023-2024 Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcmp() */

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "mac_test.h"
#include "kat_common_hash.h"

int
ghash_test(struct IMB_MGR *mb_mgr);

static struct mac_test *ghash_vectors;

static void
free_ghash_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        ghash_vectors = NULL;
}

static int
check_data(const uint8_t *test, const char *expected, uint64_t len, const char *data_name)
{
        int mismatch;
        int is_error = 0;

        if (len == 0)
                return is_error;

        if (test == NULL || expected == NULL || data_name == NULL)
                return 1;

        mismatch = memcmp(test, expected, len);
        if (mismatch) {
                uint64_t a;

                is_error = 1;
                printf("  expected results don't match %s \t\t", data_name);
                for (a = 0; a < len; a++)
                        if (test[a] != expected[a]) {
                                printf(" '%x' != '%x' at %llx of %llx\n", test[a], expected[a],
                                       (unsigned long long) a, (unsigned long long) len);
                                break;
                        }
        }
        return is_error;
}

struct ghash_job_ctx {
        struct gcm_key_data *key;
};

static int
ghash_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                  void *ctx)
{
        struct ghash_job_ctx *ghash = calloc(1, sizeof(*ghash));

        (void) ctx;
        if (ghash == NULL)
                return -1;

        job->user_data = ghash;
        ghash->key = test_aligned_alloc(16, sizeof(*ghash->key));
        if (ghash->key == NULL)
                return -1;

        IMB_GHASH_PRE(mb_mgr, vec->key, ghash->key);
        memset(job->auth_tag_output, 0, IMB_AES_BLOCK_SIZE);
        job->u.GHASH._key = ghash->key;
        job->u.GHASH._init_tag = job->auth_tag_output;
        return 0;
}

static void
ghash_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct ghash_job_ctx *ghash = job->user_data;

        (void) ctx;
        if (ghash != NULL) {
                test_aligned_free(ghash->key);
                free(ghash);
        }
        job->user_data = NULL;
}

int
ghash_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        struct test_json_alloc_ctx *jctx = NULL;
        int use_job_api = 0;

        if (load_mac_vectors(kat_vector_dir, "ghash_test.json", &ghash_vectors, &jctx) < 0 ||
            ghash_vectors == NULL)
                return 1;

        test_suite_start(&ts, "GHASH");

        while (use_job_api < 2) {
                const struct mac_test *vec = ghash_vectors;

                printf("GHASH test vectors (%s API):\n", use_job_api ? "job" : "direct");
                while (vec->msg != NULL) {
                        struct gcm_key_data gdata_key;
                        uint8_t T_test[16];

                        memset(&gdata_key, 0, sizeof(struct gcm_key_data));
                        memset(T_test, 0, sizeof(T_test));
                        IMB_GHASH_PRE(mb_mgr, vec->key, &gdata_key);

                        if (!use_job_api) {
                                IMB_GHASH(mb_mgr, &gdata_key, vec->msg, (vec->msgSize / 8), T_test,
                                          vec->tagSize / 8);
                        } else {
                                const struct kat_hash_job_ops ops = {
                                        .prepare = ghash_job_prepare,
                                        .cleanup = ghash_job_cleanup,
                                        .hash_alg = IMB_AUTH_GHASH,
                                        .tag_alloc_size = IMB_AES_BLOCK_SIZE,
                                };
                                const struct mac_test *vec_ptr = vec;

                                if (kat_hash_test_submit_flush(mb_mgr, &vec_ptr, 1, 1, &ops))
                                        test_suite_update(&ts, 0, 1);
                                else
                                        test_suite_update(&ts, 1, 0);
                                vec++;
                                continue;
                        }

                        if (check_data(T_test, vec->tag, vec->tagSize / 8, "generated tag (T)"))
                                test_suite_update(&ts, 0, 1);
                        else
                                test_suite_update(&ts, 1, 0);
                        vec++;
                }
                use_job_api++;
        }

        int ret = test_suite_end(&ts);

        free_ghash_vectors(jctx);
        return ret;
}
