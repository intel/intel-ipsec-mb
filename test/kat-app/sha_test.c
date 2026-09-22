/*****************************************************************************
 Copyright (c) 2018-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "mac_test.h"
#include "kat_common_hash.h"

int
sha_test(struct IMB_MGR *mb_mgr);

static struct mac_test *sha_vectors;

static void
free_sha_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        sha_vectors = NULL;
}

static int
sha_hash_alg(const int sha_type, IMB_HASH_ALG *hash_alg)
{
        switch (sha_type) {
        case 1:
                *hash_alg = IMB_AUTH_SHA_1;
                break;
        case 224:
                *hash_alg = IMB_AUTH_SHA_224;
                break;
        case 256:
                *hash_alg = IMB_AUTH_SHA_256;
                break;
        case 384:
                *hash_alg = IMB_AUTH_SHA_384;
                break;
        case 512:
                *hash_alg = IMB_AUTH_SHA_512;
                break;
        default:
                return -1;
        }

        return 0;
}

static int
test_sha(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs, const int sha_type)
{
        IMB_HASH_ALG hash_alg;

        if (sha_hash_alg(sha_type, &hash_alg) < 0)
                return -1;

        const struct kat_hash_job_ops ops = {
                .hash_alg = hash_alg,
        };

        return kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops);
}

static int
test_sha_sb(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs,
            const int sha_type)
{
        uint8_t padding[16];
        uint8_t *auths;
        int i = 0, ret = -1;
        const size_t sizeof_padding = sizeof(padding);

        memset(padding, -1, sizeof_padding);

        const size_t alloc_len = vec->tagSize / 8 + (sizeof_padding * 2);

        auths = malloc(alloc_len);
        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end;
        }
        memset(auths, -1, alloc_len);

        for (i = 0; i < num_jobs; i++) {
                switch (sha_type) {
                case 1:
                        IMB_SHA1(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                case 224:
                        IMB_SHA224(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                case 256:
                        IMB_SHA256(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                case 384:
                        IMB_SHA384(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                case 512:
                        IMB_SHA512(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                default:
                        fprintf(stderr, "SHA algorithm not supported\n");
                        goto end;
                }
                if (memcmp(auths + sizeof_padding, vec->tag, vec->tagSize / 8) != 0) {
                        fprintf(stderr, "hash mismatched\n");
                        goto end;
                }
                if (memcmp(padding, auths, sizeof_padding)) {
                        fprintf(stderr, "hash overwrite head\n");
                        goto end;
                }
                if (memcmp(padding, auths + vec->tagSize / 8 + sizeof_padding, sizeof_padding)) {
                        fprintf(stderr, "hash overwrite tail\n");
                        goto end;
                }
        }

        ret = 0;

end:
        if (auths != NULL)
                free(auths);

        return ret;
}

static int
test_sha_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs,
                    const int sha_type)
{
        IMB_HASH_ALG hash_alg;

        if (sha_hash_alg(sha_type, &hash_alg) < 0)
                return -1;

        const struct kat_hash_job_ops ops = {
                .hash_alg = hash_alg,
        };

        return kat_hash_test_hash_burst(mb_mgr, &vec, 1, num_jobs, &ops);
}

static void
test_sha_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *sha1_ctx,
                 struct test_suite_context *sha224_ctx, struct test_suite_context *sha256_ctx,
                 struct test_suite_context *sha384_ctx, struct test_suite_context *sha512_ctx,
                 const int num_jobs)
{
        struct test_suite_context *ctx;
        const struct mac_test *v = sha_vectors;
        int sha_type;

        if (!quiet_mode)
                printf("SHA standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                switch (v->tagSize) {
                case 160:
                        ctx = sha1_ctx;
                        sha_type = 1;
                        break;
                case 224:
                        ctx = sha224_ctx;
                        sha_type = 224;
                        break;
                case 256:
                        ctx = sha256_ctx;
                        sha_type = 256;
                        break;
                case 384:
                        ctx = sha384_ctx;
                        sha_type = 384;
                        break;
                case 512:
                        ctx = sha512_ctx;
                        sha_type = 512;
                        break;
                default:
                        ctx = sha1_ctx;
                        printf("error #%zu, invalid tag size\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                        continue;
                }
#ifdef DEBUG
                if (!quiet_mode) {
                        printf("SHA%d Test Case %zu "
                               "data_len:%zu digest_len:%zu\n",
                               sha_type, v->tcId, v->msgSize / 8, v->tagSize / 8);
                }
#endif
                if (test_sha(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_sha_sb(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_sha_hash_burst(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
}

int
sha_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context sha1_ctx, sha224_ctx, sha256_ctx;
        struct test_suite_context sha384_ctx, sha512_ctx;
        struct test_json_alloc_ctx *ctx = NULL;
        int errors;
        unsigned i;

        if (load_mac_vectors(kat_vector_dir, "sha_test.json", &sha_vectors, &ctx) < 0 ||
            sha_vectors == NULL)
                return 1;

        test_suite_start(&sha1_ctx, "SHA1");
        test_suite_start(&sha224_ctx, "SHA224");
        test_suite_start(&sha256_ctx, "SHA256");
        test_suite_start(&sha384_ctx, "SHA384");
        test_suite_start(&sha512_ctx, "SHA512");
        for (i = 1; i <= 17; i++) {
                test_sha_vectors(mb_mgr, &sha1_ctx, &sha224_ctx, &sha256_ctx, &sha384_ctx,
                                 &sha512_ctx, i);
        }
        errors = test_suite_end(&sha1_ctx);
        errors += test_suite_end(&sha224_ctx);
        errors += test_suite_end(&sha256_ctx);
        errors += test_suite_end(&sha384_ctx);
        errors += test_suite_end(&sha512_ctx);

        free_sha_vectors(ctx);
        return errors;
}
