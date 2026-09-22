/*****************************************************************************
 Copyright (c) 2009-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

/*-----------------------------------------------------------------------
 * KASUMI functional test
 *-----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "mac_test.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

static struct mac_test *kasumi_f9_vectors;

static void
free_kasumi_f9_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        kasumi_f9_vectors = NULL;
}

static struct cipher_test *kasumi_f8_vectors;

static void
free_kasumi_f8_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        kasumi_f8_vectors = NULL;
}

int
kasumi_test(struct IMB_MGR *mb_mgr);
static int
validate_kasumi_f8_1_block(struct IMB_MGR *mb_mgr);
static int
validate_kasumi_f9(IMB_MGR *mgr);

static int
submit_kasumi_f9_job(struct IMB_MGR *mb_mgr, kasumi_key_sched_t *key, const void *src, void *tag,
                     const uint32_t len);

struct kasumi_f8_job_ctx {
        kasumi_key_sched_t *key_sched;
        uint8_t *key;
        uint8_t *iv;
};

static int
kasumi_f8_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                      void *ctx)
{
        struct kasumi_f8_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) ctx;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->key = test_aligned_alloc_copy(16, vec->key, vec->keySize / 8);
        job_ctx->iv = malloc(vec->ivSize / 8 == 0 ? 1 : vec->ivSize / 8);
        job_ctx->key_sched = test_aligned_alloc(16, IMB_KASUMI_KEY_SCHED_SIZE(mb_mgr));
        if (job_ctx->key == NULL || job_ctx->iv == NULL || job_ctx->key_sched == NULL)
                return -1;

        memcpy(job_ctx->iv, vec->iv, vec->ivSize / 8);
        if (IMB_KASUMI_INIT_F8_KEY_SCHED(mb_mgr, job_ctx->key, job_ctx->key_sched) != 0)
                return -1;

        job->enc_keys = job_ctx->key_sched;
        job->dec_keys = job_ctx->key_sched;
        job->iv = job_ctx->iv;
        job->iv_len_in_bytes = IMB_KASUMI_IV_SIZE;
        return 0;
}

static void
kasumi_f8_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct kasumi_f8_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->key_sched);
                test_aligned_free(job_ctx->key);
                free(job_ctx->iv);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
submit_kasumi_f8_job(struct IMB_MGR *mb_mgr, const struct cipher_test *vec, const int dir)
{
        const struct cipher_test *vec_ptr = vec;
        const struct kat_cipher_job_ops ops = {
                .prepare = kasumi_f8_job_prepare,
                .cleanup = kasumi_f8_job_cleanup,
                .cipher_mode = IMB_CIPHER_KASUMI_UEA1,
                .cipher_direction = dir,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = IMB_KASUMI_KEY_SIZE,
                .in_place = 1,
        };

        return kat_cipher_test_submit_flush(mb_mgr, &vec_ptr, 1, 1, &ops);
}

static int
submit_kasumi_f9_job(struct IMB_MGR *mb_mgr, kasumi_key_sched_t *key, const void *src, void *tag,
                     const uint32_t len)
{
        IMB_JOB *job;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->chain_order = IMB_ORDER_CIPHER_HASH;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->src = src;
        job->u.KASUMI_UIA1._key = key;

        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = len;
        job->hash_alg = IMB_AUTH_KASUMI_UIA1;
        job->auth_tag_output = tag;
        job->auth_tag_output_len_in_bytes = 4;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job != NULL) {
                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("%d error status:%d", __LINE__, job->status);
                        return -1;
                }
        } else {
                printf("Expected returned job, but got nothing\n");
                return -1;
        }

        return 0;
}

static int
validate_kasumi_f8_1_block(IMB_MGR *mgr)
{
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_1_BUFFER (Job API):\n");

        for (v = kasumi_f8_vectors; v->msg != NULL; v++) {
                if ((v->msgSize % CHAR_BIT) != 0)
                        continue;

                if (submit_kasumi_f8_job(mgr, v, IMB_DIR_ENCRYPT) < 0)
                        return 1;
                if (submit_kasumi_f8_job(mgr, v, IMB_DIR_DECRYPT) < 0)
                        return 1;
        }

        printf("[%s]:  PASS, for single buffers.\n", __FUNCTION__);
        return 0;
}

static int
validate_kasumi_f9(IMB_MGR *mgr)
{
        int ret = 1; /* assume error */
        uint8_t *framed = NULL;

        printf("Testing IMB_KASUMI_F9_1_BUFFER (Job API):\n");

        kasumi_key_sched_t *pKeySched = malloc(IMB_KASUMI_KEY_SCHED_SIZE(mgr));
        if (!pKeySched) {
                printf("malloc (IMB_KASUMI_KEY_SCHED_SIZE()): failed !\n");
                goto exit;
        }

        for (const struct mac_test *v = kasumi_f9_vectors; v->msg != NULL; v++) {

                /* Skip vectors whose message length is not byte-aligned */
                if ((v->msgSize % CHAR_BIT) != 0)
                        continue;

                const size_t iv_bytes = v->ivSize / CHAR_BIT;
                const size_t msg_bytes = v->msgSize / CHAR_BIT;
                const void *src = v->msg;
                uint32_t total_bytes = (uint32_t) msg_bytes;

                IMB_ASSERT(v->keySize == (IMB_KASUMI_KEY_SIZE * CHAR_BIT));

                if (IMB_KASUMI_INIT_F9_KEY_SCHED(mgr, v->key, pKeySched)) {
                        printf("IMB_KASUMI_INIT_F9_KEY_SCHED()error\n");
                        goto exit;
                }

                /*
                 * If the vector supplies a separate IV, the test vector uses one
                 * of two formats and the full f9 input frame is assembled here:
                 *
                 * ivSize == 72 (9 bytes):
                 *   iv[0]    = DIRECTION byte (ls bit = DIR bit)
                 *   iv[1..8] = COUNT (4 bytes) || FRESH (4 bytes)
                 *   msg      = raw user message (DIR and pad bits cleared)
                 *   frame = COUNT||FRESH||msg||DIR||pad assembled below
                 *
                 * ivSize == 64 (8 bytes):
                 *   iv[0..3] = COUNT (4 bytes)
                 *   iv[4..7] = BEARER(5b)||DIRECTION(1b)||0^26
                 *   msg      = the complete pre-assembled f9 input frame
                 *   pass msg directly, no framing needed
                 *
                 * ivSize == 0:
                 *   msg is already the complete f9 input frame (COUNT||FRESH||
                 *   user-data||DIR||pad), ready to pass directly to the library.
                 */
                if (iv_bytes == (72 / CHAR_BIT)) {
                        /* 72-bit IV: iv[0]=direction byte, iv[1..8]=COUNT+FRESH */
                        const size_t count_fresh_bytes = iv_bytes - 1;
                        const uint8_t dir = *((const uint8_t *) v->iv) & 1;

                        /*
                         * Total frame size rounded up to a multiple of 64 bits:
                         *   64 (COUNT+FRESH) + msgSize + 1 (DIR) + 1 (pad '1')
                         * The +63 ensures we round up.
                         */
                        const size_t frame_bits =
                                (count_fresh_bytes * CHAR_BIT + (size_t) v->msgSize + 2 + 63) &
                                ~(size_t) 63;
                        total_bytes = (uint32_t) (frame_bits / CHAR_BIT);

                        framed = calloc(total_bytes, 1);
                        if (!framed) {
                                printf("F9 calloc(framed, %u bytes) tcId:%zu: failed!\n",
                                       total_bytes, v->tcId);
                                goto exit;
                        }
                        memcpy(framed, (const uint8_t *) v->iv + 1, count_fresh_bytes);
                        memcpy(framed + count_fresh_bytes, v->msg, msg_bytes);

                        /*
                         * Set DIR bit at position msgSize (0-indexed within msg)
                         * and the mandatory '1' padding start bit at msgSize+1.
                         * The offset into framed[] accounts for COUNT+FRESH.
                         */
                        const size_t dir_bit = v->msgSize;
                        const size_t dir_byte = count_fresh_bytes + dir_bit / CHAR_BIT;
                        const unsigned int dir_shift =
                                (unsigned int) (CHAR_BIT - 1 - (dir_bit % CHAR_BIT));
                        const size_t pad_bit = dir_bit + 1;
                        const size_t pad_byte = count_fresh_bytes + pad_bit / CHAR_BIT;
                        const unsigned int pad_shift =
                                (unsigned int) (CHAR_BIT - 1 - (pad_bit % CHAR_BIT));

                        framed[dir_byte] |= (uint8_t) (dir << dir_shift);
                        framed[pad_byte] |= (uint8_t) (1u << pad_shift);

                        src = framed;
                }

                uint8_t digest[IMB_KASUMI_DIGEST_SIZE] = { 0 };

                /* Test F9 integrity */
                submit_kasumi_f9_job(mgr, pKeySched, src, digest, total_bytes);

                /* Compare the digest with the expected in the vectors */
                IMB_ASSERT(v->tagSize == (IMB_KASUMI_DIGEST_SIZE * CHAR_BIT));
                if (memcmp(digest, v->tag, IMB_KASUMI_DIGEST_SIZE) != 0) {
                        hexdump(stdout, "Actual", digest, IMB_KASUMI_DIGEST_SIZE);
                        hexdump(stdout, "Expected", v->tag, v->tagSize / CHAR_BIT);
                        printf("F9 integrity tcId:%zu Failed\n", v->tcId);
                        goto exit;
                }

                free(framed);
                framed = NULL;
        }

        ret = 0;
        printf("[%s]: PASS, for single buffers.\n", __FUNCTION__);
exit:
        free(framed);
        free(pKeySched);
        return ret;
}

int
kasumi_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        struct test_json_alloc_ctx *f9_jctx = NULL;
        struct test_json_alloc_ctx *f8_jctx = NULL;
        int errors = 0;

        if (load_mac_vectors(kat_vector_dir, "kasumi_f9_test.json", &kasumi_f9_vectors, &f9_jctx) <
            0)
                return 1;
        if (load_cipher_vectors(kat_vector_dir, "kasumi_f8_test.json", &kasumi_f8_vectors,
                                &f8_jctx) < 0) {
                free_kasumi_f9_vectors(f9_jctx);
                return 1;
        }

        test_suite_start(&ts, "KASUMI-F8");
        if (validate_kasumi_f8_1_block(mb_mgr)) {
                printf("validate_kasumi_f8_1_block: FAIL\n");
                test_suite_update(&ts, 0, 1);
        } else {
                test_suite_update(&ts, 1, 0);
        }
        errors += test_suite_end(&ts);

        test_suite_start(&ts, "KASUMI-F9");
        if (validate_kasumi_f9(mb_mgr)) {
                printf("validate_kasumi_f9: FAIL\n");
                test_suite_update(&ts, 0, 1);
        } else {
                test_suite_update(&ts, 1, 0);
        }
        errors += test_suite_end(&ts);

        free_kasumi_f9_vectors(f9_jctx);
        free_kasumi_f8_vectors(f8_jctx);
        return errors;
}
