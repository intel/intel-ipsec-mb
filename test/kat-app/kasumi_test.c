/*****************************************************************************
 Copyright (c) 2009-2024, Intel Corporation

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
submit_kasumi_f8_jobs(struct IMB_MGR *mb_mgr, kasumi_key_sched_t **keys, uint64_t **ivs,
                      uint8_t **const src, uint8_t **const dst, const uint32_t *bytelens,
                      const uint32_t *byte_offsets, const int dir, const unsigned int num_jobs)
{
        unsigned int i;
        unsigned int jobs_rx = 0;

        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = IMB_GET_NEXT_JOB(mb_mgr);

                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_KASUMI_UEA1;
                job->src = src[i];
                job->dst = dst[i];
                job->iv = (void *) ivs[i];
                job->iv_len_in_bytes = 8;
                job->enc_keys = (uint8_t *) keys[i];
                job->key_len_in_bytes = 16;

                job->cipher_start_src_offset_in_bytes = byte_offsets[i];
                job->msg_len_to_cipher_in_bytes = bytelens[i];
                job->hash_alg = IMB_AUTH_NULL;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED) {
                                printf("%d error status:%d, job %u", __LINE__, job->status, i);
                                return -1;
                        }
                } else {
                        printf("Expected returned job, but got nothing\n");
                        return -1;
                }
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                return -1;
        }

        return 0;
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

struct kasumi_f8_x_blocks {
        size_t n;
        void **key;
        kasumi_key_sched_t **keySched;
        uint64_t **pIV;
        uint64_t *IV; /* for n buffer direct API */
        uint32_t *packetLen;
        uint32_t *byteOffsets;
        const struct cipher_test **vt;

        uint8_t **encBuff;
        uint8_t **decBuff;
};

static void
kasumi_f8_x_block_free(struct kasumi_f8_x_blocks *s)
{
        for (size_t i = 0; i < s->n; i++) {
                if (s->pIV)
                        if (s->pIV[i])
                                free(s->pIV[i]);
                if (s->key)
                        if (s->key[i])
                                free(s->key[i]);
                if (s->keySched)
                        if (s->keySched[i])
                                free(s->keySched[i]);
                if (s->encBuff)
                        if (s->encBuff[i])
                                free(s->encBuff[i]);
                if (s->decBuff)
                        if (s->decBuff[i])
                                free(s->decBuff[i]);
        }

        if (s->key)
                free(s->key);
        if (s->keySched)
                free(s->keySched);
        if (s->pIV)
                free(s->pIV);
        if (s->IV)
                free(s->IV);
        if (s->packetLen)
                free(s->packetLen);
        if (s->byteOffsets)
                free(s->byteOffsets);
        if (s->vt)
                free((void *) s->vt);
        if (s->encBuff)
                free(s->encBuff);
        if (s->decBuff)
                free(s->decBuff);

        memset(s, 0, sizeof(*s));
}

static int
kasumi_f8_x_block_alloc(IMB_MGR *mgr, struct kasumi_f8_x_blocks *s, const size_t n)
{
        memset(s, 0, sizeof(*s));
        s->n = n;

        s->key = malloc(n * sizeof(s->key[0]));
        if (s->key)
                memset(s->key, 0, n * sizeof(s->key[0]));

        s->keySched = malloc(n * sizeof(s->keySched[0]));
        if (s->keySched)
                memset(s->keySched, 0, n * sizeof(s->keySched[0]));

        s->pIV = malloc(n * sizeof(s->pIV[0]));
        if (s->pIV)
                memset(s->pIV, 0, n * sizeof(s->pIV[0]));

        s->IV = malloc(n * sizeof(s->IV[0]));
        if (s->IV)
                memset(s->IV, 0, n * sizeof(s->IV[0]));

        s->packetLen = malloc(n * sizeof(s->packetLen[0]));
        if (s->packetLen)
                memset(s->packetLen, 0, n * sizeof(s->packetLen[0]));

        s->byteOffsets = malloc(n * sizeof(s->byteOffsets[0]));
        if (s->byteOffsets)
                memset(s->byteOffsets, 0, n * sizeof(s->byteOffsets[0]));

        s->vt = malloc(n * sizeof(s->vt[0]));
        if (s->vt) {
                for (size_t i = 0; i < n; i++)
                        s->vt[i] = NULL;
        }

        s->encBuff = malloc(n * sizeof(s->encBuff[0]));
        if (s->encBuff)
                memset(s->encBuff, 0, n * sizeof(s->encBuff[0]));

        s->decBuff = malloc(n * sizeof(s->decBuff[0]));
        if (s->decBuff)
                memset(s->decBuff, 0, n * sizeof(s->decBuff[0]));

        if (s->key == NULL || s->keySched == NULL || s->pIV == NULL || s->vt == NULL ||
            s->packetLen == NULL || s->byteOffsets == NULL || s->IV == NULL) {
                kasumi_f8_x_block_free(s);
                return 0;
        }

        for (size_t i = 0; i < n; i++) {
                s->pIV[i] = malloc(IMB_KASUMI_IV_SIZE);
                s->key[i] = malloc(IMB_KASUMI_KEY_SIZE);
                s->keySched[i] = malloc(IMB_KASUMI_KEY_SCHED_SIZE(mgr));
                s->byteOffsets[i] = 0;
                if (s->pIV[i] == NULL || s->key[i] == NULL || s->keySched[i] == NULL) {
                        kasumi_f8_x_block_free(s);
                        return 0;
                }
        }

        return 1;
}

static void
kasumi_f8_x_block_clean_op(struct kasumi_f8_x_blocks *s)
{
        for (size_t i = 0; i < s->n; i++) {
                if (s->encBuff) {
                        if (s->encBuff[i]) {
                                free(s->encBuff[i]);
                                s->encBuff[i] = NULL;
                        }
                }
                if (s->decBuff) {
                        if (s->decBuff[i]) {
                                free(s->decBuff[i]);
                                s->decBuff[i] = NULL;
                        }
                }
        }
}

static int
kasumi_f8_x_block_prep_op(IMB_MGR *mgr, struct kasumi_f8_x_blocks *s, const struct cipher_test *v,
                          const struct cipher_test *vstart)
{
        /* set up vt[] */
        s->vt[0] = v;

        for (size_t i = 1; i < s->n; i++) {
                const struct cipher_test *vc = s->vt[i - 1];

                vc++;
                if (vc->msg == NULL)
                        vc = vstart;

                /* find byte aligned length vector */
                while ((vc->msgSize % CHAR_BIT) != 0) {
                        vc++;
                        if (vc->msg == NULL)
                                vc = vstart;
                }

                s->vt[i] = vc;
        }

        /*
         * - copy key
         * - alloc src/dst buffers
         * - copy src/dst buffers
         * - copy IV
         */

        for (size_t i = 0; i < s->n; i++) {
                const size_t msg_len = s->vt[i]->msgSize / CHAR_BIT;

                memcpy(s->key[i], s->vt[i]->key, s->vt[i]->keySize / CHAR_BIT);

                s->packetLen[i] = (uint32_t) msg_len;
                s->byteOffsets[i] = 0;

                s->encBuff[i] = malloc(msg_len);
                if (!s->encBuff[i]) {
                        printf("malloc(encBuff[]):failed !\n");
                        kasumi_f8_x_block_clean_op(s);
                        return 0;
                }

                s->decBuff[i] = malloc(msg_len);
                if (!s->decBuff[i]) {
                        printf("malloc(decBuff[]): failed !\n");
                        kasumi_f8_x_block_clean_op(s);
                        return 0;
                }

                memcpy(s->encBuff[i], s->vt[i]->msg, msg_len);
                memcpy(s->decBuff[i], s->vt[i]->ct, msg_len);

                memcpy(s->pIV[i], s->vt[i]->iv, s->vt[i]->ivSize / CHAR_BIT);
                memcpy(&s->IV[i], s->vt[i]->iv, s->vt[i]->ivSize / CHAR_BIT);
        }

        /* init key schedule */
        for (size_t i = 0; i < s->n; i++) {
                if (IMB_KASUMI_INIT_F8_KEY_SCHED(mgr, s->key[i], s->keySched[i])) {
                        printf("IMB_KASUMI_INIT_F8_KEY_SCHED() error\n");
                        kasumi_f8_x_block_clean_op(s);
                        return 0;
                }
        }

        return 1;
}

static int
kasumi_f8_x_block_check_op(struct kasumi_f8_x_blocks *s, const char *name)
{
        /* Compare the cipher-text with the encrypted plain-text */
        for (size_t i = 0; i < s->n; i++) {
                if (memcmp(s->encBuff[i], s->vt[i]->ct, s->packetLen[i]) != 0) {
                        printf("%s(Enc)  tcId:%zu\n", name, s->vt[i]->tcId);
                        hexdump(stdout, "Actual:", s->encBuff[i], s->packetLen[i]);
                        hexdump(stdout, "Expected:", s->vt[i]->ct, s->packetLen[i]);
                        return 0;
                }
        }

        /* Compare the plain-text with the decrypted cipher-text */
        for (size_t i = 0; i < s->n; i++) {
                if (memcmp(s->decBuff[i], s->vt[i]->msg, s->packetLen[i]) != 0) {
                        printf("%s(Dec)  tcId:%zu\n", name, s->vt[i]->tcId);
                        hexdump(stdout, "Actual:", s->decBuff[i], s->packetLen[i]);
                        hexdump(stdout, "Expected:", s->vt[i]->msg, s->packetLen[i]);
                        return 0;
                }
        }
        return 1;
}

static int
validate_kasumi_f8_1_block(IMB_MGR *mgr)
{
        const uint32_t n = 1;
        struct kasumi_f8_x_blocks s;
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_1_BUFFER (Job API):\n");

        if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                printf("F8 alloc failed !\n");
                return 1;
        }

        for (v = kasumi_f8_vectors; v->msg != NULL; v++) {

                if ((v->msgSize % CHAR_BIT) != 0)
                        continue;

                if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_vectors)) {
                        kasumi_f8_x_block_free(&s);
                        printf("F8 prep failed !\n");
                        return 1;
                }

                /* Validate Encrypt */
                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff, s.packetLen,
                                      s.byteOffsets, IMB_DIR_ENCRYPT, n);

                /*Validate Decrypt*/
                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff, s.packetLen,
                                      s.byteOffsets, IMB_DIR_DECRYPT, n);

                if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__)) {
                        kasumi_f8_x_block_free(&s);
                        return 1;
                }

                kasumi_f8_x_block_clean_op(&s);
        }

        printf("[%s]:  PASS, for single buffers.\n", __FUNCTION__);
        kasumi_f8_x_block_free(&s);
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
