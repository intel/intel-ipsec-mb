/*****************************************************************************
 Copyright (c) 2009-2024, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

extern const struct mac_test kasumi_f9_json[];
extern const struct cipher_test kasumi_f8_json[];

int
kasumi_test(struct IMB_MGR *mb_mgr);
static int
validate_kasumi_f8_1_block(struct IMB_MGR *mb_mgr, const unsigned job_api);
static int
validate_kasumi_f8_1_bitblock(struct IMB_MGR *mb_mgr, const unsigned job_api);
static int
validate_kasumi_f8_1_bitblock_offset(struct IMB_MGR *mb_mgr, const unsigned job_api);
static int
validate_kasumi_f8_2_blocks(struct IMB_MGR *mb_mgr, const unsigned job_api);
static int
validate_kasumi_f8_3_blocks(struct IMB_MGR *mb_mgr, const unsigned job_api);
static int
validate_kasumi_f8_4_blocks(struct IMB_MGR *mb_mgr, const unsigned job_api);
static int
validate_kasumi_f8_n_blocks(struct IMB_MGR *mb_mgr, const unsigned job_api);
static int
validate_kasumi_f9(IMB_MGR *mgr, const unsigned job_api);
static int
validate_kasumi_f9_user(IMB_MGR *mgr, const unsigned job_api);

struct kasumi_test_case {
        int (*func)(struct IMB_MGR *, const unsigned job_api);
        const char *func_name;
};

/* kasumi f8 validation function pointer table */
static const struct kasumi_test_case kasumi_f8_func_tab[] = {
        { validate_kasumi_f8_1_block, "validate_kasumi_f8_1_block" },
        { validate_kasumi_f8_1_bitblock, "validate_kasumi_f8_1_bitblock" },
        { validate_kasumi_f8_1_bitblock_offset, "validate_kasumi_f8_1_bitblock_offset" },
        { validate_kasumi_f8_2_blocks, "validate_kasumi_f8_2_blocks" },
        { validate_kasumi_f8_3_blocks, "validate_kasumi_f8_3_blocks" },
        { validate_kasumi_f8_4_blocks, "validate_kasumi_f8_4_blocks" },
        { validate_kasumi_f8_n_blocks, "validate_kasumi_f8_n_blocks" }
};

/* kasumi f9 validation function pointer table */
static const struct kasumi_test_case kasumi_f9_func_tab[] = {
        { validate_kasumi_f9, "validate_kasumi_f9" },
        { validate_kasumi_f9_user, "validate_kasumi_f9_user" }
};

static int
submit_kasumi_f8_jobs(struct IMB_MGR *mb_mgr, kasumi_key_sched_t **keys, uint64_t **ivs,
                      uint8_t **const src, uint8_t **const dst, const uint32_t *bitlens,
                      const uint32_t *bit_offsets, const int dir, const unsigned int num_jobs)
{
        unsigned int i;
        unsigned int jobs_rx = 0;

        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = IMB_GET_NEXT_JOB(mb_mgr);

                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_KASUMI_UEA1_BITLEN;
                job->src = src[i];
                job->dst = dst[i];
                job->iv = (void *) ivs[i];
                job->iv_len_in_bytes = 8;
                job->enc_keys = (uint8_t *) keys[i];
                job->key_len_in_bytes = 16;

                job->cipher_start_src_offset_in_bits = bit_offsets[i];
                job->msg_len_to_cipher_in_bits = bitlens[i];
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

/* Shift right a buffer by "offset" bits, "offset" < 8 */
static void
buffer_shift_right(uint8_t *buffer, uint32_t length, uint8_t offset)
{
        uint8_t prev_byte;
        const uint32_t length_in_bytes = (length + offset + 7) / CHAR_BIT;
        const uint8_t lower_byte_mask = (1 << offset) - 1;
        uint32_t i;

        /* Padding */
        prev_byte = 0xff;

        for (i = 0; i < length_in_bytes; i++) {
                const uint8_t curr_byte = buffer[i];

                buffer[i] = ((prev_byte & lower_byte_mask) << (8 - offset)) | (curr_byte >> offset);
                prev_byte = curr_byte;
        }
}

struct kasumi_f8_x_blocks {
        size_t n;
        void **key;
        kasumi_key_sched_t **keySched;
        uint64_t **pIV;
        uint64_t *IV; /* for n buffer direct API */
        uint32_t *packetLen;
        uint32_t *bitLens;
        uint32_t *bitOffsets;
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
        if (s->bitLens)
                free(s->bitLens);
        if (s->bitOffsets)
                free(s->bitOffsets);
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

        s->bitLens = malloc(n * sizeof(s->bitLens[0]));
        if (s->bitLens)
                memset(s->bitLens, 0, n * sizeof(s->bitLens[0]));

        s->bitOffsets = malloc(n * sizeof(s->bitOffsets[0]));
        if (s->bitOffsets)
                memset(s->bitOffsets, 0, n * sizeof(s->bitOffsets[0]));

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
            s->packetLen == NULL || s->bitLens == NULL || s->bitOffsets == NULL || s->IV == NULL) {
                kasumi_f8_x_block_free(s);
                return 0;
        }

        for (size_t i = 0; i < n; i++) {
                s->pIV[i] = malloc(IMB_KASUMI_IV_SIZE);
                s->key[i] = malloc(IMB_KASUMI_KEY_SIZE);
                s->keySched[i] = malloc(IMB_KASUMI_KEY_SCHED_SIZE(mgr));
                s->bitOffsets[i] = 0;
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
                          const struct cipher_test *vstart, const unsigned job_api,
                          const int same_size, const uint32_t bit_offset)
{
        /* set up vt[] */
        s->vt[0] = v;

        for (size_t i = 1; i < s->n; i++) {
                const struct cipher_test *vc = s->vt[i - 1];

                vc++;
                if (vc->msg == NULL)
                        vc = vstart;

                if (!job_api) {
                        /* find same key match for direct API and byte length */
                        while ((vc->msgSize % CHAR_BIT) != 0 ||
                               memcmp(vc->key, v->key, v->keySize / CHAR_BIT) != 0) {
                                vc++;
                                if (vc->msg == NULL)
                                        vc = vstart;
                        }
                } else {
                        /* find byte aligned length vector */
                        while ((vc->msgSize % CHAR_BIT) != 0) {
                                vc++;
                                if (vc->msg == NULL)
                                        vc = vstart;
                        }
                }

                s->vt[i] = vc;
        }

        /*
         * - copy key
         * - alloc src/dst buffers
         * - copy src/dst buffers
         * - copy IV
         */

        uint32_t min_size_bits = UINT32_MAX;

        for (size_t i = 0; i < s->n; i++)
                if (s->vt[i]->msgSize < min_size_bits)
                        min_size_bits = (uint32_t) s->vt[i]->msgSize;

        const uint32_t min_size = (min_size_bits + 7) / CHAR_BIT;

        for (size_t i = 0; i < s->n; i++) {
                const size_t msg_len_vec =
                        ((!job_api) && same_size) ? min_size : (s->vt[i]->msgSize + 7) / CHAR_BIT;
                const size_t msg_len = (bit_offset != 0) ? (msg_len_vec + 1) : msg_len_vec;
                const size_t msg_len_bits =
                        ((!job_api) && same_size) ? min_size_bits : s->vt[i]->msgSize;

                memcpy(s->key[i], s->vt[i]->key, s->vt[i]->keySize / CHAR_BIT);

                s->packetLen[i] = (uint32_t) msg_len;
                s->bitLens[i] = (uint32_t) msg_len_bits;
                s->bitOffsets[i] = bit_offset;

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

                if (bit_offset != 0) {
                        buffer_shift_right(s->encBuff[i], s->packetLen[i], s->bitOffsets[i]);
                        buffer_shift_right(s->decBuff[i], s->packetLen[i], s->bitOffsets[i]);
                }

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
kasumi_f8_x_block_check_op(struct kasumi_f8_x_blocks *s, const char *name, const int bit_length)
{
        if (!bit_length) {
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
        } else {
                /* Compare the cipher-text with the encrypted plain-text */
                for (size_t i = 0; i < s->n; i++) {
                        uint8_t *cp = malloc(s->packetLen[i] + 1);

                        if (cp == NULL)
                                return 0;

                        memset(cp, 0, s->packetLen[i] + 1);
                        memcpy(cp, s->vt[i]->ct, s->packetLen[i]);
                        buffer_shift_right(cp, s->packetLen[i], s->bitOffsets[i]);

                        if (membitcmp(s->encBuff[i], cp, s->bitLens[i], s->bitOffsets[i]) != 0) {
                                printf("%s(Enc) bit_offset:%u tcId:%zu\n", name, s->bitOffsets[i],
                                       s->vt[i]->tcId);
                                hexdump(stdout, "Actual:", s->encBuff[i], s->packetLen[i]);
                                hexdump(stdout, "Expected:", s->vt[i]->ct, s->packetLen[i]);
                                free(cp);
                                return 0;
                        }

                        free(cp);
                }

                for (size_t i = 0; i < s->n; i++) {
                        uint8_t *cp = malloc(s->packetLen[i] + 1);

                        if (cp == NULL)
                                return 0;

                        memset(cp, 0, s->packetLen[i] + 1);
                        memcpy(cp, s->vt[i]->msg, s->packetLen[i]);
                        buffer_shift_right(cp, s->packetLen[i], s->bitOffsets[i]);

                        if (membitcmp(s->decBuff[i], cp, s->bitLens[i], s->bitOffsets[i]) != 0) {
                                printf("%s(Dec) bit_offset:%u tcId:%zu\n", name, s->bitOffsets[i],
                                       s->vt[i]->tcId);
                                hexdump(stdout, "Actual:", s->decBuff[i], s->packetLen[i]);
                                hexdump(stdout, "Expected:", s->vt[i]->msg, s->packetLen[i]);
                                free(cp);
                                return 0;
                        }

                        free(cp);
                }
        }
        return 1;
}

static int
validate_kasumi_f8_1_bitblock(IMB_MGR *mgr, const unsigned job_api)
{
        const uint32_t n = 1;
        struct kasumi_f8_x_blocks s;
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_1_BUFFER_BIT (%s):\n", job_api ? "Job API" : "Direct API");

        if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                printf("F8 alloc failed !\n");
                return 1;
        }

        for (v = kasumi_f8_json; v->msg != NULL; v++) {

                if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 0, 0)) {
                        kasumi_f8_x_block_free(&s);
                        printf("F8 prep failed !\n");
                        return 1;
                }

                /* Validate Encrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                else
                        IMB_KASUMI_F8_1_BUFFER_BIT(mgr, s.keySched[0], *s.pIV[0], s.encBuff[0],
                                                   s.encBuff[0], s.bitLens[0], s.bitOffsets[0]);

                /* Validate Decrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                else
                        IMB_KASUMI_F8_1_BUFFER_BIT(mgr, s.keySched[0], *s.pIV[0], s.decBuff[0],
                                                   s.decBuff[0], s.bitLens[0], s.bitOffsets[0]);

                if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 1)) {
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
validate_kasumi_f8_1_bitblock_offset(IMB_MGR *mgr, const unsigned job_api)
{
        const uint32_t n = 1;
        struct kasumi_f8_x_blocks s;
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_1_BUFFER_BIT (offset) (%s):\n",
               job_api ? "Job API" : "Direct API");

        if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                printf("F8 alloc failed !\n");
                return 1;
        }

        for (v = kasumi_f8_json; v->msg != NULL; v++) {

                for (uint32_t bitoff = 0; bitoff < 8; bitoff++) {
                        if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 0,
                                                       bitoff)) {
                                kasumi_f8_x_block_free(&s);
                                printf("F8 prep failed !\n");
                                return 1;
                        }

                        /* Validate Encrypt */
                        if (job_api)
                                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                                      s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                        else
                                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, s.keySched[0], *s.pIV[0],
                                                           s.encBuff[0], s.encBuff[0], s.bitLens[0],
                                                           s.bitOffsets[0]);

                        /* Validate Decrypt */
                        if (job_api)
                                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                                      s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                        else
                                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, s.keySched[0], *s.pIV[0],
                                                           s.decBuff[0], s.decBuff[0], s.bitLens[0],
                                                           s.bitOffsets[0]);

                        if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 1)) {
                                kasumi_f8_x_block_free(&s);
                                return 1;
                        }

                        kasumi_f8_x_block_clean_op(&s);
                }
        }

        printf("[%s]:  PASS, for single buffers.\n", __FUNCTION__);
        kasumi_f8_x_block_free(&s);

        return 0;
}
static int
validate_kasumi_f8_1_block(IMB_MGR *mgr, const unsigned job_api)
{
        const uint32_t n = 1;
        struct kasumi_f8_x_blocks s;
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_1_BUFFER (%s):\n", job_api ? "Job API" : "Direct API");

        if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                printf("F8 alloc failed !\n");
                return 1;
        }

        for (v = kasumi_f8_json; v->msg != NULL; v++) {

                if ((v->msgSize % CHAR_BIT) != 0)
                        continue;

                if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 0, 0)) {
                        kasumi_f8_x_block_free(&s);
                        printf("F8 prep failed !\n");
                        return 1;
                }

                /* Validate Encrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                else
                        IMB_KASUMI_F8_1_BUFFER(mgr, s.keySched[0], *s.pIV[0], s.encBuff[0],
                                               s.encBuff[0], s.packetLen[0]);

                /*Validate Decrypt*/
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                else
                        IMB_KASUMI_F8_1_BUFFER(mgr, s.keySched[0], *s.pIV[0], s.decBuff[0],
                                               s.decBuff[0], s.packetLen[0]);

                if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 0)) {
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
validate_kasumi_f8_2_blocks(IMB_MGR *mgr, const unsigned job_api)
{
        const uint32_t n = 2;
        struct kasumi_f8_x_blocks s;
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_2_BUFFER (%s):\n", job_api ? "Job API" : "Direct API");

        if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                printf("F8 alloc failed !\n");
                return 1;
        }

        for (v = kasumi_f8_json; v->msg != NULL; v++) {

                if ((v->msgSize % CHAR_BIT) != 0)
                        continue;

                if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 0, 0)) {
                        kasumi_f8_x_block_free(&s);
                        printf("F8 prep failed !\n");
                        return 1;
                }

                /* Test the encrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                else
                        IMB_KASUMI_F8_2_BUFFER(mgr, s.keySched[0], *s.pIV[0], *s.pIV[1],
                                               s.encBuff[0], s.encBuff[0], s.packetLen[0],
                                               s.encBuff[1], s.encBuff[1], s.packetLen[1]);

                /* Test the decrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                else
                        IMB_KASUMI_F8_2_BUFFER(mgr, s.keySched[0], *s.pIV[0], *s.pIV[1],
                                               s.decBuff[0], s.decBuff[0], s.packetLen[0],
                                               s.decBuff[1], s.decBuff[1], s.packetLen[1]);

                if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 0)) {
                        kasumi_f8_x_block_free(&s);
                        return 1;
                }

                kasumi_f8_x_block_clean_op(&s);
        }

        printf("[%s]: PASS.\n", __FUNCTION__);

        kasumi_f8_x_block_free(&s);
        return 0;
}

static int
validate_kasumi_f8_3_blocks(IMB_MGR *mgr, const unsigned job_api)
{
        const uint32_t n = 3;
        struct kasumi_f8_x_blocks s;
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_3_BUFFER (%s):\n", job_api ? "Job API" : "Direct API");

        if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                printf("F8 alloc failed !\n");
                return 1;
        }

        for (v = kasumi_f8_json; v->msg != NULL; v++) {

                if ((v->msgSize % CHAR_BIT) != 0)
                        continue;

                if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 1, 0)) {
                        kasumi_f8_x_block_free(&s);
                        printf("F8 prep failed !\n");
                        return 1;
                }

                /* Test the encrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                else
                        IMB_KASUMI_F8_3_BUFFER(mgr, s.keySched[0], *s.pIV[0], *s.pIV[1], *s.pIV[2],
                                               s.encBuff[0], s.encBuff[0], s.encBuff[1],
                                               s.encBuff[1], s.encBuff[2], s.encBuff[2],
                                               s.packetLen[0]);

                /* Test the decrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                else
                        IMB_KASUMI_F8_3_BUFFER(mgr, s.keySched[0], *s.pIV[0], *s.pIV[1], *s.pIV[2],
                                               s.decBuff[0], s.decBuff[0], s.decBuff[1],
                                               s.decBuff[1], s.decBuff[2], s.decBuff[2],
                                               s.packetLen[0]);

                if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 0)) {
                        kasumi_f8_x_block_free(&s);
                        return 1;
                }

                kasumi_f8_x_block_clean_op(&s);
        }

        printf("[%s]: PASS.\n", __FUNCTION__);
        kasumi_f8_x_block_free(&s);
        return 0;
}

static int
validate_kasumi_f8_4_blocks(IMB_MGR *mgr, const unsigned job_api)
{
        const uint32_t n = 4;
        struct kasumi_f8_x_blocks s;
        const struct cipher_test *v;

        printf("Testing IMB_KASUMI_F8_4_BUFFER (%s):\n", job_api ? "Job API" : "Direct API");

        if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                printf("F8 alloc failed !\n");
                return 1;
        }

        for (v = kasumi_f8_json; v->msg != NULL; v++) {

                if ((v->msgSize % CHAR_BIT) != 0)
                        continue;

                if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 1, 0)) {
                        kasumi_f8_x_block_free(&s);
                        printf("F8 prep failed !\n");
                        return 1;
                }

                /* Test the encrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                else
                        IMB_KASUMI_F8_4_BUFFER(mgr, s.keySched[0], *s.pIV[0], *s.pIV[1], *s.pIV[2],
                                               *s.pIV[3], s.encBuff[0], s.encBuff[0], s.encBuff[1],
                                               s.encBuff[1], s.encBuff[2], s.encBuff[2],
                                               s.encBuff[3], s.encBuff[3], s.packetLen[0]);

                /* Test the decrypt */
                if (job_api)
                        submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                              s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                else
                        IMB_KASUMI_F8_4_BUFFER(mgr, s.keySched[0], *s.pIV[0], *s.pIV[1], *s.pIV[2],
                                               *s.pIV[3], s.decBuff[0], s.decBuff[0], s.decBuff[1],
                                               s.decBuff[1], s.decBuff[2], s.decBuff[2],
                                               s.decBuff[3], s.decBuff[3], s.packetLen[0]);

                if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 0)) {
                        kasumi_f8_x_block_free(&s);
                        return 1;
                }

                kasumi_f8_x_block_clean_op(&s);
        }

        printf("[%s]: PASS.\n", __FUNCTION__);
        kasumi_f8_x_block_free(&s);
        return 0;
}

static int
validate_kasumi_f8_n_blocks(IMB_MGR *mgr, const unsigned job_api)
{
        const size_t max_n = 16;

        printf("Testing IMB_KASUMI_F8_N_BUFFER (%s):\n", job_api ? "Job API" : "Direct API");

        for (uint32_t n = 1; n <= max_n; n++) {
                struct kasumi_f8_x_blocks s;

                if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                        printf("F8 alloc failed !\n");
                        return 1;
                }

                for (const struct cipher_test *v = kasumi_f8_json; v->msg != NULL; v++) {

                        if ((v->msgSize % CHAR_BIT) != 0)
                                continue;

                        /* same size */
                        if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 1, 0)) {
                                kasumi_f8_x_block_free(&s);
                                printf("F8 prep failed !\n");
                                return 1;
                        }

                        /* Test the encrypt */
                        if (job_api)
                                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                                      s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                        else
                                /* All buffers share the same key */
                                IMB_KASUMI_F8_N_BUFFER(mgr, s.keySched[0], s.IV,
                                                       (const void *const *) s.encBuff,
                                                       (void **) s.encBuff, s.packetLen, n);

                        /* Test the decrypt */
                        if (job_api)
                                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                                      s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                        else
                                /* All buffers share the same key */
                                IMB_KASUMI_F8_N_BUFFER(mgr, s.keySched[0], s.IV,
                                                       (const void *const *) s.decBuff,
                                                       (void **) s.decBuff, s.packetLen, n);

                        if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 0)) {
                                kasumi_f8_x_block_free(&s);
                                return 1;
                        }

                        kasumi_f8_x_block_clean_op(&s);
                } /* json vectors */

                kasumi_f8_x_block_free(&s);
        }

        printf("[%s]: PASS, 1 to %zu buffers equal sizes.\n", __FUNCTION__, max_n);

        for (uint32_t n = 1; n <= max_n; n++) {
                struct kasumi_f8_x_blocks s;

                if (!kasumi_f8_x_block_alloc(mgr, &s, n)) {
                        printf("F8 alloc failed !\n");
                        return 1;
                }

                for (const struct cipher_test *v = kasumi_f8_json; v->msg != NULL; v++) {

                        if ((v->msgSize % CHAR_BIT) != 0)
                                continue;

                        /* different sizes */
                        if (!kasumi_f8_x_block_prep_op(mgr, &s, v, kasumi_f8_json, job_api, 0, 0)) {
                                kasumi_f8_x_block_free(&s);
                                printf("F8 prep failed !\n");
                                return 1;
                        }

                        /* Test the encrypt */
                        if (job_api)
                                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.encBuff, s.encBuff,
                                                      s.bitLens, s.bitOffsets, IMB_DIR_ENCRYPT, n);
                        else
                                /* All buffers share the same key */
                                IMB_KASUMI_F8_N_BUFFER(mgr, s.keySched[0], s.IV,
                                                       (const void *const *) s.encBuff,
                                                       (void **) s.encBuff, s.packetLen, n);

                        /* Test the decrypt */
                        if (job_api)
                                submit_kasumi_f8_jobs(mgr, s.keySched, s.pIV, s.decBuff, s.decBuff,
                                                      s.bitLens, s.bitOffsets, IMB_DIR_DECRYPT, n);
                        else
                                /* All buffers share the same key */
                                IMB_KASUMI_F8_N_BUFFER(mgr, s.keySched[0], s.IV,
                                                       (const void *const *) s.decBuff,
                                                       (void **) s.decBuff, s.packetLen, n);

                        if (!kasumi_f8_x_block_check_op(&s, __FUNCTION__, 0)) {
                                kasumi_f8_x_block_free(&s);
                                return 1;
                        }

                        kasumi_f8_x_block_clean_op(&s);
                } /* json vectors */

                kasumi_f8_x_block_free(&s);
        }

        printf("[%s]: PASS, 1 to %zu buffers.\n", __FUNCTION__, max_n);

        return 0;
}

static int
validate_kasumi_f9(IMB_MGR *mgr, const unsigned job_api)
{
        int ret = 1; /* assume error */

        printf("Testing IMB_KASUMI_F9_1_BUFFER (%s):\n", job_api ? "Job API" : "Direct API");

        kasumi_key_sched_t *pKeySched = malloc(IMB_KASUMI_KEY_SCHED_SIZE(mgr));
        if (!pKeySched) {
                printf("malloc (IMB_KASUMI_KEY_SCHED_SIZE()): failed !\n");
                goto exit;
        }

        for (const struct mac_test *v = kasumi_f9_json; v->msg != NULL; v++) {

                /* in this test skip vectors with non-empty IV */
                if (v->ivSize != 0)
                        continue;

                const uint32_t byteLen = (uint32_t) ((v->msgSize + 7) / CHAR_BIT);

                IMB_ASSERT(v->keySize == (IMB_KASUMI_KEY_SIZE * CHAR_BIT));

                if (IMB_KASUMI_INIT_F9_KEY_SCHED(mgr, v->key, pKeySched)) {
                        printf("IMB_KASUMI_INIT_F9_KEY_SCHED()error\n");
                        goto exit;
                }

                uint8_t digest[IMB_KASUMI_DIGEST_SIZE] = { 0 };

                /* Test F9 integrity */
                if (job_api)
                        submit_kasumi_f9_job(mgr, pKeySched, v->msg, digest, byteLen);
                else
                        IMB_KASUMI_F9_1_BUFFER(mgr, pKeySched, v->msg, byteLen, digest);

                /* Compare the digest with the expected in the vectors */
                IMB_ASSERT(v->tagSize == (IMB_KASUMI_DIGEST_SIZE * CHAR_BIT));
                if (memcmp(digest, v->tag, IMB_KASUMI_DIGEST_SIZE) != 0) {
                        hexdump(stdout, "Actual", digest, IMB_KASUMI_DIGEST_SIZE);
                        hexdump(stdout, "Expected", v->tag, v->tagSize / CHAR_BIT);
                        printf("F9 integrity tcId:%zu Failed\n", v->tcId);
                        goto exit;
                }
        }

        ret = 0;
        printf("[%s]: PASS, for single buffers.\n", __FUNCTION__);
exit:
        free(pKeySched);
        return ret;
}

static int
validate_kasumi_f9_user(IMB_MGR *mgr, const unsigned job_api)
{
        /* only direct API available here */
        if (job_api)
                return 0;

        int ret = 1; /* assume error */

        printf("Testing IMB_KASUMI_F9_1_BUFFER_USER (Direct API):\n");

        kasumi_key_sched_t *pKeySched = malloc(IMB_KASUMI_KEY_SCHED_SIZE(mgr));
        if (!pKeySched) {
                printf("malloc (IMB_KASUMI_KEY_SCHED_SIZE()): failed !\n");
                goto exit;
        }

        for (const struct mac_test *v = kasumi_f9_json; v->msg != NULL; v++) {

                /* in this test skip vectors with empty IV */
                if (v->ivSize != ((IMB_KASUMI_IV_SIZE + 1) * CHAR_BIT))
                        continue;

                uint64_t iv = 0;

                IMB_ASSERT(sizeof(iv) == IMB_KASUMI_IV_SIZE);
                memcpy(&iv, &v->iv[1], IMB_KASUMI_IV_SIZE);

                const uint32_t direction = (uint32_t) v->iv[0];

                IMB_ASSERT(v->keySize == (IMB_KASUMI_KEY_SIZE * CHAR_BIT));

                if (IMB_KASUMI_INIT_F9_KEY_SCHED(mgr, v->key, pKeySched)) {
                        printf("IMB_KASUMI_INIT_F9_KEY_SCHED() error\n");
                        goto exit;
                }

                uint8_t digest[IMB_KASUMI_DIGEST_SIZE] = { 0 };

                /* Test the integrity for f9_user with IV */
                IMB_ASSERT(v->msgSize < UINT32_MAX);
                IMB_KASUMI_F9_1_BUFFER_USER(mgr, pKeySched, iv, v->msg, (uint32_t) v->msgSize,
                                            digest, direction);

                /* Compare the digest with the expected in the vectors */
                IMB_ASSERT(v->tagSize == (IMB_KASUMI_DIGEST_SIZE * CHAR_BIT));
                if (memcmp(digest, v->tag, IMB_KASUMI_DIGEST_SIZE) != 0) {
                        hexdump(stdout, "digest", digest, IMB_KASUMI_DIGEST_SIZE);
                        hexdump(stdout, "expected", v->tag, v->tagSize / CHAR_BIT);
                        printf("direction %u\n", direction);
                        printf("F9 integrity tcId:%zu Failed\n", v->tcId);
                        goto exit;
                }
        }

        printf("[%s]:     PASS, for single buffers.\n", __FUNCTION__);
        ret = 0;

exit:
        free(pKeySched);
        return ret;
}

int
kasumi_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        int errors = 0;
        unsigned i;

        test_suite_start(&ts, "KASUMI-F8");
        for (i = 0; i < DIM(kasumi_f8_func_tab); i++) {
                /* validate direct API */
                if (kasumi_f8_func_tab[i].func(mb_mgr, 0)) {
                        printf("%s: FAIL\n", kasumi_f8_func_tab[i].func_name);
                        test_suite_update(&ts, 0, 1);
                } else {
                        test_suite_update(&ts, 1, 0);
                }

                /* validate job API */
                if (kasumi_f8_func_tab[i].func(mb_mgr, 1)) {
                        printf("%s: FAIL\n", kasumi_f8_func_tab[i].func_name);
                        test_suite_update(&ts, 0, 1);
                } else {
                        test_suite_update(&ts, 1, 0);
                }
        }
        errors += test_suite_end(&ts);

        test_suite_start(&ts, "KASUMI-F9");
        for (i = 0; i < DIM(kasumi_f9_func_tab); i++) {
                /* validate direct API */
                if (kasumi_f9_func_tab[i].func(mb_mgr, 0)) {
                        printf("%s: FAIL\n", kasumi_f9_func_tab[i].func_name);
                        test_suite_update(&ts, 0, 1);
                } else {
                        test_suite_update(&ts, 1, 0);
                }

                /* validate job API */
                if (kasumi_f9_func_tab[i].func(mb_mgr, 1)) {
                        printf("%s: FAIL\n", kasumi_f9_func_tab[i].func_name);
                        test_suite_update(&ts, 0, 1);
                } else {
                        test_suite_update(&ts, 1, 0);
                }
        }
        errors += test_suite_end(&ts);

        return errors;
}
