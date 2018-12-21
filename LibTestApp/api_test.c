/*****************************************************************************
 Copyright (c) 2018-2019, Intel Corporation

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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"

int api_test(const enum arch_type arch, struct MB_MGR *mb_mgr);

/*
 * @brief Performs JOB API behavior tests
 */
static int
test_job_api(struct MB_MGR *mb_mgr)
{
        struct JOB_AES_HMAC *job, *job_next;

	printf("JOB API behavior test:\n");

        /* ======== test 1 */
        job = IMB_GET_NEXT_JOB(mb_mgr);
        if (job == NULL) {
                printf("%s: test 1, unexpected job = NULL\n", __func__);
                return 1;
        }
	printf(".");

        /* ======== test 2 : invalid cipher and mac */
        memset(job, 0, sizeof(*job));
        job_next = IMB_SUBMIT_JOB(mb_mgr);
        if (job_next != NULL) {
                /* MB MGR was empty so it should return NULL */
                printf("%s: test 2, unexpected submit_job() != NULL\n",
                       __func__);
                return 1;
        }
	printf(".");

        job_next = IMB_GET_NEXT_JOB(mb_mgr);
        if (job == job_next) {
                /* get next job should point to a new job slot */
                printf("%s: test 2, unexpected job == get_next_job()\n",
                       __func__);
                return 1;
        }
	printf(".");

        if (job->status != STS_INVALID_ARGS) {
                /* job wasn't returned but its status is set at this stage */
                printf("%s: test 2, unexpected job->status != "
                       "STS_INVALID_ARGS\n", __func__);
                return 1;
        }
	printf(".");

        job_next = IMB_GET_COMPLETED_JOB(mb_mgr);
        if (job_next != job) {
                /* the completed job should be the same as the submitted one */
                printf("%s: test 2, unexpected job_ret != job\n", __func__);
                return 1;
        }
	printf(".");

        if (job_next->status != STS_INVALID_ARGS) {
                /* let's check job status again now */
                printf("%s: test 2, unexpected job_ret->status != "
                       "STS_INVALID_ARGS\n", __func__);
                return 1;
        }
	printf(".");

        /* clean up */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

	printf("\n");
        return 0;
}

/*
 * @brief Dummy function for custom hash and cipher modes
 */
static int dummy_cipher_hash_func(struct JOB_AES_HMAC *job)
{
        (void) job;
        return 0;
}

/*
 * @brief Fills in job structure with valid settings
 */
static void
fill_in_job(struct JOB_AES_HMAC *job,
            const JOB_CIPHER_MODE cipher_mode,
            const JOB_CIPHER_DIRECTION cipher_direction,
            const JOB_HASH_ALG hash_alg,
            const JOB_CHAIN_ORDER chain_order)
{
        const uint64_t tag_len_tab[] = {
                0,  /* INVALID selection */
                12, /* SHA1 */
                14, /* SHA_224 */
                16, /* SHA_256 */
                24, /* SHA_384 */
                32, /* SHA_512 */
                12, /* AES_XCBC */
                12, /* MD5 */
                0,  /* NULL_HASH */
                16, /* AES_GMAC */
                0,  /* CUSTOM HASH */
                16, /* AES_CCM */
                16, /* AES_CMAC */
                20, /* PLAIN_SHA1 */
                28, /* PLAIN_SHA_224 */
                32, /* PLAIN_SHA_256 */
                48, /* PLAIN_SHA_384 */
                64, /* PLAIN_SHA_512 */
        };
        static DECLARE_ALIGNED(uint8_t dust_bin[2048], 64);
        static void *dust_keys[3] = {dust_bin, dust_bin, dust_bin};
        const uint64_t msg_len_to_cipher = 32;
        const uint64_t msg_len_to_hash = 48;

        if (job == NULL)
                return;

        memset(job, 0, sizeof(*job));
        job->chain_order = chain_order;
        job->hash_alg = hash_alg;
        job->cipher_mode = cipher_mode;
        job->cipher_direction = cipher_direction;

        switch (job->cipher_mode) {
        case CBC:
                if (job->cipher_direction == ENCRYPT)
                        job->aes_enc_key_expanded = dust_bin;
                else
                        job->aes_dec_key_expanded = dust_bin;
                job->aes_key_len_in_bytes = UINT64_C(16);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(16);
                break;
        case CNTR:
                job->aes_enc_key_expanded = dust_bin;
                job->aes_key_len_in_bytes = UINT64_C(16);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(16);
                break;
        case NULL_CIPHER:
                break;
        case DOCSIS_SEC_BPI:
                /* it has to be set regardless of direction (AES-CFB) */
                job->aes_enc_key_expanded = dust_bin;
                if (job->cipher_direction == DECRYPT)
                        job->aes_dec_key_expanded = dust_bin;
                job->aes_key_len_in_bytes = UINT64_C(16);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(16);
                break;
        case GCM:
                if (job->cipher_direction == ENCRYPT)
                        job->aes_enc_key_expanded = dust_bin;
                else
                        job->aes_dec_key_expanded = dust_bin;
                job->aes_key_len_in_bytes = UINT64_C(16);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(12);
                break;
        case CUSTOM_CIPHER:
                job->cipher_func = dummy_cipher_hash_func;
                break;
        case DES:
                if (job->cipher_direction == ENCRYPT)
                        job->aes_enc_key_expanded = dust_bin;
                else
                        job->aes_dec_key_expanded = dust_bin;
                job->aes_key_len_in_bytes = UINT64_C(8);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(8);
                break;
        case DOCSIS_DES:
                if (job->cipher_direction == ENCRYPT)
                        job->aes_enc_key_expanded = dust_bin;
                else
                        job->aes_dec_key_expanded = dust_bin;
                job->aes_key_len_in_bytes = UINT64_C(8);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(8);
                break;
        case CCM:
                /* AES-CTR and CBC-MAC use only encryption keys */
                job->aes_enc_key_expanded = dust_bin;
                job->aes_key_len_in_bytes = UINT64_C(16);
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(13);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                break;
        case DES3:
                if (job->cipher_direction == ENCRYPT)
                        job->aes_enc_key_expanded = dust_keys;
                else
                        job->aes_dec_key_expanded = dust_keys;
                job->aes_key_len_in_bytes = UINT64_C(24);
                job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;
                job->iv = dust_bin;
                job->iv_len_in_bytes = UINT64_C(8);
                break;
        default:
                break;
        }

        switch (job->hash_alg) {
        case SHA1:
        case AES_XCBC:
        case MD5:
        case SHA_224:
        case SHA_256:
        case SHA_384:
        case SHA_512:
        case PLAIN_SHA1:
        case PLAIN_SHA_224:
        case PLAIN_SHA_256:
        case PLAIN_SHA_384:
        case PLAIN_SHA_512:
                job->msg_len_to_hash_in_bytes = msg_len_to_hash;
                job->auth_tag_output = dust_bin;
                job->auth_tag_output_len_in_bytes = tag_len_tab[job->hash_alg];
                break;
        case NULL_HASH:
                break;
        case CUSTOM_HASH:
                job->hash_func = dummy_cipher_hash_func;
                break;
        case AES_GMAC:
                job->msg_len_to_hash_in_bytes = msg_len_to_hash;
                job->auth_tag_output = dust_bin;
                job->auth_tag_output_len_in_bytes = tag_len_tab[job->hash_alg];
                job->u.GCM.aad = dust_bin;
                job->u.GCM.aad_len_in_bytes = 16;
                break;
        case AES_CCM:
                job->u.CCM.aad = dust_bin;
                job->u.CCM.aad_len_in_bytes = 16;
                job->msg_len_to_hash_in_bytes = job->msg_len_to_cipher_in_bytes;
                job->hash_start_src_offset_in_bytes =
                        job->cipher_start_src_offset_in_bytes;
                job->auth_tag_output = dust_bin;
                job->auth_tag_output_len_in_bytes = tag_len_tab[job->hash_alg];
                break;
        case AES_CMAC:
                job->u.CMAC._key_expanded = dust_bin;
                job->u.CMAC._skey1 = dust_bin;
                job->u.CMAC._skey2 = dust_bin;
                job->msg_len_to_hash_in_bytes = msg_len_to_hash;
                job->auth_tag_output = dust_bin;
                job->auth_tag_output_len_in_bytes = tag_len_tab[job->hash_alg];
                break;
        default:
                break;
        }
}

/*
 * @brief Submits \a job to \a mb_mgr and verifies it failed with
 *        invalid arguments status.
 */
static int
is_submit_invalid(struct MB_MGR *mb_mgr, const struct JOB_AES_HMAC *job,
                  const int test_num)
{
        struct JOB_AES_HMAC *mb_job = NULL, *job_ret = NULL;

        /* get next available job slot */
        mb_job = IMB_GET_NEXT_JOB(mb_mgr);
        if (mb_job == NULL) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected get_next_job() == NULL\n",
                       __func__, test_num, (int) job->hash_alg,
                       (int) job->chain_order, (int) job->cipher_direction,
                       (int) job->cipher_mode);
                return 0;
        }

        /* copy template job into available slot */
        *mb_job = *job;

        /* submit the job for processing */
        job_ret = IMB_SUBMIT_JOB(mb_mgr);

        /*
         * Returned job can be a previously submitted job or NULL
         * (if MB_MGR was empty).
         * Let's keep asking for completed jobs until we get the submitted job.
         */
        while (job_ret != mb_job) {
                job_ret = IMB_GET_COMPLETED_JOB(mb_mgr);
                if (job_ret == NULL) {
                        printf("%s : test %d, hash_alg %d, chain_order %d, "
                               "cipher_dir %d, cipher_mode %d : "
                               "unexpected job_ret == NULL "
                               "(most likely job passed checks and got "
                               "submitted)\n",
                               __func__, test_num, (int) job->hash_alg,
                               (int) job->chain_order,
                               (int) job->cipher_direction,
                               (int) job->cipher_mode);
                        return 0;
                }
        }

        if (job_ret->status != STS_INVALID_ARGS) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected job->status %d != STS_INVALID_ARGS\n",
                       __func__, test_num, (int) job_ret->hash_alg,
                       (int) job_ret->chain_order,
                       (int) job_ret->cipher_direction,
                       (int) job_ret->cipher_mode, (int) job_ret->status);
                return 0;
        }

        return 1;
}

/*
 * @brief Tests invalid settings for MAC modes
 */
static int
test_job_invalid_mac_args(struct MB_MGR *mb_mgr)
{
        JOB_HASH_ALG hash;
        JOB_CIPHER_DIRECTION dir;
        const JOB_CIPHER_MODE cipher = NULL_CIPHER;
        JOB_CHAIN_ORDER order;
        struct JOB_AES_HMAC template_job;
        struct JOB_AES_HMAC *job;

	printf("Invalid JOB MAC arguments test:\n");

        /* prep */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        /* ======== test 100
         * SRC = NULL
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (dir = ENCRYPT; dir <= DECRYPT; dir++)
                        for (hash = SHA1; hash <= PLAIN_SHA_512; hash++) {
                                if (hash == NULL_HASH ||
                                    hash == CUSTOM_HASH)
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order);
                                template_job.src = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       100))
                                        return 1;
                                printf(".");
                        }

        /* ======== test 101
         * AUTH_TAG_OUTPUT = NULL
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (dir = ENCRYPT; dir <= DECRYPT; dir++)
                        for (hash = SHA1; hash <= PLAIN_SHA_512; hash++) {
                                if (hash == NULL_HASH ||
                                    hash == CUSTOM_HASH)
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order);
                                template_job.auth_tag_output = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       101))
                                        return 1;
                                printf(".");
                        }

        /* ======== test 102
         * AUTH_TAG_OUTPUT_LEN = 0
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (dir = ENCRYPT; dir <= DECRYPT; dir++)
                        for (hash = SHA1; hash <= PLAIN_SHA_512; hash++) {
                                if (hash == NULL_HASH ||
                                    hash == CUSTOM_HASH)
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order);
                                template_job.auth_tag_output_len_in_bytes = 0;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       102))
                                        return 1;
                                printf(".");
                        }

        /* clean up */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        printf("\n");
        return 0;
}

/*
 * @brief Tests invalid settings for CIPHER modes
 */
static int
test_job_invalid_cipher_args(struct MB_MGR *mb_mgr)
{
        const JOB_HASH_ALG hash = NULL_HASH;
        JOB_CIPHER_DIRECTION dir;
        JOB_CIPHER_MODE cipher;
        JOB_CHAIN_ORDER order;
        struct JOB_AES_HMAC template_job;
        struct JOB_AES_HMAC *job;

	printf("Invalid JOB CIPHER arguments test:\n");

        /* prep */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        /* ======== test 200
         * SRC = NULL
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (dir = ENCRYPT; dir <= DECRYPT; dir++)
                        for (cipher = CBC; cipher <= DES3; cipher++) {
                                if (cipher == NULL_CIPHER ||
                                    cipher == CUSTOM_CIPHER)
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order);
                                template_job.src = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       200))
                                        return 1;
                                printf(".");
                        }

        /* ======== test 201
         * DST = NULL
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (dir = ENCRYPT; dir <= DECRYPT; dir++)
                        for (cipher = CBC; cipher <= DES3; cipher++) {
                                if (cipher == NULL_CIPHER ||
                                    cipher == CUSTOM_CIPHER)
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order);
                                template_job.dst = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       201))
                                        return 1;
                                printf(".");
                        }

        /* ======== test 202
         * IV = NULL
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (dir = ENCRYPT; dir <= DECRYPT; dir++)
                        for (cipher = CBC; cipher <= DES3; cipher++) {
                                if (cipher == NULL_CIPHER ||
                                    cipher == CUSTOM_CIPHER)
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order);
                                template_job.iv = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       202))
                                        return 1;
                                printf(".");
                        }

        /* ======== test 203 (encrypt)
         * AES_ENC_KEY_EXPANDED = NULL
         * AES_DEC_KEY_EXPANDED = NULL
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (cipher = CBC; cipher <= DES3; cipher++) {
                        fill_in_job(&template_job, cipher, ENCRYPT,
                                    hash, order);
                        switch (cipher) {
                        case CBC:
                        case CNTR:
                        case DOCSIS_SEC_BPI:
                        case GCM:
                        case DES:
                        case DOCSIS_DES:
                        case CCM:
                        case DES3:
                                template_job.aes_enc_key_expanded = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       203))
                                        return 1;
                                break;
                        case NULL_CIPHER:
                        case CUSTOM_CIPHER:
                        default:
                                break;
                        }
                        printf(".");
                }

        /* ======== test 204 (decrypt)
         * AES_ENC_KEY_EXPANDED = NULL
         * AES_DEC_KEY_EXPANDED = NULL
         */
        for (order = CIPHER_HASH; order <= HASH_CIPHER; order++)
                for (cipher = CBC; cipher <= DES3; cipher++) {
                        fill_in_job(&template_job, cipher, DECRYPT,
                                    hash, order);
                        switch (cipher) {
                        case GCM:
                        case CBC:
                        case DES:
                        case DES3:
                        case DOCSIS_DES:
                                template_job.aes_dec_key_expanded = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       204))
                                        return 1;
                                break;
                        case CNTR:
                        case CCM:
                                template_job.aes_enc_key_expanded = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       204))
                                        return 1;
                                break;
                        case DOCSIS_SEC_BPI:
                                template_job.aes_enc_key_expanded = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       204))
                                        return 1;
                                template_job.aes_enc_key_expanded =
                                        template_job.aes_dec_key_expanded;
                                template_job.aes_dec_key_expanded = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       204))
                                        return 1;
                                break;
                        case NULL_CIPHER:
                        case CUSTOM_CIPHER:
                        default:
                                break;
                        }
                        printf(".");
                }

        /* clean up */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        printf("\n");
        return 0;
}

int
api_test(const enum arch_type arch, struct MB_MGR *mb_mgr)
{
        int errors = 0;

        (void) arch; /* unused */

        errors += test_job_api(mb_mgr);
        errors += test_job_invalid_mac_args(mb_mgr);
        errors += test_job_invalid_cipher_args(mb_mgr);

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

	return errors;
}
