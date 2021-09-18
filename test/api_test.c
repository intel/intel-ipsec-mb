/*****************************************************************************
 Copyright (c) 2018-2021, Intel Corporation

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
#include "utils.h"

#ifdef _WIN32
#define __func__ __FUNCTION__
#endif

int api_test(struct IMB_MGR *mb_mgr);

enum {
      TEST_UNEXPECTED_JOB = 1,
      TEST_INVALID_JOB,
      TEST_AUTH_SRC_NULL = 100,
      TEST_AUTH_AUTH_TAG_OUTPUT_NULL,
      TEST_AUTH_TAG_OUTPUT_LEN_ZERO,
      TEST_AUTH_MSG_LEN_ZERO,
      TEST_AUTH_MSG_LEN_GT_MAX,
      TEST_CIPH_SRC_NULL = 200,
      TEST_CIPH_DST_NULL,
      TEST_CIPH_IV_NULL,
      TEST_CIPH_ENC_KEY_NULL,
      TEST_CIPH_DEC_KEY_NULL,
      TEST_CIPH_MSG_LEN_ZERO,
      TEST_CIPH_MSG_LEN_GT_MAX,
      TEST_CIPH_NEXT_IV_NULL,
};

/*
 * @brief Performs JOB API behavior tests
 */
static int
test_job_api(struct IMB_MGR *mb_mgr)
{
        struct IMB_JOB *job, *job_next;
        int err;

	printf("JOB API behavior test:\n");

        /* ======== test 1 */
        job = IMB_GET_NEXT_JOB(mb_mgr);
        if (job == NULL) {
                printf("%s: test %d, unexpected job = NULL\n",
                       __func__, TEST_UNEXPECTED_JOB);
                return 1;
        }
        printf(".");
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s: test %d, unexpected error: %s\n",
                       __func__, TEST_UNEXPECTED_JOB, imb_get_strerror(err));
                return 1;
        }
	printf(".");

        /* ======== test 2 : invalid cipher and mac */
        memset(job, 0, sizeof(*job));
        job_next = IMB_SUBMIT_JOB(mb_mgr);
        if (job != job_next) {
                /* Invalid job should be returned straight away */
                printf("%s: test %d, unexpected job != job_next\n",
                       __func__, TEST_INVALID_JOB);
                return 1;
        }
        printf(".");
        err = imb_get_errno(mb_mgr);
        if (err == 0) {
                printf("%s: test %d, unexpected error: %s\n",
                       __func__, TEST_INVALID_JOB, imb_get_strerror(err));
                return 1;
        }
        printf(".");

        if (job_next->status != IMB_STATUS_INVALID_ARGS) {
                /* Invalid job is returned, and status should be INVALID_ARGS */
                printf("%s: test %d, unexpected job->status != "
                       "IMB_STATUS_INVALID_ARGS\n", __func__, TEST_INVALID_JOB);
                return 1;
        }
	printf(".");

        job_next = IMB_GET_NEXT_JOB(mb_mgr);
        if (job == job_next) {
                /* get next job should point to a new job slot */
                printf("%s: test %d, unexpected job == get_next_job()\n",
                       __func__, TEST_INVALID_JOB);
                return 1;
        }
	printf(".");
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s: test %d, unexpected error: %s\n",
                       __func__, TEST_INVALID_JOB, imb_get_strerror(err));
                return 1;
        }
	printf(".");

        job = IMB_GET_COMPLETED_JOB(mb_mgr);
        if (job) {
                /* there should not be any completed jobs left */
                printf("%s: test %d, unexpected completed job\n",
                       __func__, TEST_INVALID_JOB);
                return 1;
        }
        printf(".");
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s: test %d, unexpected error: %s\n",
                       __func__, TEST_INVALID_JOB, imb_get_strerror(err));
                return 1;
        }
	printf(".");

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

	printf("\n");
        return 0;
}

/*
 * @brief Dummy function for custom hash and cipher modes
 */
static int dummy_cipher_hash_func(struct IMB_JOB *job)
{
        (void) job;
        return 0;
}

/*
 * @brief Fills in job structure with valid settings
 */
static void
fill_in_job(struct IMB_JOB *job,
            const IMB_CIPHER_MODE cipher_mode,
            const IMB_CIPHER_DIRECTION cipher_direction,
            const IMB_HASH_ALG hash_alg,
            const IMB_CHAIN_ORDER chain_order,
            struct chacha20_poly1305_context_data *chacha_ctx,
            struct gcm_context_data *gcm_ctx)
{
        const uint64_t tag_len_tab[] = {
                0,  /* INVALID selection */
                12, /* IMB_AUTH_HMAC_SHA_1 */
                14, /* IMB_AUTH_HMAC_SHA_224 */
                16, /* IMB_AUTH_HMAC_SHA_256 */
                24, /* IMB_AUTH_HMAC_SHA_384 */
                32, /* IMB_AUTH_HMAC_SHA_512 */
                12, /* IMB_AUTH_AES_XCBC */
                12, /* IMB_AUTH_MD5 */
                0,  /* IMB_AUTH_NULL */
                16, /* IMB_AUTH_AES_GMAC */
                0,  /* IMB_AUTH_CUSTOM */
                16, /* IMB_AUTH_AES_CCM */
                16, /* IMB_AUTH_AES_CMAC */
                20, /* IMB_AUTH_SHA_1 */
                28, /* IMB_AUTH_SHA_224 */
                32, /* IMB_AUTH_SHA_256 */
                48, /* IMB_AUTH_SHA_384 */
                64, /* IMB_AUTH_SHA_512 */
                4,  /* IMB_AUTH_AES_CMAC 3GPP */
                8,  /* IMB_AUTH_PON_CRC_BIP */
                4,  /* IMB_AUTH_ZUC_EIA3_BITLEN */
                4,  /* IMB_AUTH_DOCSIS_CRC32 */
                4,  /* IMB_AUTH_SNOW3G_UIA2_BITLEN */
                4,  /* IMB_AUTH_KASUMI_UIA1 */
                16, /* IMB_AUTH_AES_GMAC_128 */
                16, /* IMB_AUTH_AES_GMAC_192 */
                16, /* IMB_AUTH_AES_GMAC_256 */
                16, /* IMB_AUTH_AES_CMAC_256 */
                16, /* IMB_AUTH_POLY1305 */
                16, /* IMB_AUTH_CHACHA20_POLY1305 */
                16, /* IMB_AUTH_CHACHA20_POLY1305_SGL */
                4,  /* IMB_AUTH_ZUC256_EIA3_BITLEN */
                16, /* IMB_AUTH_SNOW_V_AEAD */
                16, /* IMB_AUTH_AES_GCM_SGL */
                4,  /* IMB_AUTH_CRC32_ETHERNET_FCS */
                4,  /* IMB_AUTH_CRC32_SCTP */
                4,  /* IMB_AUTH_CRC32_WIMAX_OFDMA_DATA */
                4,  /* IMB_AUTH_CRC24_LTE_A */
                4,  /* IMB_AUTH_CRC24_LTE_B */
                4,  /* IMB_AUTH_CRC16_X25 */
                4,  /* IMB_AUTH_CRC16_FP_DATA */
                4,  /* IMB_AUTH_CRC11_FP_HEADER */
                4,  /* IMB_AUTH_CRC10_IUUP_DATA */
                4,  /* IMB_AUTH_CRC8_WIMAX_OFDMA_HCS */
                4,  /* IMB_AUTH_CRC7_FP_HEADER */
                4,  /* IMB_AUTH_CRC6_IUUP_HEADER */
        };
        static DECLARE_ALIGNED(uint8_t dust_bin[2048], 64);
        const uint64_t msg_len_to_cipher = 32;
        const uint64_t msg_len_to_hash = 48;

        if (job == NULL)
                return;

        memset(job, 0, sizeof(*job));
        job->chain_order = chain_order;
        job->hash_alg = hash_alg;
        job->cipher_mode = cipher_mode;
        job->cipher_direction = cipher_direction;
        job->src = dust_bin;
        job->dst = dust_bin;
        job->enc_keys = dust_bin;
        job->dec_keys = dust_bin;
        job->iv = dust_bin;
        job->msg_len_to_cipher_in_bytes = msg_len_to_cipher;

        job->auth_tag_output = dust_bin;
        job->msg_len_to_hash_in_bytes = msg_len_to_hash;
        job->auth_tag_output_len_in_bytes = tag_len_tab[job->hash_alg];

        switch (job->cipher_mode) {
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_CBCS_1_9:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(16);
                break;
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_CNTR_BITLEN:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(16);
                break;
        case IMB_CIPHER_NULL:
                break;
        case IMB_CIPHER_DOCSIS_SEC_BPI:
                /* it has to be set regardless of direction (AES-CFB) */
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(16);
                break;
        case IMB_CIPHER_GCM:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(12);
                break;
        case IMB_CIPHER_CUSTOM:
                job->cipher_func = dummy_cipher_hash_func;
                break;
        case IMB_CIPHER_DES:
                job->key_len_in_bytes = UINT64_C(8);
                job->iv_len_in_bytes = UINT64_C(8);
                break;
        case IMB_CIPHER_DOCSIS_DES:
                job->key_len_in_bytes = UINT64_C(8);
                job->iv_len_in_bytes = UINT64_C(8);
                break;
        case IMB_CIPHER_CCM:
                /* AES-CTR and CBC-MAC use only encryption keys */
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(13);
                break;
        case IMB_CIPHER_DES3:
                job->key_len_in_bytes = UINT64_C(24);
                job->iv_len_in_bytes = UINT64_C(8);
                break;
        case IMB_CIPHER_PON_AES_CNTR:
                job->dst = dust_bin + 8;
                job->hash_alg = IMB_AUTH_PON_CRC_BIP;
                job->key_len_in_bytes = 16;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_ECB:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = 0;
                break;
        case IMB_CIPHER_ZUC_EEA3:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = 8;
                break;
        case IMB_CIPHER_CHACHA20:
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_CHACHA20_POLY1305:
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305_SGL;
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_SNOW_V:
                job->hash_alg = IMB_AUTH_NULL;
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_SNOW_V_AEAD:
                job->hash_alg = IMB_AUTH_SNOW_V_AEAD;
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_GCM_SGL:
                job->hash_alg = IMB_AUTH_GCM_SGL;
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(12);
                break;
        default:
                break;
        }

        switch (job->hash_alg) {
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_MD5:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
        case IMB_AUTH_CRC32_ETHERNET_FCS:
        case IMB_AUTH_CRC32_SCTP:
        case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
        case IMB_AUTH_CRC24_LTE_A:
        case IMB_AUTH_CRC24_LTE_B:
        case IMB_AUTH_CRC16_X25:
        case IMB_AUTH_CRC16_FP_DATA:
        case IMB_AUTH_CRC11_FP_HEADER:
        case IMB_AUTH_CRC10_IUUP_DATA:
        case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
        case IMB_AUTH_CRC7_FP_HEADER:
        case IMB_AUTH_CRC6_IUUP_HEADER:
        case IMB_AUTH_NULL:
                break;
        case IMB_AUTH_AES_XCBC:
                job->u.XCBC._k1_expanded = (const uint32_t *) dust_bin;
                job->u.XCBC._k2 = dust_bin;
                job->u.XCBC._k3 = dust_bin;
                break;
        case IMB_AUTH_CUSTOM:
                job->hash_func = dummy_cipher_hash_func;
                break;
        case IMB_AUTH_AES_GMAC:
                job->u.GCM.aad = dust_bin;
                job->u.GCM.aad_len_in_bytes = 16;
                /* set required cipher mode fields */
                job->cipher_mode = IMB_CIPHER_GCM;
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(12);
                break;
        case IMB_AUTH_AES_CCM:
                job->u.CCM.aad = dust_bin;
                job->u.CCM.aad_len_in_bytes = 16;
                job->hash_start_src_offset_in_bytes =
                        job->cipher_start_src_offset_in_bytes;
                job->msg_len_to_hash_in_bytes = msg_len_to_cipher;
                /* set required cipher mode fields */
                job->cipher_mode = IMB_CIPHER_CCM;
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(12);
                break;
        case IMB_AUTH_AES_CMAC:
        case IMB_AUTH_AES_CMAC_BITLEN:
        case IMB_AUTH_AES_CMAC_256:
                job->u.CMAC._key_expanded = dust_bin;
                job->u.CMAC._skey1 = dust_bin;
                job->u.CMAC._skey2 = dust_bin;
                break;
        case IMB_AUTH_PON_CRC_BIP:
                job->msg_len_to_hash_in_bytes = 8;
                job->auth_tag_output_len_in_bytes = 8;
                job->hash_start_src_offset_in_bytes = 0;
                job->cipher_start_src_offset_in_bytes = 8;
                /* set required cipher mode fields */
                job->cipher_mode = IMB_CIPHER_PON_AES_CNTR;
                job->dst = dust_bin + 8;
                job->hash_alg = IMB_AUTH_PON_CRC_BIP;
                job->key_len_in_bytes = 16;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_AUTH_ZUC_EIA3_BITLEN:
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
                job->u.ZUC_EIA3._key = dust_bin;
                job->u.ZUC_EIA3._iv = dust_bin;
                job->auth_tag_output_len_in_bytes = 4;
                break;
        case IMB_AUTH_DOCSIS_CRC32:
                job->auth_tag_output_len_in_bytes = 4;
                job->hash_start_src_offset_in_bytes = 32;
                job->cipher_start_src_offset_in_bytes =
                        job->hash_start_src_offset_in_bytes + 12;
                job->msg_len_to_hash_in_bits = 64;
                job->msg_len_to_cipher_in_bytes =
                        job->msg_len_to_hash_in_bytes - 12 + 4;
                /* set required cipher mode fields */
                job->cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI;
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(16);
                break;
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                job->msg_len_to_hash_in_bits = msg_len_to_hash * 8;
                job->u.SNOW3G_UIA2._key = dust_bin;
                job->u.SNOW3G_UIA2._iv = dust_bin;
                job->auth_tag_output_len_in_bytes = 4;
                break;
        case IMB_AUTH_KASUMI_UIA1:
                job->u.KASUMI_UIA1._key = dust_bin;
                job->auth_tag_output_len_in_bytes = 4;
                break;
        case IMB_AUTH_AES_GMAC_128:
        case IMB_AUTH_AES_GMAC_192:
        case IMB_AUTH_AES_GMAC_256:
                job->u.GMAC._key = (struct gcm_key_data *) dust_bin;
                job->u.GMAC._iv = dust_bin;
                job->u.GMAC.iv_len_in_bytes = 12;
                job->auth_tag_output_len_in_bytes = 16;
                break;
        case IMB_AUTH_POLY1305:
                job->u.POLY1305._key = dust_bin;
                job->auth_tag_output_len_in_bytes = 16;
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 12;
                job->u.CHACHA20_POLY1305.aad = dust_bin;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = 12;
                job->auth_tag_output_len_in_bytes = 16;
                break;
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305_SGL;
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 12;
                job->u.CHACHA20_POLY1305.aad = dust_bin;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = 12;
                job->auth_tag_output_len_in_bytes = 16;
                job->u.CHACHA20_POLY1305.ctx = chacha_ctx;
                break;
        case IMB_AUTH_GCM_SGL:
                job->u.GCM.ctx = gcm_ctx;
                job->u.GCM.aad = dust_bin;
                job->u.GCM.aad_len_in_bytes = 16;
                /* set required cipher mode fields */
                job->cipher_mode = IMB_CIPHER_GCM_SGL;
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(12);
                break;
        case IMB_AUTH_SNOW_V_AEAD:
                job->cipher_mode = IMB_CIPHER_SNOW_V_AEAD;
                job->key_len_in_bytes = UINT64_C(32);
                job->iv_len_in_bytes = 16;
                job->auth_tag_output_len_in_bytes = 16;
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
is_submit_invalid(struct IMB_MGR *mb_mgr, const struct IMB_JOB *job,
                  const int test_num, int expected_errnum)
{
        struct IMB_JOB *mb_job = NULL, *job_ret = NULL;
        int err;

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
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected error: %s\n",
                       __func__, test_num, (int) job->hash_alg,
                       (int) job->chain_order, (int) job->cipher_direction,
                       (int) job->cipher_mode, imb_get_strerror(err));
                return 0;
        }

        /* copy template job into available slot */
        *mb_job = *job;

        /* submit the job for processing */
        job_ret = IMB_SUBMIT_JOB(mb_mgr);
        err = imb_get_errno(mb_mgr);
        if (err != expected_errnum) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected error: %s\n",
                       __func__, test_num, (int) job->hash_alg,
                       (int) job->chain_order, (int) job->cipher_direction,
                       (int) job->cipher_mode, imb_get_strerror(err));
                return 0;
        }

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
                err = imb_get_errno(mb_mgr);
                if (err != 0) {
                        printf("%s : test %d, hash_alg %d, chain_order %d, "
                               "cipher_dir %d, cipher_mode %d : "
                               "unexpected error: %s\n",
                               __func__, test_num, (int) job->hash_alg,
                               (int) job->chain_order,
                               (int) job->cipher_direction,
                               (int) job->cipher_mode,
                               imb_get_strerror(err));
                        return 0;
                }
        }

        if (job_ret->status != IMB_STATUS_INVALID_ARGS) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected job->status %d != IMB_STATUS_INVALID_ARGS\n",
                       __func__, test_num, (int) job_ret->hash_alg,
                       (int) job_ret->chain_order,
                       (int) job_ret->cipher_direction,
                       (int) job_ret->cipher_mode, (int) job_ret->status);
                return 0;
        }

        return 1;
}

/*
 * @brief Checks for AEAD algorithms
 */
static int
check_aead(IMB_HASH_ALG hash, IMB_CIPHER_MODE cipher)
{
        if (hash == IMB_AUTH_CHACHA20_POLY1305 ||
            hash == IMB_AUTH_CHACHA20_POLY1305_SGL ||
            hash == IMB_AUTH_GCM_SGL ||
            hash == IMB_AUTH_AES_GMAC ||
            hash == IMB_AUTH_AES_CCM ||
            hash == IMB_AUTH_SNOW_V_AEAD ||
            hash == IMB_AUTH_PON_CRC_BIP)
                return 1;

        if (cipher == IMB_CIPHER_CHACHA20_POLY1305 ||
            cipher == IMB_CIPHER_CHACHA20_POLY1305_SGL ||
            cipher == IMB_CIPHER_GCM_SGL ||
            cipher == IMB_CIPHER_GCM ||
            cipher == IMB_CIPHER_CCM ||
            cipher == IMB_CIPHER_SNOW_V_AEAD ||
            cipher == IMB_CIPHER_PON_AES_CNTR)
                return 1;
        return 0;
}

/*
 * @brief Tests invalid settings for MAC modes
 */
static int
test_job_invalid_mac_args(struct IMB_MGR *mb_mgr)
{
        IMB_HASH_ALG hash;
        IMB_CIPHER_DIRECTION dir;
        const IMB_CIPHER_MODE cipher = IMB_CIPHER_NULL;
        IMB_CHAIN_ORDER order;
        struct IMB_JOB template_job;
        struct chacha20_poly1305_context_data chacha_ctx;
        struct gcm_context_data gcm_ctx;

	printf("Invalid JOB MAC arguments test:\n");

        /* prep */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        /*
         * SRC = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1;
                             hash < IMB_AUTH_NUM; hash++) {
                                if (hash == IMB_AUTH_NULL ||
                                    hash == IMB_AUTH_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (hash != IMB_AUTH_SNOW3G_UIA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order, &chacha_ctx, &gcm_ctx);
                                template_job.src = NULL;
                                if (!is_submit_invalid(mb_mgr,
                                                       &template_job,
                                                       TEST_AUTH_SRC_NULL,
                                                       IMB_ERR_JOB_NULL_SRC))
                                        return 1;
                                printf(".");
                        }

        /*
         * AUTH_TAG_OUTPUT = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1;
                             hash < IMB_AUTH_NUM; hash++) {
                                if (hash == IMB_AUTH_NULL ||
                                    hash == IMB_AUTH_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (hash != IMB_AUTH_SNOW3G_UIA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order, &chacha_ctx, &gcm_ctx);
                                template_job.auth_tag_output = NULL;
                                if (hash == IMB_AUTH_GCM_SGL)
                                        template_job.sgl_state =
                                                IMB_SGL_COMPLETE;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                 TEST_AUTH_AUTH_TAG_OUTPUT_NULL,
                                                 IMB_ERR_JOB_NULL_AUTH))
                                        return 1;
                                printf(".");
                        }

        /*
         * AUTH_TAG_OUTPUT_LEN = 0 test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1;
                             hash < IMB_AUTH_NUM; hash++) {
                                if (hash == IMB_AUTH_NULL ||
                                    hash == IMB_AUTH_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (hash != IMB_AUTH_SNOW3G_UIA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order, &chacha_ctx, &gcm_ctx);
                                template_job.auth_tag_output_len_in_bytes = 0;
                                if (hash == IMB_AUTH_GCM_SGL)
                                        template_job.sgl_state =
                                                IMB_SGL_COMPLETE;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                  TEST_AUTH_TAG_OUTPUT_LEN_ZERO,
                                                  IMB_ERR_JOB_AUTH_TAG_LEN))
                                        return 1;
                                printf(".");
                        }

        /*
         * AUTH_MSG_LEN > MAX
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1;
                             hash < IMB_AUTH_NUM; hash++) {
                                /* skip algorithms with no max length limit */
                                if (hash == IMB_AUTH_NULL ||
                                    hash == IMB_AUTH_CUSTOM ||
                                    hash == IMB_AUTH_PON_CRC_BIP ||
                                    hash == IMB_AUTH_AES_GMAC ||
                                    hash == IMB_AUTH_AES_GMAC_128 ||
                                    hash == IMB_AUTH_AES_GMAC_192 ||
                                    hash == IMB_AUTH_AES_GMAC_256 ||
                                    hash == IMB_AUTH_SNOW_V_AEAD ||
                                    hash == IMB_AUTH_CRC32_ETHERNET_FCS ||
                                    hash == IMB_AUTH_CRC32_SCTP ||
                                    hash == IMB_AUTH_CRC32_WIMAX_OFDMA_DATA ||
                                    hash == IMB_AUTH_CRC24_LTE_A ||
                                    hash == IMB_AUTH_CRC24_LTE_B ||
                                    hash == IMB_AUTH_CRC16_X25 ||
                                    hash == IMB_AUTH_CRC16_FP_DATA ||
                                    hash == IMB_AUTH_CRC11_FP_HEADER ||
                                    hash == IMB_AUTH_CRC10_IUUP_DATA ||
                                    hash == IMB_AUTH_CRC8_WIMAX_OFDMA_HCS ||
                                    hash == IMB_AUTH_CRC7_FP_HEADER ||
                                    hash == IMB_AUTH_CRC6_IUUP_HEADER ||
                                    hash == IMB_AUTH_POLY1305)
                                        continue;
#ifdef __aarch64__
                                if (hash != IMB_AUTH_SNOW3G_UIA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order, &chacha_ctx, &gcm_ctx);

                                switch (hash) {
                                case IMB_AUTH_ZUC_EIA3_BITLEN:
                                case IMB_AUTH_ZUC256_EIA3_BITLEN:
                                        /* (2^32) - 32 is max */
                                        template_job.msg_len_to_hash_in_bytes =
                                                ((1ULL << 32) - 31);
                                        break;
                                case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                                        /* (2^32) is max */
                                        template_job.msg_len_to_hash_in_bits =
                                                ((1ULL << 32) + 1);
                                        break;
                                case IMB_AUTH_KASUMI_UIA1:
                                        /* 20000 bits (2500 bytes) is max */
                                        template_job.msg_len_to_hash_in_bytes =
                                                (20008 / 8); /* 2501 bytes */
                                        break;
                                case IMB_AUTH_CHACHA20_POLY1305:
                                case IMB_AUTH_CHACHA20_POLY1305_SGL:
                                        /* CHACHA20 limit (2^32 - 1) x 64 */
                                        template_job.msg_len_to_hash_in_bytes =
                                                ((1ULL << 38) - 64) + 1;
                                        break;
                                default:
                                        template_job.msg_len_to_hash_in_bytes =
                                                ((1 << 16) - 1);
                                        break;
                                }
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                  TEST_AUTH_MSG_LEN_GT_MAX,
                                                  IMB_ERR_JOB_AUTH_LEN))
                                        return 1;
                                printf(".");
                        }

        /*
         * AUTH_MSG_LEN = 0
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1;
                             hash < IMB_AUTH_NUM; hash++) {
#ifdef __aarch64__
                                if (hash != IMB_AUTH_SNOW3G_UIA2_BITLEN)
                                        continue;
#endif

                                switch (hash) {
                                /*
                                 * Cases below don't allow for zero length
                                 * hash messages
                                 */
                                case IMB_AUTH_HMAC_SHA_1:
                                case IMB_AUTH_HMAC_SHA_224:
                                case IMB_AUTH_HMAC_SHA_256:
                                case IMB_AUTH_HMAC_SHA_384:
                                case IMB_AUTH_HMAC_SHA_512:
                                case IMB_AUTH_MD5:
                                case IMB_AUTH_KASUMI_UIA1:
                                        fill_in_job(&template_job, cipher, dir,
                                                    hash, order, &chacha_ctx,
                                                    &gcm_ctx);
                                        template_job.msg_len_to_hash_in_bytes
                                                = 0;
                                        break;
                                default:
                                        /*
                                         * Skip algos that accept 0 length
                                         * hash messages
                                         */
                                        continue;
                                }

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_AUTH_MSG_LEN_ZERO,
                                                       IMB_ERR_JOB_AUTH_LEN))
                                        return 1;
                                printf(".");
                        }

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        printf("\n");
        return 0;
}

/*
 * @brief Tests invalid settings for CIPHER modes
 */
static int
test_job_invalid_cipher_args(struct IMB_MGR *mb_mgr)
{
        const IMB_HASH_ALG hash = IMB_AUTH_NULL;
        IMB_CIPHER_DIRECTION dir;
        IMB_CIPHER_MODE cipher;
        IMB_CHAIN_ORDER order;
        struct IMB_JOB template_job;
        struct chacha20_poly1305_context_data chacha_ctx;
        struct gcm_context_data gcm_ctx;

	printf("Invalid JOB CIPHER arguments test:\n");

        /* prep */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        /*
         * SRC = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC;
                             cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL ||
                                    cipher == IMB_CIPHER_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (cipher != IMB_CIPHER_SNOW3G_UEA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order, &chacha_ctx, &gcm_ctx);
                                template_job.src = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_SRC_NULL,
                                                       IMB_ERR_JOB_NULL_SRC))
                                        return 1;
                                printf(".");
                        }

        /*
         * DST = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC;
                             cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL ||
                                    cipher == IMB_CIPHER_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (cipher != IMB_CIPHER_SNOW3G_UEA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order, &chacha_ctx, &gcm_ctx);
                                template_job.dst = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_DST_NULL,
                                                       IMB_ERR_JOB_NULL_DST))
                                        return 1;
                                printf(".");
                        }

        /*
         * IV = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC;
                             cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL ||
                                    cipher == IMB_CIPHER_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (cipher != IMB_CIPHER_SNOW3G_UEA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir,
                                            hash, order, &chacha_ctx, &gcm_ctx);
                                template_job.iv = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_IV_NULL,
                                                       IMB_ERR_JOB_NULL_IV))
                                        return 1;
                                printf(".");
                        }

        /* ======== (encrypt test)
         * AES_ENC_KEY_EXPANDED = NULL
         * AES_DEC_KEY_EXPANDED = NULL
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM;
                     cipher++) {
#ifdef __aarch64__
                        if ((cipher != IMB_CIPHER_NULL) &&
                            (cipher != IMB_CIPHER_SNOW3G_UEA2_BITLEN))
                                continue;
#endif

                        fill_in_job(&template_job, cipher, IMB_DIR_ENCRYPT,
                                    hash, order, &chacha_ctx, &gcm_ctx);

                        /*
                         * Skip cipher algorithms belonging to AEAD
                         * algorithms, as the test is for cipher
                         * only algorithms */
                        if (check_aead(hash, cipher))
                                continue;

                        switch (cipher) {
                        case IMB_CIPHER_NULL:
                        case IMB_CIPHER_CUSTOM:
                                break;
                        default:
                                template_job.enc_keys = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_ENC_KEY_NULL,
                                                       IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                break;
                        }
                        printf(".");
                }

        /* ======== (decrypt test)
         * AES_ENC_KEY_EXPANDED = NULL
         * AES_DEC_KEY_EXPANDED = NULL
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM;
                     cipher++) {
#ifdef __aarch64__
                        if ((cipher != IMB_CIPHER_NULL) &&
                            (cipher != IMB_CIPHER_SNOW3G_UEA2_BITLEN))
                                continue;
#endif
                        /*
                         * Skip cipher algorithms belonging to AEAD
                         * algorithms, as the test is for cipher
                         * only algorithms */
                        if (check_aead(hash, cipher))
                                continue;

                        fill_in_job(&template_job, cipher, IMB_DIR_DECRYPT,
                                    hash, order, &chacha_ctx, &gcm_ctx);
                        switch (cipher) {
                        case IMB_CIPHER_GCM:
                        case IMB_CIPHER_CBC:
                        case IMB_CIPHER_CBCS_1_9:
                        case IMB_CIPHER_DES:
                        case IMB_CIPHER_DES3:
                        case IMB_CIPHER_DOCSIS_DES:
                                template_job.dec_keys = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_DEC_KEY_NULL,
                                                       IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                break;
                        case IMB_CIPHER_CNTR:
                        case IMB_CIPHER_CNTR_BITLEN:
                        case IMB_CIPHER_CCM:
                        case IMB_CIPHER_ECB:
                        case IMB_CIPHER_PON_AES_CNTR:
                        case IMB_CIPHER_ZUC_EEA3:
                        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                        case IMB_CIPHER_CHACHA20:
                                template_job.enc_keys = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_DEC_KEY_NULL,
                                                       IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                break;
                        case IMB_CIPHER_DOCSIS_SEC_BPI:
                                template_job.enc_keys = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_DEC_KEY_NULL,
                                                       IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                template_job.enc_keys =
                                        template_job.dec_keys;
                                template_job.dec_keys = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_DEC_KEY_NULL,
                                                       IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                break;
                        case IMB_CIPHER_NULL:
                        case IMB_CIPHER_CUSTOM:
                        default:
                                break;
                        }
                        printf(".");
                }

        /*
         * CIPHER_MSG_LEN = 0
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC;
                             cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL ||
                                    cipher == IMB_CIPHER_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (cipher != IMB_CIPHER_SNOW3G_UEA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order,
                                            &chacha_ctx, &gcm_ctx);

                                switch (cipher) {
                                /* skip ciphers that allow msg length 0 */
                                case IMB_CIPHER_GCM:
                                case IMB_CIPHER_GCM_SGL:
                                case IMB_CIPHER_CCM:
                                case IMB_CIPHER_DOCSIS_SEC_BPI:
                                case IMB_CIPHER_CHACHA20_POLY1305:
                                case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                                case IMB_CIPHER_PON_AES_CNTR:
                                case IMB_CIPHER_SNOW_V:
                                case IMB_CIPHER_SNOW_V_AEAD:

                                        break;
                                default:
                                        job->msg_len_to_cipher_in_bytes = 0;
                                        if (!is_submit_invalid(mb_mgr, job,
                                                         TEST_CIPH_MSG_LEN_ZERO,
                                                         IMB_ERR_JOB_CIPH_LEN))
                                                return 1;
                                }
                                printf(".");
                        }

        /*
         * CIPHER_MSG_LEN > MAX
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC;
                             cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL ||
                                    cipher == IMB_CIPHER_CUSTOM)
                                        continue;
#ifdef __aarch64__
                                if (cipher != IMB_CIPHER_SNOW3G_UEA2_BITLEN)
                                        continue;
#endif

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order,
                                            &chacha_ctx, &gcm_ctx);

                                switch (cipher) {
                                        /* skip ciphers with no max limit */
                                case IMB_CIPHER_GCM:
                                case IMB_CIPHER_GCM_SGL:
                                case IMB_CIPHER_CUSTOM:
                                case IMB_CIPHER_CNTR:
                                case IMB_CIPHER_CNTR_BITLEN:
                                case IMB_CIPHER_PON_AES_CNTR:
                                case IMB_CIPHER_SNOW_V:
                                case IMB_CIPHER_SNOW_V_AEAD:
                                case IMB_CIPHER_NULL:
                                        continue;
                                        /* not allowed with null hash */
                                case IMB_CIPHER_CHACHA20_POLY1305:
                                case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                                        continue;
                                case IMB_CIPHER_ZUC_EEA3:
                                        /* max is 8188 bytes */
                                        job->msg_len_to_cipher_in_bytes = 8190;
                                        break;
                                case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                                        /* max is 2^32 bits */
                                        job->msg_len_to_cipher_in_bits =
                                                ((1ULL << 32));
                                        break;
                                case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                                        /* max is 20000 bits */
                                        job->msg_len_to_cipher_in_bits =
                                                20008;
                                        break;
                                case IMB_CIPHER_CBCS_1_9:
                                        /* max is 2^60 bytes */
                                        job->msg_len_to_cipher_in_bytes =
                                                ((1ULL << 60) + 1);
                                        break;
                                case IMB_CIPHER_CHACHA20:
                                        /* Chacha20 limit (2^32 - 1) x 64 */
                                        job->msg_len_to_cipher_in_bytes =
                                                ((1ULL << 38) - 64) + 1;
                                        break;
                                default:
                                        /* most MB max len is 2^16 - 2 */
                                        job->msg_len_to_cipher_in_bytes =
                                                ((1 << 16) - 1);
                                        break;
                                }
                                if (!is_submit_invalid(mb_mgr, job,
                                                       TEST_CIPH_MSG_LEN_GT_MAX,
                                                       IMB_ERR_JOB_CIPH_LEN))
                                        return 1;

                                printf(".");
                        }

        /*
         * OTHER MISC TESTS
         */

#ifndef __aarch64__
        /* CBCS NULL NEXT IV TEST */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER;
             order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        cipher = IMB_CIPHER_CBCS_1_9;

                        /*
                         * Skip cipher algorithms belonging to AEAD
                         * algorithms, as the test is for cipher
                         * only algorithms */
                        if (check_aead(hash, cipher))
                                continue;

                        IMB_JOB *job = &template_job;

                        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx,
                                    &gcm_ctx);

                        job->cipher_fields.CBCS.next_iv = NULL;

                        if (!is_submit_invalid(mb_mgr, job,
                                               TEST_CIPH_NEXT_IV_NULL,
                                               IMB_ERR_JOB_NULL_NEXT_IV))
                                return 1;
                        printf(".");
                }
#endif

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        printf("\n");
        return 0;
}

int
api_test(struct IMB_MGR *mb_mgr)
{
        int errors = 0, run = 0;
        struct test_suite_context ctx;

        test_suite_start(&ctx, "INVALID-JOB-ARGS");

        errors += test_job_api(mb_mgr);
        run++;

        errors += test_job_invalid_mac_args(mb_mgr);
        run++;

        errors += test_job_invalid_cipher_args(mb_mgr);
        run++;

        test_suite_update(&ctx, run - errors, errors);

        test_suite_end(&ctx);

        return errors;
}
