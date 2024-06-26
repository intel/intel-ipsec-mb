/*****************************************************************************
 Copyright (c) 2018-2023, Intel Corporation

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

int
api_test(struct IMB_MGR *mb_mgr);

enum {
        TEST_UNEXPECTED_JOB = 1,
        TEST_INVALID_JOB,
        TEST_INVALID_BURST,
        TEST_AUTH_SRC_NULL = 100,
        TEST_AUTH_AUTH_TAG_OUTPUT_NULL,
        TEST_AUTH_TAG_OUTPUT_LEN_ZERO,
        TEST_AUTH_MSG_LEN_ZERO,
        TEST_AUTH_MSG_LEN_GT_MAX,
        TEST_AUTH_IV_LEN,
        TEST_AUTH_NULL_HMAC_OPAD,
        TEST_AUTH_NULL_HMAC_IPAD,
        TEST_AUTH_NULL_XCBC_K1_EXP,
        TEST_AUTH_NULL_XCBC_K2,
        TEST_AUTH_NULL_XCBC_K3,
        TEST_AUTH_NULL_GHASH_KEY,
        TEST_AUTH_NULL_GHASH_INIT_TAG,
        TEST_AUTH_NULL_GMAC_KEY,
        TEST_AUTH_NULL_GMAC_IV,
        TEST_AUTH_GMAC_IV_LEN,
        TEST_CIPH_SRC_NULL = 200,
        TEST_CIPH_DST_NULL,
        TEST_CIPH_IV_NULL,
        TEST_CIPH_ENC_KEY_NULL,
        TEST_CIPH_DEC_KEY_NULL,
        TEST_CIPH_MSG_LEN_ZERO,
        TEST_CIPH_MSG_LEN_GT_MAX,
        TEST_CIPH_NEXT_IV_NULL,
        TEST_CIPH_IV_LEN,
        TEST_CIPH_DIR,
        TEST_INVALID_PON_PLI = 300,
};

static void
print_progress(void)
{
        if (!quiet_mode)
                printf(".");
}

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
                printf("%s: test %d, unexpected job = NULL\n", __func__, TEST_UNEXPECTED_JOB);
                return 1;
        }
        print_progress();
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_UNEXPECTED_JOB,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        /* ======== test 2 : invalid cipher and mac */
        memset(job, 0, sizeof(*job));
        job_next = IMB_SUBMIT_JOB(mb_mgr);
        if (job != job_next) {
                /* Invalid job should be returned straight away */
                printf("%s: test %d, unexpected job != job_next\n", __func__, TEST_INVALID_JOB);
                return 1;
        }
        print_progress();
        err = imb_get_errno(mb_mgr);
        if (err == 0) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_JOB,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        if (job_next->status != IMB_STATUS_INVALID_ARGS) {
                /* Invalid job is returned, and status should be INVALID_ARGS */
                printf("%s: test %d, unexpected job->status != "
                       "IMB_STATUS_INVALID_ARGS\n",
                       __func__, TEST_INVALID_JOB);
                return 1;
        }
        print_progress();

        job_next = IMB_GET_NEXT_JOB(mb_mgr);
        if (job == job_next) {
                /* get next job should point to a new job slot */
                printf("%s: test %d, unexpected job == get_next_job()\n", __func__,
                       TEST_INVALID_JOB);
                return 1;
        }
        print_progress();
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_JOB,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        job = IMB_GET_COMPLETED_JOB(mb_mgr);
        if (job) {
                /* there should not be any completed jobs left */
                printf("%s: test %d, unexpected completed job\n", __func__, TEST_INVALID_JOB);
                return 1;
        }
        print_progress();
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_JOB,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Dummy function for custom hash and cipher modes
 */
static int
dummy_cipher_hash_func(struct IMB_JOB *job)
{
        (void) job;
        return 0;
}

/*
 * @brief Fills in job structure with valid settings
 */
static void
fill_in_job(struct IMB_JOB *job, const IMB_CIPHER_MODE cipher_mode,
            const IMB_CIPHER_DIRECTION cipher_direction, const IMB_HASH_ALG hash_alg,
            const IMB_CHAIN_ORDER chain_order, struct chacha20_poly1305_context_data *chacha_ctx,
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
                16, /* IMB_AUTH_GHASH */
                32, /* IMB_AUTH_SM3 */
                32, /* IMB_AUTH_HMAC_SM3 */
        };
        static DECLARE_ALIGNED(uint8_t dust_bin[2048], 64);
        static void *ks_ptrs[3];
        const uint64_t msg_len_to_cipher = 32;
        const uint64_t msg_len_to_hash = 48;

        if (job == NULL)
                return;

        /*
         * Some algs use src data for checks e.g. PON PLI check
         * Fill buffer with invalid data
         */
        memset(dust_bin, 0xff, sizeof(dust_bin));

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
        case IMB_CIPHER_SM4_CBC:
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_CBCS_1_9:
                job->key_len_in_bytes = UINT64_C(16);
                job->iv_len_in_bytes = UINT64_C(16);
                if (job->cipher_mode == IMB_CIPHER_CBCS_1_9)
                        job->cipher_fields.CBCS.next_iv = dust_bin;
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
                job->hash_alg = IMB_AUTH_AES_GMAC;
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
                ks_ptrs[0] = dust_bin;
                ks_ptrs[1] = dust_bin;
                ks_ptrs[2] = dust_bin;
                job->enc_keys = ks_ptrs;
                job->dec_keys = ks_ptrs;
                break;
        case IMB_CIPHER_PON_AES_CNTR:
                job->dst = dust_bin + 8;
                job->hash_alg = IMB_AUTH_PON_CRC_BIP;
                job->key_len_in_bytes = 16;
                job->iv_len_in_bytes = 16;

                /* create XGEM header template */
                const uint64_t pli = (msg_len_to_cipher << 2) & 0xffff;
                uint64_t *ptr64 = (uint64_t *) dust_bin;

                ptr64[0] = ((pli >> 8) & 0xff) | ((pli & 0xff) << 8);
                break;
        case IMB_CIPHER_ECB:
        case IMB_CIPHER_SM4_ECB:
                job->key_len_in_bytes = UINT64_C(16);
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
                job->sgl_state = IMB_SGL_UPDATE;
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
                job->sgl_state = IMB_SGL_UPDATE;
                break;
        default:
                break;
        }

        switch (job->hash_alg) {
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_HMAC_SM3:
        case IMB_AUTH_MD5:
                job->u.HMAC._hashed_auth_key_xor_ipad = dust_bin;
                job->u.HMAC._hashed_auth_key_xor_opad = dust_bin;
                break;
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
                job->hash_start_src_offset_in_bytes = job->cipher_start_src_offset_in_bytes;
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
                job->cipher_start_src_offset_in_bytes = job->hash_start_src_offset_in_bytes + 12;
                job->msg_len_to_hash_in_bits = 64;
                job->msg_len_to_cipher_in_bytes = job->msg_len_to_hash_in_bytes - 12 + 4;
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
        case IMB_AUTH_GHASH:
                job->u.GHASH._key = (struct gcm_key_data *) dust_bin;
                job->u.GHASH._init_tag = dust_bin;
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
        case IMB_AUTH_SM3:
                job->auth_tag_output_len_in_bytes = IMB_SM3_DIGEST_SIZE;
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
is_submit_invalid(struct IMB_MGR *mb_mgr, const struct IMB_JOB *job, const int test_num,
                  int expected_errnum)
{
        struct IMB_JOB *mb_job = NULL, *job_ret = NULL;
        int err;

        /* get next available job slot */
        mb_job = IMB_GET_NEXT_JOB(mb_mgr);
        if (mb_job == NULL) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected get_next_job() == NULL\n",
                       __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                       (int) job->cipher_direction, (int) job->cipher_mode);
                return 0;
        }
        err = imb_get_errno(mb_mgr);
        if (err != 0) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected error: %s\n",
                       __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                       (int) job->cipher_direction, (int) job->cipher_mode, imb_get_strerror(err));
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
                       __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                       (int) job->cipher_direction, (int) job->cipher_mode, imb_get_strerror(err));
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
                               __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                               (int) job->cipher_direction, (int) job->cipher_mode);
                        return 0;
                }
                err = imb_get_errno(mb_mgr);
                if (err != 0) {
                        printf("%s : test %d, hash_alg %d, chain_order %d, "
                               "cipher_dir %d, cipher_mode %d : "
                               "unexpected error: %s\n",
                               __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                               (int) job->cipher_direction, (int) job->cipher_mode,
                               imb_get_strerror(err));
                        return 0;
                }
        }

        if (job_ret->status != IMB_STATUS_INVALID_ARGS) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected job->status %d != IMB_STATUS_INVALID_ARGS\n",
                       __func__, test_num, (int) job_ret->hash_alg, (int) job_ret->chain_order,
                       (int) job_ret->cipher_direction, (int) job_ret->cipher_mode,
                       (int) job_ret->status);
                return 0;
        }

        return 1;
}

/*
 * @brief Submits \a job using the burst API and verifies it failed with
 *        invalid arguments status and error value
 */
static int
is_submit_burst_invalid(struct IMB_MGR *mb_mgr, const struct IMB_JOB *job, const int test_num,
                        int expected_errnum)
{
        IMB_JOB *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint32_t i, completed_jobs, n_jobs = IMB_MAX_BURST_SIZE;
        int err;

        while (IMB_GET_NEXT_BURST(mb_mgr, n_jobs, jobs) < n_jobs)
                IMB_FLUSH_BURST(mb_mgr, n_jobs, jobs);

        /* duplicate job to test */
        for (i = 0; i < n_jobs; i++)
                *jobs[i] = *job;

        /* submit the job for processing */
        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, jobs);
        if (completed_jobs != 0) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected number of completed jobs: %u\n",
                       __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                       (int) job->cipher_direction, (int) job->cipher_mode, completed_jobs);
        }

        err = imb_get_errno(mb_mgr);
        if (err != expected_errnum) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected error: %s\n",
                       __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                       (int) job->cipher_direction, (int) job->cipher_mode, imb_get_strerror(err));
                return 0;
        }

        if (jobs[0]->status != IMB_STATUS_INVALID_ARGS) {
                printf("%s : test %d, hash_alg %d, chain_order %d, "
                       "cipher_dir %d, cipher_mode %d : "
                       "unexpected job->status %d != IMB_STATUS_INVALID_ARGS\n",
                       __func__, test_num, (int) job->hash_alg, (int) job->chain_order,
                       (int) job->cipher_direction, (int) job->cipher_mode, (int) job->status);
                return 0;
        }

        return 1;
}

/*
 * @brief Performs BURST API behavior tests
 */
static int
test_burst_api(struct IMB_MGR *mb_mgr)
{
        struct IMB_JOB *job = NULL, *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint32_t i, completed_jobs, n_jobs = IMB_MAX_BURST_SIZE;
        struct IMB_JOB **null_jobs = NULL;
        int err;

        printf("SUBMIT_BURST() API behavior test:\n");

        /* ======== test 1 : NULL pointer to jobs array */

        if (mb_mgr->features & IMB_FEATURE_SAFE_PARAM) {
                completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, null_jobs);
                if (completed_jobs != 0) {
                        printf("%s: test %d, unexpected number of completed "
                               "jobs\n",
                               __func__, TEST_INVALID_BURST);
                        return 1;
                }
                print_progress();

                err = imb_get_errno(mb_mgr);
                if (err != IMB_ERR_NULL_BURST) {
                        printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                               imb_get_strerror(err));
                        return 1;
                }
                print_progress();

                /* ======== test 2 : NULL jobs array  */

                completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, jobs);
                if (completed_jobs != 0) {
                        printf("%s: test %d, unexpected number of completed "
                               "jobs\n",
                               __func__, TEST_INVALID_BURST);
                        return 1;
                }
                print_progress();

                err = imb_get_errno(mb_mgr);
                if (err != IMB_ERR_NULL_JOB) {
                        printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                               imb_get_strerror(err));
                        return 1;
                }
                print_progress();

                /* ========== test 3: invalid burst size */

                completed_jobs = IMB_SUBMIT_BURST(mb_mgr, IMB_MAX_BURST_SIZE + 1, jobs);
                if (completed_jobs != 0) {
                        printf("%s: test %d, unexpected number of completed "
                               "jobs\n",
                               __func__, TEST_INVALID_BURST);
                        return 1;
                }
                print_progress();

                err = imb_get_errno(mb_mgr);
                if (err != IMB_ERR_BURST_SIZE) {
                        printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                               imb_get_strerror(err));
                        return 1;
                }
                print_progress();
        }

        /* ======== test 4 : invalid job order */

        while (IMB_GET_NEXT_BURST(mb_mgr, n_jobs, jobs) < n_jobs)
                IMB_FLUSH_BURST(mb_mgr, n_jobs, jobs);

        /* fill in valid jobs */
        for (i = 0; i < n_jobs; i++) {
                job = jobs[i];
                fill_in_job(job, IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, IMB_AUTH_NULL,
                            IMB_ORDER_CIPHER_HASH, NULL, NULL);
                imb_set_session(mb_mgr, job);
        }

        /* set invalid job order */
        jobs[n_jobs / 2] = jobs[n_jobs - 1];

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, jobs);
        if (completed_jobs != 0) {
                printf("%s: test %d, unexpected number of completed "
                       "jobs\n",
                       __func__, TEST_INVALID_BURST);
                return 1;
        }
        print_progress();

        err = imb_get_errno(mb_mgr);
        if (err != IMB_ERR_BURST_OOO) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        /* ======== test 5 : invalid job */

        while (IMB_GET_NEXT_BURST(mb_mgr, n_jobs, jobs) < n_jobs)
                IMB_FLUSH_BURST(mb_mgr, n_jobs, jobs);

        /* fill in valid jobs */
        for (i = 0; i < n_jobs; i++) {
                job = jobs[i];
                fill_in_job(job, IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, IMB_AUTH_NULL,
                            IMB_ORDER_CIPHER_HASH, NULL, NULL);
                imb_set_session(mb_mgr, job);
        }

        /* set a single invalid field */
        jobs[n_jobs - 1]->enc_keys = NULL;

        /* no jobs should complete if any job is invalid */
        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, jobs);
        if (completed_jobs != 0) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }
        print_progress();

        err = imb_get_errno(mb_mgr);
        if (err != IMB_ERR_JOB_NULL_KEY) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        /* check invalid job returned in jobs[0] */
        if (jobs[0] != jobs[n_jobs - 1]) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                       "invalid job not returned in burst_job[0]");
                return 1;
        }

        if (!quiet_mode)
                printf("\n");

        /* ======== test 6: full job queue wrapping around */

        struct IMB_JOB *burst_jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint32_t num_jobs = 0;

        /* ensure all jobs flushed */
        while (IMB_FLUSH_BURST(mb_mgr, IMB_MAX_BURST_SIZE, burst_jobs) != 0)
                ;

        if (IMB_QUEUE_SIZE(mb_mgr) != 0) {
                printf("%s: test %d, unexpected number of jobs in queue\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }

        /* get first 128 jobs from job queue */
        num_jobs = IMB_GET_NEXT_BURST(mb_mgr, IMB_MAX_BURST_SIZE, burst_jobs);
        if (num_jobs != IMB_MAX_BURST_SIZE) {
                printf("%s: test %d, unexpected number of burst jobs\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }

        /* fill in valid jobs */
        for (i = 0; i < num_jobs; i++) {
                job = burst_jobs[i];
                fill_in_job(job, IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, IMB_AUTH_NULL,
                            IMB_ORDER_CIPHER_HASH, NULL, NULL);
                imb_set_session(mb_mgr, job);
        }

        /* use large buffer for first (earliest) job */
        const size_t LG_BUFFER_SIZE = 1024 * 16;
        uint8_t *large_buffer = malloc(LG_BUFFER_SIZE);

        if (large_buffer == NULL) {
                printf("Failed to allocate large buffer\n");
                return 1;
        }

        burst_jobs[0]->msg_len_to_cipher_in_bytes = LG_BUFFER_SIZE;
        burst_jobs[0]->src = large_buffer;
        burst_jobs[0]->dst = large_buffer;

        /* no jobs should complete since earliest will not be fully processed */
        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, burst_jobs);
        if (completed_jobs != 0) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        /* ensure correct number of jobs in queue */
        if (IMB_QUEUE_SIZE(mb_mgr) != num_jobs) {
                printf("%s: test %d, unexpected number of jobs in queue\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        /* ensure that mbr_mgr job buffer was not marked as "empty" in the process */
        if (mb_mgr->earliest_job == -1) {
                printf("%s: test %d, job buffer unexpectedly marked 'empty'\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        /* get last 128 jobs from job queue */
        num_jobs = IMB_GET_NEXT_BURST(mb_mgr, IMB_MAX_BURST_SIZE, burst_jobs);
        if (num_jobs != IMB_MAX_BURST_SIZE) {
                printf("%s: test %d, unexpected number of burst jobs\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        /* fill in valid jobs */
        for (i = 0; i < num_jobs; i++) {
                job = burst_jobs[i];
                fill_in_job(job, IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, IMB_AUTH_NULL,
                            IMB_ORDER_CIPHER_HASH, NULL, NULL);
                imb_set_session(mb_mgr, job);
        }

        /* fill queue to capacity and force flushing number of jobs submitted  */
        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, burst_jobs);
        if (completed_jobs != num_jobs) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        /* ensure correct number of jobs remain in queue after forced flush */
        if (IMB_QUEUE_SIZE(mb_mgr) != (IMB_MAX_JOBS - num_jobs)) {
                printf("%s: test %d, unexpected number of jobs in queue\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        /* ensure that mbr_mgr job buffer not marked as "empty" */
        if (mb_mgr->earliest_job == -1) {
                printf("%s: test %d, job buffer unexpectedly NOT marked 'empty'\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        /* flush second set of burst jobs  */
        completed_jobs = IMB_FLUSH_BURST(mb_mgr, IMB_MAX_BURST_SIZE, burst_jobs);
        if (completed_jobs != IMB_MAX_BURST_SIZE) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                free(large_buffer);
                return 1;
        }

        free(large_buffer);

        /* 0 jobs in queue after flush */
        if (IMB_QUEUE_SIZE(mb_mgr) != 0) {
                printf("%s: test %d, unexpected number of jobs in queue\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }

        /* ensure that mbr_mgr job buffer WAS marked as "empty" */
        if (mb_mgr->earliest_job != -1) {
                printf("%s: test %d, job buffer unexpectedly NOT marked 'empty'\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }

        print_progress();

        if ((mb_mgr->features & IMB_FEATURE_SAFE_PARAM) == 0)
                return 0;

        printf("GET_NEXT_BURST() API behavior test:\n");

        /* ======== test 7 : NULL pointer to burst job array */

        completed_jobs = IMB_GET_NEXT_BURST(mb_mgr, n_jobs, null_jobs);
        if (completed_jobs != 0) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }
        print_progress();

        err = imb_get_errno(mb_mgr);
        if (err != IMB_ERR_NULL_BURST) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        /* ======== test 8 : Invalid burst size */

        completed_jobs = IMB_GET_NEXT_BURST(mb_mgr, IMB_MAX_BURST_SIZE + 1, jobs);
        if (completed_jobs != 0) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }
        print_progress();

        err = imb_get_errno(mb_mgr);
        if (err != IMB_ERR_BURST_SIZE) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();
        if (!quiet_mode)
                printf("\n");

        printf("FLUSH_BURST() API behavior test:\n");

        completed_jobs = IMB_FLUSH_BURST(mb_mgr, n_jobs, null_jobs);
        if (completed_jobs != 0) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }
        print_progress();

        err = imb_get_errno(mb_mgr);
        if (err != IMB_ERR_NULL_BURST) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        /* ======== test 9 : invalid suite_id */

        while (IMB_GET_NEXT_BURST(mb_mgr, n_jobs, jobs) < n_jobs)
                IMB_FLUSH_BURST(mb_mgr, n_jobs, jobs);

        /* fill in valid jobs */
        for (i = 0; i < n_jobs; i++) {
                job = jobs[i];
                fill_in_job(job, IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, IMB_AUTH_NULL,
                            IMB_ORDER_CIPHER_HASH, NULL, NULL);

                if (i == (n_jobs - 1))
                        memset(job->suite_id, 0, sizeof(job->suite_id)); /* bad suite_id */
                else
                        imb_set_session(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, jobs);
        if (completed_jobs != 0) {
                printf("%s: test %d, unexpected number of completed "
                       "jobs\n",
                       __func__, TEST_INVALID_BURST);
                return 1;
        }
        print_progress();

        err = imb_get_errno(mb_mgr);
        if (err != IMB_ERR_BURST_SUITE_ID) {
                printf("%s: test %d, unexpected error: %s\n", __func__, TEST_INVALID_BURST,
                       imb_get_strerror(err));
                return 1;
        }
        print_progress();

        /* ======== test 10 : session_id */

        while (IMB_GET_NEXT_BURST(mb_mgr, n_jobs, jobs) < n_jobs)
                IMB_FLUSH_BURST(mb_mgr, n_jobs, jobs);

        /* fill in valid jobs */
        for (i = 0; i < n_jobs; i++) {
                job = jobs[i];
                fill_in_job(job, IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, IMB_AUTH_HMAC_SHA_256,
                            IMB_ORDER_CIPHER_HASH, NULL, NULL);
                if (i > 0) {
                        /*
                         * Check if each call to session ID for the same cipher suite gives
                         * different ID.
                         */
                        imb_set_session(mb_mgr, job);
                        if (job->session_id == jobs[i - 1]->session_id) {
                                printf("%s: test %d, unexpected/duplicate session_id value\n",
                                       __func__, TEST_INVALID_BURST);
                                return 1;
                        }
                } else {
                        /* NULL MB MGR pointer */
                        imb_set_session(NULL, job);
                        err = imb_get_errno(mb_mgr);
                        if (err != IMB_ERR_NULL_MBMGR) {
                                printf("%s: test %d, unexpected error: %s\n", __func__,
                                       TEST_INVALID_BURST, imb_get_strerror(err));
                                return 1;
                        }
                        print_progress();

                        /* NULL JOB pointer */
                        imb_set_session(mb_mgr, NULL);
                        err = imb_get_errno(mb_mgr);
                        if (err != IMB_ERR_NULL_JOB) {
                                printf("%s: test %d, unexpected error: %s\n", __func__,
                                       TEST_INVALID_BURST, imb_get_strerror(err));
                                return 1;
                        }
                        print_progress();

                        /* correct call at the end */
                        imb_set_session(mb_mgr, job);
                        err = imb_get_errno(mb_mgr);
                        if (err != 0) {
                                printf("%s: test %d, unexpected error: %s\n", __func__,
                                       TEST_INVALID_BURST, imb_get_strerror(err));
                                return 1;
                        }
                }
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, jobs);
        completed_jobs += IMB_FLUSH_BURST(mb_mgr, n_jobs, jobs);
        if (completed_jobs != n_jobs) {
                printf("%s: test %d, unexpected number of completed jobs\n", __func__,
                       TEST_INVALID_BURST);
                return 1;
        }
        print_progress();

        /* ======== end */

        if (!quiet_mode)
                printf("\n");

        return 0;
}

/*
 * @brief Checks for AEAD algorithms
 */
static int
check_aead(IMB_HASH_ALG hash, IMB_CIPHER_MODE cipher)
{
        if (hash == IMB_AUTH_CHACHA20_POLY1305 || hash == IMB_AUTH_CHACHA20_POLY1305_SGL ||
            hash == IMB_AUTH_DOCSIS_CRC32 || hash == IMB_AUTH_GCM_SGL ||
            hash == IMB_AUTH_AES_GMAC || hash == IMB_AUTH_AES_CCM || hash == IMB_AUTH_SNOW_V_AEAD ||
            hash == IMB_AUTH_PON_CRC_BIP)
                return 1;

        if (cipher == IMB_CIPHER_CHACHA20_POLY1305 || cipher == IMB_CIPHER_CHACHA20_POLY1305_SGL ||
            cipher == IMB_CIPHER_DOCSIS_SEC_BPI || cipher == IMB_CIPHER_GCM_SGL ||
            cipher == IMB_CIPHER_GCM || cipher == IMB_CIPHER_CCM ||
            cipher == IMB_CIPHER_SNOW_V_AEAD || cipher == IMB_CIPHER_PON_AES_CNTR)
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
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {
                                if (hash == IMB_AUTH_NULL || hash == IMB_AUTH_CUSTOM)
                                        continue;

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms
                                 */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx,
                                            &gcm_ctx);
                                template_job.src = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job, TEST_AUTH_SRC_NULL,
                                                       IMB_ERR_JOB_NULL_SRC))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_AUTH_SRC_NULL,
                                                             IMB_ERR_JOB_NULL_SRC))
                                        return 1;
                                print_progress();
                        }

        /*
         * AUTH_TAG_OUTPUT = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {
                                if (hash == IMB_AUTH_NULL || hash == IMB_AUTH_CUSTOM)
                                        continue;

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx,
                                            &gcm_ctx);
                                template_job.auth_tag_output = NULL;
                                if (hash == IMB_AUTH_GCM_SGL)
                                        template_job.sgl_state = IMB_SGL_COMPLETE;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_AUTH_AUTH_TAG_OUTPUT_NULL,
                                                       IMB_ERR_JOB_NULL_AUTH))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_AUTH_AUTH_TAG_OUTPUT_NULL,
                                                             IMB_ERR_JOB_NULL_AUTH))
                                        return 1;
                                print_progress();
                        }

        /*
         * AUTH_TAG_OUTPUT_LEN = 0 test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {
                                if (hash == IMB_AUTH_NULL || hash == IMB_AUTH_CUSTOM)
                                        continue;

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx,
                                            &gcm_ctx);
                                template_job.auth_tag_output_len_in_bytes = 0;
                                if (hash == IMB_AUTH_GCM_SGL)
                                        template_job.sgl_state = IMB_SGL_COMPLETE;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_AUTH_TAG_OUTPUT_LEN_ZERO,
                                                       IMB_ERR_JOB_AUTH_TAG_LEN))
                                        return 1;
                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_AUTH_TAG_OUTPUT_LEN_ZERO,
                                                             IMB_ERR_JOB_AUTH_TAG_LEN))
                                        return 1;
                                print_progress();
                        }

        /*
         * AUTH_MSG_LEN > MAX
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {
                                /* skip algorithms with no max length limit */
                                if (hash == IMB_AUTH_NULL || hash == IMB_AUTH_CUSTOM ||
                                    hash == IMB_AUTH_PON_CRC_BIP || hash == IMB_AUTH_AES_GMAC ||
                                    hash == IMB_AUTH_AES_GMAC_128 ||
                                    hash == IMB_AUTH_AES_GMAC_192 ||
                                    hash == IMB_AUTH_AES_GMAC_256 || hash == IMB_AUTH_SNOW_V_AEAD ||
                                    hash == IMB_AUTH_CRC32_ETHERNET_FCS ||
                                    hash == IMB_AUTH_CRC32_SCTP ||
                                    hash == IMB_AUTH_CRC32_WIMAX_OFDMA_DATA ||
                                    hash == IMB_AUTH_CRC24_LTE_A || hash == IMB_AUTH_CRC24_LTE_B ||
                                    hash == IMB_AUTH_CRC16_X25 || hash == IMB_AUTH_CRC16_FP_DATA ||
                                    hash == IMB_AUTH_CRC11_FP_HEADER ||
                                    hash == IMB_AUTH_CRC10_IUUP_DATA ||
                                    hash == IMB_AUTH_CRC8_WIMAX_OFDMA_HCS ||
                                    hash == IMB_AUTH_CRC7_FP_HEADER ||
                                    hash == IMB_AUTH_CRC6_IUUP_HEADER ||
                                    hash == IMB_AUTH_POLY1305 || hash == IMB_AUTH_GHASH ||
                                    hash == IMB_AUTH_SM3 || hash == IMB_AUTH_HMAC_SM3)
                                        continue;

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx,
                                            &gcm_ctx);

                                switch (hash) {
                                case IMB_AUTH_ZUC_EIA3_BITLEN:
                                case IMB_AUTH_ZUC256_EIA3_BITLEN:
                                        /* (2^32) - 32 is max */
                                        template_job.msg_len_to_hash_in_bytes = ((1ULL << 32) - 31);
                                        break;
                                case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                                        /* (2^32) is max */
                                        template_job.msg_len_to_hash_in_bits = ((1ULL << 32) + 1);
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
                                        template_job.msg_len_to_hash_in_bytes = ((1 << 16) - 1);
                                        break;
                                }
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_AUTH_MSG_LEN_GT_MAX,
                                                       IMB_ERR_JOB_AUTH_LEN))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_AUTH_MSG_LEN_GT_MAX,
                                                             IMB_ERR_JOB_AUTH_LEN))
                                        return 1;
                                print_progress();
                        }

        /*
         * AUTH_MSG_LEN = 0
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {

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
                                case IMB_AUTH_HMAC_SM3:
                                case IMB_AUTH_MD5:
                                case IMB_AUTH_KASUMI_UIA1:
                                        fill_in_job(&template_job, cipher, dir, hash, order,
                                                    &chacha_ctx, &gcm_ctx);
                                        template_job.msg_len_to_hash_in_bytes = 0;
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

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_AUTH_MSG_LEN_ZERO,
                                                             IMB_ERR_JOB_AUTH_LEN))
                                        return 1;
                                print_progress();
                        }

        /*
         * Invalid auth IV length test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {
                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                                /*
                                 * Set invalid IV lengths
                                 * for relevant algos
                                 */
                                switch (hash) {
                                        /* GMAC IVs must be not be 0 bytes */
                                case IMB_AUTH_AES_GMAC_128:
                                case IMB_AUTH_AES_GMAC_192:
                                case IMB_AUTH_AES_GMAC_256:
                                        job->u.GMAC.iv_len_in_bytes = 0;
                                        break;
                                default:
                                        /*
                                         * Skip other algos
                                         */
                                        continue;
                                }
                                if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_IV_LEN,
                                                       IMB_ERR_JOB_IV_LEN))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_IV_LEN,
                                                             IMB_ERR_JOB_IV_LEN))
                                        return 1;
                                print_progress();
                        }

        /*
         * Invalid HMAC IPAD & OPAD
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {
                                IMB_JOB *job = &template_job;
                                int skip = 1;

                                switch (hash) {
                                case IMB_AUTH_HMAC_SHA_1:
                                case IMB_AUTH_HMAC_SHA_224:
                                case IMB_AUTH_HMAC_SHA_256:
                                case IMB_AUTH_HMAC_SHA_384:
                                case IMB_AUTH_HMAC_SHA_512:
                                case IMB_AUTH_HMAC_SM3:
                                case IMB_AUTH_MD5:
                                        skip = 0;
                                        break;
                                default:
                                        break;
                                }

                                if (skip)
                                        continue;

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                                job->u.HMAC._hashed_auth_key_xor_ipad = NULL;

                                const int err_ipad = IMB_ERR_JOB_NULL_HMAC_IPAD;

                                if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_HMAC_IPAD,
                                                       err_ipad))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_HMAC_IPAD,
                                                             err_ipad))
                                        return 1;
                                print_progress();

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                                job->u.HMAC._hashed_auth_key_xor_opad = NULL;

                                const int err_opad = IMB_ERR_JOB_NULL_HMAC_OPAD;

                                if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_HMAC_OPAD,
                                                       err_opad))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_HMAC_OPAD,
                                                             err_opad))
                                        return 1;
                                print_progress();
                        }

        /*
         * Invalid XCBC key parameters
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        IMB_JOB *job = &template_job;

                        hash = IMB_AUTH_AES_XCBC;

                        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                        job->u.XCBC._k1_expanded = NULL;
                        if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_XCBC_K1_EXP,
                                               IMB_ERR_JOB_NULL_XCBC_K1_EXP))
                                return 1;

                        imb_set_session(mb_mgr, job);
                        if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_XCBC_K1_EXP,
                                                     IMB_ERR_JOB_NULL_XCBC_K1_EXP))
                                return 1;
                        print_progress();

                        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                        job->u.XCBC._k2 = NULL;
                        if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_XCBC_K2,
                                               IMB_ERR_JOB_NULL_XCBC_K2))
                                return 1;

                        imb_set_session(mb_mgr, job);
                        if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_XCBC_K2,
                                                     IMB_ERR_JOB_NULL_XCBC_K2))
                                return 1;
                        print_progress();

                        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                        job->u.XCBC._k3 = NULL;
                        if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_XCBC_K3,
                                               IMB_ERR_JOB_NULL_XCBC_K3))
                                return 1;
                        imb_set_session(mb_mgr, job);
                        if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_XCBC_K3,
                                                     IMB_ERR_JOB_NULL_XCBC_K3))
                                return 1;
                        print_progress();
                }

        /*
         * Invalid GHASH parameters
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        IMB_JOB *job = &template_job;

                        hash = IMB_AUTH_GHASH;

                        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                        job->u.GHASH._key = NULL;
                        if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_GHASH_KEY,
                                               IMB_ERR_JOB_NULL_AUTH_KEY))
                                return 1;

                        imb_set_session(mb_mgr, job);
                        if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_GHASH_KEY,
                                                     IMB_ERR_JOB_NULL_AUTH_KEY))
                                return 1;
                        print_progress();

                        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                        job->u.GHASH._init_tag = NULL;
                        if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_GHASH_INIT_TAG,
                                               IMB_ERR_JOB_NULL_GHASH_INIT_TAG))
                                return 1;

                        imb_set_session(mb_mgr, job);
                        if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_GHASH_INIT_TAG,
                                                     IMB_ERR_JOB_NULL_GHASH_INIT_TAG))
                                return 1;
                        print_progress();
                }

        /*
         * Invalid GMAC parameters
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        for (hash = IMB_AUTH_AES_GMAC_128; hash <= IMB_AUTH_AES_GMAC_256; hash++) {
                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                                job->u.GMAC._key = NULL;

                                if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_GMAC_KEY,
                                                       IMB_ERR_JOB_NULL_AUTH_KEY))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_GMAC_KEY,
                                                             IMB_ERR_JOB_NULL_AUTH_KEY))
                                        return 1;
                                print_progress();

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                                job->u.GMAC._iv = NULL;
                                if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_NULL_GMAC_IV,
                                                       IMB_ERR_JOB_NULL_IV))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_NULL_GMAC_IV,
                                                             IMB_ERR_JOB_NULL_IV))
                                        return 1;
                                print_progress();

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);
                                job->u.GMAC.iv_len_in_bytes = 0;
                                if (!is_submit_invalid(mb_mgr, job, TEST_AUTH_GMAC_IV_LEN,
                                                       IMB_ERR_JOB_IV_LEN))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_AUTH_GMAC_IV_LEN,
                                                             IMB_ERR_JOB_IV_LEN))
                                        return 1;
                                print_progress();
                        }
                }

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        if (!quiet_mode)
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
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL || cipher == IMB_CIPHER_CUSTOM)
                                        continue;

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx,
                                            &gcm_ctx);
                                template_job.src = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job, TEST_CIPH_SRC_NULL,
                                                       IMB_ERR_JOB_NULL_SRC))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_CIPH_SRC_NULL,
                                                             IMB_ERR_JOB_NULL_SRC))
                                        return 1;
                                print_progress();
                        }

        /*
         * DST = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL || cipher == IMB_CIPHER_CUSTOM)
                                        continue;

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx,
                                            &gcm_ctx);
                                template_job.dst = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job, TEST_CIPH_DST_NULL,
                                                       IMB_ERR_JOB_NULL_DST))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_CIPH_DST_NULL,
                                                             IMB_ERR_JOB_NULL_DST))
                                        return 1;
                                print_progress();
                        }

        /*
         * IV = NULL test
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL || cipher == IMB_CIPHER_CUSTOM)
                                        continue;

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                /* Skip AES-ECB, as it doesn't use any IV */
                                if (cipher == IMB_CIPHER_ECB || cipher == IMB_CIPHER_SM4_ECB)
                                        continue;

                                fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx,
                                            &gcm_ctx);
                                template_job.iv = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job, TEST_CIPH_IV_NULL,
                                                       IMB_ERR_JOB_NULL_IV))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_CIPH_IV_NULL,
                                                             IMB_ERR_JOB_NULL_IV))
                                        return 1;
                                print_progress();
                        }
        /*
         * CIPHER_DIR = Invalid dir
         */
        for (dir = 0; dir <= 10; dir++) {
                /* skip valid directions */
                if (dir == IMB_DIR_ENCRYPT || dir == IMB_DIR_DECRYPT)
                        continue;

                for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {

                        if (cipher == IMB_CIPHER_NULL || cipher == IMB_CIPHER_CUSTOM)
                                continue;

                        /*
                         * Skip cipher algorithms belonging to AEAD
                         * algorithms, as the test is for cipher
                         * only algorithms */
                        if (check_aead(hash, cipher))
                                continue;

                        order = IMB_ORDER_CIPHER_HASH;

                        fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

                        if (!is_submit_invalid(mb_mgr, &template_job, TEST_CIPH_DIR,
                                               IMB_ERR_JOB_CIPH_DIR))
                                return 1;

                        imb_set_session(mb_mgr, &template_job);
                        if (!is_submit_burst_invalid(mb_mgr, &template_job, TEST_CIPH_DIR,
                                                     IMB_ERR_JOB_CIPH_DIR))
                                return 1;
                        print_progress();
                }
        }

        /* ======== (encrypt test)
         * AES_ENC_KEY_EXPANDED = NULL
         * AES_DEC_KEY_EXPANDED = NULL
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                        fill_in_job(&template_job, cipher, IMB_DIR_ENCRYPT, hash, order,
                                    &chacha_ctx, &gcm_ctx);

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

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_CIPH_ENC_KEY_NULL,
                                                             IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                break;
                        }
                        print_progress();
                }

        /* ======== (decrypt test)
         * AES_ENC_KEY_EXPANDED = NULL
         * AES_DEC_KEY_EXPANDED = NULL
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                        /*
                         * Skip cipher algorithms belonging to AEAD
                         * algorithms, as the test is for cipher
                         * only algorithms */
                        if (check_aead(hash, cipher))
                                continue;

                        fill_in_job(&template_job, cipher, IMB_DIR_DECRYPT, hash, order,
                                    &chacha_ctx, &gcm_ctx);
                        switch (cipher) {
                        case IMB_CIPHER_GCM:
                        case IMB_CIPHER_SM4_CBC:
                        case IMB_CIPHER_CBC:
                        case IMB_CIPHER_CBCS_1_9:
                        case IMB_CIPHER_DES:
                        case IMB_CIPHER_DES3:
                        case IMB_CIPHER_DOCSIS_DES:
                        case IMB_CIPHER_SM4_ECB:
                        case IMB_CIPHER_ECB:
                                template_job.dec_keys = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_DEC_KEY_NULL,
                                                       IMB_ERR_JOB_NULL_KEY))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_CIPH_DEC_KEY_NULL,
                                                             IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                break;
                        case IMB_CIPHER_CNTR:
                        case IMB_CIPHER_CNTR_BITLEN:
                        case IMB_CIPHER_CCM:
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

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
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

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_CIPH_DEC_KEY_NULL,
                                                             IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                template_job.enc_keys = template_job.dec_keys;
                                template_job.dec_keys = NULL;
                                if (!is_submit_invalid(mb_mgr, &template_job,
                                                       TEST_CIPH_DEC_KEY_NULL,
                                                       IMB_ERR_JOB_NULL_KEY))
                                        return 1;

                                imb_set_session(mb_mgr, &template_job);
                                if (!is_submit_burst_invalid(mb_mgr, &template_job,
                                                             TEST_CIPH_DEC_KEY_NULL,
                                                             IMB_ERR_JOB_NULL_KEY))
                                        return 1;
                                break;
                        case IMB_CIPHER_NULL:
                        case IMB_CIPHER_CUSTOM:
                        default:
                                break;
                        }
                        print_progress();
                }

        /*
         * CIPHER_MSG_LEN = 0
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL || cipher == IMB_CIPHER_CUSTOM)
                                        continue;

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

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
                                        if (!is_submit_invalid(mb_mgr, job, TEST_CIPH_MSG_LEN_ZERO,
                                                               IMB_ERR_JOB_CIPH_LEN))
                                                return 1;

                                        imb_set_session(mb_mgr, job);
                                        if (!is_submit_burst_invalid(mb_mgr, job,
                                                                     TEST_CIPH_MSG_LEN_ZERO,
                                                                     IMB_ERR_JOB_CIPH_LEN))
                                                return 1;
                                }
                                print_progress();
                        }

        /*
         * CIPHER_MSG_LEN > MAX
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                                if (cipher == IMB_CIPHER_NULL || cipher == IMB_CIPHER_CUSTOM)
                                        continue;

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms */
                                if (check_aead(hash, cipher))
                                        continue;

                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

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
                                        job->msg_len_to_cipher_in_bits = ((1ULL << 32));
                                        break;
                                case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                                        /* max is 20000 bits */
                                        job->msg_len_to_cipher_in_bits = 20008;
                                        break;
                                case IMB_CIPHER_CBCS_1_9:
                                        /* max is 2^60 bytes */
                                        job->msg_len_to_cipher_in_bytes = ((1ULL << 60) + 1);
                                        break;
                                case IMB_CIPHER_CHACHA20:
                                        /* Chacha20 limit (2^32 - 1) x 64 */
                                        job->msg_len_to_cipher_in_bytes = ((1ULL << 38) - 64) + 1;
                                        break;
                                default:
                                        /* most MB max len is 2^16 - 2 */
                                        job->msg_len_to_cipher_in_bytes = ((1 << 16) - 1);
                                        break;
                                }
                                if (!is_submit_invalid(mb_mgr, job, TEST_CIPH_MSG_LEN_GT_MAX,
                                                       IMB_ERR_JOB_CIPH_LEN))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_CIPH_MSG_LEN_GT_MAX,
                                                             IMB_ERR_JOB_CIPH_LEN))
                                        return 1;

                                print_progress();
                        }

        /*
         * Invalid cipher IV length tests
         */
        const struct invalid_cipher_iv_params {
                IMB_CIPHER_MODE cipher_mode;
                uint64_t invalid_iv_len;
        } invalid_iv_lens[] = {
                /* IVs must be 16 bytes */
                { IMB_CIPHER_SM4_CBC, 15 },
                { IMB_CIPHER_SM4_CBC, 17 },
                { IMB_CIPHER_CBC, 15 },
                { IMB_CIPHER_CBC, 17 },
                { IMB_CIPHER_CBCS_1_9, 15 },
                { IMB_CIPHER_CBCS_1_9, 17 },
                { IMB_CIPHER_DOCSIS_SEC_BPI, 15 },
                { IMB_CIPHER_DOCSIS_SEC_BPI, 17 },
                { IMB_CIPHER_CNTR_BITLEN, 15 },
                { IMB_CIPHER_CNTR_BITLEN, 17 },
                { IMB_CIPHER_PON_AES_CNTR, 15 },
                { IMB_CIPHER_PON_AES_CNTR, 17 },
                { IMB_CIPHER_SNOW3G_UEA2_BITLEN, 15 },
                { IMB_CIPHER_SNOW3G_UEA2_BITLEN, 17 },
                { IMB_CIPHER_SNOW_V_AEAD, 15 },
                { IMB_CIPHER_SNOW_V_AEAD, 17 },
                { IMB_CIPHER_SNOW_V, 15 },
                { IMB_CIPHER_SNOW_V, 17 },
                /* CCM IV must be 13 to 7 bytes */
                { IMB_CIPHER_CCM, 6 },
                { IMB_CIPHER_CCM, 14 },
                /* CNTR IV must be 12 or 16 bytes */
                { IMB_CIPHER_CNTR, 11 },
                { IMB_CIPHER_CNTR, 14 },
                { IMB_CIPHER_CNTR, 17 },
                /* DES IVs must be 8 bytes */
                { IMB_CIPHER_DES, 7 },
                { IMB_CIPHER_DES, 9 },
                { IMB_CIPHER_DOCSIS_DES, 7 },
                { IMB_CIPHER_DOCSIS_DES, 9 },
                { IMB_CIPHER_DES3, 7 },
                { IMB_CIPHER_DES3, 9 },
                /* KASUMI IV must be 8 bytes */
                { IMB_CIPHER_KASUMI_UEA1_BITLEN, 7 },
                { IMB_CIPHER_KASUMI_UEA1_BITLEN, 9 },
                /* ZUC IV must be 16, 23 or 25 bytes */
                { IMB_CIPHER_ZUC_EEA3, 15 },
                { IMB_CIPHER_ZUC_EEA3, 17 },
                { IMB_CIPHER_ZUC_EEA3, 22 },
                { IMB_CIPHER_ZUC_EEA3, 24 },
                { IMB_CIPHER_ZUC_EEA3, 26 },
                /* CHACHA20 IVs must be 12 bytes */
                { IMB_CIPHER_CHACHA20, 15 },
                { IMB_CIPHER_CHACHA20, 17 },
                { IMB_CIPHER_CHACHA20_POLY1305, 15 },
                { IMB_CIPHER_CHACHA20_POLY1305, 17 },
                { IMB_CIPHER_CHACHA20_POLY1305_SGL, 15 },
                { IMB_CIPHER_CHACHA20_POLY1305_SGL, 17 },
                /* GCM IVs must be not be 0 bytes */
                { IMB_CIPHER_GCM, 0 },
                { IMB_CIPHER_GCM_SGL, 0 },
        };

        dir = IMB_DIR_ENCRYPT;

        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++) {
                uint64_t key_len;

                for (key_len = IMB_KEY_128_BYTES; key_len <= IMB_KEY_256_BYTES; key_len += 8) {
                        uint32_t i;

                        for (i = 0; i < DIM(invalid_iv_lens); i++) {
                                IMB_JOB *job = &template_job;

                                /* set cipher mode */
                                cipher = invalid_iv_lens[i].cipher_mode;

                                /* set up job fields */
                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

                                /* set key length */
                                job->key_len_in_bytes = key_len;

                                /* set invalid IV length */
                                job->iv_len_in_bytes = invalid_iv_lens[i].invalid_iv_len;

                                /* skip some key lengths for specific ciphers */
                                switch (cipher) {
                                case IMB_CIPHER_CCM:
                                case IMB_CIPHER_DOCSIS_SEC_BPI:
                                case IMB_CIPHER_ZUC_EEA3:
                                        if (key_len == IMB_KEY_192_BYTES)
                                                continue;
                                        break;
                                case IMB_CIPHER_DES:
                                case IMB_CIPHER_DOCSIS_DES:
                                        /* override default key len for DES */
                                        job->key_len_in_bytes = 8;
                                        break;
                                case IMB_CIPHER_DES3:
                                        if (key_len != IMB_KEY_192_BYTES)
                                                continue;
                                        break;
                                case IMB_CIPHER_CHACHA20:
                                case IMB_CIPHER_CHACHA20_POLY1305:
                                case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                                case IMB_CIPHER_SNOW_V_AEAD:
                                case IMB_CIPHER_SNOW_V:
                                        if (key_len != IMB_KEY_256_BYTES)
                                                continue;
                                        break;
                                case IMB_CIPHER_CBCS_1_9:
                                case IMB_CIPHER_PON_AES_CNTR:
                                case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                                case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                                        if (key_len != IMB_KEY_128_BYTES)
                                                continue;
                                        break;
                                default:
                                        break;
                                }

                                if (!is_submit_invalid(mb_mgr, job, TEST_CIPH_IV_LEN,
                                                       IMB_ERR_JOB_IV_LEN))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_CIPH_IV_LEN,
                                                             IMB_ERR_JOB_IV_LEN))
                                        return 1;
                                print_progress();
                        }
                }
        }

        /*
         * OTHER MISC TESTS
         */

        /* CBCS NULL NEXT IV TEST */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        cipher = IMB_CIPHER_CBCS_1_9;

                        /*
                         * Skip cipher algorithms belonging to AEAD
                         * algorithms, as the test is for cipher
                         * only algorithms */
                        if (check_aead(hash, cipher))
                                continue;

                        IMB_JOB *job = &template_job;

                        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

                        job->cipher_fields.CBCS.next_iv = NULL;

                        if (!is_submit_invalid(mb_mgr, job, TEST_CIPH_NEXT_IV_NULL,
                                               IMB_ERR_JOB_NULL_NEXT_IV))
                                return 1;

                        imb_set_session(mb_mgr, job);
                        if (!is_submit_burst_invalid(mb_mgr, job, TEST_CIPH_NEXT_IV_NULL,
                                                     IMB_ERR_JOB_NULL_NEXT_IV))
                                return 1;
                        print_progress();
                }

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Tests misc invalid settings
 */
static int
test_job_invalid_misc_args(struct IMB_MGR *mb_mgr)
{
        IMB_HASH_ALG hash;
        IMB_CIPHER_DIRECTION dir;
        IMB_CIPHER_MODE cipher;
        IMB_CHAIN_ORDER order;
        struct IMB_JOB template_job;
        struct chacha20_poly1305_context_data chacha_ctx;
        struct gcm_context_data gcm_ctx;

        printf("Invalid MISC JOB arguments test:\n");

        /* prep */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        /*
         * Invalid PLI for PON
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        cipher = IMB_CIPHER_PON_AES_CNTR;
                        hash = IMB_AUTH_PON_CRC_BIP;

                        /*
                         * XGEM header is set to all 1s in fill_in_job()
                         * This will result in an invalid PLI field
                         */
                        fill_in_job(&template_job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

                        /* Set msg len to ensure PLI error */
                        template_job.msg_len_to_cipher_in_bytes = 8;

                        if (!is_submit_invalid(mb_mgr, &template_job, TEST_INVALID_PON_PLI,
                                               IMB_ERR_JOB_PON_PLI))
                                return 1;

                        imb_set_session(mb_mgr, &template_job);

                        if (!is_submit_burst_invalid(mb_mgr, &template_job, TEST_INVALID_PON_PLI,
                                                     IMB_ERR_JOB_PON_PLI))
                                return 1;
                        print_progress();
                }

        /*
         * AEAD MSG_LEN > MAX
         */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++)
                        for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                                /* reset hash alg */
                                hash = IMB_AUTH_NULL;

                                /* Skip non AEAD algorithms */
                                if (!check_aead(hash, cipher))
                                        continue;

                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

                                switch (cipher) {
                                        /* skip algos with no max limit */
                                case IMB_CIPHER_PON_AES_CNTR:
                                case IMB_CIPHER_SNOW_V_AEAD:
                                case IMB_CIPHER_CHACHA20_POLY1305:
                                case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                                case IMB_CIPHER_CCM:
                                        continue;
                                case IMB_CIPHER_GCM:
                                case IMB_CIPHER_GCM_SGL:
                                        /* must be < ((2^39) - 256)  bytes */
                                        job->msg_len_to_cipher_in_bytes = ((1ULL << 39) - 256);
                                        break;
                                default:
                                        continue;
                                }
                                if (!is_submit_invalid(mb_mgr, job, TEST_CIPH_MSG_LEN_GT_MAX,
                                                       IMB_ERR_JOB_CIPH_LEN))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_CIPH_MSG_LEN_GT_MAX,
                                                             IMB_ERR_JOB_CIPH_LEN))
                                        return 1;

                                print_progress();
                        }

        /*
         * INVALID SGL PARAMS
         */
        IMB_CIPHER_MODE sgl_cipher_modes[] = { IMB_CIPHER_GCM_SGL,
                                               IMB_CIPHER_CHACHA20_POLY1305_SGL };
        IMB_HASH_ALG sgl_auth_modes[] = { IMB_AUTH_GCM_SGL, IMB_AUTH_CHACHA20_POLY1305_SGL };

        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++)
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        for (unsigned i = 0; i < DIM(sgl_cipher_modes); i++) {
                                cipher = sgl_cipher_modes[i];
                                hash = sgl_auth_modes[i];

                                IMB_JOB *job = &template_job;

                                fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

                                /* Invalid SGL state */
                                job->sgl_state = IMB_SGL_ALL + 1;

                                if (!is_submit_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                       IMB_ERR_JOB_SGL_STATE))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                             IMB_ERR_JOB_SGL_STATE))
                                        return 1;

                                /* Invalid SGL segments */
                                job->sgl_state = IMB_SGL_ALL;
                                job->num_sgl_io_segs = 2;
                                job->sgl_io_segs = NULL;

                                if (!is_submit_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                       IMB_ERR_JOB_NULL_SRC))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                             IMB_ERR_JOB_NULL_SRC))
                                        return 1;

                                /* Null source in non-zero length segment */
                                struct IMB_SGL_IOV segs[2];
                                uint8_t buf[50];

                                job->sgl_io_segs = segs;

                                segs[0].in = NULL;
                                segs[0].out = buf;
                                segs[0].len = 50;

                                if (!is_submit_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                       IMB_ERR_JOB_NULL_SRC))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                             IMB_ERR_JOB_NULL_SRC))
                                        return 1;

                                segs[0].in = buf;
                                segs[0].out = NULL;

                                if (!is_submit_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                       IMB_ERR_JOB_NULL_DST))
                                        return 1;

                                imb_set_session(mb_mgr, job);
                                if (!is_submit_burst_invalid(mb_mgr, job, TEST_INVALID_JOB,
                                                             IMB_ERR_JOB_NULL_DST))
                                        return 1;

                                /* Null destination in non-zero length segment */
                                print_progress();
                        }
                }

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * Submits a job and, if job is not returned straight away,
 * MB_MGR function pointers are reset, but OOO manager contents
 * should remain, so after a flush, a job should be retrieved.
 */
static int
submit_reset_check_job(struct IMB_MGR *mb_mgr, IMB_CIPHER_MODE cipher, IMB_CIPHER_DIRECTION dir,
                       IMB_HASH_ALG hash, IMB_CHAIN_ORDER order)
{
        struct IMB_JOB *job, *next_job;
        struct chacha20_poly1305_context_data chacha_ctx;
        struct gcm_context_data gcm_ctx;

        job = IMB_GET_NEXT_JOB(mb_mgr);

        fill_in_job(job, cipher, dir, hash, order, &chacha_ctx, &gcm_ctx);

        next_job = IMB_SUBMIT_JOB(mb_mgr);

        if (next_job == NULL) {
                /*
                 * If job is not retrieved, could mean
                 * that the job is still in OOO managers
                 * (due to a multi-buffer implementation)
                 */

                /*
                 * Reset MB MGR pointers first and
                 * check if job can be retrieved later
                 */
                if (imb_set_pointers_mb_mgr(mb_mgr, mb_mgr->flags, 0) == NULL)
                        return 1;

                next_job = IMB_FLUSH_JOB(mb_mgr);
                if (next_job == NULL) {
                        printf("Could not retrieve any job\n");
                        return 1;
                }
        }

        if (next_job->status != IMB_STATUS_COMPLETED) {
                printf("Returned job's status is not completed\n");
                printf("cipher = %d\n", cipher);
                printf("imb errno = %d (%s)\n", mb_mgr->imb_errno,
                       imb_get_strerror(mb_mgr->imb_errno));
                exit(0);
        }

        return 0;
}

/*
 * @brief Test reset API
 */
static int
test_reset_api(struct IMB_MGR *mb_mgr)
{
        IMB_HASH_ALG hash;
        IMB_CIPHER_DIRECTION dir;
        IMB_CIPHER_MODE cipher;
        IMB_CHAIN_ORDER order;

        printf("Reset API test:\n");

        /* prep */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        /* Reset MB MGR pointers first */
        if (imb_set_pointers_mb_mgr(mb_mgr, mb_mgr->flags, 0) == NULL)
                return 1;

        /* Loop around all cipher algorithms */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++) {
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        for (cipher = IMB_CIPHER_CBC; cipher < IMB_CIPHER_NUM; cipher++) {
                                /* Cipher only */
                                hash = IMB_AUTH_NULL;

                                /*
                                 * Skip cipher algorithms belonging to AEAD
                                 * algorithms, as the test is for cipher
                                 * only algorithms
                                 */
                                if (check_aead(hash, cipher))
                                        continue;

                                if (submit_reset_check_job(mb_mgr, cipher, dir, hash, order) > 0)
                                        return 1;
                        }
                }
        }
        /* Loop around all authentication algorithms */
        for (order = IMB_ORDER_CIPHER_HASH; order <= IMB_ORDER_HASH_CIPHER; order++) {
                for (dir = IMB_DIR_ENCRYPT; dir <= IMB_DIR_DECRYPT; dir++) {
                        for (hash = IMB_AUTH_HMAC_SHA_1; hash < IMB_AUTH_NUM; hash++) {
                                if (hash == IMB_AUTH_NULL || hash == IMB_AUTH_CUSTOM)
                                        continue;

                                /* Hash only */
                                cipher = IMB_CIPHER_NULL;

                                /*
                                 * Skip hash algorithms belonging to AEAD
                                 * algorithms, as the test is for authentication
                                 * only algorithms
                                 */
                                if (check_aead(hash, cipher))
                                        continue;

                                if (submit_reset_check_job(mb_mgr, cipher, dir, hash, order) > 0)
                                        return 1;
                        }
                }
        }

        /* Test AEAD algorithms */
        const IMB_HASH_ALG aead_hash_algos[] = { IMB_AUTH_AES_GMAC,          IMB_AUTH_AES_CCM,
                                                 IMB_AUTH_CHACHA20_POLY1305, IMB_AUTH_PON_CRC_BIP,
                                                 IMB_AUTH_DOCSIS_CRC32,      IMB_AUTH_SNOW_V_AEAD };
        const IMB_CIPHER_MODE aead_cipher_algos[] = { IMB_CIPHER_GCM,
                                                      IMB_CIPHER_CCM,
                                                      IMB_CIPHER_CHACHA20_POLY1305,
                                                      IMB_CIPHER_PON_AES_CNTR,
                                                      IMB_CIPHER_DOCSIS_SEC_BPI,
                                                      IMB_CIPHER_SNOW_V_AEAD };

        unsigned int i;

        for (i = 0; i < DIM(aead_cipher_algos); i++) {
                hash = aead_hash_algos[i];
                cipher = aead_cipher_algos[i];

                if (cipher == IMB_CIPHER_CCM || cipher == IMB_CIPHER_DOCSIS_SEC_BPI)
                        order = IMB_ORDER_HASH_CIPHER;
                else
                        order = IMB_ORDER_CIPHER_HASH;
                dir = IMB_DIR_ENCRYPT;

                if (submit_reset_check_job(mb_mgr, cipher, dir, hash, order) > 0)
                        return 1;

                if (cipher == IMB_CIPHER_CCM || cipher == IMB_CIPHER_DOCSIS_SEC_BPI)
                        order = IMB_ORDER_CIPHER_HASH;
                else
                        order = IMB_ORDER_HASH_CIPHER;
                dir = IMB_DIR_DECRYPT;

                if (submit_reset_check_job(mb_mgr, cipher, dir, hash, order) > 0)
                        return 1;
        }

        /* clean up */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Test Self-Test API
 */
struct self_test_context {
        int is_corrupt;

        int to_corrupt;
        int corrupted_counter;

        int error_counter;

        int start_counter;
        int corrupt_counter;
        int fail_counter;
        int pass_counter;
        int all_counter;
};

static int
self_test_callback(void *arg, const IMB_SELF_TEST_CALLBACK_DATA *data)
{
        struct self_test_context *p = (struct self_test_context *) arg;
        const char *phase = "";

        IMB_ASSERT(p != NULL);
        if (p == NULL)
                return 1;

        p->all_counter++;

        IMB_ASSERT(data != NULL);
        if (data == NULL) {
                p->error_counter++;
                return 1;
        }

        if (data->phase != NULL)
                phase = data->phase;
        else
                p->error_counter++;

        if (strcmp(phase, IMB_SELF_TEST_PHASE_START) == 0) {
                p->start_counter++;
                if (data->type == NULL || data->descr == NULL)
                        p->error_counter++;
        } else if (strcmp(phase, IMB_SELF_TEST_PHASE_CORRUPT) == 0) {
                p->corrupt_counter++;
                if (p->is_corrupt) {
                        /*
                         * if this is corrupt test then what value
                         * should be returned (0 -> corrupt)
                         */
                        if (p->to_corrupt > p->corrupted_counter) {
                                p->corrupted_counter++;
                                return 0;
                        }
                }
                return 1;
        } else if (strcmp(phase, IMB_SELF_TEST_PHASE_PASS) == 0) {
                p->pass_counter++;
        } else if (strcmp(phase, IMB_SELF_TEST_PHASE_FAIL) == 0) {
                p->fail_counter++;
        } else {
                p->error_counter++;
        }

        return 1;
}

static int
self_test_check_context(const struct self_test_context *p)
{
        if (p->start_counter != p->corrupt_counter)
                return 0;

        if (p->start_counter != (p->fail_counter + p->pass_counter))
                return 0;

        if (p->all_counter !=
            (p->fail_counter + p->pass_counter + p->corrupt_counter + p->start_counter))
                return 0;

        if (p->is_corrupt) {
                if (p->fail_counter != p->corrupted_counter)
                        return 0;
                if (p->to_corrupt != p->corrupted_counter)
                        return 0;
        }

        if (p->error_counter != 0)
                return 0;
        return 1;
}

static void
self_test_set_context(struct self_test_context *p, const int is_corrupt, const int to_corrupt)
{
        memset(p, 0, sizeof(*p));
        p->is_corrupt = is_corrupt;
        p->to_corrupt = to_corrupt;
}

static int
test_self_test_api(struct IMB_MGR *mb_mgr)
{
        printf("Self-Test API test:\n");

        /* invalid get test scenarios */
        imb_self_test_cb_t cb_fn;
        void *cb_arg;

        if (imb_self_test_get_cb(NULL, &cb_fn, &cb_arg) != IMB_ERR_NULL_MBMGR)
                return 1;

        if (imb_self_test_get_cb(mb_mgr, NULL, &cb_arg) != EINVAL)
                return 1;

        if (imb_self_test_get_cb(mb_mgr, &cb_fn, NULL) != EINVAL)
                return 1;

        if (imb_self_test_get_cb(mb_mgr, NULL, NULL) != EINVAL)
                return 1;

        if (imb_self_test_get_cb(NULL, NULL, NULL) != IMB_ERR_NULL_MBMGR)
                return 1;

        if (!quiet_mode)
                printf(".");

        /* invalid set test scenarios */
        if (imb_self_test_set_cb(NULL, NULL, NULL) != IMB_ERR_NULL_MBMGR)
                return 1;

        if (!quiet_mode)
                printf(".");

        /* valid test scenarios */
        imb_self_test_cb_t cb_fn1, cb_fn2;
        void *cb_arg1, *cb_arg2;

        /* check if get called twice returns same values */
        if (imb_self_test_get_cb(mb_mgr, &cb_fn1, &cb_arg1) != 0)
                return 1;

        if (imb_self_test_get_cb(mb_mgr, &cb_fn2, &cb_arg2) != 0)
                return 1;

        if ((cb_fn1 != cb_fn2) || (cb_arg1 != cb_arg2))
                return 1;

        if (!quiet_mode)
                printf(".");

        /* check set followed by get */
        if (imb_self_test_set_cb(mb_mgr, self_test_callback, mb_mgr) != 0)
                return 1;

        if (imb_self_test_get_cb(mb_mgr, &cb_fn1, &cb_arg1) != 0)
                return 1;

        if ((cb_fn1 != self_test_callback) || (cb_arg1 != (void *) mb_mgr))
                return 1;

        /* check set with NULL argument */
        if (imb_self_test_set_cb(mb_mgr, self_test_callback, NULL) != 0)
                return 1;

        if (imb_self_test_get_cb(mb_mgr, &cb_fn1, &cb_arg1) != 0)
                return 1;

        if ((cb_fn1 != self_test_callback) || (cb_arg1 != NULL))
                return 1;

        if (!quiet_mode)
                printf(".");

        /* check set with NULL callback */
        if (imb_self_test_set_cb(mb_mgr, NULL, mb_mgr) != 0)
                return 1;

        if (imb_self_test_get_cb(mb_mgr, &cb_fn1, &cb_arg1) != 0)
                return 1;

        if ((cb_fn1 != NULL) || (cb_arg1 != (void *) mb_mgr))
                return 1;

        if (!quiet_mode)
                printf(".");

        /* check callback set followed by init - success scenario */
        struct IMB_MGR *t_mgr = alloc_mb_mgr(0);
        struct self_test_context test_ctx;
        IMB_ARCH arch;

        if (t_mgr == NULL)
                return 1;

        self_test_set_context(&test_ctx, 0, 0);

        if (imb_self_test_set_cb(t_mgr, self_test_callback, &test_ctx) != 0) {
                free_mb_mgr(t_mgr);
                return 1;
        }

        init_mb_mgr_auto(t_mgr, &arch);
        free_mb_mgr(t_mgr);

        if (self_test_check_context(&test_ctx) == 0)
                return 1;

        const int num_tests = test_ctx.start_counter;

        if (!quiet_mode)
                printf(".");

        /* check callback set followed by init - fail scenario */
        for (int i = 0; i <= num_tests; i++) {
                t_mgr = alloc_mb_mgr(0);

                if (t_mgr == NULL)
                        return 1;

                self_test_set_context(&test_ctx, 1, i);

                if (imb_self_test_set_cb(t_mgr, self_test_callback, &test_ctx) != 0) {
                        free_mb_mgr(t_mgr);
                        return 1;
                }

                init_mb_mgr_auto(t_mgr, &arch);
                free_mb_mgr(t_mgr);

                if (self_test_check_context(&test_ctx) == 0)
                        return 1;

                if (!quiet_mode)
                        printf(".");
        }

        /* check callback set, set NULL and then init - callback disabled */

        if (!quiet_mode)
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

        errors += test_burst_api(mb_mgr);
        run++;

        errors += test_job_invalid_mac_args(mb_mgr);
        run++;

        errors += test_job_invalid_cipher_args(mb_mgr);
        run++;

        errors += test_job_invalid_misc_args(mb_mgr);
        run++;

        errors += test_reset_api(mb_mgr);
        run++;

        errors += test_self_test_api(mb_mgr);
        run++;

        test_suite_update(&ctx, run - errors, errors);

        test_suite_end(&ctx);

        return errors;
}
