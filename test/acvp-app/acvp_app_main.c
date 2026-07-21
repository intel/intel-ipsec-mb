/**********************************************************************
  Copyright(c) 2022-2026, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/
#include <stdio.h>
#include <string.h>

#include <acvp/acvp.h>
#include <intel-ipsec-mb.h>

#include "utils.h"

#define LIB_VER(a, b, c) (((a) << 16) + ((b) << 8) + (c))

/* Available from libacvp 2.1.0 */
#ifdef ACVP_LIBRARY_VERSION_MAJOR
#define INT_ACVP_LIB_VER_NUM                                                                       \
        LIB_VER(ACVP_LIBRARY_VERSION_MAJOR, ACVP_LIBRARY_VERSION_MINOR, ACVP_LIBRARY_VERSION_PATCH)
#else
/* Assume version 2.0.0 (minimum required for this app) */
#define INT_ACVP_LIB_VER_NUM LIB_VER(2, 0, 0)
#endif

#if INT_ACVP_LIB_VER_NUM >= LIB_VER(2, 2, 0)
#include <ml_dsa/ml_dsa_internal_api.h>
#endif

#define MAX_TAG_LENGTH 16

static ACVP_RESULT
logger(char *msg, ACVP_LOG_LVL level)
{
        if (level == ACVP_LOG_LVL_ERR)
                printf("[ERROR] ");
        else if (level == ACVP_LOG_LVL_WARN)
                printf("[WARNING] ");

        printf("%s", msg);
        return ACVP_SUCCESS;
}

IMB_MGR *mb_mgr = NULL;
int verbose = 0;
int direct_api = 0; /* job API by default */

static int
aes_cbc_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);
        static uint8_t next_iv[16];

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        switch (tc->key_len) {
        case 128:
                IMB_AES_KEYEXP_128(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 192:
                IMB_AES_KEYEXP_192(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 256:
                IMB_AES_KEYEXP_256(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len >> 3;
        job->cipher_mode = IMB_CIPHER_CBC;
        job->hash_alg = IMB_AUTH_NULL;
        /*
         * If Monte-carlo test, use the IV from the ciphertext of
         * the previous iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT && tc->mct_index != 0)
                job->iv = next_iv;
        else
                job->iv = tc->iv;

        job->iv_len_in_bytes = tc->iv_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->enc_keys = enc_keys;
        job->dec_keys = dec_keys;

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = tc->pt;
                job->dst = tc->ct;
                job->msg_len_to_cipher_in_bytes = tc->pt_len;
                tc->ct_len = tc->pt_len;
        } else /* DECRYPT */ {
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = tc->ct;
                job->dst = tc->pt;
                job->msg_len_to_cipher_in_bytes = tc->ct_len;
                tc->pt_len = tc->ct_len;
        }
        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        /*
         * If Monte-carlo test, copy the ciphertext for
         * the IV of the next iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT)
                memcpy(next_iv, tc->ct, 16);

        return ACVP_SUCCESS;
}

static int
aes_cfb_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);
        static uint8_t next_iv[16];

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        switch (tc->key_len) {
        case 128:
                IMB_AES_KEYEXP_128(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 192:
                IMB_AES_KEYEXP_192(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 256:
                IMB_AES_KEYEXP_256(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len >> 3;
        job->cipher_mode = IMB_CIPHER_CFB;
        job->hash_alg = IMB_AUTH_NULL;
        /*
         * If Monte-carlo test, use the IV from the ciphertext of
         * the previous iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT && tc->mct_index != 0)
                job->iv = next_iv;
        else
                job->iv = tc->iv;

        job->iv_len_in_bytes = tc->iv_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->enc_keys = enc_keys;
        job->dec_keys = enc_keys;

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = tc->pt;
                job->dst = tc->ct;
                job->msg_len_to_cipher_in_bytes = tc->pt_len;
                tc->ct_len = tc->pt_len;
        } else /* DECRYPT */ {
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = tc->ct;
                job->dst = tc->pt;
                job->msg_len_to_cipher_in_bytes = tc->ct_len;
                tc->pt_len = tc->ct_len;
        }
        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        /*
         * If Monte-carlo test, copy the ciphertext for
         * the IV of the next iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT)
                memcpy(next_iv, tc->ct, 16);

        return ACVP_SUCCESS;
}

static int
aes_ecb_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        switch (tc->key_len) {
        case 128:
                IMB_AES_KEYEXP_128(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 192:
                IMB_AES_KEYEXP_192(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 256:
                IMB_AES_KEYEXP_256(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len >> 3;
        job->cipher_mode = IMB_CIPHER_ECB;
        job->hash_alg = IMB_AUTH_NULL;
        job->cipher_start_src_offset_in_bytes = 0;
        job->enc_keys = enc_keys;
        job->dec_keys = dec_keys;

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = tc->pt;
                job->dst = tc->ct;
                job->msg_len_to_cipher_in_bytes = tc->pt_len;
                tc->ct_len = tc->pt_len;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        const int err = imb_get_errno(mb_mgr);
                        const char *err_str = imb_get_strerror(err);

                        fprintf(stderr, "Invalid encrypt job: %s\n", err_str);
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        } else /* DECRYPT */ {
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = tc->ct;
                job->dst = tc->pt;
                job->msg_len_to_cipher_in_bytes = tc->ct_len;
                tc->pt_len = tc->ct_len;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        const int err = imb_get_errno(mb_mgr);
                        const char *err_str = imb_get_strerror(err);

                        fprintf(stderr, "Invalid decrypt job: %s\n", err_str);
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }

        return ACVP_SUCCESS;
}

static int
aes_gcm_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        struct gcm_key_data key;
        struct gcm_context_data ctx;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        switch (tc->key_len) {
        case 128:
                IMB_AES128_GCM_PRE(mb_mgr, tc->key, &key);
                break;
        case 192:
                IMB_AES192_GCM_PRE(mb_mgr, tc->key, &key);
                break;
        case 256:
                IMB_AES256_GCM_PRE(mb_mgr, tc->key, &key);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (direct_api != 1) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->key_len_in_bytes = tc->key_len >> 3;
                job->cipher_mode = IMB_CIPHER_GCM;
                job->hash_alg = IMB_AUTH_AES_GMAC;
                job->u.GCM.aad = tc->aad;
                job->u.GCM.aad_len_in_bytes = tc->aad_len;
                job->enc_keys = &key;
                job->dec_keys = &key;
                job->iv = tc->iv;
                job->iv_len_in_bytes = tc->iv_len;
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output_len_in_bytes = tc->tag_len;
        }

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                if (direct_api == 1) {
                        switch (tc->key_len) {
                        case 128:
                                imb_aes128_gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len, tc->aad,
                                                           tc->aad_len, mb_mgr);
                                imb_aes128_gcm_enc_update(&key, &ctx, tc->ct, tc->pt, tc->pt_len,
                                                          mb_mgr);
                                imb_aes128_gcm_enc_finalize(&key, &ctx, tc->tag, tc->tag_len,
                                                            mb_mgr);
                                break;
                        case 192:
                                imb_aes192_gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len, tc->aad,
                                                           tc->aad_len, mb_mgr);
                                imb_aes192_gcm_enc_update(&key, &ctx, tc->ct, tc->pt, tc->pt_len,
                                                          mb_mgr);
                                imb_aes192_gcm_enc_finalize(&key, &ctx, tc->tag, tc->tag_len,
                                                            mb_mgr);
                                break;
                        case 256:
                                imb_aes256_gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len, tc->aad,
                                                           tc->aad_len, mb_mgr);
                                imb_aes256_gcm_enc_update(&key, &ctx, tc->ct, tc->pt, tc->pt_len,
                                                          mb_mgr);
                                imb_aes256_gcm_enc_finalize(&key, &ctx, tc->tag, tc->tag_len,
                                                            mb_mgr);
                                break;
                        default:
                                fprintf(stderr, "Unsupported AES key length\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                } else {
                        job->src = tc->pt;
                        job->dst = tc->ct;
                        job->msg_len_to_cipher_in_bytes = tc->pt_len;
                        job->msg_len_to_hash_in_bytes = tc->pt_len;
                        job->cipher_direction = IMB_DIR_ENCRYPT;
                        job->chain_order = IMB_ORDER_CIPHER_HASH;
                        job->auth_tag_output = tc->tag;

                        job = IMB_SUBMIT_JOB(mb_mgr);
                        if (job == NULL)
                                job = IMB_FLUSH_JOB(mb_mgr);
                        if (job->status != IMB_STATUS_COMPLETED) {
                                fprintf(stderr, "Invalid job\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                }
        } else /* DECRYPT */ {
                uint8_t res_tag[MAX_TAG_LENGTH] = { 0 };

                if (direct_api == 1) {
                        switch (tc->key_len) {
                        case 128:
                                imb_aes128_gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len, tc->aad,
                                                           tc->aad_len, mb_mgr);
                                imb_aes128_gcm_dec_update(&key, &ctx, tc->pt, tc->ct, tc->ct_len,
                                                          mb_mgr);
                                imb_aes128_gcm_dec_finalize(&key, &ctx, res_tag, tc->tag_len,
                                                            mb_mgr);
                                break;
                        case 192:
                                imb_aes192_gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len, tc->aad,
                                                           tc->aad_len, mb_mgr);
                                imb_aes192_gcm_dec_update(&key, &ctx, tc->pt, tc->ct, tc->ct_len,
                                                          mb_mgr);
                                imb_aes192_gcm_dec_finalize(&key, &ctx, res_tag, tc->tag_len,
                                                            mb_mgr);
                                break;
                        case 256:
                                imb_aes256_gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len, tc->aad,
                                                           tc->aad_len, mb_mgr);
                                imb_aes256_gcm_dec_update(&key, &ctx, tc->pt, tc->ct, tc->ct_len,
                                                          mb_mgr);
                                imb_aes256_gcm_dec_finalize(&key, &ctx, res_tag, tc->tag_len,
                                                            mb_mgr);
                                break;
                        default:
                                fprintf(stderr, "Unsupported AES key length\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                } else {
                        job->src = tc->ct;
                        job->dst = tc->pt;
                        job->msg_len_to_cipher_in_bytes = tc->ct_len;
                        job->msg_len_to_hash_in_bytes = tc->ct_len;
                        job->cipher_direction = IMB_DIR_DECRYPT;
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
                        job->auth_tag_output = res_tag;

                        job = IMB_SUBMIT_JOB(mb_mgr);
                        if (job == NULL)
                                job = IMB_FLUSH_JOB(mb_mgr);
                        if (job->status != IMB_STATUS_COMPLETED) {
                                fprintf(stderr, "Invalid job\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                }
                if (memcmp(res_tag, tc->tag, tc->tag_len) != 0) {
                        if (verbose) {
                                hexdump(stdout, "result tag: ", res_tag, tc->tag_len);
                                hexdump(stdout, "reference tag: ", tc->tag, tc->tag_len);
                                fprintf(stderr, "Tag mismatch\n");
                        }
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        return ACVP_SUCCESS;
}

static int
aes_gmac_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        struct gcm_key_data key;
        struct gcm_context_data ctx;
        IMB_HASH_ALG hash_mode;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        switch (tc->key_len) {
        case 128:
                IMB_AES128_GCM_PRE(mb_mgr, tc->key, &key);
                hash_mode = IMB_AUTH_AES_GMAC_128;
                break;
        case 192:
                IMB_AES192_GCM_PRE(mb_mgr, tc->key, &key);
                hash_mode = IMB_AUTH_AES_GMAC_192;
                break;
        case 256:
                IMB_AES256_GCM_PRE(mb_mgr, tc->key, &key);
                hash_mode = IMB_AUTH_AES_GMAC_256;
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (direct_api != 1) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->key_len_in_bytes = tc->key_len >> 3;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = hash_mode;
                job->u.GMAC._iv = tc->iv;
                job->u.GMAC.iv_len_in_bytes = tc->iv_len;
                job->u.GMAC._key = &key;
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output_len_in_bytes = tc->tag_len;
        }

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                if (direct_api == 1) {
                        switch (tc->key_len) {
                        case 128:
                                imb_aes128_gmac_init(&key, &ctx, tc->iv, tc->iv_len, mb_mgr);
                                imb_aes128_gmac_update(&key, &ctx, tc->aad, tc->aad_len, mb_mgr);
                                imb_aes128_gmac_finalize(&key, &ctx, tc->tag, tc->tag_len, mb_mgr);
                                break;
                        case 192:
                                imb_aes192_gmac_init(&key, &ctx, tc->iv, tc->iv_len, mb_mgr);
                                imb_aes192_gmac_update(&key, &ctx, tc->aad, tc->aad_len, mb_mgr);
                                imb_aes192_gmac_finalize(&key, &ctx, tc->tag, tc->tag_len, mb_mgr);
                                break;
                        case 256:
                                imb_aes256_gmac_init(&key, &ctx, tc->iv, tc->iv_len, mb_mgr);
                                imb_aes256_gmac_update(&key, &ctx, tc->aad, tc->aad_len, mb_mgr);
                                imb_aes256_gmac_finalize(&key, &ctx, tc->tag, tc->tag_len, mb_mgr);
                                break;
                        default:
                                fprintf(stderr, "Unsupported AES key length\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                } else {
                        job->src = tc->aad;
                        job->msg_len_to_hash_in_bytes = tc->aad_len;
                        job->cipher_direction = IMB_DIR_ENCRYPT;
                        job->chain_order = IMB_ORDER_CIPHER_HASH;
                        job->auth_tag_output = tc->tag;

                        job = IMB_SUBMIT_JOB(mb_mgr);
                        if (job == NULL)
                                job = IMB_FLUSH_JOB(mb_mgr);
                        if (job->status != IMB_STATUS_COMPLETED) {
                                fprintf(stderr, "Invalid job\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                }
        } else /* DECRYPT */ {
                uint8_t res_tag[MAX_TAG_LENGTH] = { 0 };

                if (direct_api == 1) {
                        switch (tc->key_len) {
                        case 128:
                                imb_aes128_gmac_init(&key, &ctx, tc->iv, tc->iv_len, mb_mgr);
                                imb_aes128_gmac_update(&key, &ctx, tc->aad, tc->aad_len, mb_mgr);
                                imb_aes128_gmac_finalize(&key, &ctx, res_tag, tc->tag_len, mb_mgr);
                                break;
                        case 192:
                                imb_aes192_gmac_init(&key, &ctx, tc->iv, tc->iv_len, mb_mgr);
                                imb_aes192_gmac_update(&key, &ctx, tc->aad, tc->aad_len, mb_mgr);
                                imb_aes192_gmac_finalize(&key, &ctx, res_tag, tc->tag_len, mb_mgr);
                                break;
                        case 256:
                                imb_aes256_gmac_init(&key, &ctx, tc->iv, tc->iv_len, mb_mgr);
                                imb_aes256_gmac_update(&key, &ctx, tc->aad, tc->aad_len, mb_mgr);
                                imb_aes256_gmac_finalize(&key, &ctx, res_tag, tc->tag_len, mb_mgr);
                                break;
                        default:
                                fprintf(stderr, "Unsupported AES key length\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                } else {
                        job->src = tc->aad;
                        job->msg_len_to_hash_in_bytes = tc->aad_len;
                        job->cipher_direction = IMB_DIR_DECRYPT;
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
                        job->auth_tag_output = res_tag;

                        job = IMB_SUBMIT_JOB(mb_mgr);
                        if (job == NULL)
                                job = IMB_FLUSH_JOB(mb_mgr);
                        if (job->status != IMB_STATUS_COMPLETED) {
                                fprintf(stderr, "Invalid job\n");
                                return ACVP_CRYPTO_MODULE_FAIL;
                        }
                }
                if (memcmp(res_tag, tc->tag, tc->tag_len) != 0) {
                        if (verbose) {
                                hexdump(stdout, "result tag: ", res_tag, tc->tag_len);
                                hexdump(stdout, "reference tag: ", tc->tag, tc->tag_len);
                                fprintf(stderr, "Tag mismatch\n");
                        }
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        return ACVP_SUCCESS;
}

static int
aes_ctr_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        switch (tc->key_len) {
        case 128:
                IMB_AES_KEYEXP_128(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 192:
                IMB_AES_KEYEXP_192(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 256:
                IMB_AES_KEYEXP_256(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len >> 3;
        job->cipher_mode = IMB_CIPHER_CNTR;
        job->hash_alg = IMB_AUTH_NULL;

        job->iv = tc->iv;
        job->iv_len_in_bytes = tc->iv_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->enc_keys = enc_keys;
        job->dec_keys = dec_keys;

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = tc->pt;
                job->dst = tc->ct;
                job->msg_len_to_cipher_in_bytes = tc->pt_len;
                tc->ct_len = tc->pt_len;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        } else /* DECRYPT */ {
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = tc->ct;
                job->dst = tc->pt;
                job->msg_len_to_cipher_in_bytes = tc->ct_len;
                tc->pt_len = tc->ct_len;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        return ACVP_SUCCESS;
}

static int
tdes_cbc_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        static DECLARE_ALIGNED(uint64_t keys1[IMB_DES_KEY_SCHED_SIZE / sizeof(uint64_t)], 16);
        static DECLARE_ALIGNED(uint64_t keys2[IMB_DES_KEY_SCHED_SIZE / sizeof(uint64_t)], 16);
        static DECLARE_ALIGNED(uint64_t keys3[IMB_DES_KEY_SCHED_SIZE / sizeof(uint64_t)], 16);
        static const void *ks_ptr[3];
        static uint8_t next_iv[8];

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (tc->keyingOption != 1) {
                fprintf(stderr, "Unsupported keyingOption\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        /*
         * Only 3 key DES supported
         */
        if (tc->key_len != 192) {
                fprintf(stderr, "Unsupported DES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        /*
         * Only TDES CBC supported
         */
        const ACVP_SUB_TDES alg = acvp_get_tdes_alg(tc->cipher);

        if (alg == 0) {
                fprintf(stderr, "Invalid cipher value");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (alg != ACVP_SUB_TDES_CBC) {
                fprintf(stderr, "Error: Unsupported DES mode requested by ACVP server\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        /* Create key schedules */
        if (tc->test_type != ACVP_SYM_TEST_TYPE_MCT || tc->mct_index == 0) {
                /*
                 * Always create key schedules unless this is continuation of
                 * Monte Carlo inner loop.
                 * Not creating key schedules every time in MCT test
                 * improves performance.
                 */
                IMB_DES_KEYSCHED(mb_mgr, keys1, &tc->key[0]);
                IMB_DES_KEYSCHED(mb_mgr, keys2, &tc->key[8]);
                IMB_DES_KEYSCHED(mb_mgr, keys3, &tc->key[16]);
                ks_ptr[0] = keys1;
                ks_ptr[1] = keys2;
                ks_ptr[2] = keys3;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = 192 / 8;
        job->cipher_mode = IMB_CIPHER_DES3;
        job->hash_alg = IMB_AUTH_NULL;

        job->iv = tc->iv;

        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT && tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT &&
            tc->mct_index != 0)
                job->iv = next_iv;

        job->iv_len_in_bytes = tc->iv_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->enc_keys = ks_ptr;
        job->dec_keys = ks_ptr;

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = tc->pt;
                job->dst = tc->ct;
                job->msg_len_to_cipher_in_bytes = tc->pt_len;
                tc->ct_len = tc->pt_len;
        } else /* DECRYPT */ {
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = tc->ct;
                job->dst = tc->pt;
                job->msg_len_to_cipher_in_bytes = tc->ct_len;
                tc->pt_len = tc->ct_len;
        }

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        /*
         * If Monte Carlo test:
         *   encrypt/decrypt - set IV for the next outer iteration
         *   decrypt - copy the ciphertext as IV for the next inner iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
                if (tc->mct_index == ACVP_DES_MCT_INNER - 1)
                        memcpy(tc->iv_ret_after, tc->ct, 8);

                if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
                        memcpy(next_iv, tc->ct, 8);
        }

        return ACVP_SUCCESS;
}

static int
aes_ccm_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);
        uint8_t res_tag[MAX_TAG_LENGTH] = { 0 };

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        switch (tc->key_len) {
        case 128:
                IMB_AES_KEYEXP_128(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 192:
                IMB_AES_KEYEXP_192(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        case 256:
                IMB_AES_KEYEXP_256(mb_mgr, tc->key, enc_keys, dec_keys);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len >> 3;
        job->cipher_mode = IMB_CIPHER_CCM;
        job->hash_alg = IMB_AUTH_AES_CCM;

        job->iv = tc->iv;
        job->iv_len_in_bytes = tc->iv_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->enc_keys = enc_keys;
        job->dec_keys = dec_keys;
        job->auth_tag_output_len_in_bytes = tc->tag_len;
        job->u.CCM.aad = tc->aad;
        job->u.CCM.aad_len_in_bytes = tc->aad_len;

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = tc->pt;
                job->dst = tc->ct;
                job->msg_len_to_cipher_in_bytes = tc->pt_len;
                job->msg_len_to_hash_in_bytes = tc->pt_len;
                /* Auth tag must be placed at the end of the ciphertext. */
                job->auth_tag_output = tc->ct + tc->pt_len;
                tc->ct_len = tc->pt_len + tc->tag_len;
        } else /* DECRYPT */ {
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = tc->ct;
                job->dst = tc->pt;
                job->msg_len_to_hash_in_bytes = tc->ct_len;
                job->msg_len_to_cipher_in_bytes = tc->ct_len;
                job->auth_tag_output = res_tag;
                tc->pt_len = tc->ct_len;
        }

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
                /* Tag is placed at the end of the ciphertext. */
                const uint8_t *ref_tag = tc->ct + tc->ct_len;

                if (memcmp(res_tag, ref_tag, tc->tag_len) != 0) {
                        if (verbose) {
                                hexdump(stdout, "result tag: ", res_tag, tc->tag_len);
                                hexdump(stdout, "reference tag: ", ref_tag, tc->tag_len);
                                fprintf(stderr, "Tag mismatch\n");
                        }
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        return ACVP_SUCCESS;
}

static int
aes_cmac_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_CMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        uint32_t skey1[4], skey2[4];
        uint8_t res_tag[MAX_TAG_LENGTH] = { 0 };

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.cmac;

        switch (tc->key_len) {
        case 16:
                IMB_AES_KEYEXP_128(mb_mgr, tc->key, expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, expkey, skey1, skey2);
                break;
        case 32:
                IMB_AES_KEYEXP_256(mb_mgr, tc->key, expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_256(mb_mgr, expkey, skey1, skey2);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;

        if (tc->key_len == 32)
                job->hash_alg = IMB_AUTH_AES_CMAC_256;
        else
                job->hash_alg = IMB_AUTH_AES_CMAC;

        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.CMAC._key_expanded = expkey;
        job->u.CMAC._skey1 = skey1;
        job->u.CMAC._skey2 = skey2;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        job->auth_tag_output_len_in_bytes = tc->mac_len;

        if (tc->verify == 1)
                job->auth_tag_output = res_tag;
        else /* verify == 0 */
                job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (tc->verify == 1) {
                if (memcmp(res_tag, tc->mac, tc->mac_len) != 0) {
                        if (verbose) {
                                hexdump(stdout, "result tag: ", res_tag, (tc->mac_len));
                                hexdump(stdout, "reference tag: ", tc->mac, tc->mac_len);
                                fprintf(stderr, "Tag mismatch\n");
                        }
                        tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
                } else
                        tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha1_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_1, tc->key, tc->key_len, ipad_hash, opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA_1;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        /*
         * The library is optimized for 12 byte tags but can output
         * tag sizes from 4 bytes to 20 bytes.
         */
        job->auth_tag_output_len_in_bytes = tc->mac_len;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha256_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA256_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA256_DIGEST_SIZE_IN_BYTES], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_256, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA_256;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        /*
         * The library only supports 16 or 32-byte tags and therefore,
         * we are outputting 32 bytes always
         */
        job->auth_tag_output_len_in_bytes = IMB_SHA256_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha224_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA224_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA224_DIGEST_SIZE_IN_BYTES], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_224, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA_224;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        /*
         * The library only supports 14 or 28-byte tags and therefore,
         * we are outputting 28 bytes always
         */
        job->auth_tag_output_len_in_bytes = IMB_SHA224_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha384_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_384, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA_384;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        /*
         * The library only supports 24 or 48-byte tags and therefore,
         * we are outputting 48 bytes always
         */
        job->auth_tag_output_len_in_bytes = IMB_SHA384_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha512_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_512, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA_512;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        /*
         * The library only supports 32 or 64-byte tags and therefore,
         * we are outputting 64 bytes always
         */
        job->auth_tag_output_len_in_bytes = IMB_SHA512_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha3_224_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA3_224, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA3_224;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        job->auth_tag_output_len_in_bytes = tc->mac_len;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha3_256_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA3_256, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA3_256;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        job->auth_tag_output_len_in_bytes = tc->mac_len;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha3_384_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA3_384, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA3_384;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        job->auth_tag_output_len_in_bytes = tc->mac_len;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
hmac_sha3_512_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HMAC_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA3_MAX_BLOCK_SIZE], 16);

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hmac;

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA3_512, tc->key, tc->key_len, ipad_hash,
                           opad_hash);

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_HMAC_SHA3_512;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        job->auth_tag_output_len_in_bytes = tc->mac_len;
        job->auth_tag_output = tc->mac;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        return ACVP_SUCCESS;
}

static int
sha1_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        unsigned len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                m = malloc(tc->msg_len * 3);
                len = tc->msg_len * 3;

                if (m == NULL) {
                        printf("Can't allocate buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                memcpy(m, tc->m1, tc->msg_len);
                memcpy(m + tc->msg_len, tc->m2, tc->msg_len);
                memcpy(m + tc->msg_len * 2, tc->m3, tc->msg_len);
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        if (direct_api == 1) {
                IMB_SHA1(mb_mgr, m, len, tc->md);
        } else {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_SHA_1;
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->src = m;
                job->msg_len_to_hash_in_bytes = len;
                job->auth_tag_output_len_in_bytes = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
                job->auth_tag_output = tc->md;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT)
                free(m);
        tc->md_len = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha2_224_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        unsigned len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                m = malloc(tc->msg_len * 3);
                len = tc->msg_len * 3;

                if (m == NULL) {
                        printf("Can't allocate buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                memcpy(m, tc->m1, tc->msg_len);
                memcpy(m + tc->msg_len, tc->m2, tc->msg_len);
                memcpy(m + tc->msg_len * 2, tc->m3, tc->msg_len);
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        if (direct_api == 1) {
                IMB_SHA224(mb_mgr, m, len, tc->md);
        } else {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_SHA_224;
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->src = m;
                job->msg_len_to_hash_in_bytes = len;
                job->auth_tag_output_len_in_bytes = IMB_SHA224_DIGEST_SIZE_IN_BYTES;
                job->auth_tag_output = tc->md;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT)
                free(m);
        tc->md_len = IMB_SHA224_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha2_256_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        unsigned len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                m = malloc(tc->msg_len * 3);
                len = tc->msg_len * 3;

                if (m == NULL) {
                        printf("Can't allocate buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                memcpy(m, tc->m1, tc->msg_len);
                memcpy(m + tc->msg_len, tc->m2, tc->msg_len);
                memcpy(m + tc->msg_len * 2, tc->m3, tc->msg_len);
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        if (direct_api == 1) {
                IMB_SHA256(mb_mgr, m, len, tc->md);
        } else {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_SHA_256;
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->src = m;
                job->msg_len_to_hash_in_bytes = len;
                job->auth_tag_output_len_in_bytes = IMB_SHA256_DIGEST_SIZE_IN_BYTES;
                job->auth_tag_output = tc->md;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT)
                free(m);
        tc->md_len = IMB_SHA256_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha2_384_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        unsigned len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                m = malloc(tc->msg_len * 3);
                len = tc->msg_len * 3;

                if (m == NULL) {
                        printf("Can't allocate buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                memcpy(m, tc->m1, tc->msg_len);
                memcpy(m + tc->msg_len, tc->m2, tc->msg_len);
                memcpy(m + tc->msg_len * 2, tc->m3, tc->msg_len);
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        if (direct_api == 1) {
                IMB_SHA384(mb_mgr, m, len, tc->md);
        } else {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_SHA_384;
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->src = m;
                job->msg_len_to_hash_in_bytes = len;
                job->auth_tag_output_len_in_bytes = IMB_SHA384_DIGEST_SIZE_IN_BYTES;
                job->auth_tag_output = tc->md;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT)
                free(m);
        tc->md_len = IMB_SHA384_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha2_512_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        unsigned len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                m = malloc(tc->msg_len * 3);
                len = tc->msg_len * 3;

                if (m == NULL) {
                        printf("Can't allocate buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                memcpy(m, tc->m1, tc->msg_len);
                memcpy(m + tc->msg_len, tc->m2, tc->msg_len);
                memcpy(m + tc->msg_len * 2, tc->m3, tc->msg_len);
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        if (direct_api == 1) {
                IMB_SHA512(mb_mgr, m, len, tc->md);
        } else {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_SHA_512;
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->src = m;
                job->msg_len_to_hash_in_bytes = len;
                job->auth_tag_output_len_in_bytes = IMB_SHA512_DIGEST_SIZE_IN_BYTES;
                job->auth_tag_output = tc->md;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }
        if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT)
                free(m);
        tc->md_len = IMB_SHA512_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha3_224_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        uint8_t *large_data = NULL;
        uint64_t len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_LDT) {
                int num_iter = tc->exp_len / tc->msg_len;
                uint8_t *ld_idx;

                large_data = calloc(tc->exp_len, sizeof(uint8_t));
                if (large_data == NULL) {
                        printf("Can't allocate large data buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                ld_idx = large_data;

                /* concatenate message in large data buffer */
                for (int i = 0; i < num_iter; i++) {
                        memcpy(ld_idx, tc->msg, tc->msg_len);
                        ld_idx += tc->msg_len;
                }
                m = large_data;
                len = tc->exp_len;

                printf("Running SHA3-224 LDT (Long Data Test). This may take some time...\n");
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_SHA3_224;
        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->src = m;
        job->msg_len_to_hash_in_bytes = len;
        job->auth_tag_output_len_in_bytes = IMB_SHA3_224_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->md;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);

        if (large_data != NULL)
                free(large_data);

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        tc->md_len = IMB_SHA3_224_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha3_256_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        uint8_t *large_data = NULL;
        uint64_t len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_LDT) {
                int num_iter = tc->exp_len / tc->msg_len;
                uint8_t *ld_idx;

                large_data = calloc(tc->exp_len, sizeof(uint8_t));
                if (large_data == NULL) {
                        printf("Can't allocate large data buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                ld_idx = large_data;

                /* concatenate message in large data buffer */
                for (int i = 0; i < num_iter; i++) {
                        memcpy(ld_idx, tc->msg, tc->msg_len);
                        ld_idx += tc->msg_len;
                }
                m = large_data;
                len = tc->exp_len;

                printf("Running SHA3-256 LDT (Long Data Test). This may take some time...\n");
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_SHA3_256;
        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->src = m;
        job->msg_len_to_hash_in_bytes = len;
        job->auth_tag_output_len_in_bytes = IMB_SHA3_256_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->md;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);

        if (large_data != NULL)
                free(large_data);

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        tc->md_len = IMB_SHA3_256_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha3_384_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        uint8_t *large_data = NULL;
        uint64_t len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_LDT) {
                int num_iter = tc->exp_len / tc->msg_len;
                uint8_t *ld_idx;

                large_data = calloc(tc->exp_len, sizeof(uint8_t));
                if (large_data == NULL) {
                        printf("Can't allocate large data buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                ld_idx = large_data;

                /* concatenate message in large data buffer */
                for (int i = 0; i < num_iter; i++) {
                        memcpy(ld_idx, tc->msg, tc->msg_len);
                        ld_idx += tc->msg_len;
                }
                m = large_data;
                len = tc->exp_len;

                printf("Running SHA3-384 LDT (Long Data Test). This may take some time...\n");
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_SHA3_384;
        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->src = m;
        job->msg_len_to_hash_in_bytes = len;
        job->auth_tag_output_len_in_bytes = IMB_SHA3_384_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->md;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);

        if (large_data != NULL)
                free(large_data);

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        tc->md_len = IMB_SHA3_384_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
sha3_512_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;
        uint8_t *large_data = NULL;
        uint64_t len;
        uint8_t *m;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        if (tc->test_type == ACVP_HASH_TEST_TYPE_LDT) {
                int num_iter = tc->exp_len / tc->msg_len;
                uint8_t *ld_idx;

                large_data = calloc(tc->exp_len, sizeof(uint8_t));
                if (large_data == NULL) {
                        printf("Can't allocate large data buffer memory\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                ld_idx = large_data;

                /* concatenate message in large data buffer */
                for (int i = 0; i < num_iter; i++) {
                        memcpy(ld_idx, tc->msg, tc->msg_len);
                        ld_idx += tc->msg_len;
                }
                m = large_data;
                len = tc->exp_len;

                printf("Running SHA3-512 LDT (Long Data Test). This may take some time...\n");
        } else {
                m = tc->msg;
                len = tc->msg_len;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_SHA3_512;
        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->src = m;
        job->msg_len_to_hash_in_bytes = len;
        job->auth_tag_output_len_in_bytes = IMB_SHA3_512_DIGEST_SIZE_IN_BYTES;
        job->auth_tag_output = tc->md;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);

        if (large_data != NULL)
                free(large_data);

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        tc->md_len = IMB_SHA3_512_DIGEST_SIZE_IN_BYTES;
        return ACVP_SUCCESS;
}

static int
shake128_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        /*
         * For SHAKE, we need to handle variable output length.
         * If no output length is specified, default to 32 bytes.
         */
        uint32_t output_len = (tc->xof_len > 0) ? tc->xof_len : 32;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_SHAKE128;
        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        job->auth_tag_output_len_in_bytes = output_len;
        job->auth_tag_output = tc->md;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        tc->md_len = output_len;
        return ACVP_SUCCESS;
}

static int
shake256_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_HASH_TC *tc;
        IMB_JOB *job = NULL;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.hash;

        /*
         * For SHAKE, we need to handle variable output length.
         * If no output length is specified, default to 64 bytes.
         */
        uint32_t output_len = (tc->xof_len > 0) ? tc->xof_len : 64;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->hash_alg = IMB_AUTH_SHAKE256;
        job->cipher_start_src_offset_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->src = tc->msg;
        job->msg_len_to_hash_in_bytes = tc->msg_len;
        job->auth_tag_output_len_in_bytes = output_len;
        job->auth_tag_output = tc->md;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "Invalid job\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        tc->md_len = output_len;
        return ACVP_SUCCESS;
}

#if INT_ACVP_LIB_VER_NUM >= LIB_VER(2, 2, 0)

#define ML_DSA_RND_BYTES  32
#define ML_DSA_SEED_BYTES 32

struct ml_dsa_variant {
        IMB_ML_DSA_ALG alg;
        size_t pk_len;
        size_t sk_len;
        size_t sig_len;
};

static int
ml_dsa_get_variant(ACVP_ML_DSA_PARAM_SET param_set, struct ml_dsa_variant *v)
{
        switch (param_set) {
        case ACVP_ML_DSA_PARAM_SET_ML_DSA_44:
                v->alg = IMB_ML_DSA_44;
                v->pk_len = IMB_ML_DSA_44_PUBKEY_BYTES;
                v->sk_len = IMB_ML_DSA_44_PRIVKEY_BYTES;
                v->sig_len = IMB_ML_DSA_44_SIG_BYTES;
                return 0;
        case ACVP_ML_DSA_PARAM_SET_ML_DSA_65:
                v->alg = IMB_ML_DSA_65;
                v->pk_len = IMB_ML_DSA_65_PUBKEY_BYTES;
                v->sk_len = IMB_ML_DSA_65_PRIVKEY_BYTES;
                v->sig_len = IMB_ML_DSA_65_SIG_BYTES;
                return 0;
        case ACVP_ML_DSA_PARAM_SET_ML_DSA_87:
                v->alg = IMB_ML_DSA_87;
                v->pk_len = IMB_ML_DSA_87_PUBKEY_BYTES;
                v->sk_len = IMB_ML_DSA_87_PRIVKEY_BYTES;
                v->sig_len = IMB_ML_DSA_87_SIG_BYTES;
                return 0;
        default:
                return -1;
        }
}

static int
ml_dsa_keygen_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_ML_DSA_TC *tc;
        IMB_ML_DSA *handle = NULL;
        IMB_ML_DSA_KEYGEN_PARAMS keygen_params;
        struct ml_dsa_variant v;
        int ret = ACVP_CRYPTO_MODULE_FAIL;
        int imb_rc;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.ml_dsa;

        if (ml_dsa_get_variant(tc->param_set, &v) != 0) {
                fprintf(stderr, "Unsupported ML-DSA parameter set\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (tc->seed == NULL || tc->seed_len != ML_DSA_SEED_BYTES) {
                fprintf(stderr, "Invalid ML-DSA key generation seed\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (tc->pub_key == NULL || tc->secret_key == NULL) {
                fprintf(stderr, "Missing ML-DSA key output buffers\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        imb_rc = imb_ml_dsa_new(mb_mgr, v.alg, &handle);
        if (imb_rc != 0 || handle == NULL) {
                fprintf(stderr, "Could not allocate ML-DSA context\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        keygen_params.xi_32 = tc->seed;
        if (imb_ml_dsa_keypair(handle, tc->pub_key, tc->secret_key, &keygen_params) != 0) {
                fprintf(stderr, "ML-DSA key generation failed\n");
                goto exit;
        }

        tc->pub_key_len = (int) v.pk_len;
        tc->secret_key_len = (int) v.sk_len;
        ret = ACVP_SUCCESS;
exit:
        imb_ml_dsa_free(handle);
        return ret;
}

static int
ml_dsa_siggen_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_ML_DSA_TC *tc;
        IMB_ML_DSA *handle = NULL;
        struct ml_dsa_variant v;
        uint8_t rnd[ML_DSA_RND_BYTES];
        size_t sig_len = 0;
        int ret = ACVP_CRYPTO_MODULE_FAIL;
        int sign_rc;
        int imb_rc;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.ml_dsa;

        if ((tc->sig_interface == ACVP_SIG_INTERFACE_EXTERNAL && tc->is_prehash != 0) ||
            (tc->sig_interface != ACVP_SIG_INTERFACE_EXTERNAL &&
             tc->sig_interface != ACVP_SIG_INTERFACE_INTERNAL)) {
                tc->sig_len = 0;
                return ACVP_SUCCESS;
        }
        if (ml_dsa_get_variant(tc->param_set, &v) != 0) {
                fprintf(stderr, "Unsupported ML-DSA parameter set\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (tc->secret_key == NULL || (size_t) tc->secret_key_len != v.sk_len) {
                fprintf(stderr, "Invalid ML-DSA private key\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (tc->msg == NULL || tc->sig == NULL) {
                if (!tc->is_mu_external || tc->mu == NULL || tc->sig == NULL) {
                        fprintf(stderr, "Missing ML-DSA message or signature buffer\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }

        if (tc->is_deterministic) {
                memset(rnd, 0, sizeof(rnd));
        } else {
                if (tc->rnd == NULL || tc->rnd_len != (int) sizeof(rnd)) {
                        fprintf(stderr, "Invalid ML-DSA signing randomizer\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
                memcpy(rnd, tc->rnd, sizeof(rnd));
        }

        imb_rc = imb_ml_dsa_new(mb_mgr, v.alg, &handle);
        if (imb_rc != 0 || handle == NULL) {
                fprintf(stderr, "Could not allocate ML-DSA context\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (imb_ml_dsa_set_privkey(handle, tc->secret_key) != 0) {
                fprintf(stderr, "ML-DSA private key binding failed\n");
                goto exit;
        }

        if (tc->sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
                IMB_ML_DSA_SIGN_PARAMS params = { 0 };

                params.ctx = tc->context;
                params.ctx_len = (size_t) tc->context_len;
                params.rnd_32 = rnd;
                sign_rc = imb_ml_dsa_sign(handle, tc->sig, &sig_len, tc->msg, (size_t) tc->msg_len,
                                          &params);
        } else if (tc->is_mu_external) {
                IMB_ML_DSA_SIGN_PARAMS params = { 0 };

                params.rnd_32 = rnd;
                params.msg_is_mu = 1;
                sign_rc = imb_ml_dsa_sign(handle, tc->sig, &sig_len, tc->mu, (size_t) tc->mu_len,
                                          &params);
        } else {
                sign_rc = imb_ml_dsa_sign_internal(handle, tc->sig, &sig_len, tc->msg,
                                                   (size_t) tc->msg_len, rnd);
        }

        if (sign_rc != 0) {
                fprintf(stderr, "ML-DSA signature generation failed\n");
                goto exit;
        }

        tc->sig_len = (int) sig_len;
        ret = ACVP_SUCCESS;
exit:
        imb_ml_dsa_free(handle);
        return ret;
}

static int
ml_dsa_sigver_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_ML_DSA_TC *tc;
        IMB_ML_DSA *handle = NULL;
        struct ml_dsa_variant v;
        int ret = ACVP_CRYPTO_MODULE_FAIL;
        int verify_rc;
        int imb_rc;

        if (test_case == NULL)
                return ACVP_CRYPTO_MODULE_FAIL;

        tc = test_case->tc.ml_dsa;

        if ((tc->sig_interface == ACVP_SIG_INTERFACE_EXTERNAL && tc->is_prehash != 0) ||
            (tc->sig_interface != ACVP_SIG_INTERFACE_EXTERNAL &&
             tc->sig_interface != ACVP_SIG_INTERFACE_INTERNAL)) {
                tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;
                return ACVP_SUCCESS;
        }
        if (ml_dsa_get_variant(tc->param_set, &v) != 0) {
                fprintf(stderr, "Unsupported ML-DSA parameter set\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (tc->pub_key == NULL || (size_t) tc->pub_key_len != v.pk_len) {
                fprintf(stderr, "Invalid ML-DSA public key\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (tc->msg == NULL || tc->sig == NULL) {
                if (!tc->is_mu_external || tc->mu == NULL || tc->sig == NULL) {
                        fprintf(stderr, "Missing ML-DSA message or signature\n");
                        return ACVP_CRYPTO_MODULE_FAIL;
                }
        }

        imb_rc = imb_ml_dsa_new(mb_mgr, v.alg, &handle);
        if (imb_rc != 0 || handle == NULL) {
                fprintf(stderr, "Could not allocate ML-DSA context\n");
                return ACVP_CRYPTO_MODULE_FAIL;
        }

        if (imb_ml_dsa_set_pubkey(handle, tc->pub_key) != 0) {
                verify_rc = -1;
        } else if (tc->sig_interface == ACVP_SIG_INTERFACE_EXTERNAL) {
                IMB_ML_DSA_VERIFY_PARAMS params = { 0 };

                params.ctx = tc->context;
                params.ctx_len = (size_t) tc->context_len;
                verify_rc = imb_ml_dsa_verify(handle, tc->msg, (size_t) tc->msg_len, tc->sig,
                                              (size_t) tc->sig_len, &params);
        } else if (tc->is_mu_external) {
                IMB_ML_DSA_VERIFY_PARAMS params = { 0 };

                params.msg_is_mu = 1;
                verify_rc = imb_ml_dsa_verify(handle, tc->mu, (size_t) tc->mu_len, tc->sig,
                                              (size_t) tc->sig_len, &params);
        } else {
                verify_rc = imb_ml_dsa_verify_internal(handle, tc->msg, (size_t) tc->msg_len,
                                                       tc->sig, (size_t) tc->sig_len);
        }

        if (verify_rc == 0)
                tc->ver_disposition = ACVP_TEST_DISPOSITION_PASS;
        else
                tc->ver_disposition = ACVP_TEST_DISPOSITION_FAIL;

        ret = ACVP_SUCCESS;
        imb_ml_dsa_free(handle);
        return ret;
}

#endif /* INT_ACVP_LIB_VER_NUM >= LIB_VER(2, 2, 0) */

static void
usage(const char *app_name)
{
        fprintf(stderr,
                "Usage: %s --req FILENAME --resp FILENAME [opt args], "
                "where args are two or more\n"
                "--req FILENAME: request file in JSON format (required)\n"
                "--resp FILENAME: response file in JSON format (required)\n"
                "--direct-api: uses direct API instead of job API if available\n"
                "--arch ARCH: select arch to test (SSE/AVX/AVX2/AVX512)\n"
                "-h: print this message\n"
                "-v: verbose, prints extra information\n\n"
                "Example: %s --req AES-GCM-req.json --resp AES-GCM-resp.json\n",
                app_name, app_name);
}

int
main(int argc, char **argv)
{
        ACVP_RESULT acvp_ret = ACVP_SUCCESS;
        ACVP_CTX *ctx = NULL;
        char *req_filename = NULL;
        const char *resp_filename = NULL;
        int i;
        int ret = EXIT_FAILURE;
        IMB_ARCH test_arch = IMB_ARCH_NONE;

        if (argc < 2) {
                printf("At least one parameter is required\n");
                usage(argv[0]);
                return EXIT_FAILURE;
        }
        for (i = 1; i < argc; i++) {
                if (strcmp(argv[i], "--req") == 0) {
                        if (argv[i + 1] == NULL) {
                                fprintf(stderr, "Missing argument for --req\n");
                                goto exit;
                        }
                        req_filename = realpath(argv[i + 1], NULL);

                        if (req_filename == NULL) {
                                fprintf(stderr, "Request file does not exist\n");
                                goto exit;
                        }
                        i++;
                } else if (strcmp(argv[i], "--resp") == 0) {
                        if (argv[i + 1] == NULL) {
                                fprintf(stderr, "Missing argument for --resp\n");
                                goto exit;
                        }
                        resp_filename = argv[i + 1];
                        i++;
                } else if (strcmp(argv[i], "--arch") == 0) {
                        const char *arch = argv[i + 1];

                        if (arch == NULL) {
                                fprintf(stderr, "Missing argument for --arch\n");
                                goto exit;
                        }
                        if (strcmp(arch, "SSE") == 0)
                                test_arch = IMB_ARCH_SSE;
                        else if (strcmp(arch, "AVX2") == 0)
                                test_arch = IMB_ARCH_AVX2;
                        else if (strcmp(arch, "AVX512") == 0)
                                test_arch = IMB_ARCH_AVX512;
                        else if (strcmp(arch, "AVX10") == 0)
                                test_arch = IMB_ARCH_AVX10;
                        else {
                                fprintf(stderr, "Unsupported architecture\n");
                                goto exit;
                        }
                        i++;
                } else if (strcmp(argv[i], "--direct-api") == 0) {
                        direct_api = 1;
                } else if (strcmp(argv[i], "-h") == 0) {
                        usage(argv[0]);
                        ret = EXIT_SUCCESS;
                        goto exit;
                } else if (strcmp(argv[i], "-v") == 0) {
                        verbose = 1;
                } else {
                        fprintf(stderr, "Unknown argument: '%s'\n", argv[i]);
                        usage(argv[0]);
                        goto exit;
                }
        }

        if (req_filename == NULL) {
                fprintf(stderr, "Request file is needed\n");
                usage(argv[0]);
                goto exit;
        }

        if (resp_filename == NULL) {
                fprintf(stderr, "Response file is needed\n");
                usage(argv[0]);
                goto exit;
        }

        printf("ACVP library: %s\n", acvp_version());

        /* Create test session and enable supported algorithms */
        if (verbose)
                acvp_ret = acvp_create_test_session(&ctx, logger, ACVP_LOG_LVL_VERBOSE);
        else
                acvp_ret = acvp_create_test_session(&ctx, logger, ACVP_LOG_LVL_INFO);

        if (acvp_ret != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &aes_gcm_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &aes_cbc_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_ECB, &aes_ecb_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CFB128, &aes_cfb_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR, &aes_ctr_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GMAC, &aes_gmac_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_TDES_CBC, &tdes_cbc_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM, &aes_ccm_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &aes_cmac_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &hmac_sha1_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_256, &hmac_sha256_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_224, &hmac_sha224_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_384, &hmac_sha384_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA2_512, &hmac_sha512_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_224, &hmac_sha3_224_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_256, &hmac_sha3_256_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_384, &hmac_sha3_384_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA3_512, &hmac_sha3_512_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &sha1_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA224, &sha2_224_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA256, &sha2_256_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA384, &sha2_384_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &sha2_512_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_224, &sha3_224_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_256, &sha3_256_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_384, &sha3_384_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHA3_512, &sha3_512_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHAKE_128, &shake128_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_hash_enable(ctx, ACVP_HASH_SHAKE_256, &shake256_handler) != ACVP_SUCCESS)
                goto exit;

#if INT_ACVP_LIB_VER_NUM >= LIB_VER(2, 2, 0)
        if (acvp_cap_ml_dsa_enable(ctx, ACVP_ML_DSA_KEYGEN, &ml_dsa_keygen_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_KEYGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_44) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_KEYGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_65) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_KEYGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_87) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_enable(ctx, ACVP_ML_DSA_SIGGEN, &ml_dsa_siggen_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_44) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_65) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_87) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGGEN, 0,
                                     ACVP_ML_DSA_PARAM_DETERMINISTIC_MODE,
                                     ACVP_DETERMINISTIC_BOTH) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_enable(ctx, ACVP_ML_DSA_SIGVER, &ml_dsa_sigver_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_44) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_65) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_ml_dsa_set_parm(ctx, ACVP_ML_DSA_SIGVER, 0, ACVP_ML_DSA_PARAM_PARAMETER_SET,
                                     ACVP_ML_DSA_PARAM_SET_ML_DSA_87) != ACVP_SUCCESS)
                goto exit;

#endif /* INT_ACVP_LIB_VER_NUM >= LIB_VER(2, 2, 0) */

        /* Allocate and initialize MB_MGR */
        mb_mgr = alloc_mb_mgr(0);
        if (mb_mgr == NULL) {
                fprintf(stderr, "Could not allocate memory for MB_MGR\n");
                goto exit;
        }

        /*
         * Initialize MB_MGR with best architecture
         * if architecture is not specified
         */
        switch (test_arch) {
        case IMB_ARCH_NONE:
                init_mb_mgr_auto(mb_mgr, NULL);
                break;
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(mb_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(mb_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(mb_mgr);
                break;
        case IMB_ARCH_AVX10:
                init_mb_mgr_avx10(mb_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                goto exit;
        }

        uint64_t features = 0;
        const int imb_ret = imb_get_features(mb_mgr, &features);

        if (imb_ret != 0) {
                printf("Error retrieving MB_MGR features! %s\n", imb_get_strerror(imb_ret));
                free_mb_mgr(mb_mgr);
                return EXIT_FAILURE;
        }

        if ((mb_mgr != NULL) && (features & IMB_FEATURE_SELF_TEST)) {
                if (features & IMB_FEATURE_SELF_TEST_PASS)
                        printf("SELF-TEST: PASS\n");
                else
                        printf("SELF-TEST: FAIL\n");
        } else {
                printf("SELF-TEST: N/A (requires >= v1.3)\n");
        }

        if (imb_get_errno(mb_mgr) != 0) {
                fprintf(stderr, "Error initializing MB_MGR structure! %s\n",
                        imb_get_strerror(imb_get_errno(mb_mgr)));
                goto exit;
        }

        /* Parse request file, run crypto tests and write out response file */
#if INT_ACVP_LIB_VER_NUM >= LIB_VER(2, 2, 0)
        acvp_run_vectors_from_file_offline(ctx, req_filename, resp_filename);
#else
        acvp_run_vectors_from_file(ctx, req_filename, resp_filename);
#endif

        ret = EXIT_SUCCESS;

exit:
        /* Free MB_MGR and test session */
        if (mb_mgr != NULL)
                free_mb_mgr(mb_mgr);

        if (ctx != NULL)
                acvp_free_test_session(ctx);

        if (req_filename != NULL)
                free(req_filename);
        return ret;
}
