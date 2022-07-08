/**********************************************************************
  Copyright(c) 2022, Intel Corporation All rights reserved.

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

#define MAX_TAG_LENGTH 16

static ACVP_RESULT logger(char *msg)
{
        printf("%s", msg);
        return ACVP_SUCCESS;
}

IMB_MGR *mb_mgr = NULL;
int verbose = 0;
int direct_api = 0; /* job API by default */
int gmac_api = 0;

static int aes_cbc_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);
        static uint8_t next_iv[16];

        if (test_case == NULL)
                return EXIT_FAILURE;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return EXIT_FAILURE;
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
                return EXIT_FAILURE;
        }

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->key_len_in_bytes = tc->key_len >> 3;
        job->cipher_mode = IMB_CIPHER_CBC;
        job->hash_alg = IMB_AUTH_NULL;
        /*
         * If Monte-carlo test, use the IV from the ciphertext of
         * the previous iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT &&
            tc->mct_index != 0)
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

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL)
                        job = IMB_FLUSH_JOB(mb_mgr);
                if (job->status != IMB_STATUS_COMPLETED) {
                        fprintf(stderr, "Invalid job\n");
                        return EXIT_FAILURE;
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
                        return EXIT_FAILURE;
                }
        }
        /*
         * If Monte-carlo test, copy the ciphertext for
         * the IV of the next iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT)
                memcpy(next_iv, tc->ct, 16);

        return EXIT_SUCCESS;
}

static int aes_gcm_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        aes_gcm_init_var_iv_t gcm_init_var_iv = mb_mgr->gcm128_init_var_iv;
        aes_gcm_enc_dec_update_t gcm_update_enc = mb_mgr->gcm128_enc_update;
        aes_gcm_enc_dec_finalize_t gcm_finalize_enc =
                mb_mgr->gcm128_enc_finalize;
        aes_gcm_enc_dec_update_t gcm_update_dec = mb_mgr->gcm128_dec_update;
        aes_gcm_enc_dec_finalize_t gcm_finalize_dec =
                mb_mgr->gcm128_dec_finalize;
        aes_gmac_init_t gmac_init_var = mb_mgr->gmac128_init;
        aes_gmac_update_t gmac_update = mb_mgr->gmac128_update;
        aes_gmac_finalize_t gmac_finalize = mb_mgr->gmac128_finalize;
        struct gcm_key_data key;
        struct gcm_context_data ctx;
        IMB_HASH_ALG hash_mode;
        int use_gmac_api = 0;

        if (test_case == NULL)
                return EXIT_FAILURE;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                return EXIT_FAILURE;
        }

        if (gmac_api) {
                if ((tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT &&
                     tc->pt_len == 0) ||
                    (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT &&
                     tc->ct_len == 0))
                        use_gmac_api = 1;
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
                return EXIT_FAILURE;
        }

        if (direct_api == 1) {
                switch (tc->key_len) {
                case 128:
                        /* Function pointers already set for 128-bit key */
                        break;
                case 192:
                        gcm_init_var_iv = mb_mgr->gcm192_init_var_iv;
                        gcm_update_enc = mb_mgr->gcm192_enc_update;
                        gcm_finalize_enc = mb_mgr->gcm192_enc_finalize;
                        gcm_update_dec = mb_mgr->gcm192_dec_update;
                        gcm_finalize_dec = mb_mgr->gcm192_dec_finalize;
                        gmac_init_var = mb_mgr->gmac192_init;
                        gmac_update = mb_mgr->gmac192_update;
                        gmac_finalize = mb_mgr->gmac192_finalize;
                        break;
                case 256:
                        gcm_init_var_iv = mb_mgr->gcm256_init_var_iv;
                        gcm_update_enc = mb_mgr->gcm256_enc_update;
                        gcm_finalize_enc = mb_mgr->gcm256_enc_finalize;
                        gcm_update_dec = mb_mgr->gcm256_dec_update;
                        gcm_finalize_dec = mb_mgr->gcm256_dec_finalize;
                        gmac_init_var = mb_mgr->gmac256_init;
                        gmac_update = mb_mgr->gmac256_update;
                        gmac_finalize = mb_mgr->gmac256_finalize;
                        break;
                default:
                        fprintf(stderr, "Unsupported AES key length\n");
                        return EXIT_FAILURE;
                }
        } else {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->key_len_in_bytes = tc->key_len >> 3;
                if (use_gmac_api == 1) {
                        job->cipher_mode = IMB_CIPHER_NULL;
                        job->hash_alg = hash_mode;
                        job->u.GMAC._iv = tc->iv;
                        job->u.GMAC.iv_len_in_bytes = tc->iv_len;
                        job->u.GMAC._key = &key;
                } else {
                        job->cipher_mode = IMB_CIPHER_GCM;
                        job->hash_alg = IMB_AUTH_AES_GMAC;
                        job->u.GCM.aad = tc->aad;
                        job->u.GCM.aad_len_in_bytes = tc->aad_len;
                        job->enc_keys = &key;
                        job->dec_keys = &key;
                        job->iv = tc->iv;
                        job->iv_len_in_bytes = tc->iv_len;
                }
                job->cipher_start_src_offset_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output_len_in_bytes = tc->tag_len;
        }

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
                if (direct_api == 1) {
                        if (use_gmac_api == 1) {
                                gmac_init_var(&key, &ctx, tc->iv, tc->iv_len);
                                gmac_update(&key, &ctx, tc->aad, tc->aad_len);
                                gmac_finalize(&key, &ctx, tc->tag,
                                              tc->tag_len);
                        } else {
                                gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len,
                                            tc->aad, tc->aad_len);
                                gcm_update_enc(&key, &ctx, tc->ct,
                                           tc->pt, tc->pt_len);
                                gcm_finalize_enc(&key, &ctx, tc->tag,
                                                 tc->tag_len);
                                }
                } else {
                        if (use_gmac_api == 1) {
                                job->src = tc->aad;
                                job->msg_len_to_hash_in_bytes = tc->aad_len;
                        } else {
                                job->src = tc->pt;
                                job->dst = tc->ct;
                                job->msg_len_to_cipher_in_bytes = tc->pt_len;
                                job->msg_len_to_hash_in_bytes = tc->pt_len;
                        }
                        job->cipher_direction = IMB_DIR_ENCRYPT;
                        job->chain_order = IMB_ORDER_CIPHER_HASH;
                        job->auth_tag_output = tc->tag;

                        job = IMB_SUBMIT_JOB(mb_mgr);
                        if (job == NULL)
                                job = IMB_FLUSH_JOB(mb_mgr);
                        if (job->status != IMB_STATUS_COMPLETED) {
                                fprintf(stderr, "Invalid job\n");
                                return EXIT_FAILURE;
                        }
                }
        } else /* DECRYPT */ {
                uint8_t res_tag[MAX_TAG_LENGTH];

                if (direct_api == 1) {
                        if (use_gmac_api == 1) {
                                gmac_init_var(&key, &ctx, tc->iv, tc->iv_len);
                                gmac_update(&key, &ctx, tc->aad, tc->aad_len);
                                gmac_finalize(&key, &ctx, res_tag, tc->tag_len);
                        } else {
                                gcm_init_var_iv(&key, &ctx, tc->iv, tc->iv_len,
                                                tc->aad, tc->aad_len);
                                gcm_update_dec(&key, &ctx, tc->pt,
                                               tc->ct, tc->ct_len);
                                gcm_finalize_dec(&key, &ctx,
                                                 res_tag, tc->tag_len);
                        }
                } else {
                        if (use_gmac_api == 1) {
                                job->src = tc->aad;
                                job->msg_len_to_hash_in_bytes = tc->aad_len;
                        } else {
                                job->src = tc->ct;
                                job->dst = tc->pt;
                                job->msg_len_to_cipher_in_bytes = tc->ct_len;
                                job->msg_len_to_hash_in_bytes = tc->ct_len;
                        }
                        job->cipher_direction = IMB_DIR_DECRYPT;
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
                        job->auth_tag_output = res_tag;

                        job = IMB_SUBMIT_JOB(mb_mgr);
                        if (job == NULL)
                                job = IMB_FLUSH_JOB(mb_mgr);
                        if (job->status != IMB_STATUS_COMPLETED) {
                                fprintf(stderr, "Invalid job\n");
                                return EXIT_FAILURE;
                        }
                }
                if (memcmp(res_tag, tc->tag, tc->tag_len) != 0) {
                        if (verbose) {
                                hexdump(stdout, "result tag: ",
                                        res_tag, tc->tag_len);
                                hexdump(stdout, "reference tag: ",
                                        tc->tag, tc->tag_len);
                                fprintf(stderr, "Invalid tag\n");
                        }
                        return EXIT_FAILURE;
                }
        }
        return EXIT_SUCCESS;
}

static int aes_ctr_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);

        if (test_case == NULL)
                return EXIT_FAILURE;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return EXIT_FAILURE;
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
                return EXIT_FAILURE;
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
                        return EXIT_FAILURE;
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
                        return EXIT_FAILURE;
                }
        }
        return EXIT_SUCCESS;
}

static int aes_ccm_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_SYM_CIPHER_TC *tc;
        IMB_JOB *job = NULL;
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);
        uint8_t res_tag[MAX_TAG_LENGTH];

        if (test_case == NULL)
                return EXIT_FAILURE;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return EXIT_FAILURE;
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
                return EXIT_FAILURE;
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
                return EXIT_FAILURE;
        }

        if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
                /* Tag is placed at the end of the ciphertext. */
                const uint8_t *ref_tag = tc->ct + tc->ct_len;

                if (memcmp(res_tag, ref_tag, tc->tag_len) != 0) {
                        if (verbose) {
                                hexdump(stdout, "result tag: ",
                                        res_tag, tc->tag_len);
                                hexdump(stdout, "reference tag: ",
                                        ref_tag, tc->tag_len);
                                fprintf(stderr, "Invalid tag\n");
                        }
                        return EXIT_FAILURE;
                }
        }
        return EXIT_SUCCESS;
}

static void usage(const char *app_name)
{
        fprintf(stderr, "Usage: %s --req FILENAME --resp FILENAME [opt args], "
                "where args are two or more\n"
                "--req FILENAME: request file in JSON format (required)\n"
                "--resp FILENAME: response file in JSON format (required)\n"
                "--direct-api: uses direct API instead of job API if available\n"
                "--gmac-api: uses GMAC API\n"
                "--arch ARCH: select arch to test (SSE/AVX/AVX2/AVX512)\n"
                "-h: print this message\n"
                "-v: verbose, prints extra information\n\n"
                "Example: %s --req AES-GCM-req.json --resp AES-GCM-resp.json\n",
                app_name, app_name);
}

int main(int argc, char **argv)
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
                                fprintf(stderr,
                                        "Request file does not exist\n");
                                goto exit;
                        }
                        i++;
                } else if (strcmp(argv[i], "--resp") == 0) {
                        if (argv[i + 1] == NULL) {
                                fprintf(stderr,
                                        "Missing argument for --resp\n");
                                goto exit;
                        }
                        resp_filename = argv[i + 1];
                        i++;
                } else if (strcmp(argv[i], "--arch") == 0) {
                        if (argv[i + 1] == NULL) {
                                fprintf(stderr,
                                        "Missing argument for --arch\n");
                                goto exit;
                        }
                        if (strcmp(argv[i], "SSE") == 0)
                                test_arch = IMB_ARCH_SSE;
                        else if (strcmp(argv[i], "AVX") == 0)
                                test_arch = IMB_ARCH_AVX;
                        else if (strcmp(argv[i], "AVX2") == 0)
                                test_arch = IMB_ARCH_AVX2;
                        else if (strcmp(argv[i], "AVX512") == 0)
                                test_arch = IMB_ARCH_AVX512;
                        else if (strcmp(argv[i], "NO-AESNI") == 0)
                                test_arch = IMB_ARCH_NOAESNI;
                        else {
                                fprintf(stderr, "Unsupported architecture\n");
                                goto exit;
                        }
                        i++;
                } else if (strcmp(argv[i], "--direct-api") == 0) {
                        direct_api = 1;
                } else if (strcmp(argv[i], "--gmac-api") == 0) {
                        gmac_api = 1;
                } else if (strcmp(argv[i], "-h") == 0) {
                        usage(argv[0]);
                        ret = EXIT_SUCCESS;
                        goto exit;
                } else if (strcmp(argv[i], "-v") == 0) {
                        verbose = 1;
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

        /* Create test session and enable supported algorithms */
        acvp_ret = acvp_create_test_session(&ctx, logger, ACVP_LOG_LVL_INFO);
        if (acvp_ret != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM,
                                       &aes_gcm_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC,
                                       &aes_cbc_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CTR,
                                       &aes_ctr_handler) != ACVP_SUCCESS)
                goto exit;

        if (acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CCM,
                                       &aes_ccm_handler) != ACVP_SUCCESS)
                goto exit;

        /* Allocate and initialize MB_MGR */
        if (test_arch == IMB_ARCH_NOAESNI)
                mb_mgr = alloc_mb_mgr(IMB_FLAG_AESNI_OFF);
        else
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
        case IMB_ARCH_NOAESNI:
                init_mb_mgr_sse(mb_mgr);
                break;
        case IMB_ARCH_AVX:
                init_mb_mgr_avx(mb_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(mb_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(mb_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                goto exit;
        }

        /* Parse request file, run crypto tests and write out response file */
        acvp_run_vectors_from_file(ctx, req_filename, resp_filename);

        /* Free MB_MGR and test session */
        free_mb_mgr(mb_mgr);

        acvp_free_test_session(ctx);

        ret = EXIT_SUCCESS;
exit:
        free(req_filename);
        return ret;
}
