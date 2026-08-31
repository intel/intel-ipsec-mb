/**********************************************************************
  Copyright(c) 2019-2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdio.h>
#include <stdlib.h> /* posix_memalign() and free() */
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#ifndef LINUX
#include <malloc.h> /* _aligned_malloc() and aligned_free() */
#endif
#include "misc.h"
#include "utils.h"
#ifdef PIN_BASED_CEC
#include <pin_based_cec.h>
#endif

#ifdef _WIN32
#include <intrin.h>
#define strdup     _strdup
#define BSWAP64    _byteswap_uint64
#define __func__   __FUNCTION__
#define strcasecmp _stricmp
#else
#include <x86intrin.h>
#define BSWAP64 __builtin_bswap64
#endif

#include <intel-ipsec-mb.h>
#include "include/mb_mgr.h"

#include "algo_maps.h"
#include "job_params.h"
#include "job_utils.h"

/* maximum size of a test buffer */
#define JOB_SIZE_TOP (16 * 1024)
/* min size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MIN 16
/* max size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MAX (2 * 1024)
/* number of bytes to increase buffer size when testing range of buffers */
#define DEFAULT_JOB_SIZE_STEP 16

/* MAX_AAD_SIZE, MAX_GCM_AAD_SIZE, MAX_CCM_AAD_SIZE and NUM_TAG_SIZES come from job_params.h */

#define MAX_IV_SIZE 16

#define MAX_NUM_JOBS 32
#define IMIX_ITER    1000

/* MAX_KEY_SIZE and MAX_DIGEST_SIZE come from job_params.h */

#define SEED 0xdeadcafe

/* Struct storing all necessary data for crypto operations */
struct data {
        uint8_t test_buf[MAX_NUM_JOBS][JOB_SIZE_TOP];
        uint8_t src_dst_buf[MAX_NUM_JOBS][JOB_SIZE_TOP];
        uint8_t aad[MAX_AAD_SIZE];
        uint8_t in_digest[MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        uint8_t out_digest[MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        uint8_t cipher_iv[MAX_IV_SIZE];
        uint8_t auth_iv[MAX_IV_SIZE];
        uint8_t ciph_key[MAX_KEY_SIZE];
        uint8_t auth_key[MAX_KEY_SIZE];
        struct cipher_auth_keys enc_keys;
        struct cipher_auth_keys dec_keys;
        uint8_t tag_size;
};

/*
 * IMB_MGR's and the architectures they have been initialized for.
 * Encryption is done with one architecture and decryption with another one,
 * so that results can be cross validated.
 */
struct test_mgr {
        IMB_MGR *enc_mb_mgr;
        IMB_ARCH enc_arch;
        IMB_MGR *dec_mb_mgr;
        IMB_ARCH dec_arch;
};

uint8_t custom_test = 0;
uint8_t verbose = 0;

uint32_t job_sizes[NUM_RANGE] = { DEFAULT_JOB_SIZE_MIN, DEFAULT_JOB_SIZE_STEP,
                                  DEFAULT_JOB_SIZE_MAX };
/* Max number of jobs to submit in IMIX testing */
uint32_t max_num_jobs = 17;
/* IMIX disabled by default */
unsigned int imix_enabled = 0;

struct custom_job_params custom_job_params = { .cipher_mode = IMB_CIPHER_NULL,
                                               .hash_alg = IMB_AUTH_NULL,
                                               .key_size = 0 };

/* Architectures to test, indexed with IMB_ARCH, IMB_ARCH_NONE is never tested */
uint8_t enc_archs[IMB_ARCH_NUM] = { 0, 1, 1, 1, 1 };
uint8_t dec_archs[IMB_ARCH_NUM] = { 0, 1, 1, 1, 1 };

uint64_t flags = 0; /* flags passed to alloc_mb_mgr() */

int burst_api = 0;

static void
clear_data(struct data *data)
{
        unsigned i;

        for (i = 0; i < MAX_NUM_JOBS; i++) {
                imb_clear_mem(data->test_buf[i], JOB_SIZE_TOP);
                imb_clear_mem(data->src_dst_buf[i], JOB_SIZE_TOP);
                imb_clear_mem(data->in_digest[i], MAX_DIGEST_SIZE);
                imb_clear_mem(data->out_digest[i], MAX_DIGEST_SIZE);
        }

        imb_clear_mem(data->aad, MAX_AAD_SIZE);
        imb_clear_mem(data->cipher_iv, MAX_IV_SIZE);
        imb_clear_mem(data->auth_iv, MAX_IV_SIZE);
        imb_clear_mem(data->ciph_key, MAX_KEY_SIZE);
        imb_clear_mem(data->auth_key, MAX_KEY_SIZE);
        imb_clear_mem(&data->enc_keys, sizeof(struct cipher_auth_keys));
        imb_clear_mem(&data->dec_keys, sizeof(struct cipher_auth_keys));
}

/* Modify the test buffer to set the HEC value and CRC, so the final
 * decrypted message can be compared against the test buffer */
static int
modify_pon_test_buf(uint8_t *test_buf, const IMB_JOB *job, const uint32_t pli,
                    const uint64_t xgem_hdr)
{
        /* Set plaintext CRC in test buffer for PON */
        uint32_t *buf32 = (uint32_t *) &test_buf[8 + pli - 4];
        uint64_t *buf64 = (uint64_t *) test_buf;
        const uint32_t *tag32 = (uint32_t *) job->auth_tag_output;
        const uint64_t hec_mask = BSWAP64(0xfffffffffffe000);
        const uint64_t xgem_hdr_out =
                ((const uint64_t *) (job->src + job->hash_start_src_offset_in_bytes))[0];

        /* Update CRC if PLI > 4 */
        if (pli > 4)
                buf32[0] = tag32[1];

        /* Check if any bits apart from HEC are modified */
        if ((xgem_hdr_out & hec_mask) != (xgem_hdr & hec_mask)) {
                fprintf(stderr, "XGEM header overwritten outside HEC\n");
                fprintf(stderr, "Original XGEM header: %" PRIx64 "\n", xgem_hdr & hec_mask);
                fprintf(stderr, "Output XGEM header: %" PRIx64 "\n", xgem_hdr_out & hec_mask);
                return -1;
        }

        /* Modify original XGEM header to include calculated HEC */
        buf64[0] = xgem_hdr_out;

        return 0;
}

/* Modify the test buffer to set the CRC value, so the final
 * decrypted message can be compared against the test buffer */
static void
modify_docsis_crc32_test_buf(uint8_t *test_buf, const IMB_JOB *job, const uint32_t buf_size)
{
        if (buf_size >= (IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE + IMB_DOCSIS_CRC32_TAG_SIZE)) {
                /* Set plaintext CRC32 in the test buffer */
                nosimd_memcpy(&test_buf[buf_size - IMB_DOCSIS_CRC32_TAG_SIZE], job->auth_tag_output,
                              IMB_DOCSIS_CRC32_TAG_SIZE);
        }
}

static int
post_job(IMB_MGR *mgr, IMB_JOB *job, unsigned *num_processed_jobs, const struct params_s *params,
         struct job_ctx *job_tab, const IMB_CIPHER_DIRECTION dir)
{

        const unsigned idx = (unsigned) ((uintptr_t) job->user_data);

        if (job->status != IMB_STATUS_COMPLETED) {
                int errc = imb_get_errno(mgr);

                fprintf(stderr,
                        "failed job, status:%d, "
                        "error code:%d '%s'\n",
                        job->status, errc, imb_get_strerror(errc));
                return -1;
        }
        if (idx != *num_processed_jobs) {
                fprintf(stderr,
                        "enc-submit job returned out of order, "
                        "received %u, expected %u\n",
                        idx, *num_processed_jobs);
                return -1;
        }
        (*num_processed_jobs)++;

        /* Only need to modify the buffer after encryption */
        if (dir == IMB_DIR_ENCRYPT) {
                if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                        if (modify_pon_test_buf(job_tab[idx].test_buf, job, job_tab[idx].pli,
                                                job_tab[idx].xgem_hdr) < 0)
                                return -1;
                }

                if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32)
                        modify_docsis_crc32_test_buf(job_tab[idx].test_buf, job,
                                                     job_tab[idx].buf_size);
        }

        return 0;
}

static int
process_jobs(IMB_MGR *mb_mgr, IMB_JOB *job_tab, const unsigned num_jobs,
             const struct params_s *params, struct job_ctx *job_ctx_tab,
             const char *avx_sse_text_submit, const char *avx_sse_text_flush, unsigned *err_idx)
{
        unsigned i;
        unsigned num_processed_jobs = 0;

        *err_idx = num_jobs;

        if (burst_api) {
                IMB_JOB *burst_jobs[IMB_MAX_BURST_SIZE];

                /* num_jobs will always be lower than IMB_MAX_BURST_SIZE */
                unsigned num_rx_jobs = IMB_GET_NEXT_BURST(mb_mgr, num_jobs, burst_jobs);

                if (num_rx_jobs != num_jobs) {
                        fprintf(stderr,
                                "Number of jobs received %u is different than requested %u\n",
                                num_rx_jobs, num_jobs);
                        return -1;
                }

                for (i = 0; i < num_jobs; i++)
                        *burst_jobs[i] = job_tab[i];

                num_rx_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, burst_jobs);

                avx_sse_check(avx_sse_text_submit, (unsigned) params->hash_alg,
                              (unsigned) params->cipher_mode);

                if (num_rx_jobs < num_jobs) {
                        num_rx_jobs += IMB_FLUSH_BURST(mb_mgr, (num_jobs - num_rx_jobs),
                                                       &burst_jobs[num_rx_jobs]);
                        avx_sse_check(avx_sse_text_flush, (unsigned) params->hash_alg,
                                      (unsigned) params->cipher_mode);
                }

                if (num_rx_jobs != num_jobs) {
                        fprintf(stderr,
                                "Number of processed jobs %u is different than submitted %u\n",
                                num_rx_jobs, num_jobs);
                        return -1;
                }

                for (i = 0; i < num_rx_jobs; i++)
                        if (post_job(mb_mgr, burst_jobs[i], &num_processed_jobs, params,
                                     job_ctx_tab, IMB_DIR_ENCRYPT) < 0) {
                                *err_idx = i;
                                return -1;
                        }

        } else {
                for (i = 0; i < num_jobs; i++) {
                        IMB_JOB *job = IMB_GET_NEXT_JOB(mb_mgr);

                        *job = job_tab[i];

                        job = IMB_SUBMIT_JOB(mb_mgr);

                        avx_sse_check(avx_sse_text_submit, (unsigned) params->hash_alg,
                                      (unsigned) params->cipher_mode);

                        if (job)
                                if (post_job(mb_mgr, job, &num_processed_jobs, params, job_ctx_tab,
                                             IMB_DIR_ENCRYPT) < 0) {
                                        *err_idx = (unsigned) ((uintptr_t) job->user_data);
                                        return -1;
                                }
                }
                /* Flush rest of the jobs, if there are outstanding jobs */
                while (num_processed_jobs != num_jobs) {
                        IMB_JOB *job = IMB_FLUSH_JOB(mb_mgr);

                        avx_sse_check(avx_sse_text_flush, (unsigned) params->hash_alg,
                                      (unsigned) params->cipher_mode);

                        while (job != NULL) {
                                if (post_job(mb_mgr, job, &num_processed_jobs, params, job_ctx_tab,
                                             IMB_DIR_ENCRYPT) < 0) {
                                        *err_idx = (unsigned) ((uintptr_t) job->user_data);
                                        return -1;
                                }

                                /* Get more completed jobs */
                                job = IMB_GET_COMPLETED_JOB(mb_mgr);
                        }
                }
        }

        return 0;
}

static void
print_fail_context(const struct test_mgr *mgr, const struct params_s *params, struct data *data,
                   const unsigned imix, const unsigned num_jobs, const unsigned idx,
                   const struct job_ctx *job_ctx_tab)
{
        uint64_t features;

        printf("Failures in\n");
        print_algo_info(params);

        printf("\nEncrypting ");
        features = 0;
        (void) imb_get_features(mgr->enc_mb_mgr, &features);
        print_tested_arch(features, mgr->enc_arch);

        printf("Decrypting ");
        features = 0;
        (void) imb_get_features(mgr->dec_mb_mgr, &features);
        print_tested_arch(features, mgr->dec_arch);

        /*
         * Print buffer size info if the failure was caused by an actual job,
         * where "idx" indicates the index of the job failing
         */
        if (idx < num_jobs) {
                if (imix) {
                        if (job_ctx_tab != NULL) {
                                printf("Job #%u, buffer size = %u\n", idx,
                                       job_ctx_tab[idx].buf_size);

                                for (unsigned n = 0; n < num_jobs; n++)
                                        printf("Other sizes = %u\n", job_ctx_tab[n].buf_size);
                        }
                } else
                        printf("Buffer size = %u\n", params->buf_size);
        }
        printf("Key size = %u\n", params->key_size);
        printf("Tag size = %u\n", data->tag_size);
        printf("AAD size = %u\n", params->aad_size);
}

/*
 * @brief Performs test using AES_HMAC or DOCSIS
 * @return Operation status
 * @retval 0 success
 * @retval -1 encrypt/decrypt operation error (result mismatch, unsupported algorithm etc.)
 */
static int
do_test(const struct test_mgr *mgr, const struct params_s *params, struct data *data,
        const unsigned imix, const unsigned num_jobs)
{
        struct job_ctx job_ctx_tab[MAX_NUM_JOBS] = { 0 };
        IMB_JOB job_tab[MAX_NUM_JOBS];
        unsigned i;
        int ret = -1;
        IMB_MGR *const enc_mb_mgr = mgr->enc_mb_mgr;
        IMB_MGR *const dec_mb_mgr = mgr->dec_mb_mgr;
        struct cipher_auth_keys *enc_keys = &data->enc_keys;
        struct cipher_auth_keys *dec_keys = &data->dec_keys;

        if (num_jobs == 0)
                return ret;

        /* Randomize the keys and the test data */
        generate_random_buf(data->cipher_iv, MAX_IV_SIZE);
        generate_random_buf(data->auth_iv, MAX_IV_SIZE);
        generate_random_buf(data->aad, MAX_AAD_SIZE);
        generate_random_buf(data->ciph_key, MAX_KEY_SIZE);
        generate_random_buf(data->auth_key, MAX_KEY_SIZE);

        for (i = 0; i < num_jobs; i++) {
                /* Job sizes are randomized per job in the IMIX mode */
                const uint32_t buf_size =
                        imix ? generate_imix_job_size(params, DEFAULT_JOB_SIZE_MAX)
                             : params->buf_size;

                if (set_job_ctx(&job_ctx_tab[i], params, buf_size, JOB_SIZE_TOP, data->in_digest[i],
                                data->out_digest[i], data->tag_size, data->test_buf[i],
                                data->src_dst_buf[i], generate_random_buf) < 0)
                        goto exit;
        }

        /* Expand/schedule keys */
        if (fill_keys(enc_mb_mgr, enc_keys, data->ciph_key, data->auth_key, params, NULL) < 0)
                goto exit;

        if (fill_keys(dec_mb_mgr, dec_keys, data->ciph_key, data->auth_key, params, NULL) < 0)
                goto exit;

#ifdef PIN_BASED_CEC
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->enc_keys, sizeof(enc_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->dec_keys, sizeof(enc_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &enc_keys->gdata_key, sizeof(enc_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k1_expanded, sizeof(enc_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k2, sizeof(enc_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k3, sizeof(enc_keys->k3));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->ck, sizeof(enc_keys->ck));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->nia4_key, sizeof(enc_keys->nia4_key));

        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->enc_keys, sizeof(dec_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->dec_keys, sizeof(dec_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &dec_keys->gdata_key, sizeof(dec_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k1_expanded, sizeof(dec_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k2, sizeof(dec_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k3, sizeof(dec_keys->k3));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->ck, sizeof(dec_keys->ck));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->nia4_key, sizeof(dec_keys->nia4_key));
#endif

        /* Build encrypt job structures */
        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = &job_tab[i];

                /*
                 * Encrypt + generate digest from encrypted message
                 * using architecture under test
                 */
                nosimd_memcpy(job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].test_buf,
                              job_ctx_tab[i].buf_size);
                if (fill_job(job, params, job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].in_digest,
                             data->aad, job_ctx_tab[i].buf_size, data->tag_size, IMB_DIR_ENCRYPT,
                             enc_keys, data->cipher_iv, data->auth_iv, i) < 0)
                        goto exit;

                /* Randomize memory for input digest */
                generate_random_buf(job_ctx_tab[i].in_digest, data->tag_size);

                if (burst_api)
                        imb_set_session(enc_mb_mgr, job);
        }

        /* Process encrypt operations */
        if (process_jobs(enc_mb_mgr, job_tab, num_jobs, params, job_ctx_tab, "enc-submit",
                         "enc-flush", &i) != 0)
                goto exit;

#ifdef PIN_BASED_CEC
        PinBasedCEC_ClearSecrets();
#endif

#ifdef PIN_BASED_CEC
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->enc_keys, sizeof(enc_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->dec_keys, sizeof(enc_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &enc_keys->gdata_key, sizeof(enc_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k1_expanded, sizeof(enc_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k2, sizeof(enc_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k3, sizeof(enc_keys->k3));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->ck, sizeof(enc_keys->ck));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->nia4_key, sizeof(enc_keys->nia4_key));

        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->enc_keys, sizeof(dec_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->dec_keys, sizeof(dec_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &dec_keys->gdata_key, sizeof(dec_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k1_expanded, sizeof(dec_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k2, sizeof(dec_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k3, sizeof(dec_keys->k3));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->ck, sizeof(dec_keys->ck));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->nia4_key, sizeof(dec_keys->nia4_key));
#endif

        /* Build decrypt job structures */
        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = &job_tab[i];

                /* Randomize memory for output digest */
                generate_random_buf(job_ctx_tab[i].out_digest, data->tag_size);

                /*
                 * Generate digest from encrypted message and decrypt
                 * using reference architecture
                 */
                if (fill_job(job, params, job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].out_digest,
                             data->aad, job_ctx_tab[i].buf_size, data->tag_size, IMB_DIR_DECRYPT,
                             dec_keys, data->cipher_iv, data->auth_iv, i) < 0)
                        goto exit;

                if (burst_api)
                        imb_set_session(dec_mb_mgr, job);
        }

        /* Process decrypt operations */
        if (process_jobs(dec_mb_mgr, job_tab, num_jobs, params, job_ctx_tab, "dec-submit",
                         "dec-flush", &i) != 0)
                goto exit;

#ifdef PIN_BASED_CEC
        PinBasedCEC_ClearSecrets();
#endif
        /* Check the results */
        for (i = 0; i < num_jobs; i++) {
                int goto_exit = 0;

                if (params->hash_alg != IMB_AUTH_NULL &&
                    memcmp(job_ctx_tab[i].in_digest, job_ctx_tab[i].out_digest,
                           job_ctx_tab[i].tag_size_to_check) != 0) {
                        fprintf(stderr, "\nInput and output tags "
                                        "don't match\n");
                        hexdump(stdout, "Input digest", job_ctx_tab[i].in_digest,
                                job_ctx_tab[i].tag_size_to_check);
                        hexdump(stdout, "Output digest", job_ctx_tab[i].out_digest,
                                job_ctx_tab[i].tag_size_to_check);
                        goto_exit = 1;
                }

                if (params->cipher_mode != IMB_CIPHER_NULL &&
                    memcmp(job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].test_buf,
                           job_ctx_tab[i].buf_size) != 0) {
                        fprintf(stderr, "\nDecrypted text and "
                                        "plaintext don't match\n");
                        hexdump(stdout, "Plaintext (orig)", job_ctx_tab[i].test_buf,
                                job_ctx_tab[i].buf_size);
                        hexdump(stdout, "Decrypted msg", job_ctx_tab[i].src_dst_buf,
                                job_ctx_tab[i].buf_size);
                        goto_exit = 1;
                }

                if ((params->hash_alg == IMB_AUTH_PON_CRC_BIP) && (job_ctx_tab[i].pli > 4)) {
                        const uint64_t plen = 8 + job_ctx_tab[i].pli - 4;

                        if (memcmp(job_ctx_tab[i].src_dst_buf + plen, job_ctx_tab[i].out_digest + 4,
                                   4) != 0) {
                                fprintf(stderr, "\nDecrypted CRC and "
                                                "calculated CRC don't match\n");
                                hexdump(stdout, "Decrypted CRC", job_ctx_tab[i].src_dst_buf + plen,
                                        4);
                                hexdump(stdout, "Calculated CRC", job_ctx_tab[i].out_digest + 4, 4);
                                goto_exit = 1;
                        }
                }

                if (goto_exit)
                        goto exit;
        }

        ret = 0;

exit:
        /* clear data */
        clear_data(data);

        if (ret == -1)
                print_fail_context(mgr, params, data, imix, num_jobs, i, job_ctx_tab);

        return ret;
}

static void
test_single(const struct test_mgr *mgr, const struct params_s *params, struct data *variant_data,
            const uint32_t buf_size)
{
        uint8_t tag_sizes[NUM_TAG_SIZES];
        const uint32_t min_aad_sz = 0;

        if (params->hash_alg >= IMB_AUTH_NUM) {
                if (verbose) {
                        fprintf(stderr, "Invalid hash alg\n");
                        printf("FAIL\n");
                }
                exit(EXIT_FAILURE);
        }

        const uint32_t max_aad_sz = get_max_aad_size(params);
        const unsigned num_tag_sizes = get_tag_sizes(params, tag_sizes);

        for (unsigned i = 0; i < num_tag_sizes; i++) {
                variant_data->tag_size = tag_sizes[i];

                for (uint32_t aad_sz = min_aad_sz; aad_sz <= max_aad_sz; aad_sz++) {
                        /* Parameters of this test case, params is left untouched */
                        struct params_s job_params = *params;

                        job_params.aad_size = aad_sz;
                        job_params.buf_size = buf_size;

                        if (!is_valid_job_size(&job_params, buf_size))
                                continue;

                        if (do_test(mgr, &job_params, variant_data, 0, 1) < 0)
                                exit(EXIT_FAILURE);
                }
        }
}

/* Runs test for each buffer size */
static void
process_variant(const struct test_mgr *mgr, const struct params_s *params,
                struct data *variant_data)
{
#ifdef PIN_BASED_CEC
        const uint32_t sizes = job_sizes[RANGE_MAX];
#else
        const uint32_t sizes = params->num_sizes;
#endif
        uint32_t sz;

        if (verbose) {
                printf("[INFO] ");
                print_algo_info(params);
        }

        /* Reset the variant data */
        clear_data(variant_data);

        for (sz = 0; sz < sizes; sz++) {
#ifdef PIN_BASED_CEC
                const uint32_t buf_size = job_sizes[RANGE_MIN];
#else
                const uint32_t buf_size = job_sizes[RANGE_MIN] + (sz * job_sizes[RANGE_STEP]);
#endif

                test_single(mgr, params, variant_data, buf_size);
        }

        /* Perform IMIX tests */
        if (imix_enabled) {
                /* IMIX tests are run with no AAD and with job sizes randomized per job */
                struct params_s imix_params = *params;

                imix_params.aad_size = 0;
                imix_params.buf_size = 0;

                for (unsigned i = 2; i <= max_num_jobs; i++) {
                        for (unsigned j = 0; j < IMIX_ITER; j++) {
                                if (do_test(mgr, &imix_params, variant_data, 1, i) < 0) {
                                        printf("FAIL\n");
                                        exit(EXIT_FAILURE);
                                }
                        }
                }
        }
        if (verbose)
                printf("PASS\n");
}

/* Sets cipher direction and key size  */
static void
run_test(const IMB_ARCH enc_arch, const IMB_ARCH dec_arch, struct params_s *params,
         struct data *variant_data)
{
        IMB_MGR *enc_mgr = NULL;
        IMB_MGR *dec_mgr = NULL;

        enc_mgr = alloc_mb_mgr(flags);

        if (enc_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        switch (enc_arch) {
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(enc_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(enc_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(enc_mgr);
                break;
        case IMB_ARCH_AVX10:
                init_mb_mgr_avx10(enc_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                exit(EXIT_FAILURE);
        }

        uint64_t features = 0;
        int ret = imb_get_features(enc_mgr, &features);

        if (ret != 0) {
                fprintf(stderr, "MB MGR get features failure\n");
                exit(EXIT_FAILURE);
        }

        if (features & IMB_FEATURE_SELF_TEST)
                if (!(features & IMB_FEATURE_SELF_TEST_PASS))
                        fprintf(stderr, "SELF-TEST: FAIL\n");

        if (imb_get_errno(enc_mgr) != 0) {
                fprintf(stderr, "Error initializing enc MB_MGR structure! %s\n",
                        imb_get_strerror(imb_get_errno(enc_mgr)));
                exit(EXIT_FAILURE);
        }

        printf("Encrypting ");
        print_tested_arch(features, enc_arch);

        dec_mgr = alloc_mb_mgr(flags);

        if (dec_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        switch (dec_arch) {
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(dec_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(dec_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(dec_mgr);
                break;
        case IMB_ARCH_AVX10:
                init_mb_mgr_avx10(dec_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                exit(EXIT_FAILURE);
        }

        features = 0;
        ret = imb_get_features(dec_mgr, &features);

        if (ret != 0) {
                fprintf(stderr, "MB MGR get features failure\n");
                exit(EXIT_FAILURE);
        }

        if (features & IMB_FEATURE_SELF_TEST)
                if (!(features & IMB_FEATURE_SELF_TEST_PASS))
                        fprintf(stderr, "SELF-TEST: FAIL\n");

        if (imb_get_errno(dec_mgr) != 0) {
                fprintf(stderr, "Error initializing dec MB_MGR structure! %s\n",
                        imb_get_strerror(imb_get_errno(dec_mgr)));
                exit(EXIT_FAILURE);
        }

        printf("Decrypting ");
        print_tested_arch(features, dec_arch);

        const struct test_mgr mgr = { .enc_mb_mgr = enc_mgr,
                                      .enc_arch = enc_arch,
                                      .dec_mb_mgr = dec_mgr,
                                      .dec_arch = dec_arch };

        if (custom_test) {
                params->key_size = custom_job_params.key_size;
                params->cipher_mode = custom_job_params.cipher_mode;
                params->hash_alg = custom_job_params.hash_alg;
                process_variant(&mgr, params, variant_data);
                goto exit;
        }

        IMB_CIPHER_MODE c_mode;

        for (c_mode = IMB_CIPHER_CBC; c_mode < IMB_CIPHER_NUM; c_mode++) {
                IMB_HASH_ALG hash_alg;

                params->cipher_mode = c_mode;

                for (hash_alg = IMB_AUTH_HMAC_SHA_1; hash_alg < IMB_AUTH_NUM; hash_alg++) {
                        /* Skip IMB_AUTH_CUSTOM */
                        if (hash_alg == IMB_AUTH_CUSTOM)
                                continue;

                        /* Skip not supported combinations */
                        if (!is_valid_combination(c_mode, hash_alg))
                                continue;

                        params->hash_alg = hash_alg;

                        uint8_t min_sz = key_sizes[c_mode - 1][0];
                        uint8_t max_sz = key_sizes[c_mode - 1][1];
                        uint8_t step_sz = key_sizes[c_mode - 1][2];
                        uint8_t key_sz;

                        for (key_sz = min_sz; key_sz <= max_sz; key_sz += step_sz) {
                                params->key_size = key_sz;
                                process_variant(&mgr, params, variant_data);
                        }
                }
        }

exit:
        free_mb_mgr(enc_mgr);
        free_mb_mgr(dec_mgr);
}

/* Prepares data structure for test variants storage,
 * sets test configuration
 */
static void
run_tests(void)
{
        struct params_s params;
        struct data *variant_data = NULL;
        IMB_ARCH enc_arch, dec_arch;
#ifdef PIN_BASED_CEC
        const uint32_t pkt_size = job_sizes[RANGE_MIN];
        const uint32_t num_iter = job_sizes[RANGE_MAX];
#else
        const uint32_t min_size = job_sizes[RANGE_MIN];
        const uint32_t max_size = job_sizes[RANGE_MAX];
        const uint32_t step_size = job_sizes[RANGE_STEP];
#endif

#ifdef PIN_BASED_CEC
        params.num_sizes = 1;
#else
        params.num_sizes = ((max_size - min_size) / step_size) + 1;
#endif
        variant_data = malloc(sizeof(struct data));

        if (variant_data == NULL) {
                fprintf(stderr, "Test data could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        if (verbose) {
#ifdef PIN_BASED_CEC
                printf("Testing buffer size = %u bytes, %u times\n", pkt_size, num_iter);
#else
                if (min_size == max_size)
                        printf("Testing buffer size = %u bytes\n", min_size);
                else
                        printf("Testing buffer sizes from %u to %u "
                               "in steps of %u bytes\n",
                               min_size, max_size, step_size);
#endif
        }
        /* Performing tests for each selected architecture */
        for (enc_arch = IMB_ARCH_SSE; enc_arch < IMB_ARCH_NUM; enc_arch++) {
                if (enc_archs[enc_arch] == 0)
                        continue;
                for (dec_arch = IMB_ARCH_SSE; dec_arch < IMB_ARCH_NUM; dec_arch++) {
                        if (dec_archs[dec_arch] == 0)
                                continue;
                        run_test(enc_arch, dec_arch, &params, variant_data);
                }

        } /* end for run */

        free(variant_data);
}

static void
usage(const char *app_name)
{
        fprintf(stderr,
                "Usage: %s [args], "
                "where args are zero or more\n"
                "-h: print this message\n"
                "-v: verbose, prints extra information\n"
                "--enc-arch: encrypting with architecture "
                "(SSE/AVX/AVX2/AVX512)\n"
                "--dec-arch: decrypting with architecture "
                "(SSE/AVX/AVX2/AVX512)\n"
                "--cipher-algo: Select cipher algorithm to run on the custom "
                "test\n"
                "--hash-algo: Select hash algorithm to run on the custom test\n"
                "--aead-algo: Select AEAD algorithm to run on the custom test\n"
                "--no-avx10: Don't do AVX10\n"
                "--no-avx512: Don't do AVX512\n"
                "--no-avx2: Don't do AVX2\n"
                "--no-sse: Don't do SSE\n"
                "--shani-on: use SHA extensions, default: auto-detect\n"
                "--shani-off: don't use SHA extensions\n"
                "--gfni-on: use Galois Field extensions, default: auto-detect\n"
                "--gfni-off: don't use Galois Field extensions\n"
                "--cipher-iv-size: size of cipher IV.\n"
                "--auth-iv-size: size of authentication IV.\n"
                "--tag-size: size of authentication tag\n"
                "--job-size: size of the cipher & MAC job in bytes. "
#ifndef PIN_BASED_CEC
                "It can be:\n"
                "            - single value: test single size\n"
                "            - range: test multiple sizes with following format"
                " min:step:max (e.g. 16:16:256)\n"
#else
                "            - size:1:num_iterations format\n"
                "              e.g. 64:1:128 => repeat 128 times operation on a 64 byte buffer\n"
#endif
                "--num-jobs: maximum number of number of jobs to submit in one go "
                "(maximum = %d)\n"
                "--avx-sse: if XGETBV is available then check for potential "
                "AVX-SSE transition problems\n"
                "--burst-api: use burst API instead of single job API\n"
                "--offset: offset in bytes where the plaintext will be placed from the start of "
                "the allocated buffer (default 4 bytes)",
                app_name, MAX_NUM_JOBS);
}

int
main(int argc, char *argv[])
{
        int i;
        unsigned int arch_id;
        uint8_t arch_support[IMB_ARCH_NUM];
        const union params *values;
        unsigned int cipher_algo_set = 0;
        unsigned int hash_algo_set = 0;
        unsigned int aead_algo_set = 0;

        for (i = 1; i < argc; i++)
                if (strcmp(argv[i], "-h") == 0) {
                        usage(argv[0]);
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "-v") == 0) {
                        verbose = 1;
                } else if (update_flags_and_archs(argv[i], enc_archs, &flags)) {
                        if (!update_flags_and_archs(argv[i], dec_archs, &flags)) {
                                fprintf(stderr, "Same archs should be available\n");
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--enc-arch") == 0) {

                        /* Use index 1 to skip arch_str_map.name = "NONE" */
                        values = check_string_arg(argv[i], argv[i + 1], arch_str_map + 1,
                                                  num_arch_str_map - 1);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        nosimd_memset(enc_archs, 0, sizeof(enc_archs));
                        enc_archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--dec-arch") == 0) {
                        /* Use index 1 to skip arch_str_map.name = "NONE" */
                        values = check_string_arg(argv[i], argv[i + 1], arch_str_map + 1,
                                                  num_arch_str_map - 1);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        nosimd_memset(dec_archs, 0, sizeof(dec_archs));
                        dec_archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--cipher-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], cipher_algo_str_map,
                                                  num_cipher_algo_str_map);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode = values->job_params.cipher_mode;
                        custom_job_params.key_size = values->job_params.key_size;
                        custom_test = 1;
                        cipher_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--hash-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], hash_algo_str_map,
                                                  num_hash_algo_str_map);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.hash_alg = values->job_params.hash_alg;
                        custom_test = 1;
                        hash_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--aead-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], aead_algo_str_map,
                                                  num_aead_algo_str_map);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode = values->job_params.cipher_mode;
                        custom_job_params.key_size = values->job_params.key_size;
                        custom_job_params.hash_alg = values->job_params.hash_alg;
                        custom_test = 1;
                        aead_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--job-size") == 0) {
                        /* Try parsing the argument as a range first */
                        i = parse_range((const char *const *) argv, i, argc, job_sizes);
                        if (job_sizes[RANGE_MAX] > JOB_SIZE_TOP) {
                                fprintf(stderr, "Invalid job size %u (max %d)\n",
                                        (unsigned) job_sizes[RANGE_MAX], JOB_SIZE_TOP);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--cipher-iv-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &cipher_iv_size,
                                             sizeof(cipher_iv_size));
                        if (cipher_iv_size > MAX_IV_SIZE) {
                                fprintf(stderr,
                                        "IV size cannot be "
                                        "higher than %d\n",
                                        MAX_IV_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--auth-iv-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &auth_iv_size,
                                             sizeof(auth_iv_size));
                        if (auth_iv_size > MAX_IV_SIZE) {
                                fprintf(stderr,
                                        "IV size cannot be "
                                        "higher than %d\n",
                                        MAX_IV_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--tag-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &auth_tag_size,
                                             sizeof(auth_tag_size));
                        if (auth_tag_size > MAX_DIGEST_SIZE) {
                                fprintf(stderr,
                                        "Tag size cannot be "
                                        "higher than %d\n",
                                        MAX_DIGEST_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--num-jobs") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &max_num_jobs,
                                             sizeof(max_num_jobs));
                        if (max_num_jobs > MAX_NUM_JOBS) {
                                fprintf(stderr,
                                        "Number of jobs cannot be "
                                        "higher than %d\n",
                                        MAX_NUM_JOBS);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--imix") == 0) {
                        imix_enabled = 1;
                } else if (strcmp(argv[i], "--avx-sse") == 0) {
                        is_avx_sse_check_possible = avx_sse_detectability();
                        if (!is_avx_sse_check_possible)
                                fprintf(stderr, "XGETBV not available\n");
                } else if (strcmp(argv[i], "--burst-api") == 0) {
                        burst_api = 1;
                } else if (strcmp(argv[i], "--offset") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &offset,
                                             sizeof(offset));
                } else {
                        usage(argv[0]);
                        return EXIT_FAILURE;
                }

        if (custom_test) {
                if (aead_algo_set && (cipher_algo_set || hash_algo_set)) {
                        fprintf(stderr, "AEAD algorithm cannot be used "
                                        "combined with another cipher/hash "
                                        "algorithm\n");
                        return EXIT_FAILURE;
                }
        }

        if (job_sizes[RANGE_MIN] == 0) {
                fprintf(stderr, "Buffer size cannot be 0 unless only "
                                "an AEAD algorithm is tested\n");
                return EXIT_FAILURE;
        }

        /* detect available architectures and features*/
        if (detect_arch(arch_support, flags) < 0)
                return EXIT_FAILURE;

        /* disable tests depending on instruction sets supported */
        for (arch_id = IMB_ARCH_SSE; arch_id < IMB_ARCH_NUM; arch_id++) {
                if (arch_support[arch_id] == 0) {
                        enc_archs[arch_id] = 0;
                        dec_archs[arch_id] = 0;
                        fprintf(stderr, "%s not supported. Disabling %s tests\n",
                                arch_str_map[arch_id].name, arch_str_map[arch_id].name);
                }
        }

        IMB_MGR *p_mgr = alloc_mb_mgr(flags);

        if (p_mgr == NULL) {
                fprintf(stderr, "Error allocating MB_MGR structure!\n");
                return EXIT_FAILURE;
        }

        uint64_t features = 0;
        const int ret = imb_get_features(p_mgr, &features);

        if (ret != 0) {
                printf("Error retrieving MB_MGR features! %s\n", imb_get_strerror(ret));
                free_mb_mgr(p_mgr);
                return EXIT_FAILURE;
        }

        free_mb_mgr(p_mgr);

        srand(SEED);

        run_tests();

        fprintf(stdout, "All tests passed\n");

        return EXIT_SUCCESS;
}
