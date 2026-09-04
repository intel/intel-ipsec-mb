/**********************************************************************
  Copyright(c) 2021-2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <intel-ipsec-mb.h>
#include "fuzz_common.h"

#define BUFF_SIZE    (32 * 1024 * 1024)
#define MAX_SGL_SEGS 32

int
LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int
LLVMFuzzerInitialize(int *, char ***);

static struct fuzz_args fargs = { 0 };

/**
 * @brief libFuzzer initialization hook. Extracts the application specific
 *        arguments introduced by "--" and hides them from libFuzzer.
 *
 * @param [in,out] argc  Argument count, truncated at the "--" argument
 * @param [in,out] argv  Argument vector
 *
 * @return 0 always
 */
int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
        fuzz_args_init(&fargs);
        return parse_args(argc, argv, &fargs);
}

static void
clamp_lengths(struct IMB_JOB *job, const uint64_t buffsize)
{
        if (job->msg_len_to_cipher_in_bytes > buffsize)
                job->msg_len_to_cipher_in_bytes = buffsize;

        if (job->msg_len_to_hash_in_bytes > buffsize)
                job->msg_len_to_hash_in_bytes = buffsize;

        if (job->cipher_start_src_offset_in_bytes > buffsize)
                job->cipher_start_src_offset_in_bytes = buffsize;

        if (job->hash_start_src_offset_in_bytes > buffsize)
                job->hash_start_src_offset_in_bytes = buffsize;

        if (job->auth_tag_output_len_in_bytes > buffsize)
                job->auth_tag_output_len_in_bytes = buffsize;
}

static void
fill_job_sgl_segments(struct IMB_JOB *job, struct IMB_SGL_IOV *sgl_segs, const int num_sgl_segs,
                      void *buff, const uint64_t buffsize)
{
        for (int i = 0; i < num_sgl_segs; i++) {
                sgl_segs->in = buff;
                sgl_segs->out = buff;
                sgl_segs->len = buffsize;
        }

        job->sgl_io_segs = sgl_segs;
        job->num_sgl_io_segs = (uint64_t) num_sgl_segs;
}

static void
fill_job_data(struct IMB_JOB *job, void *buff)
{
        if (job->src != NULL)
                job->src = (uint8_t *) buff;
        if (job->dst != NULL)
                job->dst = (uint8_t *) buff;
        if (job->enc_keys != NULL)
                job->enc_keys = buff;
        if (job->dec_keys != NULL)
                job->dec_keys = buff;
        if (job->iv != NULL)
                job->iv = (uint8_t *) buff;
        if (job->auth_tag_output != NULL)
                job->auth_tag_output = (uint8_t *) buff;
}

static void
fill_additional_cipher_data(struct IMB_JOB *job, struct IMB_SGL_IOV *sgl_segs,
                            const int num_sgl_segs, void *buff, const uint64_t buffsize)
{
        const IMB_CIPHER_MODE cipherMode = job->cipher_mode;

        switch (cipherMode) {
        case IMB_CIPHER_CCM:
                if (job->u.CCM.aad != NULL)
                        job->u.CCM.aad = buff;
                if (job->u.CCM.aad_len_in_bytes > buffsize)
                        job->u.CCM.aad_len_in_bytes = buffsize;
                break;
        case IMB_CIPHER_GCM:
                if (job->u.GCM.aad != NULL)
                        job->u.GCM.aad = buff;
                if (job->u.GCM.aad_len_in_bytes > buffsize)
                        job->u.GCM.aad_len_in_bytes = buffsize;
                if (job->iv_len_in_bytes > buffsize)
                        job->iv_len_in_bytes = buffsize;
                break;
        case IMB_CIPHER_GCM_SGL:
                if (job->u.GCM.aad != NULL)
                        job->u.GCM.aad = buff;
                if (job->u.GCM.ctx != NULL) {
                        job->u.GCM.ctx = buff;
                }
                if (job->u.GCM.aad_len_in_bytes > buffsize)
                        job->u.GCM.aad_len_in_bytes = buffsize;
                if (job->iv_len_in_bytes > buffsize)
                        job->iv_len_in_bytes = buffsize;
                fill_job_sgl_segments(job, sgl_segs, num_sgl_segs, buff, buffsize);
                break;
        case IMB_CIPHER_CHACHA20_POLY1305:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
                break;
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.ctx != NULL) {
                        job->u.CHACHA20_POLY1305.ctx = buff;
                        job->u.CHACHA20_POLY1305.ctx->remain_ks_bytes &= 63;
                        job->u.CHACHA20_POLY1305.ctx->remain_ct_bytes &= 15;
                }
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
                fill_job_sgl_segments(job, sgl_segs, num_sgl_segs, buff, buffsize);
                break;
        case IMB_CIPHER_AES_NCA5:
        case IMB_CIPHER_ZUC_NCA6:
        case IMB_CIPHER_SNOW5G_NCA4:
                if (job->u.NCA.aad != NULL)
                        job->u.NCA.aad = buff;
                if (job->u.NCA.aad_len_in_bytes > buffsize)
                        job->u.NCA.aad_len_in_bytes = buffsize;
                break;
        default:
                break;
        }
}

static void
fill_additional_hash_data(struct IMB_JOB *job, void *buff, uint64_t buffsize)
{
        const IMB_HASH_ALG hashMode = job->hash_alg;

        switch (hashMode) {
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_MD5:
        case IMB_AUTH_HMAC_SM3:
        case IMB_AUTH_HMAC_SHA3_224:
        case IMB_AUTH_HMAC_SHA3_256:
        case IMB_AUTH_HMAC_SHA3_384:
        case IMB_AUTH_HMAC_SHA3_512:
                if (job->u.HMAC._hashed_auth_key_xor_ipad != NULL)
                        job->u.HMAC._hashed_auth_key_xor_ipad = (uint8_t *) buff;
                if (job->u.HMAC._hashed_auth_key_xor_opad != NULL)
                        job->u.HMAC._hashed_auth_key_xor_opad = (uint8_t *) buff;
                break;
        case IMB_AUTH_AES_XCBC:
                if (job->u.XCBC._k1_expanded != NULL)
                        job->u.XCBC._k1_expanded = (uint32_t *) buff;
                if (job->u.XCBC._k2 != NULL)
                        job->u.XCBC._k2 = (uint8_t *) buff;
                if (job->u.XCBC._k3 != NULL)
                        job->u.XCBC._k3 = (uint8_t *) buff;
                break;
        case IMB_AUTH_AES_CCM:
                if (job->u.CCM.aad != NULL)
                        job->u.CCM.aad = buff;
                if (job->u.CCM.aad_len_in_bytes > buffsize)
                        job->u.CCM.aad_len_in_bytes = buffsize;
                break;
        case IMB_AUTH_AES_CMAC:
        case IMB_AUTH_AES_CMAC_256:
                if (job->u.CMAC._key_expanded != NULL)
                        job->u.CMAC._key_expanded = buff;
                if (job->u.CMAC._skey1 != NULL)
                        job->u.CMAC._skey1 = buff;
                if (job->u.CMAC._skey2 != NULL)
                        job->u.CMAC._skey2 = buff;
                break;
        case IMB_AUTH_ZUC_EIA3:
                if (job->u.ZUC_EIA3._key != NULL)
                        job->u.ZUC_EIA3._key = (uint8_t *) buff;
                if (job->u.ZUC_EIA3._iv != NULL)
                        job->u.ZUC_EIA3._iv = (uint8_t *) buff;
                break;
        case IMB_AUTH_ZUC_NIA6:
        case IMB_AUTH_AES_NIA5:
        case IMB_AUTH_SNOW5G_NIA4:
                if (job->u.NIA._key != NULL)
                        job->u.NIA._key = buff;
                if (job->u.NIA._iv != NULL)
                        job->u.NIA._iv = buff;
                break;
        case IMB_AUTH_AES_NCA5:
        case IMB_AUTH_ZUC_NCA6:
        case IMB_AUTH_SNOW5G_NCA4:
                if (job->u.NCA.aad != NULL)
                        job->u.NCA.aad = buff;
                if (job->u.NCA.aad_len_in_bytes > buffsize)
                        job->u.NCA.aad_len_in_bytes = buffsize;
                break;
        case IMB_AUTH_SNOW3G_UIA2:
                if (job->u.SNOW3G_UIA2._key != NULL)
                        job->u.SNOW3G_UIA2._key = buff;
                if (job->u.SNOW3G_UIA2._iv != NULL)
                        job->u.SNOW3G_UIA2._iv = buff;
                break;
        case IMB_AUTH_KASUMI_UIA1:
                if (job->u.KASUMI_UIA1._key != NULL)
                        job->u.KASUMI_UIA1._key = buff;
                break;
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_AES_GMAC_128:
        case IMB_AUTH_AES_GMAC_192:
        case IMB_AUTH_AES_GMAC_256:
                if (job->u.GMAC._key != NULL)
                        job->u.GMAC._key = buff;
                if (job->u.GMAC._iv != NULL)
                        job->u.GMAC._iv = buff;
                if (job->u.GMAC.iv_len_in_bytes > buffsize)
                        job->u.GMAC.iv_len_in_bytes = buffsize;
                break;
        case IMB_AUTH_GHASH:
                if (job->u.GHASH._key != NULL)
                        job->u.GHASH._key = buff;
                if (job->u.GHASH._init_tag != NULL)
                        job->u.GHASH._init_tag = buff;
                break;
        case IMB_AUTH_POLY1305:
                if (job->u.POLY1305._key != NULL)
                        job->u.POLY1305._key = buff;
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
                break;
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.ctx != NULL) {
                        job->u.CHACHA20_POLY1305.ctx = buff;
                        job->u.CHACHA20_POLY1305.ctx->remain_ks_bytes &= 63;
                        job->u.CHACHA20_POLY1305.ctx->remain_ct_bytes &= 15;
                }
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes > buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes = buffsize;
                break;
        case IMB_AUTH_GCM_SGL:
                if (job->u.GCM.aad != NULL)
                        job->u.GCM.aad = buff;
                if (job->u.GCM.ctx != NULL) {
                        job->u.GCM.ctx = buff;
                }
                if (job->u.GCM.aad_len_in_bytes > buffsize)
                        job->u.GCM.aad_len_in_bytes = buffsize;
                if (job->iv_len_in_bytes > buffsize)
                        job->iv_len_in_bytes = buffsize;
                break;
        default:
                break;
        }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize)
{
        static IMB_MGR *p_mgr = NULL;
        const unsigned num_jobs = fargs.num_jobs;
        const unsigned key_len = fargs.key_length;
        const IMB_CIPHER_DIRECTION dir = fargs.dir;
        unsigned i;
        const size_t buffsize = BUFF_SIZE;

        /* Setting minimum datasize to always fill job structure  */
        if (dataSize < sizeof(IMB_JOB))
                return -1;

        if (num_jobs > IMB_MAX_BURST_SIZE || num_jobs == 0 || key_len == 0)
                return 0;

        /* allocate multi-buffer manager */
        if (allocate_init_mb_mgr(&p_mgr, &fargs) != 0)
                return 0;

        IMB_JOB *job = NULL;
        /* create job array */

        if (fargs.api == FUZZ_API_JOB) {
                for (i = 0; i < num_jobs; i++) {
                        IMB_HASH_ALG hash = fargs.hash;
                        IMB_CIPHER_MODE cipher = fargs.cipher;

                        job = IMB_GET_NEXT_JOB(p_mgr);
                        memcpy(job, data, sizeof(*job));

                        /* if specific hash/cipher not selected then keep it random */
                        if (hash == 0)
                                job->hash_alg %= (IMB_AUTH_NUM + 1);
                        else
                                job->hash_alg = hash;
                        if (cipher == 0)
                                job->cipher_mode %= (IMB_CIPHER_NUM + 1);
                        else
                                job->cipher_mode = cipher;

                        clamp_lengths(job, buffsize);

                        static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);
                        static struct IMB_SGL_IOV sgl_segs[MAX_SGL_SEGS];

                        fill_job_data(job, buff);
                        fill_additional_cipher_data(job, sgl_segs, MAX_SGL_SEGS, buff, buffsize);
                        fill_additional_hash_data(job, buff, buffsize);
                        IMB_SUBMIT_JOB(p_mgr);
                }
        } else if (fargs.api == FUZZ_API_BURST) {
                IMB_JOB *jobs[IMB_MAX_BURST_SIZE] = { NULL };

                while (IMB_GET_NEXT_BURST(p_mgr, num_jobs, jobs) < (uint32_t) num_jobs)
                        IMB_FLUSH_BURST(p_mgr, num_jobs, jobs);

                for (i = 0; i < num_jobs; i++) {
                        IMB_HASH_ALG hash = fargs.hash;
                        IMB_CIPHER_MODE cipher = fargs.cipher;

                        job = jobs[i];
                        memcpy(job, data, sizeof(*job));
                        /* if specific hash/cipher not selected then keep it random */
                        if (hash == 0)
                                job->hash_alg %= (IMB_AUTH_NUM + 1);
                        else
                                job->hash_alg = hash;

                        if (cipher == 0)
                                job->cipher_mode %= (IMB_CIPHER_NUM + 1);
                        else
                                job->cipher_mode = cipher;

                        clamp_lengths(job, buffsize);

                        static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);
                        static struct IMB_SGL_IOV sgl_segs[MAX_SGL_SEGS];

                        fill_job_data(job, buff);
                        fill_additional_cipher_data(job, sgl_segs, MAX_SGL_SEGS, buff, buffsize);
                        fill_additional_hash_data(job, buff, buffsize);
                }

                IMB_SUBMIT_BURST(p_mgr, num_jobs, jobs);
        } else if (fargs.api == FUZZ_API_CIPHER_BURST) {
                IMB_JOB jobs[IMB_MAX_BURST_SIZE] = { 0 };
                IMB_CIPHER_MODE cipher = fargs.cipher;

                for (i = 0; i < num_jobs; i++) {
                        job = &jobs[i];
                        memcpy(job, data, sizeof(*job));

                        /* if specific cipher not selected then keep it random */
                        if (cipher == 0)
                                cipher = (job->cipher_mode % (IMB_CIPHER_NUM + 1));

                        job->cipher_mode = cipher;

                        clamp_lengths(job, buffsize);
                        static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);
                        static struct IMB_SGL_IOV sgl_segs[MAX_SGL_SEGS];

                        fill_job_data(job, buff);
                        fill_additional_cipher_data(job, sgl_segs, MAX_SGL_SEGS, buff, buffsize);
                }

                IMB_SUBMIT_CIPHER_BURST(p_mgr, jobs, num_jobs, cipher, dir, key_len);
        } else if (fargs.api == FUZZ_API_HASH_BURST) {
                IMB_JOB jobs[IMB_MAX_BURST_SIZE] = { 0 };
                IMB_HASH_ALG hash = fargs.hash;

                for (i = 0; i < num_jobs; i++) {
                        job = &jobs[i];
                        memcpy(job, data, sizeof(*job));

                        /* if specific hash not selected then keep it random */
                        if (hash == 0)
                                hash = (job->hash_alg % (IMB_AUTH_NUM + 1));

                        job->hash_alg = hash;

                        clamp_lengths(job, buffsize);

                        static DECLARE_ALIGNED(uint8_t buff[2 * BUFF_SIZE], 64);

                        fill_job_data(job, buff);
                        fill_additional_hash_data(job, buff, buffsize);
                }

                IMB_SUBMIT_HASH_BURST(p_mgr, jobs, num_jobs, hash);
        }

        return 0;
}
