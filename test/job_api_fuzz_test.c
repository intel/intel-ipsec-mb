/**********************************************************************
  Copyright(c) 2021, Intel Corporation All rights reserved.

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
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <intel-ipsec-mb.h>

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

static int custom_op(struct IMB_JOB *job)
{
        (void) job;
        return 0;
}

static void clamp_lengths(struct IMB_JOB *job, const uint64_t buffsize)
{
        if (job->msg_len_to_cipher_in_bytes > buffsize)
                job->msg_len_to_cipher_in_bytes = buffsize;

        if (job->msg_len_to_hash_in_bytes > buffsize)
                job->msg_len_to_hash_in_bytes = buffsize;

        if (job->cipher_start_src_offset_in_bytes > buffsize)
                job->cipher_start_src_offset_in_bytes = buffsize;

        if (job->hash_start_src_offset_in_bytes > buffsize)
                job->hash_start_src_offset_in_bytes = buffsize;
}

static void fill_job_data(struct IMB_JOB *job, void *buff)
{
        if (job->src != NULL)
                job->src = (uint8_t *)buff;
        if (job->dst != NULL)
                job->dst = (uint8_t *)buff;
        if (job->enc_keys != NULL)
                job->enc_keys = buff;
        if (job->dec_keys != NULL)
                job->dec_keys = buff;
        if (job->iv != NULL)
                job->iv = (uint8_t *)buff;
        if (job->auth_tag_output != NULL)
                job->auth_tag_output = (uint8_t *)buff;
}

static void fill_additional_cipher_data(struct IMB_JOB *job,
                                        void *buff, const uint64_t buffsize)
{
        const IMB_CIPHER_MODE cipherMode = job->cipher_mode;

        switch (cipherMode) {
        case IMB_CIPHER_CUSTOM:
                job->cipher_func = custom_op;
                break;
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
                        job->u.GCM.ctx->partial_block_length &= 15;
                }
                if (job->u.GCM.aad_len_in_bytes > buffsize)
                        job->u.GCM.aad_len_in_bytes = buffsize;
                if (job->iv_len_in_bytes > buffsize)
                        job->iv_len_in_bytes = buffsize;
                break;
        case IMB_CIPHER_CHACHA20_POLY1305:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes >
                    buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes =
                                buffsize;
                break;
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.ctx != NULL) {
                        job->u.CHACHA20_POLY1305.ctx = buff;
                        job->u.CHACHA20_POLY1305.ctx->remain_ks_bytes &= 63;
                        job->u.CHACHA20_POLY1305.ctx->remain_ct_bytes &= 15;
                }
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes >
                    buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes =
                                buffsize;
                break;
        case IMB_CIPHER_SNOW_V_AEAD:
                if (job->u.SNOW_V_AEAD.aad != NULL)
                        job->u.SNOW_V_AEAD.aad = buff;
                if (job->u.SNOW_V_AEAD.reserved != NULL)
                        job->u.SNOW_V_AEAD.reserved = buff;
                if (job->u.SNOW_V_AEAD.aad_len_in_bytes >
                    buffsize)
                        job->u.SNOW_V_AEAD.aad_len_in_bytes =
                                buffsize;
                break;
        case IMB_CIPHER_CBCS_1_9:
                if (job->cipher_fields.CBCS.next_iv != NULL)
                        job->cipher_fields.CBCS.next_iv = buff;
                break;
        default:
                break;
        }
}

static void fill_additional_hash_data(struct IMB_JOB *job,
                                      void *buff, uint64_t buffsize)
{
        const IMB_HASH_ALG hashMode = job->hash_alg;

        switch (hashMode) {
        case IMB_AUTH_CUSTOM:
                job->hash_func = custom_op;
                break;
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_MD5:
                if (job->u.HMAC._hashed_auth_key_xor_ipad != NULL)
                        job->u.HMAC._hashed_auth_key_xor_ipad = (uint8_t *)buff;
                if (job->u.HMAC._hashed_auth_key_xor_opad != NULL)
                        job->u.HMAC._hashed_auth_key_xor_opad = (uint8_t *)buff;
                break;
        case IMB_AUTH_AES_XCBC:
                if (job->u.XCBC._k1_expanded != NULL)
                        job->u.XCBC._k1_expanded = (uint32_t *)buff;
                if (job->u.XCBC._k2 != NULL)
                        job->u.XCBC._k2 = (uint8_t *)buff;
                if (job->u.XCBC._k3 != NULL)
                        job->u.XCBC._k3 = (uint8_t *)buff;
                break;
        case IMB_AUTH_AES_CCM:
                if (job->u.CCM.aad != NULL)
                        job->u.CCM.aad = buff;
                if (job->u.CCM.aad_len_in_bytes > buffsize)
                        job->u.CCM.aad_len_in_bytes = buffsize;
                break;
        case IMB_AUTH_AES_CMAC:
        case IMB_AUTH_AES_CMAC_BITLEN:
        case IMB_AUTH_AES_CMAC_256:
                if (job->u.CMAC._key_expanded != NULL)
                        job->u.CMAC._key_expanded = buff;
                if (job->u.CMAC._skey1 != NULL)
                        job->u.CMAC._skey1 = buff;
                if (job->u.CMAC._skey2 != NULL)
                        job->u.CMAC._skey2 = buff;
                break;
        case IMB_AUTH_ZUC_EIA3_BITLEN:
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
                if (job->u.ZUC_EIA3._key != NULL)
                        job->u.ZUC_EIA3._key = (uint8_t *)buff;
                if (job->u.ZUC_EIA3._iv != NULL)
                        job->u.ZUC_EIA3._iv = (uint8_t *)buff;
                break;
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
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
        case IMB_AUTH_POLY1305:
                if (job->u.POLY1305._key != NULL)
                        job->u.POLY1305._key = buff;
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes >
                    buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes =
                                buffsize;
                break;
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
                if (job->u.CHACHA20_POLY1305.aad != NULL)
                        job->u.CHACHA20_POLY1305.aad = buff;
                if (job->u.CHACHA20_POLY1305.ctx != NULL) {
                        job->u.CHACHA20_POLY1305.ctx = buff;
                        job->u.CHACHA20_POLY1305.ctx->remain_ks_bytes &= 63;
                        job->u.CHACHA20_POLY1305.ctx->remain_ct_bytes &= 15;
                }
                if (job->u.CHACHA20_POLY1305.aad_len_in_bytes >
                    buffsize)
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes =
                                buffsize;
                 break;
        case IMB_AUTH_SNOW_V_AEAD:
                if (job->u.SNOW_V_AEAD.aad != NULL)
                        job->u.SNOW_V_AEAD.aad = buff;
                if (job->u.SNOW_V_AEAD.aad_len_in_bytes >
                    buffsize)
                        job->u.SNOW_V_AEAD.aad_len_in_bytes =
                                buffsize;
                break;
        case IMB_AUTH_GCM_SGL:
                if (job->u.GCM.aad != NULL)
                        job->u.GCM.aad = buff;
                if (job->u.GCM.ctx != NULL) {
                        job->u.GCM.ctx = buff;
                        job->u.GCM.ctx->partial_block_length &= 15;
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize)
{
        IMB_MGR *p_mgr = NULL;
        IMB_ARCH arch;
        unsigned i;
        const unsigned num_jobs = 20;
        const size_t buffsize = (32*1024*1024);

        /* Setting minimum datasize to always fill job structure  */
        if (dataSize < sizeof(IMB_JOB))
                return 0;

        /* allocate multi-buffer manager */
        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                printf("Error allocating MB_MGR structure!\n");
                return EXIT_FAILURE;
        }

        init_mb_mgr_auto(p_mgr, &arch);
        IMB_JOB *job = NULL;

        for (i = 0; i < num_jobs; i++) {
                void *buff;

                job = IMB_GET_NEXT_JOB(p_mgr);
                memcpy(job, data, sizeof(*job));
                job->cipher_mode %= (IMB_CIPHER_NUM + 1);
                job->hash_alg %= (IMB_AUTH_NUM + 1);
                clamp_lengths(job, buffsize);

                if (posix_memalign((void **)&buff, 64, (2*buffsize)))
                        goto end;

                fill_job_data(job, buff);
                fill_additional_cipher_data(job, buff, buffsize);
                fill_additional_hash_data(job, buff, buffsize);
                job = IMB_SUBMIT_JOB(p_mgr);

                int err = imb_get_errno(p_mgr);
                /*
                 * If error in submission free the buff.
                 * Else if submission was successful and we
                 * got a job back, then free buffer associated
                 * with returned job
                 */
                if (err != 0)
                        free(buff);
                else if (job != NULL)
                        free(job->dst);
        }
 end:

        while ((job = IMB_FLUSH_JOB(p_mgr)) != NULL)
                free(job->dst);

        free_mb_mgr(p_mgr);
        return 0;
}
