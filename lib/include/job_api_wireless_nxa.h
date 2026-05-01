/*******************************************************************************
  Copyright (c) 2025-2026, Intel Corporation

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
*******************************************************************************/

#include "intel-ipsec-mb.h"

#ifndef JOB_API_WIRELESS_NXA_H
#define JOB_API_WIRELESS_NXA_H

void
generate_hqp_snow5g_sse(const uint8_t *key, const uint8_t *iv, uint8_t *hqp, uint8_t *state);
void
snow5g_nca4_sse(IMB_JOB *job, uint8_t *state);

static const uint8_t zero_low_4B_mask[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                              0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };

__forceinline IMB_JOB *
submit_job_aes_nea5(IMB_JOB *job)
{
        uint8_t iv[16];
        __m128i iv_reg = _mm_loadu_si128((const __m128i *) job->iv);
        iv_reg = _mm_and_si128(iv_reg, _mm_loadu_si128((const __m128i *) zero_low_4B_mask));

        _mm_storeu_si128((__m128i *) iv, iv_reg);
        AES_CTR_256(job->src + job->cipher_start_src_offset_in_bytes, iv, job->enc_keys, job->dst,
                    job->msg_len_to_cipher_in_bytes, 16);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;

        return job;
}

__forceinline IMB_JOB *
submit_aes_nia5_job(IMB_JOB *job)
{
        DECLARE_ALIGNED(uint8_t HQP[3 * 16], 64);
        DECLARE_ALIGNED(uint8_t digest[16], 16) = { 0 };
        const uint8_t *msg = job->src + job->hash_start_src_offset_in_bytes;

        /* Generate H, Q, P keys */
        GENERATE_HQP_AES(job->u.NIA._key, job->u.NIA._iv, HQP);

        NIA_MSG(digest, HQP, msg, job->msg_len_to_hash_in_bytes);

        job->status |= IMB_STATUS_COMPLETED_AUTH;
        memcpy(job->auth_tag_output, digest, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
        clear_mem(HQP, sizeof(HQP));
#endif
        return job;
}

__forceinline IMB_JOB *
submit_aes_nca5_job(IMB_JOB *job, IMB_CIPHER_DIRECTION cipher_dir)
{
        DECLARE_ALIGNED(uint8_t HQP[3 * 16], 64);
        DECLARE_ALIGNED(uint8_t digest[16], 16) = { 0 };
        const uint8_t *msg = job->src + job->cipher_start_src_offset_in_bytes;

        /* Generate H, Q, P keys */
        GENERATE_HQP_AES(job->enc_keys, job->iv, HQP);

        /* Prepare IV for AES-CTR */
        uint8_t iv[16];

        __m128i iv_reg = _mm_loadu_si128((const __m128i *) job->iv);
        iv_reg = _mm_and_si128(iv_reg, _mm_loadu_si128((const __m128i *) zero_low_4B_mask));

        _mm_storeu_si128((__m128i *) iv, iv_reg);
        if (cipher_dir == IMB_DIR_ENCRYPT) {
                /* Encrypt plaintext */
                AES_CTR_256(msg, iv, job->enc_keys, job->dst, job->msg_len_to_cipher_in_bytes, 16);

                /* Digest ciphertext */
                NCA_MSG(digest, HQP, job->dst, job->msg_len_to_cipher_in_bytes, job->u.NCA.aad,
                        job->u.NCA.aad_len_in_bytes);
        } else { /* Decrypt */
                /* Digest ciphertext */
                NCA_MSG(digest, HQP, msg, job->msg_len_to_cipher_in_bytes, job->u.NCA.aad,
                        job->u.NCA.aad_len_in_bytes);

                /* Decrypt ciphertext (assumes last 4 bytes of 16-byte IV as 0) */
                AES_CTR_256(msg, iv, job->enc_keys, job->dst, job->msg_len_to_cipher_in_bytes, 16);
        }

        job->status |= IMB_STATUS_COMPLETED;
        memcpy(job->auth_tag_output, digest, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
        clear_mem(HQP, sizeof(HQP));
#endif
        return job;
}

__forceinline IMB_JOB *
submit_snow5g_nia4_job(IMB_JOB *job)
{
        DECLARE_ALIGNED(uint8_t HQP[3 * 16], 64);
        DECLARE_ALIGNED(uint8_t digest[16], 16) = { 0 };
        const uint8_t *msg = job->src + job->hash_start_src_offset_in_bytes;

        /* Generate H, Q, P keys for SNOW5G NIA4 */
        GENERATE_HQP_SNOW5G(job->u.NIA._key, job->u.NIA._iv, HQP, NULL);

        NIA_MSG(digest, HQP, msg, job->msg_len_to_hash_in_bytes);

        job->status |= IMB_STATUS_COMPLETED_AUTH;
        memcpy(job->auth_tag_output, digest, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
        clear_mem(HQP, sizeof(HQP));
#endif
        return job;
}

__forceinline IMB_JOB *
submit_snow5g_nca4_job(IMB_JOB *job, IMB_CIPHER_DIRECTION cipher_dir)
{
        DECLARE_ALIGNED(uint8_t HQP[3 * 16], 64);
        DECLARE_ALIGNED(uint8_t digest[16], 16) = { 0 };
        DECLARE_ALIGNED(uint8_t state[10 * 16], 16);

        const uint8_t *msg = job->src + job->cipher_start_src_offset_in_bytes;

        GENERATE_HQP_SNOW5G(job->enc_keys, job->iv, HQP, state);

        if (cipher_dir == IMB_DIR_ENCRYPT) {
                SNOW5G_NCA4(job, state);
                /* Digest ciphertext */
                NCA_MSG(digest, HQP, job->dst, job->msg_len_to_cipher_in_bytes, job->u.NCA.aad,
                        job->u.NCA.aad_len_in_bytes);
        } else {
                /* Digest ciphertext */
                NCA_MSG(digest, HQP, msg, job->msg_len_to_cipher_in_bytes, job->u.NCA.aad,
                        job->u.NCA.aad_len_in_bytes);
                SNOW5G_NCA4(job, state);
        }

        memcpy(job->auth_tag_output, digest, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
        clear_mem(state, sizeof(state));
        clear_mem(HQP, sizeof(HQP));
#endif
        job->status |= IMB_STATUS_COMPLETED;
        return job;
}

#endif /* JOB_API_WIRELESS_NXA_H */
