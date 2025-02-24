/*******************************************************************************
  Copyright (c) 2025, Intel Corporation

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

__forceinline IMB_JOB *
submit_aes_nia5_job(IMB_JOB *job)
{
        DECLARE_ALIGNED(uint8_t HQP[3 * 16], 64);
        DECLARE_ALIGNED(uint8_t digest[16], 16) = { 0 };
        struct gcm_key_data gdata_key;
        uint8_t *H = HQP;
        uint8_t *Q = &HQP[16];
        uint8_t *P = &HQP[16 * 2];

        /* Generate H, Q, P keys */
        GENERATE_HQP_AES(job->u.AES_NIA5._expanded_auth_key, job->u.AES_NIA5._iv, HQP);

        /* Precompute hash keys from H */
        POLYVAL_PRE(H, &gdata_key);
        /* Digest message bytes */
        POLYVAL(&gdata_key, job->src, job->msg_len_to_hash_in_bytes, digest);

        /* XOR 16-byte lengths array with previous digest and hash with Q */
        uint8_t lengths[16] = { 0 };
        const uint64_t msg_len_in_bits = job->msg_len_to_hash_in_bytes * 8;

        memcpy(&lengths[8], &msg_len_in_bits, 8);

        /* TODO: No need for whole precompute process */
        POLYVAL_PRE(Q, &gdata_key);
        POLYVAL(&gdata_key, lengths, 16, digest);

        /* XOR digest with P */
        for (int i = 0; i < 16; i++)
                digest[i] ^= P[i];

        job->status |= IMB_STATUS_COMPLETED_AUTH;
        memcpy(job->auth_tag_output, digest, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
        clear_mem(HQP, sizeof(HQP));
        clear_mem(&gdata_key, sizeof(struct gcm_key_data));
#endif
        return job;
}

#endif /* JOB_API_WIRELESS_NXA_H */
