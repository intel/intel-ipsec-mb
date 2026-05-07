/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

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
#include "include/zuc_internal.h"
#include "intel-ipsec-mb.h"
#include "include/error.h"

void
zuc_eea3_n_buffer(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                  const void *const pBufferIn[], void *pBufferOut[], const uint32_t length[],
                  const uint32_t numBuffers)
{
        IMB_JOB *job;
        uint32_t i;

#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (mgr == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (pIv == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_IV);
                return;
        }
        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (pBufferOut == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_DST);
                return;
        }
        if (length == NULL) {
                imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                return;
        }
        for (i = 0; i < numBuffers; i++) {
                if (pKey[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                        return;
                }
                if (pIv[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_IV);
                        return;
                }
                if (pBufferIn[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                        return;
                }
                if (pBufferOut[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_DST);
                        return;
                }
                if (length[i] < ZUC_MIN_BYTELEN || length[i] > ZUC_MAX_BYTELEN) {
                        imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                        return;
                }
        }
#endif
        if (IMB_FLUSH_JOB(mgr) != NULL) {
                imb_set_errno(mgr, IMB_ERR_QUEUE_SPACE);
                return;
        }

        uint32_t jobs_returned = 0;

        for (i = 0; i < numBuffers; i++) {
                job = IMB_GET_NEXT_JOB(mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_ZUC_EEA3;
                job->enc_keys = pKey[i];
                job->key_len_in_bytes = IMB_ZUC_KEY_LEN_IN_BYTES;
                job->iv = (const uint8_t *) pIv[i];
                job->iv_len_in_bytes = IMB_ZUC_IV_LEN_IN_BYTES;
                job->src = (const uint8_t *) pBufferIn[i];
                job->dst = (uint8_t *) pBufferOut[i];
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = length[i];
                job->hash_alg = IMB_AUTH_NULL;

                job = IMB_SUBMIT_JOB(mgr);
                if (job != NULL)
                        jobs_returned++;
        }

        while (IMB_FLUSH_JOB(mgr) != NULL)
                jobs_returned++;

        if (jobs_returned != numBuffers)
                imb_set_errno(mgr, IMB_ERR_NULL_JOB);
}

void
zuc_eia3_n_buffer(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                  const void *const pBufferIn[], const uint32_t lengthInBits[], uint32_t *pMacI[],
                  const uint32_t numBuffers)
{
        IMB_JOB *job;
        uint32_t i;

#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (mgr == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (pIv == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_IV);
                return;
        }
        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (pMacI == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                return;
        }
        if (lengthInBits == NULL) {
                imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                return;
        }
        for (i = 0; i < numBuffers; i++) {
                if (pKey[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                        return;
                }
                if (pIv[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_IV);
                        return;
                }
                if (pBufferIn[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                        return;
                }
                if (pMacI[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                        return;
                }
                if (lengthInBits[i] < ZUC_MIN_BITLEN || lengthInBits[i] > ZUC_MAX_BITLEN) {
                        imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                        return;
                }
        }
#endif
        if (IMB_FLUSH_JOB(mgr) != NULL) {
                imb_set_errno(mgr, IMB_ERR_QUEUE_SPACE);
                return;
        }

        uint32_t jobs_returned = 0;

        for (i = 0; i < numBuffers; i++) {
                job = IMB_GET_NEXT_JOB(mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->key_len_in_bytes = IMB_ZUC_KEY_LEN_IN_BYTES;
                job->hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN;
                job->src = (const uint8_t *) pBufferIn[i];
                job->u.ZUC_EIA3._key = (const uint8_t *) pKey[i];
                job->u.ZUC_EIA3._iv = (const uint8_t *) pIv[i];
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bits = lengthInBits[i];
                job->auth_tag_output = (uint8_t *) pMacI[i];
                job->auth_tag_output_len_in_bytes = IMB_ZUC_DIGEST_LEN_IN_BYTES;

                job = IMB_SUBMIT_JOB(mgr);
                if (job != NULL)
                        jobs_returned++;
        }

        while (IMB_FLUSH_JOB(mgr) != NULL)
                jobs_returned++;

        if (jobs_returned != numBuffers)
                imb_set_errno(mgr, IMB_ERR_NULL_JOB);
}