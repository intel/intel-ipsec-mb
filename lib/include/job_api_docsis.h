/*******************************************************************************
  Copyright (c) 2022, Intel Corporation

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
#include "include/docsis_common.h"

#ifndef JOB_API_DOCSIS_H
#define JOB_API_DOCSIS_H

__forceinline
IMB_JOB *
submit_docsis_enc_job(IMB_MGR *state, IMB_JOB *job)
{
        if (16 == job->key_len_in_bytes) {
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis128_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_CRC_ENC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis128_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_ENC(p_ooo, job);
                }
        } else { /* 32 */
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis256_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_CRC_ENC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis256_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_ENC(p_ooo, job);
                }
        }
}

__forceinline
IMB_JOB *
flush_docsis_enc_job(IMB_MGR *state, IMB_JOB *job)
{
        if (16 == job->key_len_in_bytes) {
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis128_crc32_sec_ooo;

                        return FLUSH_JOB_DOCSIS128_SEC_CRC_ENC(p_ooo);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis128_sec_ooo;

                        return FLUSH_JOB_DOCSIS128_SEC_ENC(p_ooo);
                }
        } else { /* 32 */
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis256_crc32_sec_ooo;

                        return FLUSH_JOB_DOCSIS256_SEC_CRC_ENC(p_ooo);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis256_sec_ooo;

                        return FLUSH_JOB_DOCSIS256_SEC_ENC(p_ooo);
                }
        }
}

__forceinline
IMB_JOB *
submit_docsis_dec_job(IMB_MGR *state, IMB_JOB *job)
{
        if (16 == job->key_len_in_bytes) {
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis128_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_CRC_DEC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis128_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_DEC(p_ooo, job);
                }
        } else { /* 32 */
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis256_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_CRC_DEC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo =
                                state->docsis256_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_DEC(p_ooo, job);
                }
        }
}

#endif /* JOB_API_DOCSIS_H */
