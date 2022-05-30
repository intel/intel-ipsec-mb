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

#ifndef JOB_API_SNOWV_H
#define JOB_API_SNOWV_H

__forceinline
IMB_JOB *
submit_snow_v_aead_job(IMB_MGR *state, IMB_JOB *job)
{
        struct gcm_key_data gdata_key;
        imb_uint128_t *auth = (imb_uint128_t *) job->auth_tag_output;
        imb_uint128_t temp;
        imb_uint128_t hkey_endpad[2];

        temp.low = BSWAP64((job->u.SNOW_V_AEAD.aad_len_in_bytes << 3));
        temp.high = BSWAP64((job->msg_len_to_cipher_in_bytes << 3));

        /* if hkey_endpad[1].high == 0:
         *      SUBMIT_JOB_SNOW_V_AEAD does enc/decrypt operation
         *      and fills hkey_endpad with first 2 keystreams
         * else
         *      SUBMIT_JOB_SNOW_V_AEAD fills hkey_endpad with first
         *      2 keystreams (no operations on src vector are done)
         */
        if(job->cipher_direction == IMB_DIR_ENCRYPT)
                hkey_endpad[1].high = 0;
        else
                hkey_endpad[1].high = 1;

        job->u.SNOW_V_AEAD.reserved = hkey_endpad;
        job = SUBMIT_JOB_SNOW_V_AEAD(job);

        memset(auth, 0, sizeof(imb_uint128_t));

        /* GHASH key H */
        IMB_GHASH_PRE(state, (void *)hkey_endpad,  &gdata_key);

        /* push AAD into GHASH */
        IMB_GHASH(state, &gdata_key, job->u.SNOW_V_AEAD.aad,
                  job->u.SNOW_V_AEAD.aad_len_in_bytes,
                  (void *)auth, sizeof(imb_uint128_t));

        if (job->cipher_direction == IMB_DIR_ENCRYPT)
                IMB_GHASH(state, &gdata_key, job->dst,
                          job->msg_len_to_cipher_in_bytes,
                          (void *)auth, sizeof(imb_uint128_t));
        else
                IMB_GHASH(state, &gdata_key, job->src,
                          job->msg_len_to_cipher_in_bytes,
                          (void *)auth, sizeof(imb_uint128_t));

        IMB_GHASH(state, &gdata_key, (void *)&temp, sizeof(temp),
                  (void *)auth, sizeof(imb_uint128_t));

        /* The resulting AuthTag */
        auth->low = auth->low ^ hkey_endpad[1].low;
        auth->high = auth->high ^ hkey_endpad[1].high;

        if (job->cipher_direction == IMB_DIR_DECRYPT) {
                hkey_endpad[1].high = 0;
                job = SUBMIT_JOB_SNOW_V_AEAD(job);
        }
        return job;
}

#endif /* JOB_API_SNOWV_H */
