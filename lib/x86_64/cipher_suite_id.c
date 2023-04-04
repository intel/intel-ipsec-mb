/*******************************************************************************
  Copyright (c) 2023, Intel Corporation

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
#include "include/error.h"
#include "include/arch_x86_64.h"

IMB_DLL_EXPORT uint32_t imb_set_session(IMB_MGR *state, IMB_JOB *job)
{
        struct {
                uint16_t key_len;
                uint16_t hash_alg;
                uint16_t cipher_mode;
                uint16_t cipher_dir;
                uint64_t counter;
        } extract;
        static uint64_t counter = 1;

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return 0;
        }
        if (job == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_JOB);
                return 0;
        }
        imb_set_errno(state, 0);
#endif
        /* Fill in suite_id[] structure in \a job */
        state->set_suite_id(state, job);

        /**
         * Calculate and set session_id in \a job
         * Set up extract structure:
         * - collect session specific data
         * - plus counter value (secures different ID for the same
         *   cipher suite params)
         * Session ID is CRC calculated on the extract structure.
         */
        extract.key_len = (uint16_t) job->key_len_in_bytes;
        extract.hash_alg = (uint16_t) job->hash_alg;
        extract.cipher_mode = (uint16_t) job->cipher_mode ;
        extract.cipher_dir = (uint16_t) job->cipher_direction;
        extract.counter = atomic_uint64_inc(&counter);

        const uint32_t id =
                IMB_CRC32_WIMAX_OFDMA_DATA(state, &extract, sizeof(extract));

        job->session_id = id;
        return id;
}
