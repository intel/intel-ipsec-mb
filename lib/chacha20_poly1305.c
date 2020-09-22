/*******************************************************************************
  Copyright (c) 2020, Intel Corporation

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

#include <stdlib.h>
#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "include/clear_regs_mem.h"
#include "include/chacha20_poly1305.h"

__forceinline
IMB_JOB *aead_chacha20_poly1305(IMB_JOB *job, const int arch)
{
        uint8_t poly_key[32];
        uint64_t hash[3] = {0, 0, 0};
        const uint64_t aad_len = job->u.CHACHA20_POLY1305.aad_len_in_bytes;
        const uint64_t hash_len = job->msg_len_to_hash_in_bytes;
        uint64_t last[2];

        /* generate key for authentication */
        if (arch == 0)
                poly1305_key_gen_sse(job, poly_key);
        else
                poly1305_key_gen_avx(job, poly_key);

        /* Calculate hash over AAD */
        poly1305_aead_update(job->u.CHACHA20_POLY1305.aad, aad_len,
                             hash, poly_key);

        if (job->cipher_direction == IMB_DIR_DECRYPT) {
                /* compute hash first on decrypt */
                poly1305_aead_update(job->src +
                                     job->hash_start_src_offset_in_bytes,
                                     hash_len, hash, poly_key);
        }

        /*
         * On encrypt, cipher first and then hash
         * On decrypt, hash first and then cipher
         */
        if (arch == 0)
                submit_job_chacha20_enc_dec_sse(job);
        else if (arch == 1)
                submit_job_chacha20_enc_dec_avx(job);
        else if (arch == 3)
                submit_job_chacha20_enc_dec_avx512(job);

        if (job->cipher_direction == IMB_DIR_ENCRYPT) {
                /* compute hash after cipher on encrypt */
                poly1305_aead_update(job->dst, hash_len, hash, poly_key);
        }

        /*
         * Construct extra block with AAD and message lengths for
         * authentication
         */
        last[0] = aad_len;
        last[1] = hash_len;
        poly1305_aead_update(last, sizeof(last), hash, poly_key);

        /* Finalize AEAD Poly1305 (final reduction and +S) */
        poly1305_aead_complete(hash, poly_key, job->auth_tag_output);

#ifdef SAFE_DATA
        clear_mem(poly_key, sizeof(poly_key));
#endif
        job->status |= STS_COMPLETED;
        return job;
}


IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_sse(IMB_JOB *job)
{
        return aead_chacha20_poly1305(job, 0 /* SSE */);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_avx(IMB_JOB *job)
{
        return aead_chacha20_poly1305(job, 1 /* AVX */);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_avx512(IMB_JOB *job)
{
        return aead_chacha20_poly1305(job, 3 /* AVX512 */);
}
