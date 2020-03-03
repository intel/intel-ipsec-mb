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

#ifndef _CHACHA20_H_
#define _CHACHA20_H_
#include <stdint.h>

void
chacha20_enc_dec_basic(const void *input, void *output, const uint64_t size,
                       const void *ks, const void *iv);

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_CHACHA20_ENC_DEC_SCALAR(JOB_AES_HMAC *job)
{
        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        chacha20_enc_dec_basic(job->src + job->cipher_start_src_offset_in_bytes,
                               job->dst,
                               job->msg_len_to_cipher_in_bytes,
                               job->aes_enc_key_expanded,
                               job->iv);
        job->status |= STS_COMPLETED_AES;
        return job;
}

#endif /* _CHACHA20_H_ */
