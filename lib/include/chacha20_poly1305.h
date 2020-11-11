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

#ifndef IMB_CHACHA20POLY1305_H
#define IMB_CHACHA20POLY1305_H

#include "intel-ipsec-mb.h"

/* new internal API's */
IMB_JOB *aead_chacha20_poly1305_sse(IMB_JOB *job);
IMB_JOB *aead_chacha20_poly1305_avx(IMB_JOB *job);
IMB_JOB *aead_chacha20_poly1305_avx2(IMB_JOB *job);
IMB_JOB *aead_chacha20_poly1305_avx512(IMB_JOB *job);

/* external symbols needed to implement the above */
IMB_JOB *submit_job_chacha20_enc_dec_sse(IMB_JOB *);
IMB_JOB *submit_job_chacha20_enc_dec_avx(IMB_JOB *);
IMB_JOB *submit_job_chacha20_enc_dec_avx2(IMB_JOB *);
IMB_JOB *submit_job_chacha20_enc_dec_avx512(IMB_JOB *);
IMB_JOB *submit_job_chacha20_poly_enc_avx512(IMB_JOB *, void *poly_key);

void poly1305_key_gen_sse(const IMB_JOB *job, void *key);
void poly1305_key_gen_avx(const IMB_JOB *job, void *key);

void poly1305_aead_update(const void *msg, const uint64_t msg_len,
                          void *hash, const void *key);
void poly1305_aead_complete(const void *hash, const void *key, void *tag);

#endif /* IMB_CHACHA20POLY1305_H */
