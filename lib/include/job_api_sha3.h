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

#ifndef JOB_API_SHA3_H
#define JOB_API_SHA3_H

#include "sha3.h"

__forceinline IMB_JOB *
submit_job_sha3(IMB_MGR *state, IMB_JOB *job, const IMB_HASH_ALG hash_alg)
{
        /* state not used */
        (void) state;

        switch (hash_alg) {
        case IMB_AUTH_SHA3_224:
                sha3_224(job->src, job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHA3_256:
                sha3_256(job->src, job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHA3_384:
                sha3_384(job->src, job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHA3_512:
                sha3_512(job->src, job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHAKE128:
                shake128(job->src, job->msg_len_to_hash_in_bytes, job->auth_tag_output,
                         job->auth_tag_output_len_in_bytes);
                break;
        case IMB_AUTH_SHAKE256:
                shake256(job->src, job->msg_len_to_hash_in_bytes, job->auth_tag_output,
                         job->auth_tag_output_len_in_bytes);
                break;
        default:
                job->status |= IMB_STATUS_INVALID_ARGS;
                return job;
        }

        job->status |= IMB_STATUS_COMPLETED_AUTH;
        return job;
}

#endif /* JOB_API_SHA3_H */
