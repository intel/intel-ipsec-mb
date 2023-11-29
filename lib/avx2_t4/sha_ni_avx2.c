/*******************************************************************************
  Copyright (c) 2020-2024, Intel Corporation

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

#include "include/sha_generic.h"
#include "include/arch_avx2_type4.h"

/* ========================================================================== */
/* One block SHA384 computation for IPAD / OPAD usage only */
void
sha384_one_block_ni_avx2(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX2_SHANI, 384 /* SHA384 */);
}

/* ========================================================================== */
/*
 * SHA384 API for use in HMAC-SHA384 when key is longer than the block size
 */
void
sha384_ni_avx2(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX2_SHANI, 384, IMB_SHA_384_BLOCK_SIZE,
                    SHA384_PAD_SIZE);
}

/* ========================================================================== */
/* One block SHA512 computation for IPAD / OPAD usage only */
void
sha512_one_block_ni_avx2(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX2_SHANI, 512 /* SHA512 */);
}

/* ========================================================================== */
/*
 * SHA512 API for use in HMAC-SHA512 when key is longer than the block size
 */
void
sha512_ni_avx2(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX2_SHANI, 512, IMB_SHA_512_BLOCK_SIZE,
                    SHA512_PAD_SIZE);
}

/* ========================================================================== */
/*
 * SHA384 API for JOB API
 */
IMB_JOB *
submit_job_sha384_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        const void *msg = (job->src + job->hash_start_src_offset_in_bytes);
        const uint64_t length = job->msg_len_to_hash_in_bytes;
        uint64_t tag[8];

        (void) state;

        sha384_ni_avx2(msg, length, tag);
        memcpy(job->auth_tag_output, tag, job->auth_tag_output_len_in_bytes);
        job->status |= IMB_STATUS_COMPLETED_AUTH;
        return job;
}

IMB_JOB *
flush_job_sha384_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        (void) state;
        (void) job;
        return NULL;
}

/* ========================================================================== */
/*
 * SHA512 API for JOB API
 */
IMB_JOB *
submit_job_sha512_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        const void *msg = (job->src + job->hash_start_src_offset_in_bytes);
        const uint64_t length = job->msg_len_to_hash_in_bytes;
        uint64_t tag[8];

        (void) state;

        sha512_ni_avx2(msg, length, tag);
        memcpy(job->auth_tag_output, tag, job->auth_tag_output_len_in_bytes);
        job->status |= IMB_STATUS_COMPLETED_AUTH;
        return job;
}

IMB_JOB *
flush_job_sha512_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        (void) state;
        (void) job;
        return NULL;
}
