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

#ifndef JOB_API_SHA3_H
#define JOB_API_SHA3_H

#include <string.h>
#include "sha3.h"
#include "clear_regs_mem.h"

__forceinline IMB_JOB *
submit_job_sha3(IMB_MGR *state, IMB_JOB *job, const IMB_HASH_ALG hash_alg)
{
        switch (hash_alg) {
        case IMB_AUTH_SHA3_224:
                state->sha3_224(job->src + job->hash_start_src_offset_in_bytes,
                                job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHA3_256:
                state->sha3_256(job->src + job->hash_start_src_offset_in_bytes,
                                job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHA3_384:
                state->sha3_384(job->src + job->hash_start_src_offset_in_bytes,
                                job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHA3_512:
                state->sha3_512(job->src + job->hash_start_src_offset_in_bytes,
                                job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                break;
        case IMB_AUTH_SHAKE128:
                state->shake128(job->src + job->hash_start_src_offset_in_bytes,
                                job->msg_len_to_hash_in_bytes, job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);
                break;
        case IMB_AUTH_SHAKE256:
                state->shake256(job->src + job->hash_start_src_offset_in_bytes,
                                job->msg_len_to_hash_in_bytes, job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);
                break;
        default:
                job->status |= IMB_STATUS_INVALID_ARGS;
                return job;
        }

        job->status |= IMB_STATUS_COMPLETED_AUTH;
        return job;
}

/*
 * HMAC-SHA3: HMAC(K, m) = SHA3(K' XOR opad || SHA3(K' XOR ipad || m))
 *
 * Unlike HMAC-SHA2, SHA3 is a sponge with no partial-state trick.
 * The ipad/opad fields hold raw K' XOR 0x36/0x5c blocks (block-size bytes),
 * computed by imb_hmac_ipad_opad().
 *
 * We build the inner input (ipad_key || msg) on the stack and call sha3_*
 * twice — once for inner, once for outer. msg_len is bounded by the caller;
 * for safety very large messages should use a streaming path, but this
 * mirrors how all other single-buffer hash types work in this library.
 */
__forceinline IMB_JOB *
submit_job_hmac_sha3(IMB_MGR *state, IMB_JOB *job, const IMB_HASH_ALG hash_alg)
{
        const uint8_t *ipad = job->u.HMAC._hashed_auth_key_xor_ipad;
        const uint8_t *opad = job->u.HMAC._hashed_auth_key_xor_opad;
        const uint64_t msg_len = job->msg_len_to_hash_in_bytes;
        uint64_t block_size, digest_size;
        sha3_ctx_t ctx;
        uint8_t inner_digest[IMB_SHA3_512_DIGEST_SIZE_IN_BYTES];
        uint8_t outer_digest[IMB_SHA3_512_DIGEST_SIZE_IN_BYTES];

        switch (hash_alg) {
        case IMB_AUTH_HMAC_SHA3_224:
                block_size = IMB_SHA3_224_BLOCK_SIZE;
                digest_size = IMB_SHA3_224_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA3_256:
                block_size = IMB_SHA3_256_BLOCK_SIZE;
                digest_size = IMB_SHA3_256_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA3_384:
                block_size = IMB_SHA3_384_BLOCK_SIZE;
                digest_size = IMB_SHA3_384_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA3_512:
        default:
                block_size = IMB_SHA3_512_BLOCK_SIZE;
                digest_size = IMB_SHA3_512_DIGEST_SIZE_IN_BYTES;
                break;
        }

        /* Inner hash: SHA3(ipad || msg) — absorbed in two pieces, no malloc */
        sha3_ctx_init(&ctx, block_size, 0x06);
        sha3_ctx_update(&ctx, ipad, block_size);
        if (msg_len > 0)
                sha3_ctx_update(&ctx, job->src + job->hash_start_src_offset_in_bytes, msg_len);
        sha3_ctx_final(&ctx, inner_digest, digest_size);

        /* Outer hash: SHA3(opad || inner_digest) */
        sha3_ctx_init(&ctx, block_size, 0x06);
        sha3_ctx_update(&ctx, opad, block_size);
        sha3_ctx_update(&ctx, inner_digest, digest_size);
        sha3_ctx_final(&ctx, outer_digest, digest_size);

        /* Copy only the requested tag length — may be truncated (4..digest_size) */
        memcpy(job->auth_tag_output, outer_digest, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
        imb_clear_mem(&ctx, sizeof(ctx));
        imb_clear_mem(inner_digest, sizeof(inner_digest));
        imb_clear_mem(outer_digest, sizeof(outer_digest));
        clear_scratch_gps();
        clear_scratch_xmms_sse();
#endif
        (void) state; /* unused — single-buffer, no OOO manager */
        job->status |= IMB_STATUS_COMPLETED_AUTH;
        return job;
}

#endif /* JOB_API_SHA3_H */
