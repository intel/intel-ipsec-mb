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

#include "include/sha_generic.h"
#include "ipsec_ooo_mgr.h"
#include "constants.h"

extern void call_sha1_mult_sse_from_c(SHA1_ARGS *args,
                                      uint32_t size_in_blocks);

extern void call_sha1_mult_avx_from_c(SHA1_ARGS *args,
                                      uint32_t size_in_blocks);

__forceinline
void copy_bswap4_array_mb(void *dst, const void *src, const size_t num,
                          const size_t offset, const unsigned lane)
{
        uint32_t *outp = (uint32_t *) dst;
        const uint32_t *inp = (const uint32_t *) src;
        size_t i;

        for (i = 0; i < num; i++)
                outp[i] = bswap4(inp[lane + i*offset]);
}

__forceinline
void sha1_mb_init_digest(uint32_t *digest, const unsigned lane)
{
        digest[lane + 0*16] = H0;
        digest[lane + 1*16] = H1;
        digest[lane + 2*16] = H2;
        digest[lane + 3*16] = H3;
        digest[lane + 4*16] = H4;
}

__forceinline
void
sha_mb_generic_init(void *digest, const int sha_type, const unsigned lane)
{
        if (sha_type == 1)
                sha1_mb_init_digest(digest, lane);
}

__forceinline
void sha_mb_generic_write_digest(void *dst, const void *src,
                                const int sha_type, const size_t offset,
                                const unsigned lane)
{
        if (sha_type == 1)
                copy_bswap4_array_mb(dst, src, NUM_SHA_DIGEST_WORDS, offset,
                                     lane);
}

__forceinline
void create_extra_blocks(MB_MGR_HMAC_SHA_1_OOO *state,
                         const uint64_t blk_size, const uint64_t r,
                         const unsigned min_idx)
{
        HMAC_SHA1_LANE_DATA *ld = &state->ldata[min_idx];
        const uint64_t xblk_size = blk_size*state->ldata[min_idx].extra_blocks;

        memset(ld->extra_block, 0, sizeof(ld->extra_block));

        var_memcpy(ld->extra_block, state->args.data_ptr[min_idx], r);
        ld->extra_block[r] = 0x80;

        store8_be(&ld->extra_block[xblk_size - 8],
                  ld->job_in_lane->msg_len_to_hash_in_bytes * 8);

        state->args.data_ptr[min_idx] = &ld->extra_block[0];

        state->lens[min_idx] = (uint16_t)xblk_size;

        state->ldata[min_idx].extra_blocks = 0;
}

__forceinline
IMB_JOB *
submit_flush_job_sha_1(MB_MGR_HMAC_SHA_1_OOO *state, IMB_JOB *job,
                         const unsigned max_jobs, const int is_submit,
                         const int sha_type, const uint64_t blk_size,
                         const uint64_t pad_size,
                         void (*fn)(SHA1_ARGS *, uint32_t))
{
        unsigned lane, min_len, min_idx;
        IMB_JOB *ret_job = NULL;
        unsigned i;

        if (is_submit) {
                /*
                 * SUBMIT
                 * - get a free lane id
                 */

                lane = state->unused_lanes & 15;
                state->unused_lanes >>= 4;
                state->args.data_ptr[lane] =
                        job->src + job->hash_start_src_offset_in_bytes;

                sha_mb_generic_init(state->args.digest, sha_type, lane);

                /* copy job data in and set up initial blocks */
                state->ldata[lane].job_in_lane = job;
                state->lens[lane] = (uint16_t)job->msg_len_to_hash_in_bytes;
                state->ldata[lane].extra_blocks = 1;

                /* enough jobs to start processing? */
                if (state->unused_lanes != 0xf)
                        return NULL;
        } else {
                /*
                 * FLUSH
                 * - find 1st non null job
                 */
                for (lane = 0; lane < max_jobs; lane++)
                        if (state->ldata[lane].job_in_lane != NULL)
                                break;
                if (lane >= max_jobs)
                        return NULL; /* no not null job */
        }

        do {
                if (is_submit) {
                        /*
                        * SUBMIT
                        * - find min common length to process
                        */
                        min_idx = 0;
                        min_len = state->lens[0];

                        for (i = 1; i < max_jobs; i++) {
                                if (min_len > state->lens[i]) {
                                        min_idx = i;
                                        min_len = state->lens[i];
                                }
                        }
                } else {
                        /*
                        * FLUSH
                        * - copy good (not null) lane onto empty lanes
                        * - find min common length to process across
                        * - not null lanes
                        */
                        min_idx = lane;
                        min_len = state->lens[lane];

                        for (i = 0; i < max_jobs; i++) {
                                if (i == lane)
                                        continue;

                                if (state->ldata[i].job_in_lane != NULL) {
                                        if (min_len > state->lens[i]) {
                                                min_idx = i;
                                                min_len = state->lens[i];
                                        }
                                } else {
                                        state->args.data_ptr[i] =
                                                state->args.data_ptr[lane];
                                        state->lens[i] = UINT16_MAX;
                                }
                        }
                }

                /* subtract min len from all lanes */
                for (i = 0; i < max_jobs; i++)
                        state->lens[i] -=
                                (uint16_t)((min_len/blk_size)*blk_size);

                const uint64_t r = min_len % blk_size;

                if (r >= (blk_size - pad_size))
                        state->ldata[min_idx].extra_blocks = 2;

                /* run the algorithmic code on full selected blocks */
                if(min_len >= blk_size)
                        (*fn)(&state->args,
                                (uint32_t)(min_len/blk_size));

                /* create extra blocks */
                if (state->ldata[min_idx].extra_blocks != 0)
                        create_extra_blocks(state, blk_size, r, min_idx);

        } while(state->lens[min_idx] != 0);

        ret_job = state->ldata[min_idx].job_in_lane;

        /* put back processed packet into unused lanes, set job as complete */
        state->unused_lanes = (state->unused_lanes << 4) | min_idx;
        sha_mb_generic_write_digest(ret_job->auth_tag_output,
                state->args.digest, sha_type, 16, min_idx);
        ret_job->status |= IMB_STATUS_COMPLETED_AUTH;
        state->ldata[min_idx].job_in_lane = NULL;

        return ret_job;
}
