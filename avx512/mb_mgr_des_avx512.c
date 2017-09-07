/*
 * Copyright (c) 2017, Intel Corporation
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* AVX512 DES job manager */

#include <x86intrin.h>
#include <string.h>

#include "mb_mgr.h"
#include "asm_types.h"
#include "des_x16_avx512.h"
#include "des.h"
#include "os.h"

JOB_AES_HMAC *submit_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state);
JOB_AES_HMAC *submit_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state);

JOB_AES_HMAC *submit_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state);
JOB_AES_HMAC *submit_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state);


/**
 * @brief Submit a DES CBC or DOCSIS DES job
 *
 * @param state OOO manager state structure
 * @param job crypto job to be scheduled for processing
 * @param do_enc if non-zero do encryption, otherwise decryption
 * @param is_docsis if zero do DES CBC operation, otherwise DOCSIS DES
 */
__forceinline
JOB_AES_HMAC *
submit_job_des_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job, const int do_enc, const int is_docsis)
{
        __m128i l1, l2, r1, r2;
        unsigned lane, min_len, min_idx;
        JOB_AES_HMAC *ret_job;
        const uint32_t *p_iv;
        
        /* find unused lane */
        lane = (unsigned) state->unused_lanes & 0xf;
        state->unused_lanes >>= 4;
        state->num_lanes_inuse++;

        /* store job info in OOO */
        state->job_in_lane[lane] = job;
        state->lens[lane] = (uint16_t) (job->msg_len_to_cipher_in_bytes & (~7));
        state->args.in[lane] = job->src + job->cipher_start_src_offset_in_bytes;
        state->args.out[lane] = job->dst;
        if (is_docsis) {
                state->args.partial_len[lane] = (uint32_t) (job->msg_len_to_cipher_in_bytes & 7);
                state->args.block_len[lane] = (uint32_t) state->lens[lane];
                state->args.last_out[lane] = state->args.out[lane] + state->lens[lane];
                state->args.last_in[lane] = state->args.in[lane] + state->lens[lane];
        }
        if (do_enc)
                state->args.keys[lane] = job->aes_enc_key_expanded;
        else
                state->args.keys[lane] = job->aes_dec_key_expanded;
        /* copy & scramble IV */
        p_iv = (const uint32_t *) job->iv;
        state->args.IV[lane] = p_iv[0];
        state->args.IV[lane + AVX512_NUM_DES_LANES] = p_iv[1];

        /* enough jobs to start processing? */
        if (state->num_lanes_inuse < AVX512_NUM_DES_LANES)
                return NULL;

        /* find min common length to process */
        l1 = _mm_loadu_si128((const __m128i*)&state->lens[0]);
        l2 = _mm_loadu_si128((const __m128i*)&state->lens[8]);
        r1 = _mm_minpos_epu16(l1);
        r2 = _mm_minpos_epu16(l2);
        min_len = (unsigned) _mm_extract_epi16(r1, 0);
        min_idx = (unsigned) _mm_extract_epi16(r1, 1);
        if (min_len > (unsigned) _mm_extract_epi16(r2, 0)) {
                min_len = _mm_extract_epi16(r2, 0);
                min_idx = _mm_extract_epi16(r2, 1) + 8;
                r1 = r2;
        }

        if (min_len == 0) {
                if (is_docsis) {
                        if (state->args.partial_len[min_idx] != 0) {
                                if (do_enc)
                                        docsis_des_x16_enc_avx512(&state->args, min_len);
                                else
                                        docsis_des_x16_dec_avx512(&state->args, min_len);
                        }
                }
                goto no_algorithmic_code_needed;
        }
        
        /* subtract min len from all lanes */
        r1 = _mm_broadcastw_epi16(r1);
        _mm_storeu_si128((__m128i *)&state->lens[0], _mm_sub_epi16(l1, r1));
        _mm_storeu_si128((__m128i *)&state->lens[8], _mm_sub_epi16(l2, r1));

        /* run the algorythmic code */
        if (do_enc) {
                if (is_docsis)
                        docsis_des_x16_enc_avx512(&state->args, min_len);
                else
                        des_x16_cbc_enc_avx512(&state->args, min_len);
        } else {
                if (is_docsis)
                        docsis_des_x16_dec_avx512(&state->args, min_len);
                else
                        des_x16_cbc_dec_avx512(&state->args, min_len);
        }

 no_algorithmic_code_needed:
        
        /* put back processed packet into unused lanes, set job as complete */
        state->num_lanes_inuse--;
        state->unused_lanes = (state->unused_lanes << 4) | min_idx;
        ret_job = state->job_in_lane[min_idx];
        ret_job->status |= STS_COMPLETED_AES;
        state->job_in_lane[min_idx] = NULL;
        /* write back IV? */
        return ret_job;
}

/**
 * @brief Flush DES CBC or DOCSIS DES OOO manager
 *
 * @param state OOO manager state structure
 * @param do_enc if non-zero do encryption, otherwise decryption
 * @param is_docsis if zero do DES CBC operation, otherwise DOCSIS DES
 */
__forceinline
JOB_AES_HMAC *
flush_job_des_avx512(MB_MGR_DES_OOO *state, const int do_enc, const int is_docsis)
{
        __m128i l1, l2, r1, r2;
        unsigned i, lane, min_len, min_idx;
        JOB_AES_HMAC *ret_job;

        if (state->num_lanes_inuse == 0)
                return NULL;

        /* find lane with non null job */
        for (lane = 0; lane < AVX512_NUM_DES_LANES; lane++)
                if (state->job_in_lane[lane] != NULL)
                        break;

        /* copy good lane into null lanes */
        for (i = 0; i < AVX512_NUM_DES_LANES; i++) {
                if (state->job_in_lane[i] == NULL) {
                        state->args.in[i] = state->args.in[lane];
                        state->args.out[i] = state->args.out[lane];
                        state->args.keys[i] = state->args.keys[lane];
                        state->lens[i] = UINT16_MAX;
                        state->args.IV[i] = state->args.IV[lane];
                        state->args.IV[i + AVX512_NUM_DES_LANES] = state->args.IV[lane + AVX512_NUM_DES_LANES];
                        state->args.partial_len[i] = 0;
                }
        }

        /* find min common length to process */
        l1 = _mm_loadu_si128((const __m128i*)&state->lens[0]);
        l2 = _mm_loadu_si128((const __m128i*)&state->lens[8]);
        r1 = _mm_minpos_epu16(l1);
        r2 = _mm_minpos_epu16(l2);
        min_len = (unsigned) _mm_extract_epi16(r1, 0);
        min_idx = (unsigned) _mm_extract_epi16(r1, 1);
        if (min_len > (unsigned) _mm_extract_epi16(r2, 0)) {
                min_len = _mm_extract_epi16(r2, 0);
                min_idx = _mm_extract_epi16(r2, 1) + 8;
                r1 = r2;
        }

        /* subtract min len from all lanes */
        r1 = _mm_broadcastw_epi16(r1);
        _mm_storeu_si128((__m128i *)&state->lens[0], _mm_sub_epi16(l1, r1));
        _mm_storeu_si128((__m128i *)&state->lens[8], _mm_sub_epi16(l2, r1));

        /* run the algorythmic code */
        if (do_enc) {
                if (is_docsis)
                        docsis_des_x16_enc_avx512(&state->args, min_len);
                else
                        des_x16_cbc_enc_avx512(&state->args, min_len);
        } else {
                if (is_docsis)
                        docsis_des_x16_dec_avx512(&state->args, min_len);
                else
                        des_x16_cbc_dec_avx512(&state->args, min_len);
        }

        /* put back processed packet into unused lanes */
        state->num_lanes_inuse--;
        state->unused_lanes = (state->unused_lanes << 4) | min_idx;
        ret_job = state->job_in_lane[min_idx];
        ret_job->status |= STS_COMPLETED_AES;
        state->job_in_lane[min_idx] = NULL;
        /* write back IV? */
        return ret_job;
}

JOB_AES_HMAC *submit_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job)
{
        return submit_job_des_avx512(state, job, 1, 0);
}

JOB_AES_HMAC *flush_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state)
{
        return flush_job_des_avx512(state, 1, 0);
}

JOB_AES_HMAC *submit_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job)
{
        return submit_job_des_avx512(state, job, 0, 0);
}

JOB_AES_HMAC *flush_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state)
{
        return flush_job_des_avx512(state, 0, 0);
}

JOB_AES_HMAC *submit_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job)
{
        return submit_job_des_avx512(state, job, 1, 1);
}

JOB_AES_HMAC *flush_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state)
{
        return flush_job_des_avx512(state, 1, 1);
}

JOB_AES_HMAC *submit_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state, JOB_AES_HMAC *job)
{
        return submit_job_des_avx512(state, job, 0, 1);
}

JOB_AES_HMAC *flush_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state)
{
        return flush_job_des_avx512(state, 0, 1);
}
