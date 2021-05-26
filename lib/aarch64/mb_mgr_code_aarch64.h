/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/
#ifndef MB_MGR_CODE_H
#define MB_MGR_CODE_H

/*
 * This contains the bulk of the mb_mgr code, with #define's to build
 * an AARCH64 version (see mb_mgr_aarch64.c).
 *
 * get_next_job() returns a job object. This must be filled in and returned
 * via submit_job() before get_next_job() is called again.
 *
 * submit_job() and flush_job() returns a job object. This job object ceases
 * to be usable at the next call to get_next_job()
 */

#include <string.h> /* memcpy(), memset() */

#include "clear_regs_mem_aarch64.h"
#include "intel-ipsec-mb.h"
#include "error.h"

#define BSWAP64 __builtin_bswap64

/*
 * JOBS() and ADV_JOBS() moved into mb_mgr_code.h
 * get_next_job() and get_completed_job() API's are no longer inlines.
 * For binary compatibility they have been made proper symbols.
 */
__forceinline
IMB_JOB *JOBS(IMB_MGR *state, const int offset)
{
        char *cp = (char *)state->jobs;

        return (IMB_JOB *)(cp + offset);
}

__forceinline
void ADV_JOBS(int *ptr)
{
        *ptr += sizeof(IMB_JOB);
        if (*ptr >= (int) (IMB_MAX_JOBS * sizeof(IMB_JOB)))
                *ptr = 0;
}

__forceinline
IMB_JOB *
submit_snow3g_uea2_job(IMB_MGR *state, IMB_JOB *job)
{
        const snow3g_key_schedule_t *key = job->enc_keys;
        const uint32_t msg_bitlen =
                        (const uint32_t)job->msg_len_to_cipher_in_bits;
        const uint32_t msg_bitoff =
                        (const uint32_t)job->cipher_start_src_offset_in_bits;

        /* Use bit length API if
         * - msg length is not a multiple of bytes
         * - bit offset is not a multiple of bytes
         */
        if ((msg_bitlen & 0x07) || (msg_bitoff & 0x07)) {
                IMB_SNOW3G_F8_1_BUFFER_BIT(state, key, job->iv, job->src,
                                           job->dst, msg_bitlen, msg_bitoff);
        } else {
                const uint32_t msg_bytelen = msg_bitlen >> 3;
                const uint32_t msg_byteoff = msg_bitoff >> 3;
                const void *src = job->src + msg_byteoff;
                void *dst = job->dst + msg_byteoff;

                IMB_SNOW3G_F8_1_BUFFER(state, key, job->iv, src,
                                       dst, msg_bytelen);
        }

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline
IMB_JOB *
SUBMIT_JOB_AES_ENC(IMB_MGR *state, IMB_JOB *job)
{
        if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == job->cipher_mode) {
                return submit_snow3g_uea2_job(state, job);
        } else { /* assume IMB_CIPHER_NULL */
                job->status |= IMB_STATUS_COMPLETED_CIPHER;
                return job;
        }
}

__forceinline
IMB_JOB *
FLUSH_JOB_AES_ENC(IMB_MGR *state, IMB_JOB *job)
{
        (void) state;
        (void) job;

        return NULL;
}

__forceinline
IMB_JOB *
SUBMIT_JOB_AES_DEC(IMB_MGR *state, IMB_JOB *job)
{
        if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == job->cipher_mode) {
                return submit_snow3g_uea2_job(state, job);
        } else {
                /* assume IMB_CIPHER_NULL */
                job->status |= IMB_STATUS_COMPLETED_CIPHER;
                return job;
        }
}

__forceinline
IMB_JOB *
FLUSH_JOB_AES_DEC(IMB_MGR *state, IMB_JOB *job)
{
        (void) state;
        (void) job;

        return NULL;
}

/* ========================================================================= */
/* Hash submit & flush functions */
/* ========================================================================= */
__forceinline
IMB_JOB *
SUBMIT_JOB_HASH(IMB_MGR *state, IMB_JOB *job)
{
        switch (job->hash_alg) {
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                IMB_SNOW3G_F9_1_BUFFER(state, (const snow3g_key_schedule_t *)
                               job->u.SNOW3G_UIA2._key,
                               job->u.SNOW3G_UIA2._iv,
                               job->src + job->hash_start_src_offset_in_bytes,
                               job->msg_len_to_hash_in_bits,
                               job->auth_tag_output);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        default:
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        }
}

__forceinline
IMB_JOB *
FLUSH_JOB_HASH(IMB_MGR *state, IMB_JOB *job)
{
        (void) state;

        switch (job->hash_alg) {
        default:
                if (!(job->status & IMB_STATUS_COMPLETED_AUTH)) {
                        job->status |= IMB_STATUS_COMPLETED_AUTH;
                        return job;
                }
                return NULL;
        }
}


/* ========================================================================= */
/* Job submit & flush functions */
/* ========================================================================= */

#define SNOW3G_MAX_BITLEN (UINT32_MAX)
#define MB_MAX_LEN16 ((1 << 16) - 2)

__forceinline int
is_job_invalid(IMB_MGR *state, const IMB_JOB *job)
{
        switch (job->cipher_mode) {
        case IMB_CIPHER_NULL:
                 /*
                  * No checks required for this mode
                  * @note NULL cipher doesn't perform memory copy operation
                  *       from source to destination
                  */
                break;
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (job->key_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bits == 0 ||
                    job->msg_len_to_cipher_in_bits > SNOW3G_MAX_BITLEN) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        default:
                imb_set_errno(state, IMB_ERR_CIPH_MODE);
                return 1;
        }

        switch (job->hash_alg) {
        case IMB_AUTH_NULL:
                break;
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if ((job->msg_len_to_hash_in_bits == 0) ||
                    (job->msg_len_to_hash_in_bits > SNOW3G_MAX_BITLEN)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->u.SNOW3G_UIA2._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (job->u.SNOW3G_UIA2._iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes != UINT64_C(4)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                break;
        default:
                imb_set_errno(state, IMB_ERR_HASH_ALGO);
                return 1;
        }
        return 0;
}

__forceinline
IMB_JOB *SUBMIT_JOB_AES(IMB_MGR *state, IMB_JOB *job)
{
        if (job->cipher_direction == IMB_DIR_ENCRYPT)
                job = SUBMIT_JOB_AES_ENC(state, job);
        else
                job = SUBMIT_JOB_AES_DEC(state, job);

        return job;
}

__forceinline
IMB_JOB *FLUSH_JOB_AES(IMB_MGR *state, IMB_JOB *job)
{
        if (job->cipher_direction == IMB_DIR_ENCRYPT)
                job = FLUSH_JOB_AES_ENC(state, job);
        else
                job = FLUSH_JOB_AES_DEC(state, job);

        return job;
}

/* submit a half-completed job, based on the status */
__forceinline
IMB_JOB *RESUBMIT_JOB(IMB_MGR *state, IMB_JOB *job)
{
        while (job != NULL && job->status < IMB_STATUS_COMPLETED) {
                if (job->status == IMB_STATUS_COMPLETED_AUTH)
                        job = SUBMIT_JOB_AES(state, job);
                else /* assumed job->status = IMB_STATUS_COMPLETED_CIPHER */
                        job = SUBMIT_JOB_HASH(state, job);
        }

        return job;
}

__forceinline
IMB_JOB *submit_new_job(IMB_MGR *state, IMB_JOB *job)
{
        if (job->chain_order == IMB_ORDER_CIPHER_HASH)
                job = SUBMIT_JOB_AES(state, job);
        else
                job = SUBMIT_JOB_HASH(state, job);

        job = RESUBMIT_JOB(state, job);
        return job;
}

__forceinline
void complete_job(IMB_MGR *state, IMB_JOB *job)
{
        if (job->chain_order == IMB_ORDER_CIPHER_HASH) {
                /* while() loop optimized for cipher_hash order */
                while (job->status < IMB_STATUS_COMPLETED) {
                        IMB_JOB *tmp = FLUSH_JOB_AES(state, job);

                        if (tmp == NULL)
                                tmp = FLUSH_JOB_HASH(state, job);

                        (void) RESUBMIT_JOB(state, tmp);
                }
        } else {
                /* while() loop optimized for hash_cipher order */
                while (job->status < IMB_STATUS_COMPLETED) {
                        IMB_JOB *tmp = FLUSH_JOB_HASH(state, job);

                        if (tmp == NULL)
                                tmp = FLUSH_JOB_AES(state, job);

                        (void) RESUBMIT_JOB(state, tmp);
                }
        }
}

__forceinline
IMB_JOB *
submit_job_and_check(IMB_MGR *state, const int run_check)
{
        IMB_JOB *job = NULL;

        job = JOBS(state, state->next_job);

        if (run_check) {
                if (is_job_invalid(state, job)) {
                        job->status = IMB_STATUS_INVALID_ARGS;
                } else {
                        job->status = IMB_STATUS_BEING_PROCESSED;
                        job = submit_new_job(state, job);
                }
        } else {
                job->status = IMB_STATUS_BEING_PROCESSED;
                job = submit_new_job(state, job);
        }

        if (state->earliest_job < 0) {
                /* state was previously empty */
                if (job == NULL)
                        state->earliest_job = state->next_job;
                ADV_JOBS(&state->next_job);
                goto exit;
        }

        ADV_JOBS(&state->next_job);

        if (state->earliest_job == state->next_job) {
                /* Full */
                job = JOBS(state, state->earliest_job);
                complete_job(state, job);
                ADV_JOBS(&state->earliest_job);
                goto exit;
        }

        /* not full */
        job = JOBS(state, state->earliest_job);
        if (job->status < IMB_STATUS_COMPLETED) {
                job = NULL;
                goto exit;
        }

        ADV_JOBS(&state->earliest_job);
exit:
#ifdef SAFE_DATA
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        return job;
}

IMB_JOB *
SUBMIT_JOB(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif

        return submit_job_and_check(state, 1);
}

IMB_JOB *
SUBMIT_JOB_NOCHECK(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif

        return submit_job_and_check(state, 0);
}

IMB_JOB *
FLUSH_JOB(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif
        IMB_JOB *job;
        if (state->earliest_job < 0)
                return NULL; /* empty */

        job = JOBS(state, state->earliest_job);
        complete_job(state, job);

        ADV_JOBS(&state->earliest_job);

        if (state->earliest_job == state->next_job)
                state->earliest_job = -1; /* becomes empty */

#ifdef SAFE_DATA
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        return job;
}

/* ========================================================================= */
/* ========================================================================= */

uint32_t
QUEUE_SIZE(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return 0;
        }
#endif
        int a, b;

        if (state->earliest_job < 0)
                return 0;
        a = state->next_job / sizeof(IMB_JOB);
        b = state->earliest_job / sizeof(IMB_JOB);
        return ((a-b) & (IMB_MAX_JOBS-1));
}

IMB_JOB *
GET_COMPLETED_JOB(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif
        IMB_JOB *job;

        if (state->earliest_job < 0)
                return NULL;

        job = JOBS(state, state->earliest_job);
        if (job->status < IMB_STATUS_COMPLETED)
                return NULL;

        ADV_JOBS(&state->earliest_job);

        if (state->earliest_job == state->next_job)
                state->earliest_job = -1;

        return job;
}

IMB_JOB *
GET_NEXT_JOB(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif

        return JOBS(state, state->next_job);
}

#endif /* MB_MGR_CODE_H */
