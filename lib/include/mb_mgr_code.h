/*******************************************************************************
  Copyright (c) 2012-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef MB_MGR_CODE_H
#define MB_MGR_CODE_H

#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "include/error.h"

__forceinline IMB_JOB *
JOBS(IMB_MGR *state, const int offset)
{
        char *cp = (char *) state->jobs;

        return (IMB_JOB *) (cp + offset);
}

__forceinline void
ADV_JOBS(int *ptr)
{
        *ptr += sizeof(IMB_JOB);
        if (*ptr >= (int) (IMB_MAX_JOBS * sizeof(IMB_JOB)))
                *ptr = 0;
}

__forceinline uint32_t
get_queue_sz(IMB_MGR *state)
{
        const int a = (state->next_job - state->earliest_job) / (int) sizeof(IMB_JOB);

        return a & (IMB_MAX_JOBS - 1);
}

__forceinline uint32_t
queue_sz(IMB_MGR *state)
{
        if (state->earliest_job < 0)
                return 0;

        const uint32_t queue_size = get_queue_sz(state);

        /* zero here means queue is full */
        return queue_size ? queue_size : IMB_MAX_JOBS;
}

/* ========================================================================= */
/*
 * Implements:
 *     GET_NEXT_JOB
 *     GET_COMPLETED_JOB
 *     QUEUE_SIZE
 *     FLUSH_JOB
 *     SUBMIT_JOB_NOCHECK
 *     SUBMIT_JOB
 */
#include "include/mb_mgr_job_api.h" /* JOB API */

/* ========================================================================= */
/*
 * Implements:
 *     GET_NEXT_BURST
 *     SUBMIT_BURST
 *     SUBMIT_BURST_NOCHECK
 *     FLUSH_BURST
 */
#include "include/mb_mgr_burst_async.h" /* asynchronous burst API */

/* ========================================================================= */
/*
 * Implements:
 *     SUBMIT_CIPHER_BURST
 *     SUBMIT_CIPHER_BURST_NOCHECK
 *     SUBMIT_HASH_BURST
 *     SUBMIT_HASH_BURST_NOCHECK
 */

#include "include/mb_mgr_burst.h" /* synchronous cipher/hash burst API */

#endif /* MB_MGR_CODE_H */
