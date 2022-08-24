/*******************************************************************************
  Copyright (c) 2012-2022, Intel Corporation

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

#ifndef MB_MGR_CODE_H
#define MB_MGR_CODE_H

#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "include/error.h"

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

__forceinline uint32_t
get_queue_sz(IMB_MGR *state)
{
        const int a = (state->next_job - state->earliest_job) / sizeof(IMB_JOB);

        return a & (IMB_MAX_JOBS-1);
}

__forceinline uint32_t
queue_sz(IMB_MGR *state)
{
        if (state->earliest_job < 0)
                return 0;

        return get_queue_sz(state);
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
