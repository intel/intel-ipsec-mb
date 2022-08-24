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

#ifndef MB_MGR_BURST_ASYNC_H
#define MB_MGR_BURST_ASYNC_H

/* asynchronous burst API (chained cipher & hash) */

#include "intel-ipsec-mb.h"
#include "include/error.h"
#include "include/mb_mgr_job_check.h" /* is_job_invalid() */

__forceinline
void ADV_N_JOBS(int *ptr, const uint32_t n_jobs)
{
        *ptr += (sizeof(IMB_JOB) * n_jobs);
        if (*ptr >= (int) (IMB_MAX_JOBS * sizeof(IMB_JOB)))
                *ptr -= (int) (IMB_MAX_JOBS * sizeof(IMB_JOB));
}


/* get number of jobs between job_offset and the end of the queue */
__forceinline uint32_t
get_queue_sz_end(const int job_offset)
{
        return IMB_MAX_JOBS - (job_offset / sizeof(IMB_JOB));
}

__forceinline uint32_t
queue_sz_remaining(IMB_MGR *state)
{
        if (state->earliest_job < 0)
                return IMB_MAX_JOBS;

        return IMB_MAX_JOBS - get_queue_sz(state);
}

uint32_t
GET_NEXT_BURST(IMB_MGR *state, const uint32_t n_req_jobs, IMB_JOB **jobs)
{
        uint32_t i, num_jobs, n_ret_jobs, filled_jobs = 0;
        IMB_JOB *job = NULL;

        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (jobs == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_BURST);
                return 0;
        }
        if (n_req_jobs > IMB_MAX_BURST_SIZE) {
                imb_set_errno(state, IMB_ERR_BURST_SIZE);
                return 0;
        }
#endif
        /* set number of jobs to return */
        n_ret_jobs = queue_sz_remaining(state);
        if (n_ret_jobs > n_req_jobs)
                n_ret_jobs = n_req_jobs;

        /* start filling list from next available job */
        job = JOBS(state, state->next_job);

        /* check enough jobs available before end of queue */
        num_jobs = get_queue_sz_end(state->next_job);

        if (num_jobs < n_ret_jobs) {
                /* fill jobs to the end of the queue */
                for (i = 0; i < num_jobs; i++) {
                        jobs[filled_jobs++] = job;
                        job++;
                }
                /* fill remaining jobs from beginning of queue */
                num_jobs = n_ret_jobs - num_jobs;
                job = &state->jobs[0];
        } else
                /* fill all jobs */
                num_jobs = n_ret_jobs;

        for (i = 0; i < num_jobs; i++) {
                jobs[filled_jobs++] = job;
                job++;
        }

        return filled_jobs;
}

__forceinline uint32_t
submit_burst_and_check(IMB_MGR *state, const uint32_t n_jobs,
                       IMB_JOB **jobs, const int run_check)
{
        uint32_t i, n_ret_jobs = 0, num_jobs = n_jobs;
        IMB_JOB *job = NULL;

        /* reset error status */
        imb_set_errno(state, 0);

        if (run_check) {
                int job_offset = state->next_job;

                if (jobs == NULL) {
                        imb_set_errno(state, IMB_ERR_NULL_BURST);
                        return 0;
                }
                if (n_jobs > IMB_MAX_BURST_SIZE) {
                        imb_set_errno(state, IMB_ERR_BURST_SIZE);
                        return 0;
                }
                /* check enough space in queue */
                if (queue_sz_remaining(state) < n_jobs) {
                        imb_set_errno(state, IMB_ERR_QUEUE_SPACE);
                        return 0;
                }

                for (i = 0; i < n_jobs; i++) {
                        if (jobs[i] == NULL) {
                                imb_set_errno(state, IMB_ERR_NULL_JOB);
                                return 0;
                        }
                        if (jobs[i] != JOBS(state, job_offset)) {
                                imb_set_errno(state, IMB_ERR_BURST_OOO);
                                goto return_invalid_job;
                        }
                        ADV_JOBS(&job_offset);

                        /* validate job */
                        if (is_job_invalid(state, jobs[i],
                                           jobs[i]->cipher_mode,
                                           jobs[i]->hash_alg,
                                           jobs[i]->cipher_direction,
                                           jobs[i]->key_len_in_bytes)) {
                                goto return_invalid_job;
                        }
                }
        }

        /* state was previously empty */
        if (state->earliest_job < 0)
                state->earliest_job = state->next_job;

        /* submit all jobs */
        for (i = 0; i < n_jobs; i++) {
                jobs[i]->status = IMB_STATUS_BEING_PROCESSED;
                submit_new_job(state, jobs[i]);
        }
        ADV_N_JOBS(&state->next_job, n_jobs);

        /*
         * return completed jobs
         * - may need 2 passes if jobs wrap in queue
         */
        num_jobs = get_queue_sz_end(state->earliest_job);
        if (num_jobs > n_jobs)
                num_jobs = n_jobs;

        /* start returning from earliest job */
        job = JOBS(state, state->earliest_job);

return_jobs:
        for (i = 0; i < num_jobs; i++) {
                if (job->status < IMB_STATUS_COMPLETED)
                        goto return_jobs_done;
                jobs[n_ret_jobs++] = job;
                job++;
        }

        /* check if all jobs returned
         * if not, return remaining jobs from beginning of queue
         */
        if (n_ret_jobs < n_jobs) {
                num_jobs = n_jobs - num_jobs;
                job = &state->jobs[0];
                goto return_jobs;
        }

return_jobs_done:
        ADV_N_JOBS(&state->earliest_job, n_ret_jobs);

        if (state->earliest_job == state->next_job) {
                state->earliest_job = -1; /* becomes empty */
                state->next_job = 0;
        }

        return n_ret_jobs;

return_invalid_job:
        jobs[i]->status = IMB_STATUS_INVALID_ARGS;
        jobs[0] = jobs[i];
        return 0;
}

uint32_t
SUBMIT_BURST(IMB_MGR *state, const uint32_t n_jobs, IMB_JOB **jobs)
{
        return submit_burst_and_check(state, n_jobs, jobs, 1);
}

uint32_t
SUBMIT_BURST_NOCHECK(IMB_MGR *state, const uint32_t n_jobs, IMB_JOB **jobs)
{
        return submit_burst_and_check(state, n_jobs, jobs, 0);
}

uint32_t
FLUSH_BURST(IMB_MGR *state, const uint32_t max_jobs, IMB_JOB **jobs)
{
        uint32_t i, max_ret_jobs, n_ret_jobs = 0;

        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (jobs == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_BURST);
                return 0;
        }
#endif
        /* check if any jobs in queue */
        max_ret_jobs = queue_sz(state);
        if (max_ret_jobs == 0)
                return 0;

        /* set max number of jobs to return */
        if (max_ret_jobs > max_jobs)
                max_ret_jobs = max_jobs;

        for (i = 0; i < max_ret_jobs; i++) {
                IMB_JOB *job = JOBS(state, state->earliest_job);

                if (job->status < IMB_STATUS_COMPLETED)
                        complete_job(state, job);

                jobs[n_ret_jobs++] = job;
                ADV_JOBS(&state->earliest_job);
        }

        if (state->earliest_job == state->next_job) {
                state->earliest_job = -1; /* becomes empty */
                state->next_job = 0;
        }

        return n_ret_jobs;
}

#endif /* MB_MGR_BURST_ASYNC_H */
