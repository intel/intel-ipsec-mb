/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <xmmintrin.h>
#include <sys/epoll.h>

/* Local includes */
#include "e_prov.h"
#include "prov_events.h"
#include "prov_sw_sha.h"
#include "prov_sw_request.h"
#include "prov_sw_freelist.h"
#include "prov_sw_submit.h"

int
check_for_stuck_jobs(mb_thread_data *tlv)
{
        ASYNC_JOB *job = queue_async_check_stuck_job(tlv->jobs);

        if (job != NULL) // oldest submitted job is stuck
                prov_wake_job(job);

        return 1;
}

static struct IMB_JOB *
submit_single_job(mb_thread_data *tlv, ALG_CTX *ctx, ASYNC_JOB *async_job, IMB_JOB *job)
{
        if (!job || !async_job || !tlv || !ctx) {
                fprintf(stderr, "Error: Invalid parameters in submit_single_job\n");
                return NULL;
        }

        struct IMB_JOB *return_job = IMB_SUBMIT_JOB(tlv->imb_mgr);

        int err = imb_get_errno(tlv->imb_mgr);
        if (err != 0) {
                fprintf(stderr, "Error: IMB_SUBMIT_JOB failed with error %d: '%s'\n", err,
                        imb_get_strerror(err));
        }

        // Retrieve a free item from the freelist
        op_data *req = NULL;
        while ((req = flist_async_pop(tlv->freelist_jobs)) == NULL) {
                prov_wake_job(async_job);
                prov_pause_job(async_job);
        }

        // Populate with job details
        req->state = ctx;
        req->job = async_job;
        req->imb_job = job;

        // Record the current timestamp for the job
        clock_gettime(CLOCK_MONOTONIC, &req->timestamp);

        // Enqueue submitted jobs
        queue_async_enqueue(tlv->jobs, req);

        return return_job;
}

int
async_update(mb_thread_data *tlv, ALG_CTX *ctx, ASYNC_JOB *async_job, IMB_JOB *imb_job)
{
        if (ctx == NULL) {
                fprintf(stderr, "Error: SHA context is NULL.\n");
                return 0;
        }

        // Setup async event notifications
        if (!prov_setup_async_event_notification(async_job)) {
                fprintf(stderr, "Error: Failed to setup async notifications.\n");
                return 0;
        }

        // Submit single job
        struct IMB_JOB *ret_job = submit_single_job(tlv, ctx, async_job, imb_job);
        ASYNC_JOB *ret_async_job = NULL;

        if (ret_job != NULL) {
                ret_async_job = (ASYNC_JOB *) ret_job->user_data2;
                if (ret_async_job != async_job) {
                        if (ret_job->status == IMB_STATUS_COMPLETED) {
                                prov_wake_job(ret_async_job);
                        } else {
                                fprintf(stderr,
                                        "ASYNC JOB %p IMB_JOB %p not completed, status = %d\n",
                                        ret_async_job, ret_job, ret_job->status);
                                return 0;
                        }
                }
        }

        // Pause the current async job if a different one is returned
        if (ret_async_job != async_job) {
                int job_ret;
                do {
                        job_ret = ASYNC_pause_job();
                        if (job_ret == 0) {
                                fprintf(stderr, "Error: Failed to pause the job.\n");
                                return 0;
                        }
                } while (PROV_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));
        }

        // Find and dequeue the async job data
        op_data *op_data = queue_async_dequeue_find(tlv->jobs, async_job);
        if (op_data == NULL) {
                fprintf(stderr, "Error: Failed to find async job data.\n");
                return 0;
        }

        // Handle flush if required - for stuck jobs woken up by the watchdog/polling thread
        if (op_data->flush == 1) {
                // Flush the oldest job
                struct IMB_JOB *flush_job = IMB_FLUSH_JOB(tlv->imb_mgr);

                const int err = imb_get_errno(tlv->imb_mgr);
                if (err != 0) {
                        fprintf(stderr, "Error: Flush job error %d : '%s'\n", err,
                                imb_get_strerror(err));
                }

                if (flush_job != NULL) {
                        ASYNC_JOB *flush_async_job = (ASYNC_JOB *) flush_job->user_data2;
                        if (flush_async_job != async_job) {
                                // If the flush async job is not the same as the current async job,
                                // wake it up
                                prov_wake_job(flush_async_job);
                        }
                }
        }

        // Clean up and return the op_data to the freelist
        OPENSSL_cleanse(op_data, sizeof(*op_data));
        flist_async_push(tlv->freelist_jobs, op_data);

        return 1;
}