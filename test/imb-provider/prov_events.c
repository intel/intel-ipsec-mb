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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <fcntl.h>

#include "e_prov.h"
#include "prov_events.h"

static void
prov_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key, OSSL_ASYNC_FD readfd, void *custom)
{
        if (close(readfd) != 0) {
                fprintf(stderr, "Failed to close readfd: %d - error: %d\n", readfd, errno);
        }
}

int
prov_setup_async_event_notification(ASYNC_JOB *job)
{
        ASYNC_WAIT_CTX *waitctx;
        OSSL_ASYNC_FD efd;
        void *custom = NULL;
        if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *) job)) == NULL) {
                fprintf(stderr, "Could not obtain wait context for job\n");
                return 0;
        }

        if (ASYNC_WAIT_CTX_get_fd(waitctx, prov_id, &efd, &custom) == 0) {

                efd = eventfd(0, EFD_NONBLOCK);
                if (efd == -1) {
                        fprintf(stderr, "Failed to get eventfd = %d\n", errno);
                        return 0;
                }

                if (ASYNC_WAIT_CTX_set_wait_fd(waitctx, prov_id, efd, custom, prov_fd_cleanup) ==
                    0) {
                        fprintf(stderr, "failed to set the fd in the ASYNC_WAIT_CTX\n");
                        prov_fd_cleanup(waitctx, prov_id, efd, NULL);
                        return 0;
                }
        }
        return 1;
}

int
prov_clear_async_event_notification(ASYNC_JOB *job)
{
        ASYNC_WAIT_CTX *waitctx;
        size_t num_add_fds = 0;
        size_t num_del_fds = 0;
        OSSL_ASYNC_FD efd;
        void *custom = NULL;

        if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *) job)) == NULL) {
                fprintf(stderr, "Could not obtain wait context for job\n");
                return 0;
        }

        if (ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &num_add_fds, NULL, &num_del_fds) == 0) {
                fprintf(stderr, "Failure in ASYNC_WAIT_CTX_get_changed_async_fds\n");
                return 0;
        }

        if (num_add_fds > 0) {
                if (ASYNC_WAIT_CTX_get_fd(waitctx, prov_id, &efd, &custom) == 0) {
                        fprintf(stderr, "Failure in ASYNC_WAIT_CTX_get_fd\n");
                        return 0;
                }

                prov_fd_cleanup(waitctx, prov_id, efd, NULL);

                if (ASYNC_WAIT_CTX_clear_fd(waitctx, prov_id) == 0) {
                        fprintf(stderr, "Failure in ASYNC_WAIT_CTX_clear_fd\n");
                        return 0;
                }
        }
        return 1;
}

int
prov_pause_job(ASYNC_JOB *job)
{

        if (ASYNC_pause_job() == 0) {
                fprintf(stderr, "Failed to pause the job\n");
                return PROV_JOB_RESUMED_UNEXPECTEDLY;
        }

        return 1;
}

int
prov_wake_job(ASYNC_JOB *job)
{
        ASYNC_WAIT_CTX *waitctx;
        OSSL_ASYNC_FD efd;
        void *custom = NULL;
        uint64_t buf = 1;

        if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *) job)) == NULL) {
                return 0;
        }

        if (ASYNC_WAIT_CTX_get_fd(waitctx, prov_id, &efd, &custom) > 0) {
                if (write(efd, &buf, sizeof(uint64_t)) == -1) {
                        fprintf(stderr, "Failed to write to fd: %d - error: %d\n", efd, errno);
                        return 0;
                }
        }

        return 1;
}

int
prov_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr, void *(*start_func)(void *),
                   void *pArg)
{
        return pthread_create(pThreadId, attr, start_func, (void *) pArg);
}
