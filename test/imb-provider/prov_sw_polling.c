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

/* Standard Includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_sw_polling.h"
#include "prov_sw_submit.h"

/* OpenSSL Includes */
#include <openssl/err.h>

#define PROV_SW_NUM_EVENT_RETRIES 5
#define PROV_SW_NSEC_PER_SEC      1000000000L

#define MB_TIMEOUT_LEVEL 10000000

struct timespec mb_poll_timeout_time = { 0, MB_TIMEOUT_LEVEL };
const unsigned int mb_timeout_level = MB_TIMEOUT_LEVEL;

void
get_sem_wait_abs_time(struct timespec *polling_abs_timeout, const struct timespec polling_timeout)
{
        clock_gettime(CLOCK_REALTIME, polling_abs_timeout); /* Get current real time. */
        polling_abs_timeout->tv_sec += polling_timeout.tv_sec;
        polling_abs_timeout->tv_nsec += polling_timeout.tv_nsec;

        if (polling_abs_timeout->tv_nsec >= PROV_SW_NSEC_PER_SEC) {
                polling_abs_timeout->tv_sec += polling_abs_timeout->tv_nsec / PROV_SW_NSEC_PER_SEC;
                polling_abs_timeout->tv_nsec %= PROV_SW_NSEC_PER_SEC;
        }
}

void *
multibuff_timer_poll_func(void *thread_ptr)
{
        int sig = 0;
        unsigned int eintr_count = 0;
        mb_thread_data *tlv = (mb_thread_data *) thread_ptr;
        struct timespec mb_polling_abs_timeout;

        while (tlv->keep_polling) {
                get_sem_wait_abs_time(&mb_polling_abs_timeout, mb_poll_timeout_time);
                while ((sig = sem_timedwait(&tlv->mb_polling_thread_sem,
                                            &mb_polling_abs_timeout)) == -1 &&
                       errno == EINTR && eintr_count < PROV_SW_NUM_EVENT_RETRIES) {
                        eintr_count++;
                }
                eintr_count = 0;
                if (sig == -1) {
                        if (errno == ETIMEDOUT || errno == EINTR) {
                                if (queue_async_get_size(tlv->jobs) >= 1) {
                                        check_for_stuck_jobs(tlv);
                                        continue;
                                }
                        }
                }

                if (queue_async_get_size(tlv->jobs) >= 1) {
                        check_for_stuck_jobs(tlv);
                }
        }

        return NULL;
}