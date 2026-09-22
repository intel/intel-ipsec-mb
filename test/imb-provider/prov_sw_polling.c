/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
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