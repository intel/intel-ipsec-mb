/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "e_prov.h"

#define PROV_JOB_RESUMED_UNEXPECTEDLY        -1
#define PROV_CHK_JOB_RESUMED_UNEXPECTEDLY(x) (x == PROV_JOB_RESUMED_UNEXPECTEDLY)

int
prov_is_event_driven();
int
prov_setup_async_event_notification(ASYNC_JOB *job);
int
prov_clear_async_event_notification(ASYNC_JOB *job);
int
prov_reset_async_event_notification(ASYNC_JOB *job);
int
prov_pause_job(ASYNC_JOB *job);
int
prov_wake_job(ASYNC_JOB *job);

int
prov_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr, void *(*start_func)(void *),
                   void *pArg);
