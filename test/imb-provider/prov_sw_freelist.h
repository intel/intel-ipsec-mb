/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_SW_FREELIST_H
#define PROV_SW_FREELIST_H

#include <stdio.h>
#include <semaphore.h>
#include "prov_sw_request.h"
#include "prov_sw_queue.h"

#ifndef MULTIBUFF_MAX_INFLIGHTS
#define MULTIBUFF_MAX_INFLIGHTS 128
#endif

typedef struct _flist_async {
        pthread_mutex_t mb_flist_mutex;
        op_data *head;
} flist_async;

typedef struct _mb_thread_data {
        pthread_t polling_thread;
        int keep_polling;
        sem_t mb_polling_thread_sem;
        queue_async *jobs;
        flist_async *freelist_jobs;
        IMB_MGR *imb_mgr;
        int woke_up;
} mb_thread_data;

flist_async *
flist_async_create();
int
flist_async_cleanup(flist_async *freelist);
int
flist_async_push(flist_async *freelist, op_data *item);
op_data *
flist_async_pop(flist_async *flist);
#endif
