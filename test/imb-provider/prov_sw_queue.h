/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_SW_QUEUE_H
#define PROV_SW_QUEUE_H

#include <stdio.h>
#include "prov_sw_request.h"

#define STUCK_JOB_TIMEOUT_MS 10

typedef struct _queue_async {
        pthread_mutex_t mb_queue_mutex;
        op_data *head;
        op_data *tail;
        int num_items;
        int disabled;
} queue_async;

queue_async *
queue_async_create();
int
queue_async_disable(queue_async *queue);
int
queue_async_cleanup(queue_async *queue);
int
queue_async_enqueue(queue_async *queue, op_data *item);
op_data *
queue_async_dequeue(queue_async *queue);
void *
queue_async_check_stuck_job(queue_async *queue);
op_data *
queue_async_dequeue_find(queue_async *queue, ASYNC_JOB *job);
int
queue_async_get_size(queue_async *queue);

#endif /* PROV_SW_QUEUE_H */
