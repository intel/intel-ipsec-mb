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
#include <pthread.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_sw_queue.h"
#include "prov_sw_request.h"

/* OpenSSL Includes */
#include <openssl/err.h>

queue_async *
queue_async_create()
{
        queue_async *queue = OPENSSL_zalloc(sizeof(queue_async));
        if (queue == NULL)
                return NULL;

        pthread_mutex_init(&queue->mb_queue_mutex, NULL);

        queue->head = NULL;
        queue->tail = NULL;
        queue->disabled = 0;
        queue->num_items = 0;

        return queue;
}

int
queue_async_disable(queue_async *queue)
{
        if (queue == NULL)
                return 1;

        pthread_mutex_lock(&queue->mb_queue_mutex);
        queue->disabled = 1;
        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return 0;
}

int
queue_async_cleanup(queue_async *queue)
{
        if (queue == NULL)
                return 1;

        pthread_mutex_destroy(&queue->mb_queue_mutex);
        OPENSSL_free(queue);

        return 0;
}

int
queue_async_enqueue(queue_async *queue, op_data *item)
{
        if (queue == NULL || item == NULL || queue->disabled)
                return 1;

        pthread_mutex_lock(&queue->mb_queue_mutex);

        if (queue->num_items == 0) {
                queue->head = queue->tail = item;
        } else {
                queue->tail->next = item;
                queue->tail = item;
        }
        queue->tail->next = NULL;
        queue->num_items++;

        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return 0;
}

void *
queue_async_check_stuck_job(queue_async *queue)
{
        if (queue == NULL)
                return NULL;

        pthread_mutex_lock(&queue->mb_queue_mutex);

        void *job_ptr = NULL;
        if (queue->head != NULL) {
                struct timespec current_time;
                clock_gettime(CLOCK_MONOTONIC, &current_time);

                long elapsed_ms = (current_time.tv_sec - queue->head->timestamp.tv_sec) * 1000 +
                                  (current_time.tv_nsec - queue->head->timestamp.tv_nsec) / 1000000;

                if (elapsed_ms > 10) {
                        job_ptr = queue->head->job;
                        queue->head->flush = 1;
                }
        }

        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return job_ptr;
}

op_data *
queue_async_dequeue(queue_async *queue)
{
        if (queue == NULL)
                return NULL;

        pthread_mutex_lock(&queue->mb_queue_mutex);

        op_data *item = NULL;

        if (queue->tail != NULL) {
                item = queue->tail;

                if (queue->head == queue->tail) {
                        queue->head = queue->tail = NULL;
                } else {
                        op_data *current = queue->head;
                        while (current->next != queue->tail) {
                                current = current->next;
                        }
                        current->next = NULL;
                        queue->tail = current;
                }

                queue->num_items--;
        }

        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return item;
}

op_data *
queue_async_dequeue_find(queue_async *queue, ASYNC_JOB *job)
{
        if (queue == NULL || job == NULL)
                return NULL;

        pthread_mutex_lock(&queue->mb_queue_mutex);

        op_data *item = queue->head;
        op_data *prev = NULL;

        while (item != NULL) {
                if (item->job == job) {
                        if (prev != NULL) {
                                prev->next = item->next;
                        } else {
                                queue->head = item->next;
                        }
                        if (item == queue->tail) {
                                queue->tail = prev;
                        }
                        queue->num_items--;
                        break;
                }
                prev = item;
                item = item->next;
        }

        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return item;
}

int
queue_async_get_size(queue_async *queue)
{
        if (queue == NULL)
                return 0;

        pthread_mutex_lock(&queue->mb_queue_mutex);
        const int size = queue->num_items;
        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return size;
}
