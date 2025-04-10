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

mb_queue_update *
mb_queue_update_create()
{
        mb_queue_update *queue = OPENSSL_zalloc(sizeof(mb_queue_update));
        if (queue == NULL)
                return NULL;

        pthread_mutex_init(&queue->mb_queue_mutex, NULL);
        pthread_mutex_lock(&queue->mb_queue_mutex);

        queue->head = NULL;
        queue->tail = NULL;
        queue->disabled = 0;
        queue->num_items = 0;
        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return queue;
}

int
mb_queue_update_disable(mb_queue_update *queue)
{
        if (queue == NULL)
                return 1;

        pthread_mutex_lock(&queue->mb_queue_mutex);

        queue->disabled = 1;
        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return 0;
}

int
mb_queue_update_cleanup(mb_queue_update *queue)
{
        if (queue == NULL)
                return 1;

        pthread_mutex_destroy(&queue->mb_queue_mutex);
        OPENSSL_free(queue);

        return 0;
}

int
mb_queue_update_enqueue(mb_queue_update *queue, op_data *item)
{
        if (queue == NULL || item == NULL)
                return 1;

        pthread_mutex_lock(&queue->mb_queue_mutex);

        if (queue->disabled == 1) {
                pthread_mutex_unlock(&queue->mb_queue_mutex);
                return 1;
        }

        if (queue->num_items == 0) {
                queue->tail = item;
                queue->head = item;
        } else {
                queue->tail->next = item;
                queue->tail = item;
        }
        queue->tail->next = NULL;
        queue->num_items++;

        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return 0;
}

op_data *
mb_queue_update_dequeue(mb_queue_update *queue)
{
        if (queue == NULL)
                return NULL;

        pthread_mutex_lock(&queue->mb_queue_mutex);

        if (queue->head == NULL) {
                pthread_mutex_unlock(&queue->mb_queue_mutex);
                return NULL;
        }

        op_data *item = queue->head;
        queue->head = item->next;
        queue->num_items--;

        if (queue->num_items == 0)
                queue->tail = NULL;

        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return item;
}

int
mb_queue_update_get_size(mb_queue_update *queue)
{
        if (queue == NULL)
                return 0;

        pthread_mutex_lock(&queue->mb_queue_mutex);
        const int size = queue->num_items;
        pthread_mutex_unlock(&queue->mb_queue_mutex);

        return size;
}
