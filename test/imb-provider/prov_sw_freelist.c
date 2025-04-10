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
#include "prov_sw_freelist.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include <emmintrin.h>

/* OpenSSL Includes */
#include <openssl/err.h>

mb_flist_update *
mb_flist_update_create()
{
        mb_flist_update *freelist = NULL;
        op_data *item = NULL;
        int num_items = MULTIBUFF_MAX_INFLIGHTS;

        freelist = OPENSSL_zalloc(sizeof(mb_flist_update));
        if (freelist == NULL)
                return NULL;

        pthread_mutex_init(&freelist->mb_flist_mutex, NULL);

        freelist->head = NULL;

        while (num_items > 0) {
                item = OPENSSL_zalloc(sizeof(op_data));
                if (item == NULL) {
                        mb_flist_update_cleanup(freelist);
                        return NULL;
                }
                if (mb_flist_update_push(freelist, item) != 0) {
                        mb_flist_update_cleanup(freelist);
                        return NULL;
                }
                num_items--;
        }
        return freelist;
}

int
mb_flist_update_cleanup(mb_flist_update *freelist)
{
        op_data *item = NULL;

        if (freelist == NULL)
                return 1;

        pthread_mutex_lock(&freelist->mb_flist_mutex);

        while ((item = freelist->head) != NULL) {
                if (item->next != NULL) {
                        freelist->head = item->next;
                } else {
                        freelist->head = NULL;
                }
                OPENSSL_free(item);
        }

        pthread_mutex_unlock(&freelist->mb_flist_mutex);
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);

        return 0;
}

int
mb_flist_update_push(mb_flist_update *freelist, op_data *item)
{
        if (freelist == NULL)
                return 1;

        pthread_mutex_lock(&freelist->mb_flist_mutex);

        item->next = freelist->head;
        freelist->head = item;

        pthread_mutex_unlock(&freelist->mb_flist_mutex);

        return 0;
}

int
mb_flist_update_push_array(mb_flist_update *freelist, op_data **items, int num_items)
{
        if (freelist == NULL)
                return 1;

        pthread_mutex_lock(&freelist->mb_flist_mutex);

        for (int num = 0; num < num_items; num++) {
                op_data *item = (op_data *) items[num];
                prov_wake_job(item->job, ASYNC_STATUS_OK);
                OPENSSL_cleanse(item, sizeof(op_data));
                item->next = freelist->head;
                freelist->head = item;
        }

        _mm_sfence();

        pthread_mutex_unlock(&freelist->mb_flist_mutex);

        return 0;
}

op_data *
mb_flist_update_pop(mb_flist_update *freelist)
{
        if (freelist == NULL)
                return NULL;

        pthread_mutex_lock(&freelist->mb_flist_mutex);

        if (freelist->head == NULL) {
                pthread_mutex_unlock(&freelist->mb_flist_mutex);
                return NULL;
        }

        op_data *item = freelist->head;
        freelist->head = item->next;

        pthread_mutex_unlock(&freelist->mb_flist_mutex);

        return item;
}
