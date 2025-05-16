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

#include "e_prov.h"
#include "prov_sw_freelist.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include <emmintrin.h>

#include <openssl/err.h>

flist_async *
flist_async_create()
{
        flist_async *freelist = OPENSSL_zalloc(sizeof(flist_async));
        if (freelist == NULL)
                return NULL;

        if (pthread_mutex_init(&freelist->mb_flist_mutex, NULL) != 0) {
                OPENSSL_free(freelist);
                return NULL;
        }

        freelist->head = NULL;

        for (int i = 0; i < MULTIBUFF_MAX_INFLIGHTS; i++) {
                op_data *item = OPENSSL_zalloc(sizeof(op_data));
                if (item == NULL || flist_async_push(freelist, item) != 0) {
                        flist_async_cleanup(freelist);
                        return NULL;
                }
        }

        return freelist;
}

int
flist_async_cleanup(flist_async *freelist)
{
        op_data *item = NULL;

        if (freelist == NULL)
                return 1;

        pthread_mutex_lock(&freelist->mb_flist_mutex);

        while ((item = freelist->head) != NULL) {
                freelist->head = item->next;
                OPENSSL_free(item);
        }

        pthread_mutex_unlock(&freelist->mb_flist_mutex);
        pthread_mutex_destroy(&freelist->mb_flist_mutex);
        OPENSSL_free(freelist);

        return 0;
}

int
flist_async_push(flist_async *freelist, op_data *item)
{
        if (freelist == NULL || item == NULL)
                return 1;

        pthread_mutex_lock(&freelist->mb_flist_mutex);

        item->next = freelist->head;
        freelist->head = item;

        pthread_mutex_unlock(&freelist->mb_flist_mutex);

        return 0;
}

op_data *
flist_async_pop(flist_async *freelist)
{
        op_data *item = NULL;

        if (freelist == NULL)
                return NULL;

        pthread_mutex_lock(&freelist->mb_flist_mutex);

        if (freelist->head != NULL) {
                item = freelist->head;
                freelist->head = item->next;
        }

        pthread_mutex_unlock(&freelist->mb_flist_mutex);

        return item;
}
