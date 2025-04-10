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

#ifndef PROV_SW_FREELIST_H
#define PROV_SW_FREELIST_H

#include <stdio.h>
#include <semaphore.h>
#include "prov_sw_request.h"
#include "prov_sw_queue.h"

typedef struct _mb_flist_update {
        pthread_mutex_t mb_flist_mutex;
        op_data *head;
} mb_flist_update;

typedef struct _mb_thread_data {
        pthread_t polling_thread;
        int keep_polling;
        sem_t mb_polling_thread_sem;
        mb_flist_update *update_freelist;
        mb_queue_update *update_queue;
} mb_thread_data;

mb_flist_update *
mb_flist_update_create();
int
mb_flist_update_cleanup(mb_flist_update *freelist);
int
mb_flist_update_push(mb_flist_update *freelist, op_data *item);
int
mb_flist_update_push_array(mb_flist_update *freelist, op_data **items, int num_items);
op_data *
mb_flist_update_pop(mb_flist_update *flist);
#endif
