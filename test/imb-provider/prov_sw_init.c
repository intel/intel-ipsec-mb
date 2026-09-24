/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

#include "e_prov.h"
#include "prov_sw_polling.h"
#include "prov_sw_request.h"
#include "prov_sw_freelist.h"
#include "prov_sw_queue.h"
#include "prov_events.h"

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

static mb_thread_data *global_tlv = NULL;
static pthread_mutex_t global_tlv_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_int global_tlv_initialized = 0;

static int
initialize_global_tlv()
{
        if (atomic_load(&global_tlv_initialized)) {
                return 1;
        }

        pthread_mutex_lock(&global_tlv_init_mutex);

        if (global_tlv == NULL) {
                global_tlv = OPENSSL_zalloc(sizeof(mb_thread_data));
                if (global_tlv == NULL) {
                        fprintf(stderr, "Failed to allocate global TLV.\n");
                        goto null;
                }

                global_tlv->imb_mgr = alloc_mb_mgr(0);
                if (global_tlv->imb_mgr == NULL) {
                        fprintf(stderr, "Error allocating Intel IPsec MB_MGR!\n");
                        goto err;
                }

                init_mb_mgr_auto(global_tlv->imb_mgr, NULL);

                const int init_err = imb_get_errno(global_tlv->imb_mgr);

                if (init_err != 0) {
                        fprintf(stderr, "Error initializing Intel IPsec MB_MGR: %s\n",
                                imb_get_strerror(init_err));
                        goto err;
                }

                if (((global_tlv->jobs = queue_async_create()) == NULL) ||
                    ((global_tlv->freelist_jobs = flist_async_create()) == NULL)) {
                        fprintf(stderr, "Failure to allocate global freelists and queues.\n");
                        goto err;
                }

                if (sem_init(&global_tlv->mb_polling_thread_sem, 0, 0) == -1) {
                        fprintf(stderr, "sem_init failed!\n");
                        goto err;
                }

                global_tlv->keep_polling = 1;

                if (prov_create_thread(&global_tlv->polling_thread, NULL, multibuff_timer_poll_func,
                                       global_tlv)) {
                        fprintf(stderr, "Creation of polling thread failed.\n");
                        sem_destroy(&global_tlv->mb_polling_thread_sem);
                        goto err;
                }

                fprintf(stderr, "Global polling thread created %lx, global_tlv %p\n",
                        (uintptr_t) global_tlv->polling_thread, global_tlv);

                atomic_store(&global_tlv_initialized, 1);
        }

        pthread_mutex_unlock(&global_tlv_init_mutex);
        return 1;

err:
        if (global_tlv->imb_mgr) {
                free_mb_mgr(global_tlv->imb_mgr);
                global_tlv->imb_mgr = NULL;
        }
        OPENSSL_free(global_tlv);
        global_tlv = NULL;
null:
        pthread_mutex_unlock(&global_tlv_init_mutex);
        return 0;
}

static void
cleanup_global_tlv()
{
        if (global_tlv != NULL) {
                op_data *req;

                /*
                 * Stop the polling thread and wait for it before anything it
                 * touches goes away: it dereferences the job queue and the
                 * semaphore on every iteration. Posting the semaphore breaks it
                 * out of sem_timedwait() at once instead of after another
                 * polling period.
                 */
                global_tlv->keep_polling = 0;
                sem_post(&global_tlv->mb_polling_thread_sem);
                pthread_join(global_tlv->polling_thread, NULL);
                sem_destroy(&global_tlv->mb_polling_thread_sem);

                queue_async_disable(global_tlv->jobs);
                if (global_tlv->jobs) {
                        /* Anything still queued belongs to an operation that
                         * will never complete; release its waiter. */
                        while ((req = queue_async_dequeue(global_tlv->jobs)) != NULL) {
                                prov_wake_job(req->job);
                                OPENSSL_free(req);
                        }
                        queue_async_cleanup(global_tlv->jobs);
                }

                flist_async_cleanup(global_tlv->freelist_jobs);

                if (global_tlv->imb_mgr != NULL) {
                        free_mb_mgr(global_tlv->imb_mgr);
                        global_tlv->imb_mgr = NULL;
                }

                OPENSSL_free(global_tlv);
                global_tlv = NULL;

                atomic_store(&global_tlv_initialized, 0);
        }
}

void
mb_cleanup_thread_local(void)
{
        pthread_mutex_lock(&global_tlv_init_mutex);
        cleanup_global_tlv();
        pthread_mutex_unlock(&global_tlv_init_mutex);
}

mb_thread_data *
mb_check_thread_local()
{
        if (!initialize_global_tlv()) {
                cleanup_global_tlv();
                return NULL;
        }
        return global_tlv;
}
