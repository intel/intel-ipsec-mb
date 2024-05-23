/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

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
*****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "mp_alloc.h"
#include "mp_shared_mem.h"
#include "mp_imb.h"
#include "mp_info_context.h"

#if defined(__MINGW32__)

static int
mp_primary(const char *name2)
{
        (void) name2;
        printf("Multi-Process test not executed.\n");
        return 0;
}

#else

#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/wait.h>
#endif

/*
 * =============================================================================
 * =============================================================================
 * Primary processes
 */

/*
 * Process data
 * - primary process allocates and initializes them
 * - secondary process only picks them up
 * All shared memory allocations will have the same virtual address
 * in primary and secondary processes.
 */

static int
alloc_crypto_op_data(struct info_context *ctx, struct allocator *app_alloc, const int is_pri)
{
        if (!is_pri)
                return 0;

        /*
         * Primary process does all memory allocations in shared memory and
         * stores pointers in data section that secondary process will inherit
         */
        size_t i;

        ctx->exp_enc_key = mp_alloc(app_alloc, 11 * 16, 16);
        ctx->exp_dec_key = mp_alloc(app_alloc, 11 * 16, 16);
        ctx->aes_key = mp_alloc(app_alloc, 16, 0);
        ctx->iv = mp_alloc(app_alloc, 16, 0);

        for (i = 0; i < IMB_DIM(ctx->buffer_table_in_out); i++) {
                ctx->buffer_table_in_out[i] = mp_alloc(app_alloc, buffer_size, 4);
                if (ctx->buffer_table_in_out[i] == NULL)
                        break;
                memset(ctx->buffer_table_in_out[i], (int) ~i, buffer_size);

                ctx->buffer_table_ref[i] = mp_alloc(app_alloc, buffer_size, 4);
                if (ctx->buffer_table_ref[i] == NULL)
                        break;
                memset(ctx->buffer_table_ref[i], 0, buffer_size);
        }

        if (ctx->exp_enc_key == NULL || ctx->exp_dec_key == NULL || ctx->aes_key == NULL ||
            ctx->iv == NULL || i < IMB_DIM(ctx->buffer_table_in_out))
                return -1;

        return 0;
}

static int
prepare_reference_output(struct info_context *ctx, const int is_pri)
{
        if (!is_pri)
                return 0;

        /* Create key schedule and set IV */
        memset(ctx->aes_key, 0xaa, 16);
        IMB_AES_KEYEXP_128(ctx->mb_mgr, ctx->aes_key, ctx->exp_enc_key, ctx->exp_dec_key);

        memset(ctx->iv, 0x55, 16);

        /*
         * Use allocated manager to get reference answers
         */
        ctx->jobs_sent = 0;
        ctx->jobs_received = 0;

        if (submit_aes_cbc_enc_jobs(ctx->mb_mgr, ctx->buffer_table_in_out, ctx->buffer_table_ref,
                                    IMB_DIM(ctx->buffer_table_in_out), &ctx->jobs_received,
                                    &ctx->jobs_sent, ctx->exp_enc_key, ctx->iv, buffer_size) != 0)
                return -1;

        if (flush_aes_cbc_enc_jobs(ctx->mb_mgr, &ctx->jobs_received) != 0)
                return -1;

        if (ctx->jobs_sent != IMB_DIM(ctx->buffer_table_in_out))
                return -1;

        ctx->jobs_sent = 0;
        ctx->jobs_received = 0;
        return 0;
}

static int
mp_primary(const char *name2)
{
        const int is_pri = 1;
        struct shared_memory app_shm, info_shm;
        struct info_context *ctx = NULL;
        struct allocator app_alloc;

        fprintf(stdout, "PRIMARY: init start %p\n", (void *) imb_get_errno);

        if (shm_create(&info_shm, is_pri, SHM_INFO_NAME, SHM_INFO_SIZE, NULL) != 0)
                return -1;

        /* cast info shared memory onto info context structure */
        ctx = (struct info_context *) info_shm.ptr;
        memset(ctx, 0, sizeof(*ctx));

        if (shm_create(&app_shm, is_pri, SHM_DATA_NAME, SHM_DATA_SIZE, NULL) != 0) {
                (void) shm_destroy(&info_shm, is_pri);
                return -1;
        }

        /* secondary process needs to mmap app/data shared memory at this address */
        ctx->app_mmap = app_shm.ptr;

        /* init allocator on app/data shared memory */
        mp_init(&app_alloc, app_shm.ptr, app_shm.size);

        /* init IMB */
        ctx->mb_mgr = init_imb(NULL, &app_alloc, is_pri);
        if (ctx->mb_mgr == NULL) {
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        fprintf(stdout, "PRIMARY: init complete\n");

        /* allocate data for crypto operations */
        if (alloc_crypto_op_data(ctx, &app_alloc, is_pri) != 0) {
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        /* generate reference output data */
        if (prepare_reference_output(ctx, is_pri) != 0) {
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        /* send jobs in primary process */
        ctx->jobs_sent = 0;
        ctx->jobs_received = 0;
        if (submit_aes_cbc_enc_jobs(ctx->mb_mgr, ctx->buffer_table_in_out, ctx->buffer_table_in_out,
                                    IMB_DIM(ctx->buffer_table_in_out), &ctx->jobs_received,
                                    &ctx->jobs_sent, ctx->exp_enc_key, ctx->iv, buffer_size) != 0) {
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        fprintf(stdout, "PRIMARY: sent %u AES-128-CBC encrypt jobs\n", ctx->jobs_sent);
        fprintf(stdout, "PRIMARY: received %u AES-128-CBC encrypt jobs\n", ctx->jobs_received);

        if (ctx->jobs_sent != IMB_DIM(ctx->buffer_table_in_out)) {
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        /*
         * - spawn secondary process now
         * - let the secondary perform the flush operation
         * - wait for the secondary process to complete and check the results
         */
        fprintf(stdout, "PRIMARY: starting SECONDARY process now\n");

        const int status = system(name2);

#ifdef _WIN32
        const int err = (status != EXIT_SUCCESS);
#endif

#if defined(__linux__) || defined(__FreeBSD__)
        const int err = (!WIFEXITED(status)) || (WEXITSTATUS(status) != EXIT_SUCCESS);
#endif

        if (err != 0) {
                fprintf(stderr, "PRIMARY: SECONDARY process failed\n");
                fprintf(stdout, "MULTI-PROCESS TEST: FAILED\n");
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        fprintf(stdout, "PRIMARY: SECONDARY has finished\n");

        /*
         * Child process exited normally - let's check the answers
         */
        unsigned mismatch = 0;

        for (size_t i = 0; i < IMB_DIM(ctx->buffer_table_in_out); i++)
                if (memcmp(ctx->buffer_table_in_out[i], ctx->buffer_table_ref[i], buffer_size) != 0)
                        mismatch++;

        fprintf(stdout, "MULTI-PROCESS TEST: %s\n", mismatch ? "FAILED " : "PASSED");

        fprintf(stdout, "PRIMARY: finished\n");

        /* clean up and exit */
        if (shm_destroy(&info_shm, is_pri) != 0) {
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }
        if (shm_destroy(&app_shm, is_pri) != 0)
                return -1;

        return 0;
}
#endif /* _WIN32 || __linux__ || __FreeBSD__ */

int
main(int argc, char **argv)
{
        int ret = -1;

        if (argc > 1)
                ret = mp_primary(argv[1]);
        else
                fprintf(stderr,
                        "ERROR: argument required! Command syntax: %s <PATH TO SECONDARY APP>\n",
                        argv[0]);

        return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
