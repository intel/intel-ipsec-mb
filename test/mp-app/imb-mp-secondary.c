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

#include "mp_shared_mem.h"
#include "mp_imb.h"
#include "mp_info_context.h"

#if defined(__MINGW32__)

static int
mp_secondary(const char *shm_info_uname, const char *shm_data_uname)
{
        (void) shm_info_uname;
        (void) shm_data_uname;
        printf("Multi-Process test not executed.\n");
        return 0;
}

#else

/*
 * =============================================================================
 * =============================================================================
 * Secondary processes
 */

static int
mp_secondary(const char *shm_info_uname, const char *shm_data_uname)
{
        const int is_pri = 0;
        struct shared_memory app_shm, info_shm;
        struct info_context *ctx = NULL;

        fprintf(stdout, "SECONDARY: init start %p, %s, %s\n", (void *) imb_get_errno,
                shm_info_uname, shm_data_uname);

        if (shm_create(&info_shm, is_pri, shm_info_uname, SHM_INFO_SIZE, NULL) != 0)
                return -1;

        /* cast info shared memory onto info context structure */
        ctx = (struct info_context *) info_shm.ptr;

        /* check if any jobs were sent */
        if (ctx->jobs_sent == 0) {
                (void) shm_destroy(&info_shm, is_pri);
                return -1;
        }

        if (shm_create(&app_shm, is_pri, shm_data_uname, SHM_DATA_SIZE, ctx->app_mmap) != 0) {
                (void) shm_destroy(&info_shm, is_pri);
                return -1;
        }

        /* init IMB */
        if (init_imb(ctx->mb_mgr, NULL, is_pri) == NULL) {
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        fprintf(stdout, "SECONDARY: init complete\n");

        /* flush jobs sent by primary process */
        unsigned jobs_received_now = 0;

        if (flush_aes_cbc_enc_jobs(ctx->mb_mgr, &jobs_received_now) != 0) {
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        ctx->jobs_received += jobs_received_now;

        fprintf(stdout, "SECONDARY: received %u (total %u) AES-128-CBC encrypt jobs\n",
                jobs_received_now, ctx->jobs_received);

        if (ctx->jobs_sent != ctx->jobs_received) {
                fprintf(stderr, "SECONDARY: expected %u jobs, received %u\n", ctx->jobs_sent,
                        ctx->jobs_received);
                (void) shm_destroy(&info_shm, is_pri);
                (void) shm_destroy(&app_shm, is_pri);
                return -1;
        }

        fprintf(stdout, "SECONDARY: finished\n");

#ifdef _WIN32
        _flushall();
#endif

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

        (void) argc;
        (void) argv;

        if (argc == 3)
                ret = mp_secondary(argv[1], argv[2]);

        return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
