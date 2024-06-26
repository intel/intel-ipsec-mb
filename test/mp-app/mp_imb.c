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

#include <stdio.h>
#include <intel-ipsec-mb.h>
#include <string.h>
#include "mp_alloc.h"
#include "mp_imb.h"

/*
 * =============================================================================
 * =============================================================================
 * IMB submit, flush and init functions
 */

int
flush_aes_cbc_enc_jobs(IMB_MGR *p_mgr, unsigned *jobs_received)
{
        if (p_mgr == NULL || jobs_received == NULL)
                return -2;

        while (IMB_FLUSH_JOB(p_mgr) != NULL) {
                const int err = imb_get_errno(p_mgr);

                if (err != 0) {
                        fprintf(stderr, "!Flush error: %s!\n", imb_get_strerror(err));
                        return -1;
                } else {
                        *jobs_received = *jobs_received + 1;
                }
        }

        return 0;
}

int
submit_aes_cbc_enc_jobs(IMB_MGR *p_mgr, void **in, void **out, const size_t n,
                        unsigned *jobs_received, unsigned *jobs_sent, void *exp_enc_key, void *iv,
                        const size_t msg_size)
{
        if (p_mgr == NULL || in == NULL || out == NULL || n == 0 || jobs_received == NULL ||
            jobs_sent == NULL || exp_enc_key == NULL || iv == NULL)
                return -2;

        for (size_t i = 0; i < n; i++) {
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                memset(job, 0, sizeof(*job));

                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = in[i];
                job->dst = out[i];
                job->cipher_mode = IMB_CIPHER_CBC;
                job->enc_keys = exp_enc_key;
                job->dec_keys = NULL;
                job->key_len_in_bytes = IMB_KEY_128_BYTES;

                job->iv = iv;
                job->iv_len_in_bytes = 16;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = msg_size;
                job->hash_alg = IMB_AUTH_NULL;

                IMB_JOB *job_ret = IMB_SUBMIT_JOB(p_mgr);

                if (imb_get_errno(p_mgr) == 0)
                        *jobs_sent = *jobs_sent + 1;
                else
                        return -1;

                if (job_ret != NULL)
                        *jobs_received = *jobs_received + 1;
        }

        return 0;
}

IMB_MGR *
init_imb(IMB_MGR *in_mb_mgr, struct allocator *app_alloc, const int is_pri)
{
        if (is_pri) {
                /*
                 * Primary process does all memory allocations in shared memory and
                 * stores pointers in data section that secondary process will inherit
                 */
                void *p_mgr = mp_alloc(app_alloc, imb_get_mb_mgr_size(), 64);

                if (p_mgr == NULL)
                        return NULL;

                /*
                 * Set up multi-buffer manager in the shared memory
                 * - imb_set_pointers_mb_mgr() call with reset parameter is required
                 *     Normally, alloc_mb_mgr() clears memory and sets selected feature flags.
                 * - it is followed with init_mb_mgr_auto() call
                 */

                IMB_MGR *mb_mgr = imb_set_pointers_mb_mgr(p_mgr, 0, 1);

                if (mb_mgr == NULL)
                        return NULL;

                init_mb_mgr_auto(mb_mgr, NULL);

                if (imb_get_errno(mb_mgr) != 0)
                        return NULL;

                return mb_mgr;

        } else {
                /*
                 * Secondary process picks allocations done by primary process and
                 * resets functions pointers in the manager
                 */
                void *p_mgr = (void *) in_mb_mgr;
                IMB_MGR *mb_mgr = imb_set_pointers_mb_mgr(p_mgr, 0, 0);

                return mb_mgr;
        }
}
