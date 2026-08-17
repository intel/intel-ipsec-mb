/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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

#ifndef HMAC_COMMON_H
#define HMAC_COMMON_H

#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>
#include "mac_test.h"

/* Per-algorithm properties: the only part that varies between HMAC KATs */
struct hmac_alg_desc {
        IMB_HASH_ALG hash_alg;
        size_t digest_size;
        /*
         * Minimum number of submitted jobs before IMB_SUBMIT_JOB may legally
         * return a completed job (e.g. 8 for HMAC-MD5, 2 for SHANI HMAC-SHA).
         */
        uint32_t min_jobs_for_early_completion;
};

struct hmac_auth_bufs {
        uint8_t **auths;
        uint32_t num_jobs;
        size_t tag_size;
};

int
hmac_auth_bufs_alloc(struct hmac_auth_bufs *b, const uint32_t num_jobs, const size_t tag_size);

void
hmac_auth_bufs_free(struct hmac_auth_bufs *b);

int
hmac_job_ok(const struct mac_test *vec, const struct IMB_JOB *job, const uint8_t *auth,
            const size_t tag_size);

void
hmac_job_fill(struct IMB_JOB *job, const struct mac_test *vec, const struct hmac_alg_desc *desc,
              uint8_t *auth_buf, const size_t tag_size, const uint8_t *ipad_hash,
              const uint8_t *opad_hash);

int
hmac_test_submit_flush(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                       const size_t tag_size, const struct hmac_alg_desc *desc);

int
hmac_test_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                const size_t tag_size, const struct hmac_alg_desc *desc);

int
hmac_test_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                     const size_t tag_size, const struct hmac_alg_desc *desc);

#endif /* HMAC_COMMON_H */
