/****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef KAT_COMMON_HASH_H
#define KAT_COMMON_HASH_H

#include <stddef.h>

#include <intel-ipsec-mb.h>
#include "mac_test.h"

typedef int (*kat_job_prepare_hash_fn)(struct IMB_JOB *job, void *ctx);

/* Hash test callback bundle. tag_size == 0 uses the vector's tagSize field. */
struct kat_hash_job_ops {
        kat_job_prepare_hash_fn prepare;
        size_t tag_size;
        void *ctx;
};

/* Initializes fields common to hash-only KAT jobs. Algorithm fields are caller-owned. */
void
kat_hash_job_init(struct IMB_JOB *job, const void *src, const size_t msg_len, const size_t tag_len);

/* Common MAC/hash tag validation and auth_tag_output cleanup helpers. */
int
kat_hash_job_check(const struct IMB_JOB *job, const void *vec, const void *ctx);

void
kat_hash_job_cleanup(struct IMB_JOB *job, void *ctx);

/* Exercises submit/flush APIs while callers supply algorithm-specific preparation. */
int
kat_hash_test_submit_flush(struct IMB_MGR *mb_mgr, const void *vec, const uint32_t num_jobs,
                           const struct kat_hash_job_ops *ops);

int
kat_hash_test_burst(struct IMB_MGR *mb_mgr, const void *vec, const uint32_t num_jobs,
                    const struct kat_hash_job_ops *ops);

int
kat_hash_test_hash_burst(struct IMB_MGR *mb_mgr, const void *vec, const uint32_t num_jobs,
                         const IMB_HASH_ALG hash_alg, const struct kat_hash_job_ops *ops);

#endif /* KAT_COMMON_HASH_H */
