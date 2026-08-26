/****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef KAT_COMMON_HASH_H
#define KAT_COMMON_HASH_H

#include <stddef.h>
#include <stdint.h>

#include <intel-ipsec-mb.h>
#include "mac_test.h"

/**
 * @brief Set algorithm-specific job fields.
 *
 * @return 0 on success or -1 on failure.
 */
typedef int (*kat_job_prepare_hash_fn)(struct IMB_MGR *mb_mgr, struct IMB_JOB *job,
                                       const struct mac_test *vec, void *ctx);

/**
 * @brief Release algorithm-specific per-job resources.
 */
typedef void (*kat_job_cleanup_hash_fn)(struct IMB_JOB *job, void *ctx);

/**
 * @brief Hash test callback bundle.
 */
struct kat_hash_job_ops {
        /* Optional preparation for algorithm-specific fields. */
        kat_job_prepare_hash_fn prepare;
        /* Optional cleanup for per-job resources allocated by prepare(). */
        kat_job_cleanup_hash_fn cleanup;
        void *ctx;
        /* Algorithm assigned to each prepared job. */
        IMB_HASH_ALG hash_alg;
};

/**
 * @brief Exercise submit/flush APIs with caller-supplied algorithm preparation.
 *
 * @return 0 if all num_jobs completed and matched their expected tag, -1 otherwise.
 */
int
kat_hash_test_submit_flush(struct IMB_MGR *mb_mgr, const struct mac_test *const *vec_tab,
                           const uint32_t vec_tab_num, const uint32_t num_jobs,
                           const struct kat_hash_job_ops *ops);

/**
 * @brief Exercise burst submit/flush APIs with caller-supplied algorithm preparation.
 *
 * @return 0 if all num_jobs completed and matched their expected tag, -1 otherwise.
 */
int
kat_hash_test_burst(struct IMB_MGR *mb_mgr, const struct mac_test *const *vec_tab,
                    const uint32_t vec_tab_num, const uint32_t num_jobs,
                    const struct kat_hash_job_ops *ops);

/**
 * @brief Exercise the hash-only burst API with caller-supplied algorithm preparation.
 *
 * ops->hash_alg selects the algorithm passed to the hash-only burst API.
 *
 * @return 0 if all num_jobs completed and matched their expected tag, -1 otherwise.
 */
int
kat_hash_test_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *const *vec_tab,
                         const uint32_t vec_tab_num, const uint32_t num_jobs,
                         const struct kat_hash_job_ops *ops);

#endif /* KAT_COMMON_HASH_H */
