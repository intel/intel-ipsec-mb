/****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef KAT_COMMON_AEAD_H
#define KAT_COMMON_AEAD_H

#include <stdint.h>

#include <intel-ipsec-mb.h>
#include "aead_test.h"

/**
 * @brief Set algorithm-specific AEAD job fields.
 *
 * @param [in,out] mb_mgr multi-buffer manager
 * @param [in,out] job    job structure to prepare
 * @param [in]     vec    test vector
 * @param [in,out] ctx    callback context pointer
 *
 * @return 0 on success or -1 on failure.
 */
typedef int (*kat_job_prepare_aead_fn)(struct IMB_MGR *mb_mgr, struct IMB_JOB *job,
                                       const struct aead_test *vec, const void *ctx);

/**
 * @brief Set custom algorithm-specific job fields for non-standard AEAD jobs.
 *
 * This is intentionally broader than the standard vec-based helper so packet-level
 * and hybrid algorithms can still reuse the common submission/validation lifecycle.
 */
typedef int (*kat_job_prepare_generic_fn)(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, void *ctx);

/**
 * @brief Release algorithm-specific per-job resources.
 *
 * @param [in,out] job job structure to clean up
 * @param [in,out] ctx callback context pointer
 */
typedef void (*kat_job_cleanup_aead_fn)(struct IMB_JOB *job, const void *ctx);

/**
 * @brief Release algorithm-specific resources owned by a custom job.
 */
typedef void (*kat_job_cleanup_generic_fn)(struct IMB_JOB *job, void *ctx);

/**
 * @brief Validate a completed custom job against algorithm-specific expectations.
 */
typedef int (*kat_job_validate_generic_fn)(struct IMB_JOB *job, const void *ctx);

/**
 * @brief AEAD test callback bundle.
 */
struct kat_aead_job_ops {
        /* Optional preparation for algorithm-specific fields. */
        kat_job_prepare_aead_fn prepare;
        /* Optional cleanup for per-job resources allocated by prepare(). */
        kat_job_cleanup_aead_fn cleanup;
        const void *ctx;
        IMB_CIPHER_MODE cipher_mode;
        IMB_HASH_ALG hash_alg;
        IMB_CIPHER_DIRECTION cipher_direction;
        IMB_CHAIN_ORDER chain_order;
        uint32_t key_len_in_bytes;
        int in_place;
};

/**
 * @brief Custom job callback bundle for non-standard AEAD jobs.
 */
struct kat_custom_job_ops {
        kat_job_prepare_generic_fn prepare;
        kat_job_cleanup_generic_fn cleanup;
        kat_job_validate_generic_fn validate;
        void *ctx;
};

enum kat_aead_test_mode {
        KAT_AEAD_SUBMIT_FLUSH,
        KAT_AEAD_BURST,
        KAT_AEAD_CCM_BURST,
        KAT_AEAD_ROUND_TRIP,
};

/**
 * @brief Dispatch an AEAD test to the appropriate internal test API.
 *
 * The selected internal API uses @p ops for submit/flush and burst modes,
 * including CCM burst mode. Round-trip mode also uses @p decrypt_ops and
 * requires exactly one vector and job from @p vec_tab.
 *
 * @return 0 on success or -1 on failure.
 */
int
kat_aead_test(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab, uint32_t vec_tab_num,
              uint32_t num_jobs, const struct kat_aead_job_ops *ops,
              const struct kat_aead_job_ops *decrypt_ops, enum kat_aead_test_mode mode);

/**
 * @brief Exercise mixed-direction submit/flush AEAD APIs with per-job preparation.
 *
 * @param [in,out] mb_mgr      multi-buffer manager
 * @param [in]     vec_tab     array of test vector pointers
 * @param [in]     vec_tab_num number of test vectors in vec_tab
 * @param [in]     num_jobs    number of jobs to test
 * @param [in]     ops_tab     array of test callback operations bundles
 *
 * @return 0 if all num_jobs completed and matched expected output, -1 otherwise.
 */
int
kat_aead_test_submit_flush_mixed(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                                 const uint32_t vec_tab_num, const uint32_t num_jobs,
                                 const struct kat_aead_job_ops *const *ops_tab);

/**
 * @brief Exercise submit/flush APIs with caller-owned custom job handling.
 *
 * Each prepare callback must associate per-job resources with @p job so they
 * remain available to validate and cleanup until that job is returned.
 */
int
kat_aead_test_custom_submit_flush(struct IMB_MGR *mb_mgr, const struct kat_custom_job_ops *ops,
                                  uint32_t num_jobs);

#endif /* KAT_COMMON_AEAD_H */