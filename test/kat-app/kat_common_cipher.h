/****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef KAT_COMMON_CIPHER_H
#define KAT_COMMON_CIPHER_H

#include <stdint.h>

#include <intel-ipsec-mb.h>
#include "cipher_test.h"

/**
 * @brief Set algorithm-specific cipher job fields.
 *
 * @return 0 on success or -1 on failure.
 */
typedef int (*kat_job_prepare_cipher_fn)(struct IMB_MGR *mb_mgr, struct IMB_JOB *job,
                                         const struct cipher_test *vec, void *ctx);

/**
 * @brief Release algorithm-specific per-job resources.
 */
typedef void (*kat_job_cleanup_cipher_fn)(struct IMB_JOB *job, void *ctx);

/**
 * @brief Cipher test callback bundle.
 */
struct kat_cipher_job_ops {
        /* Optional preparation for algorithm-specific fields. */
        kat_job_prepare_cipher_fn prepare;
        /* Optional cleanup for per-job resources allocated by prepare(). */
        kat_job_cleanup_cipher_fn cleanup;
        void *ctx;
        IMB_CIPHER_MODE cipher_mode;
        IMB_CIPHER_DIRECTION cipher_direction;
        IMB_CHAIN_ORDER chain_order;
        uint32_t key_len_in_bytes;
        int in_place;
};

/**
 * @brief Exercise submit/flush cipher APIs with caller-supplied preparation.
 *
 * @return 0 if all num_jobs completed and matched expected output, -1 otherwise.
 */
int
kat_cipher_test_submit_flush(struct IMB_MGR *mb_mgr, const struct cipher_test *const *vec_tab,
                             const uint32_t vec_tab_num, const uint32_t num_jobs,
                             const struct kat_cipher_job_ops *ops);

/**
 * @brief Exercise cipher burst API with caller-supplied preparation.
 *
 * @return 0 if all num_jobs completed and matched expected output, -1 otherwise.
 */
int
kat_cipher_test_burst(struct IMB_MGR *mb_mgr, const struct cipher_test *const *vec_tab,
                      const uint32_t vec_tab_num, const uint32_t num_jobs,
                      const struct kat_cipher_job_ops *ops);

#endif /* KAT_COMMON_CIPHER_H */