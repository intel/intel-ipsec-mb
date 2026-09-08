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
 * @brief Release algorithm-specific per-job resources.
 *
 * @param [in,out] job job structure to clean up
 * @param [in,out] ctx callback context pointer
 */
typedef void (*kat_job_cleanup_aead_fn)(struct IMB_JOB *job, const void *ctx);

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
 * @brief Exercise submit/flush AEAD APIs with caller-supplied preparation.
 *
 * @param [in,out] mb_mgr      multi-buffer manager
 * @param [in]     vec_tab     array of test vector pointers
 * @param [in]     vec_tab_num number of test vectors in vec_tab
 * @param [in]     num_jobs    number of jobs to test
 * @param [in]     ops         test callback operations bundle
 *
 * @return 0 if all num_jobs completed and matched expected output, -1 otherwise.
 */
int
kat_aead_test_submit_flush(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                           const uint32_t vec_tab_num, const uint32_t num_jobs,
                           const struct kat_aead_job_ops *ops);

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
 * @brief Exercise AEAD burst APIs with caller-supplied preparation.
 *
 * @param [in,out] mb_mgr      multi-buffer manager
 * @param [in]     vec_tab     array of test vector pointers
 * @param [in]     vec_tab_num number of test vectors in vec_tab
 * @param [in]     num_jobs    number of jobs to test
 * @param [in]     ops         test callback operations bundle
 *
 * @return 0 if all num_jobs completed and matched expected output, -1 otherwise.
 */
int
kat_aead_test_burst(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                    const uint32_t vec_tab_num, const uint32_t num_jobs,
                    const struct kat_aead_job_ops *ops);

/**
 * @brief Encrypt and decrypt one vector on an empty manager and verify the round-trip result.
 *
 * @param [in,out] mb_mgr      multi-buffer manager
 * @param [in]     vec         test vector
 * @param [in]     encrypt_ops encryption callback operations bundle
 * @param [in]     decrypt_ops decryption callback operations bundle
 *
 * @return 0 if the ciphertext/plaintext and tags round-trip correctly, -1 otherwise.
 */
int
kat_aead_test_round_trip(struct IMB_MGR *mb_mgr, const struct aead_test *vec,
                         const struct kat_aead_job_ops *encrypt_ops,
                         const struct kat_aead_job_ops *decrypt_ops);

#endif /* KAT_COMMON_AEAD_H */