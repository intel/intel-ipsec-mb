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
 * @brief Exercise generic burst APIs with caller-supplied preparation for cipher algorithms.
 *
 * @return 0 if all num_jobs completed and matched expected output, -1 otherwise.
 */
int
kat_cipher_test_generic_burst(struct IMB_MGR *mb_mgr, const struct cipher_test *const *vec_tab,
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

enum kat_cipher_burst_type {
        KAT_CIPHER_BURST_NONE = 0,
        KAT_CIPHER_BURST_GENERIC = 1,
        KAT_CIPHER_BURST_CIPHER = 2,
};

struct kat_cipher_test_case {
        int dir;
        int in_place;
        enum kat_cipher_burst_type burst;
        const char *label;
};

struct kat_cipher_dir_burst_case {
        int dir;
        enum kat_cipher_burst_type burst;
        const char *label;
};

struct kat_cipher_aes_prepare_ctx {
        const void *enc_keys;
        const void *dec_keys;
        const void *iv;
        size_t key_sched_len;
        unsigned iv_len;
};

/**
 * @brief Test an AES cipher vector through a selected job or burst API.
 *
 * Initializes the common AES job fields, copies the supplied encryption and decryption schedules
 * into job-local aligned storage, and dispatches to submit/flush, generic-burst, or cipher-only
 * burst testing according to @p burst_type. The expected plaintext or ciphertext is taken from
 * @p vec based on @p dir, and in-place operation is controlled by @p in_place.
 *
 * @return 0 if all num_jobs completed and matched expected output, -1 otherwise.
 */
int
kat_cipher_test_aes_common(struct IMB_MGR *mb_mgr, const void *enc_keys, const void *dec_keys,
                           const void *iv, const unsigned iv_len, const struct cipher_test *vec,
                           const int dir, const int order, const IMB_CIPHER_MODE cipher,
                           const int in_place, const unsigned key_len, const uint32_t num_jobs,
                           const enum kat_cipher_burst_type burst_type);

#endif /* KAT_COMMON_CIPHER_H */