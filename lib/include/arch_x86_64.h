/*******************************************************************************
  Copyright (c) 2022-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef IMB_ARCH_X86_64_H
#define IMB_ARCH_X86_64_H

#include "intel-ipsec-mb.h"

IMB_DLL_LOCAL void *
poly1305_mac_scalar(IMB_JOB *job);
IMB_DLL_LOCAL void
poly1305_aead_update_scalar(const void *msg, const uint64_t msg_len, void *hash, const void *key);
IMB_DLL_LOCAL void
poly1305_aead_complete_scalar(const void *hash, const void *key, void *tag);

/**
 * @brief Runs self test on selected CAVP algorithms
 *
 * @param p_mgr initialized MB manager structure
 *
 * @return Self test status
 * @retval 0 self test failed
 * @retval 1 self test passed
 */
IMB_DLL_LOCAL int
self_test(IMB_MGR *p_mgr);

/**
 * @brief Puts the manager into the fail-closed self-test error state
 *
 * Every IMB_MGR function pointer is replaced with a stub that sets
 * IMB_ERR_SELFTEST and returns without performing any operation.
 * The manager can only leave this state through a successful re-run of
 * init_mb_mgr_*().
 *
 * @param p_mgr MB manager structure
 */
IMB_DLL_LOCAL void
self_test_fail_closed(IMB_MGR *p_mgr);

/**
 * @brief Atomic 64-bit counter increment
 *
 * This implements counter post increment.
 *
 * @param counter pointer to a 64-bit counter
 *
 * @return Counter value prior to increment
 */
IMB_DLL_LOCAL uint64_t
atomic_uint64_inc(uint64_t *counter);

#endif /* IMB_ARCH_X86_64_H */
