/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_ABI_PROBE_H
#define TESTAPP_ABI_PROBE_H

#include <stdint.h>

/**
 * @brief Number of XMM registers checked by xmm_abi_probe() (XMM6-XMM15)
 */
#define ABI_PROBE_NUM_XMM 10

/**
 * @brief First XMM register index checked by xmm_abi_probe()
 */
#define ABI_PROBE_FIRST_XMM 6

/**
 * @brief Calls a function while checking Windows x64 ABI XMM6-XMM15 preservation
 *
 * Fills XMM6-XMM15 with unique per-register sentinel patterns, calls
 * func_ptr(arg1) and compares XMM6-XMM15 against the sentinels afterwards.
 * The Windows x64 calling convention declares XMM6-XMM15 callee-saved, so a
 * correctly behaving callee must leave them unchanged across the call.
 *
 * @param [in] func_ptr  Function to call, taking a single pointer argument
 * @param [in] arg1      Argument passed to func_ptr
 * @param [out] ret_out  Return value of func_ptr, NULL if not needed
 *
 * @return Bitmask of corrupted registers
 * @retval bit N set  XMM(ABI_PROBE_FIRST_XMM + N) was not preserved across the call
 * @retval 0          all XMM6-XMM15 registers were preserved
 */
uint32_t
xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out);

#endif /* TESTAPP_ABI_PROBE_H */
