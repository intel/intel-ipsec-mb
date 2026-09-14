/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_ABI_PROBE_H
#define TESTAPP_ABI_PROBE_H

#include <stdint.h>

/**
 * Callee-saved register sets of the two x86-64 ABIs:
 * - Windows x64: XMM6-XMM15 and RBX, RBP, RSI, RDI, R12-R15
 * - System V AMD64: RBX, RBP, R12-R15 only (no XMM, and RSI/RDI are
 *   argument registers)
 *
 * RSP is callee-saved on both but is not checked, as a stack imbalance
 * would corrupt the probe itself.
 */
#ifdef _WIN32
/** @brief Number of XMM registers checked by xmm_abi_probe() (XMM6-XMM15) */
#define ABI_PROBE_NUM_XMM 10

/** @brief Number of general purpose registers checked by xmm_abi_probe() */
#define ABI_PROBE_NUM_GP 8

/** @brief Names of the GP registers checked, indexed as per ABI_PROBE_GP_BIT() */
#define ABI_PROBE_GP_NAMES { "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15" }
#else
/** @brief Number of XMM registers checked, zero on System V AMD64 */
#define ABI_PROBE_NUM_XMM  0

/** @brief Number of general purpose registers checked by xmm_abi_probe() */
#define ABI_PROBE_NUM_GP   6

/** @brief Names of the GP registers checked, indexed as per ABI_PROBE_GP_BIT() */
#define ABI_PROBE_GP_NAMES { "rbx", "rbp", "r12", "r13", "r14", "r15" }
#endif /* _WIN32 */

/**
 * @brief First XMM register index checked by xmm_abi_probe()
 */
#define ABI_PROBE_FIRST_XMM 6

/**
 * @brief Bitmask bit occupied by XMM(ABI_PROBE_FIRST_XMM + n)
 */
#define ABI_PROBE_XMM_BIT(n) (n)

/**
 * @brief Bitmask bit occupied by the n-th checked GP register
 *
 * n indexes ABI_PROBE_GP_NAMES.
 */
#define ABI_PROBE_GP_BIT(n) (ABI_PROBE_NUM_XMM + (n))

/**
 * @brief Bitmask bit set when func_ptr() leaves the upper 128 bits of
 *        YMM6-YMM15 dirty (non-zero) after the call
 *
 * Only meaningful with check_vzeroupper non-zero. Signals AVX code without
 * a trailing VZEROUPPER: not an ABI violation (the upper YMM/ZMM halves
 * are not callee-saved), but a performance cliff for legacy SSE callers.
 */
#define ABI_PROBE_VZEROUPPER_BIT (ABI_PROBE_NUM_XMM + ABI_PROBE_NUM_GP)

/**
 * @brief Calls a function while checking x86-64 ABI callee-saved register
 *        preservation
 *
 * Fills the callee-saved registers of the host ABI (see above) with unique
 * per-register sentinels, calls func_ptr(arg1) and compares them against
 * the sentinels afterwards.
 *
 * On Windows x64 the caller's XMM6-XMM15 are saved and restored around the
 * sentinels, so the probe does not corrupt the caller's own XMM state. On
 * System V AMD64 those registers are call-clobbered and not checked.
 *
 * When check_vzeroupper is non-zero, the upper 128 bits of YMM6-YMM15 are
 * seeded and checked for being left dirty (see
 * ABI_PROBE_VZEROUPPER_BIT). Only pass a non-zero value for architectures
 * expected to execute AVX+ code, otherwise the untouched seed is reported
 * as dirty. It also gates the only non-baseline (AVX and SSE4.1)
 * instructions of the probe, so a zero value is safe on any x86-64 CPU.
 *
 * @param [in] func_ptr  Function to call, taking a single pointer argument
 * @param [in] arg1      Argument passed to func_ptr
 * @param [out] ret_out  Return value of func_ptr, NULL if not needed
 * @param [in] check_vzeroupper  Non-zero to also check for a missing
 *             VZEROUPPER (see ABI_PROBE_VZEROUPPER_BIT); pass 0 for
 *             architectures that never execute AVX+ code (e.g. SSE)
 *
 * @return Bitmask of corrupted registers
 * @retval bit ABI_PROBE_XMM_BIT(N) set  XMM(ABI_PROBE_FIRST_XMM + N) was not
 *             preserved across the call (Windows x64 only)
 * @retval bit ABI_PROBE_GP_BIT(N) set   the GP register named by
 *             ABI_PROBE_GP_NAMES[N] was not preserved across the call
 * @retval bit ABI_PROBE_VZEROUPPER_BIT set  upper YMM6-YMM15 halves left
 *             dirty (see check_vzeroupper)
 * @retval 0   all checked registers were preserved
 */
uint32_t
xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out, int check_vzeroupper);

#endif /* TESTAPP_ABI_PROBE_H */
