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
 * @brief Bitmask bit occupied by XMM(ABI_PROBE_FIRST_XMM + n)
 */
#define ABI_PROBE_XMM_BIT(n) (n)

/**
 * @brief Number of general purpose registers checked by xmm_abi_probe()
 *
 * RBX, RBP, RSI, RDI, R12, R13, R14 and R15 are the Windows x64
 * callee-saved general purpose registers (besides RSP, which is not
 * checked here since a stack imbalance would corrupt the probe itself).
 */
#define ABI_PROBE_NUM_GP 8

/**
 * @brief Bitmask bit occupied by the n-th checked GP register
 *
 * n follows the order: 0=RBX, 1=RBP, 2=RSI, 3=RDI, 4=R12, 5=R13, 6=R14, 7=R15
 */
#define ABI_PROBE_GP_BIT(n) (ABI_PROBE_NUM_XMM + (n))

/**
 * @brief Names of the GP registers checked, indexed as per ABI_PROBE_GP_BIT()
 */
#define ABI_PROBE_GP_NAMES { "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15" }

/**
 * @brief Bitmask bit set when func_ptr() leaves the upper 128 bits of
 *        YMM6-YMM15 dirty (non-zero) after the call
 *
 * Only meaningful when xmm_abi_probe() is called with check_vzeroupper
 * non-zero. This is a best-effort signal that AVX code was executed
 * without a trailing VZEROUPPER; unlike the XMM/GP bits above it is not a
 * callee-saved register ABI violation (the upper YMM/ZMM halves are not
 * defined as callee-saved), but a performance-cliff issue for callers that
 * subsequently run legacy SSE code.
 */
#define ABI_PROBE_VZEROUPPER_BIT (ABI_PROBE_NUM_XMM + ABI_PROBE_NUM_GP)

/**
 * @brief Calls a function while checking Windows x64 ABI callee-saved
 *        register preservation
 *
 * Fills XMM6-XMM15 and the callee-saved general purpose registers (RBX,
 * RBP, RSI, RDI, R12-R15) with unique per-register sentinel patterns,
 * calls func_ptr(arg1) and compares all of them against the sentinels
 * afterwards. The Windows x64 calling convention declares these registers
 * callee-saved, so a correctly behaving callee must leave them unchanged
 * across the call.
 *
 * The probe itself behaves as a proper Windows x64 callee: the caller's
 * original XMM6-XMM15 values are saved before the sentinels are loaded and
 * restored again before xmm_abi_probe() returns, so calling this function
 * does not corrupt the caller's own (compiler-managed) XMM state.
 *
 * When check_vzeroupper is non-zero, the upper 128 bits of YMM6-YMM15 are
 * also seeded with a non-zero pattern and checked for being left dirty
 * (see ABI_PROBE_VZEROUPPER_BIT). Only pass a non-zero value for
 * architectures that are expected to execute AVX+ code (not for SSE),
 * otherwise the untouched seeded pattern will be reported as dirty.
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
 *             preserved across the call
 * @retval bit ABI_PROBE_GP_BIT(N) set   the GP register named by
 *             ABI_PROBE_GP_NAMES[N] was not preserved across the call
 * @retval bit ABI_PROBE_VZEROUPPER_BIT set  upper YMM6-YMM15 halves left
 *             dirty (see check_vzeroupper)
 * @retval 0   all checked registers were preserved
 */
uint32_t
xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out, int check_vzeroupper);

#endif /* TESTAPP_ABI_PROBE_H */
