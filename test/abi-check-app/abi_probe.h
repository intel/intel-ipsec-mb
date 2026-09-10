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
 * @param [in] func_ptr  Function to call, taking a single pointer argument
 * @param [in] arg1      Argument passed to func_ptr
 * @param [out] ret_out  Return value of func_ptr, NULL if not needed
 *
 * @return Bitmask of corrupted registers
 * @retval bit ABI_PROBE_XMM_BIT(N) set  XMM(ABI_PROBE_FIRST_XMM + N) was not
 *             preserved across the call
 * @retval bit ABI_PROBE_GP_BIT(N) set   the GP register named by
 *             ABI_PROBE_GP_NAMES[N] was not preserved across the call
 * @retval 0   all checked registers were preserved
 */
uint32_t
xmm_abi_probe(void *func_ptr, void *arg1, void **ret_out);

#endif /* TESTAPP_ABI_PROBE_H */
