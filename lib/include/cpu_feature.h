/*******************************************************************************
  Copyright (c) 2018-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"

#ifndef CPU_FEATURE_H
#define CPU_FEATURE_H

/**
 * @brief Detects hardware features and returns their status
 *
 * @return Bitmask representing presence of CPU features/extensions,
 *         see intel-ipsec-mb.h IMB_FEATURE_xyz definitions for details.
 */
IMB_DLL_LOCAL uint64_t
cpu_feature_detect(void);

/**
 * @brief Modifies CPU \a features mask based on requested \a flags
 *
 * @param flags bitmask describing CPU feature adjustments
 * @param features bitmask describing present CPU features
 *
 * @return \a features with applied modifications on them via \a flags
 */
IMB_DLL_LOCAL uint64_t
cpu_feature_adjust(const uint64_t flags, uint64_t features);

#endif /* CPU_FEATURE_H */
