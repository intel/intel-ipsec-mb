/**********************************************************************
  Copyright(c) 2018-2026 Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

/**
 * @brief Provides access to MSR read & write operations
 */

#ifndef __MSR_H__
#define __MSR_H__

#include <stdint.h>
#include <stdlib.h>
#ifdef DEBUG
#include <assert.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
#define ASSERT assert
#else
#define ASSERT(x)
#endif

#define MACHINE_DEFAULT_MAX_COREID 255 /**< max core id */

#define MACHINE_RETVAL_OK    0 /**< everything OK */
#define MACHINE_RETVAL_ERROR 1 /**< generic error */
#define MACHINE_RETVAL_PARAM 2 /**< parameter error */

/**
 * @brief Initializes machine module
 *
 * @param [in] max_core_id maximum logical core id to be handled by machine
 *             module. If zero then default value assumed
 *             \a MACHINE_DEFAULT_MAX_COREID
 *
 * @return Operation status
 * @retval MACHINE_RETVAL_OK on success
 */
int
machine_init(const unsigned max_core_id);

/**
 * @brief Shuts down machine module
 *
 * @return Operation status
 * @retval MACHINE_RETVAL_OK on success
 */
int
machine_fini(void);

/**
 * @brief Executes RDMSR on \a lcore logical core
 *
 * @param [in] lcore logical core id
 * @param [in] reg MSR to read from
 * @param [out] value place to store MSR value at
 *
 * @return Operation status
 * @retval MACHINE_RETVAL_OK on success
 */
int
msr_read(const unsigned lcore, const uint32_t reg, uint64_t *const value);

/**
 * @brief Executes WRMSR on \a lcore logical core
 *
 * @param [in] lcore logical core id
 * @param [in] reg MSR to write to
 * @param [in] value to be written into \a reg
 *
 * @return Operation status
 * @retval MACHINE_RETVAL_OK on success
 */
int
msr_write(const unsigned lcore, const uint32_t reg, const uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* __MSR_H__ */
