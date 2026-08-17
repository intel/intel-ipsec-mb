/*****************************************************************************
 Copyright (c) 2021-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

/**
 * @brief Measure TSC for set number of cycles
 *
 * @param cycles Number of iterations to run fixed cost loop with
 *               1-cycle latency dependency on all non-ancient CPUs
 *
 * @return Number of TSC cycles measured while in fixed cost loop
 */
uint64_t
measure_tsc(const uint64_t cycles);

/**
 * See the following links for more information about SSC marks:
 * https://community.intel.com/t5/Intel-ISA-Extensions/Merging-DCFG-regions-in-SDE-when-using-start-stop-ssc-mark/m-p/1232096
 * https://www.intel.com/content/www/us/en/developer/articles/technical/pintool-regions.html
 * https://github.com/WebAssembly/design/issues/1344
 */

/**
 * @brief Issue SSC mark 4
 */
void
ssc_mark4(void);

/**
 * @brief Issue SSC mark 5
 */
void
ssc_mark5(void);

/**
 * @brief Issue SSC mark 6
 */
void
ssc_mark6(void);

/**
 * @brief Issue SSC mark 7
 */
void
ssc_mark7(void);
