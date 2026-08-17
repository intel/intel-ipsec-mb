/*******************************************************************************
  Copyright (c) 2019-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef CONSTANT_LOOKUP_H
#define CONSTANT_LOOKUP_H

#include "intel-ipsec-mb.h"

/* intrinsic include is needed for data types used in prototypes */
#ifdef LINUX
#include <x86intrin.h>
#else
#include <intrin.h>
#endif

#ifdef SAFE_LOOKUP
#define LOOKUP8_SSE(_table, _idx, _size)  lookup_8bit_sse(_table, _idx, _size)
#define LOOKUP8_AVX(_table, _idx, _size)  lookup_8bit_avx(_table, _idx, _size)
#define LOOKUP32_SSE(_table, _idx, _size) lookup_32bit_sse(_table, _idx, _size)
#else
#define LOOKUP8_SSE(_table, _idx, _size)  _table[_idx]
#define LOOKUP8_AVX(_table, _idx, _size)  _table[_idx]
#define LOOKUP32_SSE(_table, _idx, _size) _table[_idx]
#endif

/**
 * @brief Constant time SSE lookup function on variable size table
 *        with 8-bit values
 *
 * @param[in] table     Pointer to the table to look up (16-byte aligned)
 * @param[in] idx       Index to look up
 * @param[in] size      Number of 8 bit elements in the table (multiple of 16)
 *
 * @return value to lookup
 */
IMB_DLL_LOCAL uint8_t
lookup_8bit_sse(const void *table, const uint32_t idx, const uint32_t size);

/**
 * @brief Constant time AVX lookup function on variable size table
 *        with 8-bit values
 *
 * @param[in] table     Pointer to the table to look up (16-byte aligned)
 * @param[in] idx       Index to look up
 * @param[in] size      Number of 8 bit elements in the table (multiple of 16)
 *
 * @return value to lookup
 */
IMB_DLL_LOCAL uint8_t
lookup_8bit_avx(const void *table, const uint32_t idx, const uint32_t size);

/**
 * @brief Constant time SSE lookup function on
 *        variable size table with 32-bit values
 *
 * @param[in] table     Pointer to the table to look up (16-byte aligned)
 * @param[in] idx       Index to look up
 * @param[in] size      Number of 32 bit elements in the table (multiple of 4)
 *
 * @return value to lookup
 */
IMB_DLL_LOCAL uint32_t
lookup_32bit_sse(const void *table, const uint32_t idx, const uint32_t size);

/**
 * @brief Constant time and parallel SSE lookup function on table of
 *        256 elements of 8-bit values.
 *
 * @param[in] indexes   vector with 16 8-bit indexes
 * @param[in] table     pointer to 256 element table
 *
 * @return Vector with 16 8-bit values corresponding to the indexes
 */
IMB_DLL_LOCAL __m128i
lookup_16x8bit_sse(const __m128i indexes, const void *table);

/**
 * @brief Constant time and parallel AVX lookup function on table of
 *        256 elements of 8-bit values.
 *
 * @param[in] indexes   vector with 16 8-bit indexes
 * @param[in] table     pointer to 256 element table
 *
 * @return Vector with 16 8-bit values corresponding to the indexes
 */
IMB_DLL_LOCAL __m128i
lookup_16x8bit_avx(const __m128i indexes, const void *table);

#ifdef AVX2
/**
 * @brief Constant time and parallel AVX2 lookup function on table of
 *        256 elements of 8-bit values.
 *
 * @param[in] indexes   vector with 32 8-bit indexes
 * @param[in] table     pointer to 256 element table
 *
 * @return Vector with 32 8-bit values corresponding to the indexes
 */
IMB_DLL_LOCAL __m256i
lookup_32x8bit_avx2(const __m256i indexes, const void *table);
#endif

#endif /* CONSTANT_LOOKUP_H */
