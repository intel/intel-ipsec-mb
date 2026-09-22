/*******************************************************************************
  Copyright (c) 2009-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef _SNOW3G_TABLES_H_
#define _SNOW3G_TABLES_H_

#include <stdint.h>
#include "constant_lookup.h"

#if defined(AVX) || defined(AVX2)
#define SNOW3G_SAFE_LUT8(table, idx, size) LOOKUP8_AVX(table, idx, size)
#else /* SSE */
#define SNOW3G_SAFE_LUT8(table, idx, size) LOOKUP8_SSE(table, idx, size)
#endif /* AVX || AVX2 */

extern const int snow3g_table_A_mul[256];
extern const int snow3g_table_A_div[256];
extern const uint8_t snow3g_invSR_SQ[256];
extern const uint64_t snow3g_table_S2[256];

extern const uint8_t snow3g_MULa_byte0_low[16];
extern const uint8_t snow3g_MULa_byte1_low[16];
extern const uint8_t snow3g_MULa_byte2_low[16];
extern const uint8_t snow3g_MULa_byte3_low[16];
extern const uint8_t snow3g_MULa_byte0_hi[16];
extern const uint8_t snow3g_MULa_byte1_hi[16];
extern const uint8_t snow3g_MULa_byte2_hi[16];
extern const uint8_t snow3g_MULa_byte3_hi[16];

extern const uint8_t snow3g_DIVa_byte0_low[16];
extern const uint8_t snow3g_DIVa_byte1_low[16];
extern const uint8_t snow3g_DIVa_byte2_low[16];
extern const uint8_t snow3g_DIVa_byte3_low[16];
extern const uint8_t snow3g_DIVa_byte0_hi[16];
extern const uint8_t snow3g_DIVa_byte1_hi[16];
extern const uint8_t snow3g_DIVa_byte2_hi[16];
extern const uint8_t snow3g_DIVa_byte3_hi[16];

#endif /* _SNOW3G_TABLES_H_  */
