/*******************************************************************************
  Copyright (c) 2019, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
      * Neither the name of Intel Corporation nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#ifndef CONSTANT_LOOKUP_H
#define CONSTANT_LOOKUP_H

#include "intel-ipsec-mb.h"

#ifdef SAFE_LOOKUP
#define LOOKUP8_SSE(_table, _idx, _size) \
        lookup_8bit_sse(_table, _idx, _size)
#define LOOKUP8_AVX(_table, _idx, _size) \
        lookup_8bit_avx(_table, _idx, _size)
#else
#define LOOKUP8_SSE(_table, _idx, _size) \
        _table[_idx]
#define LOOKUP8_AVX(_table, _idx, _size) \
        _table[_idx]
#endif

/*
 * @brief Constant time SSE lookup function on variable size table
 *        with 8-bit values
 *
 * @param[in] table     Pointer to table to look up (16-byte aligned)
 * @param[in] idx       Index to look up
 * @param[in] size      Size of table to look up (multiple of 16 bytes)
 *
 * @return value to lookup
 */
uint8_t
lookup_8bit_sse(const void *table, const uint32_t idx, const uint32_t size);

/*
 * @brief Constant time AVX lookup function on variable size table
 *        with 8-bit values
 *
 * @param[in] table     Pointer to table to look up (16-byte aligned)
 * @param[in] idx       Index to look up
 * @param[in] size      Size of table to look up (multiple of 16 bytes)
 *
 * @return value to lookup
 */
uint8_t
lookup_8bit_avx(const void *table, const uint32_t idx, const uint32_t size);

#endif /* CONSTANT_LOOKUP_H */
