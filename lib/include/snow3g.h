/*******************************************************************************
  Copyright (c) 2009-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef _SNOW3G_H_
#define _SNOW3G_H_

/*******************************************************************************
 * SSE
 ******************************************************************************/
size_t
snow3g_key_sched_size_sse(void);

int
snow3g_init_key_sched_sse(const void *pKey, snow3g_key_schedule_t *pCtx);

uint32_t
snow3g_f9_1_buffer_internal_sse(const uint64_t *pBufferIn, const uint32_t KS[5],
                                const uint64_t lengthInBits);

/*******************************************************************************
 * AVX2
 ******************************************************************************/
uint32_t
snow3g_f9_1_buffer_internal_avx(const uint64_t *pBufferIn, const uint32_t KS[5],
                                const uint64_t lengthInBits);

size_t
snow3g_key_sched_size_avx2(void);

int
snow3g_init_key_sched_avx2(const void *pKey, snow3g_key_schedule_t *pCtx);

/*******************************************************************************
 * AVX512
 ******************************************************************************/

size_t
snow3g_key_sched_size_avx512(void);

int
snow3g_init_key_sched_avx512(const void *pKey, snow3g_key_schedule_t *pCtx);

uint32_t
snow3g_f9_1_buffer_internal_vaes_avx512(const uint64_t *pBufferIn, const uint32_t KS[5],
                                        const uint64_t lengthInBits);

#endif /* _SNOW3G_H_ */
