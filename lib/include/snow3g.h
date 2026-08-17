/*******************************************************************************
  Copyright (c) 2009-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef _SNOW3G_H_
#define _SNOW3G_H_

/*******************************************************************************
 * SSE
 ******************************************************************************/
void
snow3g_f8_1_buffer_sse(const snow3g_key_schedule_t *pCtx, const void *pIV, const void *pBufferIn,
                       void *pBufferOut, const uint32_t lengthInBytes);

void
snow3g_f8_2_buffer_sse(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                       const void *pBufferIn1, void *pBufferOut1, const uint32_t lengthInBytes1,
                       const void *pBufferIn2, void *pBufferOut2, const uint32_t lengthInBytes2);

void
snow3g_f8_4_buffer_sse(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                       const void *pIV3, const void *pIV4, const void *pBufferIn1,
                       void *pBufferOut1, const uint32_t lengthInBytes1, const void *pBufferIn2,
                       void *pBufferOut2, const uint32_t lengthInBytes2, const void *pBufferIn3,
                       void *pBufferOut3, const uint32_t lengthInBytes3, const void *pBufferIn4,
                       void *pBufferOut4, const uint32_t lengthInBytes4);

void
snow3g_f8_8_buffer_sse(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                       const void *pIV3, const void *pIV4, const void *pIV5, const void *pIV6,
                       const void *pIV7, const void *pIV8, const void *pBufferIn1,
                       void *pBufferOut1, const uint32_t lengthInBytes1, const void *pBufferIn2,
                       void *pBufferOut2, const uint32_t lengthInBytes2, const void *pBufferIn3,
                       void *pBufferOut3, const uint32_t lengthInBytes3, const void *pBufferIn4,
                       void *pBufferOut4, const uint32_t lengthInBytes4, const void *pBufferIn5,
                       void *pBufferOut5, const uint32_t lengthInBytes5, const void *pBufferIn6,
                       void *pBufferOut6, const uint32_t lengthInBytes6, const void *pBufferIn7,
                       void *pBufferOut7, const uint32_t lengthInBytes7, const void *pBufferIn8,
                       void *pBufferOut8, const uint32_t lengthInBytes8);

void
snow3g_f8_8_buffer_multikey_sse(const snow3g_key_schedule_t *const pCtx[], const void *const pIV[],
                                const void *const pBufferIn[], void *pBufferOut[],
                                const uint32_t lengthInBytes[]);

void
snow3g_f8_n_buffer_sse(const snow3g_key_schedule_t *pCtx, const void *const IV[],
                       const void *const pBufferIn[], void *pBufferOut[],
                       const uint32_t bufferLenInBytes[], const uint32_t bufferCount);

void
snow3g_f8_n_buffer_multikey_sse(const snow3g_key_schedule_t *const pCtx[], const void *const IV[],
                                const void *const pBufferIn[], void *pBufferOut[],
                                const uint32_t bufferLenInBytes[], const uint32_t bufferCount);

void
snow3g_f9_1_buffer_sse(const snow3g_key_schedule_t *pCtx, const void *pIV, const void *pBufferIn,
                       const uint64_t lengthInBits, void *pDigest);

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

void
snow3g_f8_1_buffer_avx2(const snow3g_key_schedule_t *pCtx, const void *pIV, const void *pBufferIn,
                        void *pBufferOut, const uint32_t lengthInBytes);

void
snow3g_f8_2_buffer_avx2(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                        const void *pBufferIn1, void *pBufferOut1, const uint32_t lengthInBytes1,
                        const void *pBufferIn2, void *pBufferOut2, const uint32_t lengthInBytes2);

void
snow3g_f8_4_buffer_avx2(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                        const void *pIV3, const void *pIV4, const void *pBufferIn1,
                        void *pBufferOut1, const uint32_t lengthInBytes1, const void *pBufferIn2,
                        void *pBufferOut2, const uint32_t lengthInBytes2, const void *pBufferIn3,
                        void *pBufferOut3, const uint32_t lengthInBytes3, const void *pBufferIn4,
                        void *pBufferOut4, const uint32_t lengthInBytes4);

void
snow3g_f8_8_buffer_avx2(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                        const void *pIV3, const void *pIV4, const void *pIV5, const void *pIV6,
                        const void *pIV7, const void *pIV8, const void *pBufferIn1,
                        void *pBufferOut1, const uint32_t lengthInBytes1, const void *pBufferIn2,
                        void *pBufferOut2, const uint32_t lengthInBytes2, const void *pBufferIn3,
                        void *pBufferOut3, const uint32_t lengthInBytes3, const void *pBufferIn4,
                        void *pBufferOut4, const uint32_t lengthInBytes4, const void *pBufferIn5,
                        void *pBufferOut5, const uint32_t lengthInBytes5, const void *pBufferIn6,
                        void *pBufferOut6, const uint32_t lengthInBytes6, const void *pBufferIn7,
                        void *pBufferOut7, const uint32_t lengthInBytes7, const void *pBufferIn8,
                        void *pBufferOut8, const uint32_t lengthInBytes8);

void
snow3g_f8_8_buffer_multikey_avx2(const snow3g_key_schedule_t *const pCtx[], const void *const pIV[],
                                 const void *const pBufferIn[], void *pBufferOut[],
                                 const uint32_t lengthInBytes[]);

void
snow3g_f8_n_buffer_avx2(const snow3g_key_schedule_t *pCtx, const void *const IV[],
                        const void *const pBufferIn[], void *pBufferOut[],
                        const uint32_t bufferLenInBytes[], const uint32_t bufferCount);

void
snow3g_f8_n_buffer_multikey_avx2(const snow3g_key_schedule_t *const pCtx[], const void *const IV[],
                                 const void *const pBufferIn[], void *pBufferOut[],
                                 const uint32_t bufferLenInBytes[], const uint32_t bufferCount);

void
snow3g_f9_1_buffer_avx2(const snow3g_key_schedule_t *pCtx, const void *pIV, const void *pBufferIn,
                        const uint64_t lengthInBits, void *pDigest);

size_t
snow3g_key_sched_size_avx2(void);

int
snow3g_init_key_sched_avx2(const void *pKey, snow3g_key_schedule_t *pCtx);

/*******************************************************************************
 * AVX512
 ******************************************************************************/

void
snow3g_f8_1_buffer_avx512(const snow3g_key_schedule_t *pCtx, const void *pIV, const void *pBufferIn,
                          void *pBufferOut, const uint32_t lengthInBytes);

void
snow3g_f8_2_buffer_avx512(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                          const void *pBufferIn1, void *pBufferOut1, const uint32_t lengthInBytes1,
                          const void *pBufferIn2, void *pBufferOut2, const uint32_t lengthInBytes2);

void
snow3g_f8_4_buffer_avx512(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                          const void *pIV3, const void *pIV4, const void *pBufferIn1,
                          void *pBufferOut1, const uint32_t lengthInBytes1, const void *pBufferIn2,
                          void *pBufferOut2, const uint32_t lengthInBytes2, const void *pBufferIn3,
                          void *pBufferOut3, const uint32_t lengthInBytes3, const void *pBufferIn4,
                          void *pBufferOut4, const uint32_t lengthInBytes4);

void
snow3g_f8_8_buffer_avx512(const snow3g_key_schedule_t *pCtx, const void *pIV1, const void *pIV2,
                          const void *pIV3, const void *pIV4, const void *pIV5, const void *pIV6,
                          const void *pIV7, const void *pIV8, const void *pBufferIn1,
                          void *pBufferOut1, const uint32_t lengthInBytes1, const void *pBufferIn2,
                          void *pBufferOut2, const uint32_t lengthInBytes2, const void *pBufferIn3,
                          void *pBufferOut3, const uint32_t lengthInBytes3, const void *pBufferIn4,
                          void *pBufferOut4, const uint32_t lengthInBytes4, const void *pBufferIn5,
                          void *pBufferOut5, const uint32_t lengthInBytes5, const void *pBufferIn6,
                          void *pBufferOut6, const uint32_t lengthInBytes6, const void *pBufferIn7,
                          void *pBufferOut7, const uint32_t lengthInBytes7, const void *pBufferIn8,
                          void *pBufferOut8, const uint32_t lengthInBytes8);

void
snow3g_f8_8_buffer_multikey_avx512(const snow3g_key_schedule_t *const pCtx[],
                                   const void *const pIV[], const void *const pBufferIn[],
                                   void *pBufferOut[], const uint32_t lengthInBytes[]);

void
snow3g_f8_n_buffer_avx512(const snow3g_key_schedule_t *pCtx, const void *const IV[],
                          const void *const pBufferIn[], void *pBufferOut[],
                          const uint32_t bufferLenInBytes[], const uint32_t bufferCount);

void
snow3g_f8_n_buffer_multikey_avx512(const snow3g_key_schedule_t *const pCtx[],
                                   const void *const IV[], const void *const pBufferIn[],
                                   void *pBufferOut[], const uint32_t bufferLenInBytes[],
                                   const uint32_t bufferCount);

void
snow3g_f9_1_buffer_avx512(const snow3g_key_schedule_t *pCtx, const void *pIV, const void *pBufferIn,
                          const uint64_t lengthInBits, void *pDigest);

size_t
snow3g_key_sched_size_avx512(void);

int
snow3g_init_key_sched_avx512(const void *pKey, snow3g_key_schedule_t *pCtx);

void
snow3g_f9_1_buffer_vaes_avx512(const snow3g_key_schedule_t *pHandle, const void *pIV,
                               const void *pBufferIn, const uint64_t lengthInBits, void *pDigest);

uint32_t
snow3g_f9_1_buffer_internal_vaes_avx512(const uint64_t *pBufferIn, const uint32_t KS[5],
                                        const uint64_t lengthInBits);

#endif /* _SNOW3G_H_ */
