/*******************************************************************************
  Copyright (c) 2009-2019, Intel Corporation

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

#include "include/kasumi_internal.h"
#include "include/save_xmms.h"

#define SAVE_XMMS       save_xmms
#define RESTORE_XMMS    restore_xmms

void kasumi_f8_1_buffer_sse(kasumi_key_sched_t *pCtx, uint64_t IV,
                            uint8_t *pBufferIn, uint8_t *pBufferOut,
                            uint32_t cipherLengthInBytes)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f8_1_buffer(pCtx, IV, pBufferIn, pBufferOut,
                           cipherLengthInBytes);
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}

void kasumi_f8_1_buffer_bit_sse(kasumi_key_sched_t *pCtx, uint64_t IV,
                                uint8_t *pBufferIn, uint8_t *pBufferOut,
                                uint32_t cipherLengthInBits,
                                uint32_t offsetInBits)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f8_1_buffer_bit(pCtx, IV, pBufferIn, pBufferOut,
                               cipherLengthInBits, offsetInBits);
}

void kasumi_f8_2_buffer_sse(kasumi_key_sched_t *pCtx, uint64_t IV1,
                            uint64_t IV2, uint8_t *pBufferIn1,
                            uint8_t *pBufferOut1, uint32_t lengthInBytes1,
                            uint8_t *pBufferIn2, uint8_t *pBufferOut2,
                            uint32_t lengthInBytes2)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f8_2_buffer(pCtx, IV1, IV2,
                           pBufferIn1, pBufferOut1, lengthInBytes1,
                           pBufferIn2, pBufferOut2, lengthInBytes2);
}

void kasumi_f8_3_buffer_sse(kasumi_key_sched_t *pCtx, uint64_t IV1,
                            uint64_t IV2, uint64_t IV3, uint8_t *pBufferIn1,
                            uint8_t *pBufferOut1, uint8_t *pBufferIn2,
                            uint8_t *pBufferOut2, uint8_t *pBufferIn3,
                            uint8_t *pBufferOut3, uint32_t lengthInBytes)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f8_3_buffer(pCtx, IV1, IV2, IV3,
                           pBufferIn1, pBufferOut1,
                           pBufferIn2, pBufferOut2,
                           pBufferIn3, pBufferOut3, lengthInBytes);
}

void kasumi_f8_4_buffer_sse(kasumi_key_sched_t *pCtx, uint64_t IV1,
                            uint64_t IV2, uint64_t IV3, uint64_t IV4,
                            uint8_t *pBufferIn1, uint8_t *pBufferOut1,
                            uint8_t *pBufferIn2, uint8_t *pBufferOut2,
                            uint8_t *pBufferIn3, uint8_t *pBufferOut3,
                            uint8_t *pBufferIn4, uint8_t *pBufferOut4,
                            uint32_t lengthInBytes)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f8_4_buffer(pCtx, IV1, IV2, IV3, IV4,
                           pBufferIn1, pBufferOut1,
                           pBufferIn2, pBufferOut2,
                           pBufferIn3, pBufferOut3,
                           pBufferIn4, pBufferOut4,
                           lengthInBytes);
}

void kasumi_f8_n_buffer_sse(kasumi_key_sched_t *pKeySchedule, uint64_t IV[],
                            uint8_t *pDataIn[], uint8_t *pDataOut[],
                            uint32_t dataLen[], uint32_t dataCount)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        uint32_t numLeft = dataCount;
        uint64_t *IVPtr;
        uint8_t **pDataInPtr;
        uint8_t **pDataOutPtr;
        uint32_t *dataLenPtr;
        uint32_t i = 0;
        uint32_t numBuffs;

        /* KASUMI F8 n buffer function can handle up to 16 buffers */
        while (numLeft > 0) {
                IVPtr = &IV[i];
                pDataInPtr = &pDataIn[i];
                pDataOutPtr = &pDataOut[i];
                dataLenPtr = &dataLen[i];
                numBuffs = (numLeft > 16) ? 16 : numLeft;

                kasumi_f8_n_buffer(pKeySchedule, IVPtr, pDataInPtr, pDataOutPtr,
                                   dataLenPtr, numBuffs);
                i += numBuffs;
                numLeft -= numBuffs;
        }
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}


void kasumi_f9_1_buffer_sse(kasumi_key_sched_t *pCtx, uint8_t *pBufferIn,
                            uint32_t lengthInBytes, uint8_t *pDigest)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f9_1_buffer(pCtx, pBufferIn, lengthInBytes, pDigest);
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}

void kasumi_f9_1_buffer_user_sse(kasumi_key_sched_t *pCtx, uint64_t IV,
                                 uint8_t *pBufferIn, uint32_t lengthInBits,
                                 uint8_t *pDigest, uint32_t direction)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f9_1_buffer_user(pCtx, IV, pBufferIn, lengthInBits,
                                pDigest, direction);
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}
