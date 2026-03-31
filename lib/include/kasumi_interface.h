/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

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

#ifndef _KASUMI_INTERFACE_H_
#define _KASUMI_INTERFACE_H_

#include <stdint.h>
#include "intel-ipsec-mb.h"

/* Range of input data for KASUMI is from 1 to 20000 bits */
#define KASUMI_MIN_LEN 1
#define KASUMI_MAX_LEN 20000

#define BYTESIZE   (8)
#define BITSIZE(x) ((int) (sizeof(x) * BYTESIZE))

/* SSE */
size_t
kasumi_key_sched_size_sse(void);
int
kasumi_init_f8_key_sched_sse(const void *pKey, kasumi_key_sched_t *pCtx);
int
kasumi_init_f9_key_sched_sse(const void *pKey, kasumi_key_sched_t *pCtx);

void
kasumi_f8_1_buffer_sse(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pBufferIn,
                       void *pBufferOut, const uint32_t cipherLengthInBytes);

void
kasumi_f8_1_buffer_bit_sse(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pBufferIn,
                           void *pBufferOut, const uint32_t cipherLengthInBits,
                           const uint32_t offsetInBits);

void
kasumi_f9_1_buffer_sse(const kasumi_key_sched_t *pCtx, const void *pBufferIn,
                       const uint32_t lengthInBytes, void *pDigest);

#endif /*_KASUMI_INTERFACE_H_*/
