/*******************************************************************************
  Copyright (c) 2022-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
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
kasumi_f9_1_buffer_sse(const kasumi_key_sched_t *pCtx, const void *pBufferIn,
                       const uint32_t lengthInBytes, void *pDigest);

#endif /*_KASUMI_INTERFACE_H_*/
