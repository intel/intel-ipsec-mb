/*******************************************************************************
  Copyright (c) 2009-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <limits.h>

#define SSE
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_sse

#include "include/kasumi_internal.h"
#include "include/clear_regs_mem.h"
#include "include/error.h"

static void
kasumi_f8_1_buffer_sse_no_check(const kasumi_key_sched_t *pCtx, const uint64_t IV,
                                const void *pBufferIn, void *pBufferOut,
                                const uint32_t cipherLengthInBytes)
{
        kasumi_f8_1_buffer(pCtx, IV, pBufferIn, pBufferOut, cipherLengthInBytes);
}

void
kasumi_f8_1_buffer_sse(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pBufferIn,
                       void *pBufferOut, const uint32_t cipherLengthInBytes)
{
#ifdef SAFE_PARAM
        /* Check for NULL pointers */
        imb_set_errno(NULL, 0);
        if (pCtx == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (pBufferOut == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_DST);
                return;
        }
        /* Check input data is in range of supported length */
        if (cipherLengthInBytes == 0 || cipherLengthInBytes > (KASUMI_MAX_LEN / CHAR_BIT)) {
                imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                return;
        }
#endif
        kasumi_f8_1_buffer_sse_no_check(pCtx, IV, pBufferIn, pBufferOut, cipherLengthInBytes);
#ifdef SAFE_DATA
        /* Clear sensitive data in registers */
        CLEAR_SCRATCH_GPS();
#endif
}

void
kasumi_f9_1_buffer_sse(const kasumi_key_sched_t *pCtx, const void *pBufferIn,
                       const uint32_t lengthInBytes, void *pDigest)
{
#ifdef SAFE_PARAM
        /* Reset error */
        imb_set_errno(NULL, 0);

        /* Check for NULL pointers */
        if (pCtx == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (pDigest == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                return;
        }
        /* Check input data is in range of supported length */
        if (lengthInBytes == 0 || lengthInBytes > (KASUMI_MAX_LEN / CHAR_BIT)) {
                imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                return;
        }
#endif
        kasumi_f9_1_buffer(pCtx, pBufferIn, lengthInBytes, pDigest);
#ifdef SAFE_DATA
        /* Clear sensitive data in registers */
        CLEAR_SCRATCH_GPS();
#endif
}

int
kasumi_init_f8_key_sched_sse(const void *const pKey, kasumi_key_sched_t *pCtx)
{
        return kasumi_init_f8_key_sched(pKey, pCtx);
}

int
kasumi_init_f9_key_sched_sse(const void *const pKey, kasumi_key_sched_t *pCtx)
{
        return kasumi_init_f9_key_sched(pKey, pCtx);
}

size_t
kasumi_key_sched_size_sse(void)
{
        return kasumi_key_sched_size();
}
