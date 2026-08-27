/*******************************************************************************
  Copyright (c) 2009-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <limits.h>

#include "intel-ipsec-mb.h"

#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_avx

#include "include/clear_regs_mem.h"
#include "include/kasumi_internal.h"
#include "include/arch_avx2_type1.h"
#include "include/arch_avx512_type1.h"
#include "include/error.h"

void
KASUMI_F8_1_BUFFER(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pBufferIn,
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
        kasumi_f8_1_buffer(pCtx, IV, pBufferIn, pBufferOut, cipherLengthInBytes);
}

void
KASUMI_F9_1_BUFFER(const kasumi_key_sched_t *pCtx, const void *pBufferIn,
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
}
