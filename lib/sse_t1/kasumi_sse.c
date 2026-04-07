/*******************************************************************************
  Copyright (c) 2009-2026, Intel Corporation

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

#include <limits.h>

#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_sse

#include "include/kasumi_internal.h"
#include "include/save_xmms.h"
#include "include/clear_regs_mem.h"
#include "include/error.h"

#define SAVE_XMMS    save_xmms
#define RESTORE_XMMS restore_xmms

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
#ifndef LINUX
        DECLARE_ALIGNED(imb_uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        kasumi_f8_1_buffer_sse_no_check(pCtx, IV, pBufferIn, pBufferOut, cipherLengthInBytes);
#ifdef SAFE_DATA
        /* Clear sensitive data in registers */
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}

void
kasumi_f9_1_buffer_sse(const kasumi_key_sched_t *pCtx, const void *pBufferIn,
                       const uint32_t lengthInBytes, void *pDigest)
{
#ifndef LINUX
        DECLARE_ALIGNED(imb_uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
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
        CLEAR_SCRATCH_SIMD_REGS();
#endif
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
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
