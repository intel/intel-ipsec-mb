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

#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_avx

#include "include/save_xmms.h"
#include "include/clear_regs_mem.h"
#include "include/kasumi_internal.h"
#include "include/arch_avx2_type1.h"
#include "include/arch_avx512_type1.h"
#include "include/error.h"

#define SAVE_XMMS    save_xmms_avx
#define RESTORE_XMMS restore_xmms_avx

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
KASUMI_F8_1_BUFFER_BIT(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pBufferIn,
                       void *pBufferOut, const uint32_t cipherLengthInBits,
                       const uint32_t offsetInBits)
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
        if (cipherLengthInBits == 0 || cipherLengthInBits > KASUMI_MAX_LEN) {
                imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                return;
        }
#endif
        kasumi_f8_1_buffer_bit(pCtx, IV, pBufferIn, pBufferOut, cipherLengthInBits, offsetInBits);
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
