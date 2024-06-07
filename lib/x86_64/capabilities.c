/*******************************************************************************
  Copyright (c) 2024, Intel Corporation

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

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

int
imb_hash_burst_get_size(IMB_MGR *mb_mgr, const IMB_HASH_ALG algo, unsigned *out_burst_size)
{
#ifdef SAFE_PARAM
        if (mb_mgr == NULL)
                return IMB_ERR_NULL_MBMGR;

        if (out_burst_size == NULL)
                return IMB_ERR_NULL_BURST;
#endif

        IMB_ARCH used_arch = (IMB_ARCH) mb_mgr->used_arch;

        switch (algo) {
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_SHA_1:
                switch (used_arch) {
                case IMB_ARCH_NOAESNI:
                case IMB_ARCH_SSE:
                        *out_burst_size = SSE_NUM_SHA1_LANES;
                        break;
                case IMB_ARCH_AVX:
                        *out_burst_size = AVX_NUM_SHA1_LANES;
                        break;
                case IMB_ARCH_AVX2:
                        *out_burst_size = AVX2_NUM_SHA1_LANES;
                        break;
                case IMB_ARCH_AVX512:
                default:
                        *out_burst_size = AVX2_NUM_SHA1_LANES;
                        break;
                }
                break;
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_SHA_256:
                switch (used_arch) {
                case IMB_ARCH_NOAESNI:
                case IMB_ARCH_SSE:
                        *out_burst_size = SSE_NUM_SHA256_LANES;
                        break;
                case IMB_ARCH_AVX:
                        *out_burst_size = AVX_NUM_SHA256_LANES;
                        break;
                case IMB_ARCH_AVX2:
                        *out_burst_size = AVX2_NUM_SHA256_LANES;
                        break;
                case IMB_ARCH_AVX512:
                default:
                        *out_burst_size = AVX2_NUM_SHA256_LANES;
                        break;
                }
                break;
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_SHA_512:
                switch (used_arch) {
                case IMB_ARCH_NOAESNI:
                case IMB_ARCH_SSE:
                        *out_burst_size = SSE_NUM_SHA512_LANES;
                        break;
                case IMB_ARCH_AVX:
                        *out_burst_size = AVX_NUM_SHA512_LANES;
                        break;
                case IMB_ARCH_AVX2:
                        *out_burst_size = AVX2_NUM_SHA512_LANES;
                        break;
                case IMB_ARCH_AVX512:
                default:
                        *out_burst_size = AVX2_NUM_SHA512_LANES;
                        break;
                }
                break;
        default:
                *out_burst_size = 0;
                return IMB_ERR_HASH_ALGO;
        }

        return 0;
}
