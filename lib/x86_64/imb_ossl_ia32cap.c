/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

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

/*
 * Provide the OPENSSL_ia32cap_P capability vector consumed by vendored
 * OpenSSL perl-asm modules (currently: the ML-DSA AVX2 NTT and the x4
 * AVX512VL Keccak/SHAKE kernels; any future vendored-OpenSSL port, e.g.
 * ML-KEM, that reuses perl-asm relying on OPENSSL_ia32cap_P should reuse
 * this bridge too rather than duplicating it).
 * The vector is populated from the IMB_MGR features field (set by
 * init_mb_mgr_auto) so that CPUID is not called twice.
 * Call imb_ossl_ia32cap_init() before the first operation that may invoke
 * a vendored-OpenSSL asm kernel.
 */

#if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)

#include <stdint.h>
#include "intel-ipsec-mb.h"
#include "imb_ossl_ia32cap.h"

#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
__attribute__((visibility("hidden")))
#endif
unsigned int OPENSSL_ia32cap_P[4] = { 0, 0, 0, 0 };

/*
 * Map IMB_MGR feature bits to OPENSSL_ia32cap_P[2] (CPUID leaf 7, EBX).
 * Currently called once from imb_ml_dsa_new() after init_mb_mgr_auto() has
 * run; any future caller (e.g. an ML-KEM constructor) should do the same.
 */
void
imb_ossl_ia32cap_init(uint64_t features)
{
        unsigned int ebx7 = 0;

        if (features & IMB_FEATURE_AVX2)
                ebx7 |= (1u << 5); /* AVX2 */
        if (features & IMB_FEATURE_AVX512F)
                ebx7 |= (1u << 16); /* AVX512F */
        if (features & IMB_FEATURE_AVX512DQ)
                ebx7 |= (1u << 17); /* AVX512DQ */
        if (features & IMB_FEATURE_AVX512BW)
                ebx7 |= (1u << 30); /* AVX512BW */
        if (features & IMB_FEATURE_AVX512VL)
                ebx7 |= (1u << 31); /* AVX512VL */

        OPENSSL_ia32cap_P[2] = ebx7;
}

#endif /* x86_64 */
