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
 * Generic bridge that provides the OPENSSL_ia32cap_P capability vector
 * consumed by vendored OpenSSL perl-asm modules (e.g. the ML-DSA AVX2 NTT
 * and the x4 AVX512VL Keccak/SHAKE kernels). Not specific to any single
 * post-quantum algorithm: any future vendored-OpenSSL port (e.g. ML-KEM)
 * that reuses OpenSSL perl-asm relying on OPENSSL_ia32cap_P should call
 * imb_ossl_ia32cap_init() as well, instead of duplicating this glue.
 */

#ifndef IMB_OSSL_IA32CAP_H
#define IMB_OSSL_IA32CAP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Populate OPENSSL_ia32cap_P from IMB_MGR CPU \a features.
 *
 * Maps the ipsec-mb IMB_FEATURE_* bitmask (already detected once by
 * init_mb_mgr_auto()) onto the OPENSSL_ia32cap_P[] vector so that the
 * vendored OpenSSL perl-asm modules can select their optimized code paths
 * without re-running CPUID. Should be called once, before the first
 * operation that may invoke vendored-OpenSSL asm kernels.
 *
 * @param [in] features CPU feature bitmask, see IMB_FEATURE_xyz in
 *                       intel-ipsec-mb.h
 */
void
imb_ossl_ia32cap_init(uint64_t features);

#ifdef __cplusplus
}
#endif

#endif /* IMB_OSSL_IA32CAP_H */
