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
 * Compatibility shim for <openssl/err.h> used by the vendored ML-DSA
 * (FIPS 204) and ML-KEM (FIPS 203) sources.  ERR_raise/ERR_raise_data
 * degrade to no-ops in the intel-ipsec-mb OpenSSL compatibility layer (errors
 * surface via return codes); the library/reason ids referenced by the
 * ported code are provided here.
 */

#ifndef IMB_ML_DSA_COMPAT_OPENSSL_ERR_H
#define IMB_ML_DSA_COMPAT_OPENSSL_ERR_H

#include "openssl_compat.h"

#ifndef ERR_LIB_PROV
#define ERR_LIB_PROV 0
#endif
#ifndef ERR_LIB_CRYPTO
#define ERR_LIB_CRYPTO 0
#endif
#ifndef ERR_R_INTERNAL_ERROR
#define ERR_R_INTERNAL_ERROR 0
#endif
#ifndef ERR_R_PASSED_INVALID_ARGUMENT
#define ERR_R_PASSED_INVALID_ARGUMENT 0
#endif

#endif /* IMB_ML_DSA_COMPAT_OPENSSL_ERR_H */
