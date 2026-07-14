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
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Compatibility shim for <openssl/core_dispatch.h> used by the vendored ML-DSA
 * (FIPS 204) sources.  Only the key-management selection bit flags are
 * referenced by the ported code (key dup / equal / has helpers).
 */

#ifndef IMB_ML_DSA_COMPAT_OPENSSL_CORE_DISPATCH_H
#define IMB_ML_DSA_COMPAT_OPENSSL_CORE_DISPATCH_H

#define OSSL_KEYMGMT_SELECT_PRIVATE_KEY       0x01
#define OSSL_KEYMGMT_SELECT_PUBLIC_KEY        0x02
#define OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS 0x04
#define OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS  0x80

#define OSSL_KEYMGMT_SELECT_ALL_PARAMETERS                                                         \
        (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
#define OSSL_KEYMGMT_SELECT_KEYPAIR                                                                \
        (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
#define OSSL_KEYMGMT_SELECT_ALL (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

#endif /* IMB_ML_DSA_COMPAT_OPENSSL_CORE_DISPATCH_H */
