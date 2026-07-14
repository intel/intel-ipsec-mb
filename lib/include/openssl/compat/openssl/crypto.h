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
 * Compatibility shim for <openssl/crypto.h> used by the vendored ML-DSA
 * (FIPS 204) sources.  Provides the allocator helpers (via openssl_compat.h),
 * the aligned-allocation helper used by the signing path, and a minimal
 * run-once primitive used by the NTT initialiser.
 */

#ifndef IMB_ML_DSA_COMPAT_OPENSSL_CRYPTO_H
#define IMB_ML_DSA_COMPAT_OPENSSL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "openssl_compat.h"

/* ------------------------------------------------------------------------- */
/* Aligned allocation (OpenSSL OPENSSL_aligned_alloc semantics).             */
/* Returns an |alignment|-aligned pointer of |num| usable bytes and stores   */
/* the pointer that must be passed to OPENSSL_free() in |*freeptr|.          */
/* ------------------------------------------------------------------------- */
static ossl_inline ossl_unused void *
OPENSSL_aligned_alloc(size_t num, size_t alignment, void **freeptr)
{
        uintptr_t raw, aligned;

        *freeptr = NULL;
        if (alignment == 0 || (alignment & (alignment - 1)) != 0)
                return NULL;
        if (num == 0)
                return NULL;
        /* Over-allocate so we can return an aligned address within the block. */
        if (num > SIZE_MAX - alignment)
                return NULL;
        raw = (uintptr_t) malloc(num + alignment);
        if (raw == 0)
                return NULL;
        aligned = (raw + alignment) & ~(uintptr_t) (alignment - 1);
        *freeptr = (void *) raw;
        return (void *) aligned;
}

/* ------------------------------------------------------------------------- */
/* Run-once primitive (OpenSSL CRYPTO_THREAD_run_once semantics).            */
/* The only ML-DSA user (NTT initialiser) runs an idempotent init that sets  */
/* function pointers to values they already hold in the portable build, so a */
/* benign double-init under contention is harmless.                          */
/* ------------------------------------------------------------------------- */
typedef int CRYPTO_ONCE;
#define CRYPTO_ONCE_STATIC_INIT 0

static ossl_inline ossl_unused int
CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
#if defined(__GNUC__) || defined(__clang__)
        if (__atomic_load_n(once, __ATOMIC_ACQUIRE) == 0) {
                init();
                __atomic_store_n(once, 1, __ATOMIC_RELEASE);
        }
#else
        /* MSVC: __atomic builtins not available.
         * Double-init is harmless per the comment above. */
        if (*once == 0) {
                init();
                *once = 1;
        }
#endif
        return 1;
}

#endif /* IMB_ML_DSA_COMPAT_OPENSSL_CRYPTO_H */
