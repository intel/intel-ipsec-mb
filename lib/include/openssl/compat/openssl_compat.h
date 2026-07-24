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

/**
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * Thin OpenSSL-compatibility shim for the ported ML-DSA (FIPS 204) sources.
 *
 * Maps the small set of OpenSSL allocator / error / cleanse / byte-order
 * helpers used by the ported code onto libipsec-mb / libc equivalents so the
 * ported .c files compile with minimal edits.  EVP digest plumbing lives in a
 * separate shim (ml_dsa_evp_shim.h).
 *
 * Most of this file is original ipsec-mb glue (macro renames onto libc /
 * clear_regs_mem primitives). The following functions are adapted from
 * genuine OpenSSL sources and therefore carry the OpenSSL copyright/license
 * notice above alongside the Intel one:
 *   - CRYPTO_memcmp() - adapted from crypto/cpuid.c
 *   - OPENSSL_memdup() - adapted from CRYPTO_memdup() in crypto/o_str.c
 *   - OPENSSL_store_u{16,32,64}_le() / OPENSSL_load_u{16,32,64}_le() -
 *     adapted from the portable (non-intrinsic) fallback paths in
 *     include/openssl/byteorder.h
 */

#ifndef IMB_ML_DSA_OPENSSL_COMPAT_H
#define IMB_ML_DSA_OPENSSL_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "clear_regs_mem.h"
#include "imb_rand.h"

/* ------------------------------------------------------------------------- */
/* Compiler attribute / inline keyword shims (from OpenSSL e_os2.h)          */
/* ------------------------------------------------------------------------- */
#ifndef OPENSSL_EXPORT
#define OPENSSL_EXPORT extern
#endif

#ifndef IMB_ML_DSA_COMPAT_OPENSSL_PARAMS_H
#define IMB_ML_DSA_COMPAT_OPENSSL_PARAMS_H
typedef struct ossl_param_st {
        const char *key;
        unsigned int data_type;
        void *data;
        size_t data_size;
        size_t return_size;
} OSSL_PARAM;
#endif

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
#endif

#ifndef ossl_inline
#define ossl_inline inline
#endif

#ifndef ossl_unused
#if defined(__GNUC__) || defined(__clang__)
#define ossl_unused __attribute__((unused))
#else
#define ossl_unused
#endif
#endif

#ifndef __owur
#if defined(__GNUC__) || defined(__clang__)
#define __owur __attribute__((warn_unused_result))
#else
#define __owur
#endif
#endif

#ifndef ossl_likely
#if defined(__GNUC__) || defined(__clang__)
#define ossl_likely(x)   __builtin_expect(!!(x), 1)
#define ossl_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define ossl_likely(x)   (x)
#define ossl_unlikely(x) (x)
#endif
#endif

#ifndef ossl_assert
#define ossl_assert(x) ossl_likely((x) != 0)
#endif

/* ------------------------------------------------------------------------- */
/* Allocator shims                                                           */
/* ------------------------------------------------------------------------- */
#define OPENSSL_malloc(num)             malloc(num)
#define OPENSSL_zalloc(num)             calloc(1, (num))
#define OPENSSL_malloc_array(num, size) OPENSSL_malloc((size_t) (num) * (size_t) (size))
#define OPENSSL_free(addr)              free(addr)

/* Secure allocations have no separate arena here - map to regular libc. */
#define OPENSSL_secure_malloc(num)             OPENSSL_malloc(num)
#define OPENSSL_secure_zalloc(num)             OPENSSL_zalloc(num)
#define OPENSSL_secure_malloc_array(num, size) OPENSSL_malloc_array(num, size)
#define OPENSSL_secure_free(addr)              OPENSSL_free(addr)

/* Cleanse / clear-free route through the constant-time IMB memory wipe. */
#define OPENSSL_cleanse(addr, num) clear_mem((addr), (num))

static ossl_inline ossl_unused void
OPENSSL_clear_free(void *addr, size_t num)
{
        if (addr != NULL) {
                if (num != 0)
                        clear_mem(addr, num);
                free(addr);
        }
}

#define OPENSSL_secure_clear_free(addr, num) OPENSSL_clear_free((addr), (num))

static ossl_inline ossl_unused void *
OPENSSL_memdup(const void *data, size_t size)
{
        void *ret;

        if (data == NULL || size == 0)
                return NULL;
        ret = malloc(size);
        if (ret != NULL)
                memcpy(ret, data, size);
        return ret;
}

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
        if (*once == 0) {
                init();
                *once = 1;
        }
#endif
        return 1;
}

/* ------------------------------------------------------------------------- */
/* Error reporting shims - ML-DSA error state is surfaced via return codes,  */
/* so OpenSSL's ERR_raise machinery degrades to a no-op.                     */
/* ------------------------------------------------------------------------- */
#define ERR_raise(lib, reason)           ((void) (lib), (void) (reason))
#define ERR_raise_data(lib, reason, ...) ((void) (lib), (void) (reason))

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

#ifndef PROV_R_BAD_LENGTH
#define PROV_R_BAD_LENGTH 0
#endif
#ifndef PROV_R_INVALID_KEY
#define PROV_R_INVALID_KEY 0
#endif

/* ------------------------------------------------------------------------- */
/* Constant-time memory compare (OpenSSL CRYPTO_memcmp semantics).           */
/* ------------------------------------------------------------------------- */
static ossl_inline ossl_unused int
CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len)
{
        const volatile unsigned char *a = (const volatile unsigned char *) in_a;
        const volatile unsigned char *b = (const volatile unsigned char *) in_b;
        unsigned char acc = 0;
        size_t i;

        for (i = 0; i < len; i++)
                acc |= (unsigned char) (a[i] ^ b[i]);
        return acc;
}

/* ------------------------------------------------------------------------- */
/* Little-endian byte load / store helpers (subset of OpenSSL byteorder.h).  */
/* Each returns the buffer pointer advanced past the value read / written.   */
/* ------------------------------------------------------------------------- */
static ossl_inline ossl_unused unsigned char *
OPENSSL_store_u16_le(unsigned char *out, uint16_t val)
{
        out[0] = (unsigned char) (val & 0xff);
        out[1] = (unsigned char) ((val >> 8) & 0xff);
        return out + 2;
}

static ossl_inline ossl_unused unsigned char *
OPENSSL_store_u32_le(unsigned char *out, uint32_t val)
{
        out[0] = (unsigned char) (val & 0xff);
        out[1] = (unsigned char) ((val >> 8) & 0xff);
        out[2] = (unsigned char) ((val >> 16) & 0xff);
        out[3] = (unsigned char) ((val >> 24) & 0xff);
        return out + 4;
}

static ossl_inline ossl_unused unsigned char *
OPENSSL_store_u64_le(unsigned char *out, uint64_t val)
{
        int i;

        for (i = 0; i < 8; i++)
                out[i] = (unsigned char) ((val >> (8 * i)) & 0xff);
        return out + 8;
}

static ossl_inline ossl_unused const unsigned char *
OPENSSL_load_u16_le(uint16_t *val, const unsigned char *in)
{
        *val = (uint16_t) ((uint16_t) in[0] | ((uint16_t) in[1] << 8));
        return in + 2;
}

static ossl_inline ossl_unused const unsigned char *
OPENSSL_load_u32_le(uint32_t *val, const unsigned char *in)
{
        *val = (uint32_t) in[0] | ((uint32_t) in[1] << 8) | ((uint32_t) in[2] << 16) |
               ((uint32_t) in[3] << 24);
        return in + 4;
}

static ossl_inline ossl_unused const unsigned char *
OPENSSL_load_u64_le(uint64_t *val, const unsigned char *in)
{
        uint64_t v = 0;
        int i;

        for (i = 0; i < 8; i++)
                v |= (uint64_t) in[i] << (8 * i);
        *val = v;
        return in + 8;
}

/* ------------------------------------------------------------------------- */
/* Randomness shims used by ML-DSA/ML-KEM.                                   */
/* ------------------------------------------------------------------------- */
static ossl_inline ossl_unused int
RAND_priv_bytes_ex(void *libctx, unsigned char *buf, size_t num, unsigned int strength)
{
        (void) libctx;
        (void) strength;
        return imb_get_random(buf, num) == 0;
}

static ossl_inline ossl_unused int
RAND_bytes_ex(void *libctx, unsigned char *buf, size_t num, unsigned int strength)
{
        return RAND_priv_bytes_ex(libctx, buf, num, strength);
}

#endif /* IMB_ML_DSA_OPENSSL_COMPAT_H */
