/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026, Intel Corporation.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Shared scalar rejection-sampling helpers used by ml_dsa_sample.c (base path)
 * and the x4-SHAKE instantiation files (AVX-512VL / AVX2).
 *
 * Prerequisites: ml_dsa_local.h and internal/sha3.h must already be visible.
 */

#ifndef ML_DSA_SAMPLE_HELPERS_H
#define ML_DSA_SAMPLE_HELPERS_H

#define SHAKE128_BLOCKSIZE SHA3_BLOCKSIZE(128)
#define SHAKE256_BLOCKSIZE SHA3_BLOCKSIZE(256)

/*
 * Constant-time n % 5.
 * 0xFFFF / 5 = 0x3333; +2 gives an over-estimate of 1/5, divided by 0x10000.
 */
#define MOD5(n) ((n) - 5 * (0x3335 * (n) >> 16))

#if SHAKE128_BLOCKSIZE % 3 != 0
#error "rej_ntt_poly() requires SHAKE128_BLOCKSIZE to be a multiple of 3"
#endif

typedef int(COEFF_FROM_NIBBLE_FUNC)(uint32_t nibble, uint32_t *out);

/* See FIPS 204, Algorithm 14, CoeffFromThreeBytes() */
static ossl_inline int
coeff_from_three_bytes(const uint8_t *s, uint32_t *out)
{
        *out = (uint32_t) s[0] | ((uint32_t) s[1] << 8) | (((uint32_t) s[2] & 0x7f) << 16);
        return *out < ML_DSA_Q;
}

/* See FIPS 204, Algorithm 15, CoeffFromHalfByte() where eta = 4 */
static ossl_inline int
coeff_from_nibble_4(uint32_t nibble, uint32_t *out)
{
        if (value_barrier_32(nibble < 9)) {
                *out = mod_sub(4, nibble);
                return 1;
        }
        return 0;
}

/* See FIPS 204, Algorithm 15, CoeffFromHalfByte() where eta = 2 */
static ossl_inline int
coeff_from_nibble_2(uint32_t nibble, uint32_t *out)
{
        if (value_barrier_32(nibble < 15)) {
                *out = mod_sub(2, MOD5(nibble));
                return 1;
        }
        return 0;
}

#endif /* ML_DSA_SAMPLE_HELPERS_H */
