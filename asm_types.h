/*
 * Copyright (c) 2012-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef _ASM_TYPES_H
#define _ASM_TYPES_H

#include "os.h"
#include "constants.h"


// AVX512 with its larger register sizes (vs AVX2) supports more parallelism
// It will be used to size objects

#define AVX512_NUM_SHA1_LANES 16
#define AVX512_NUM_SHA256_LANES 16
#define AVX512_NUM_SHA512_LANES 8
#define AVX512_NUM_MD5_LANES 32

// AVX2 with its larger register sizes (vs SSE) supports more parallelism

#define AVX2_NUM_SHA1_LANES 8
#define AVX2_NUM_SHA256_LANES 8
#define AVX2_NUM_SHA512_LANES 4
#define AVX2_NUM_MD5_LANES  16

#define  AVX_NUM_SHA1_LANES 4
#define  AVX_NUM_SHA256_LANES 4
#define  AVX_NUM_SHA512_LANES  2
#define  AVX_NUM_MD5_LANES 8

#define  SSE_NUM_SHA1_LANES AVX_NUM_SHA1_LANES
#define  SSE_NUM_SHA256_LANES AVX_NUM_SHA256_LANES
#define  SSE_NUM_SHA512_LANES AVX_NUM_SHA512_LANES
#define  SSE_NUM_MD5_LANES AVX_NUM_MD5_LANES

/* block size in byte */
#define MD5_BLOCK_SIZE		64	/* 512 bit */
#define SHA1_BLOCK_SIZE		64	/* 512 bit */
#define SHA_224_BLOCK_SIZE	64	/* 512 bit */
#define SHA_256_BLOCK_SIZE	64	/* 512 bits */
#define SHA_384_BLOCK_SIZE	128	/* 1024 bits */
#define SHA_512_BLOCK_SIZE	128	/* 1024 biyts */

#define MAX_HASH_BLOCK_SIZE	SHA_512_BLOCK_SIZE

/* digest size in byte */
#define MD5_DIGEST_SIZE		16	/* 128 bits */
#define SHA1_DIGEST_SIZE	20	/* 160 bits */
#define SHA_224_DIGEST_SIZE	28	/* 224 bits */
#define SHA_256_DIGEST_SIZE	32	/* 256 bits */
#define SHA_384_DIGEST_SIZE	48	/* 384 bits */
#define SHA_512_DIGEST_SIZE	64	/* 512 bits */
#define AES_XCBC_DIGEST_SIZE    16
#define GCM_DIGEST_SIZE         16

#define MAX_DIGEST_SIZE		SHA_512_DIGEST_SIZE


/* AES */
#define AES_BLOCK_SIZE 16

#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32

#define AES128_RAOUNDS 10
#define AES192_RAOUNDS 12
#define AES256_RAOUNDS 14
#define AES_RAOUNDS_MAX (AES256_RAOUNDS)


// Each row is sized to hold enough lanes for AVX2, AVX1 and SSE use a subset
// of each row. Thus one row is not adjacent in memory to its neighboring rows in
// the case of SSE and AVX1.
typedef UINT32 digest_array_MD5[NUM_MD5_DIGEST_WORDS][AVX512_NUM_MD5_LANES];
typedef UINT32 digest_array_SHA_1[NUM_SHA_DIGEST_WORDS][AVX512_NUM_SHA1_LANES];
typedef UINT32 digest_array_SHA_256[NUM_SHA_256_DIGEST_WORDS][AVX512_NUM_SHA256_LANES];
typedef UINT64 digest_array_SHA_512[NUM_SHA_512_DIGEST_WORDS][AVX512_NUM_SHA512_LANES];

typedef struct AES_ARGS_x8 {
        const UINT8 *in[8];
        UINT8 *out[8];
        const UINT32 *keys[8];
        DECLARE_ALIGNED(UINT128 IV[8], 32);
} AES_ARGS_x8;

typedef struct SHA1 {
        DECLARE_ALIGNED(digest_array_SHA_1 digest, 32);
        UINT8 *data_ptr[AVX512_NUM_SHA1_LANES];
} SHA1_ARGS;

typedef struct SHA256_ARGS {
        DECLARE_ALIGNED(digest_array_SHA_256 digest, 32);
        UINT8 *data_ptr[AVX512_NUM_SHA256_LANES];
} SHA256_ARGS;


typedef struct SHA512_ARGS {
        DECLARE_ALIGNED(digest_array_SHA_512 digest, 32);
        UINT8 *data_ptr[AVX512_NUM_SHA512_LANES];
}  SHA512_ARGS ;


typedef struct MD5_ARGS {
        DECLARE_ALIGNED(digest_array_MD5 digest, 32);
        UINT8 *data_ptr[AVX512_NUM_MD5_LANES];
} MD5_ARGS;

typedef struct AES_XCBC_ARGS_x8 {
        const UINT8 *in[8];
        const UINT32 *keys[8];
        DECLARE_ALIGNED(UINT128 ICV[8], 32);
} AES_XCBC_ARGS_x8;

/*
 * keys
 */
struct aes_exp_key {
        UINT128 expanded_keys[AES_RAOUNDS_MAX + 1];
};

struct hmac_exp_key {
        UINT8 ipad[MAX_HASH_BLOCK_SIZE];
        UINT8 opad[MAX_HASH_BLOCK_SIZE];
};

struct xcbc_exp_key {
        struct aes_exp_key k1;
        UINT128 k2;
        UINT128 k3;
};



#endif /* ifdef _ASM_TYPES_H */
