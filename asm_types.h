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

typedef struct {
        const UINT8 *in[8];
        UINT8 *out[8];
        const UINT32 *keys[8];
        DECLARE_ALIGNED(UINT128 IV[8], 32);
} AES_ARGS_x8;


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


// Each row is sized to hold enough lanes for AVX2, AVX1 and SSE use a subset
// of each row. Thus one row is not adjacent in memory to its neighboring rows in
// the case of SSE and AVX1.
typedef UINT32 digest_array_md5[NUM_MD5_DIGEST_WORDS][AVX512_NUM_MD5_LANES];

typedef UINT32 digest_array[NUM_SHA_DIGEST_WORDS][AVX512_NUM_SHA1_LANES];
typedef UINT32 digest_array_SHA_256[NUM_SHA_256_DIGEST_WORDS][AVX512_NUM_SHA256_LANES];
typedef UINT64 digest_array_SHA_512[NUM_SHA_512_DIGEST_WORDS][AVX512_NUM_SHA512_LANES];

typedef struct {
        DECLARE_ALIGNED(digest_array digest, 32);
        UINT8 *data_ptr[AVX512_NUM_SHA1_LANES];
} SHA1_ARGS;

typedef struct {
        DECLARE_ALIGNED(digest_array_SHA_256 digest, 32);
        UINT8 *data_ptr[AVX512_NUM_SHA256_LANES];
} SHA256_ARGS;


typedef struct {
        DECLARE_ALIGNED(digest_array_SHA_512 digest, 32);
        UINT8 *data_ptr[AVX512_NUM_SHA512_LANES];
}  SHA512_ARGS ;


typedef struct {
        DECLARE_ALIGNED(digest_array_md5 digest, 32);
        UINT8 *data_ptr[AVX512_NUM_MD5_LANES];
} MD5_ARGS;

typedef struct {
        const UINT8 *in[8];
        const UINT32 *keys[8];
        DECLARE_ALIGNED(UINT128 ICV[8], 32);
} AES_XCBC_ARGS_x8;

#endif /* ifdef _ASM_TYPES_H */
