/*
 * Copyright (c) 2017, Intel Corporation
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

/*
 * Author: Shuzo Ichiyoshi
 */

#ifndef _IPSEC_MB_TYPES_H_
#define	_IPSEC_MB_TYPES_H_

/******************************************************************************
 * Basic types
 ******************************************************************************/
#if !defined(ARRAYOF)
# define ARRAYOF(_a)	(sizeof(_a)/sizeof(_a[0]))
#endif

typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned int   UINT32;
typedef unsigned long  UINT64;

/* big endian types */
typedef UINT16 BE16;
typedef UINT32 BE32;
typedef UINT64 BE64;

/* xmm (__m128i) */
typedef struct {
        UINT64 low;
        UINT64 high;
} UINT128;

/* ymm (__m256i) */
typedef struct {
        UINT128 low;
        UINT128 high;
} UINT256;

/* zmm (__m512i) */
typedef struct {
        UINT256 low;
        UINT256 high;
} UINT512;

typedef struct {
        BE64 high;
        BE64 low;
} BE128;


/******************************************************************************
 * OS oriented
 ******************************************************************************/
struct xmm_storage {
        UINT128 xmms[10];
};

#ifdef LINUX
# define DECLARE_ALIGNED(decl, alignval) decl __attribute__((aligned(alignval)))
# define __forceinline	 static inline __attribute__((always_inline))
# define __packed __attribute__((packed))
# define __unused __attribute__((unused))
#else
# define DECLARE_ALIGNED(decl, alignval) __declspec(align(alignval)) decl
# define __forceinline	 static __forceinline
# define __packed	error "i dont know, sorry"
#endif


/******************************************************************************
 * Algorithm values
 ******************************************************************************/
#define AES128_RAOUNDS	10
#define AES192_RAOUNDS	12
#define AES256_RAOUNDS	14
#define AES_RAOUNDS_MAX	(AES256_RAOUNDS)

#define	AES_BLOCK_SIZE		16

#define	CIPHER_AES_CBC_BLOCK_SIZE	16
#define	CIPHER_AES_CTR_BLOCK_SIZE	4	/* (ESP use, raw:1) */
#define	CIPHER_AES_GCM_BLOCK_SIZE	4	/* (ESP use, raw:1) */
#define	CIPHER_NULL_BLOCK_SIZE		4	/* (ESP use, raw:1) */

#define AES128_KEY_SIZE		16
#define AES192_KEY_SIZE		24
#define AES256_KEY_SIZE		32

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

#define MAX_DIGEST_SIZE		SHA_512_DIGEST_SIZE

#define HMAC_MD5_TAG_SIZE	12	/* 96 bits */
#define HMAC_SHA1_TAG_SIZE	12	/* 96 bits */
#define HMAC_SHA_224_TAG_SIZE	14	/* XXX:unknown */
#define HMAC_SHA_256_TAG_SIZE	16	/* 256 bits */
#define HMAC_SHA_384_TAG_SIZE	24	/* 384 bits */
#define HMAC_SHA_512_TAG_SIZE	32	/* 512 bits */
#define AES_XCBC_TAG_SIZE	12	/* 96 bits */
#define NULL_AUTH_TAG_SIZE	0
#define GMAC_TAG_SIZE		16	/* or 8 or 12 (almost:16) */

/* Number of Lanes per Arch */
#define SSE_NUM_AES_LANES	4
#define AVX_NUM_AES_LANES	8
#define AVX2_NUM_AES_LANES	8
#define AVX512_NUM_AES_LANES	8
#define MAX_NUM_AES_LANES	AVX512_NUM_AES_LANES

#define SSE_NUM_SHA1_LANES	4
#define AVX_NUM_SHA1_LANES	4
#define AVX2_NUM_SHA1_LANES	8
#define AVX512_NUM_SHA1_LANES	16
#define MAX_NUM_SHA1_LANES	AVX512_NUM_SHA1_LANES

#define SSE_NUM_SHA224_LANES	4
#define AVX_NUM_SHA224_LANES	4
#define AVX2_NUM_SHA224_LANES	8
#define AVX512_NUM_SHA224_LANES 16
#define MAX_NUM_SHA224_LANES	AVX512_NUM_SHA224_LANES

#define SSE_NUM_SHA256_LANES	4
#define AVX_NUM_SHA256_LANES	4
#define AVX2_NUM_SHA256_LANES	8
#define AVX512_NUM_SHA256_LANES 16
#define MAX_NUM_SHA256_LANES	AVX512_NUM_SHA256_LANES

#define SSE_NUM_SHA384_LANES	2
#define AVX_NUM_SHA384_LANES	2
#define AVX2_NUM_SHA384_LANES	4
#define AVX512_NUM_SHA384_LANES 8
#define MAX_NUM_SHA384_LANES	AVX512_NUM_SHA384_LANES

#define SSE_NUM_SHA512_LANES	2
#define AVX_NUM_SHA512_LANES	2
#define AVX2_NUM_SHA512_LANES	4
#define AVX512_NUM_SHA512_LANES 8
#define MAX_NUM_SHA512_LANES	AVX512_NUM_SHA512_LANES

#define SSE_NUM_MD5_LANES	8
#define AVX_NUM_MD5_LANES	8
#define AVX2_NUM_MD5_LANES	16
#define AVX512_NUM_MD5_LANES	32	/* really ? */
#define	MAX_NUM_MD5_LANES	AVX512_NUM_MD5_LANES

#define SSE_NUM_XCBC_LANES	4
#define AVX_NUM_XCBC_LANES	8
#define AVX2_NUM_XCBC_LANES	8
#define AVX512_NUM_XCBC_LANES	8
#define MAX_NUM_XCBC_LANES	AVX512_NUM_XCBC_LANES


/******************************************************************************
 * Algorithm oriented structures
 ******************************************************************************/
/*
 * AES
 */
struct AES_ARGS_x8 {
        const void *in[MAX_NUM_AES_LANES];
        void *out[MAX_NUM_AES_LANES];
        const struct aes_exp_key *keys[MAX_NUM_AES_LANES];
        DECLARE_ALIGNED(UINT128 IV[MAX_NUM_AES_LANES], 32);
};

struct MB_MGR_AES_OOO {
        struct AES_ARGS_x8 args;
        DECLARE_ALIGNED(UINT16 lens[MAX_NUM_AES_LANES], 16);
        UINT64 unused_lanes; // each nibble is index (0...7) of unused lanes
        // nibble 8 is set to F as a flag
        struct JOB_AES_HMAC *job_in_lane[MAX_NUM_AES_LANES];
};

/*
 * SHA1
 */
struct HMAC_SHA1_LANE_DATA {
        DECLARE_ALIGNED(UINT8 extra_block[2 * SHA1_BLOCK_SIZE + 8], 32); // allows ymm aligned access
        struct JOB_AES_HMAC *job_in_lane;
        UINT8 outer_block[SHA1_BLOCK_SIZE];
        UINT32 outer_done;
        UINT32 extra_blocks; // num extra blocks (1 or 2)
        UINT32 size_offset;  // offset in extra_block to start of size field
        UINT32 start_offset; // offset to start of data
};

struct digest_array_sha1 {
        UINT8 digest_array[SHA1_DIGEST_SIZE][AVX512_NUM_SHA1_LANES];
};

struct SHA1_ARGS {
        DECLARE_ALIGNED(struct digest_array_sha1 digest, 32);
        void *data_ptr[MAX_NUM_SHA1_LANES];
};

struct MB_MGR_HMAC_SHA1_OOO {
        struct SHA1_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[MAX_NUM_SHA1_LANES], 32);
        UINT64 unused_lanes;
        struct HMAC_SHA1_LANE_DATA ldata[MAX_NUM_SHA1_LANES];
        UINT32 num_lanes_inuse;
};

/*
 * SHA256
 */
struct digest_array_SHA256 {
        UINT8 digest_array_SHA_256[SHA_256_DIGEST_SIZE][MAX_NUM_SHA256_LANES];
};

struct SHA256_ARGS {
        DECLARE_ALIGNED(struct digest_array_SHA256 digest, 32);
        void *data_ptr[MAX_NUM_SHA256_LANES];
};

struct MB_MGR_HMAC_SHA256_OOO {
        struct SHA256_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[MAX_NUM_SHA256_LANES], 16);
        UINT64 unused_lanes;
        struct HMAC_SHA1_LANE_DATA ldata[MAX_NUM_SHA256_LANES];
        UINT32 num_lanes_inuse;
};

/*
 * SHA512
 */
struct digest_array_SHA512 {
        UINT8 digest_array_SHA_512[SHA_512_DIGEST_SIZE][MAX_NUM_SHA512_LANES];
};

struct SHA512_ARGS {
        DECLARE_ALIGNED(struct digest_array_SHA512 digest, 32);
        void *data_ptr[MAX_NUM_SHA512_LANES];
};

struct HMAC_SHA512_LANE_DATA {
        DECLARE_ALIGNED(UINT8 extra_block[2 * SHA_512_BLOCK_SIZE + 16], 32);
        UINT8 outer_block[SHA_512_BLOCK_SIZE];
        struct JOB_AES_HMAC *job_in_lane;
        UINT32 outer_done;
        UINT32 extra_blocks; // num extra blocks (1 or 2)
        UINT32 size_offset;  // offset in extra_block to start of size field
        UINT32 start_offset; // offset to start of data
};

struct MB_MGR_HMAC_SHA512_OOO {
        struct SHA512_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[MAX_NUM_SHA512_LANES], 16);
        UINT64 unused_lanes;
        struct HMAC_SHA512_LANE_DATA ldata[MAX_NUM_SHA512_LANES];
};

/*
 * MD5
 */
struct digest_array_md5 {
        UINT8 digest_array_md5[MD5_DIGEST_SIZE][MAX_NUM_MD5_LANES];
};

struct MD5_ARGS {
        DECLARE_ALIGNED(struct digest_array_md5 digest, 32);
        void *data_ptr[MAX_NUM_MD5_LANES];
};

struct MB_MGR_HMAC_MD5_OOO {
        struct MD5_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[MAX_NUM_MD5_LANES], 16);
        // In the avx2 case, all 16 nibbles of unused lanes are used. In that
        // case num_lanes_inuse is used to detect the end of the list
        UINT64 unused_lanes;
        struct HMAC_SHA1_LANE_DATA ldata[MAX_NUM_MD5_LANES];
        UINT32 num_lanes_inuse;
};

/*
 * XCBC
 */
struct AES_XCBC_ARGS_x8 {
        const void *in[MAX_NUM_XCBC_LANES];
        const struct xcbc_exp_key *keys[MAX_NUM_XCBC_LANES];
        DECLARE_ALIGNED(UINT128 ICV[MAX_NUM_XCBC_LANES], 32);
};

struct XCBC_LANE_DATA {
        DECLARE_ALIGNED(UINT8 final_block[2 * AES_BLOCK_SIZE], 32);
        struct JOB_AES_HMAC *job_in_lane;
        UINT64 final_done;
};

struct MB_MGR_AES_XCBC_OOO {
        struct AES_XCBC_ARGS_x8 args;
        DECLARE_ALIGNED(UINT16 lens[MAX_NUM_XCBC_LANES], 16);
        UINT64 unused_lanes; // each byte is index (0...3) of unused lanes
        // byte 4 is set to FF as a flag
        struct XCBC_LANE_DATA ldata[MAX_NUM_XCBC_LANES];
};

#endif	/* !_IPSEC_MB_TYPES_H_ */
