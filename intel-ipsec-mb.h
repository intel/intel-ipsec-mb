/*******************************************************************************
  Copyright (c) 2012-2018, Intel Corporation

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

#ifndef IMB_IPSEC_MB_H
#define IMB_IPSEC_MB_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 128-bit data type that is not in sdtint.h */
typedef struct {
        uint64_t low;
        uint64_t high;
} uint128_t;

/*
 * Macros for aligning data structures and function inlines
 */
#ifdef __linux__
/* Linux */
#define DECLARE_ALIGNED(decl, alignval) \
        decl __attribute__((aligned(alignval)))
#define __forceinline \
        static inline __attribute__((always_inline))

#if __GNUC__ >= 4
#define IMB_DLL_EXPORT __attribute__((visibility("default")))
#define IMB_DLL_LOCAL  __attribute__((visibility("hidden")))
#else /* GNU C 4.0 and later */
#define IMB_DLL_EXPORT
#define IMB_DLL_LOCAL
#endif /* different C compiler */

#else
/* Windows */
#define DECLARE_ALIGNED(decl, alignval) \
        __declspec(align(alignval)) decl
#define __forceinline \
        static __forceinline

/* Windows DLL export is done via DEF file */
#define IMB_DLL_EXPORT
#define IMB_DLL_LOCAL
#endif

/* Library version */
#define IMB_VERSION_STR "0.52.0"
#define IMB_VERSION_NUM 0x3400

/* Macro to translate version number */
#define IMB_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

/*
 * Custom ASSERT and DIM macros
 */
#ifdef DEBUG
#include <assert.h>
#define IMB_ASSERT(x) assert(x)
#else
#define IMB_ASSERT(x)
#endif

#ifndef IMB_DIM
#define IMB_DIM(x) (sizeof(x) / sizeof(x[0]))
#endif

/*
 * Algorithm constants
 */

#define DES_KEY_SCHED_SIZE (16 * 8) /* 16 rounds x 8 bytes */
#define DES_BLOCK_SIZE 8

#define AES_BLOCK_SIZE 16

#define NUM_MD5_DIGEST_WORDS     4
#define NUM_SHA_DIGEST_WORDS     5
#define NUM_SHA_256_DIGEST_WORDS 8
#define NUM_SHA_224_DIGEST_WORDS 7
#define NUM_SHA_512_DIGEST_WORDS 8
#define NUM_SHA_384_DIGEST_WORDS 6

#define SHA_DIGEST_WORD_SIZE      4
#define SHA224_DIGEST_WORD_SIZE   4
#define SHA256_DIGEST_WORD_SIZE   4
#define SHA384_DIGEST_WORD_SIZE   8
#define SHA512_DIGEST_WORD_SIZE   8

#define SHA1_DIGEST_SIZE_IN_BYTES \
        (NUM_SHA_DIGEST_WORDS * SHA_DIGEST_WORD_SIZE)
#define SHA224_DIGEST_SIZE_IN_BYTES \
        (NUM_SHA_224_DIGEST_WORDS * SHA224_DIGEST_WORD_SIZE)
#define SHA256_DIGEST_SIZE_IN_BYTES \
        (NUM_SHA_256_DIGEST_WORDS * SHA256_DIGEST_WORD_SIZE)
#define SHA384_DIGEST_SIZE_IN_BYTES \
        (NUM_SHA_384_DIGEST_WORDS * SHA384_DIGEST_WORD_SIZE)
#define SHA512_DIGEST_SIZE_IN_BYTES \
        (NUM_SHA_512_DIGEST_WORDS * SHA512_DIGEST_WORD_SIZE)

#define SHA1_BLOCK_SIZE 64    /* 512 bits is 64 byte blocks */
#define SHA_256_BLOCK_SIZE 64 /* 512 bits is 64 byte blocks */
#define SHA_384_BLOCK_SIZE 128
#define SHA_512_BLOCK_SIZE 128

/* Number of lanes AVX512, AVX2, AVX and SSE */
#define AVX512_NUM_SHA1_LANES   16
#define AVX512_NUM_SHA256_LANES 16
#define AVX512_NUM_SHA512_LANES 8
#define AVX512_NUM_MD5_LANES    32
#define AVX512_NUM_DES_LANES    16

#define AVX2_NUM_SHA1_LANES     8
#define AVX2_NUM_SHA256_LANES   8
#define AVX2_NUM_SHA512_LANES   4
#define AVX2_NUM_MD5_LANES      16

#define AVX_NUM_SHA1_LANES      4
#define AVX_NUM_SHA256_LANES    4
#define AVX_NUM_SHA512_LANES    2
#define AVX_NUM_MD5_LANES       8

#define SSE_NUM_SHA1_LANES   AVX_NUM_SHA1_LANES
#define SSE_NUM_SHA256_LANES AVX_NUM_SHA256_LANES
#define SSE_NUM_SHA512_LANES AVX_NUM_SHA512_LANES
#define SSE_NUM_MD5_LANES    AVX_NUM_MD5_LANES

/*
 *  Each row is sized to hold enough lanes for AVX2, AVX1 and SSE use a subset
 * of each row. Thus one row is not adjacent in memory to its neighboring rows
 * in the case of SSE and AVX1.
 */
#define MD5_DIGEST_SZ    (NUM_MD5_DIGEST_WORDS * AVX512_NUM_MD5_LANES)
#define SHA1_DIGEST_SZ   (NUM_SHA_DIGEST_WORDS * AVX512_NUM_SHA1_LANES)
#define SHA256_DIGEST_SZ (NUM_SHA_256_DIGEST_WORDS * AVX512_NUM_SHA256_LANES)
#define SHA512_DIGEST_SZ (NUM_SHA_512_DIGEST_WORDS * AVX512_NUM_SHA512_LANES)

/*
 * Job structure definitions
 */

typedef enum {
        STS_BEING_PROCESSED = 0,
        STS_COMPLETED_AES =   1,
        STS_COMPLETED_HMAC =  2,
        STS_COMPLETED =       3, /* COMPLETED_AES | COMPLETED_HMAC */
        STS_INVALID_ARGS =    4,
        STS_INTERNAL_ERROR,
        STS_ERROR
} JOB_STS;

typedef enum {
        CBC = 1,
        CNTR,
        NULL_CIPHER,
        DOCSIS_SEC_BPI,
#ifndef NO_GCM
        GCM,
#endif /* !NO_GCM */
        CUSTOM_CIPHER,
        DES,
        DOCSIS_DES,
        CCM,
        DES3,
        PON_AES_CNTR
} JOB_CIPHER_MODE;

typedef enum {
        ENCRYPT = 1,
        DECRYPT
} JOB_CIPHER_DIRECTION;

typedef enum {
        SHA1 = 1,  /* HMAC-SHA1 */
        SHA_224,   /* HMAC-SHA224 */
        SHA_256,   /* HMAC-SHA256 */
        SHA_384,   /* HMAC-SHA384 */
        SHA_512,   /* HMAC-SHA512 */
        AES_XCBC,
        MD5,       /* HMAC-MD5 */
        NULL_HASH,
#ifndef NO_GCM
        AES_GMAC,
#endif /* !NO_GCM */
        CUSTOM_HASH,
        AES_CCM,         /* AES128-CCM */
        AES_CMAC,        /* AES128-CMAC */
        PLAIN_SHA1,      /* SHA1 */
        PLAIN_SHA_224,   /* SHA224 */
        PLAIN_SHA_256,   /* SHA256 */
        PLAIN_SHA_384,   /* SHA384 */
        PLAIN_SHA_512,   /* SHA512 */
        AES_CMAC_BITLEN, /* 128-EIA2 (3GPP) */
        PON_CRC_BIP
} JOB_HASH_ALG;

typedef enum {
        CIPHER_HASH = 1,
        HASH_CIPHER
} JOB_CHAIN_ORDER;

typedef enum {
        AES_128_BYTES = 16,
        AES_192_BYTES = 24,
        AES_256_BYTES = 32
} AES_KEY_SIZE_BYTES;

typedef struct JOB_AES_HMAC {
        /*
         * For AES, aes_enc_key_expanded and aes_dec_key_expanded are
         * expected to point to expanded keys structure.
         * - AES-CTR and AES-CCM, only aes_enc_key_expanded is used
         * - DOCSIS (AES-CBC + AES-CFB), both pointers are used
         *   aes_enc_key_expanded has to be set always for the partial block
         *
         * For DES, aes_enc_key_expanded and aes_dec_key_expanded are
         * expected to point to DES key schedule.
         * - same key schedule used for enc and dec operations
         *
         * For 3DES, aes_enc_key_expanded and aes_dec_key_expanded are
         * expected to point to an array of 3 pointers for
         * the corresponding 3 key schedules.
         * - same key schedule used for enc and dec operations
         */
        const void *aes_enc_key_expanded;  /* 16-byte aligned pointer. */
        const void *aes_dec_key_expanded;
        uint64_t aes_key_len_in_bytes; /* 16, 24 and 32 byte (128, 192 and
                                        * 256-bit) keys supported */
        const uint8_t *src; /* Input. May be cipher text or plaintext.
                             * In-place ciphering allowed. */
        uint8_t *dst; /*Output. May be cipher text or plaintext.
                       * In-place ciphering allowed, i.e. dst = src. */
        uint64_t cipher_start_src_offset_in_bytes;
        uint64_t msg_len_to_cipher_in_bytes; /* Max len = 65472 bytes.
                                              * IPSec case, the maximum cipher
                                              * length would be:
                                              * 65535 -
                                              * 20 (outer IP header) -
                                              * 24 (ESP header + IV) -
                                              * 12 (supported ICV length) */
        uint64_t hash_start_src_offset_in_bytes;
        uint64_t msg_len_to_hash_in_bytes; /* Max len = 65496 bytes.
                                            * (Max cipher len +
                                            * 24 bytes ESP header) */
        const uint8_t *iv; /* AES IV. */
        uint64_t iv_len_in_bytes; /* AES IV length in bytes. */
        uint8_t *auth_tag_output; /* HMAC Tag output. This may point to
                                   * a location in the src buffer
                                   * (for in place)*/
        uint64_t auth_tag_output_len_in_bytes; /* Authentication (i.e. HMAC) tag
                                                * output length in bytes
                                                * (may be a truncated value) */

        /* Start algorithm-specific fields */
        union {
                struct _HMAC_specific_fields {
                        /* Hashed result of HMAC key xor'd with ipad (0x36). */
                        const uint8_t *_hashed_auth_key_xor_ipad;
                        /* Hashed result of HMAC key xor'd with opad (0x5c). */
                        const uint8_t *_hashed_auth_key_xor_opad;
                } HMAC;
                struct _AES_XCBC_specific_fields {
                        /* 16-byte aligned pointers */
                        const uint32_t *_k1_expanded;
                        const uint8_t *_k2;
                        const uint8_t *_k3;
                } XCBC;
                struct _AES_CCM_specific_fields {
                        /* Additional Authentication Data (AAD) */
                        const void *aad;
                        uint64_t aad_len_in_bytes; /* Length of AAD */
                } CCM;
                struct _AES_CMAC_specific_fields {
                        const void *_key_expanded; /* 16-byte aligned */
                        const void *_skey1;
                        const void *_skey2;
                } CMAC;
                struct _AES_CMAC_BITLEN_specific_fields {
                        const void *_key_expanded; /* 16-byte aligned */
                        const void *_skey1;
                        const void *_skey2;
                        uint64_t msg_len_to_hash_in_bits;
                } CMAC_BITLEN;
#ifndef NO_GCM
                struct _AES_GCM_specific_fields {
                        /* Additional Authentication Data (AAD) */
                        const void *aad;
                        uint64_t aad_len_in_bytes;    /* Length of AAD */
                } GCM;
#endif /* !NO_GCM */
        } u;

        JOB_STS status;
        JOB_CIPHER_MODE cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        JOB_CIPHER_DIRECTION cipher_direction; /* Encrypt/decrypt */
        JOB_HASH_ALG hash_alg; /* SHA-1 or others... */
        JOB_CHAIN_ORDER chain_order; /* CIPHER_HASH or HASH_CIPHER.
                                      * For AES-CCM, when encrypting,
                                      * HASH_CIPHER must be selected,
                                      * and when decrypting,
                                      * CIPHER_HASH must be selected. */

        void *user_data;
        void *user_data2;

        /*
         * stateless custom cipher and hash
         *   Return:
         *     success: 0
         *     fail:    other
         */
        int (*cipher_func)(struct JOB_AES_HMAC *);
        int (*hash_func)(struct JOB_AES_HMAC *);
} JOB_AES_HMAC;

/*
 * Argument structures for various algorithms
 */
typedef struct {
        const uint8_t *in[8];
        uint8_t *out[8];
        const uint32_t *keys[8];
        DECLARE_ALIGNED(uint128_t IV[8], 32);
} AES_ARGS_x8;

typedef struct {
        DECLARE_ALIGNED(uint32_t digest[SHA1_DIGEST_SZ], 32);
        uint8_t *data_ptr[AVX512_NUM_SHA1_LANES];
} SHA1_ARGS;

typedef struct {
        DECLARE_ALIGNED(uint32_t digest[SHA256_DIGEST_SZ], 32);
        uint8_t *data_ptr[AVX512_NUM_SHA256_LANES];
} SHA256_ARGS;

typedef struct {
        DECLARE_ALIGNED(uint64_t digest[SHA512_DIGEST_SZ], 32);
        uint8_t *data_ptr[AVX512_NUM_SHA512_LANES];
}  SHA512_ARGS;

typedef struct {
        DECLARE_ALIGNED(uint32_t digest[MD5_DIGEST_SZ], 32);
        uint8_t *data_ptr[AVX512_NUM_MD5_LANES];
} MD5_ARGS;

typedef struct {
        const uint8_t *in[8];
        const uint32_t *keys[8];
        DECLARE_ALIGNED(uint128_t ICV[8], 32);
} AES_XCBC_ARGS_x8;

typedef struct {
        const uint8_t *in[AVX512_NUM_DES_LANES];
        uint8_t *out[AVX512_NUM_DES_LANES];
        const uint8_t *keys[AVX512_NUM_DES_LANES];
        uint32_t IV[AVX512_NUM_DES_LANES * 2]; /* uint32_t is more handy here */
        uint32_t partial_len[AVX512_NUM_DES_LANES];
        uint32_t block_len[AVX512_NUM_DES_LANES];
        const uint8_t *last_in[AVX512_NUM_DES_LANES];
        uint8_t *last_out[AVX512_NUM_DES_LANES];
} DES_ARGS_x16;

/* AES out-of-order scheduler fields */
typedef struct {
        AES_ARGS_x8 args;
        DECLARE_ALIGNED(uint16_t lens[8], 16);
        /* each nibble is index (0...7) of an unused lane,
         * the last nibble is set to F as a flag
         */
        uint64_t unused_lanes;
        JOB_AES_HMAC *job_in_lane[8];
} MB_MGR_AES_OOO;

/* AES XCBC out-of-order scheduler fields */
typedef struct {
        DECLARE_ALIGNED(uint8_t final_block[2 * 16], 32);
        JOB_AES_HMAC *job_in_lane;
        uint64_t final_done;
} XCBC_LANE_DATA;

typedef struct {
        AES_XCBC_ARGS_x8 args;
        DECLARE_ALIGNED(uint16_t lens[8], 16);
        /* each byte is index (0...3) of unused lanes
         * byte 4 is set to FF as a flag
         */
        uint64_t unused_lanes;
        XCBC_LANE_DATA ldata[8];
} MB_MGR_AES_XCBC_OOO;

/* AES-CCM out-of-order scheduler structure */
typedef struct {
        AES_ARGS_x8 args; /* need to re-use AES arguments */
        DECLARE_ALIGNED(uint16_t lens[8], 16);
        DECLARE_ALIGNED(uint16_t init_done[8], 16);
        /* each byte is index (0...3) of unused lanes
         * byte 4 is set to FF as a flag
         */
        uint64_t unused_lanes;
        JOB_AES_HMAC *job_in_lane[8];
        DECLARE_ALIGNED(uint8_t init_blocks[8 * (4 * 16)], 32);
} MB_MGR_CCM_OOO;


/* AES-CMAC out-of-order scheduler structure */
typedef struct {
        AES_ARGS_x8 args; /* need to re-use AES arguments */
        DECLARE_ALIGNED(uint16_t lens[8], 16);
        DECLARE_ALIGNED(uint16_t init_done[8], 16);
        /* each byte is index (0...3) of unused lanes
         * byte 4 is set to FF as a flag
         */
        uint64_t unused_lanes;
        JOB_AES_HMAC *job_in_lane[8];
        DECLARE_ALIGNED(uint8_t scratch[8 * 16], 32);
} MB_MGR_CMAC_OOO;


/* DES out-of-order scheduler fields */
typedef struct {
        DES_ARGS_x16 args;
        DECLARE_ALIGNED(uint16_t lens[16], 16);
        /* each nibble is index (0...7) of unused lanes
         * nibble 8 is set to F as a flag
         */
        uint64_t unused_lanes;
        JOB_AES_HMAC *job_in_lane[16];
        uint32_t num_lanes_inuse;
} MB_MGR_DES_OOO;


/* HMAC-SHA1 and HMAC-SHA256/224 */
typedef struct {
        /* YMM aligned access to extra_block */
        DECLARE_ALIGNED(uint8_t extra_block[2 * SHA1_BLOCK_SIZE+8], 32);
        JOB_AES_HMAC *job_in_lane;
        uint8_t outer_block[64];
        uint32_t outer_done;
        uint32_t extra_blocks; /* num extra blocks (1 or 2) */
        uint32_t size_offset;  /* offset in extra_block to start of
                                * size field */
        uint32_t start_offset; /* offset to start of data */
} HMAC_SHA1_LANE_DATA;

/* HMAC-SHA512/384 */
typedef struct {
        DECLARE_ALIGNED(uint8_t extra_block[2 * SHA_512_BLOCK_SIZE + 16], 32);
        uint8_t outer_block[SHA_512_BLOCK_SIZE];
        JOB_AES_HMAC *job_in_lane;
        uint32_t outer_done;
        uint32_t extra_blocks; /* num extra blocks (1 or 2) */
        uint32_t size_offset;  /* offset in extra_block to start of
                                * size field */
        uint32_t start_offset; /* offset to start of data */
} HMAC_SHA512_LANE_DATA;

/*
 * unused_lanes contains a list of unused lanes stored as bytes or as
 * nibbles depending on the arch. The end of list is either FF or F.
 */
typedef struct {
        SHA1_ARGS args;
        DECLARE_ALIGNED(uint16_t lens[16], 32);
        uint64_t unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_SHA1_LANES];
        uint32_t num_lanes_inuse;
} MB_MGR_HMAC_SHA_1_OOO;

typedef struct {
        SHA256_ARGS args;
        DECLARE_ALIGNED(uint16_t lens[16], 16);
        uint64_t unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_SHA256_LANES];
        uint32_t num_lanes_inuse;
} MB_MGR_HMAC_SHA_256_OOO;

typedef struct {
        SHA512_ARGS args;
        DECLARE_ALIGNED(uint16_t lens[8], 16);
        uint64_t unused_lanes;
        HMAC_SHA512_LANE_DATA ldata[AVX512_NUM_SHA512_LANES];
} MB_MGR_HMAC_SHA_512_OOO;

/* MD5-HMAC out-of-order scheduler fields */
typedef struct {
        MD5_ARGS args;
        DECLARE_ALIGNED(uint16_t lens[AVX512_NUM_MD5_LANES], 16);
        /*
         * In the avx2 case, all 16 nibbles of unused lanes are used.
         * In that case num_lanes_inuse is used to detect the end of the list
         */
        uint64_t unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_MD5_LANES];
        uint32_t num_lanes_inuse;
} MB_MGR_HMAC_MD5_OOO;


/* GCM data structures */
#define GCM_BLOCK_LEN   16

/**
 * @brief holds GCM operation context
 */
struct gcm_context_data {
        /* init, update and finalize context data */
        uint8_t  aad_hash[GCM_BLOCK_LEN];
        uint64_t aad_length;
        uint64_t in_length;
        uint8_t  partial_block_enc_key[GCM_BLOCK_LEN];
        uint8_t  orig_IV[GCM_BLOCK_LEN];
        uint8_t  current_counter[GCM_BLOCK_LEN];
        uint64_t partial_block_length;
};

/**
 * @brief GCM argument data per lane
 */
struct GCM_ARGS {
        struct gcm_context_data *ctx[4];
        const void *keys[4];
        uint8_t *out[4];
        const uint8_t *in[4];
        void *tag[4];
        uint64_t tag_len[4];
};

/**
 * @brief GCM multi-buffer manager structure
 */
typedef struct {
        struct GCM_ARGS args;
        struct gcm_context_data ctxs[4];
        uint64_t lens[4];
        JOB_AES_HMAC *job_in_lane[4];
        uint64_t unused_lanes;
} MB_MGR_GCM_OOO;

/* Authenticated Tag Length in bytes.
 * Valid values are 16 (most likely), 12 or 8. */
#define MAX_TAG_LEN (16)

/*
 * IV data is limited to 16 bytes as follows:
 * 12 bytes is provided by an application -
 *    pre-counter block j0: 4 byte salt (from Security Association)
 *    concatenated with 8 byte Initialization Vector (from IPSec ESP
 *    Payload).
 * 4 byte value 0x00000001 is padded automatically by the library -
 *    there is no need to add these 4 bytes on application side anymore.
 */
#define GCM_IV_DATA_LEN (12)

#define LONGEST_TESTED_AAD_LENGTH (2 * 1024)

/* Key lengths of 128 and 256 supported */
#define GCM_128_KEY_LEN (16)
#define GCM_192_KEY_LEN (24)
#define GCM_256_KEY_LEN (32)

/* #define GCM_BLOCK_LEN   16 */
#define GCM_ENC_KEY_LEN 16
#define GCM_KEY_SETS    (15) /*exp key + 14 exp round keys*/

/**
 * @brief holds intermediate key data needed to improve performance
 *
 * gcm_key_data hold internal key information used by gcm128, gcm192 and gcm256.
 */
#ifdef __WIN32
__declspec(align(64))
#endif /* WIN32 */
struct gcm_key_data {
        uint8_t expanded_keys[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
        uint8_t padding[GCM_ENC_KEY_LEN];        /* To align HashKey to 64 */
        /* storage for HashKey mod poly */
        uint8_t shifted_hkey_8[GCM_ENC_KEY_LEN]; /* HashKey^8<<1 mod poly */
        uint8_t shifted_hkey_7[GCM_ENC_KEY_LEN]; /* HashKey^7<<1 mod poly */
        uint8_t shifted_hkey_6[GCM_ENC_KEY_LEN]; /* HashKey^6<<1 mod poly */
        uint8_t shifted_hkey_5[GCM_ENC_KEY_LEN]; /* HashKey^5<<1 mod poly */
        uint8_t shifted_hkey_4[GCM_ENC_KEY_LEN]; /* HashKey^4<<1 mod poly */
        uint8_t shifted_hkey_3[GCM_ENC_KEY_LEN]; /* HashKey^3<<1 mod poly */
        uint8_t shifted_hkey_2[GCM_ENC_KEY_LEN]; /* HashKey^2<<1 mod poly */
        uint8_t shifted_hkey_1[GCM_ENC_KEY_LEN]; /* HashKey<<1 mod poly */
        /*
         * Storage for XOR of High 64 bits and low 64 bits of HashKey mod poly.
         * This is needed for Karatsuba purposes.
         */
        uint8_t shifted_hkey_1_k[GCM_ENC_KEY_LEN]; /* HashKey<<1 mod poly */
        uint8_t shifted_hkey_2_k[GCM_ENC_KEY_LEN]; /* HashKey^2<<1 mod poly */
        uint8_t shifted_hkey_3_k[GCM_ENC_KEY_LEN]; /* HashKey^3<<1 mod poly */
        uint8_t shifted_hkey_4_k[GCM_ENC_KEY_LEN]; /* HashKey^4<<1 mod poly */
        uint8_t shifted_hkey_5_k[GCM_ENC_KEY_LEN]; /* HashKey^5<<1 mod poly */
        uint8_t shifted_hkey_6_k[GCM_ENC_KEY_LEN]; /* HashKey^6<<1 mod poly */
        uint8_t shifted_hkey_7_k[GCM_ENC_KEY_LEN]; /* HashKey^7<<1 mod poly */
        uint8_t shifted_hkey_8_k[GCM_ENC_KEY_LEN]; /* HashKey^8<<1 mod poly */
}
#ifdef LINUX
__attribute__((aligned(64)));
#else
;
#endif

/* ========================================================================== */
/* API data type definitions */
struct MB_MGR;

typedef void (*init_mb_mgr_t)(struct MB_MGR *);
typedef JOB_AES_HMAC *(*get_next_job_t)(struct MB_MGR *);
typedef JOB_AES_HMAC *(*submit_job_t)(struct MB_MGR *);
typedef JOB_AES_HMAC *(*get_completed_job_t)(struct MB_MGR *);
typedef JOB_AES_HMAC *(*flush_job_t)(struct MB_MGR *);
typedef uint32_t (*queue_size_t)(struct MB_MGR *);
typedef void (*keyexp_t)(const void *, void *, void *);
typedef void (*cmac_subkey_gen_t)(const void *, void *, void *);
typedef void (*hash_one_block_t)(const void *, void *);
typedef void (*hash_fn_t)(const void *, const uint64_t, void *);
typedef void (*xcbc_keyexp_t)(const void *, void *, void *, void *);
typedef int (*des_keysched_t)(uint64_t *, const void *);
typedef void (*aes128_cfb_t)(void *, const void *, const void *, const void *,
                             uint64_t);
typedef void (*aes_gcm_enc_dec_t)(const struct gcm_key_data *,
                                  struct gcm_context_data *,
                                  uint8_t *, uint8_t const *, uint64_t,
                                  const uint8_t *, uint8_t const *, uint64_t,
                                  uint8_t *, uint64_t);
typedef void (*aes_gcm_init_t)(const struct gcm_key_data *,
                               struct gcm_context_data *,
                               const uint8_t *, uint8_t const *, uint64_t);
typedef void (*aes_gcm_enc_dec_update_t)(const struct gcm_key_data *,
                                         struct gcm_context_data *,
                                         uint8_t *, const uint8_t *, uint64_t);
typedef void (*aes_gcm_enc_dec_finalize_t)(const struct gcm_key_data *,
                                           struct gcm_context_data *,
                                           uint8_t *, uint64_t);
typedef void (*aes_gcm_precomp_t)(struct gcm_key_data *);
typedef void (*aes_gcm_pre_t)(const void *, struct gcm_key_data *);

/* ========================================================================== */
/* Multi-buffer manager flags passed to alloc_mb_mgr() */

#define IMB_FLAG_SHANI_OFF (1ULL << 0) /* disable use of SHANI extension */
#define IMB_FLAG_AESNI_OFF (1ULL << 1) /* disable use of AESNI extension */

/* ========================================================================== */
/* Multi-buffer manager detected features
 * - if bit is set then hardware supports given extension
 * - valid after call to init_mb_mgr() or alloc_mb_mgr()
 * - some HW supported features can be disabled via IMB_FLAG_xxx (see above)
 */

#define IMB_FEATURE_SHANI      (1ULL << 0)
#define IMB_FEATURE_AESNI      (1ULL << 1)
#define IMB_FEATURE_PCLMULQDQ  (1ULL << 2)
#define IMB_FEATURE_CMOV       (1ULL << 3)
#define IMB_FEATURE_SSE4_2     (1ULL << 4)
#define IMB_FEATURE_AVX        (1ULL << 5)
#define IMB_FEATURE_AVX2       (1ULL << 6)
#define IMB_FEATURE_AVX512F    (1ULL << 7)
#define IMB_FEATURE_AVX512DQ   (1ULL << 8)
#define IMB_FEATURE_AVX512CD   (1ULL << 9)
#define IMB_FEATURE_AVX512BW   (1ULL << 10)
#define IMB_FEATURE_AVX512VL   (1ULL << 11)
#define IMB_FEATURE_AVX512_SKX (IMB_FEATURE_AVX512F | IMB_FEATURE_AVX512DQ | \
                                IMB_FEATURE_AVX512CD | IMB_FEATURE_AVX512BW | \
                                IMB_FEATURE_AVX512VL)
#define IMB_FEATURE_VAES       (1ULL << 12)
#define IMB_FEATURE_VPCLMULQDQ (1ULL << 13)

/* ========================================================================== */
/* TOP LEVEL (MB_MGR) Data structure fields */

#define MAX_JOBS 128

typedef struct MB_MGR {
        /*
         * flags - passed to alloc_mb_mgr()
         * features - reflects features of multi-buffer instance
         */
        uint64_t flags;
        uint64_t features;

        /*
         * Reserved for the future
         */
        uint64_t reserved[6];

        /*
         * ARCH handlers / API
         * Careful as changes here can break ABI compatibility
         */
        get_next_job_t          get_next_job;
        submit_job_t            submit_job;
        submit_job_t            submit_job_nocheck;
        get_completed_job_t     get_completed_job;
        flush_job_t             flush_job;
        queue_size_t            queue_size;
        keyexp_t                keyexp_128;
        keyexp_t                keyexp_192;
        keyexp_t                keyexp_256;
        cmac_subkey_gen_t       cmac_subkey_gen_128;
        xcbc_keyexp_t           xcbc_keyexp;
        des_keysched_t          des_key_sched;
        hash_one_block_t        sha1_one_block;
        hash_one_block_t        sha224_one_block;
        hash_one_block_t        sha256_one_block;
        hash_one_block_t        sha384_one_block;
        hash_one_block_t        sha512_one_block;
        hash_one_block_t        md5_one_block;
        hash_fn_t               sha1;
        hash_fn_t               sha224;
        hash_fn_t               sha256;
        hash_fn_t               sha384;
        hash_fn_t               sha512;
        aes128_cfb_t            aes128_cfb_one;

        aes_gcm_enc_dec_t       gcm128_enc;
        aes_gcm_enc_dec_t       gcm192_enc;
        aes_gcm_enc_dec_t       gcm256_enc;
        aes_gcm_enc_dec_t       gcm128_dec;
        aes_gcm_enc_dec_t       gcm192_dec;
        aes_gcm_enc_dec_t       gcm256_dec;
        aes_gcm_init_t          gcm128_init;
        aes_gcm_init_t          gcm192_init;
        aes_gcm_init_t          gcm256_init;
        aes_gcm_enc_dec_update_t gcm128_enc_update;
        aes_gcm_enc_dec_update_t gcm192_enc_update;
        aes_gcm_enc_dec_update_t gcm256_enc_update;
        aes_gcm_enc_dec_update_t gcm128_dec_update;
        aes_gcm_enc_dec_update_t gcm192_dec_update;
        aes_gcm_enc_dec_update_t gcm256_dec_update;
        aes_gcm_enc_dec_finalize_t gcm128_enc_finalize;
        aes_gcm_enc_dec_finalize_t gcm192_enc_finalize;
        aes_gcm_enc_dec_finalize_t gcm256_enc_finalize;
        aes_gcm_enc_dec_finalize_t gcm128_dec_finalize;
        aes_gcm_enc_dec_finalize_t gcm192_dec_finalize;
        aes_gcm_enc_dec_finalize_t gcm256_dec_finalize;
        aes_gcm_precomp_t       gcm128_precomp;
        aes_gcm_precomp_t       gcm192_precomp;
        aes_gcm_precomp_t       gcm256_precomp;
        aes_gcm_pre_t           gcm128_pre;
        aes_gcm_pre_t           gcm192_pre;
        aes_gcm_pre_t           gcm256_pre;

        /* in-order scheduler fields */
        int              earliest_job; /* byte offset, -1 if none */
        int              next_job;     /* byte offset */
        JOB_AES_HMAC     jobs[MAX_JOBS];

        /* out of order managers */
        DECLARE_ALIGNED(MB_MGR_AES_OOO aes128_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_AES_OOO aes192_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_AES_OOO aes256_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_AES_OOO docsis_sec_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_DES_OOO des_enc_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_DES_OOO des_dec_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_DES_OOO des3_enc_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_DES_OOO des3_dec_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_DES_OOO docsis_des_enc_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_DES_OOO docsis_des_dec_ooo, 64);

        DECLARE_ALIGNED(MB_MGR_HMAC_SHA_1_OOO hmac_sha_1_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_HMAC_SHA_256_OOO hmac_sha_224_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_HMAC_SHA_256_OOO hmac_sha_256_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_HMAC_SHA_512_OOO hmac_sha_384_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_HMAC_SHA_512_OOO hmac_sha_512_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_HMAC_MD5_OOO hmac_md5_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_AES_XCBC_OOO aes_xcbc_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_CCM_OOO aes_ccm_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_CMAC_OOO aes_cmac_ooo, 64);

        DECLARE_ALIGNED(MB_MGR_GCM_OOO gcm128_enc_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_GCM_OOO gcm192_enc_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_GCM_OOO gcm256_enc_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_GCM_OOO gcm128_dec_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_GCM_OOO gcm192_dec_ooo, 64);
        DECLARE_ALIGNED(MB_MGR_GCM_OOO gcm256_dec_ooo, 64);
} MB_MGR;

/* ========================================================================== */
/* API definitions */

/**
 * @brief Get library version in string format
 *
 * @return library version string
 */
IMB_DLL_EXPORT const char *imb_get_version_str(void);

/**
 * @brief Get library version in numerical format
 *
 * Use IMB_VERSION() macro to compare this
 * numerical version against known library version.
 *
 * @return library version number
 */
IMB_DLL_EXPORT unsigned imb_get_version(void);

/*
 * get_next_job returns a job object. This must be filled in and returned
 * via submit_job before get_next_job is called again.
 * After submit_job is called, one should call get_completed_job() at least
 * once (and preferably until it returns NULL).
 * get_completed_job and flush_job returns a job object. This job object ceases
 * to be usable at the next call to get_next_job
 */
IMB_DLL_EXPORT MB_MGR *alloc_mb_mgr(uint64_t flags);
IMB_DLL_EXPORT void free_mb_mgr(MB_MGR *state);

IMB_DLL_EXPORT void init_mb_mgr_avx(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_avx(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_nocheck_avx(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *flush_job_avx(MB_MGR *state);
IMB_DLL_EXPORT uint32_t queue_size_avx(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_completed_job_avx(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_next_job_avx(MB_MGR *state);

IMB_DLL_EXPORT void init_mb_mgr_avx2(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_avx2(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_nocheck_avx2(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *flush_job_avx2(MB_MGR *state);
IMB_DLL_EXPORT uint32_t queue_size_avx2(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_completed_job_avx2(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_next_job_avx2(MB_MGR *state);

IMB_DLL_EXPORT void init_mb_mgr_avx512(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_avx512(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_nocheck_avx512(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *flush_job_avx512(MB_MGR *state);
IMB_DLL_EXPORT uint32_t queue_size_avx512(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_completed_job_avx512(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_next_job_avx512(MB_MGR *state);

IMB_DLL_EXPORT void init_mb_mgr_sse(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_sse(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *submit_job_nocheck_sse(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *flush_job_sse(MB_MGR *state);
IMB_DLL_EXPORT uint32_t queue_size_sse(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_completed_job_sse(MB_MGR *state);
IMB_DLL_EXPORT JOB_AES_HMAC *get_next_job_sse(MB_MGR *state);

/*
 * Wrapper macros to call arch API's set up
 * at init phase of multi-buffer manager.
 *
 * For example, after calling init_mb_mgr_sse(&mgr)
 * The 'mgr' structure be set up so that:
 *   mgr.get_next_job will point to get_next_job_sse(),
 *   mgr.submit_job will point to submit_job_sse(),
 *   mgr.submit_job_nocheck will point to submit_job_nocheck_sse(),
 *   mgr.get_completed_job will point to get_completed_job_sse(),
 *   mgr.flush_job will point to flush_job_sse(),
 *   mgr.queue_size will point to queue_size_sse()
 *   mgr.keyexp_128 will point to aes_keyexp_128_sse()
 *   mgr.keyexp_192 will point to aes_keyexp_192_sse()
 *   mgr.keyexp_256 will point to aes_keyexp_256_sse()
 *   etc.
 *
 * Direct use of arch API's may result in better performance.
 * Using below indirect interface may produce slightly worse performance but
 * it can simplify application implementation.
 * LibTestApp provides example of using the indirect interface.
 */
#define IMB_GET_NEXT_JOB(_mgr)       ((_mgr)->get_next_job((_mgr)))
#define IMB_SUBMIT_JOB(_mgr)         ((_mgr)->submit_job((_mgr)))
#define IMB_SUBMIT_JOB_NOCHECK(_mgr) ((_mgr)->submit_job_nocheck((_mgr)))
#define IMB_GET_COMPLETED_JOB(_mgr)  ((_mgr)->get_completed_job((_mgr)))
#define IMB_FLUSH_JOB(_mgr)          ((_mgr)->flush_job((_mgr)))
#define IMB_QUEUE_SIZE(_mgr)         ((_mgr)->queue_size((_mgr)))

/* Key expansion and generation API's */
#define IMB_AES_KEYEXP_128(_mgr, _raw, _enc, _dec)      \
        ((_mgr)->keyexp_128((_raw), (_enc), (_dec)))
#define IMB_AES_KEYEXP_192(_mgr, _raw, _enc, _dec)      \
        ((_mgr)->keyexp_192((_raw), (_enc), (_dec)))
#define IMB_AES_KEYEXP_256(_mgr, _raw, _enc, _dec)      \
        ((_mgr)->keyexp_256((_raw), (_enc), (_dec)))

#define IMB_AES_CMAC_SUBKEY_GEN_128(_mgr, _key_exp, _k1, _k2)   \
        ((_mgr)->cmac_subkey_gen_128((_key_exp), (_k1), (_k2)))

#define IMB_AES_XCBC_KEYEXP(_mgr, _key, _k1_exp, _k2, _k3)      \
        ((_mgr)->xcbc_keyexp((_key), (_k1_exp), (_k2), (_k3)))

#define IMB_DES_KEYSCHED(_mgr, _ks, _key)       \
        ((_mgr)->des_key_sched((_ks), (_key)))

/* Hash API's */
#define IMB_SHA1_ONE_BLOCK(_mgr, _data, _digest)        \
        ((_mgr)->sha1_one_block((_data), (_digest)))
#define IMB_SHA1(_mgr, _data, _length, _digest)         \
        ((_mgr)->sha1((_data), (_length), (_digest)))
#define IMB_SHA224_ONE_BLOCK(_mgr, _data, _digest)      \
        ((_mgr)->sha224_one_block((_data), (_digest)))
#define IMB_SHA224(_mgr, _data, _length, _digest)       \
        ((_mgr)->sha224((_data), (_length), (_digest)))
#define IMB_SHA256_ONE_BLOCK(_mgr, _data, _digest)      \
        ((_mgr)->sha256_one_block((_data), (_digest)))
#define IMB_SHA256(_mgr, _data, _length, _digest)       \
        ((_mgr)->sha256((_data), (_length), (_digest)))
#define IMB_SHA384_ONE_BLOCK(_mgr, _data, _digest)      \
        ((_mgr)->sha384_one_block((_data), (_digest)))
#define IMB_SHA384(_mgr, _data, _length, _digest)       \
        ((_mgr)->sha384((_data), (_length), (_digest)))
#define IMB_SHA512_ONE_BLOCK(_mgr, _data, _digest)      \
        ((_mgr)->sha512_one_block((_data), (_digest)))
#define IMB_SHA512(_mgr, _data, _length, _digest)       \
        ((_mgr)->sha512((_data), (_length), (_digest)))
#define IMB_MD5_ONE_BLOCK(_mgr, _data, _digest)         \
        ((_mgr)->md5_one_block((_data), (_digest)))

/* AES-CFB API */
#define IMB_AES128_CFB_ONE(_mgr, _out, _in, _iv, _enc, _len)            \
        ((_mgr)->aes128_cfb_one((_out), (_in), (_iv), (_enc), (_len)))

/* AES-GCM API's */
#define IMB_AES128_GCM_ENC(_mgr, _key, _ctx, _out, _in, _len, _iv, _aad, _aadl,\
                           _tag, _tagl)                                 \
        ((_mgr)->gcm128_enc((_key), (_ctx), (_out), (_in), (_len), (_iv), \
                            (_aad), (_aadl), (_tag), (_tagl)))
#define IMB_AES192_GCM_ENC(_mgr, _key, _ctx, _out, _in, _len, _iv, _aad, _aadl,\
                           _tag, _tagl)                                 \
        ((_mgr)->gcm192_enc((_key), (_ctx), (_out), (_in), (_len), (_iv), \
                            (_aad), (_aadl), (_tag), (_tagl)))
#define IMB_AES256_GCM_ENC(_mgr, _key, _ctx, _out, _in, _len, _iv, _aad, _aadl,\
                           _tag, _tagl)                                 \
        ((_mgr)->gcm256_enc((_key), (_ctx), (_out), (_in), (_len), (_iv), \
                            (_aad), (_aadl), (_tag), (_tagl)))

#define IMB_AES128_GCM_DEC(_mgr, _key, _ctx, _out, _in, _len, _iv, _aad, _aadl,\
                           _tag, _tagl)                                 \
        ((_mgr)->gcm128_dec((_key), (_ctx), (_out), (_in), (_len), (_iv), \
                            (_aad), (_aadl), (_tag), (_tagl)))
#define IMB_AES192_GCM_DEC(_mgr, _key, _ctx, _out, _in, _len, _iv, _aad, _aadl,\
                           _tag, _tagl)                                 \
        ((_mgr)->gcm192_dec((_key), (_ctx), (_out), (_in), (_len), (_iv), \
                            (_aad), (_aadl), (_tag), (_tagl)))
#define IMB_AES256_GCM_DEC(_mgr, _key, _ctx, _out, _in, _len, _iv, _aad, _aadl,\
                           _tag, _tagl)                                 \
        ((_mgr)->gcm256_dec((_key), (_ctx), (_out), (_in), (_len), (_iv), \
                            (_aad), (_aadl), (_tag), (_tagl)))

#define IMB_AES128_GCM_INIT(_mgr, _key, _ctx, _iv, _aad, _aadl)        \
        ((_mgr)->gcm128_init((_key), (_ctx), (_iv), (_aad), (_aadl)))
#define IMB_AES192_GCM_INIT(_mgr, _key, _ctx, _iv, _aad, _aadl)        \
        ((_mgr)->gcm192_init((_key), (_ctx), (_iv), (_aad), (_aadl)))
#define IMB_AES256_GCM_INIT(_mgr, _key, _ctx, _iv, _aad, _aadl)        \
        ((_mgr)->gcm256_init((_key), (_ctx), (_iv), (_aad), (_aadl)))

#define IMB_AES128_GCM_ENC_UPDATE(_mgr, _key, _ctx, _out, _in, _len)    \
        ((_mgr)->gcm128_enc_update((_key), (_ctx), (_out), (_in), (_len)))
#define IMB_AES192_GCM_ENC_UPDATE(_mgr, _key, _ctx, _out, _in, _len)    \
        ((_mgr)->gcm192_enc_update((_key), (_ctx), (_out), (_in), (_len)))
#define IMB_AES256_GCM_ENC_UPDATE(_mgr, _key, _ctx, _out, _in, _len)    \
        ((_mgr)->gcm256_enc_update((_key), (_ctx), (_out), (_in), (_len)))

#define IMB_AES128_GCM_DEC_UPDATE(_mgr, _key, _ctx, _out, _in, _len)    \
        ((_mgr)->gcm128_dec_update((_key), (_ctx), (_out), (_in), (_len)))
#define IMB_AES192_GCM_DEC_UPDATE(_mgr, _key, _ctx, _out, _in, _len)    \
        ((_mgr)->gcm192_dec_update((_key), (_ctx), (_out), (_in), (_len)))
#define IMB_AES256_GCM_DEC_UPDATE(_mgr, _key, _ctx, _out, _in, _len)    \
        ((_mgr)->gcm256_dec_update((_key), (_ctx), (_out), (_in), (_len)))

#define IMB_AES128_GCM_ENC_FINALIZE(_mgr, _key, _ctx, _tag, _tagl)      \
        ((_mgr)->gcm128_enc_finalize((_key), (_ctx), (_tag), (_tagl)))
#define IMB_AES192_GCM_ENC_FINALIZE(_mgr, _key, _ctx, _tag, _tagl)      \
        ((_mgr)->gcm192_enc_finalize((_key), (_ctx), (_tag), (_tagl)))
#define IMB_AES256_GCM_ENC_FINALIZE(_mgr, _key, _ctx, _tag, _tagl)      \
        ((_mgr)->gcm256_enc_finalize((_key), (_ctx), (_tag), (_tagl)))

#define IMB_AES128_GCM_DEC_FINALIZE(_mgr, _key, _ctx, _tag, _tagl)      \
        ((_mgr)->gcm128_dec_finalize((_key), (_ctx), (_tag), (_tagl)))
#define IMB_AES192_GCM_DEC_FINALIZE(_mgr, _key, _ctx, _tag, _tagl)      \
        ((_mgr)->gcm192_dec_finalize((_key), (_ctx), (_tag), (_tagl)))
#define IMB_AES256_GCM_DEC_FINALIZE(_mgr, _key, _ctx, _tag, _tagl)      \
        ((_mgr)->gcm256_dec_finalize((_key), (_ctx), (_tag), (_tagl)))

#define IMB_AES128_GCM_PRECOMP(_mgr, _key) \
        ((_mgr)->gcm128_precomp((_key)))
#define IMB_AES192_GCM_PRECOMP(_mgr, _key) \
        ((_mgr)->gcm192_precomp((_key)))
#define IMB_AES256_GCM_PRECOMP(_mgr, _key) \
        ((_mgr)->gcm256_precomp((_key)))

#define IMB_AES128_GCM_PRE(_mgr, _key_in, _key_exp)     \
        ((_mgr)->gcm128_pre((_key_in), (_key_exp)))
#define IMB_AES192_GCM_PRE(_mgr, _key_in, _key_exp)     \
        ((_mgr)->gcm192_pre((_key_in), (_key_exp)))
#define IMB_AES256_GCM_PRE(_mgr, _key_in, _key_exp)     \
        ((_mgr)->gcm256_pre((_key_in), (_key_exp)))

/* Auxiliary functions */

/**
 * @brief DES key schedule set up
 *
 * \a ks buffer needs to accomodate \a DES_KEY_SCHED_SIZE (128) bytes of data.
 *
 * @param ks destination buffer to accomodate DES key schedule
 * @param key a pointer to an 8 byte DES key
 *
 * @return Operation status
 * @retval 0 success
 * @retval !0 error
 */
IMB_DLL_EXPORT int
des_key_schedule(uint64_t *ks, const void *key);

/* SSE */
IMB_DLL_EXPORT void sha1_sse(const void *data, const uint64_t length,
                             void *digest);
IMB_DLL_EXPORT void sha1_one_block_sse(const void *data, void *digest);
IMB_DLL_EXPORT void sha224_sse(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha224_one_block_sse(const void *data, void *digest);
IMB_DLL_EXPORT void sha256_sse(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha256_one_block_sse(const void *data, void *digest);
IMB_DLL_EXPORT void sha384_sse(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha384_one_block_sse(const void *data, void *digest);
IMB_DLL_EXPORT void sha512_sse(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha512_one_block_sse(const void *data, void *digest);
IMB_DLL_EXPORT void md5_one_block_sse(const void *data, void *digest);
IMB_DLL_EXPORT void aes_keyexp_128_sse(const void *key, void *enc_exp_keys,
                                       void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_sse(const void *key, void *enc_exp_keys,
                                       void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_sse(const void *key, void *enc_exp_keys,
                                       void *dec_exp_keys);
IMB_DLL_EXPORT void aes_xcbc_expand_key_sse(const void *key, void *k1_exp,
                                            void *k2, void *k3);
IMB_DLL_EXPORT void aes_keyexp_128_enc_sse(const void *key,
                                           void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_enc_sse(const void *key,
                                           void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_enc_sse(const void *key,
                                           void *enc_exp_keys);
IMB_DLL_EXPORT void aes_cmac_subkey_gen_sse(const void *key_exp, void *key1,
                                            void *key2);
IMB_DLL_EXPORT void aes_cfb_128_one_sse(void *out, const void *in,
                                        const void *iv, const void *keys,
                                        uint64_t len);

/* AVX */
IMB_DLL_EXPORT void sha1_avx(const void *data, const uint64_t length,
                             void *digest);
IMB_DLL_EXPORT void sha1_one_block_avx(const void *data, void *digest);
IMB_DLL_EXPORT void sha224_avx(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha224_one_block_avx(const void *data, void *digest);
IMB_DLL_EXPORT void sha256_avx(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha256_one_block_avx(const void *data, void *digest);
IMB_DLL_EXPORT void sha384_avx(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha384_one_block_avx(const void *data, void *digest);
IMB_DLL_EXPORT void sha512_avx(const void *data, const uint64_t length,
                               void *digest);
IMB_DLL_EXPORT void sha512_one_block_avx(const void *data, void *digest);
IMB_DLL_EXPORT void md5_one_block_avx(const void *data, void *digest);
IMB_DLL_EXPORT void aes_keyexp_128_avx(const void *key, void *enc_exp_keys,
                                       void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_avx(const void *key, void *enc_exp_keys,
                                       void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_avx(const void *key, void *enc_exp_keys,
                                       void *dec_exp_keys);
IMB_DLL_EXPORT void aes_xcbc_expand_key_avx(const void *key, void *k1_exp,
                                            void *k2, void *k3);
IMB_DLL_EXPORT void aes_keyexp_128_enc_avx(const void *key,
                                           void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_enc_avx(const void *key,
                                           void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_enc_avx(const void *key,
                                           void *enc_exp_keys);
IMB_DLL_EXPORT void aes_cmac_subkey_gen_avx(const void *key_exp, void *key1,
                                            void *key2);
IMB_DLL_EXPORT void aes_cfb_128_one_avx(void *out, const void *in,
                                        const void *iv, const void *keys,
                                        uint64_t len);

/* AVX2 */
IMB_DLL_EXPORT void sha1_avx2(const void *data, const uint64_t length,
                              void *digest);
IMB_DLL_EXPORT void sha1_one_block_avx2(const void *data, void *digest);
IMB_DLL_EXPORT void sha224_avx2(const void *data, const uint64_t length,
                                void *digest);
IMB_DLL_EXPORT void sha224_one_block_avx2(const void *data, void *digest);
IMB_DLL_EXPORT void sha256_avx2(const void *data, const uint64_t length,
                                void *digest);
IMB_DLL_EXPORT void sha256_one_block_avx2(const void *data, void *digest);
IMB_DLL_EXPORT void sha384_avx2(const void *data, const uint64_t length,
                                void *digest);
IMB_DLL_EXPORT void sha384_one_block_avx2(const void *data, void *digest);
IMB_DLL_EXPORT void sha512_avx2(const void *data, const uint64_t length,
                                void *digest);
IMB_DLL_EXPORT void sha512_one_block_avx2(const void *data, void *digest);
IMB_DLL_EXPORT void md5_one_block_avx2(const void *data, void *digest);
IMB_DLL_EXPORT void aes_keyexp_128_avx2(const void *key, void *enc_exp_keys,
                                        void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_avx2(const void *key, void *enc_exp_keys,
                                        void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_avx2(const void *key, void *enc_exp_keys,
                                        void *dec_exp_keys);
IMB_DLL_EXPORT void aes_xcbc_expand_key_avx2(const void *key, void *k1_exp,
                                             void *k2, void *k3);
IMB_DLL_EXPORT void aes_keyexp_128_enc_avx2(const void *key,
                                            void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_enc_avx2(const void *key,
                                            void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_enc_avx2(const void *key,
                                            void *enc_exp_keys);
IMB_DLL_EXPORT void aes_cmac_subkey_gen_avx2(const void *key_exp, void *key1,
                                             void *key2);
IMB_DLL_EXPORT void aes_cfb_128_one_avx2(void *out, const void *in,
                                         const void *iv, const void *keys,
                                         uint64_t len);

/* AVX512 */
IMB_DLL_EXPORT void sha1_avx512(const void *data, const uint64_t length,
                                 void *digest);
IMB_DLL_EXPORT void sha1_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void sha224_avx512(const void *data, const uint64_t length,
                                  void *digest);
IMB_DLL_EXPORT void sha224_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void sha256_avx512(const void *data, const uint64_t length,
                                  void *digest);
IMB_DLL_EXPORT void sha256_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void sha384_avx512(const void *data, const uint64_t length,
                                  void *digest);
IMB_DLL_EXPORT void sha384_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void sha512_avx512(const void *data, const uint64_t length,
                                  void *digest);
IMB_DLL_EXPORT void sha512_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void md5_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void aes_keyexp_128_avx512(const void *key, void *enc_exp_keys,
                                          void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_avx512(const void *key, void *enc_exp_keys,
                                          void *dec_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_avx512(const void *key, void *enc_exp_keys,
                                          void *dec_exp_keys);
IMB_DLL_EXPORT void aes_xcbc_expand_key_avx512(const void *key, void *k1_exp,
                                               void *k2, void *k3);
IMB_DLL_EXPORT void aes_keyexp_128_enc_avx512(const void *key,
                                              void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_192_enc_avx512(const void *key,
                                              void *enc_exp_keys);
IMB_DLL_EXPORT void aes_keyexp_256_enc_avx512(const void *key,
                                              void *enc_exp_keys);
IMB_DLL_EXPORT void aes_cmac_subkey_gen_avx512(const void *key_exp, void *key1,
                                               void *key2);
IMB_DLL_EXPORT void aes_cfb_128_one_avx512(void *out, const void *in,
                                           const void *iv, const void *keys,
                                           uint64_t len);

/*
 * Direct GCM API.
 * Note that GCM is also availabe through job API.
 */
#ifndef NO_GCM
/**
 * @brief GCM-AES Encryption
 *
 * @param key_data GCM expanded key data
 * @param context_data GCM operation context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for encryption.
 * @param iv pointer to 12 byte IV structure. Internally, library
 *        concates 0x00000001 value to it.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
IMB_DLL_EXPORT void
aes_gcm_enc_128_sse(const struct gcm_key_data *key_data,
                    struct gcm_context_data *context_data,
                    uint8_t *out, uint8_t const *in, uint64_t len,
                    const uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_avx_gen2(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_avx_gen4(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_enc_192_sse(const struct gcm_key_data *key_data,
                    struct gcm_context_data *context_data,
                    uint8_t *out, uint8_t const *in, uint64_t len,
                    const uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_avx_gen2(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_avx_gen4(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_enc_256_sse(const struct gcm_key_data *key_data,
                    struct gcm_context_data *context_data,
                    uint8_t *out, uint8_t const *in, uint64_t len,
                    const uint8_t *iv,
                    uint8_t const *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_avx_gen2(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_avx_gen4(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief GCM-AES Decryption
 *
 * @param key_data GCM expanded keys data
 * @param context_data GCM operation context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 * @param iv pointer to 12 byte IV structure. Internally, library
 *        concates 0x00000001 value to it.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
IMB_DLL_EXPORT void
aes_gcm_dec_128_sse(const struct gcm_key_data *key_data,
                    struct gcm_context_data *context_data,
                    uint8_t *out, uint8_t const *in, uint64_t len,
                    const uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_avx_gen2(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_avx_gen4(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_dec_192_sse(const struct gcm_key_data *key_data,
                    struct gcm_context_data *context_data,
                    uint8_t *out, uint8_t const *in, uint64_t len,
                    const uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_avx_gen2(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_avx_gen4(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_dec_256_sse(const struct gcm_key_data *key_data,
                    struct gcm_context_data *context_data,
                    uint8_t *out, uint8_t const *in, uint64_t len,
                    const uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_avx_gen2(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_avx_gen4(const struct gcm_key_data *key_data,
                         struct gcm_context_data *context_data,
                         uint8_t *out, uint8_t const *in, uint64_t len,
                         const uint8_t *iv,
                         uint8_t const *aad, uint64_t aad_len,
                         uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief Start a AES-GCM Encryption message
 *
 * @param key_data GCM expanded key data
 * @param context_data GCM operation context data
 * @param iv pointer to 12 byte IV structure. Internally, library
 *        concates 0x00000001 value to it.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 *
 */
IMB_DLL_EXPORT void
aes_gcm_init_128_sse(const struct gcm_key_data *key_data,
                     struct gcm_context_data *context_data,
                     const uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_128_avx_gen2(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data,
                          const uint8_t *iv,
                          uint8_t const *aad, uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_128_avx_gen4(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data,
                          const uint8_t *iv,
                          uint8_t const *aad, uint64_t aad_len);

IMB_DLL_EXPORT void
aes_gcm_init_192_sse(const struct gcm_key_data *key_data,
                     struct gcm_context_data *context_data,
                     const uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_192_avx_gen2(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data,
                          const uint8_t *iv,
                          uint8_t const *aad, uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_192_avx_gen4(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data,
                          const uint8_t *iv,
                          uint8_t const *aad, uint64_t aad_len);

IMB_DLL_EXPORT void
aes_gcm_init_256_sse(const struct gcm_key_data *key_data,
                     struct gcm_context_data *context_data,
                     const uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_256_avx_gen2(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data,
                          const uint8_t *iv,
                          uint8_t const *aad, uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_256_avx_gen4(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data,
                          const uint8_t *iv,
                          uint8_t const *aad, uint64_t aad_len);

/**
 * @brief encrypt a block of a AES-GCM Encryption message
 *
 * @param key_data GCM expanded key data
 * @param context_data GCM operation context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for decryption.
 */
IMB_DLL_EXPORT void
aes_gcm_enc_128_update_sse(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data,
                           uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_update_avx_gen2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_update_avx_gen4(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);

IMB_DLL_EXPORT void
aes_gcm_enc_192_update_sse(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data,
                           uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_update_avx_gen2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_update_avx_gen4(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);

IMB_DLL_EXPORT void
aes_gcm_enc_256_update_sse(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data,
                           uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_update_avx_gen2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_update_avx_gen4(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);

/**
 * @brief decrypt a block of a AES-GCM Encryption message
 *
 * @param key_data GCM expanded key data
 * @param context_data GCM operation context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 */
IMB_DLL_EXPORT void
aes_gcm_dec_128_update_sse(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data,
                           uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_update_avx_gen2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_update_avx_gen4(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);

IMB_DLL_EXPORT void
aes_gcm_dec_192_update_sse(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data,
                           uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_update_avx_gen2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_update_avx_gen4(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);

IMB_DLL_EXPORT void
aes_gcm_dec_256_update_sse(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data,
                           uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_update_avx_gen2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_update_avx_gen4(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in, uint64_t len);

/**
 * @brief End encryption of a AES-GCM Encryption message
 *
 * @param key_data GCM expanded key data
 * @param context_data GCM operation context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
IMB_DLL_EXPORT void
aes_gcm_enc_128_finalize_sse(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_finalize_avx_gen2(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_finalize_avx_gen4(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_enc_192_finalize_sse(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_finalize_avx_gen2(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_finalize_avx_gen4(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_enc_256_finalize_sse(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_finalize_avx_gen2(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_finalize_avx_gen4(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief End decryption of a AES-GCM Encryption message
 *
 * @param key_data GCM expanded key data
 * @param context_data GCM operation context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
IMB_DLL_EXPORT void
aes_gcm_dec_128_finalize_sse(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_finalize_avx_gen2(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_finalize_avx_gen4(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_dec_192_finalize_sse(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_finalize_avx_gen2(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_finalize_avx_gen4(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_dec_256_finalize_sse(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_finalize_avx_gen2(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_finalize_avx_gen4(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief Precomputation of HashKey constants
 *
 * Precomputation of HashKey<<1 mod poly constants (shifted_hkey_X and
 * shifted_hkey_X_k).
 *
 * @param gdata GCM context data
 */
IMB_DLL_EXPORT void aes_gcm_precomp_128_sse(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_precomp_128_avx_gen2(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_precomp_128_avx_gen4(struct gcm_key_data *key_data);

IMB_DLL_EXPORT void aes_gcm_precomp_192_sse(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_precomp_192_avx_gen2(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_precomp_192_avx_gen4(struct gcm_key_data *key_data);

IMB_DLL_EXPORT void aes_gcm_precomp_256_sse(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_precomp_256_avx_gen2(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_precomp_256_avx_gen4(struct gcm_key_data *key_data);

/**
 * @brief Pre-processes GCM key data
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key pointer to key data
 * @param key_data GCM expanded key data
 *
 */
IMB_DLL_EXPORT void aes_gcm_pre_128_sse(const void *key,
                                        struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_128_avx_gen2(const void *key,
                                             struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_128_avx_gen4(const void *key,
                                             struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_192_sse(const void *key,
                                        struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_192_avx_gen2(const void *key,
                                             struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_192_avx_gen4(const void *key,
                                             struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_256_sse(const void *key,
                                        struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_256_avx_gen2(const void *key,
                                             struct gcm_key_data *key_data);
IMB_DLL_EXPORT void aes_gcm_pre_256_avx_gen4(const void *key,
                                             struct gcm_key_data *key_data);
#endif /* !NO_GCM */

#ifdef __cplusplus
}
#endif

#endif /* IMB_IPSEC_MB_H */
