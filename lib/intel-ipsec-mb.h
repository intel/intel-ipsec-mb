/*******************************************************************************
  Copyright (c) 2012-2026, Intel Corporation

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
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 128-bit data type that is not in sdtint.h */
typedef struct {
        uint64_t low;
        uint64_t high;
} imb_uint128_t;

/**
 * Macros for aligning data structures and function inlines
 */
#if defined __linux__ || defined __FreeBSD__
/**< Linux/FreeBSD */
#define DECLARE_ALIGNED(decl, alignval) decl __attribute__((aligned(alignval)))
#define __forceinline                   static inline __attribute__((always_inline))

#if __GNUC__ >= 4
#define IMB_DLL_EXPORT __attribute__((visibility("default")))
#define IMB_DLL_LOCAL  __attribute__((visibility("hidden")))
#else /* GNU C 4.0 and later */
#define IMB_DLL_EXPORT
#define IMB_DLL_LOCAL
#endif /**< different C compiler */

#else
/* Windows */

#ifdef __MINGW32__
/* MinGW-w64 */
#define DECLARE_ALIGNED(decl, alignval) decl __attribute__((aligned(alignval)))
#undef __forceinline
#define __forceinline static inline __attribute__((always_inline))

#else
/* MSVS */
#define DECLARE_ALIGNED(decl, alignval) __declspec(align(alignval)) decl
#define __forceinline                   static __forceinline

#endif /* __MINGW__ */

/**
 * Windows DLL export is done via DEF file
 */
#define IMB_DLL_EXPORT
#define IMB_DLL_LOCAL

#endif /* defined __linux__ || defined __FreeBSD__ */

/**
 * Library version
 */
#define IMB_VERSION_STR "3.0.0-dev"
#define IMB_VERSION_NUM 0x30000

/**
 * Macro to translate version number
 */
#define IMB_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

/**
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

/**
 * Architecture definitions
 */
typedef enum {
        IMB_ARCH_NONE = 0,
        IMB_ARCH_SSE,
        IMB_ARCH_AVX2,
        IMB_ARCH_AVX512,
        IMB_ARCH_AVX10,
        IMB_ARCH_NUM,
} IMB_ARCH;

/**
 * Algorithm constants and structures
 */
#define IMB_DES_KEY_SCHED_SIZE (16 * 8) /**< 16 rounds x 8 bytes */
#define IMB_DES_BLOCK_SIZE     8

#define IMB_AES_BLOCK_SIZE 16

#define IMB_SM4_BLOCK_SIZE 16

#define IMB_SHA1_DIGEST_SIZE_IN_BYTES   20
#define IMB_SHA224_DIGEST_SIZE_IN_BYTES 28
#define IMB_SHA256_DIGEST_SIZE_IN_BYTES 32
#define IMB_SHA384_DIGEST_SIZE_IN_BYTES 48
#define IMB_SHA512_DIGEST_SIZE_IN_BYTES 64

#define IMB_SHA3_224_DIGEST_SIZE_IN_BYTES 28
#define IMB_SHA3_256_DIGEST_SIZE_IN_BYTES 32
#define IMB_SHA3_384_DIGEST_SIZE_IN_BYTES 48
#define IMB_SHA3_512_DIGEST_SIZE_IN_BYTES 64

#define IMB_SHA3_224_BLOCK_SIZE 144
#define IMB_SHA3_256_BLOCK_SIZE 136
#define IMB_SHA3_384_BLOCK_SIZE 104
#define IMB_SHA3_512_BLOCK_SIZE 72
#define IMB_SHA3_MAX_BLOCK_SIZE IMB_SHA3_224_BLOCK_SIZE

#define IMB_MD5_DIGEST_SIZE_IN_BYTES 16

#define IMB_SHA1_BLOCK_SIZE    64 /**< 512 bits is 64 byte blocks */
#define IMB_SHA_224_BLOCK_SIZE 64 /**< 512 bits is 64 byte blocks */
#define IMB_SHA_256_BLOCK_SIZE 64 /**< 512 bits is 64 byte blocks */
#define IMB_SHA_384_BLOCK_SIZE 128
#define IMB_SHA_512_BLOCK_SIZE 128

#define IMB_MD5_BLOCK_SIZE 64

#define IMB_KASUMI_KEY_SIZE    16
#define IMB_KASUMI_IV_SIZE     8
#define IMB_KASUMI_BLOCK_SIZE  8
#define IMB_KASUMI_DIGEST_SIZE 4

#define IMB_ZUC_KEY_LEN_IN_BYTES      16
#define IMB_ZUC_NEA6_KEY_LEN_IN_BYTES 32
#define IMB_ZUC_IV_LEN_IN_BYTES       16
#define IMB_ZUC_DIGEST_LEN_IN_BYTES   4

#define IMB_SNOW3G_DIGEST_LEN      4
#define IMB_SNOW3G_IV_LEN_IN_BYTES 16

#define IMB_SM3_DIGEST_SIZE 32
#define IMB_SM3_BLOCK_SIZE  64

/* 32 precomputed (4-byte) rounds for SM4 key schedule (128 bytes in total) */
#define IMB_SM4_KEY_SCHEDULE_ROUNDS 32

#define IMB_CHACHA20_POLY1305_KEY_SIZE 32
#define IMB_CHACHA20_POLY1305_IV_SIZE  12
#define IMB_POLY1305_BLOCK_SIZE        16

/* Per RFC 7539, max cipher size is (2^32 - 1) x 64 */
#define IMB_CHACHA20_POLY1305_MAX_LEN UINT64_C((1ULL << 38) - 64)

/**
 * @brief holds Chacha20-Poly1305 operation context
 */
struct chacha20_poly1305_context_data {
        uint64_t hash[3];    /**< Intermediate computation of hash value */
        uint64_t aad_len;    /**< Total AAD length */
        uint64_t hash_len;   /**< Total length to digest (excluding AAD) */
        uint8_t last_ks[64]; /**< Last 64 bytes of KS */
        uint8_t poly_key[IMB_CHACHA20_POLY1305_KEY_SIZE]; /**< Poly key */
        uint8_t poly_scratch[IMB_POLY1305_BLOCK_SIZE]; /**< Scratchpad to compute Poly on 16 bytes
                                                        */
        uint64_t last_block_count;                     /**< Last block count used in last segment */
        uint64_t remain_ks_bytes;                  /**< Amount of bytes still to use of key stream
                                                     (up to 63 bytes) */
        uint64_t remain_ct_bytes;                  /**< Amount of cipher text bytes still to use
                                                     of previous segment to authenticate
                                                     (up to 16 bytes) */
        uint8_t IV[IMB_CHACHA20_POLY1305_IV_SIZE]; /**< IV (12 bytes) */
};

/**
 * Minimum Ethernet frame size to calculate CRC32
 * Source Address (6 bytes) + Destination Address (6 bytes) + Type/Len (2 bytes)
 */
#define IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE 14
#define IMB_DOCSIS_CRC32_TAG_SIZE         4

/* 64 precomputed words for Kasumi key schedule */
#define KASUMI_KEY_SCHEDULE_SIZE 64

/**
 * Kasumi internal key scheduling
 */
typedef struct kasumi_key_sched_s {
        /**< Kasumi internal scheduling */
        uint16_t sk16[KASUMI_KEY_SCHEDULE_SIZE];  /**< key schedule */
        uint16_t msk16[KASUMI_KEY_SCHEDULE_SIZE]; /**< modified key schedule */
} kasumi_key_sched_t;

/**
 * IV data is limited to 16 bytes as follows:
 * 12 bytes is provided by an application -
 *    pre-counter block j0: 4 byte salt (from Security Association)
 *    concatenated with 8 byte Initialization Vector (from IPSec ESP
 *    Payload).
 * 4 byte value 0x00000001 is padded automatically by the library -
 *    there is no need to add these 4 bytes on application side anymore.
 */
#define IMB_GCM_IV_DATA_LEN (12)

#define IMB_GCM_128_KEY_LEN (16)
#define IMB_GCM_192_KEY_LEN (24)
#define IMB_GCM_256_KEY_LEN (32)

/* NIST SP 800-38-D, section 5.2.1.1: len(P) < 2^39 - 256 [bits] */
#define IMB_GCM_MAX_LEN UINT64_C((((1ULL << 39) - 256) / 8) - 1)

/**
 * @brief holds GCM operation context
 *
 * init, update and finalize context data
 */
struct gcm_context_data {
        /**
         * The context includes:
         * - AAD hash (16 bytes)
         * - AAD length (8 bytes)
         * - message length (8 bytes)
         * - partial block encrypted (16 bytes)
         * - original IV (16 bytes)
         * - current counter block (16 bytes)
         * - partial blocklength (8 bytes)
         */
        uint64_t ctx[11];
};

/**
 * @brief holds intermediate key data needed to improve performance
 *
 * gcm_key_data hold internal key information used by gcm128, gcm192 and gcm256.
 */
#ifdef _WIN32
__declspec(align(64))
#endif /* WIN32 */
struct gcm_key_data {
        /**
         * AES key schedule takes at most 15 expanded keys (AES256).
         * Each expanded key is 16 bytes long.
         */
        uint8_t expanded_keys[16 * 15];

        /**
         * Hash key size is 16 bytes.
         * Hash key structure sizes for various architectures look as follows:
         * - SSE: 8 pairs of hash keys -> 8 * 2 * 16 bytes
         * - AVX2: 8 pairs of hash keys -> 8 * 2 * 16 bytes
         * - AVX2 Type2: 16 pairs of hash keys -> 16 * 2 * 16 bytes
         * - AVX512 Type2: 32 pairs of hash keys -> 32 * 2 * 16 bytes
         */
        uint8_t ghash_keys[32 * 2 * 16];
}
#if defined(__linux__) || defined(__FreeBSD__)
__attribute__((aligned(64)));
#else
;
#endif

#define IMB_CCM_AAD_MAX_SIZE (46) /* Maximum CCM AAD size */

/**
 * Snow3G key scheduling structure
 */
typedef struct snow3g_key_schedule_s {
        uint32_t k[4];
} snow3g_key_schedule_t;

/**
 * Job structure definitions
 */

typedef enum {
        IMB_STATUS_BEING_PROCESSED = 0,
        IMB_STATUS_COMPLETED_CIPHER = 1,
        IMB_STATUS_COMPLETED_AUTH = 2,
        IMB_STATUS_COMPLETED = 3, /**< COMPLETED_CIPHER |
                                    COMPLETED_AUTH */
        IMB_STATUS_INVALID_ARGS = 4,
        IMB_STATUS_INTERNAL_ERROR,
        IMB_STATUS_ERROR
} IMB_STATUS;

/**
 * Library error types
 */
typedef enum {
        IMB_ERR_MIN = 2000,
        IMB_ERR_NULL_MBMGR,
        IMB_ERR_JOB_NULL_SRC,
        IMB_ERR_JOB_NULL_DST,
        IMB_ERR_JOB_NULL_KEY,
        IMB_ERR_JOB_NULL_IV,
        IMB_ERR_JOB_NULL_AUTH,
        IMB_ERR_JOB_NULL_AAD,
        IMB_ERR_JOB_CIPH_LEN,
        IMB_ERR_JOB_AUTH_LEN,
        IMB_ERR_JOB_IV_LEN,
        IMB_ERR_JOB_KEY_LEN,
        IMB_ERR_JOB_AUTH_TAG_LEN,
        IMB_ERR_JOB_AAD_LEN,
        IMB_ERR_JOB_SRC_OFFSET,
        IMB_ERR_JOB_CHAIN_ORDER,
        IMB_ERR_CIPH_MODE,
        IMB_ERR_HASH_ALGO,
        IMB_ERR_JOB_NULL_AUTH_KEY,
        IMB_ERR_JOB_NULL_SGL_CTX,
        IMB_ERR_JOB_NULL_NEXT_IV,
        IMB_ERR_JOB_PON_PLI,
        IMB_ERR_NULL_SRC,
        IMB_ERR_NULL_DST,
        IMB_ERR_NULL_KEY,
        IMB_ERR_NULL_EXP_KEY,
        IMB_ERR_NULL_IV,
        IMB_ERR_NULL_AUTH,
        IMB_ERR_NULL_AAD,
        IMB_ERR_CIPH_LEN,
        IMB_ERR_AUTH_LEN,
        IMB_ERR_IV_LEN,
        IMB_ERR_KEY_LEN,
        IMB_ERR_AUTH_TAG_LEN,
        IMB_ERR_AAD_LEN,
        IMB_ERR_SRC_OFFSET,
        IMB_ERR_NULL_AUTH_KEY,
        IMB_ERR_NULL_CTX,
        IMB_ERR_JOB_NULL_HMAC_OPAD,
        IMB_ERR_JOB_NULL_HMAC_IPAD,
        IMB_ERR_JOB_NULL_XCBC_K1_EXP,
        IMB_ERR_JOB_NULL_XCBC_K2,
        IMB_ERR_JOB_NULL_XCBC_K3,
        IMB_ERR_JOB_CIPH_DIR,
        IMB_ERR_JOB_NULL_GHASH_INIT_TAG,
        IMB_ERR_MISSING_CPUFLAGS_INIT_MGR,
        IMB_ERR_NULL_JOB,
        IMB_ERR_QUEUE_SPACE,
        IMB_ERR_NULL_BURST,
        IMB_ERR_BURST_SIZE,
        IMB_ERR_BURST_OOO,
        IMB_ERR_SELFTEST,
        IMB_ERR_BURST_SUITE_ID,
        IMB_ERR_JOB_SGL_STATE,
        /* add new error types above this comment */
        IMB_ERR_PQC_KEYOP,  /**< PQC key generation or key parse failure */
        IMB_ERR_PQC_SIGNOP, /**< PQC sign or verify operation failure */
        IMB_ERR_PQC_NO_KEY, /**< PQC operation attempted with no key bound to the context */
        IMB_ERR_PQC_ALG,    /**< Invalid PQC algorithm/parameter set selector */
        IMB_ERR_PQC_INIT,   /**< PQC context allocation or initialization failure */
        IMB_ERR_PQC_KEMOP,  /**< PQC key-encapsulation encap/decap operation failure */
        IMB_ERR_MAX         /* don't move this one */
} IMB_ERR;

/**
 * IMB_ERR_MIN should be higher than __ELASTERROR
 * to avoid overlap with standard error values
 */
#ifdef __ELASTERROR
#if __ELASTERROR > 2000
#error "Library error codes conflict with errno.h - please update IMB_ERR_MIN!"
#endif
#endif

typedef enum {
        IMB_CIPHER_CBC = 1,
        IMB_CIPHER_CNTR,
        IMB_CIPHER_CTR = IMB_CIPHER_CNTR,
        IMB_CIPHER_NULL,
        IMB_CIPHER_DOCSIS_SEC_BPI,
        IMB_CIPHER_GCM,
        IMB_CIPHER_CUSTOM,
        IMB_CIPHER_DES,
        IMB_CIPHER_DOCSIS_DES,
        IMB_CIPHER_CCM,
        IMB_CIPHER_DES3,
        IMB_CIPHER_PON_AES_CNTR,
        IMB_CIPHER_PON_AES_CTR = IMB_CIPHER_PON_AES_CNTR,
        IMB_CIPHER_ECB,
        IMB_CIPHER_ZUC_EEA3,    /**< 128-EEA3/NEA3 (3GPP) */
        IMB_CIPHER_SNOW3G_UEA2, /**< 128-UEA2 (3GPP) */
        IMB_CIPHER_KASUMI_UEA1, /**< 128-UEA1 (3GPP) */
        IMB_CIPHER_CHACHA20,
        IMB_CIPHER_CHACHA20_POLY1305,     /**< AEAD CHACHA20 */
        IMB_CIPHER_CHACHA20_POLY1305_SGL, /**< AEAD CHACHA20 with SGL support*/
        IMB_CIPHER_GCM_SGL,
        IMB_CIPHER_SM4_ECB,
        IMB_CIPHER_SM4_CBC,
        IMB_CIPHER_CFB,
        IMB_CIPHER_SM4_CNTR,
        IMB_CIPHER_SM4_CTR = IMB_CIPHER_SM4_CNTR,
        IMB_CIPHER_SM4_GCM,
        IMB_CIPHER_ZUC_NEA6,
        IMB_CIPHER_SNOW5G_NEA4,
        IMB_CIPHER_AES_NEA5,    /**< AES256-NEA5 */
        IMB_CIPHER_AES_NCA5,    /**< AES256-NCA5 */
        IMB_CIPHER_ZUC_NCA6,    /**< ZUC256-NCA6 */
        IMB_CIPHER_SNOW5G_NCA4, /**< SNOW5G-NCA4 */
        IMB_CIPHER_NUM          /**< Number of cipher modes */
} IMB_CIPHER_MODE;

typedef enum { IMB_DIR_ENCRYPT = 1, IMB_DIR_DECRYPT } IMB_CIPHER_DIRECTION;

typedef enum {
        IMB_AUTH_HMAC_SHA_1 = 1, /**< HMAC-SHA1 */
        IMB_AUTH_HMAC_SHA_224,   /**< HMAC-SHA224 */
        IMB_AUTH_HMAC_SHA_256,   /**< HMAC-SHA256 */
        IMB_AUTH_HMAC_SHA_384,   /**< HMAC-SHA384 */
        IMB_AUTH_HMAC_SHA_512,   /**< HMAC-SHA512 */
        IMB_AUTH_AES_XCBC,
        IMB_AUTH_MD5, /**< HMAC-MD5 */
        IMB_AUTH_NULL,
        IMB_AUTH_AES_GMAC,
        IMB_AUTH_CUSTOM,
        IMB_AUTH_AES_CCM,  /**< AES128-CCM */
        IMB_AUTH_AES_CMAC, /**< AES128-CMAC */
        IMB_AUTH_SHA_1,    /**< SHA1 */
        IMB_AUTH_SHA_224,  /**< SHA224 */
        IMB_AUTH_SHA_256,  /**< SHA256 */
        IMB_AUTH_SHA_384,  /**< SHA384 */
        IMB_AUTH_SHA_512,  /**< SHA512 */
        IMB_AUTH_PON_CRC_BIP,
        IMB_AUTH_ZUC_EIA3,               /**< 128-EIA3/NIA3 (3GPP) */
        IMB_AUTH_DOCSIS_CRC32,           /**< with DOCSIS_SEC_BPI only */
        IMB_AUTH_SNOW3G_UIA2,            /**< 128-UIA2 (3GPP) */
        IMB_AUTH_KASUMI_UIA1,            /**< 128-UIA1 (3GPP) */
        IMB_AUTH_AES_GMAC_128,           /**< AES-GMAC (128-bit key) */
        IMB_AUTH_AES_GMAC_192,           /**< AES-GMAC (192-bit key) */
        IMB_AUTH_AES_GMAC_256,           /**< AES-GMAC (256-bit key) */
        IMB_AUTH_AES_CMAC_256,           /**< AES256-CMAC */
        IMB_AUTH_POLY1305,               /**< POLY1305 */
        IMB_AUTH_CHACHA20_POLY1305,      /**< AEAD POLY1305 */
        IMB_AUTH_CHACHA20_POLY1305_SGL,  /**< AEAD CHACHA20 with SGL support */
        IMB_AUTH_GCM_SGL,                /**< AES-GCM with SGL support */
        IMB_AUTH_CRC32_ETHERNET_FCS,     /**< CRC32-ETHERNET-FCS */
        IMB_AUTH_CRC32_SCTP,             /**< CRC32-SCTP */
        IMB_AUTH_CRC32_WIMAX_OFDMA_DATA, /**< CRC32-WIMAX-OFDMA-DATA */
        IMB_AUTH_CRC24_LTE_A,            /**< CRC32-LTE-A */
        IMB_AUTH_CRC24_LTE_B,            /**< CRC32-LTE-B */
        IMB_AUTH_CRC16_X25,              /**< CRC16-X25 */
        IMB_AUTH_CRC16_FP_DATA,          /**< CRC16-FP-DATA */
        IMB_AUTH_CRC11_FP_HEADER,        /**< CRC11-FP-HEADER */
        IMB_AUTH_CRC10_IUUP_DATA,        /**< CRC10-IUUP-DATA */
        IMB_AUTH_CRC8_WIMAX_OFDMA_HCS,   /**< CRC8-WIMAX-OFDMA-HCS */
        IMB_AUTH_CRC7_FP_HEADER,         /**< CRC7-FP-HEADER */
        IMB_AUTH_CRC6_IUUP_HEADER,       /**< CRC6-IUUP-HEADER */
        IMB_AUTH_GHASH,                  /**< GHASH */
        IMB_AUTH_SM3,                    /**< SM3 */
        IMB_AUTH_HMAC_SM3,               /**< SM3-HMAC */
        IMB_AUTH_SM4_GCM,                /**< SM4-GCM */
        IMB_AUTH_SHA3_224,               /**< SHA3-224 */
        IMB_AUTH_SHA3_256,               /**< SHA3-256 */
        IMB_AUTH_SHA3_384,               /**< SHA3-384 */
        IMB_AUTH_SHA3_512,               /**< SHA3-512 */
        IMB_AUTH_SHAKE128,               /**< SHAKE128 */
        IMB_AUTH_SHAKE256,               /**< SHAKE256 */
        IMB_AUTH_AES_NIA5,               /**< AES256-NIA5 */
        IMB_AUTH_AES_NCA5,               /**< AES256-NCA5 */
        IMB_AUTH_ZUC_NIA6,               /**< ZUC256-NIA6 */
        IMB_AUTH_ZUC_NCA6,               /**< ZUC256-NCA6 */
        IMB_AUTH_SNOW5G_NIA4,            /**< SNOW5G-NIA4 */
        IMB_AUTH_SNOW5G_NCA4,            /**< SNOW5G-NCA4 */
        IMB_AUTH_HMAC_SHA3_224,          /**< HMAC-SHA3-224 */
        IMB_AUTH_HMAC_SHA3_256,          /**< HMAC-SHA3-256 */
        IMB_AUTH_HMAC_SHA3_384,          /**< HMAC-SHA3-384 */
        IMB_AUTH_HMAC_SHA3_512,          /**< HMAC-SHA3-512 */
        IMB_AUTH_NUM
} IMB_HASH_ALG;

typedef enum { IMB_ORDER_CIPHER_HASH = 1, IMB_ORDER_HASH_CIPHER } IMB_CHAIN_ORDER;

typedef enum {
        IMB_KEY_64_BYTES = 8,
        IMB_KEY_128_BYTES = 16,
        IMB_KEY_192_BYTES = 24,
        IMB_KEY_256_BYTES = 32
} IMB_KEY_SIZE_BYTES;

typedef enum { IMB_SGL_INIT = 0, IMB_SGL_UPDATE, IMB_SGL_COMPLETE, IMB_SGL_ALL } IMB_SGL_STATE;

/**
 * Input/output SGL segment structure.
 */
struct IMB_SGL_IOV {
        const void *in; /**< Input segment */
        void *out;      /**< Output segment */
        uint64_t len;   /** Length of segment */
};

/**
 * Job structure.
 *
 * For AES, enc_keys and dec_keys are
 * expected to point to expanded keys structure.
 * - AES-CTR, AES-ECB and AES-CCM, only enc_keys is used
 * - DOCSIS (AES-CBC + AES-CFB), both pointers are used
 *   enc_keys has to be set always for the partial block
 *
 * For DES, enc_keys and dec_keys are
 * expected to point to DES key schedule.
 * - same key schedule used for enc and dec operations
 *
 * For 3DES, enc_keys and dec_keys are
 * expected to point to an array of 3 pointers for
 * the corresponding 3 key schedules.
 * - same key schedule used for enc and dec operations
 *
 * Cipher offset only applies to src pointer, not dst pointer.
 * In case of an in-place operation, dst pointer needs to point
 * at src + cipher_start_src_offset_in_bytes.
 */
typedef struct IMB_JOB {
        const void *enc_keys;      /**< Encryption key pointer */
        const void *dec_keys;      /**< Decryption key pointer */
        uint64_t key_len_in_bytes; /**< Key length in bytes */
        union {
                const uint8_t *src; /**< Input buffer.
                                May be cipher text or plain text.
                                In-place ciphering allowed. */
                const struct IMB_SGL_IOV *sgl_io_segs;
                /**< Pointer to array of input/output SGL segments */
        };
        union {
                uint8_t *dst; /**< Output buffer.
                               May be cipher text or plain text.
                               In-place ciphering allowed, i.e. dst = src. */
                uint64_t num_sgl_io_segs;
                /**< Number of input/output SGL segments */
        };
        union {
                uint64_t cipher_start_src_offset_in_bytes;
                /**< Offset into input buffer to start ciphering (in bytes) */
        }; /**< Offset into input buffer to start ciphering */
        union {
                uint64_t msg_len_to_cipher_in_bytes;
                /**< Length of message to cipher (in bytes) */
        }; /**< Length of message to cipher */
        uint64_t hash_start_src_offset_in_bytes;
        union {
                uint64_t msg_len_to_hash_in_bytes;
                /**< Length of message to hash (in bytes) */
        }; /**< Length of message to hash */
        const uint8_t *iv;                     /**< Initialization Vector (IV) */
        uint64_t iv_len_in_bytes;              /**< IV length in bytes */
        uint8_t *auth_tag_output;              /**< Authentication tag output */
        uint64_t auth_tag_output_len_in_bytes; /**< Authentication tag output
                                                    length in bytes */

        /* Start hash algorithm-specific fields */
        union {
                struct _HMAC_specific_fields {
                        const uint8_t *_hashed_auth_key_xor_ipad;
                        /**< Hashed result of HMAC key xor'd
                         * with ipad (0x36). */
                        const uint8_t *_hashed_auth_key_xor_opad;
                        /**< Hashed result of HMAC key xor'd
                         * with opad (0x5c). */
                } HMAC; /**< HMAC specific fields */
                struct _AES_XCBC_specific_fields {
                        const uint32_t *_k1_expanded;
                        /**< k1 expanded key pointer (16-byte aligned) */
                        const uint8_t *_k2;
                        /**< k2 expanded key pointer (16-byte aligned) */
                        const uint8_t *_k3;
                        /**< k3 expanded key pointer (16-byte aligned) */
                } XCBC; /**< AES-XCBC specific fields */
                struct _AES_CCM_specific_fields {
                        const void *aad;
                        /**< Additional Authentication Data (AAD) */
                        uint64_t aad_len_in_bytes; /**< Length of AAD */
                } CCM;                             /**< AES-CCM specific fields */
                struct _AES_CMAC_specific_fields {
                        const void *_key_expanded;
                        /**< Expanded key (16-byte aligned) */
                        const void *_skey1; /**< S key 1 (16-byte aligned) */
                        const void *_skey2; /**< S key 2 (16-byte aligned) */
                } CMAC;                     /**< AES-CMAC specific fields */
                struct _AES_GCM_specific_fields {
                        const void *aad;
                        /**< Additional Authentication Data (AAD) */
                        uint64_t aad_len_in_bytes; /**< Length of AAD */
                        struct gcm_context_data *ctx;
                        /**< AES-GCM context (for SGL only) */
                } GCM; /**< AES-GCM specific fields */
                struct _ZUC_EIA3_specific_fields {
                        const uint8_t *_key;
                        /**< Authentication key (16-byte aligned) */
                        const uint8_t *_iv;
                        /**< Authentication 16-byte IV (16-byte aligned) */
                } ZUC_EIA3; /**< ZUC-EIA3 specific fields */
                struct _SNOW3G_UIA2_specific_fields {
                        const void *_key;
                        /**< Authentication key (16-byte aligned) */
                        const void *_iv;
                        /**< Authentication IV (16-byte aligned) */
                } SNOW3G_UIA2; /**< SNOW3G-UIA2 specific fields */
                struct _KASUMI_UIA1_specific_fields {
                        const void *_key;
                        /**< Authentication key (16-byte aligned) */
                } KASUMI_UIA1; /**< KASUMI-UIA2 specific fields */
                struct _AES_GMAC_specific_fields {
                        const struct gcm_key_data *_key;
                        /**< Authentication key */
                        const void *_iv;
                        /**< Authentication IV */
                        uint64_t iv_len_in_bytes;
                        /**< Authentication IV length in bytes */
                } GMAC; /**< AES-GMAC specific fields */
                struct _GHASH_specific_fields {
                        const struct gcm_key_data *_key;
                        /**< Expanded GHASH key */
                        const void *_init_tag; /**< initial tag value */
                } GHASH;                       /**< GHASH specific fields */
                struct _POLY1305_specific_fields {
                        const void *_key;
                        /**< Poly1305 key */
                } POLY1305; /**< Poly1305 specific fields */
                struct _CHACHA20_POLY1305_specific_fields {
                        const void *aad;
                        /**< Additional Authentication Data (AAD) */
                        uint64_t aad_len_in_bytes;
                        /**< Length of AAD */
                        struct chacha20_poly1305_context_data *ctx;
                        /**< Chacha20-Poly1305 context (for SGL only) */
                } CHACHA20_POLY1305; /**< Chacha20-Poly1305 specific fields */
                struct _NIA_specific_fields {
                        const void *_key;
                        /**< Authentication pointer key (16 bytes for NIA4 and NIA6
                         * pointer to expanded key for NIA5) */
                        const void *_iv;
                        /**< Authentication IV pointer (16 bytes) */
                } NIA; /**< NIA4/5/6 specific fields */
                struct _NCA_specific_fields {
                        const void *aad;
                        /**< Additional Authentication Data (AAD) */
                        uint64_t aad_len_in_bytes; /**< Length of AAD */
                } NCA;                             /**< NCA4/5/6 specific fields */

        } u; /**< Hash algorithm-specific fields */

        IMB_STATUS status;                     /**< Job status */
        IMB_CIPHER_MODE cipher_mode;           /**< Cipher mode */
        IMB_CIPHER_DIRECTION cipher_direction; /**< Cipher direction */
        IMB_HASH_ALG hash_alg;                 /**< Hashing algorithm */
        IMB_CHAIN_ORDER chain_order;
        /**< Chain order (IMB_ORDER_CIPHER_HASH / IMB_ORDER_HASH_CIPHER).*/

        void *user_data;  /**< Pointer 1 to user data */
        void *user_data2; /**< Pointer 2 to user data */

        int (*cipher_func)(struct IMB_JOB *);
        /**< Customer cipher function */
        int (*hash_func)(struct IMB_JOB *);
        /**< Customer hash function */

        IMB_SGL_STATE sgl_state;
        /**< SGL state (IMB_SGL_INIT/IMB_SGL_UPDATE/IMB_SGL_COMPLETE/
                        IMB_SGL_ALL) */

        uint32_t suite_id[2]; /**< see imb_set_session() */
        uint32_t session_id;  /**< see imb_set_session() */
} IMB_JOB;

/* Multi buffer manager data type definitions */
struct IMB_MGR;
typedef struct IMB_MGR IMB_MGR;

#define IMB_MAX_BURST_SIZE 128
#define IMB_MAX_JOBS       (IMB_MAX_BURST_SIZE * 2)

/**
 * Maximum Authenticated Tag Length in bytes.
 */
#define IMB_MAX_TAG_LEN (64)

/* Self-Test callback definitions */
typedef struct {
        const char *phase;
        const char *type;
        const char *descr;
} IMB_SELF_TEST_CALLBACK_DATA;

typedef int (*imb_self_test_cb_t)(void *cb_arg, const IMB_SELF_TEST_CALLBACK_DATA *data);

/* Multi-buffer manager flags passed to alloc_mb_mgr() */
#define IMB_FLAG_SHANI_OFF (1ULL << 0) /**< disable use of SHANI extension */
#define IMB_FLAG_GFNI_OFF  (1ULL << 1) /**< disable use of GFNI extension */

/**
 * Multi-buffer manager detected features
 * - if bit is set then hardware supports given extension
 * - valid after call to init_mb_mgr() or alloc_mb_mgr()
 * - some HW supported features can be disabled via IMB_FLAG_xxx (see above)
 */
#define IMB_FEATURE_SHANI     (1ULL << 0)
#define IMB_FEATURE_AESNI     (1ULL << 1)
#define IMB_FEATURE_PCLMULQDQ (1ULL << 2)
#define IMB_FEATURE_CMOV      (1ULL << 3)
#define IMB_FEATURE_SSE4_2    (1ULL << 4)
#define IMB_FEATURE_AVX       (1ULL << 5)
#define IMB_FEATURE_AVX2      (1ULL << 6)
#define IMB_FEATURE_AVX512F   (1ULL << 7)
#define IMB_FEATURE_AVX512DQ  (1ULL << 8)
#define IMB_FEATURE_AVX512CD  (1ULL << 9)
#define IMB_FEATURE_AVX512BW  (1ULL << 10)
#define IMB_FEATURE_AVX512VL  (1ULL << 11)
#define IMB_FEATURE_AVX512_SKX                                                                     \
        (IMB_FEATURE_AVX512F | IMB_FEATURE_AVX512DQ | IMB_FEATURE_AVX512CD |                       \
         IMB_FEATURE_AVX512BW | IMB_FEATURE_AVX512VL)
#define IMB_FEATURE_VAES           (1ULL << 12)
#define IMB_FEATURE_VPCLMULQDQ     (1ULL << 13)
#define IMB_FEATURE_SAFE_DATA      (1ULL << 14)
#define IMB_FEATURE_SAFE_PARAM     (1ULL << 15)
#define IMB_FEATURE_GFNI           (1ULL << 16)
#define IMB_FEATURE_AVX512_IFMA    (1ULL << 17)
#define IMB_FEATURE_BMI2           (1ULL << 18)
#define IMB_FEATURE_SELF_TEST      (1ULL << 19) /* self-test feature present */
#define IMB_FEATURE_SELF_TEST_PASS (1ULL << 20) /* self-test passed */
#define IMB_FEATURE_AVX_IFMA       (1ULL << 21)
#define IMB_FEATURE_HYBRID         (1ULL << 22) /* Hybrid core */
#define IMB_FEATURE_SM3NI          (1ULL << 23)
#define IMB_FEATURE_SM4NI          (1ULL << 24)
#define IMB_FEATURE_SHA512NI       (1ULL << 25)
#define IMB_FEATURE_XSAVE          (1ULL << 26)
#define IMB_FEATURE_OSXSAVE        (1ULL << 27) /* OS-enabled XSAVE */
#define IMB_FEATURE_APX            (1ULL << 28)
#define IMB_FEATURE_AVX10_256      (1ULL << 29)
#define IMB_FEATURE_AVX10_512      (1ULL << 30)
#define IMB_FEATURE_AVX10_2        (1ULL << 31)
#define IMB_FEATURE_MOVBE          (1ULL << 32)

/**
 * Self test defines
 */
#define IMB_SELF_TEST_PHASE_START   "START"
#define IMB_SELF_TEST_PHASE_PASS    "PASS"
#define IMB_SELF_TEST_PHASE_FAIL    "FAIL"
#define IMB_SELF_TEST_PHASE_CORRUPT "CORRUPT"

#define IMB_SELF_TEST_TYPE_KAT_CIPHER    "KAT_Cipher"
#define IMB_SELF_TEST_TYPE_KAT_AUTH      "KAT_Auth"
#define IMB_SELF_TEST_TYPE_KAT_AEAD      "KAT_AEAD"
#define IMB_SELF_TEST_TYPE_KAT_SIGNATURE "KAT_Signature"
#define IMB_SELF_TEST_TYPE_KAT_KEM       "KAT_KEM"

/**
 * CPU flags needed for each implementation
 */
#define IMB_CPUFLAGS_NO_AESNI (IMB_FEATURE_SSE4_2 | IMB_FEATURE_CMOV)
#define IMB_CPUFLAGS_SSE      (IMB_CPUFLAGS_NO_AESNI | IMB_FEATURE_AESNI | IMB_FEATURE_PCLMULQDQ)
#define IMB_CPUFLAGS_SSE_T2   (IMB_CPUFLAGS_SSE | IMB_FEATURE_SHANI)
#define IMB_CPUFLAGS_SSE_T3   (IMB_CPUFLAGS_SSE_T2 | IMB_FEATURE_GFNI)
#define IMB_CPUFLAGS_AVX2                                                                          \
        (IMB_CPUFLAGS_SSE | IMB_FEATURE_AVX | IMB_FEATURE_XSAVE | IMB_FEATURE_OSXSAVE |            \
         IMB_FEATURE_AVX2 | IMB_FEATURE_BMI2 | IMB_FEATURE_MOVBE)
#define IMB_CPUFLAGS_AVX512 (IMB_CPUFLAGS_AVX2 | IMB_FEATURE_AVX512_SKX)
#define IMB_CPUFLAGS_AVX512_T2                                                                     \
        (IMB_CPUFLAGS_AVX512 | IMB_FEATURE_VAES | IMB_FEATURE_VPCLMULQDQ | IMB_FEATURE_GFNI |      \
         IMB_FEATURE_AVX512_IFMA | IMB_FEATURE_SHANI)
#define IMB_CPUFLAGS_AVX2_T2                                                                       \
        (IMB_CPUFLAGS_AVX2 | IMB_FEATURE_SHANI | IMB_FEATURE_VAES | IMB_FEATURE_VPCLMULQDQ |       \
         IMB_FEATURE_GFNI)
#define IMB_CPUFLAGS_AVX2_T3 (IMB_CPUFLAGS_AVX2_T2 | IMB_FEATURE_AVX_IFMA)
#define IMB_CPUFLAGS_AVX2_T4                                                                       \
        (IMB_CPUFLAGS_AVX2_T3 | IMB_FEATURE_SM3NI | IMB_FEATURE_SM4NI | IMB_FEATURE_SHA512NI)
#define IMB_CPUFLAGS_AVX10                                                                         \
        (IMB_CPUFLAGS_AVX512_T2 | IMB_CPUFLAGS_AVX2_T4 | IMB_FEATURE_APX | IMB_FEATURE_AVX10_2 |   \
         IMB_FEATURE_AVX10_512)

/**
 * API definitions
 */

/**
 * @brief Get library version in string format
 *
 * @return library version string
 */
IMB_DLL_EXPORT const char *
imb_get_version_str(void);

/**
 * @brief Get library version in numerical format
 *
 * Use IMB_VERSION() macro to compare this
 * numerical version against known library version.
 *
 * @return library version number
 */
IMB_DLL_EXPORT unsigned
imb_get_version(void);

/**
 * @brief API to get error status
 *
 * @param mb_mgr Pointer to multi-buffer manager
 *
 * @retval Integer error type
 */
IMB_DLL_EXPORT int
imb_get_errno(IMB_MGR *mb_mgr);

/**
 * @brief API to get description for \a errnum
 *
 * @param errnum error type
 *
 * @retval String description of \a errnum
 */
IMB_DLL_EXPORT const char *
imb_get_strerror(int errnum);

/**
 * @brief API to get the features supported by the manager
 *
 * @param mb_mgr Pointer to multi-buffer manager
 * @param p_features Pointer to store features bit mask
 *
 * @return Operation status
 * @retval 0 success
 */
IMB_DLL_EXPORT int
imb_get_features(IMB_MGR *mb_mgr, uint64_t *p_features);

/**
 * @brief API to get the flags manager was initialized with
 *
 * @param mb_mgr Pointer to multi-buffer manager
 * @param p_flags Pointer to store flags bit mask
 *
 * @return Operation status
 * @retval 0 success
 */
IMB_DLL_EXPORT int
imb_get_flags(IMB_MGR *mb_mgr, uint64_t *p_flags);

/**
 * @brief Allocates memory for multi-buffer manager instance
 *
 * For binary compatibility between library versions
 * it is recommended to use this API.
 *
 * @param flags multi-buffer manager flags
 *     IMB_FLAG_SHANI_OFF - disable use (and detection) of SHA extensions,
 *                          currently SHANI is only available for SSE
 *     IMB_FLAG_GFNI_OFF - disable use (and detection) of
 *                         Galois Field extensions.
 *
 * @return Pointer to allocated memory for IMB_MGR structure
 * @retval NULL on allocation error
 */
IMB_DLL_EXPORT IMB_MGR *
alloc_mb_mgr(uint64_t flags);

/**
 * @brief Frees memory allocated previously by alloc_mb_mgr()
 *
 * @param [in] ptr Pointer to allocated MB_MGR structure
 *
 */
IMB_DLL_EXPORT void
free_mb_mgr(IMB_MGR *ptr);

/**
 * @brief Calculates necessary memory size for IMB_MGR.
 *
 * @return Size for IMB_MGR (aligned to 64 bytes)
 */
IMB_DLL_EXPORT size_t
imb_get_mb_mgr_size(void);

/**
 * @brief Initializes IMB_MGR pointers to out-of-order managers with
 *        use of externally allocated memory.
 *
 * imb_get_mb_mgr_size() should be called to know how much memory
 * should be allocated externally.
 *
 * init_mb_mgr_XXX() must be called after this function call,
 * whereas XXX is the desired architecture.
 *
 * @param [in] ptr a pointer to allocated memory
 * @param [in] flags multi-buffer manager flags
 *     IMB_FLAG_SHANI_OFF - disable use (and detection) of SHA extensions,
 *                          currently SHANI is only available for SSE
 *     IMB_FLAG_GFNI_OFF - disable use (and detection)
 *                         of Galois Field extensions.
 *
 * @param [in] reset_mgr if 0, IMB_MGR structure is not cleared, else it is.
 *
 * @return Pointer to IMB_MGR structure
 */
IMB_DLL_EXPORT IMB_MGR *
imb_set_pointers_mb_mgr(void *ptr, const uint64_t flags, const unsigned reset_mgr);

/**
 * @brief Retrieves the bit mask with available CPU features supported by the library,
 *        without having to allocate/initialize IMB_MGR;
 *
 * See IMB_CPUFLAGS_XXX or IMB_FEATURE_XXX (i.e. IMB_CPUFLAGS_SSE or IMB_FEATURE_AVX_IFMA).
 *
 * @return Bit mask containing CPU feature flags
 */
IMB_DLL_EXPORT uint64_t
imb_get_cpu_features(void);

/**
 * @brief Submit job for processing after validating.
 *
 * @param [in,out] state Pointer to initialized IMB_MGR structure
 *
 * @return Pointer to completed IMB_JOB or NULL if no job completed
 *         If NULL, imb_get_errno() can be used to check for potential
 *         error conditions
 */
IMB_DLL_EXPORT IMB_JOB *
imb_submit_job(IMB_MGR *state);

/**
 * @brief Submit job for processing without validating.
 *
 * This is more performant but less secure than submit_job_xxx()
 *
 * @param [in,out] state Pointer to initialized IMB_MGR structure
 *
 * @return Pointer to completed IMB_JOB or NULL if no job completed
 */
IMB_DLL_EXPORT IMB_JOB *
imb_submit_job_nocheck(IMB_MGR *state);

/**
 * @brief Force processing until next job in queue is completed.
 *
 * @param [in,out] state Pointer to initialized IMB_MGR structure
 *
 * @return Pointer to completed IMB_JOB or NULL if no more jobs to process
 */
IMB_DLL_EXPORT IMB_JOB *
imb_flush_job(IMB_MGR *state);

/**
 * @brief Get number of jobs queued to be processed.
 *
 * @param [in,out] state Pointer to initialized IMB_MGR structure
 *
 * @return Number of jobs in the queue
 */
IMB_DLL_EXPORT uint32_t
imb_queue_size(IMB_MGR *state);

/**
 * @brief Get next completed job.
 *
 * @param [in,out] state Pointer to initialized IMB_MGR structure
 *
 * @return Pointer to completed IMB_JOB or NULL if next job not complete
 */
IMB_DLL_EXPORT IMB_JOB *
imb_get_completed_job(IMB_MGR *state);

/**
 * @brief Get next available job.
 *
 * get_next_job() returns a job object. This must be filled in and returned
 * via submit_job() before get_next_job() is called again.
 * After submit_job() is called, one should call get_completed_job() at least
 * once (and preferably until it returns NULL).
 * get_completed_job() and flush_job() returns a job object. This job object ceases
 * to be usable at the next call to get_next_job().
 *
 * @param [in,out] state Pointer to initialized IMB_MGR structure
 *
 * @return Pointer to next free IMB_JOB in the queue
 */
IMB_DLL_EXPORT IMB_JOB *
imb_get_next_job(IMB_MGR *state);

/**
 * @brief Automatically initialize most performant
 *        Multi-buffer manager based on CPU features
 *
 * @param [in]  state Pointer to MB_MGR struct
 * @param [out] arch Pointer to arch enum to be set (can be NULL)
 *
 */
IMB_DLL_EXPORT void
init_mb_mgr_auto(IMB_MGR *state, IMB_ARCH *arch);

/**
 * @brief Initialize multi-buffer manager for SSE architecture
 *
 * @param [in,out] state Pointer to IMB_MGR struct
 */
IMB_DLL_EXPORT void
init_mb_mgr_sse(IMB_MGR *state);

/**
 * @brief Initialize multi-buffer manager for AVX2 architecture
 *
 * @param [in,out] state Pointer to IMB_MGR struct
 */
IMB_DLL_EXPORT void
init_mb_mgr_avx2(IMB_MGR *state);

/**
 * @brief Initialize multi-buffer manager for AVX512 architecture
 *
 * @param [in,out] state Pointer to IMB_MGR struct
 */
IMB_DLL_EXPORT void
init_mb_mgr_avx512(IMB_MGR *state);

/**
 * @brief Initialize multi-buffer manager for AVX10 architecture
 *
 * @param [in,out] state Pointer to IMB_MGR struct
 */
IMB_DLL_EXPORT void
init_mb_mgr_avx10(IMB_MGR *state);

/**
 * @brief Get information about an out-of-order (OOO) manager for testing
 *
 * This API allows test applications to access individual OOO manager structures
 * for memory scanning to detect sensitive data leaks.
 *
 * @param [in]  state         Pointer to IMB_MGR structure
 * @param [in]  index         Index of OOO manager (-1 for IMB_MGR, then 0 to count-1)
 * @param [out] ooo_ptr       Pointer to OOO manager structure (can be NULL if not initialized)
 * @param [out] ooo_size      Size of OOO manager in bytes (can be NULL)
 * @param [out] ooo_name      Name of OOO manager as NULL-terminated string (can be NULL)
 *
 * @return 0 on success, -1 if index is out of bounds
 *
 * @note This API is for TESTING/VALIDATION ONLY and should not be used in production code.
 * @note If the OOO manager at the given index is NULL (not initialized), ooo_ptr will be NULL
 *       but the function will still return 0 (success) as long as index is valid.
 */
IMB_DLL_EXPORT int
imb_get_ooo_mgr(IMB_MGR *state, const int index, void **ooo_ptr, size_t *ooo_size,
                const char **ooo_name);

/**
 * @brief API to get a string with the architecture type being used.
 *
 * init_mb_mgr_XXX() must be called before this function call,
 * where XXX is the desired architecture (can be auto).
 *
 * @param [in] state        pointer to IMB_MGR
 * @param [out] arch_type   string with architecture type
 * @param [out] description string with description of the arch type
 *
 * @return operation status.
 * @retval 0 success
 * @retval IMB_ERR_NULL_MBMGR invalid \a mb_mgr pointer
 */
IMB_DLL_EXPORT int
imb_get_arch_type_string(const IMB_MGR *state, const char **arch_type, const char **description);

/**
 * @brief Sets callback function to be invoked when running a self test.
 *
 * If \a cb_fn is NULL then self test callback functionality gets disabled.
 *
 * @param [in] state   pointer to IMB_MGR
 * @param [in] cb_fn   pointer to self test callback function
 * @param [in] cb_arg  argument to be passed to the callback function \a cb_fn
 *
 * @return Operation status of \a IMB_ERR type
 * @retval 0 on success
 */
IMB_DLL_EXPORT int
imb_self_test_set_cb(IMB_MGR *state, imb_self_test_cb_t cb_fn, void *cb_arg);

/**
 * @brief Retrieves details of callback function to be invoked when running a self test.
 *
 * It may be useful to check status of self test callback or daisy chain
 * a few callbacks together.
 *
 * @param [in] state       pointer to IMB_MGR
 * @param [in,out] cb_fn   pointer to place pointer to self test callback function
 * @param [in,out] cb_arg  pointer to place callback function argument
 *
 * @return Operation status of \a IMB_ERR type
 * @retval 0 on success
 */
IMB_DLL_EXPORT int
imb_self_test_get_cb(IMB_MGR *state, imb_self_test_cb_t *cb_fn, void **cb_arg);

/**
 * @brief Sets up suite_id and session_id fields for selected cipher suite in
 *        provided \a job structure
 *
 * This is mandatory operation for BURST API as suite_id is used to speed up
 * job dispatch process.
 * This operation is optional but helpful for JOB API use case.
 *
 * 'session_id' field is for application use to optimize job set up process.
 * If JOB structure provided by library for a new operation has same session ID
 * as required for the next operation then only message pointers and sizes
 * need to be set up by the application. All other session fields are guaranteed
 * to be unmodified by the library:
 * - cipher mode
 * - cipher direction
 * - hash algorithm
 * - key size
 * - encrypt & decrypt key pointers
 * - suite_id
 * If allocated JOB structure contains different session ID then
 * all required session and crypto operation fields need to be set up.
 *
 * In connection oriented applications, a template filled-in job structure
 * can be cached within connection structure and reused in submit operations.
 *
 * For given set of parameters: cipher mode, cipher key size,
 * cipher direction and authentication mode, suite_id field is the same.
 *
 * @see IMB_SUBMIT_BURST()
 * @see IMB_SUBMIT_BURST_NOCHECK()
 * @see IMB_SUBMIT_JOB()
 * @see IMB_SUBMIT_JOB_NOCHECK()
 *
 * @param [in]     state   pointer to IMB_MGR
 * @param [in,out] job     pointer to prepared JOB structure
 *
 * @return Session ID value
 * @retval 0 on error
 */
IMB_DLL_EXPORT uint32_t
imb_set_session(IMB_MGR *state, IMB_JOB *job);

/**
 * @brief Get next available burst
 *        (list of pointers to available IMB_JOB structures).
 *
 * @param [in] n_jobs      Requested number of burst jobs
 * @param [out] jobs       List of pointers to returned jobs
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of returned jobs.
 *         May be less than number of requested jobs if not enough space in
 *         queue. IMB_FLUSH_BURST() can be used to free up space.
 */
IMB_DLL_EXPORT uint32_t
imb_get_next_burst(IMB_MGR *state, const uint32_t n_jobs, IMB_JOB **jobs);

/**
 * @brief Submit multiple jobs to be processed after validating.
 *
 * Prior to submission, \a _jobs need to be initialized with correct
 * crypto job parameters and followed with a call to imb_set_session().
 *
 * @param [in] state  Pointer to initialized IMB_MGR structure
 * @param [in] n_jobs          Number of jobs to submit for processing
 * @param [in,out] jobs        In:  List of pointers to jobs for submission
 *                              Out: List of pointers to completed jobs
 *
 * @see imb_set_session()
 *
 * @return Number of completed jobs or zero on error.
 *         If zero, imb_get_errno() can be used to check for potential
 *         error conditions and _jobs[0] contains pointer to invalid job
 */
IMB_DLL_EXPORT uint32_t
imb_submit_burst(IMB_MGR *state, const uint32_t n_jobs, IMB_JOB **jobs);

/**
 * @brief Submit multiple jobs to be processed without validating.
 *
 * Prior to submission \a _jobs need to be initialized with correct
 * crypto job parameters and followed with call to imb_set_session().
 *
 * @param [in] n_jobs          Number of jobs to submit for processing
 * @param [in,out] jobs        In:  List of pointers to jobs for submission
 *                              Out: List of pointers to completed jobs
 * @param [in] state  Pointer to initialized IMB_MGR structure
 * @see imb_set_session()
 *
 * @return Number of completed jobs or zero on error
 */
IMB_DLL_EXPORT uint32_t
imb_submit_burst_nocheck(IMB_MGR *state, const uint32_t n_jobs, IMB_JOB **jobs);

/**
 * @brief Force up to \a max_jobs outstanding jobs to completion.
 *
 * @param [in] n_jobs        Maximum number of jobs to flush
 * @param [out] jobs           List of pointers to completed jobs
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of completed jobs
 */
IMB_DLL_EXPORT uint32_t
imb_flush_burst(IMB_MGR *state, const uint32_t n_jobs, IMB_JOB **jobs);

/**
 * @brief Retrieves minimum burst size for good performance on cipher algorithms.
 *
 * Depending on the architecture used, this function returns the minimum
 * burst size to be used for good performance on the cipher-only burst API.
 * The output burst size can be 1 (in case of a synchronous single-buffer implementation
 * or 0 if the algorithm is not supported by the API).
 *
 * @param [in] mb_mgr          pointer to IMB MGR structure
 * @param [in] cipher_mode     cipher mode
 * @param [out] out_burst_size pointer to store min burst size
 *
 * @return operation status.
 * @retval 0 success
 * @retval IMB_ERR_CIPHER_MODE  not supported \a algo
 * @retval IMB_ERR_NULL_MBMGR invalid \a mb_mgr pointer
 * @retval IMB_ERR_NULL_BURST invalid \a out_burst_size pointer
 */
IMB_DLL_EXPORT int
imb_cipher_burst_get_size(const IMB_MGR *mb_mgr, const IMB_CIPHER_MODE cipher_mode,
                          unsigned *out_burst_size);

/**
 * Submit multiple cipher jobs to be processed synchronously after validating.
 *
 * @param [in,out] jobs   Pointer to array of IMB_JOB structures
 * @param [in] n_jobs     Number of jobs to process
 * @param [in] cipher_mode     Cipher algorithm of type #IMB_CIPHER_MODE
 * @param [in] cipher_direction        Cipher direction of type #IMB_CIPHER_DIRECTION
 * @param [in] key_size   Key size in bytes of type #IMB_KEY_SIZE_BYTES
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of completed jobs
 */
IMB_DLL_EXPORT uint32_t
imb_submit_cipher_burst(IMB_MGR *state, IMB_JOB *jobs, const uint32_t n_jobs,
                        const IMB_CIPHER_MODE cipher_mode,
                        const IMB_CIPHER_DIRECTION cipher_direction,
                        const IMB_KEY_SIZE_BYTES key_size);

/**
 * Submit multiple cipher jobs to be processed synchronously without validating.
 *
 * This is more performant but less secure than IMB_SUBMIT_CIPHER_BURST().
 *
 * @param [in,out] jobs   Pointer to array of IMB_JOB structures
 * @param [in] n_jobs     Number of jobs to process
 * @param [in] cipher_mode     Cipher algorithm of type #IMB_CIPHER_MODE
 * @param [in] cipher_direction        Cipher direction of type #IMB_CIPHER_DIRECTION
 * @param [in] key_size   Key size in bytes of type #IMB_KEY_SIZE_BYTES
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of completed jobs
 */
IMB_DLL_EXPORT uint32_t
imb_submit_cipher_burst_nocheck(IMB_MGR *state, IMB_JOB *jobs, const uint32_t n_jobs,
                                const IMB_CIPHER_MODE cipher_mode,
                                const IMB_CIPHER_DIRECTION cipher_direction,
                                const IMB_KEY_SIZE_BYTES key_size);

/**
 * @brief Retrieves minimum burst size for good performance on hash algorithms.
 *
 * Depending on the architecture used, this function returns the minimum
 * burst size to be used for good performance on the hash-only burst API.
 * Note that this will not return a value for best performance, but the minimum needed
 * to start maximizing the CPU core (i.e. enough buffers to utilize efficiently the CPU core
 * resources, taking into account that when buffers have different sizes, a higher burst size is
 * recommended).
 *
 * The output burst size may also be 1 (in case of a synchronous single-buffer implementation
 * or 0 if the algorithm is not supported by the API).
 *
 * @param [in] mb_mgr          pointer to IMB MGR structure
 * @param [in] algo            hash algorithm
 * @param [out] out_burst_size pointer to store min burst size
 *
 * @return operation status.
 * @retval 0 success
 * @retval IMB_ERR_HASH_ALGO  not supported \a algo
 * @retval IMB_ERR_NULL_MBMGR invalid \a mb_mgr pointer
 * @retval IMB_ERR_NULL_BURST invalid \a out_burst_size pointer
 */
IMB_DLL_EXPORT int
imb_hash_burst_get_size(const IMB_MGR *mb_mgr, const IMB_HASH_ALG algo, unsigned *out_burst_size);

/**
 * Submit multiple hash jobs to be processed synchronously after validating.
 *
 * @param [in,out] jobs   Pointer to array of IMB_JOB structures
 * @param [in] n_jobs     Number of jobs to process
 * @param [in] hash_alg       Hash algorithm of type #IMB_HASH_ALG
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of completed jobs
 */
IMB_DLL_EXPORT uint32_t
imb_submit_hash_burst(IMB_MGR *state, IMB_JOB *jobs, const uint32_t n_jobs,
                      const IMB_HASH_ALG hash_alg);

/**
 * Submit multiple hash jobs to be processed synchronously without validating.
 *
 * This is more performant but less secure than IMB_SUBMIT_HASH_BURST().
 *
 * @param [in,out] jobs   Pointer to array of IMB_JOB structures
 * @param [in] n_jobs     Number of jobs to process
 * @param [in] hash_alg       Hash algorithm of type #IMB_HASH_ALG
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of completed jobs
 */
IMB_DLL_EXPORT uint32_t
imb_submit_hash_burst_nocheck(IMB_MGR *state, IMB_JOB *jobs, const uint32_t n_jobs,
                              const IMB_HASH_ALG hash_alg);

/**
 * @brief Retrieves minimum burst size for good performance on AEAD algorithms.
 *
 * Depending on the architecture used, this function returns the minimum
 * burst size to be used for good performance on the AEAD burst API.
 * The output burst size can be 1 (in case of a synchronous single-buffer implementation
 * or 0 if the algorithm is not supported by the API).
 *
 * @param [in] mb_mgr          pointer to IMB MGR structure
 * @param [in] cipher_mode     cipher mode
 * @param [out] out_burst_size pointer to store min burst size
 *
 * @return operation status.
 * @retval 0 success
 * @retval IMB_ERR_CIPHER_MODE  not supported \a algo
 * @retval IMB_ERR_NULL_MBMGR invalid \a mb_mgr pointer
 * @retval IMB_ERR_NULL_BURST invalid \a out_burst_size pointer
 */
IMB_DLL_EXPORT int
imb_aead_burst_get_size(const IMB_MGR *mb_mgr, const IMB_CIPHER_MODE cipher_mode,
                        unsigned *out_burst_size);

/**
 * Submit multiple cipher jobs to be processed synchronously after validating.
 *
 * @param [in,out] jobs   Pointer to array of IMB_JOB structures
 * @param [in] n_jobs     Number of jobs to process
 * @param [in] cipher_mode     Cipher algorithm of type #IMB_CIPHER_MODE
 * @param [in] cipher_direction        Cipher direction of type #IMB_CIPHER_DIRECTION
 * @param [in] key_size   Key size in bytes of type #IMB_KEY_SIZE_BYTES
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of completed jobs
 */
IMB_DLL_EXPORT uint32_t
imb_submit_aead_burst(IMB_MGR *state, IMB_JOB *jobs, const uint32_t n_jobs,
                      const IMB_CIPHER_MODE cipher_mode,
                      const IMB_CIPHER_DIRECTION cipher_direction,
                      const IMB_KEY_SIZE_BYTES key_size);

/**
 * Submit multiple cipher jobs to be processed synchronously without validating.
 *
 * This is more performant but less secure than IMB_SUBMIT_AEAD_BURST().
 *
 * @param [in,out] jobs   Pointer to array of IMB_JOB structures
 * @param [in] n_jobs     Number of jobs to process
 * @param [in] cipher_mode     Cipher algorithm of type #IMB_CIPHER_MODE
 * @param [in] cipher_direction        Cipher direction of type #IMB_CIPHER_DIRECTION
 * @param [in] key_size   Key size in bytes of type #IMB_KEY_SIZE_BYTES
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return Number of completed jobs
 */
IMB_DLL_EXPORT uint32_t
imb_submit_aead_burst_nocheck(IMB_MGR *state, IMB_JOB *jobs, const uint32_t n_jobs,
                              const IMB_CIPHER_MODE cipher_mode,
                              const IMB_CIPHER_DIRECTION cipher_direction,
                              const IMB_KEY_SIZE_BYTES key_size);

/*
 * =========================================================
 * =========================================================
 * AES
 * =========================================================
 */

/**
 * Generate encryption/decryption AES-128 expansion keys.
 *
 * @param [in] key          AES-128 key
 * @param [out] enc_exp_keys AES-128 encryption expansion key
 * @param [out] dec_exp_keys AES-128 decryption expansion key
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes_keyexp_128(const void *key, void *enc_exp_keys, void *dec_exp_keys, IMB_MGR *state);

/**
 * Generate encryption/decryption AES-192 expansion keys.
 *
 * @param [in] key          AES-192 key
 * @param [out] enc_exp_keys AES-192 encryption expansion key
 * @param [out] dec_exp_keys AES-192 decryption expansion key
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes_keyexp_192(const void *key, void *enc_exp_keys, void *dec_exp_keys, IMB_MGR *state);

/**
 * Generate encryption/decryption AES-256 expansion keys.
 *
 * @param [in] key          AES-256 key
 * @param [out] enc_exp_keys AES-256 encryption expansion key
 * @param [out] dec_exp_keys AES-256 decryption expansion key
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes_keyexp_256(const void *key, void *enc_exp_keys, void *dec_exp_keys, IMB_MGR *state);

/**
 * Generate AES-128-CMAC subkeys.
 *
 * @param [in] enc_exp_key     Input expanded AES-128-CMAC key
 * @param [out] key1       Subkey 1
 * @param [out] key2       Subkey 2
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes_cmac_subkey_gen_128(const void *enc_exp_key, void *key1, void *key2, IMB_MGR *state);

/**
 * Generate AES-256-CMAC subkeys.
 *
 * @param [in] enc_exp_key     Input expanded AES-256-CMAC key
 * @param [out] key1       Subkey 1
 * @param [out] key2       Subkey 2
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes_cmac_subkey_gen_256(const void *enc_exp_key, void *key1, void *key2, IMB_MGR *state);

/**
 * Generate AES-128-XCBC expansion keys.
 *
 * @param [in] key         AES-128-XCBC key
 * @param [out] exp_key1    k1 expansion key
 * @param [out] exp_key2   k2 expansion key
 * @param [out] exp_key3   k3 expansion key
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes_xcbc_keyexp(const void *key, void *exp_key1, void *exp_key2, void *exp_key3,
                    IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * SHA1
 * =========================================================
 */

/**
 * Authenticate 64-byte data buffer with SHA1.
 *
 * @param [in] src    64-byte data buffer
 * @param [out] digest   Digest output (20 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha1_one_block(const void *src, void *digest, IMB_MGR *state);

/**
 * Authenticate variable sized data with SHA1.
 *
 * @param [in] src    Data buffer
 * @param [in] length Length of data in bytes for authentication.
 * @param [out] digest   Digest output (20 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha1(const void *src, const uint64_t length, void *digest, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * SHA2-256
 * =========================================================
 */

/**
 * Authenticate 64-byte data buffer with SHA224.
 *
 * @note The output \a tag is 32 bytes long (not 28 bytes).
 *       This is needed for HMAC IPAD and OPAD computation
 *       where full 8 word digest is required.
 *
 * @param [in] src    64-byte data buffer
 * @param [out] digest   Digest output (32 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha224_one_block(const void *src, void *digest, IMB_MGR *state);

/**
 * Authenticate variable sized data with SHA224.
 *
 * @param [in] src    Data buffer
 * @param [in] length Length of data in bytes for authentication.
 * @param [out] digest   Digest output (28 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha224(const void *src, const uint64_t length, void *digest, IMB_MGR *state);

/**
 * Authenticate 64-byte data buffer with SHA256.
 *
 * @param [in] src    64-byte data buffer
 * @param [out] digest   Digest output (32 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha256_one_block(const void *src, void *digest, IMB_MGR *state);

/**
 * Authenticate variable sized data with SHA256.
 *
 * @param [in] src    Data buffer
 * @param [in] length Length of data in bytes for authentication.
 * @param [out] digest   Digest output (32 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha256(const void *src, const uint64_t length, void *digest, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * SHA2-512
 * =========================================================
 */

/**
 * Authenticate 128-byte data buffer with SHA384.
 *
 * @note The output \a tag is 64 bytes long, not 48 bytes.
 *       This is needed for HMAC IPAD and OPAD computation
 *       where full 8 word digest is required.
 *
 * @param [in] src    128-byte data buffer
 * @param [out] digest   Digest output (64 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha384_one_block(const void *src, void *digest, IMB_MGR *state);

/**
 * Authenticate variable sized data with SHA384.
 *
 * @param [in] src    Data buffer
 * @param [in] length Length of data in bytes for authentication.
 * @param [out] digest   Digest output (48 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha384(const void *src, const uint64_t length, void *digest, IMB_MGR *state);

/**
 * Authenticate 128-byte data buffer with SHA512.
 *
 * @param [in] src    128-byte data buffer
 * @param [out] digest   Digest output (64 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha512_one_block(const void *src, void *digest, IMB_MGR *state);

/**
 * Authenticate variable sized data with SHA512.
 *
 * @param [in] src    Data buffer
 * @param [in] length Length of data in bytes for authentication.
 * @param [out] digest   Digest output (20 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sha512(const void *src, const uint64_t length, void *digest, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm
 * =========================================================
 * =========================================================
 */

/**
 * Opaque ML-DSA context handle. Created with imb_ml_dsa_new() and released
 * with imb_ml_dsa_free(). Bound to a single parameter set for its lifetime.
 *
 * The context also caches at most one decoded/generated key at a time (see
 * imb_ml_dsa_keypair(), imb_ml_dsa_set_privkey() and imb_ml_dsa_set_pubkey()),
 * which every sign/verify call reuses. This
 * mirrors the key-lifecycle model used by an OpenSSL provider: decode/import
 * a key once, then perform many signature operations against it. Binding a
 * new key to a context replaces the previously bound one. A context is not
 * safe for concurrent use by multiple threads; independent threads should
 * use their own IMB_ML_DSA context (they may share the same key material by
 * calling imb_ml_dsa_set_privkey()/imb_ml_dsa_set_pubkey() with the same
 * encoded bytes on each context).
 */
struct IMB_ML_DSA;
typedef struct IMB_ML_DSA IMB_ML_DSA;

/**
 * ML-DSA parameter set selector (FIPS 204).
 */
typedef enum { IMB_ML_DSA_44 = 1, IMB_ML_DSA_65 = 2, IMB_ML_DSA_87 = 3 } IMB_ML_DSA_ALG;

/* Encoded public key, private key and signature sizes in bytes.
 * See FIPS 204 Section 4, Tables 1 & 2. */
#define IMB_ML_DSA_44_PUBKEY_BYTES  1312
#define IMB_ML_DSA_44_PRIVKEY_BYTES 2560
#define IMB_ML_DSA_44_SIG_BYTES     2420

#define IMB_ML_DSA_65_PUBKEY_BYTES  1952
#define IMB_ML_DSA_65_PRIVKEY_BYTES 4032
#define IMB_ML_DSA_65_SIG_BYTES     3309

#define IMB_ML_DSA_87_PUBKEY_BYTES  2592
#define IMB_ML_DSA_87_PRIVKEY_BYTES 4896
#define IMB_ML_DSA_87_SIG_BYTES     4627

/**
 * @brief Allocate and initialize an ML-DSA context for a given parameter set.
 *
 * @param [in]  mgr      Pointer to initialized IMB_MGR structure
 * @param [in]  alg      ML-DSA parameter set (IMB_ML_DSA_44/65/87)
 * @param [out] new_self Receives the new IMB_ML_DSA context on success, or
 *                       NULL on failure
 *
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_MBMGR invalid \a mgr pointer
 * @retval IMB_ERR_NULL_CTX invalid \a new_self pointer
 * @retval IMB_ERR_PQC_ALG invalid \a alg
 * @retval IMB_ERR_PQC_INIT context allocation or initialization failed
 */
IMB_DLL_EXPORT int
imb_ml_dsa_new(IMB_MGR *mgr, IMB_ML_DSA_ALG alg, IMB_ML_DSA **new_self);

/**
 * @brief Release an ML-DSA context allocated by imb_ml_dsa_new(), along with any
 *        key currently bound to it.
 *
 * @param [in] self  ML-DSA context (may be NULL)
 */
IMB_DLL_EXPORT void
imb_ml_dsa_free(IMB_ML_DSA *self);

/**
 * Optional parameters for imb_ml_dsa_keypair(). A NULL \a params pointer is
 * equivalent to a zero-initialized structure: fresh-random key generation -
 * the common-case default.
 */
typedef struct IMB_ML_DSA_KEYGEN_PARAMS {
        /**
         * Optional 32-byte key generation seed (FIPS 204 xi).
         * NULL requests fresh-random key generation: the library generates
         * a fresh random seed internally for each call.
         * Non-NULL uses the supplied 32 bytes verbatim, producing a
         * deterministic key pair.
         */
        const uint8_t *xi_32;
} IMB_ML_DSA_KEYGEN_PARAMS;

/**
 * @brief Generate an ML-DSA key pair (FIPS 204 KeyGen) and bind it to \a self,
 *        replacing any previously bound key. The generated key carries both
 *        private and public components, so \a self may be used with both the sign
 *        and verify functions immediately afterwards.
 *
 * @param [in]  self    ML-DSA context
 * @param [out] pk      Encoded public key buffer (variant PUBKEY_BYTES)
 * @param [out] sk      Encoded private key buffer (variant PRIVKEY_BYTES)
 * @param [in]  params  Optional key generation parameters, or NULL for
 *                      fresh-random key generation
 *
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a pk or \a sk pointer
 * @retval IMB_ERR_PQC_KEYOP key generation operation failed
 */
IMB_DLL_EXPORT int
imb_ml_dsa_keypair(IMB_ML_DSA *self, uint8_t *pk, uint8_t *sk,
                   const IMB_ML_DSA_KEYGEN_PARAMS *params);

/**
 * @brief Bind an encoded ML-DSA private key to the context, replacing any
 *        previously bound key. The key is decoded and fully validated (its public
 *        component is re-derived and the embedded consistency hash checked) once
 *        here; every subsequent sign/verify call on \a self reuses the cached,
 *        decoded key instead of repeating that work. The bound key carries both
 *        private and public components, so it may also be used with the verify
 *        functions.
 *
 * @param [in] self  ML-DSA context
 * @param [in] sk    Encoded private key (variant PRIVKEY_BYTES)
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a sk pointer
 * @retval IMB_ERR_PQC_KEYOP key decode/validation failed
 */
IMB_DLL_EXPORT int
imb_ml_dsa_set_privkey(IMB_ML_DSA *self, const uint8_t *sk);

/**
 * @brief Bind an encoded ML-DSA public key to the context, replacing any
 *        previously bound key. The key is decoded once here; every subsequent
 *        verify call on \a self reuses the cached, decoded key instead of
 *        repeating that work. The bound key only carries the public component and
 *        so may only be used with the verify functions.
 *
 * @param [in] self  ML-DSA context
 * @param [in] pk    Encoded public key (variant PUBKEY_BYTES)
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a pk pointer
 * @retval IMB_ERR_PQC_KEYOP key decode failed
 */
IMB_DLL_EXPORT int
imb_ml_dsa_set_pubkey(IMB_ML_DSA *self, const uint8_t *pk);

/**
 * Optional parameters for imb_ml_dsa_sign(). A NULL \a params pointer is
 * equivalent to a zero-initialized structure: no context string, hedged
 * (fresh-random) signing - the common-case default.
 */
typedef struct IMB_ML_DSA_SIGN_PARAMS {
        /**
         * Optional context string (FIPS 204 ctx) for domain separation.
         * NULL together with ctx_len = 0 means no context string.
         */
        const uint8_t *ctx;
        /** Context string length in bytes (0..255) */
        size_t ctx_len;
        /**
         * Optional 32-byte randomizer.
         * NULL requests hedged signing: the library generates a fresh
         * random value internally for each call.
         * Non-NULL uses the supplied 32 bytes verbatim - an all-zero
         * buffer yields deterministic signing, any other value supplies
         * caller-controlled entropy.
         */
        const uint8_t *rnd_32;
        /**
         * If non-zero, \a msg is a pre-computed \mu value (exactly 64 bytes)
         * and the SHAKE hashing step H(tr || M') is skipped entirely.
         * \a ctx and \a ctx_len are ignored when this flag is set.
         */
        int msg_is_mu;
} IMB_ML_DSA_SIGN_PARAMS;

/**
 * Optional parameters for imb_ml_dsa_verify(). A NULL \a params pointer is
 * equivalent to a zero-initialized structure: no context string.
 */
typedef struct IMB_ML_DSA_VERIFY_PARAMS {
        /**
         * Optional context string (FIPS 204 ctx) for domain separation.
         * NULL together with ctx_len = 0 means no context string.
         */
        const uint8_t *ctx;
        /** Context string length in bytes (0..255) */
        size_t ctx_len;
        /**
         * If non-zero, \a msg is a pre-computed \mu value (exactly 64 bytes)
         * and the SHAKE hashing step H(tr || M') is skipped entirely.
         * \a ctx and \a ctx_len are ignored when this flag is set.
         */
        int msg_is_mu;
} IMB_ML_DSA_VERIFY_PARAMS;

/**
 * @brief Sign a message. Requires a private key to have been bound to \a self via
 *        imb_ml_dsa_keypair() or imb_ml_dsa_set_privkey().
 *
 * @param [in]  self     ML-DSA context with a bound private key
 * @param [out] sig      Signature buffer (variant SIG_BYTES)
 * @param [out] sig_len  Produced signature length in bytes
 * @param [in]  msg      Message buffer
 * @param [in]  msg_len  Message length in bytes
 * @param [in]  params   Optional signing parameters, or NULL for hedged
 *                       signing with no context string
 *
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_DST invalid \a sig or \a sig_len pointer
 * @retval IMB_ERR_NULL_SRC invalid \a msg pointer, invalid
 *         \a params->ctx pointer, or \a params->msg_is_mu is set but
 *         \a msg_len is not 64
 * @retval IMB_ERR_PQC_NO_KEY no private key bound to \a self
 * @retval IMB_ERR_PQC_SIGNOP signing operation failed
 */
IMB_DLL_EXPORT int
imb_ml_dsa_sign(IMB_ML_DSA *self, uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len,
                const IMB_ML_DSA_SIGN_PARAMS *params);

/**
 * @brief Verify a signature over a message. Requires a public key to have been
 *        bound to \a self via imb_ml_dsa_keypair(),
 *        imb_ml_dsa_set_privkey() (private keys carry the public component too) or
 *        imb_ml_dsa_set_pubkey().
 *
 * @param [in] self     ML-DSA context with a bound public key
 * @param [in] msg      Message buffer
 * @param [in] msg_len  Message length in bytes
 * @param [in] sig      Signature buffer
 * @param [in] sig_len  Signature length in bytes
 * @param [in] params   Optional verification parameters, or NULL for no
 *                      context string
 *
 * @return Operation status
 * @retval 0 the signature is valid
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_SRC invalid \a sig, \a msg, \a params->ctx pointer,
 *         or \a params->msg_is_mu is set but \a msg_len is not 64
 * @retval IMB_ERR_PQC_NO_KEY no public key bound to \a self
 * @retval IMB_ERR_PQC_SIGNOP the signature is invalid, or verification
 *         could not be performed
 */
IMB_DLL_EXPORT int
imb_ml_dsa_verify(IMB_ML_DSA *self, const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                  size_t sig_len, const IMB_ML_DSA_VERIFY_PARAMS *params);

/**
 * @brief Validate an encoded ML-DSA public key.
 *
 * @param [in] self  ML-DSA context
 * @param [in] pk    Encoded public key (variant PUBKEY_BYTES)
 * @return Operation status
 * @retval 0 the key is valid
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a pk pointer
 * @retval IMB_ERR_PQC_KEYOP the key is invalid
 */
IMB_DLL_EXPORT int
imb_ml_dsa_pubkey_validate(IMB_ML_DSA *self, const uint8_t *pk);

/**
 * @brief Validate an encoded ML-DSA private key (decodes and checks consistency).
 *
 * @param [in] self  ML-DSA context
 * @param [in] sk    Encoded private key (variant PRIVKEY_BYTES)
 * @return Operation status
 * @retval 0 the key is valid
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a sk pointer
 * @retval IMB_ERR_PQC_KEYOP the key is invalid
 */
IMB_DLL_EXPORT int
imb_ml_dsa_privkey_validate(IMB_ML_DSA *self, const uint8_t *sk);

/**
 * @brief Derive an encoded public key from an encoded private key.
 *
 * @param [in]  self  ML-DSA context
 * @param [in]  sk    Encoded private key (variant PRIVKEY_BYTES)
 * @param [out] pk    Encoded public key buffer (variant PUBKEY_BYTES)
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a sk pointer
 * @retval IMB_ERR_NULL_DST invalid \a pk pointer
 * @retval IMB_ERR_PQC_KEYOP derivation failed
 */
IMB_DLL_EXPORT int
imb_ml_dsa_pubkey_from_privkey(IMB_ML_DSA *self, const uint8_t *sk, uint8_t *pk);

/*
 * =========================================================
 * =========================================================
 * ML-KEM (FIPS 203) - Module-Lattice-Based Key-Encapsulation Mechanism
 * =========================================================
 * =========================================================
 */

/**
 * Opaque ML-KEM context handle. Created with imb_ml_kem_new() and released
 * with imb_ml_kem_free(). Bound to a single parameter set for its lifetime.
 *
 * The context also caches at most one decoded/generated key at a time (see
 * imb_ml_kem_keypair(), imb_ml_kem_set_privkey() and imb_ml_kem_set_pubkey()),
 * which every subsequent encapsulate/decapsulate call reuses. This mirrors
 * the key-lifecycle model used by an OpenSSL provider: decode/import a key
 * once, then perform many KEM operations against it. Binding a new key to a
 * context replaces the previously bound one. A context is not safe for
 * concurrent use by multiple threads; independent threads should use their
 * own IMB_ML_KEM context (they may share the same key material by calling
 * imb_ml_kem_set_privkey()/imb_ml_kem_set_pubkey() with the same encoded
 * bytes on each context).
 */
struct IMB_ML_KEM;
typedef struct IMB_ML_KEM IMB_ML_KEM;

/**
 * ML-KEM parameter set selector (FIPS 203).
 */
typedef enum { IMB_ML_KEM_512 = 1, IMB_ML_KEM_768 = 2, IMB_ML_KEM_1024 = 3 } IMB_ML_KEM_ALG;

/**
 * Encoded encapsulation (public) key, decapsulation (private) key and
 * ciphertext sizes in bytes, and the fixed shared-secret size. See FIPS 203
 * Section 8, Table 2.
 */
#define IMB_ML_KEM_512_PUBKEY_BYTES     800
#define IMB_ML_KEM_512_PRIVKEY_BYTES    1632
#define IMB_ML_KEM_512_CIPHERTEXT_BYTES 768

#define IMB_ML_KEM_768_PUBKEY_BYTES     1184
#define IMB_ML_KEM_768_PRIVKEY_BYTES    2400
#define IMB_ML_KEM_768_CIPHERTEXT_BYTES 1088

#define IMB_ML_KEM_1024_PUBKEY_BYTES     1568
#define IMB_ML_KEM_1024_PRIVKEY_BYTES    3168
#define IMB_ML_KEM_1024_CIPHERTEXT_BYTES 1568

/* Shared secret size in bytes: fixed across all ML-KEM parameter sets */
#define IMB_ML_KEM_SHARED_SECRET_BYTES 32

/**
 * @brief Allocate and initialize an ML-KEM context for a parameter set.
 *
 * @param [in]  mgr      Pointer to initialized IMB_MGR structure
 * @param [in]  alg      ML-KEM parameter set (IMB_ML_KEM_512/768/1024)
 * @param [out] new_self Receives the new IMB_ML_KEM context on success, or
 *                       NULL on failure
 *
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_MBMGR invalid \a mgr pointer
 * @retval IMB_ERR_NULL_CTX invalid \a new_self pointer
 * @retval IMB_ERR_PQC_ALG invalid \a alg
 * @retval IMB_ERR_PQC_INIT context allocation or initialization failed
 */
IMB_DLL_EXPORT int
imb_ml_kem_new(IMB_MGR *mgr, IMB_ML_KEM_ALG alg, IMB_ML_KEM **new_self);

/**
 * @brief Release an ML-KEM context allocated by imb_ml_kem_new(), along with
 *        any key currently bound to it.
 *
 * @param [in] self  ML-KEM context (may be NULL)
 */
IMB_DLL_EXPORT void
imb_ml_kem_free(IMB_ML_KEM *self);

/**
 * Optional parameters for imb_ml_kem_keypair(). A NULL \a params pointer is
 * equivalent to a zero-initialized structure: fresh-random key generation -
 * the common-case default.
 */
typedef struct IMB_ML_KEM_KEYGEN_PARAMS {
        /**
         * Optional 64-byte key generation seed: the FIPS 203 "d" (first 32
         * bytes) concatenated with "z" (last 32 bytes).
         * NULL requests fresh-random key generation: the library generates
         * a fresh random seed internally for each call.
         * Non-NULL uses the supplied 64 bytes verbatim, producing a
         * deterministic key pair.
         */
        const uint8_t *seed_d_z;
} IMB_ML_KEM_KEYGEN_PARAMS;

/**
 * @brief Generate an ML-KEM key pair (FIPS 203 KeyGen) and bind it to \a self,
 *        replacing any previously bound key. The generated key carries both
 *        private and public components, so \a self may be used with both the
 *        encapsulate and decapsulate functions immediately afterwards.
 *
 * @param [in]  self    ML-KEM context
 * @param [out] ek      Encoded encapsulation key buffer (variant PUBKEY_BYTES)
 * @param [out] dk      Encoded decapsulation key buffer (variant
 *                      PRIVKEY_BYTES)
 * @param [in]  params  Optional key generation parameters, or NULL for
 *                      fresh-random key generation
 *
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a ek or \a dk pointer
 * @retval IMB_ERR_PQC_KEYOP key generation operation failed
 */
IMB_DLL_EXPORT int
imb_ml_kem_keypair(IMB_ML_KEM *self, uint8_t *ek, uint8_t *dk,
                   const IMB_ML_KEM_KEYGEN_PARAMS *params);

/**
 * @brief Bind an encoded ML-KEM decapsulation (private) key to the context,
 *        replacing any previously bound key. The key is decoded and fully
 *        validated (its public component is re-derived and the embedded
 *        consistency hash checked - FIPS 203 Section 7.3 decapsulation key check)
 *        once here; every subsequent decapsulate call on \a self reuses the
 *        cached, decoded key instead of repeating that work. The bound key carries
 *        both private and public components, so it may also be used with the
 *        encapsulate functions.
 *
 * @param [in] self  ML-KEM context
 * @param [in] dk    Encoded decapsulation key (variant PRIVKEY_BYTES)
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a dk pointer
 * @retval IMB_ERR_PQC_KEYOP key decode/validation failed
 */
IMB_DLL_EXPORT int
imb_ml_kem_set_privkey(IMB_ML_KEM *self, const uint8_t *dk);

/**
 * @brief Bind an encoded ML-KEM encapsulation (public) key to the context,
 *        replacing any previously bound key. The key is decoded once here (its
 *        encoded length and coefficient ranges are checked - FIPS 203 Section 7.2
 *        encapsulation key check); every subsequent encapsulate call on \a self
 *        reuses the cached, decoded key instead of repeating that work. The bound
 *        key only carries the public component and so may only be used with the
 *        encapsulate functions.
 *
 * @param [in] self  ML-KEM context
 * @param [in] ek    Encoded encapsulation key (variant PUBKEY_BYTES)
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a ek pointer
 * @retval IMB_ERR_PQC_KEYOP key decode failed
 */
IMB_DLL_EXPORT int
imb_ml_kem_set_pubkey(IMB_ML_KEM *self, const uint8_t *ek);

/**
 * Optional parameters for imb_ml_kem_encap(). A NULL \a params pointer is
 * equivalent to a zero-initialized structure: fresh-random encapsulation -
 * the common-case default.
 */
typedef struct IMB_ML_KEM_ENCAP_PARAMS {
        /**
         * Optional 32-byte randomness (FIPS 203 "m").
         * NULL requests fresh-random encapsulation: the library generates a
         * fresh random value internally for each call.
         * Non-NULL uses the supplied 32 bytes verbatim, producing
         * deterministic encapsulation output (e.g. for ACVP conformance
         * testing).
         */
        const uint8_t *m_32;
} IMB_ML_KEM_ENCAP_PARAMS;

/**
 * @brief Encapsulate, producing a ciphertext and shared secret. Requires an
 *        encapsulation key to have been bound to \a self via imb_ml_kem_keypair(),
 *        imb_ml_kem_set_privkey() (private keys carry the public component too) or
 *        imb_ml_kem_set_pubkey().
 *
 * @param [in]  self           ML-KEM context with a bound encapsulation key
 * @param [out] ct             Ciphertext buffer (variant CIPHERTEXT_BYTES)
 * @param [out] shared_secret  Shared secret buffer
 *                             (IMB_ML_KEM_SHARED_SECRET_BYTES)
 * @param [in]  params         Optional encapsulation parameters, or NULL for
 *                             fresh-random encapsulation
 *
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_DST invalid \a ct or \a shared_secret pointer
 * @retval IMB_ERR_PQC_NO_KEY no encapsulation key bound to \a self
 * @retval IMB_ERR_PQC_KEMOP encapsulation operation failed
 */
IMB_DLL_EXPORT int
imb_ml_kem_encap(IMB_ML_KEM *self, uint8_t *ct, uint8_t *shared_secret,
                 const IMB_ML_KEM_ENCAP_PARAMS *params);

/**
 * Reserved opaque decapsulation-parameters type (future use).
 * imb_ml_kem_decap() currently ignores this parameter; pass NULL.
 */
struct IMB_ML_KEM_DECAP_PARAMS;
typedef struct IMB_ML_KEM_DECAP_PARAMS IMB_ML_KEM_DECAP_PARAMS;

/**
 * @brief Decapsulate, recovering the shared secret from a ciphertext.
 *        Requires a decapsulation key to have been bound to \a self via
 *        imb_ml_kem_keypair()
 *        or imb_ml_kem_set_privkey().
 *
 * Per FIPS 203, decapsulation never signals a cryptographic failure for a
 * content-invalid (but correctly sized) ciphertext: the "implicit
 * rejection" mechanism always returns a (pseudorandom, but deterministic per
 * key and ciphertext) shared secret in that case. Only a ciphertext whose
 * length does not match the bound parameter set is rejected as an error
 * (FIPS 203 Section 7.3 mandates this length check on every call).
 *
 * @param [in]  self           ML-KEM context with a bound decapsulation key
 * @param [out] shared_secret  Shared secret buffer
 *                             (IMB_ML_KEM_SHARED_SECRET_BYTES)
 * @param [in]  ct             Ciphertext buffer
 * @param [in]  ct_len         Ciphertext length in bytes (must equal the
 *                             bound parameter set's CIPHERTEXT_BYTES)
 * @param [in]  params         Reserved for future use; pass NULL
 *
 * @return Operation status
 * @retval 0 success
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_DST invalid \a shared_secret pointer
 * @retval IMB_ERR_NULL_SRC invalid \a ct pointer
 * @retval IMB_ERR_PQC_NO_KEY no decapsulation key bound to \a self
 * @retval IMB_ERR_PQC_KEMOP decapsulation failed (e.g. \a ct_len mismatch)
 */
IMB_DLL_EXPORT int
imb_ml_kem_decap(IMB_ML_KEM *self, uint8_t *shared_secret, const uint8_t *ct, size_t ct_len,
                 const IMB_ML_KEM_DECAP_PARAMS *params);

/**
 * @brief Validate an encoded ML-KEM encapsulation (public) key.
 *
 * @param [in] self  ML-KEM context
 * @param [in] ek    Encoded encapsulation key (variant PUBKEY_BYTES)
 * @return Operation status
 * @retval 0 the key is valid
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a ek pointer
 * @retval IMB_ERR_PQC_KEYOP the key is invalid
 */
IMB_DLL_EXPORT int
imb_ml_kem_pubkey_validate(IMB_ML_KEM *self, const uint8_t *ek);

/**
 * @brief Validate an encoded ML-KEM decapsulation (private) key (decodes and
 *        checks consistency).
 *
 * @param [in] self  ML-KEM context
 * @param [in] dk    Encoded decapsulation key (variant PRIVKEY_BYTES)
 * @return Operation status
 * @retval 0 the key is valid
 * @retval IMB_ERR_NULL_CTX invalid \a self pointer
 * @retval IMB_ERR_NULL_KEY invalid \a dk pointer
 * @retval IMB_ERR_PQC_KEYOP the key is invalid
 */
IMB_DLL_EXPORT int
imb_ml_kem_privkey_validate(IMB_ML_KEM *self, const uint8_t *dk);

/*
 * =========================================================
 * =========================================================
 * MD5
 * =========================================================
 */

/**
 * Authenticate 64-byte data buffer with MD5.
 *
 * @param [in] src    64-byte data buffer
 * @param [out] digest   Digest output (16 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_md5_one_block(const void *src, void *digest, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * AES-CFB
 * =========================================================
 */

/**
 * @brief AES-CFB-128 Encrypt/Decrypt up to one block.
 *
 * Processes only one buffer at a time.
 * Designed to manage partial blocks of DOCSIS 3.1 SEC BPI.
 *
 * @param [out] dst    Plain/cipher text output
 * @param [in] src     Plain/cipher text input
 * @param [in] iv      Pointer to 16 byte IV
 * @param [in] exp_key Pointer to expanded AES keys
 * @param [in] len     Length of data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_cfb_one(void *dst, const void *src, const void *iv, const void *exp_key, uint64_t len,
                   IMB_MGR *state);

/**
 * @brief AES-CFB-256 Encrypt/Decrypt up to one block.
 *
 * Processes only one buffer at a time.
 * Designed to manage partial blocks of DOCSIS 3.1 SEC BPI.
 *
 * @param [out] dst    Plain/cipher text output
 * @param [in] src     Plain/cipher text input
 * @param [in] iv      Pointer to 16 byte IV
 * @param [in] exp_key Pointer to expanded AES keys
 * @param [in] len     Length of data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_cfb_one(void *dst, const void *src, const void *iv, const void *exp_key, uint64_t len,
                   IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * CHACHA20-POLY1305
 * =========================================================
 */

/**
 * @brief Initialize a chacha20_poly1305_context_data structure to prepare for
 *        ChaCha20-Poly1305 Encryption or Decryption.
 *
 * @param [in] key          Pointer to 256-bit key
 * @param [in,out] ctx      ChaCha20-Poly1305 operation context data
 * @param [in] iv           Pointer to 12 byte IV
 * @param [in] aad          Additional Authenticated Data (AAD)
 * @param [in] aadl         Length of AAD in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_chacha20_poly1305_init(const void *key, struct chacha20_poly1305_context_data *ctx,
                           const void *iv, const void *aad, const uint64_t aadl, IMB_MGR *state);

/**
 * @brief Encrypt and authenticate data for ChaCha20-Poly1305.
 *
 * @param [in] key          Pointer to 256-bit key
 * @param [in,out] ctx      ChaCha20-Poly1305 operation context data
 * @param [out] dst         Ciphertext output. Encrypt in-place is allowed
 * @param [in] src          Plaintext input
 * @param [in] len          Length of data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_chacha20_poly1305_enc_update(const void *key, struct chacha20_poly1305_context_data *ctx,
                                 void *dst, const void *src, const uint64_t len, IMB_MGR *state);

/**
 * @brief Decrypt and authenticate data for ChaCha20-Poly1305.
 *
 * @param [in] key          Pointer to 256-bit key
 * @param [in,out] ctx      ChaCha20-Poly1305 operation context data
 * @param [out] dst         Plaintext output. Decrypt in-place is allowed
 * @param [in] src          Ciphertext input
 * @param [in] len          Length of data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_chacha20_poly1305_dec_update(const void *key, struct chacha20_poly1305_context_data *ctx,
                                 void *dst, const void *src, const uint64_t len, IMB_MGR *state);

/**
 * @brief Finalize ChaCha20-Poly1305 Encryption and output the authentication tag.
 *
 * @param [in,out] ctx      ChaCha20-Poly1305 operation context data
 * @param [out] tag         Authenticated Tag output
 * @param [in] tagl         Authenticated Tag Length in bytes (must be 16)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_chacha20_poly1305_enc_finalize(struct chacha20_poly1305_context_data *ctx, void *tag,
                                   const uint64_t tagl, IMB_MGR *state);

/**
 * @brief Finalize ChaCha20-Poly1305 Decryption and output the authentication tag.
 *
 * @param [in,out] ctx      ChaCha20-Poly1305 operation context data
 * @param [out] tag         Authenticated Tag output
 * @param [in] tagl         Authenticated Tag Length in bytes (must be 16)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_chacha20_poly1305_dec_finalize(struct chacha20_poly1305_context_data *ctx, void *tag,
                                   const uint64_t tagl, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * Hybrid Error Coding (HEC)
 * =========================================================
 */

/**
 * HEC (hybrid error coding) compute and header update for 32-bit XGEM header
 *
 * @param [in] src           Pointer to XGEM header (4 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return 32-bit XGEM header with updated HEC in BE format (ready for store)
 */
IMB_DLL_EXPORT uint32_t
imb_hec_32(const uint8_t *src, IMB_MGR *state);

/**
 * HEC (hybrid error coding) compute and header update for 64-bit XGEM header
 *
 * @param [in] src           Pointer to XGEM header (8 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 *
 * @return 64-bit XGEM header with updated HEC in BE format (ready for store)
 */
IMB_DLL_EXPORT uint64_t
imb_hec_64(const uint8_t *src, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * Cyclic Redundancy Check (CRC)
 * =========================================================
 */

/**
 * CRC32 Ethernet FCS function
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc32_ethernet_fcs(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  CRC16 X25 function
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc16_x25(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  CRC32 SCTP function
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc32_sctp(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  LTE CRC24A function
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc24_lte_a(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  LTE CRC24B function
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc24_lte_b(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  Framing Protocol CRC16 function (3GPP TS 25.435, 3GPP TS 25.427)
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc16_fp_data(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  Framing Protocol CRC11 function (3GPP TS 25.435, 3GPP TS 25.427)
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc11_fp_header(const void *src, const uint64_t len, IMB_MGR *state);

/**
 * Framing Protocol CRC7 function (3GPP TS 25.435, 3GPP TS 25.427)
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc7_fp_header(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  IUUP CRC10 function (3GPP TS 25.415)
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc10_iuup_data(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  IUUP CRC6 function (3GPP TS 25.415)
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc6_iuup_header(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  WIMAX OFDMA DATA CRC32 function (IEEE 802.16)
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc32_wimax_ofdma_data(const void *src, const uint64_t len, IMB_MGR *state);

/**
 *  WIMAX OFDMA HCS CRC8 function (IEEE 802.16)
 *
 * @param [in] src  Pointer to source data
 * @param [in] len  Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT uint32_t
imb_crc8_wimax_ofdma_hcs(const void *src, const uint64_t len, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * SM4
 * =========================================================
 */

/**
 * SM4 key expansion
 *
 * @param [in] key           Input key (16 bytes)
 * @param [out] exp_enc_key  Encrypt direction key schedule (128 bytes)
 * @param [out] exp_dec_key  Decrypt direction key schedule (128 bytes)
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_sm4_keyexp(const void *key, void *exp_enc_key, void *exp_dec_key, IMB_MGR *state);

/**
 * SM4-GCM precompute
 *
 * @param [in] mb_mgr           Pointer to initialized IMB_MGR structure
 * @param [in] key              Input SM4 key (16 bytes)
 * @param [out] key_data        GCM expanded key data
 */
IMB_DLL_EXPORT void
imb_sm4_gcm_pre(IMB_MGR *mb_mgr, const void *key, struct gcm_key_data *key_data);

/*
 * =========================================================
 * =========================================================
 * DES
 * =========================================================
 */

/**
 * Generate DES key schedule
 *
 * @param [out] ks    DES key schedule
 * @param [in] key         input key
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_des_keysched(uint64_t *ks, const void *key, IMB_MGR *state);

/**
 * @brief DES key schedule set up.
 *
 * \a ks buffer needs to accommodate \a DES_KEY_SCHED_SIZE (128) bytes of data.
 *
 * @param [out] ks Destination buffer to accommodate DES key schedule
 * @param [in] key Pointer to an 8 byte DES key
 *
 * @return Operation status
 * @retval 0 success
 * @retval !0 error
 */
IMB_DLL_EXPORT int
des_key_schedule(uint64_t *ks, const void *key);

/**
 * @brief DES-CFB Encrypt/Decrypt up to one block.
 *
 * Processes only one buffer at a time.
 * Designed to manage partial blocks of DOCSIS 3.1 SEC BPI.
 *
 * @param [out] out Plain/cipher text output
 * @param [in] in   Plain/cipher text input
 * @param [in] iv   Pointer to 8 byte IV
 * @param [in] ks   Pointer to DES key schedule
 * @param [in] len  Length of data in bytes
 */
IMB_DLL_EXPORT void
des_cfb_one(void *out, const void *in, const uint64_t *iv, const uint64_t *ks, const int len);

/*
 * =========================================================
 * =========================================================
 * HMAC
 * =========================================================
 */

/**
 * @brief Ipad Opad padding for HMAC
 *
 * @param [in] mb_mgr           Pointer to initialized IMB_MGR structure
 * @param [in] sha_type         Type of HMAC_SHA from IMB_HASH_ALG enum
 * @param [in] pkey             Pointer to a HMAC key
 * @param [in] key_len          Length of the HMAC key
 * @param [out] ipad_hash       Block-sized inner padding
 * @param [out] opad_hash       Block-sized outer padding
 */
IMB_DLL_EXPORT void
imb_hmac_ipad_opad(IMB_MGR *mb_mgr, const IMB_HASH_ALG sha_type, const void *pkey,
                   const size_t key_len, void *ipad_hash, void *opad_hash);

/*
 * =========================================================
 * =========================================================
 * AES-GCM
 * Note: GCM is also available through job and burst API's.
 * =========================================================
 */

/**
 * @brief AES-GCM-128 Encryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Cipher text output. Encrypt in-place is allowed
 * @param [in] in               Plain text input
 * @param [in] len              Length of data in bytes for encryption
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authentication Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_enc(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state);
/**
 * @brief AES-GCM-192 Encryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Ciphertext output. Encrypt in-place is allowed
 * @param [in] in               Plain text input
 * @param [in] len              Length of data in bytes for encryption
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authentication Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_enc(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief AES-GCM-256 Encryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Cipher text output. Encrypt in-place is allowed
 * @param [in] in               Plain text input
 * @param [in] len              Length of data in bytes for encryption
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authentication Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_enc(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief AES-GCM-128 Decryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Plain text output. Decrypt in-place is allowed
 * @param [in] in               Cipher text input
 * @param [in] len              Length of data in bytes for decryption
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authentication Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_dec(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief AES-GCM-192 Decryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Plain text output. Decrypt in-place is allowed
 * @param [in] in               Cipher text input
 * @param [in] len              Length of data in bytes for decryption
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authentication Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_dec(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief AES-GCM-256 Decryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Plain text output. Decrypt in-place is allowed
 * @param [in] in               Cipher text input
 * @param [in] len              Length of data in bytes for decryption
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authentication Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_dec(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GCM-128 Encryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authenticated Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                    const void *iv, const void *aad, uint64_t aad_len, IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GCM-192 Encryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authenticated Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                    const void *iv, const void *aad, uint64_t aad_len, IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GCM-256 Encryption.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer to 12 byte IV structure
 *                              Internally, the library concatenates 0x00000001
 *                              to the IV
 * @param [in] aad              Additional Authenticated Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                    const void *iv, const void *aad, uint64_t aad_len, IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GCM-128 Encryption (any IV size).
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer IV structure
 * @param [in] iv_len           Size in bytes of \a iv structure
 * @param [in] aad              Additional Authenticated Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_init_var_iv(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data, const void *iv,
                           const uint64_t iv_len, const void *aad, const uint64_t aad_len,
                           IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GCM-192 Encryption (any IV size).
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer IV structure
 * @param [in] iv_len           Size in bytes of \a iv structure
 * @param [in] aad              Additional Authenticated Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_init_var_iv(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data, const void *iv,
                           const uint64_t iv_len, const void *aad, const uint64_t aad_len,
                           IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GCM-256 Encryption (any IV size).
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer IV structure
 * @param [in] iv_len           Size in bytes of \a iv structure
 * @param [in] aad              Additional Authenticated Data (AAD)
 * @param [in] aad_len          Length of AAD in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_init_var_iv(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data, const void *iv,
                           const uint64_t iv_len, const void *aad, const uint64_t aad_len,
                           IMB_MGR *state);

/**
 * @brief Encrypt a block of a AES-GCM-128 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Cipher text output. Encrypt in-place is allowed
 * @param [in] in               Plain text input
 * @param [in] len              Length of data in bytes for encryption
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_enc_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state);

/**
 * @brief Encrypt a block of a AES-GCM-192 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Cipher text output. Encrypt in-place is allowed
 * @param [in] in               Plain text input
 * @param [in] len              Length of data in bytes for encryption
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_enc_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state);

/**
 * @brief Encrypt a block of a AES-GCM-256 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Cipher text output. Encrypt in-place is allowed
 * @param [in] in               Plain text input
 * @param [in] len              Length of data in bytes for encryption
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_enc_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state);

/**
 * @brief Decrypt a block of a AES-GCM-128 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Plain text output. Decrypt in-place is allowed
 * @param [in] in               Cipher text input
 * @param [in] len              Length of data in bytes for decryption
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_dec_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state);

/**
 * @brief Decrypt a block of a AES-GCM-192 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Plain text output. Decrypt in-place is allowed
 * @param [in] in               Cipher text input
 * @param [in] len              Length of data in bytes for decryption
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_dec_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state);

/**
 * @brief Decrypt a block of a AES-GCM-256 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] out             Plain text output. Decrypt in-place is allowed
 * @param [in] in               Cipher text input
 * @param [in] len              Length of data in bytes for decryption
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_dec_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state);

/**
 * @brief End encryption of a AES-GCM-128 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are
 *                              16 (most likely), 12 or 8.
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_enc_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief End encryption of a AES-GCM-192 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are
 *                              16 (most likely), 12 or 8.
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_enc_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief End encryption of a AES-GCM-256 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are
 *                              16 (most likely), 12 or 8.
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_enc_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief End decryption of a AES-GCM-128 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are
 *                              16 (most likely), 12 or 8.
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_dec_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief End decryption of a AES-GCM-192 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are
 *                              16 (most likely), 12 or 8.
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_dec_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief End decryption of a AES-GCM-256 encryption message.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are
 *                              16 (most likely), 12 or 8.
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_dec_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief Precomputation of AES-GCM-128 HashKey constants.
 *
 * Precomputation of HashKey<<1 mod poly constants (shifted_hkey_X and
 * shifted_hkey_X_k).
 *
 * @param [in,out] key_data GCM key data
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_precomp(struct gcm_key_data *key_data, IMB_MGR *state);

/**
 * @brief Precomputation of AES-GCM-192 HashKey constants.
 *
 * Precomputation of HashKey<<1 mod poly constants (shifted_hkey_X and
 * shifted_hkey_X_k).
 *
 * @param [in,out] key_data GCM key data
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_precomp(struct gcm_key_data *key_data, IMB_MGR *state);

/**
 * @brief Precomputation of AES-GCM-256 HashKey constants.
 *
 * Precomputation of HashKey<<1 mod poly constants (shifted_hkey_X and
 * shifted_hkey_X_k).
 *
 * @param [in,out] key_data GCM key data
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_precomp(struct gcm_key_data *key_data, IMB_MGR *state);

/**
 * @brief Pre-processes AES-GCM-128 key data.
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param [in] key       Pointer to key data
 * @param [out] key_data GCM expanded key data
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gcm_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state);

/**
 * @brief Pre-processes AES-GCM-192 key data.
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param [in] key       Pointer to key data
 * @param [out] key_data GCM expanded key data
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gcm_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state);

/**
 * @brief Pre-processes AES-GCM-256 key data.
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param [in] key       Pointer to key data
 * @param [out] key_data GCM expanded key data
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gcm_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * GHASH
 * =========================================================
 */

/**
 * @brief Pre-processes GHASH key data.
 *
 * Prefills the key data with the initial sub hash key for tag encoding
 *
 * @param [in] key       Pointer to key data
 * @param [out] key_data GCM expanded key data
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_ghash_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state);

/**
 * @brief Computes GHASH authentication tag over the supplied data.
 *
 * @param [in] key_data     GCM expanded key data
 * @param [in] src          Pointer to source data
 * @param [in] len          Length of source data in bytes
 * @param [out] auth_tag    Authenticated Tag output
 * @param [in] auth_tag_len Authenticated Tag Length in bytes (must be
 *                          a multiple of 4 bytes). Valid values are 16
 *                          (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_ghash(const struct gcm_key_data *key_data, const void *src, const uint64_t len, void *auth_tag,
          const uint64_t auth_tag_len, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * AES-GMAC
 * Note: GMAC is also available through job and burst API's.
 * =========================================================
 */

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GMAC-128 tag computation.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer to IV structure
 * @param [in] iv_len           Length of IV in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gmac_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                     const void *iv, const uint64_t iv_len, IMB_MGR *state);

/**
 * @brief Process data for AES-GMAC-128 tag computation.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] in               Pointer to source data
 * @param [in] len              Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gmac_update(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                       const void *in, const uint64_t len, IMB_MGR *state);

/**
 * @brief Finalize AES-GMAC-128 tag computation and output the tag.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes128_gmac_finalize(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                         void *auth_tag, const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GMAC-192 tag computation.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer to IV structure
 * @param [in] iv_len           Length of IV in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gmac_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                     const void *iv, const uint64_t iv_len, IMB_MGR *state);

/**
 * @brief Process data for AES-GMAC-192 tag computation.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] in               Pointer to source data
 * @param [in] len              Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gmac_update(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                       const void *in, const uint64_t len, IMB_MGR *state);

/**
 * @brief Finalize AES-GMAC-192 tag computation and output the tag.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes192_gmac_finalize(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                         void *auth_tag, const uint64_t auth_tag_len, IMB_MGR *state);

/**
 * @brief Initialize a gcm_context_data structure to prepare for
 *        AES-GMAC-256 tag computation.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] iv               Pointer to IV structure
 * @param [in] iv_len           Length of IV in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gmac_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                     const void *iv, const uint64_t iv_len, IMB_MGR *state);

/**
 * @brief Process data for AES-GMAC-256 tag computation.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [in] in               Pointer to source data
 * @param [in] len              Length of source data in bytes
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gmac_update(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                       const void *in, const uint64_t len, IMB_MGR *state);

/**
 * @brief Finalize AES-GMAC-256 tag computation and output the tag.
 *
 * @param [in] key_data         GCM expanded key data
 * @param [in,out] context_data GCM operation context data
 * @param [out] auth_tag        Authenticated Tag output
 * @param [in] auth_tag_len     Authenticated Tag Length in bytes (must be
 *                              a multiple of 4 bytes). Valid values are 16
 *                              (most likely), 12 or 8
 * @param [in] state  Pointer to initialized IMB_MGR structure
 */
IMB_DLL_EXPORT void
imb_aes256_gmac_finalize(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                         void *auth_tag, const uint64_t auth_tag_len, IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * ZUC
 * =========================================================
 */

/**
 * @brief Generation of ZUC-EEA3 Initialization Vector.
 *
 * @param [in] count   COUNT (4 bytes in Little Endian)
 * @param [in] bearer  BEARER (5 bits)
 * @param [in] dir     DIRECTION (1 bit)
 * @param [out] iv_ptr Pointer to generated IV (16 bytes)
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 if one or more parameters are invalid
 */
IMB_DLL_EXPORT int
zuc_eea3_iv_gen(const uint32_t count, const uint8_t bearer, const uint8_t dir, void *iv_ptr);

/**
 * @brief Generation of ZUC-EIA3 Initialization Vector.
 *
 * @param [in] count   COUNT (4 bytes in Little Endian)
 * @param [in] bearer  BEARER (5 bits)
 * @param [in] dir     DIRECTION (1 bit)
 * @param [out] iv_ptr Pointer to generated IV (16 bytes)
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 if one or more parameters are invalid
 */
IMB_DLL_EXPORT int
zuc_eia3_iv_gen(const uint32_t count, const uint8_t bearer, const uint8_t dir, void *iv_ptr);

/*
 * =========================================================
 * =========================================================
 * KASUMI
 * =========================================================
 */

/**
 * @brief Generation of KASUMI F8 Initialization Vector.
 *
 * @param [in] count   COUNT (4 bytes in Little Endian)
 * @param [in] bearer  BEARER (5 bits)
 * @param [in] dir     DIRECTION (1 bit)
 * @param [out] iv_ptr Pointer to generated IV (8 bytes)
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 if one or more parameters are invalid
 */
IMB_DLL_EXPORT int
kasumi_f8_iv_gen(const uint32_t count, const uint8_t bearer, const uint8_t dir, void *iv_ptr);

/**
 * @brief Generation of KASUMI F9 Initialization Vector.
 *
 * @param [in] count   COUNT (4 bytes in Little Endian)
 * @param [in] fresh   FRESH (4 bytes in Little Endian)
 * @param [out] iv_ptr Pointer to generated IV (8 bytes)
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 if one or more parameters are invalid
 */
IMB_DLL_EXPORT int
kasumi_f9_iv_gen(const uint32_t count, const uint32_t fresh, void *iv_ptr);

/**
 * KASUMI F8 key schedule init function.
 *
 * @param [in]  key      Confidentiality key (expected in LE format)
 * @param [out] exp_key  Key schedule context to be initialized
 * @param [in] state  Pointer to initialized IMB_MGR structure
 * @return 0 on success, -1 on failure
 */
IMB_DLL_EXPORT int
imb_kasumi_init_f8_key_sched(const void *key, kasumi_key_sched_t *exp_key, IMB_MGR *state);

/**
 * KASUMI F9 key schedule init function.
 *
 * @param [in]  key      Integrity key (expected in LE format)
 * @param [out] exp_key  Key schedule context to be initialized
 * @param [in] state  Pointer to initialized IMB_MGR structure
 * @return 0 on success, -1 on failure
 */
IMB_DLL_EXPORT int
imb_kasumi_init_f9_key_sched(const void *key, kasumi_key_sched_t *exp_key, IMB_MGR *state);

/**
 * This function returns the size of the kasumi_key_sched_t, used
 * to store the key schedule.
 *
 * @param [in] state  Pointer to initialized IMB_MGR structure
 * @return size of kasumi_key_sched_t type success
 */
IMB_DLL_EXPORT size_t
imb_kasumi_key_sched_size(IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * SNOW3G
 * =========================================================
 */

/**
 * @brief Generation of SNOW3G F8 Initialization Vector.
 *
 * Parameters are passed in Little Endian format and
 * used to generate the IV in Big Endian format.
 *
 * @param [in] count   COUNT (4 bytes in Little Endian)
 * @param [in] bearer  BEARER (5 bits)
 * @param [in] dir     DIRECTION (1 bit)
 * @param [out] iv_ptr Pointer to generated IV (16 bytes) in Big Endian format
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 if one or more parameters are invalid
 */
IMB_DLL_EXPORT int
snow3g_f8_iv_gen(const uint32_t count, const uint8_t bearer, const uint8_t dir, void *iv_ptr);

/**
 * @brief Generation of SNOW3G F9 Initialization Vector.
 *
 * Parameters are passed in Little Endian format and
 * used to generate the IV in Big Endian format.
 *
 * @param [in] count   COUNT (4 bytes in Little Endian)
 * @param [in] fresh   FRESH (4 bytes in Little Endian)
 * @param [in] dir     DIRECTION (1 bit)
 * @param [out] iv_ptr Pointer to generated IV (16 bytes) in Big Endian format
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 if one or more parameters are invalid
 */
IMB_DLL_EXPORT int
snow3g_f9_iv_gen(const uint32_t count, const uint32_t fresh, const uint8_t dir, void *iv_ptr);

/**
 * Snow3g key schedule init function.
 *
 * @param [in]  key      Confidentiality/Integrity key (expected in LE format)
 * @param [out] exp_key  Key schedule context to be initialized
 * @param [in] state  Pointer to initialized IMB_MGR structure
 * @return 0 on success
 * @return -1 on error
 */
IMB_DLL_EXPORT int
imb_snow3g_init_key_sched(const void *key, snow3g_key_schedule_t *exp_key, IMB_MGR *state);

/**
 * This function returns the size of the snow3g_key_schedule_t, used
 * to store the key schedule.
 *
 * @param [in] state  Pointer to initialized IMB_MGR structure
 * @return size of snow3g_key_schedule_t type
 */
IMB_DLL_EXPORT size_t
imb_snow3g_key_sched_size(IMB_MGR *state);

/*
 * =========================================================
 * =========================================================
 * QUIC
 * =========================================================
 */

/**
 * @brief Batch of GCM encrypt/decrypt operations with the same key
 *
 * @note IV length of 12 bytes is assumed.
 * @note If used out of place then AAD needs to be copied by the caller.
 * @note For more info on key_data refer to IMB_AES128/192/256_GCM_PRE() API’s
 *
 * @param [in]  state         pointer to IMB_MGR
 * @param [in]  key_data      initialized key data (AES keys and hash keys)
 * @param [in]  key_size      key size (in bytes, see IMB_KEY_128_BYTES etc.)
 * @param [in]  cipher_dir    cipher direction (IMB_DIR_ENCRYPT / DECRYPT)
 * @param [out] dst_ptr_array array with destination pointers
 * @param [in]  src_ptr_array array with source pointers
 * @param [in]  len_array     array with message lengths in bytes
 * @param [in]  iv_ptr_array  array with IV pointers
 * @param [in]  aad_ptr_array array with AAD pointers
 * @param [in]  aad_len       AAD length in bytes
 * @param [out] tag_ptr_array array with authentication TAG pointers
 * @param [in]  tag_len       authentication TAG length in bytes
 * @param [in]  num_packets   number of packets in this batch
 */
IMB_DLL_EXPORT void
imb_quic_aes_gcm(IMB_MGR *state, const struct gcm_key_data *key_data,
                 const IMB_KEY_SIZE_BYTES key_size, const IMB_CIPHER_DIRECTION cipher_dir,
                 void *dst_ptr_array[], const void *const src_ptr_array[],
                 const uint64_t len_array[], const void *const iv_ptr_array[],
                 const void *const aad_ptr_array[], const uint64_t aad_len, void *tag_ptr_array[],
                 const uint64_t tag_len, const uint64_t num_packets);

/**
 * @brief Batch of AES-ECB encrypt/decrypt operations with the same key
 *
 * Sample size is fixed to 16 bytes (read from source pointers).
 * Mask output size is fixed to 5 bytes (written to destination pointer).
 * Cipher direction is fixed to ENCRYPT.
 *
 * @param [in]  state         pointer to IMB_MGR
 * @param [in]  exp_key_data  expanded AES encrypt keys
 * @param [out] dst_ptr_array array with destination pointers
 * @param [in]  src_ptr_array array with source sample pointers
 * @param [in]  num_packets   number of packets in this batch
 * @param [in]  key_size      key size (in bytes, see IMB_KEY_128_BYTES etc.)
 */
IMB_DLL_EXPORT void
imb_quic_hp_aes_ecb(IMB_MGR *state, const void *exp_key_data, void *dst_ptr_array[],
                    const void *const src_ptr_array[], const uint64_t num_packets,
                    const IMB_KEY_SIZE_BYTES key_size);

/**
 * @brief Batch of CHACHA20-POLY1305 encrypt/decrypt operations with the same key
 *
 * @note If used out of place then AAD needs to be copied by the caller.
 *
 * @param [in]  state         pointer to IMB_MGR
 * @param [in]  key           pointer to key
 * @param [in]  cipher_dir    cipher direction (IMB_DIR_ENCRYPT / DECRYPT)
 * @param [out] dst_ptr_array array with destination pointers
 * @param [in]  src_ptr_array array with source pointers
 * @param [in]  len_array     array with message lengths in bytes
 * @param [in]  iv_ptr_array  array with IV pointers
 * @param [in]  aad_ptr_array array with AAD pointers
 * @param [in]  aad_len       AAD length in bytes
 * @param [out] tag_ptr_array array with authentication TAG pointers
 * @param [in]  num_packets   number of packets in this batch
 */
IMB_DLL_EXPORT void
imb_quic_chacha20_poly1305(IMB_MGR *state, const void *key, const IMB_CIPHER_DIRECTION cipher_dir,
                           void *dst_ptr_array[], const void *const src_ptr_array[],
                           const uint64_t len_array[], const void *const iv_ptr_array[],
                           const void *const aad_ptr_array[], const uint64_t aad_len,
                           void *tag_ptr_array[], const uint64_t num_packets);

/**
 * @brief Batch of ChaCha20 encrypt operations with the same key
 *
 * Sample size is fixed to 16 bytes (read from source pointers).
 * Mask output size is fixed to 5 bytes (written to destination pointer).
 * Cipher direction is fixed to ENCRYPT.
 *
 * @param [in]  state         pointer to IMB_MGR
 * @param [in]  key           Cipher key
 * @param [out] dst_ptr_array array with destination pointers
 * @param [in]  src_ptr_array array with source sample pointers
 * @param [in]  num_packets   number of packets in this batch
 */
IMB_DLL_EXPORT void
imb_quic_hp_chacha20(IMB_MGR *state, const void *key, void *dst_ptr_array[],
                     const void *const src_ptr_array[], const uint64_t num_packets);

/**
 * @brief Force clearing/zeroing of memory
 *
 * @param [in] mem   Pointer to memory address to clear
 * @param [in] size  Size of memory to clear (in bytes)
 */
IMB_DLL_EXPORT void
imb_clear_mem(void *mem, const size_t size);

#ifdef __cplusplus
}
#endif

#ifndef NO_IPSECMB_V2_COMPATIBILITY
/*
 * Wrapper macros to secure compatibility between v3 and v2 API.
 */
#define IMB_GET_NEXT_JOB(_mgr)       imb_get_next_job(_mgr)
#define IMB_SUBMIT_JOB(_mgr)         imb_submit_job(_mgr)
#define IMB_SUBMIT_JOB_NOCHECK(_mgr) imb_submit_job_nocheck(_mgr)
#define IMB_GET_COMPLETED_JOB(_mgr)  imb_get_completed_job(_mgr)
#define IMB_FLUSH_JOB(_mgr)          imb_flush_job(_mgr)
#define IMB_QUEUE_SIZE(_mgr)         imb_queue_size(_mgr)

#define IMB_GET_NEXT_BURST(_mgr, _n_jobs, _jobs) imb_get_next_burst(_mgr, _n_jobs, _jobs)
#define IMB_SUBMIT_BURST(_mgr, _n_jobs, _jobs)   imb_submit_burst(_mgr, _n_jobs, _jobs)
#define IMB_SUBMIT_BURST_NOCHECK(_mgr, _n_jobs, _jobs)                                             \
        imb_submit_burst_nocheck(_mgr, _n_jobs, _jobs)
#define IMB_FLUSH_BURST(_mgr, _max_jobs, _jobs) imb_flush_burst(_mgr, _max_jobs, _jobs)

#define IMB_SUBMIT_CIPHER_BURST(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)                    \
        imb_submit_cipher_burst(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)
#define IMB_SUBMIT_CIPHER_BURST_NOCHECK(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)            \
        imb_submit_cipher_burst_nocheck(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)

#define IMB_SUBMIT_HASH_BURST(_mgr, _jobs, _n_jobs, _hash)                                         \
        imb_submit_hash_burst(_mgr, _jobs, _n_jobs, _hash)
#define IMB_SUBMIT_HASH_BURST_NOCHECK(_mgr, _jobs, _n_jobs, _hash)                                 \
        imb_submit_hash_burst_nocheck(_mgr, _jobs, _n_jobs, _hash)

#define IMB_SUBMIT_AEAD_BURST(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)                      \
        imb_submit_aead_burst(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)
#define IMB_SUBMIT_AEAD_BURST_NOCHECK(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)              \
        imb_submit_aead_burst_nocheck(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)

#define IMB_AES_KEYEXP_128(_mgr, _key, _enc_exp_key, _dec_exp_key)                                 \
        imb_aes_keyexp_128(_key, _enc_exp_key, _dec_exp_key, _mgr)
#define IMB_AES_KEYEXP_192(_mgr, _key, _enc_exp_key, _dec_exp_key)                                 \
        imb_aes_keyexp_192(_key, _enc_exp_key, _dec_exp_key, _mgr)
#define IMB_AES_KEYEXP_256(_mgr, _key, _enc_exp_key, _dec_exp_key)                                 \
        imb_aes_keyexp_256(_key, _enc_exp_key, _dec_exp_key, _mgr)

#define IMB_AES_CMAC_SUBKEY_GEN_128(_mgr, _exp_key, _key1, _key2)                                  \
        imb_aes_cmac_subkey_gen_128(_exp_key, _key1, _key2, _mgr)
#define IMB_AES_CMAC_SUBKEY_GEN_256(_mgr, _exp_key, _key1, _key2)                                  \
        imb_aes_cmac_subkey_gen_256(_exp_key, _key1, _key2, _mgr)

#define IMB_AES_XCBC_KEYEXP(_mgr, _key, _exp_key, _exp_key2, _exp_key3)                            \
        imb_aes_xcbc_keyexp(_key, _exp_key, _exp_key2, _exp_key3, _mgr)
#define IMB_DES_KEYSCHED(_mgr, _exp_key, _key) imb_des_keysched(_exp_key, _key, _mgr)

#define IMB_SHA1_ONE_BLOCK(_mgr, _src, _tag) imb_sha1_one_block(_src, _tag, _mgr)
#define IMB_SHA1(_mgr, _src, _length, _tag)  imb_sha1(_src, _length, _tag, _mgr)

#define IMB_SHA224_ONE_BLOCK(_mgr, _src, _tag) imb_sha224_one_block(_src, _tag, _mgr)
#define IMB_SHA224(_mgr, _src, _length, _tag)  imb_sha224(_src, _length, _tag, _mgr)

#define IMB_SHA256_ONE_BLOCK(_mgr, _src, _tag) imb_sha256_one_block(_src, _tag, _mgr)
#define IMB_SHA256(_mgr, _src, _length, _tag)  imb_sha256(_src, _length, _tag, _mgr)

#define IMB_SHA384_ONE_BLOCK(_mgr, _src, _tag) imb_sha384_one_block(_src, _tag, _mgr)
#define IMB_SHA384(_mgr, _src, _length, _tag)  imb_sha384(_src, _length, _tag, _mgr)

#define IMB_SHA512_ONE_BLOCK(_mgr, _src, _tag) imb_sha512_one_block(_src, _tag, _mgr)
#define IMB_SHA512(_mgr, _src, _length, _tag)  imb_sha512(_src, _length, _tag, _mgr)

#define IMB_MD5_ONE_BLOCK(_mgr, _src, _tag) imb_md5_one_block(_src, _tag, _mgr)

#define IMB_AES128_CFB_ONE(_mgr, _dst, _src, _iv, _exp_key, _len)                                  \
        imb_aes128_cfb_one(_dst, _src, _iv, _exp_key, _len, _mgr)
#define IMB_AES256_CFB_ONE(_mgr, _dst, _src, _iv, _exp_key, _len)                                  \
        imb_aes256_cfb_one(_dst, _src, _iv, _exp_key, _len, _mgr)

#define IMB_AES128_GCM_ENC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl)  \
        imb_aes128_gcm_enc(_exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl, _mgr)
#define IMB_AES192_GCM_ENC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl)  \
        imb_aes192_gcm_enc(_exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl, _mgr)
#define IMB_AES256_GCM_ENC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl)  \
        imb_aes256_gcm_enc(_exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl, _mgr)

#define IMB_AES128_GCM_DEC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl)  \
        imb_aes128_gcm_dec(_exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl, _mgr)
#define IMB_AES192_GCM_DEC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl)  \
        imb_aes192_gcm_dec(_exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl, _mgr)
#define IMB_AES256_GCM_DEC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl)  \
        imb_aes256_gcm_dec(_exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl, _mgr)

#define IMB_AES128_GCM_INIT(_mgr, _exp_key, _ctx, _iv, _aad, _aadl)                                \
        imb_aes128_gcm_init(_exp_key, _ctx, _iv, _aad, _aadl, _mgr)
#define IMB_AES192_GCM_INIT(_mgr, _exp_key, _ctx, _iv, _aad, _aadl)                                \
        imb_aes192_gcm_init(_exp_key, _ctx, _iv, _aad, _aadl, _mgr)
#define IMB_AES256_GCM_INIT(_mgr, _exp_key, _ctx, _iv, _aad, _aadl)                                \
        imb_aes256_gcm_init(_exp_key, _ctx, _iv, _aad, _aadl, _mgr)

#define IMB_AES128_GCM_INIT_VAR_IV(_mgr, _exp_key, _ctx, _iv, _ivl, _aad, _aadl)                   \
        imb_aes128_gcm_init_var_iv(_exp_key, _ctx, _iv, _ivl, _aad, _aadl, _mgr)
#define IMB_AES192_GCM_INIT_VAR_IV(_mgr, _exp_key, _ctx, _iv, _ivl, _aad, _aadl)                   \
        imb_aes192_gcm_init_var_iv(_exp_key, _ctx, _iv, _ivl, _aad, _aadl, _mgr)
#define IMB_AES256_GCM_INIT_VAR_IV(_mgr, _exp_key, _ctx, _iv, _ivl, _aad, _aadl)                   \
        imb_aes256_gcm_init_var_iv(_exp_key, _ctx, _iv, _ivl, _aad, _aadl, _mgr)

#define IMB_AES128_GCM_ENC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                          \
        imb_aes128_gcm_enc_update(_exp_key, _ctx, _dst, _src, _len, _mgr)
#define IMB_AES192_GCM_ENC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                          \
        imb_aes192_gcm_enc_update(_exp_key, _ctx, _dst, _src, _len, _mgr)
#define IMB_AES256_GCM_ENC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                          \
        imb_aes256_gcm_enc_update(_exp_key, _ctx, _dst, _src, _len, _mgr)

#define IMB_AES128_GCM_DEC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                          \
        imb_aes128_gcm_dec_update(_exp_key, _ctx, _dst, _src, _len, _mgr)
#define IMB_AES192_GCM_DEC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                          \
        imb_aes192_gcm_dec_update(_exp_key, _ctx, _dst, _src, _len, _mgr)
#define IMB_AES256_GCM_DEC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                          \
        imb_aes256_gcm_dec_update(_exp_key, _ctx, _dst, _src, _len, _mgr)

#define IMB_AES128_GCM_ENC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                             \
        imb_aes128_gcm_enc_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)
#define IMB_AES192_GCM_ENC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                             \
        imb_aes192_gcm_enc_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)
#define IMB_AES256_GCM_ENC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                             \
        imb_aes256_gcm_enc_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)

#define IMB_AES128_GCM_DEC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                             \
        imb_aes128_gcm_dec_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)
#define IMB_AES192_GCM_DEC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                             \
        imb_aes192_gcm_dec_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)
#define IMB_AES256_GCM_DEC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                             \
        imb_aes256_gcm_dec_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)

#define IMB_AES128_GMAC_INIT(_mgr, _exp_key, _ctx, _iv, _ivl)                                      \
        imb_aes128_gmac_init(_exp_key, _ctx, _iv, _ivl, _mgr)
#define IMB_AES192_GMAC_INIT(_mgr, _exp_key, _ctx, _iv, _ivl)                                      \
        imb_aes192_gmac_init(_exp_key, _ctx, _iv, _ivl, _mgr)
#define IMB_AES256_GMAC_INIT(_mgr, _exp_key, _ctx, _iv, _ivl)                                      \
        imb_aes256_gmac_init(_exp_key, _ctx, _iv, _ivl, _mgr)

#define IMB_AES128_GMAC_UPDATE(_mgr, _exp_key, _ctx, _src, _len)                                   \
        imb_aes128_gmac_update(_exp_key, _ctx, _src, _len, _mgr)
#define IMB_AES192_GMAC_UPDATE(_mgr, _exp_key, _ctx, _src, _len)                                   \
        imb_aes192_gmac_update(_exp_key, _ctx, _src, _len, _mgr)
#define IMB_AES256_GMAC_UPDATE(_mgr, _exp_key, _ctx, _src, _len)                                   \
        imb_aes256_gmac_update(_exp_key, _ctx, _src, _len, _mgr)

#define IMB_AES128_GMAC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                                \
        imb_aes128_gmac_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)
#define IMB_AES192_GMAC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                                \
        imb_aes192_gmac_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)
#define IMB_AES256_GMAC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                                \
        imb_aes256_gmac_finalize(_exp_key, _ctx, _tag, _tagl, _mgr)

#define IMB_AES128_GCM_PRECOMP(_mgr, _key) imb_aes128_gcm_precomp(_key, _mgr)
#define IMB_AES192_GCM_PRECOMP(_mgr, _key) imb_aes192_gcm_precomp(_key, _mgr)
#define IMB_AES256_GCM_PRECOMP(_mgr, _key) imb_aes256_gcm_precomp(_key, _mgr)

#define IMB_AES128_GCM_PRE(_mgr, _key, _exp_key) imb_aes128_gcm_pre(_key, _exp_key, _mgr)
#define IMB_AES192_GCM_PRE(_mgr, _key, _exp_key) imb_aes192_gcm_pre(_key, _exp_key, _mgr)
#define IMB_AES256_GCM_PRE(_mgr, _key, _exp_key) imb_aes256_gcm_pre(_key, _exp_key, _mgr)

#define IMB_GHASH_PRE(_mgr, _key, _exp_key) imb_ghash_pre(_key, _exp_key, _mgr)
#define IMB_GHASH(_mgr, _exp_key, _src, _len, _tag, _tagl)                                         \
        imb_ghash(_exp_key, _src, _len, _tag, _tagl, _mgr)

#define IMB_CHACHA20_POLY1305_INIT(_mgr, _key, _ctx, _iv, _aad, _aadl)                             \
        imb_chacha20_poly1305_init(_key, _ctx, _iv, _aad, _aadl, _mgr)

#define IMB_CHACHA20_POLY1305_ENC_UPDATE(_mgr, _key, _ctx, _dst, _src, _len)                       \
        imb_chacha20_poly1305_enc_update(_key, _ctx, _dst, _src, _len, _mgr)
#define IMB_CHACHA20_POLY1305_DEC_UPDATE(_mgr, _key, _ctx, _dst, _src, _len)                       \
        imb_chacha20_poly1305_dec_update(_key, _ctx, _dst, _src, _len, _mgr)

#define IMB_CHACHA20_POLY1305_ENC_FINALIZE(_mgr, _ctx, _tag, _tagl)                                \
        imb_chacha20_poly1305_enc_finalize(_ctx, _tag, _tagl, _mgr)

#define IMB_CHACHA20_POLY1305_DEC_FINALIZE(_mgr, _ctx, _tag, _tagl)                                \
        imb_chacha20_poly1305_dec_finalize(_ctx, _tag, _tagl, _mgr)

#define IMB_KASUMI_INIT_F8_KEY_SCHED(_mgr, _key, _exp_key)                                         \
        imb_kasumi_init_f8_key_sched(_key, _exp_key, _mgr)
#define IMB_KASUMI_INIT_F9_KEY_SCHED(_mgr, _key, _exp_key)                                         \
        imb_kasumi_init_f9_key_sched(_key, _exp_key, _mgr)
#define IMB_KASUMI_KEY_SCHED_SIZE(_mgr) imb_kasumi_key_sched_size(_mgr)

#define IMB_SNOW3G_INIT_KEY_SCHED(_mgr, _key, _exp_key)                                            \
        imb_snow3g_init_key_sched(_key, _exp_key, _mgr)
#define IMB_SNOW3G_KEY_SCHED_SIZE(_mgr) imb_snow3g_key_sched_size(_mgr)

#define IMB_HEC_32(_mgr, _src) imb_hec_32(_src, _mgr)
#define IMB_HEC_64(_mgr, _src) imb_hec_64(_src, _mgr)

#define IMB_CRC32_ETHERNET_FCS(_mgr, _src, _len)     imb_crc32_ethernet_fcs(_src, _len, _mgr)
#define IMB_CRC16_X25(_mgr, _src, _len)              imb_crc16_x25(_src, _len, _mgr)
#define IMB_CRC32_SCTP(_mgr, _src, _len)             imb_crc32_sctp(_src, _len, _mgr)
#define IMB_CRC24_LTE_A(_mgr, _src, _len)            imb_crc24_lte_a(_src, _len, _mgr)
#define IMB_CRC24_LTE_B(_mgr, _src, _len)            imb_crc24_lte_b(_src, _len, _mgr)
#define IMB_CRC16_FP_DATA(_mgr, _src, _len)          imb_crc16_fp_data(_src, _len, _mgr)
#define IMB_CRC11_FP_HEADER(_mgr, _src, _len)        imb_crc11_fp_header(_src, _len, _mgr)
#define IMB_CRC7_FP_HEADER(_mgr, _src, _len)         imb_crc7_fp_header(_src, _len, _mgr)
#define IMB_CRC10_IUUP_DATA(_mgr, _src, _len)        imb_crc10_iuup_data(_src, _len, _mgr)
#define IMB_CRC6_IUUP_HEADER(_mgr, _src, _len)       imb_crc6_iuup_header(_src, _len, _mgr)
#define IMB_CRC32_WIMAX_OFDMA_DATA(_mgr, _src, _len) imb_crc32_wimax_ofdma_data(_src, _len, _mgr)
#define IMB_CRC8_WIMAX_OFDMA_HCS(_mgr, _src, _len)   imb_crc8_wimax_ofdma_hcs(_src, _len, _mgr)

#define IMB_SM4_KEYEXP(_mgr, _key, _exp_enc_key, _exp_dec_key)                                     \
        imb_sm4_keyexp(_key, _exp_enc_key, _exp_dec_key, _mgr)

#endif /* NO_IPSECMB_V2_COMPATIBILITY */

#endif /* IMB_IPSEC_MB_H */
