/**********************************************************************
  Copyright(c) 2019-2024, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#ifdef LINUX
#include <stdlib.h> /* posix_memalign() and free() */
#else
#include <malloc.h> /* _aligned_malloc() and aligned_free() */
#endif
#include "misc.h"
#include "utils.h"
#ifdef PIN_BASED_CEC
#include <pin_based_cec.h>
#endif

#ifdef _WIN32
#include <intrin.h>
#define strdup     _strdup
#define BSWAP64    _byteswap_uint64
#define __func__   __FUNCTION__
#define strcasecmp _stricmp
#else
#include <x86intrin.h>
#define BSWAP64 __builtin_bswap64
#endif

#include <intel-ipsec-mb.h>

/* maximum size of a test buffer */
#define JOB_SIZE_TOP (16 * 1024)
/* min size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MIN 16
/* max size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MAX (2 * 1024)
/* number of bytes to increase buffer size when testing range of buffers */
#define DEFAULT_JOB_SIZE_STEP 16

#define DEFAULT_JOB_ITER 10

#define MAX_GCM_AAD_SIZE 1024
#define MAX_CCM_AAD_SIZE 46
#define MAX_AAD_SIZE     1024
#define NUM_TAG_SIZES    7

#define MAX_IV_SIZE  25 /* IV size for ZUC-256 */
#define MAX_TAG_SIZE 16 /* Max tag size for ZUC-256 */

#define MAX_NUM_JOBS 32
#define IMIX_ITER    1000

/* Maximum key and digest size for SHA-512 */
#define MAX_KEY_SIZE    IMB_SHA_512_BLOCK_SIZE
#define MAX_DIGEST_SIZE IMB_SHA512_DIGEST_SIZE_IN_BYTES

#define SEED        0xdeadcafe
#define STACK_DEPTH 8192

/* Max safe check retries to eliminate false positives */
#define MAX_SAFE_RETRIES     100
#define DEFAULT_SAFE_RETRIES 2

/* Sensitive data search pattern definitions */
#define FOUND_CIPHER_KEY 1
#define FOUND_AUTH_KEY   2
#define FOUND_TEXT       3

static int pattern_auth_key;
static int pattern_cipher_key;
static int pattern_plain_text;
uint64_t pattern8_auth_key;
uint64_t pattern8_cipher_key;
uint64_t pattern8_plain_text;

#define MAX_OOO_MGR_SIZE 8192

/* Struct storing cipher parameters */
struct params_s {
        IMB_CIPHER_MODE cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        IMB_HASH_ALG hash_alg;       /* SHA-1 or others... */
        uint32_t key_size;
        uint32_t buf_size;
        uint64_t aad_size;
        uint32_t num_sizes;
};

/* Struct storing all expanded keys */
struct cipher_auth_keys {
        uint8_t temp_buf[IMB_SHA_512_BLOCK_SIZE];
        DECLARE_ALIGNED(uint32_t dust[15 * 4], 16);
        uint8_t ipad[IMB_SHA512_DIGEST_SIZE_IN_BYTES];
        uint8_t opad[IMB_SHA512_DIGEST_SIZE_IN_BYTES];
        DECLARE_ALIGNED(uint32_t k1_expanded[15 * 4], 16);
        DECLARE_ALIGNED(uint8_t k2[32], 16);
        DECLARE_ALIGNED(uint8_t k3[16], 16);
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);
        DECLARE_ALIGNED(struct gcm_key_data gdata_key, 64);
};

/* Struct storing all necessary data for crypto operations */
struct data {
        uint8_t test_buf[MAX_NUM_JOBS][JOB_SIZE_TOP];
        uint8_t src_dst_buf[MAX_NUM_JOBS][JOB_SIZE_TOP];
        uint8_t aad[MAX_AAD_SIZE];
        uint8_t in_digest[MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        uint8_t out_digest[MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        uint8_t cipher_iv[MAX_IV_SIZE];
        uint8_t auth_iv[MAX_IV_SIZE];
        uint8_t ciph_key[MAX_KEY_SIZE];
        uint8_t auth_key[MAX_KEY_SIZE];
        struct cipher_auth_keys enc_keys;
        struct cipher_auth_keys dec_keys;
        uint8_t tag_size;
};

struct job_ctx {
        uint64_t xgem_hdr;
        uint16_t pli;
        uint8_t *in_digest;
        uint8_t *out_digest;
        uint8_t tag_size_to_check;
        uint8_t *test_buf;
        uint8_t *src_dst_buf;
        uint32_t buf_size;
};

struct custom_job_params {
        IMB_CIPHER_MODE cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        IMB_HASH_ALG hash_alg;       /* SHA-1 or others... */
        uint32_t key_size;
};

union params {
        IMB_ARCH arch_type;
        struct custom_job_params job_params;
};

struct str_value_mapping {
        const char *name;
        union params values;
};

const struct str_value_mapping arch_str_map[] = {
        { .name = "NONE", .values.arch_type = IMB_ARCH_NONE },
        { .name = "SSE", .values.arch_type = IMB_ARCH_SSE },
        { .name = "AVX2", .values.arch_type = IMB_ARCH_AVX2 },
        { .name = "AVX512", .values.arch_type = IMB_ARCH_AVX512 }
};

struct str_value_mapping cipher_algo_str_map[] = {
        { .name = "AES-CBC-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CBC, .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-CBC-192",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CBC, .key_size = IMB_KEY_192_BYTES } },
        { .name = "AES-CBC-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CBC, .key_size = IMB_KEY_256_BYTES } },
        { .name = "AES-CTR-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CNTR, .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-CTR-192",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CNTR, .key_size = IMB_KEY_192_BYTES } },
        { .name = "AES-CTR-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CNTR, .key_size = IMB_KEY_256_BYTES } },
        { .name = "AES-CTR-128-BIT-LENGTH",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CNTR_BITLEN,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-CTR-192-BIT-LENGTH",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CNTR_BITLEN,
                                 .key_size = IMB_KEY_192_BYTES } },
        { .name = "AES-CTR-256-BIT-LENGTH",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CNTR_BITLEN,
                                 .key_size = IMB_KEY_256_BYTES } },
        { .name = "AES-ECB-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_ECB, .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-ECB-192",
          .values.job_params = { .cipher_mode = IMB_CIPHER_ECB, .key_size = IMB_KEY_192_BYTES } },
        { .name = "AES-ECB-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_ECB, .key_size = IMB_KEY_256_BYTES } },
        { .name = "DOCSIS-SEC-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "DOCSIS-SEC-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI,
                                 .key_size = IMB_KEY_256_BYTES } },
        { .name = "DOCSIS-DES-64",
          .values.job_params = { .cipher_mode = IMB_CIPHER_DOCSIS_DES, .key_size = 8 } },
        { .name = "DES-CBC-64",
          .values.job_params = { .cipher_mode = IMB_CIPHER_DES, .key_size = 8 } },
        { .name = "3DES-CBC-192",
          .values.job_params = { .cipher_mode = IMB_CIPHER_DES3, .key_size = 24 } },
        { .name = "ZUC-EEA3",
          .values.job_params = { .cipher_mode = IMB_CIPHER_ZUC_EEA3, .key_size = 16 } },
        { .name = "ZUC-EEA3-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_ZUC_EEA3, .key_size = 32 } },
        { .name = "SNOW3G-UEA2",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SNOW3G_UEA2_BITLEN, .key_size = 16 } },
        { .name = "KASUMI-F8",
          .values.job_params = { .cipher_mode = IMB_CIPHER_KASUMI_UEA1_BITLEN, .key_size = 16 } },
        { .name = "AES-CBCS-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CBCS_1_9, .key_size = 16 } },
        { .name = "CHACHA20-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CHACHA20, .key_size = 32 } },
        { .name = "SNOW-V",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SNOW_V, .key_size = 32 } },
        { .name = "SM4-ECB-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SM4_ECB, .key_size = 16 } },
        { .name = "SM4-CBC-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SM4_CBC, .key_size = 16 } },
        { .name = "SM4-CTR-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SM4_CNTR, .key_size = 16 } },
        { .name = "NULL-CIPHER",
          .values.job_params = { .cipher_mode = IMB_CIPHER_NULL, .key_size = 0 } },
        { .name = "AES-CFB-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CFB, .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-CFB-192",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CFB, .key_size = IMB_KEY_192_BYTES } },
        { .name = "AES-CFB-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CFB, .key_size = IMB_KEY_256_BYTES } }
};

struct str_value_mapping hash_algo_str_map[] = {
        {
                .name = "HMAC-SHA1",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_1
                }
        },
        {
                .name = "HMAC-SHA224",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_224
                }
        },
        {
                .name = "HMAC-SHA256",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_256
                }
        },
        {
                .name = "HMAC-SHA384",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_384
                }
        },
        {
                .name = "HMAC-SHA512",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_512
                }
        },
        {
                .name = "AES-XCBC-128",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_XCBC
                }
        },
        {
                .name = "HMAC-MD5",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_MD5
                }
        },
        {
                .name = "AES-CMAC-128",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_CMAC
                }
        },
        {
                .name = "NULL-HASH",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_NULL
                }
        },
        {
                .name = "AES-CMAC-128-BIT-LENGTH",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_CMAC_BITLEN
                }
        },
        {
                .name = "SHA1",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_1
                }
        },
        {
                .name = "SHA224",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_224
                }
        },
        {
                .name = "SHA256",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_256
                }
        },
        {
                .name = "SHA384",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_384
                }
        },
        {
                .name = "SHA512",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_512
                }
        },
        {
                .name = "ZUC-EIA3",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN,
                }
        },
        {
                .name = "SNOW3G-UIA2",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SNOW3G_UIA2_BITLEN,
                }
        },
        {
                .name = "KASUMI-F9",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_KASUMI_UIA1,
                }
        },
        {
                .name = "AES-GMAC-128",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_GMAC_128,
                }
        },
        {
                .name = "AES-GMAC-192",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_GMAC_192,
                }
        },
        {
                .name = "AES-GMAC-256",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_GMAC_256,
                }
        },
        {
                .name = "AES-CMAC-256",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_CMAC_256,
                }
        },
        {
                .name = "POLY1305",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_POLY1305,
                }
        },
        {
                .name = "ZUC-EIA3-256",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_ZUC256_EIA3_BITLEN,
                }
        },
        {
                .name = "GHASH",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_GHASH,
                }
        },
        {       .name = "ETH-CRC32",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC32_ETHERNET_FCS,
                }
        },
        {       .name = "SCTP-CRC32",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC32_SCTP,
                }
        },
        {       .name = "WIMAX-OFDMA-CRC32",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC32_WIMAX_OFDMA_DATA,
                }
        },
        {       .name = "LTE-A-CRC24",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC24_LTE_A,
                }
        },
        {       .name = "LTE-B-CRC24",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC24_LTE_B,
                }
        },
        {       .name = "X25-CRC16",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC16_X25,
                }
        },
        {       .name = "FP-CRC16",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC16_FP_DATA,
                }
        },
        {       .name = "FP-CRC11",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC11_FP_HEADER,
                }
        },
        {       .name = "IUUP-CRC10",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC10_IUUP_DATA,
                }
        },
        {       .name = "WIMAX-OFDMA-CRC8",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC8_WIMAX_OFDMA_HCS,
                }
        },
        {       .name = "FP-CRC7",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC7_FP_HEADER,
                }
        },
        {       .name = "IUUP-CRC6",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_CRC6_IUUP_HEADER,
                }
        },
        {
                .name = "SM3",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SM3,
                }
        },
        {
                .name = "HMAC-SM3",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SM3,
                }
        },
};

struct str_value_mapping aead_algo_str_map[] = {
        { .name = "AES-GCM-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_GCM,
                                 .hash_alg = IMB_AUTH_AES_GMAC,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-GCM-192",
          .values.job_params = { .cipher_mode = IMB_CIPHER_GCM,
                                 .hash_alg = IMB_AUTH_AES_GMAC,
                                 .key_size = IMB_KEY_192_BYTES } },
        { .name = "AES-GCM-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_GCM,
                                 .hash_alg = IMB_AUTH_AES_GMAC,
                                 .key_size = IMB_KEY_256_BYTES } },
        { .name = "AES-CCM-128",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CCM,
                                 .hash_alg = IMB_AUTH_AES_CCM,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-CCM-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CCM,
                                 .hash_alg = IMB_AUTH_AES_CCM,
                                 .key_size = IMB_KEY_256_BYTES } },
        { .name = "PON-128-BIP-CRC32",
          .values.job_params = { .cipher_mode = IMB_CIPHER_PON_AES_CNTR,
                                 .hash_alg = IMB_AUTH_PON_CRC_BIP,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "PON-128-NO-CTR",
          .values.job_params = { .cipher_mode = IMB_CIPHER_PON_AES_CNTR,
                                 .hash_alg = IMB_AUTH_PON_CRC_BIP,
                                 .key_size = 0 } },
        { .name = "AEAD-CHACHA20-256-POLY1305",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CHACHA20_POLY1305,
                                 .hash_alg = IMB_AUTH_CHACHA20_POLY1305,
                                 .key_size = 32 } },
        { .name = "SNOW-V-AEAD",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SNOW_V_AEAD,
                                 .hash_alg = IMB_AUTH_SNOW_V_AEAD,
                                 .key_size = 32 } },
        { .name = "SM4-GCM",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SM4_GCM,
                                 .hash_alg = IMB_AUTH_SM4_GCM,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "DOCSIS-SEC-128-CRC32",
          .values.job_params = { .cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI,
                                 .hash_alg = IMB_AUTH_DOCSIS_CRC32,
                                 .key_size = IMB_KEY_128_BYTES } },
};

/* This struct stores all information about performed test case */
struct variant_s {
        struct params_s params;
};

const uint8_t auth_tag_len_bytes[] = {
        12,                        /* IMB_AUTH_HMAC_SHA_1 */
        14,                        /* IMB_AUTH_HMAC_SHA_224 */
        16,                        /* IMB_AUTH_HMAC_SHA_256 */
        24,                        /* IMB_AUTH_HMAC_SHA_384 */
        32,                        /* IMB_AUTH_HMAC_SHA_512 */
        12,                        /* IMB_AUTH_AES_XCBC */
        12,                        /* IMB_AUTH_MD5 */
        0,                         /* IMB_AUTH_NULL */
        16,                        /* IMB_AUTH_AES_GMAC */
        0,                         /* IMB_AUTH_CUSTOM HASH */
        16,                        /* IMB_AES_CCM */
        16,                        /* IMB_AES_CMAC */
        20,                        /* IMB_PLAIN_SHA1 */
        28,                        /* IMB_PLAIN_SHA_224 */
        32,                        /* IMB_PLAIN_SHA_256 */
        48,                        /* IMB_PLAIN_SHA_384 */
        64,                        /* IMB_PLAIN_SHA_512 */
        4,                         /* IMB_AES_CMAC_BITLEN (3GPP) */
        8,                         /* IMB_PON */
        4,                         /* IMB_ZUC_EIA3_BITLEN */
        IMB_DOCSIS_CRC32_TAG_SIZE, /* IMB_AUTH_DOCSIS_CRC32 */
        4,                         /* IMB_AUTH_SNOW3G_UIA2_BITLEN (3GPP) */
        4,                         /* IMB_AUTH_KASUMI_UIA1 (3GPP) */
        16,                        /* IMB_AUTH_AES_GMAC_128 */
        16,                        /* IMB_AUTH_AES_GMAC_192 */
        16,                        /* IMB_AUTH_AES_GMAC_256 */
        16,                        /* IMB_AUTH_AES_CMAC_256 */
        16,                        /* IMB_AUTH_POLY1305 */
        16,                        /* IMB_AUTH_CHACHA20_POLY1305 */
        16,                        /* IMB_AUTH_CHACHA20_POLY1305_SGL */
        4,                         /* IMB_AUTH_ZUC256_EIA3_BITLEN */
        16,                        /* IMB_AUTH_SNOW_V_AEAD */
        16,                        /* IMB_AUTH_AES_GCM_SGL */
        4,                         /* IMB_AUTH_CRC32_ETHERNET_FCS */
        4,                         /* IMB_AUTH_CRC32_SCTP */
        4,                         /* IMB_AUTH_CRC32_WIMAX_OFDMA_DATA */
        4,                         /* IMB_AUTH_CRC24_LTE_A */
        4,                         /* IMB_AUTH_CRC24_LTE_B */
        4,                         /* IMB_AUTH_CRC16_X25 */
        4,                         /* IMB_AUTH_CRC16_FP_DATA */
        4,                         /* IMB_AUTH_CRC11_FP_HEADER */
        4,                         /* IMB_AUTH_CRC10_IUUP_DATA */
        4,                         /* IMB_AUTH_CRC8_WIMAX_OFDMA_HCS */
        4,                         /* IMB_AUTH_CRC7_FP_HEADER */
        4,                         /* IMB_AUTH_CRC6_IUUP_HEADER */
        16,                        /* IMB_AUTH_GHASH */
        32,                        /* IMB_AUTH_SM3 */
        32,                        /* IMB_AUTH_HMAC_SM3 */
        16,                        /* IMB_AUTH_SM4_GCM */
};

/* Minimum, maximum and step values of key sizes */
const uint8_t key_sizes[][3] = {
        { 16, 32, 8 },  /* IMB_CIPHER_CBC */
        { 16, 32, 8 },  /* IMB_CIPHER_CNTR */
        { 0, 0, 1 },    /* IMB_CIPHER_NULL */
        { 16, 32, 16 }, /* IMB_CIPHER_DOCSIS_SEC_BPI */
        { 16, 32, 8 },  /* IMB_CIPHER_GCM */
        { 0, 0, 1 },    /* IMB_CIPHER_CUSTOM */
        { 8, 8, 1 },    /* IMB_CIPHER_DES */
        { 8, 8, 1 },    /* IMB_CIPHER_DOCSIS_DES */
        { 16, 32, 16 }, /* IMB_CIPHER_CCM */
        { 24, 24, 1 },  /* IMB_CIPHER_DES3 */
        { 16, 16, 1 },  /* IMB_CIPHER_PON_AES_CNTR */
        { 16, 32, 8 },  /* IMB_CIPHER_ECB */
        { 16, 32, 8 },  /* IMB_CIPHER_CNTR_BITLEN */
        { 16, 32, 16 }, /* IMB_CIPHER_ZUC_EEA3 */
        { 16, 16, 1 },  /* IMB_CIPHER_SNOW3G_UEA2 */
        { 16, 16, 1 },  /* IMB_CIPHER_KASUMI_UEA1_BITLEN */
        { 16, 16, 1 },  /* IMB_CIPHER_CBCS_1_9 */
        { 32, 32, 1 },  /* IMB_CIPHER_CHACHA20 */
        { 32, 32, 1 },  /* IMB_CIPHER_CHACHA20_POLY1305 */
        { 32, 32, 1 },  /* IMB_CIPHER_CHACHA20_POLY1305_SGL */
        { 32, 32, 1 },  /* IMB_CIPHER_SNOW_V */
        { 32, 32, 1 },  /* IMB_CIPHER_SNOW_V_AEAD */
        { 16, 32, 8 },  /* IMB_CIPHER_GCM_SGL */
        { 16, 16, 1 },  /* IMB_CIPHER_SM4_ECB */
        { 16, 16, 1 },  /* IMB_CIPHER_SM4_CBC */
        { 16, 32, 8 },  /* IMB_CIPHER_CFB */
        { 16, 16, 1 },  /* IMB_CIPHER_SM4_CNTR */
        { 16, 16, 1 }   /* IMB_CIPHER_SM4_GCM */
};

uint8_t custom_test = 0;
uint8_t verbose = 0;
uint32_t safe_retries = DEFAULT_SAFE_RETRIES;

enum range { RANGE_MIN = 0, RANGE_STEP, RANGE_MAX, NUM_RANGE };

uint32_t job_sizes[NUM_RANGE] = { DEFAULT_JOB_SIZE_MIN, DEFAULT_JOB_SIZE_STEP,
                                  DEFAULT_JOB_SIZE_MAX };
/* Max number of jobs to submit in IMIX testing */
uint32_t max_num_jobs = 17;
/* IMIX disabled by default */
unsigned int imix_enabled = 0;
/* cipher and authentication IV sizes */
uint32_t cipher_iv_size = 0;
uint32_t auth_iv_size = 0;
uint8_t auth_tag_size = 0;
uint64_t offset = 4;

struct custom_job_params custom_job_params = { .cipher_mode = IMB_CIPHER_NULL,
                                               .hash_alg = IMB_AUTH_NULL,
                                               .key_size = 0 };

uint8_t enc_archs[IMB_ARCH_NUM] = { 0, 1, 1, 1 };
uint8_t dec_archs[IMB_ARCH_NUM] = { 0, 1, 1, 1 };

uint64_t flags = 0; /* flags passed to alloc_mb_mgr() */

/* 0 => not possible, 1 => possible */
int is_avx_sse_check_possible = 0;

int burst_api = 0;

static void
avx_sse_check(const char *ctx_str, const IMB_HASH_ALG hash_alg, const IMB_CIPHER_MODE cipher_mode)
{
        if (!is_avx_sse_check_possible)
                return;

        const uint32_t avx_sse_flag = avx_sse_transition_check();

        if (!avx_sse_flag)
                return;

        const char *hash_str = misc_hash_alg_to_str(hash_alg);
        const char *cipher_str = misc_cipher_mode_to_str(cipher_mode);

        if (avx_sse_flag & MISC_AVX_SSE_ZMM0_15_ISSUE)
                printf("ERROR: AVX-SSE transition after %s in ZMM0-ZMM15: "
                       "HASH=%s, CIPHER=%s\n",
                       ctx_str, hash_str, cipher_str);
        else if (avx_sse_flag & MISC_AVX_SSE_YMM0_15_ISSUE)
                printf("ERROR: AVX-SSE transition after %s in YMM0-YMM15: "
                       "HASH=%s, CIPHER=%s\n",
                       ctx_str, hash_str, cipher_str);
}

static void
clear_data(struct data *data)
{
        unsigned i;

        for (i = 0; i < MAX_NUM_JOBS; i++) {
                imb_clear_mem(data->test_buf[i], JOB_SIZE_TOP);
                imb_clear_mem(data->src_dst_buf[i], JOB_SIZE_TOP);
                imb_clear_mem(data->in_digest[i], MAX_DIGEST_SIZE);
                imb_clear_mem(data->out_digest[i], MAX_DIGEST_SIZE);
        }

        imb_clear_mem(data->aad, MAX_AAD_SIZE);
        imb_clear_mem(data->cipher_iv, MAX_IV_SIZE);
        imb_clear_mem(data->auth_iv, MAX_IV_SIZE);
        imb_clear_mem(data->ciph_key, MAX_KEY_SIZE);
        imb_clear_mem(data->auth_key, MAX_KEY_SIZE);
        imb_clear_mem(&data->enc_keys, sizeof(struct cipher_auth_keys));
        imb_clear_mem(&data->dec_keys, sizeof(struct cipher_auth_keys));
}

/**
 * Generate fill patterns
 * - make sure each patterns are different
 * - do not return zero pattern
 * - make sure it takes as long as possible before pattern is re-used again
 */
static int
get_pattern_seed(void)
{
        static int pattern_seed = 0;

        if (pattern_seed == 0)
                pattern_seed = (pattern_seed + 1) & 255;

        const int ret_seed = pattern_seed;

        pattern_seed = (pattern_seed + 1) & 255;
        return ret_seed;
}

static void
generate_one_pattern(const int idx)
{
        switch (idx) {
        case 0:
                pattern_auth_key = get_pattern_seed();
                break;
        case 1:
                pattern_cipher_key = get_pattern_seed();
                break;
        default:
                pattern_plain_text = get_pattern_seed();
                break;
        }
}

static void
generate_patterns(void)
{
        const int var_tab[][3] = { { 0, 1, 2 }, { 1, 0, 2 }, { 2, 1, 0 },
                                   { 0, 2, 1 }, { 1, 2, 0 }, { 2, 0, 1 } };
        static int var_idx = 0;

        /* change order of generating patterns */
        generate_one_pattern(var_tab[var_idx][0]);
        generate_one_pattern(var_tab[var_idx][1]);
        generate_one_pattern(var_tab[var_idx][2]);
        var_idx = (var_idx + 1) % IMB_DIM(var_tab);

        nosimd_memset(&pattern8_auth_key, pattern_auth_key, sizeof(pattern8_auth_key));
        nosimd_memset(&pattern8_cipher_key, pattern_cipher_key, sizeof(pattern8_cipher_key));
        nosimd_memset(&pattern8_plain_text, pattern_plain_text, sizeof(pattern8_plain_text));
}

static void
print_patterns(void)
{
        printf(">>> Patterns: AUTH_KEY = 0x%02x, CIPHER_KEY = 0x%02x, "
               "PLAIN_TEXT = 0x%02x\n",
               pattern_auth_key, pattern_cipher_key, pattern_plain_text);
}

/**
 * @brief Searches across a block of memory if a pattern is present
 *        (indicating there is some left over sensitive data)
 *
 * @return search status
 * @retval 0 nothing found
 * @retval FOUND_CIPHER_KEY fragment of CIPHER_KEY found
 * @retval FOUND_AUTH_KEY fragment of AUTH_KEY found
 * @retval FOUND_TEXT fragment of TEXT found
 */
static int
search_patterns(const void *ptr, const size_t mem_size, size_t *offset)
{
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        const size_t limit = mem_size - sizeof(uint64_t);

        for (size_t i = *offset; i <= limit; i++) {
                const uint64_t string = *((const uint64_t *) &ptr8[i]);

                if (string == pattern8_cipher_key) {
                        *offset = i;
                        return FOUND_CIPHER_KEY;
                }

                if (string == pattern8_auth_key) {
                        *offset = i;
                        return FOUND_AUTH_KEY;
                }

                if (string == pattern8_plain_text) {
                        *offset = i;
                        return FOUND_TEXT;
                }
        }

        return 0;
}

/**
 * @brief Tests memory pattern search function for specific buffer size
 *
 * @param [in] cb_size size of the test buffer
 * @param [in] pattern byte pattern to be used in the test
 *
 * @return Test status
 * @retval 0 OK
 * @retval -1 Test case 1 failed
 * @retval -2 Test case 2 failed
 * @retval -3 Test case 3 failed
 * @retval -100 Buffer allocation error
 */
static int
mem_search_avx2_test_case(const size_t cb_size, const int pattern)
{
        uint8_t *cb = malloc(cb_size);
        int ret = 0;

        if (cb == NULL)
                return -100;

        size_t i = 0;

        /* test 1: pattern shrinks from start to the end */
        for (i = 0; i < cb_size; i++) {
                const size_t current_sz = cb_size - i;
                uint8_t *p = &cb[i];

                if (i != 0)
                        nosimd_memset(cb, 0, i);
                nosimd_memset(p, pattern, current_sz);

                const uint64_t r1 = mem_search_avx2(cb, cb_size);

                if (current_sz >= sizeof(uint64_t) && r1 == 0ULL) {
                        ret = -1;
                        break;
                }

                const uint64_t r2 = mem_search_avx2(p, current_sz);

                if (current_sz >= sizeof(uint64_t) && r2 == 0ULL) {
                        ret = -1;
                        break;
                }
        }

        /* test 2: pattern grows from end to start */
        for (i = 0; (ret == 0) && (i < cb_size); i++) {
                const size_t current_sz = cb_size - i;
                uint8_t *p = &cb[current_sz];

                nosimd_memset(cb, 0, current_sz);
                if (i != 0)
                        nosimd_memset(p, pattern, i);

                const uint64_t r1 = mem_search_avx2(cb, cb_size);

                if (i >= sizeof(uint64_t) && r1 == 0ULL) {
                        ret = -2;
                        break;
                }

                const uint64_t r2 = mem_search_avx2(p, i);

                if (i >= sizeof(uint64_t) && r2 == 0ULL) {
                        ret = -2;
                        break;
                }
        }

        /* test 3: moving and growing pattern */
        for (i = 0; (ret == 0) && (i < cb_size); i++) {
                const size_t current_sz = cb_size - i;
                uint8_t *p = &cb[i];

                for (size_t j = 1; (ret == 0) && (j < current_sz); j++) {
                        if ((i + j) > cb_size)
                                break;

                        nosimd_memset(cb, 0, cb_size);
                        nosimd_memset(p, pattern, j);

                        const uint64_t r1 = mem_search_avx2(cb, cb_size);

                        if (j >= sizeof(uint64_t) && r1 == 0ULL) {
                                ret = -3;
                                break;
                        }

                        const uint64_t r2 = mem_search_avx2(p, current_sz);

                        if (j >= sizeof(uint64_t) && r2 == 0ULL) {
                                ret = -3;
                                break;
                        }
                }
        }

        free(cb);
        return ret;
}

/*
 * @brief Tests memory pattern search function for range of memory buffer sizes
 *
 * @return Test status
 * @retval 0 OK
 * @retval -1 Test case 1 failed
 * @retval -2 Test case 2 failed
 * @retval -3 Test case 3 failed
 * @retval -4 Negative test case 4 failed
 * @retval -100 Buffer allocation error
 */
static int
mem_search_avx2_test(void)
{
        const int pattern_tab[3] = { pattern_cipher_key, pattern_auth_key, pattern_plain_text };
        int ret = 0;

        /* positive tests */
        for (size_t i = 8; (ret == 0) && (i <= 128); i++)
                for (size_t n = 0; (ret == 0) && (n < IMB_DIM(pattern_tab)); n++)
                        ret = mem_search_avx2_test_case(i, pattern_tab[n]);

        /* negative test */
        if (ret == 0) {
                int negative_pattern = 0;

                for (negative_pattern = 1; negative_pattern < 256; negative_pattern++) {
                        size_t n = 0;

                        for (n = 0; n < IMB_DIM(pattern_tab); n++)
                                if (negative_pattern == pattern_tab[n])
                                        break;

                        /* there was no match against existing patterns */
                        if (n >= IMB_DIM(pattern_tab))
                                break;
                }

                if (mem_search_avx2_test_case(128, negative_pattern) == 0)
                        ret = -4;
        }

        return ret;
}

/**
 * @brief Searches across a block of memory if a pattern is present
 *        (indicating there is some left over sensitive data)
 *
 * @return search status
 * @retval 0 nothing found
 * @retval FOUND_CIPHER_KEY fragment of CIPHER_KEY found
 * @retval FOUND_AUTH_KEY fragment of AUTH_KEY found
 * @retval FOUND_TEXT fragment of TEXT found
 */
static int
search_patterns_ex(const void *ptr, const size_t mem_size, size_t *offset)
{
        static uint32_t avx2_check = UINT32_MAX;

        if (mem_size < sizeof(uint64_t) || offset == NULL)
                return 0;

        if (ptr == NULL)
                return 0;

        *offset = 0;

        if (avx2_check == UINT32_MAX) {
                /* Check presence of AVX2 - bit 5 of EBX, leaf 7, subleaf 0 */
                struct misc_cpuid_regs r = { 0 };

                misc_cpuid(7, 0, &r);
                avx2_check = r.ebx & (1UL << 5);

                /* run test of mem_search_avx2() function */
                if (avx2_check && (mem_search_avx2_test() != 0)) {
                        printf("ERROR: test_mem_search_avx2() test failed!\n");
                        avx2_check = 0;
                }
        }

        if (avx2_check)
                if (mem_search_avx2(ptr, mem_size) == 0ULL)
                        return 0;

        /*
         * If AVX2 fast search reports a problem then run the slow check
         * - also run slow check if AVX2 not available
         */
        const size_t limit = mem_size - sizeof(uint64_t);

        return search_patterns(ptr, limit, offset);
}

struct safe_check_ctx {
        int key_exp_phase;

        IMB_ARCH arch;
        const char *dir_name;
        unsigned job_idx;
        unsigned job_size;

        int gps_check;
        size_t gps_offset;

        int simd_check;
        size_t simd_offset;
        size_t simd_reg_size;
        const char *simd_reg_name;

        int rsp_check;
        size_t rsp_offset;
        void *rsp_ptr;
        uint8_t rsp_buf[64];

        int mgr_check;
        size_t mgr_offset;
        void *mgr_ptr;

        int ooo_check;
        size_t ooo_offset;
        void *ooo_ptr;
        const char *ooo_name;
        size_t ooo_size;
};

static void
print_match_gp(const void *ptr, const size_t offset)
{
        const char *reg_str[] = { "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8",
                                  "r9",  "r10", "r11", "r12", "r13", "r14", "r15" };
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        const size_t len_to_print = 8;
        const size_t reg_idx = offset / 8;
        const char *reg_name = (reg_idx < DIM(reg_str)) ? reg_str[reg_idx] : "<unknown>";

        hexdump_ex(stderr, reg_name, &ptr8[offset & ~7], len_to_print, NULL);
}

static void
print_match_xyzmm(const void *ptr, const size_t offset, const size_t simd_size,
                  const char *simd_name)
{
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        const size_t len_to_print = simd_size;
        const size_t reg_idx = offset / simd_size;
        char reg_name[8];

        nosimd_memset(reg_name, 0, sizeof(reg_name));
        snprintf(reg_name, sizeof(reg_name) - 1, "%s%zu", simd_name, reg_idx);
        hexdump_ex(stderr, reg_name, &ptr8[reg_idx * simd_size], len_to_print, NULL);
}

static void
print_match_memory(const void *ptr, const size_t mem_size, const size_t offset,
                   const char *mem_name)
{
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        static uint8_t tb[64];
        const size_t len_to_print =
                (sizeof(tb) > (mem_size - offset)) ? (mem_size - offset) : sizeof(tb);

        nosimd_memcpy(tb, &ptr8[offset], len_to_print);
        hexdump_ex(stderr, mem_name, tb, len_to_print, &ptr8[offset]);
}

static void
print_match_stack(const struct safe_check_ctx *ctx)
{
        const uint8_t *ptr8 = (const uint8_t *) ctx->rsp_ptr;
        const size_t len_to_print = 64;

        fprintf(stderr, "RSP = %p, offset = %zu, effective address = %p\n", ptr8, ctx->rsp_offset,
                &ptr8[ctx->rsp_offset]);

        hexdump_ex(stderr, "STACK", ctx->rsp_buf, len_to_print, &ptr8[ctx->rsp_offset]);
}

static void
print_match_type(const int check, const char *err_str)
{
        if (check == FOUND_CIPHER_KEY)
                fprintf(stderr, "Part of CIPHER_KEY found when %s\n", err_str);
        else if (check == FOUND_AUTH_KEY)
                fprintf(stderr, "Part of AUTH_KEY found when %s\n", err_str);
        else if (check == FOUND_TEXT)
                fprintf(stderr, "Part of plain/cipher text found when %s\n", err_str);
}

static void
print_match(const struct safe_check_ctx *ctx, const char *err_str)
{
        if (ctx->gps_check) {
                print_match_type(ctx->gps_check, err_str);
                print_match_gp(gps, ctx->gps_offset);
                return;
        }

        if (ctx->simd_check) {
                print_match_type(ctx->simd_check, err_str);
                print_match_xyzmm(simd_regs, ctx->simd_offset, ctx->simd_reg_size,
                                  ctx->simd_reg_name);
                return;
        }

        if (ctx->rsp_check) {
                print_match_type(ctx->rsp_check, err_str);
                print_match_stack(ctx);
                return;
        }

        if (ctx->mgr_check) {
                print_match_type(ctx->mgr_check, err_str);
                print_match_memory(ctx->mgr_ptr, sizeof(IMB_MGR), ctx->mgr_offset, "IMB_MGR");
                return;
        }

        if (ctx->ooo_check) {
                print_match_type(ctx->ooo_check, err_str);
                print_match_memory(ctx->ooo_ptr, ctx->ooo_size, ctx->ooo_offset, ctx->ooo_name);
                return;
        }
}

static int
compare_match(const struct safe_check_ctx *a, const struct safe_check_ctx *b)
{
        if (a->key_exp_phase != b->key_exp_phase)
                return 1;
        if (a->arch != b->arch)
                return 1;
        if (a->dir_name != b->dir_name)
                return 1;

        if (a->gps_check != b->gps_check)
                return 1;
        if (a->gps_offset != b->gps_offset)
                return 1;

        if (a->simd_check != b->simd_check)
                return 1;
        if (a->simd_offset != b->simd_offset)
                return 1;

        if (a->rsp_check != b->rsp_check)
                return 1;
        if (a->rsp_offset != b->rsp_offset)
                return 1;

        if (a->mgr_check != b->mgr_check)
                return 1;
        if (a->mgr_offset != b->mgr_offset)
                return 1;

        if (a->ooo_check != b->ooo_check)
                return 1;
        if (a->ooo_offset != b->ooo_offset)
                return 1;
        if (a->ooo_ptr != b->ooo_ptr)
                return 1;

        return 0;
}

static size_t
calculate_ooo_mgr_size(const void *ptr)
{
        const size_t max_size = MAX_OOO_MGR_SIZE - sizeof(uint64_t);
        size_t i;

        for (i = 0; i <= max_size; i++) {
                const uint64_t end_of_ooo_pattern = 0xDEADCAFEDEADCAFEULL;
                const uint8_t *ptr8 = (const uint8_t *) ptr;
                const uint64_t *ptr64 = (const uint64_t *) &ptr8[i];

                if (*ptr64 == end_of_ooo_pattern)
                        return i + sizeof(uint64_t);
        }

        /* no marker found */
        fprintf(stderr, "No road-block marker found for %p manager!\n", ptr);
        return MAX_OOO_MGR_SIZE;
}

static size_t
get_ooo_mgr_size(const void *ptr, const unsigned index)
{
        static size_t mgr_sz_tab[64];

        if (index >= DIM(mgr_sz_tab)) {
                fprintf(stderr, "get_ooo_mgr_size() internal table too small!\n");
                exit(EXIT_FAILURE);
        }

        if (mgr_sz_tab[index] == 0)
                mgr_sz_tab[index] = calculate_ooo_mgr_size(ptr);

        return mgr_sz_tab[index];
}

static void
print_algo_info(const struct params_s *params)
{
        struct custom_job_params *job_params;
        uint32_t i;

        for (i = 0; i < DIM(aead_algo_str_map); i++) {
                job_params = &aead_algo_str_map[i].values.job_params;
                if (job_params->cipher_mode == params->cipher_mode &&
                    job_params->hash_alg == params->hash_alg &&
                    job_params->key_size == params->key_size) {
                        printf("AEAD algo = %s ", aead_algo_str_map[i].name);
                        return;
                }
        }

        for (i = 0; i < DIM(cipher_algo_str_map); i++) {
                job_params = &cipher_algo_str_map[i].values.job_params;
                if (job_params->cipher_mode == params->cipher_mode &&
                    job_params->key_size == params->key_size) {
                        printf("Cipher algo = %s ", cipher_algo_str_map[i].name);
                        break;
                }
        }
        for (i = 0; i < DIM(hash_algo_str_map); i++) {
                job_params = &hash_algo_str_map[i].values.job_params;
                if (job_params->hash_alg == params->hash_alg) {
                        printf("Hash algo = %s ", hash_algo_str_map[i].name);
                        break;
                }
        }
}

static int
fill_job(IMB_JOB *job, const struct params_s *params, uint8_t *buf, uint8_t *digest,
         const uint8_t *aad, const uint32_t buf_size, const uint8_t tag_size,
         IMB_CIPHER_DIRECTION cipher_dir, struct cipher_auth_keys *keys, uint8_t *cipher_iv,
         uint8_t *auth_iv, const unsigned index, uint8_t *next_iv)
{
        static const void *ks_ptr[3];
        uint32_t *k1_expanded = keys->k1_expanded;
        uint8_t *k2 = keys->k2;
        uint8_t *k3 = keys->k3;
        uint32_t *enc_keys = keys->enc_keys;
        uint32_t *dec_keys = keys->dec_keys;
        uint8_t *ipad = keys->ipad;
        uint8_t *opad = keys->opad;
        struct gcm_key_data *gdata_key = &keys->gdata_key;
        uint64_t cipher_offset_in_bytes = offset;

        /* Force partial byte, by subtracting 3 bits from the full length */
        if (params->cipher_mode == IMB_CIPHER_CNTR_BITLEN)
                job->msg_len_to_cipher_in_bits = buf_size * 8 - 3;
        else
                job->msg_len_to_cipher_in_bytes = buf_size;

        job->msg_len_to_hash_in_bytes = buf_size;
        job->iv = cipher_iv;
        job->user_data = (void *) ((uintptr_t) index);

        if (params->cipher_mode == IMB_CIPHER_PON_AES_CNTR) {
                /* Subtract XGEM header */
                job->msg_len_to_cipher_in_bytes -= 8;
                cipher_offset_in_bytes += 8;
                /* If no crypto needed, set msg_len_to_cipher to 0 */
                if (params->key_size == 0)
                        job->msg_len_to_cipher_in_bytes = 0;
        }

        if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32 &&
            params->cipher_mode == IMB_CIPHER_DOCSIS_SEC_BPI) {
                if (buf_size >= (IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE + IMB_DOCSIS_CRC32_TAG_SIZE)) {
                        const uint64_t cipher_adjust = /* SA + DA only */
                                IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE - 2;

                        cipher_offset_in_bytes += cipher_adjust;
                        job->msg_len_to_cipher_in_bytes -= cipher_adjust;
                        job->msg_len_to_hash_in_bytes -= IMB_DOCSIS_CRC32_TAG_SIZE;
                } else if (buf_size > IMB_DOCSIS_CRC32_TAG_SIZE) {
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes -= IMB_DOCSIS_CRC32_TAG_SIZE;
                } else {
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes = 0;
                }
        }

        /* In-place operation */
        /* "offset" will be applied to src inside the library code */
        job->src = buf - offset;
        job->dst = buf - offset + cipher_offset_in_bytes;
        job->auth_tag_output = digest;
        job->hash_start_src_offset_in_bytes = offset;

        job->hash_alg = params->hash_alg;
        switch (params->hash_alg) {
        case IMB_AUTH_AES_XCBC:
                job->u.XCBC._k1_expanded = k1_expanded;
                job->u.XCBC._k2 = k2;
                job->u.XCBC._k3 = k3;
                break;
        case IMB_AUTH_AES_CMAC:
                job->u.CMAC._key_expanded = k1_expanded;
                job->u.CMAC._skey1 = k2;
                job->u.CMAC._skey2 = k3;
                break;
        case IMB_AUTH_AES_CMAC_BITLEN:
                job->u.CMAC._key_expanded = k1_expanded;
                job->u.CMAC._skey1 = k2;
                job->u.CMAC._skey2 = k3;
                /*
                 * CMAC bit level version is done in bits (length is
                 * converted to bits and it is decreased by 4 bits,
                 * to force the CMAC bitlen path)
                 */
                job->msg_len_to_hash_in_bits = (job->msg_len_to_hash_in_bytes * 8) - 4;
                break;
        case IMB_AUTH_AES_CMAC_256:
                job->u.CMAC._key_expanded = k1_expanded;
                job->u.CMAC._skey1 = k2;
                job->u.CMAC._skey2 = k3;
                break;
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_HMAC_SM3:
        case IMB_AUTH_MD5:
                /* HMAC hash alg is SHA1 or MD5 */
                job->u.HMAC._hashed_auth_key_xor_ipad = (uint8_t *) ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = (uint8_t *) opad;
                break;
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
                job->u.ZUC_EIA3._key = k2;
                if (auth_iv_size == 23) {
                        job->u.ZUC_EIA3._iv23 = auth_iv;
                        job->u.ZUC_EIA3._iv = NULL;
                } else {
                        job->u.ZUC_EIA3._iv = auth_iv;
                        job->u.ZUC_EIA3._iv23 = NULL;
                }
                job->msg_len_to_hash_in_bits = (job->msg_len_to_hash_in_bytes * 8);
                break;
        case IMB_AUTH_ZUC_EIA3_BITLEN:
                job->u.ZUC_EIA3._key = k2;
                job->u.ZUC_EIA3._iv = auth_iv;
                job->msg_len_to_hash_in_bits = (job->msg_len_to_hash_in_bytes * 8);
                break;
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                job->u.SNOW3G_UIA2._key = k2;
                job->u.SNOW3G_UIA2._iv = auth_iv;
                job->msg_len_to_hash_in_bits = (job->msg_len_to_hash_in_bytes * 8);
                break;
        case IMB_AUTH_KASUMI_UIA1:
                job->u.KASUMI_UIA1._key = k2;
                break;
        case IMB_AUTH_AES_GMAC_128:
        case IMB_AUTH_AES_GMAC_192:
        case IMB_AUTH_AES_GMAC_256:
                job->u.GMAC._key = gdata_key;
                job->u.GMAC._iv = auth_iv;
                job->u.GMAC.iv_len_in_bytes = 12;
                break;
        case IMB_AUTH_GHASH:
                job->u.GHASH._key = gdata_key;
                job->u.GHASH._init_tag = auth_iv;
                break;
        case IMB_AUTH_PON_CRC_BIP:
        case IMB_AUTH_NULL:
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_AES_CCM:
        case IMB_AUTH_SM4_GCM:
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
        case IMB_AUTH_GCM_SGL:
        case IMB_AUTH_CRC32_ETHERNET_FCS:
        case IMB_AUTH_CRC32_SCTP:
        case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
        case IMB_AUTH_CRC24_LTE_A:
        case IMB_AUTH_CRC24_LTE_B:
        case IMB_AUTH_CRC16_X25:
        case IMB_AUTH_CRC16_FP_DATA:
        case IMB_AUTH_CRC11_FP_HEADER:
        case IMB_AUTH_CRC10_IUUP_DATA:
        case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
        case IMB_AUTH_CRC7_FP_HEADER:
        case IMB_AUTH_CRC6_IUUP_HEADER:
        case IMB_AUTH_SM3:
                /* No operation needed */
                break;
        case IMB_AUTH_DOCSIS_CRC32:
                break;
        case IMB_AUTH_POLY1305:
                job->u.POLY1305._key = k1_expanded;
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = params->aad_size;
                job->u.CHACHA20_POLY1305.aad = aad;
                break;
        case IMB_AUTH_SNOW_V_AEAD:
                job->u.SNOW_V_AEAD.aad_len_in_bytes = params->aad_size;
                job->u.SNOW_V_AEAD.aad = aad;
                break;
        default:
                printf("Unsupported hash algorithm %u, line %d\n", (unsigned) params->hash_alg,
                       __LINE__);
                return -1;
        }

        job->auth_tag_output_len_in_bytes = (uint64_t) tag_size;

        job->cipher_direction = cipher_dir;

        if (params->cipher_mode == IMB_CIPHER_NULL) {
                job->chain_order = IMB_ORDER_HASH_CIPHER;
        } else if (params->cipher_mode == IMB_CIPHER_CCM ||
                   (params->cipher_mode == IMB_CIPHER_DOCSIS_SEC_BPI &&
                    params->hash_alg == IMB_AUTH_DOCSIS_CRC32)) {
                if (job->cipher_direction == IMB_DIR_ENCRYPT)
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
                else
                        job->chain_order = IMB_ORDER_CIPHER_HASH;
        } else {
                if (job->cipher_direction == IMB_DIR_ENCRYPT)
                        job->chain_order = IMB_ORDER_CIPHER_HASH;
                else
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
        }

        /* Translating enum to the API's one */
        job->cipher_mode = params->cipher_mode;
        job->key_len_in_bytes = params->key_size;

        job->cipher_start_src_offset_in_bytes = cipher_offset_in_bytes;

        switch (job->cipher_mode) {
        case IMB_CIPHER_CBCS_1_9:
                job->cipher_fields.CBCS.next_iv = next_iv;
                /* Fall-through */
        case IMB_CIPHER_SM4_CBC:
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_DOCSIS_SEC_BPI:
                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_PON_AES_CNTR:
        case IMB_CIPHER_SM4_CNTR:
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_CNTR_BITLEN:
        case IMB_CIPHER_CFB:
                job->enc_keys = enc_keys;
                job->dec_keys = enc_keys;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_GCM:
        case IMB_CIPHER_SM4_GCM:
                job->enc_keys = gdata_key;
                job->dec_keys = gdata_key;
                job->u.GCM.aad_len_in_bytes = params->aad_size;
                job->u.GCM.aad = aad;
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_CCM:
                job->msg_len_to_cipher_in_bytes = buf_size;
                job->msg_len_to_hash_in_bytes = buf_size;
                job->u.CCM.aad_len_in_bytes = params->aad_size;
                job->u.CCM.aad = aad;
                job->enc_keys = enc_keys;
                job->dec_keys = enc_keys;
                job->iv_len_in_bytes = 13;
                break;
        case IMB_CIPHER_DES:
        case IMB_CIPHER_DOCSIS_DES:
                job->enc_keys = enc_keys;
                job->dec_keys = enc_keys;
                job->iv_len_in_bytes = 8;
                break;
        case IMB_CIPHER_DES3:
                ks_ptr[0] = ks_ptr[1] = ks_ptr[2] = enc_keys;
                job->enc_keys = ks_ptr;
                job->dec_keys = ks_ptr;
                job->iv_len_in_bytes = 8;
                break;
        case IMB_CIPHER_ECB:
        case IMB_CIPHER_SM4_ECB:
                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv_len_in_bytes = 0;
                break;
        case IMB_CIPHER_ZUC_EEA3:
                job->enc_keys = k2;
                job->dec_keys = k2;
                if (job->key_len_in_bytes == 16)
                        job->iv_len_in_bytes = 16;
                else /* 32 */
                        job->iv_len_in_bytes = 25;
                break;
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                job->enc_keys = k2;
                job->dec_keys = k2;
                job->iv_len_in_bytes = 16;
                job->msg_len_to_cipher_in_bits = (job->msg_len_to_cipher_in_bytes * 8);
                job->cipher_start_src_offset_in_bits *= 8;
                break;
        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                job->enc_keys = k2;
                job->dec_keys = k2;
                job->iv_len_in_bytes = 8;
                job->cipher_start_src_offset_in_bits = 0;
                job->msg_len_to_cipher_in_bits = (job->msg_len_to_cipher_in_bytes * 8);
                job->cipher_start_src_offset_in_bits *= 8;
                break;
        case IMB_CIPHER_CHACHA20:
        case IMB_CIPHER_CHACHA20_POLY1305:
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                job->enc_keys = k2;
                job->dec_keys = k2;
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_SNOW_V:
        case IMB_CIPHER_SNOW_V_AEAD:
                job->enc_keys = k2;
                job->dec_keys = k2;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_NULL:
                /* No operation needed */
                break;
        default:
                printf("Unsupported cipher mode\n");
                return -1;
        }

        /*
         * If cipher IV size is set from command line,
         * overwrite the value here.
         */
        if (cipher_iv_size != 0)
                job->iv_len_in_bytes = cipher_iv_size;

        return 0;
}

static int
prepare_keys(IMB_MGR *mb_mgr, struct cipher_auth_keys *keys, const uint8_t *ciph_key,
             const uint8_t *auth_key, const struct params_s *params,
             const unsigned int force_pattern)
{
        uint32_t *dust = keys->dust;
        uint32_t *k1_expanded = keys->k1_expanded;
        uint8_t *k2 = keys->k2;
        uint8_t *k3 = keys->k3;
        uint32_t *enc_keys = keys->enc_keys;
        uint32_t *dec_keys = keys->dec_keys;
        uint8_t *ipad = keys->ipad;
        uint8_t *opad = keys->opad;
        struct gcm_key_data *gdata_key = &keys->gdata_key;

        /* Set all expanded keys to pattern_cipher_key/pattern_auth_key
         * if flag is set */
        if (force_pattern) {
                switch (params->hash_alg) {
                case IMB_AUTH_AES_XCBC:
                        nosimd_memset(k1_expanded, pattern_auth_key, sizeof(keys->k1_expanded));
                        nosimd_memset(k2, pattern_auth_key, sizeof(keys->k2));
                        nosimd_memset(k3, pattern_auth_key, sizeof(keys->k3));
                        break;
                case IMB_AUTH_AES_CMAC:
                case IMB_AUTH_AES_CMAC_BITLEN:
                case IMB_AUTH_AES_CMAC_256:
                        nosimd_memset(k1_expanded, pattern_auth_key, sizeof(keys->k1_expanded));
                        nosimd_memset(k2, pattern_auth_key, sizeof(keys->k2));
                        nosimd_memset(k3, pattern_auth_key, sizeof(keys->k3));
                        break;
                case IMB_AUTH_POLY1305:
                        nosimd_memset(k1_expanded, pattern_auth_key, sizeof(keys->k1_expanded));
                        break;
                case IMB_AUTH_HMAC_SHA_1:
                case IMB_AUTH_HMAC_SHA_224:
                case IMB_AUTH_HMAC_SHA_256:
                case IMB_AUTH_HMAC_SHA_384:
                case IMB_AUTH_HMAC_SHA_512:
                case IMB_AUTH_HMAC_SM3:
                case IMB_AUTH_MD5:
                        nosimd_memset(ipad, pattern_auth_key, sizeof(keys->ipad));
                        nosimd_memset(opad, pattern_auth_key, sizeof(keys->opad));
                        break;
                case IMB_AUTH_ZUC_EIA3_BITLEN:
                case IMB_AUTH_ZUC256_EIA3_BITLEN:
                case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                case IMB_AUTH_KASUMI_UIA1:
                        nosimd_memset(k3, pattern_auth_key, sizeof(keys->k3));
                        break;
                case IMB_AUTH_AES_CCM:
                case IMB_AUTH_SM4_GCM:
                case IMB_AUTH_AES_GMAC:
                case IMB_AUTH_NULL:
                case IMB_AUTH_SHA_1:
                case IMB_AUTH_SHA_224:
                case IMB_AUTH_SHA_256:
                case IMB_AUTH_SHA_384:
                case IMB_AUTH_SHA_512:
                case IMB_AUTH_PON_CRC_BIP:
                case IMB_AUTH_DOCSIS_CRC32:
                case IMB_AUTH_CHACHA20_POLY1305:
                case IMB_AUTH_CHACHA20_POLY1305_SGL:
                case IMB_AUTH_SNOW_V_AEAD:
                case IMB_AUTH_GCM_SGL:
                case IMB_AUTH_CRC32_ETHERNET_FCS:
                case IMB_AUTH_CRC32_SCTP:
                case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
                case IMB_AUTH_CRC24_LTE_A:
                case IMB_AUTH_CRC24_LTE_B:
                case IMB_AUTH_CRC16_X25:
                case IMB_AUTH_CRC16_FP_DATA:
                case IMB_AUTH_CRC11_FP_HEADER:
                case IMB_AUTH_CRC10_IUUP_DATA:
                case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
                case IMB_AUTH_CRC7_FP_HEADER:
                case IMB_AUTH_CRC6_IUUP_HEADER:
                case IMB_AUTH_SM3:
                        /* No operation needed */
                        break;
                case IMB_AUTH_AES_GMAC_128:
                case IMB_AUTH_AES_GMAC_192:
                case IMB_AUTH_AES_GMAC_256:
                case IMB_AUTH_GHASH:
                        nosimd_memset(gdata_key, pattern_auth_key, sizeof(keys->gdata_key));
                        break;
                default:
                        fprintf(stderr, "Unsupported hash algorithm %u, line %d\n",
                                (unsigned) params->hash_alg, __LINE__);
                        return -1;
                }

                switch (params->cipher_mode) {
                case IMB_CIPHER_GCM:
                case IMB_CIPHER_SM4_GCM:
                        nosimd_memset(gdata_key, pattern_cipher_key, sizeof(keys->gdata_key));
                        break;
                case IMB_CIPHER_PON_AES_CNTR:
                case IMB_CIPHER_CBC:
                case IMB_CIPHER_SM4_CBC:
                case IMB_CIPHER_SM4_CNTR:
                case IMB_CIPHER_CCM:
                case IMB_CIPHER_CNTR:
                case IMB_CIPHER_CNTR_BITLEN:
                case IMB_CIPHER_DOCSIS_SEC_BPI:
                case IMB_CIPHER_SM4_ECB:
                case IMB_CIPHER_ECB:
                case IMB_CIPHER_CBCS_1_9:
                case IMB_CIPHER_CFB:
                        nosimd_memset(enc_keys, pattern_cipher_key, sizeof(keys->enc_keys));
                        nosimd_memset(dec_keys, pattern_cipher_key, sizeof(keys->dec_keys));
                        break;
                case IMB_CIPHER_DES:
                case IMB_CIPHER_DES3:
                case IMB_CIPHER_DOCSIS_DES:
                        nosimd_memset(enc_keys, pattern_cipher_key, sizeof(keys->enc_keys));
                        break;
                case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                        nosimd_memset(k2, pattern_cipher_key, 16);
                        break;
                case IMB_CIPHER_ZUC_EEA3:
                case IMB_CIPHER_CHACHA20:
                case IMB_CIPHER_CHACHA20_POLY1305:
                case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                case IMB_CIPHER_SNOW_V:
                case IMB_CIPHER_SNOW_V_AEAD:
                        nosimd_memset(k2, pattern_cipher_key, 32);
                        break;
                case IMB_CIPHER_NULL:
                        /* No operation needed */
                        break;
                default:
                        fprintf(stderr, "Unsupported cipher mode\n");
                        return -1;
                }

                return 0;
        }

        switch (params->hash_alg) {
        case IMB_AUTH_AES_XCBC:
                IMB_AES_XCBC_KEYEXP(mb_mgr, auth_key, k1_expanded, k2, k3);
                break;
        case IMB_AUTH_AES_CMAC:
        case IMB_AUTH_AES_CMAC_BITLEN:
                IMB_AES_KEYEXP_128(mb_mgr, auth_key, k1_expanded, dust);
                IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, k1_expanded, k2, k3);
                break;
        case IMB_AUTH_AES_CMAC_256:
                IMB_AES_KEYEXP_256(mb_mgr, auth_key, k1_expanded, dust);
                IMB_AES_CMAC_SUBKEY_GEN_256(mb_mgr, k1_expanded, k2, k3);
                break;
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_HMAC_SM3:
        case IMB_AUTH_MD5:
                imb_hmac_ipad_opad(mb_mgr, params->hash_alg, auth_key, MAX_KEY_SIZE, ipad, opad);
                break;
        case IMB_AUTH_ZUC_EIA3_BITLEN:
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
        case IMB_AUTH_KASUMI_UIA1:
                nosimd_memcpy(k2, auth_key, sizeof(keys->k2));
                break;
        case IMB_AUTH_AES_GMAC_128:
                IMB_AES128_GCM_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_AES_GMAC_192:
                IMB_AES192_GCM_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_AES_GMAC_256:
                IMB_AES256_GCM_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_GHASH:
                IMB_GHASH_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_AES_CCM:
        case IMB_AUTH_SM4_GCM:
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_NULL:
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
        case IMB_AUTH_PON_CRC_BIP:
        case IMB_AUTH_DOCSIS_CRC32:
        case IMB_AUTH_CHACHA20_POLY1305:
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
        case IMB_AUTH_SNOW_V_AEAD:
        case IMB_AUTH_GCM_SGL:
        case IMB_AUTH_CRC32_ETHERNET_FCS:
        case IMB_AUTH_CRC32_SCTP:
        case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
        case IMB_AUTH_CRC24_LTE_A:
        case IMB_AUTH_CRC24_LTE_B:
        case IMB_AUTH_CRC16_X25:
        case IMB_AUTH_CRC16_FP_DATA:
        case IMB_AUTH_CRC11_FP_HEADER:
        case IMB_AUTH_CRC10_IUUP_DATA:
        case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
        case IMB_AUTH_CRC7_FP_HEADER:
        case IMB_AUTH_CRC6_IUUP_HEADER:
        case IMB_AUTH_SM3:
                /* No operation needed */
                break;
        case IMB_AUTH_POLY1305:
                nosimd_memcpy(k1_expanded, auth_key, 32);
                break;
        default:
                fprintf(stderr, "Unsupported hash algorithm %u, line %d\n",
                        (unsigned) params->hash_alg, __LINE__);
                return -1;
        }

        switch (params->cipher_mode) {
        case IMB_CIPHER_GCM:
                switch (params->key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                default:
                        fprintf(stderr, "Wrong key size\n");
                        return -1;
                }
                break;
        case IMB_CIPHER_PON_AES_CNTR:
                switch (params->key_size) {
                case 16:
                        IMB_AES_KEYEXP_128(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                case 0:
                        break;
                default:
                        fprintf(stderr, "Wrong key size\n");
                        return -1;
                }
                break;
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_CCM:
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_CNTR_BITLEN:
        case IMB_CIPHER_DOCSIS_SEC_BPI:
        case IMB_CIPHER_ECB:
        case IMB_CIPHER_CBCS_1_9:
        case IMB_CIPHER_CFB:
                switch (params->key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                default:
                        fprintf(stderr, "Wrong key size\n");
                        return -1;
                }
                break;
        case IMB_CIPHER_SM4_ECB:
        case IMB_CIPHER_SM4_CBC:
        case IMB_CIPHER_SM4_CNTR:
                IMB_SM4_KEYEXP(mb_mgr, ciph_key, enc_keys, dec_keys);
                break;
        case IMB_CIPHER_SM4_GCM:
                imb_sm4_gcm_pre(mb_mgr, ciph_key, gdata_key);
                break;
        case IMB_CIPHER_DES:
        case IMB_CIPHER_DES3:
        case IMB_CIPHER_DOCSIS_DES:
                des_key_schedule((uint64_t *) enc_keys, ciph_key);
                break;
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                nosimd_memcpy(k2, ciph_key, 16);
                break;
        case IMB_CIPHER_ZUC_EEA3:
        case IMB_CIPHER_CHACHA20:
        case IMB_CIPHER_CHACHA20_POLY1305:
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
        case IMB_CIPHER_SNOW_V:
        case IMB_CIPHER_SNOW_V_AEAD:
                /* Use of:
                 *     nosimd_memcpy(k2, ciph_key, 32);
                 * leaves sensitive data on the stack.
                 * Copying data in 16 byte chunks instead.
                 */
                nosimd_memcpy(k2, ciph_key, 16);
                nosimd_memcpy(k2 + 16, ciph_key + 16, 16);
                break;
        case IMB_CIPHER_NULL:
                /* No operation needed */
                break;
        default:
                fprintf(stderr, "Unsupported cipher mode\n");
                return -1;
        }

        return 0;
}

/* Modify the test buffer to set the HEC value and CRC, so the final
 * decrypted message can be compared against the test buffer */
static int
modify_pon_test_buf(uint8_t *test_buf, const IMB_JOB *job, const uint32_t pli,
                    const uint64_t xgem_hdr)
{
        /* Set plaintext CRC in test buffer for PON */
        uint32_t *buf32 = (uint32_t *) &test_buf[8 + pli - 4];
        uint64_t *buf64 = (uint64_t *) test_buf;
        const uint32_t *tag32 = (uint32_t *) job->auth_tag_output;
        const uint64_t hec_mask = BSWAP64(0xfffffffffffe000);
        const uint64_t xgem_hdr_out =
                ((const uint64_t *) (job->src + job->hash_start_src_offset_in_bytes))[0];

        /* Update CRC if PLI > 4 */
        if (pli > 4)
                buf32[0] = tag32[1];

        /* Check if any bits apart from HEC are modified */
        if ((xgem_hdr_out & hec_mask) != (xgem_hdr & hec_mask)) {
                fprintf(stderr, "XGEM header overwritten outside HEC\n");
                fprintf(stderr, "Original XGEM header: %" PRIx64 "\n", xgem_hdr & hec_mask);
                fprintf(stderr, "Output XGEM header: %" PRIx64 "\n", xgem_hdr_out & hec_mask);
                return -1;
        }

        /* Modify original XGEM header to include calculated HEC */
        buf64[0] = xgem_hdr_out;

        return 0;
}

/* Modify the test buffer to set the CRC value, so the final
 * decrypted message can be compared against the test buffer */
static void
modify_docsis_crc32_test_buf(uint8_t *test_buf, const IMB_JOB *job, const uint32_t buf_size)
{
        if (buf_size >= (IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE + IMB_DOCSIS_CRC32_TAG_SIZE)) {
                /* Set plaintext CRC32 in the test buffer */
                nosimd_memcpy(&test_buf[buf_size - IMB_DOCSIS_CRC32_TAG_SIZE], job->auth_tag_output,
                              IMB_DOCSIS_CRC32_TAG_SIZE);
        }
}

/*
 * @brief Checks for sensitive information in registers, stack and MB_MGR
 *        (in this order, to try to minimize pollution of the data left out
 *        after the job completion, due to these actual checks).
 *
 * @return check status
 * @retval 0 all OK
 * @retval -1 sensitive data found
 * @retval -2 wrong input arguments
 */
static int
perform_safe_checks(IMB_MGR *mgr, const IMB_ARCH arch, struct safe_check_ctx *ctx, const char *dir)
{
        static const struct {
                size_t simd_set_size;
                void (*simd_dump_fn)(void);
        } simd_ctx[] = {
                { 0, NULL },                     /* none */
                { XMM_MEM_SIZE, dump_xmms_sse }, /* sse */
                { YMM_MEM_SIZE, dump_ymms },     /* avx2 */
                { ZMM_MEM_SIZE, dump_zmms }      /* avx512 */
        };

        dump_gps();

        if (ctx == NULL)
                return -2;

        if (arch == IMB_ARCH_NONE || arch >= IMB_ARCH_NUM) {
                fprintf(stderr, "Invalid architecture!\n");
                return -2;
        }

        uint8_t *rsp_ptr = rdrsp();

        simd_ctx[arch].simd_dump_fn();

        nosimd_memset(ctx, 0, sizeof(*ctx));

        ctx->rsp_ptr = rsp_ptr;
        ctx->arch = arch;
        ctx->dir_name = dir;

        if (arch == IMB_ARCH_AVX2) {
                ctx->simd_reg_size = 32;
                ctx->simd_reg_name = "ymm";
        } else if (arch == IMB_ARCH_AVX512) {
                ctx->simd_reg_size = 64;
                ctx->simd_reg_name = "zmm";
        } else {
                ctx->simd_reg_size = 16;
                ctx->simd_reg_name = "xmm";
        }

        ctx->rsp_check = search_patterns_ex((rsp_ptr - STACK_DEPTH), STACK_DEPTH, &ctx->rsp_offset);
        if (ctx->rsp_check != 0) {
                const uint8_t *sp = (const uint8_t *) (rsp_ptr - STACK_DEPTH);

                nosimd_memcpy(ctx->rsp_buf, &sp[ctx->rsp_offset], sizeof(ctx->rsp_buf));
                return -1;
        }

        ctx->gps_check = search_patterns_ex(gps, GP_MEM_SIZE, &ctx->gps_offset);
        if (ctx->gps_check != 0)
                return -1;

        ctx->simd_check =
                search_patterns_ex(simd_regs, simd_ctx[arch].simd_set_size, &ctx->simd_offset);
        if (ctx->simd_check != 0)
                return -1;

        ctx->mgr_check = search_patterns_ex(mgr, sizeof(*mgr), &ctx->mgr_offset);
        if (ctx->mgr_check != 0)
                return -1;

        /* search OOO managers */
        static const char *const ooo_names[] = {
                "aes128_ooo",
                "aes192_ooo",
                "aes256_ooo",
                "docsis128_sec_ooo",
                "docsis128_crc32_sec_ooo",
                "docsis256_sec_ooo",
                "docsis256_crc32_sec_ooo",
                "des_enc_ooo",
                "des_dec_ooo",
                "des3_enc_ooo",
                "des3_dec_ooo",
                "docsis_des_enc_ooo",
                "docsis_des_dec_ooo",
                "hmac_sha_1_ooo",
                "hmac_sha_224_ooo",
                "hmac_sha_256_ooo",
                "hmac_sha_384_ooo",
                "hmac_sha_512_ooo",
                "hmac_md5_ooo",
                "aes_xcbc_ooo",
                "aes_ccm_ooo",
                "aes_cmac_ooo",
                "zuc_eea3_ooo",
                "zuc_eia3_ooo",
                "aes128_cbcs_ooo",
                "zuc256_eea3_ooo",
                "zuc256_eia3_ooo",
                "aes256_ccm_ooo",
                "aes256_cmac_ooo",
                "snow3g_uea2_ooo",
                "snow3g_uia2_ooo",
                "sha_1_ooo",
                "sha_224_ooo",
                "sha_256_ooo",
                "sha_384_ooo",
                "sha_512_ooo",
                "aes_cfb_128_ooo",
                "aes_cfb_192_ooo",
                "aes_cfb_256_ooo",
                "end_ooo" /* add new ooo manager above this line */
        };
        static size_t ooo_size[64] = { 0 };
        static int ooo_size_set = 0;
        void **ooo_ptr = NULL;

        IMB_ASSERT(IMB_DIM(ooo_names) <= IMB_DIM(ooo_size));

        if (ooo_size_set == 0) {
                ooo_ptr = &mgr->aes128_ooo;
                for (unsigned i = 0; ooo_ptr < &mgr->end_ooo; ooo_ptr++, i++) {
                        void *ooo_mgr_p = *ooo_ptr;

                        ooo_size[i] = get_ooo_mgr_size(ooo_mgr_p, i);
                }

                ooo_size_set = 1;
        }

        ooo_ptr = &mgr->aes128_ooo;
        for (unsigned i = 0; ooo_ptr < &mgr->end_ooo; ooo_ptr++, i++) {
                void *ooo_mgr_p = *ooo_ptr;

                ctx->ooo_check = search_patterns_ex(ooo_mgr_p, ooo_size[i], &ctx->ooo_offset);
                if (ctx->ooo_check != 0) {
                        ctx->ooo_ptr = ooo_mgr_p;
                        ctx->ooo_name = ooo_names[i];
                        ctx->ooo_size = ooo_size[i];
                        return -1;
                }
        }

        return 0;
}

static int
post_job(IMB_MGR *mgr, IMB_JOB *job, unsigned *num_processed_jobs, const struct params_s *params,
         struct job_ctx *job_tab, const IMB_CIPHER_DIRECTION dir)
{

        const unsigned idx = (unsigned) ((uintptr_t) job->user_data);

        if (job->status != IMB_STATUS_COMPLETED) {
                int errc = imb_get_errno(mgr);

                fprintf(stderr,
                        "failed job, status:%d, "
                        "error code:%d '%s'\n",
                        job->status, errc, imb_get_strerror(errc));
                return -1;
        }
        if (idx != *num_processed_jobs) {
                fprintf(stderr,
                        "enc-submit job returned out of order, "
                        "received %u, expected %u\n",
                        idx, *num_processed_jobs);
                return -1;
        }
        (*num_processed_jobs)++;

        /* Only need to modify the buffer after encryption */
        if (dir == IMB_DIR_ENCRYPT) {
#ifndef __clang_analyzer__
                /*
                 * @todo scan-build-18 reports false positive issue here -> do not analyze
                 *     ipsec_xvalid.c:2055:29: warning: 3rd function call argument is an
                 *     uninitialized value [core.CallAndMessage]
                 */
                if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                        if (modify_pon_test_buf(job_tab[idx].test_buf, job, job_tab[idx].pli,
                                                job_tab[idx].xgem_hdr) < 0)
                                return -1;
                }
#endif
                if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32)
                        modify_docsis_crc32_test_buf(job_tab[idx].test_buf, job,
                                                     job_tab[idx].buf_size);
        }

        return 0;
}

static void
set_job_ctx(struct job_ctx *ctx, const unsigned imix, const unsigned safe_check,
            const struct params_s *params, uint8_t *in_digest, uint8_t *out_digest,
            uint8_t tag_size, uint8_t *test_buf, uint8_t *src_dst_buf)
{
        ctx->in_digest = in_digest;
        ctx->out_digest = out_digest;
        ctx->tag_size_to_check = tag_size;
        ctx->test_buf = test_buf;
        ctx->src_dst_buf = src_dst_buf;

        /* Prepare buffer sizes */
        if (imix) {
                uint32_t random_num = rand() % DEFAULT_JOB_SIZE_MAX;

                /* If random number is 0, change the size to 16 */
                if (random_num == 0)
                        random_num = 16;

                /*
                 * CBC, CFB, CBCS and ECB operation modes do not support lengths
                 * which are non-multiple of block size
                 */
                if (params->cipher_mode == IMB_CIPHER_CBC ||
                    params->cipher_mode == IMB_CIPHER_CFB ||
                    params->cipher_mode == IMB_CIPHER_ECB ||
                    params->cipher_mode == IMB_CIPHER_CBCS_1_9) {
                        random_num += (IMB_AES_BLOCK_SIZE - 1);
                        random_num &= (~(IMB_AES_BLOCK_SIZE - 1));
                }

                if (params->cipher_mode == IMB_CIPHER_DES ||
                    params->cipher_mode == IMB_CIPHER_DES3) {
                        random_num += (IMB_DES_BLOCK_SIZE - 1);
                        random_num &= (~(IMB_DES_BLOCK_SIZE - 1));
                }

                if (params->cipher_mode == IMB_CIPHER_SM4_ECB ||
                    params->cipher_mode == IMB_CIPHER_SM4_CBC) {
                        random_num += (IMB_SM4_BLOCK_SIZE - 1);
                        random_num &= (~(IMB_SM4_BLOCK_SIZE - 1));
                }

                /*
                 * KASUMI-UIA1 needs to be at least 9 bytes
                 * (IV + direction bit + '1' + 0s to align to
                 * byte boundary)
                 */
                if (params->hash_alg == IMB_AUTH_KASUMI_UIA1)
                        if (random_num < (IMB_KASUMI_BLOCK_SIZE + 1))
                                random_num = 16;

                ctx->buf_size = random_num;
        } else
                ctx->buf_size = params->buf_size;

        if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                /* Buf size is XGEM payload, including CRC,
                 * allocate space for XGEM header and padding */
                ctx->pli = ctx->buf_size;
                ctx->buf_size += 8;
                if (ctx->buf_size < 16)
                        ctx->buf_size = 16;
                if (ctx->buf_size % 4)
                        ctx->buf_size = (ctx->buf_size + 3) & 0xfffffffc;
                /*
                 * Only first 4 bytes are checked, corresponding to BIP
                 */
                ctx->tag_size_to_check = 4;
        }

        if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                if (ctx->buf_size >=
                    (IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE + IMB_DOCSIS_CRC32_TAG_SIZE))
                        ctx->tag_size_to_check = IMB_DOCSIS_CRC32_TAG_SIZE;
                else
                        ctx->tag_size_to_check = 0;
        }

        if (safe_check)
                nosimd_memset(ctx->test_buf, pattern_plain_text, ctx->buf_size);
        else
                generate_random_buf(ctx->test_buf, ctx->buf_size);

        /* For PON, construct the XGEM header, setting valid PLI */
        if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                /* create XGEM header template */
                const uint16_t shifted_pli = (ctx->pli << 2) & 0xffff;
                uint64_t *p_src = (uint64_t *) ctx->test_buf;

                ctx->xgem_hdr = ((shifted_pli >> 8) & 0xff) | ((shifted_pli & 0xff) << 8);
                p_src[0] = ctx->xgem_hdr;
        }

        /* Randomize memory for output digest */
        generate_random_buf(ctx->out_digest, ctx->tag_size_to_check);
}

static int
process_jobs(IMB_MGR *mb_mgr, IMB_JOB *job_tab, const unsigned num_jobs,
             const struct params_s *params, struct job_ctx *job_ctx_tab,
             const char *avx_sse_text_submit, const char *avx_sse_text_flush, unsigned *err_idx)
{
        unsigned i;
        unsigned num_processed_jobs = 0;

        *err_idx = num_jobs;

        if (burst_api) {
                IMB_JOB *burst_jobs[IMB_MAX_BURST_SIZE];

                /* num_jobs will always be lower than IMB_MAX_BURST_SIZE */
                unsigned num_rx_jobs = IMB_GET_NEXT_BURST(mb_mgr, num_jobs, burst_jobs);

                if (num_rx_jobs != num_jobs) {
                        fprintf(stderr,
                                "Number of jobs received %u is different than requested %u\n",
                                num_rx_jobs, num_jobs);
                        return -1;
                }

                for (i = 0; i < num_jobs; i++)
                        *burst_jobs[i] = job_tab[i];

                num_rx_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, burst_jobs);

                avx_sse_check(avx_sse_text_submit, (unsigned) params->hash_alg,
                              (unsigned) params->cipher_mode);

                if (num_rx_jobs < num_jobs) {
                        num_rx_jobs += IMB_FLUSH_BURST(mb_mgr, (num_jobs - num_rx_jobs),
                                                       &burst_jobs[num_rx_jobs]);
                        avx_sse_check(avx_sse_text_flush, (unsigned) params->hash_alg,
                                      (unsigned) params->cipher_mode);
                }

                if (num_rx_jobs != num_jobs) {
                        fprintf(stderr,
                                "Number of processed jobs %u is different than submitted %u\n",
                                num_rx_jobs, num_jobs);
                        return -1;
                }

                for (i = 0; i < num_rx_jobs; i++)
                        if (post_job(mb_mgr, burst_jobs[i], &num_processed_jobs, params,
                                     job_ctx_tab, IMB_DIR_ENCRYPT) < 0) {
                                *err_idx = i;
                                return -1;
                        }

        } else {
                for (i = 0; i < num_jobs; i++) {
                        IMB_JOB *job = IMB_GET_NEXT_JOB(mb_mgr);

                        *job = job_tab[i];

                        job = IMB_SUBMIT_JOB(mb_mgr);

                        avx_sse_check(avx_sse_text_submit, (unsigned) params->hash_alg,
                                      (unsigned) params->cipher_mode);

                        if (job)
                                if (post_job(mb_mgr, job, &num_processed_jobs, params, job_ctx_tab,
                                             IMB_DIR_ENCRYPT) < 0) {
                                        *err_idx = (unsigned) ((uintptr_t) job->user_data);
                                        return -1;
                                }
                }
                /* Flush rest of the jobs, if there are outstanding jobs */
                while (num_processed_jobs != num_jobs) {
                        IMB_JOB *job = IMB_FLUSH_JOB(mb_mgr);

                        avx_sse_check(avx_sse_text_flush, (unsigned) params->hash_alg,
                                      (unsigned) params->cipher_mode);

                        while (job != NULL) {
                                if (post_job(mb_mgr, job, &num_processed_jobs, params, job_ctx_tab,
                                             IMB_DIR_ENCRYPT) < 0) {
                                        *err_idx = (unsigned) ((uintptr_t) job->user_data);
                                        return -1;
                                }

                                /* Get more completed jobs */
                                job = IMB_GET_COMPLETED_JOB(mb_mgr);
                        }
                }
        }

        return 0;
}

static void
print_fail_context(IMB_MGR *enc_mb_mgr, const IMB_ARCH enc_arch, IMB_MGR *dec_mb_mgr,
                   const IMB_ARCH dec_arch, const struct params_s *params, struct data *data,
                   const unsigned imix, const unsigned num_jobs, const unsigned idx,
                   const struct job_ctx *job_ctx_tab, const struct safe_check_ctx *safe_ctx)
{
        printf("Failures in\n");
        print_algo_info(params);
        printf("\nEncrypting ");
        print_tested_arch(enc_mb_mgr->features, enc_arch);
        printf("Decrypting ");
        print_tested_arch(dec_mb_mgr->features, dec_arch);
        /*
         * Print buffer size info if the failure was caused by an actual job,
         * where "idx" indicates the index of the job failing
         */
        if (idx < num_jobs) {
                if (imix) {
                        if (job_ctx_tab != NULL) {
                                printf("Job #%u, buffer size = %u\n", idx,
                                       job_ctx_tab[idx].buf_size);

                                for (unsigned n = 0; n < num_jobs; n++)
                                        printf("Other sizes = %u\n", job_ctx_tab[n].buf_size);
                        } else if (safe_ctx != NULL) {
                                printf("Job #%u, buffer size = %u\n", safe_ctx->job_idx,
                                       safe_ctx->job_size);
                        }
                } else
                        printf("Buffer size = %u\n", params->buf_size);
        }
        printf("Key size = %u\n", params->key_size);
        printf("Tag size = %u\n", data->tag_size);
        printf("AAD size = %u\n", (uint32_t) params->aad_size);
}

/*
 * @brief Performs test using AES_HMAC or DOCSIS
 * @return Operation status
 * @retval 0 success
 * @retval -1 encrypt/decrypt operation error (result mismatch, unsupported algorithm etc.)
 * @retval -2 safe check error
 */
static int
do_test(IMB_MGR *enc_mb_mgr, const IMB_ARCH enc_arch, IMB_MGR *dec_mb_mgr, const IMB_ARCH dec_arch,
        const struct params_s *params, struct data *data, struct safe_check_ctx *p_safe_check,
        const unsigned imix, const unsigned num_jobs)
{
        struct job_ctx job_ctx_tab[MAX_NUM_JOBS];
        IMB_JOB job_tab[MAX_NUM_JOBS];
        unsigned i;
        int ret = -1;
        struct cipher_auth_keys *enc_keys = &data->enc_keys;
        struct cipher_auth_keys *dec_keys = &data->dec_keys;
        uint8_t next_iv[IMB_AES_BLOCK_SIZE];
        const unsigned safe_check = (p_safe_check != NULL);

        if (num_jobs == 0)
                return ret;

        /* If performing a test searching for sensitive information,
         * set keys and plaintext to known values,
         * so they can be searched later on in the MB_MGR structure and stack.
         * Otherwise, just randomize the data */
        generate_random_buf(data->cipher_iv, MAX_IV_SIZE);
        generate_random_buf(data->auth_iv, MAX_IV_SIZE);
        generate_random_buf(data->aad, MAX_AAD_SIZE);
        if (safe_check) {
                nosimd_memset(data->ciph_key, pattern_cipher_key, MAX_KEY_SIZE);
                nosimd_memset(data->auth_key, pattern_auth_key, MAX_KEY_SIZE);
        } else {
                generate_random_buf(data->ciph_key, MAX_KEY_SIZE);
                generate_random_buf(data->auth_key, MAX_KEY_SIZE);
        }

        for (i = 0; i < num_jobs; i++)
                set_job_ctx(&job_ctx_tab[i], imix, safe_check, params, data->in_digest[i],
                            data->out_digest[i], data->tag_size, data->test_buf[i],
                            data->src_dst_buf[i]);

        /*
         * Expand/schedule keys.
         * If checking for sensitive information, first use actual
         * key expansion functions and check the stack for left over
         * information and then set a pattern in the expanded key memory
         * to search for later on.
         * If not checking for sensitive information, just use the key
         * expansion functions.
         */
        if (safe_check) {
                if (prepare_keys(enc_mb_mgr, enc_keys, data->ciph_key, data->auth_key, params, 0) <
                    0)
                        goto exit;

                if (perform_safe_checks(enc_mb_mgr, enc_arch, p_safe_check,
                                        "expanding encryption keys") < 0) {
                        p_safe_check->key_exp_phase = 1;
                        ret = -2;
                        goto exit;
                }

                if (prepare_keys(dec_mb_mgr, dec_keys, data->ciph_key, data->auth_key, params, 0) <
                    0)
                        goto exit;

                if (perform_safe_checks(dec_mb_mgr, dec_arch, p_safe_check,
                                        "expanding decryption keys") < 0) {
                        p_safe_check->key_exp_phase = 1;
                        ret = -2;
                        goto exit;
                }

                /*
                 * After testing key normal expansion functions,
                 * it is time to setup the keys and key schedules filled
                 * with specific patterns.
                 */
                if (prepare_keys(enc_mb_mgr, enc_keys, data->ciph_key, data->auth_key, params, 1) <
                    0)
                        goto exit;

                if (prepare_keys(dec_mb_mgr, dec_keys, data->ciph_key, data->auth_key, params, 1) <
                    0)
                        goto exit;
        } else {
                if (prepare_keys(enc_mb_mgr, enc_keys, data->ciph_key, data->auth_key, params, 0) <
                    0)
                        goto exit;

                if (prepare_keys(dec_mb_mgr, dec_keys, data->ciph_key, data->auth_key, params, 0) <
                    0)
                        goto exit;
        }

#ifdef PIN_BASED_CEC
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->enc_keys, sizeof(enc_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->dec_keys, sizeof(enc_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &enc_keys->gdata_key, sizeof(enc_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k1_expanded, sizeof(enc_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k2, sizeof(enc_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k3, sizeof(enc_keys->k3));

        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->enc_keys, sizeof(dec_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->dec_keys, sizeof(dec_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &dec_keys->gdata_key, sizeof(dec_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k1_expanded, sizeof(dec_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k2, sizeof(dec_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k3, sizeof(dec_keys->k3));
#endif

        /* Build encrypt job structures */
        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = &job_tab[i];

                /*
                 * Encrypt + generate digest from encrypted message
                 * using architecture under test
                 */
                nosimd_memcpy(job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].test_buf,
                              job_ctx_tab[i].buf_size);
                if (fill_job(job, params, job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].in_digest,
                             data->aad, job_ctx_tab[i].buf_size, data->tag_size, IMB_DIR_ENCRYPT,
                             enc_keys, data->cipher_iv, data->auth_iv, i, next_iv) < 0)
                        goto exit;

                /* Randomize memory for input digest */
                generate_random_buf(job_ctx_tab[i].in_digest, data->tag_size);

                if (burst_api)
                        imb_set_session(enc_mb_mgr, job);
        }

        /* Process encrypt operations */
        if (process_jobs(enc_mb_mgr, job_tab, num_jobs, params, job_ctx_tab, "enc-submit",
                         "enc-flush", &i) != 0)
                goto exit;

#ifdef PIN_BASED_CEC
        PinBasedCEC_ClearSecrets();
#endif

        /* Check that the registers, stack and MB_MGR do not contain any
         * sensitive information after job is returned
         */
        if (safe_check)
                if (perform_safe_checks(enc_mb_mgr, enc_arch, p_safe_check, "encrypting") < 0) {
                        ret = -2;
                        goto exit;
                }

#ifdef PIN_BASED_CEC
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->enc_keys, sizeof(enc_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->dec_keys, sizeof(enc_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &enc_keys->gdata_key, sizeof(enc_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k1_expanded, sizeof(enc_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k2, sizeof(enc_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) enc_keys->k3, sizeof(enc_keys->k3));

        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->enc_keys, sizeof(dec_keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->dec_keys, sizeof(dec_keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &dec_keys->gdata_key, sizeof(dec_keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k1_expanded, sizeof(dec_keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k2, sizeof(dec_keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) dec_keys->k3, sizeof(dec_keys->k3));
#endif

        /* Build decrypt job structures */
        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = &job_tab[i];

                /* Randomize memory for output digest */
                generate_random_buf(job_ctx_tab[i].out_digest, data->tag_size);

                /*
                 * Generate digest from encrypted message and decrypt
                 * using reference architecture
                 */
                if (fill_job(job, params, job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].out_digest,
                             data->aad, job_ctx_tab[i].buf_size, data->tag_size, IMB_DIR_DECRYPT,
                             dec_keys, data->cipher_iv, data->auth_iv, i, next_iv) < 0)
                        goto exit;

                if (burst_api)
                        imb_set_session(dec_mb_mgr, job);
        }

        /* Process decrypt operations */
        if (process_jobs(dec_mb_mgr, job_tab, num_jobs, params, job_ctx_tab, "dec-submit",
                         "dec-flush", &i) != 0)
                goto exit;

#ifdef PIN_BASED_CEC
        PinBasedCEC_ClearSecrets();
#endif
        /* Check that the registers, stack and MB_MGR do not contain any
         * sensitive information after job is returned */
        if (safe_check) {
                if (perform_safe_checks(dec_mb_mgr, dec_arch, p_safe_check, "decrypting") < 0) {
                        ret = -2;
                        goto exit;
                }
        } else {
                /*
                 * In safe check mode results are expected not to match.
                 * This is due to the fact that different arch implementations
                 * use various key formats. This is particularly visible with
                 * AES-GCM and its GHASH authentication function.
                 */
                for (i = 0; i < num_jobs; i++) {
                        int goto_exit = 0;

                        if (params->hash_alg != IMB_AUTH_NULL &&
                            memcmp(job_ctx_tab[i].in_digest, job_ctx_tab[i].out_digest,
                                   job_ctx_tab[i].tag_size_to_check) != 0) {
                                fprintf(stderr, "\nInput and output tags "
                                                "don't match\n");
                                hexdump(stdout, "Input digest", job_ctx_tab[i].in_digest,
                                        job_ctx_tab[i].tag_size_to_check);
                                hexdump(stdout, "Output digest", job_ctx_tab[i].out_digest,
                                        job_ctx_tab[i].tag_size_to_check);
                                goto_exit = 1;
                        }

                        if (params->cipher_mode != IMB_CIPHER_NULL &&
                            memcmp(job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].test_buf,
                                   job_ctx_tab[i].buf_size) != 0) {
                                fprintf(stderr, "\nDecrypted text and "
                                                "plaintext don't match\n");
                                hexdump(stdout, "Plaintext (orig)", job_ctx_tab[i].test_buf,
                                        job_ctx_tab[i].buf_size);
                                hexdump(stdout, "Decrypted msg", job_ctx_tab[i].src_dst_buf,
                                        job_ctx_tab[i].buf_size);
                                goto_exit = 1;
                        }

                        if ((params->hash_alg == IMB_AUTH_PON_CRC_BIP) &&
                            (job_ctx_tab[i].pli > 4)) {
                                const uint64_t plen = 8 + job_ctx_tab[i].pli - 4;

                                if (memcmp(job_ctx_tab[i].src_dst_buf + plen,
                                           job_ctx_tab[i].out_digest + 4, 4) != 0) {
                                        fprintf(stderr, "\nDecrypted CRC and "
                                                        "calculated CRC don't match\n");
                                        hexdump(stdout, "Decrypted CRC",
                                                job_ctx_tab[i].src_dst_buf + plen, 4);
                                        hexdump(stdout, "Calculated CRC",
                                                job_ctx_tab[i].out_digest + 4, 4);
                                        goto_exit = 1;
                                }
                        }

                        if (goto_exit)
                                goto exit;
                }
        }

        ret = 0;

exit:
        /* clear data */
        clear_data(data);

        if (ret == -1) {
                print_fail_context(enc_mb_mgr, enc_arch, dec_mb_mgr, dec_arch, params, data, imix,
                                   num_jobs, i, job_ctx_tab, NULL);
        } else if (ret == -2) {
                if (p_safe_check != NULL) {
                        /*
                         * Only set job info if the error is coming from an actual job,
                         * and not something else like key expansion
                         */
                        if (i < num_jobs) {
                                p_safe_check->job_idx = i;
                                p_safe_check->job_size = job_ctx_tab[i].buf_size;
                        }
                }
        }

        return ret;
}

static void
test_single(IMB_MGR *enc_mgr, const IMB_ARCH enc_arch, IMB_MGR *dec_mgr, const IMB_ARCH dec_arch,
            struct params_s *params, struct data *variant_data, const uint32_t buf_size,
            const unsigned int safe_check)
{
        unsigned int i;
        unsigned int num_tag_sizes = 0;
        uint8_t tag_sizes[NUM_TAG_SIZES];
        uint64_t min_aad_sz = 0;
        uint64_t max_aad_sz, aad_sz;

        if (params->hash_alg >= IMB_AUTH_NUM) {
                if (verbose) {
                        fprintf(stderr, "Invalid hash alg\n");
                        printf("FAIL\n");
                }
                exit(EXIT_FAILURE);
        }

        if (params->cipher_mode == IMB_CIPHER_GCM)
                max_aad_sz = MAX_GCM_AAD_SIZE;
        else if (params->cipher_mode == IMB_CIPHER_CCM)
                max_aad_sz = MAX_CCM_AAD_SIZE;
        else
                max_aad_sz = 0;

        /* If tag size is defined by user, only test this size */
        if (auth_tag_size != 0) {
                tag_sizes[0] = auth_tag_size;
                num_tag_sizes = 1;
        } else {
                /* If CCM, test all tag sizes supported (4,6,8,10,12,14,16) */
                if (params->hash_alg == IMB_AUTH_AES_CCM) {
                        for (i = 4; i <= 16; i += 2)
                                tag_sizes[num_tag_sizes++] = i;
                        /* If ZUC-EIA3-256, test all tag sizes supported (4,8,16) */
                } else if (params->hash_alg == IMB_AUTH_ZUC256_EIA3_BITLEN) {
                        for (i = 4; i <= 16; i *= 2)
                                tag_sizes[num_tag_sizes++] = i;
                } else {
                        tag_sizes[0] = auth_tag_len_bytes[params->hash_alg - 1];
                        num_tag_sizes = 1;
                }
        }

        for (i = 0; i < num_tag_sizes; i++) {
                variant_data->tag_size = tag_sizes[i];

                for (aad_sz = min_aad_sz; aad_sz <= max_aad_sz; aad_sz++) {
                        params->aad_size = aad_sz;
                        params->buf_size = buf_size;

                        /*
                         * CBC, CFB, CBCS and ECB operation modes do not support lengths
                         * which are non-multiple of block size
                         */
                        if (params->cipher_mode == IMB_CIPHER_CBC ||
                            params->cipher_mode == IMB_CIPHER_CFB ||
                            params->cipher_mode == IMB_CIPHER_ECB ||
                            params->cipher_mode == IMB_CIPHER_CBCS_1_9)
                                if ((buf_size % IMB_AES_BLOCK_SIZE) != 0)
                                        continue;

                        if (params->cipher_mode == IMB_CIPHER_SM4_ECB ||
                            params->cipher_mode == IMB_CIPHER_SM4_CBC)
                                if ((buf_size % IMB_SM4_BLOCK_SIZE) != 0)
                                        continue;

                        if (params->cipher_mode == IMB_CIPHER_DES ||
                            params->cipher_mode == IMB_CIPHER_DES3)
                                if ((buf_size % IMB_DES_BLOCK_SIZE) != 0)
                                        continue;

                        /*
                         * KASUMI-UIA1 needs to be at least 9 bytes
                         * (IV + direction bit + '1' + 0s to align to
                         * byte boundary)
                         */
                        if (params->hash_alg == IMB_AUTH_KASUMI_UIA1)
                                if (buf_size < (IMB_KASUMI_BLOCK_SIZE + 1))
                                        continue;

                        /* Check for sensitive data first, then normal cross
                         * architecture validation */
                        if (safe_check) {
                                struct safe_check_ctx safe_ctx1 = { 0 };
                                const int result1 = do_test(enc_mgr, enc_arch, dec_mgr, dec_arch,
                                                            params, variant_data, &safe_ctx1, 0, 1);
                                if (result1 == -2) {
                                        generate_patterns();

                                        struct safe_check_ctx safe_ctx2 = { 0 };
                                        const int result2 =
                                                do_test(enc_mgr, enc_arch, dec_mgr, dec_arch,
                                                        params, variant_data, &safe_ctx2, 0, 1);

                                        if (result2 == -2 &&
                                            compare_match(&safe_ctx1, &safe_ctx2) == 0) {
                                                printf("FAIL\n");
                                                print_patterns();
                                                print_fail_context(enc_mgr, enc_arch, dec_mgr,
                                                                   dec_arch, params, variant_data,
                                                                   0, 1, 0, NULL, &safe_ctx2);
                                                print_match(&safe_ctx2, safe_ctx2.dir_name);
                                                exit(EXIT_FAILURE);
                                        }
                                }
                        } else {
                                if (do_test(enc_mgr, enc_arch, dec_mgr, dec_arch, params,
                                            variant_data, NULL, 0, 1) < 0)
                                        exit(EXIT_FAILURE);
                        }
                }
        }
}

/* Runs test for each buffer size */
static void
process_variant(IMB_MGR *enc_mgr, const IMB_ARCH enc_arch, IMB_MGR *dec_mgr,
                const IMB_ARCH dec_arch, struct params_s *params, struct data *variant_data,
                const unsigned int safe_check)
{
#ifdef PIN_BASED_CEC
        const uint32_t sizes = job_sizes[RANGE_MAX];
#else
        const uint32_t sizes = params->num_sizes;
#endif
        uint32_t sz;

        if (verbose) {
                printf("[INFO] ");
                print_algo_info(params);
        }

        /* Reset the variant data */
        clear_data(variant_data);

        for (sz = 0; sz < sizes; sz++) {
#ifdef PIN_BASED_CEC
                const uint32_t buf_size = job_sizes[RANGE_MIN];
#else
                const uint32_t buf_size = job_sizes[RANGE_MIN] + (sz * job_sizes[RANGE_STEP]);
#endif

                test_single(enc_mgr, enc_arch, dec_mgr, dec_arch, params, variant_data, buf_size,
                            safe_check);
        }

        /* Perform IMIX tests */
        if (imix_enabled) {
                unsigned int i, j;

                params->aad_size = 0;

                for (i = 2; i <= max_num_jobs; i++) {
                        for (j = 0; j < IMIX_ITER; j++) {
                                if (do_test(enc_mgr, enc_arch, dec_mgr, dec_arch, params,
                                            variant_data, 0, 1, i) < 0) {
                                        printf("FAIL\n");
                                        exit(EXIT_FAILURE);
                                }
                        }
                }
        }
        if (verbose)
                printf("PASS\n");
}

/* Sets cipher direction and key size  */
static void
run_test(const IMB_ARCH enc_arch, const IMB_ARCH dec_arch, struct params_s *params,
         struct data *variant_data, const unsigned int safe_check)
{
        IMB_MGR *enc_mgr = NULL;
        IMB_MGR *dec_mgr = NULL;

        enc_mgr = alloc_mb_mgr(flags);

        if (enc_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        switch (enc_arch) {
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(enc_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(enc_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(enc_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                exit(EXIT_FAILURE);
        }

        if (enc_mgr->features & IMB_FEATURE_SELF_TEST)
                if (!(enc_mgr->features & IMB_FEATURE_SELF_TEST_PASS))
                        fprintf(stderr, "SELF-TEST: FAIL\n");

        if (imb_get_errno(enc_mgr) != 0) {
                fprintf(stderr, "Error initializing enc MB_MGR structure! %s\n",
                        imb_get_strerror(imb_get_errno(enc_mgr)));
                exit(EXIT_FAILURE);
        }

        printf("Encrypting ");
        print_tested_arch(enc_mgr->features, enc_arch);

        dec_mgr = alloc_mb_mgr(flags);

        if (dec_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        switch (dec_arch) {
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(dec_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(dec_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(dec_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                exit(EXIT_FAILURE);
        }

        if (dec_mgr->features & IMB_FEATURE_SELF_TEST)
                if (!(dec_mgr->features & IMB_FEATURE_SELF_TEST_PASS))
                        fprintf(stderr, "SELF-TEST: FAIL\n");

        if (imb_get_errno(dec_mgr) != 0) {
                fprintf(stderr, "Error initializing dec MB_MGR structure! %s\n",
                        imb_get_strerror(imb_get_errno(dec_mgr)));
                exit(EXIT_FAILURE);
        }

        printf("Decrypting ");
        print_tested_arch(dec_mgr->features, dec_arch);

        if (custom_test) {
                params->key_size = custom_job_params.key_size;
                params->cipher_mode = custom_job_params.cipher_mode;
                params->hash_alg = custom_job_params.hash_alg;
                process_variant(enc_mgr, enc_arch, dec_mgr, dec_arch, params, variant_data,
                                safe_check);
                goto exit;
        }

        IMB_CIPHER_MODE c_mode;

        for (c_mode = IMB_CIPHER_CBC; c_mode < IMB_CIPHER_NUM; c_mode++) {
                IMB_HASH_ALG hash_alg;

                /* Skip IMB_CIPHER_CUSTOM */
                if (c_mode == IMB_CIPHER_CUSTOM)
                        continue;

                params->cipher_mode = c_mode;

                for (hash_alg = IMB_AUTH_HMAC_SHA_1; hash_alg < IMB_AUTH_NUM; hash_alg++) {
                        /* Skip IMB_AUTH_CUSTOM */
                        if (hash_alg == IMB_AUTH_CUSTOM)
                                continue;

                        /* Skip not supported combinations */
                        if ((c_mode == IMB_CIPHER_GCM && hash_alg != IMB_AUTH_AES_GMAC) ||
                            (c_mode != IMB_CIPHER_GCM && hash_alg == IMB_AUTH_AES_GMAC))
                                continue;
                        if ((c_mode == IMB_CIPHER_CCM && hash_alg != IMB_AUTH_AES_CCM) ||
                            (c_mode != IMB_CIPHER_CCM && hash_alg == IMB_AUTH_AES_CCM))
                                continue;
                        if ((c_mode == IMB_CIPHER_SM4_GCM && hash_alg != IMB_AUTH_SM4_GCM) ||
                            (c_mode != IMB_CIPHER_SM4_GCM && hash_alg == IMB_AUTH_SM4_GCM))
                                continue;
                        if ((c_mode == IMB_CIPHER_PON_AES_CNTR &&
                             hash_alg != IMB_AUTH_PON_CRC_BIP) ||
                            (c_mode != IMB_CIPHER_PON_AES_CNTR && hash_alg == IMB_AUTH_PON_CRC_BIP))
                                continue;
                        if (c_mode == IMB_CIPHER_DOCSIS_SEC_BPI &&
                            (hash_alg != IMB_AUTH_NULL && hash_alg != IMB_AUTH_DOCSIS_CRC32))
                                continue;
                        if (c_mode != IMB_CIPHER_DOCSIS_SEC_BPI &&
                            hash_alg == IMB_AUTH_DOCSIS_CRC32)
                                continue;
                        if ((c_mode == IMB_CIPHER_CHACHA20_POLY1305 &&
                             hash_alg != IMB_AUTH_CHACHA20_POLY1305) ||
                            (c_mode != IMB_CIPHER_CHACHA20_POLY1305 &&
                             hash_alg == IMB_AUTH_CHACHA20_POLY1305))
                                continue;

                        if ((c_mode == IMB_CIPHER_SNOW_V_AEAD &&
                             hash_alg != IMB_AUTH_SNOW_V_AEAD) ||
                            (c_mode != IMB_CIPHER_SNOW_V_AEAD && hash_alg == IMB_AUTH_SNOW_V_AEAD))
                                continue;

                        /* This test app does not support SGL yet */
                        if ((c_mode == IMB_CIPHER_CHACHA20_POLY1305_SGL) ||
                            (hash_alg == IMB_AUTH_CHACHA20_POLY1305_SGL))
                                continue;

                        if ((c_mode == IMB_CIPHER_GCM_SGL) || (hash_alg == IMB_AUTH_GCM_SGL))
                                continue;

                        params->hash_alg = hash_alg;

                        uint8_t min_sz = key_sizes[c_mode - 1][0];
                        uint8_t max_sz = key_sizes[c_mode - 1][1];
                        uint8_t step_sz = key_sizes[c_mode - 1][2];
                        uint8_t key_sz;

                        for (key_sz = min_sz; key_sz <= max_sz; key_sz += step_sz) {
                                params->key_size = key_sz;
                                process_variant(enc_mgr, enc_arch, dec_mgr, dec_arch, params,
                                                variant_data, safe_check);
                        }
                }
        }

exit:
        free_mb_mgr(enc_mgr);
        free_mb_mgr(dec_mgr);
}

/* Prepares data structure for test variants storage,
 * sets test configuration
 */
static void
run_tests(const unsigned int safe_check)
{
        struct params_s params;
        struct data *variant_data = NULL;
        IMB_ARCH enc_arch, dec_arch;
#ifdef PIN_BASED_CEC
        const uint32_t pkt_size = job_sizes[RANGE_MIN];
        const uint32_t num_iter = job_sizes[RANGE_MAX];
#else
        const uint32_t min_size = job_sizes[RANGE_MIN];
        const uint32_t max_size = job_sizes[RANGE_MAX];
        const uint32_t step_size = job_sizes[RANGE_STEP];
#endif

#ifdef PIN_BASED_CEC
        params.num_sizes = 1;
#else
        params.num_sizes = ((max_size - min_size) / step_size) + 1;
#endif
        variant_data = malloc(sizeof(struct data));

        if (variant_data == NULL) {
                fprintf(stderr, "Test data could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        if (verbose) {
#ifdef PIN_BASED_CEC
                printf("Testing buffer size = %u bytes, %u times\n", pkt_size, num_iter);
#else
                if (min_size == max_size)
                        printf("Testing buffer size = %u bytes\n", min_size);
                else
                        printf("Testing buffer sizes from %u to %u "
                               "in steps of %u bytes\n",
                               min_size, max_size, step_size);
#endif
        }
        /* Performing tests for each selected architecture */
        for (enc_arch = IMB_ARCH_SSE; enc_arch < IMB_ARCH_NUM; enc_arch++) {
                if (enc_archs[enc_arch] == 0)
                        continue;
                for (dec_arch = IMB_ARCH_SSE; dec_arch < IMB_ARCH_NUM; dec_arch++) {
                        if (dec_archs[dec_arch] == 0)
                                continue;
                        run_test(enc_arch, dec_arch, &params, variant_data, safe_check);
                }

        } /* end for run */

        free(variant_data);
}

static void
usage(const char *app_name)
{
        fprintf(stderr,
                "Usage: %s [args], "
                "where args are zero or more\n"
                "-h: print this message\n"
                "-v: verbose, prints extra information\n"
                "--enc-arch: encrypting with architecture "
                "(SSE/AVX/AVX2/AVX512)\n"
                "--dec-arch: decrypting with architecture "
                "(SSE/AVX/AVX2/AVX512)\n"
                "--cipher-algo: Select cipher algorithm to run on the custom "
                "test\n"
                "--hash-algo: Select hash algorithm to run on the custom test\n"
                "--aead-algo: Select AEAD algorithm to run on the custom test\n"
                "--no-avx512: Don't do AVX512\n"
                "--no-avx2: Don't do AVX2\n"
                "--no-avx: Don't do AVX\n"
                "--no-sse: Don't do SSE\n"
                "--shani-on: use SHA extensions, default: auto-detect\n"
                "--shani-off: don't use SHA extensions\n"
                "--gfni-on: use Galois Field extensions, default: auto-detect\n"
                "--gfni-off: don't use Galois Field extensions\n"
                "--cipher-iv-size: size of cipher IV.\n"
                "--auth-iv-size: size of authentication IV.\n"
                "--tag-size: size of authentication tag\n"
                "--job-size: size of the cipher & MAC job in bytes. "
#ifndef PIN_BASED_CEC
                "It can be:\n"
                "            - single value: test single size\n"
                "            - range: test multiple sizes with following format"
                " min:step:max (e.g. 16:16:256)\n"
#else
                "            - size:1:num_iterations format\n"
                "              e.g. 64:1:128 => repeat 128 times operation on a 64 byte buffer\n"
#endif
                "--num-jobs: maximum number of number of jobs to submit in one go "
                "(maximum = %d)\n"
                "--safe-check: check if keys, IVs, plaintext or tags "
                "get cleared from IMB_MGR upon job completion (off by default; "
                "requires library compiled with SAFE_DATA)\n"
                "--avx-sse: if XGETBV is available then check for potential "
                "AVX-SSE transition problems\n"
                "--burst-api: use burst API instead of single job API\n"
                "--offset: offset in bytes where the plaintext will be placed from the start of "
                "the allocated buffer (default 4 bytes)",
                app_name, MAX_NUM_JOBS);
}

static int
get_next_num_arg(const char *const *argv, const int index, const int argc, void *dst,
                 const size_t dst_size)
{
        char *endptr = NULL;
        uint64_t val;

        if (dst == NULL || argv == NULL || index < 0 || argc < 0) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        if (index >= (argc - 1)) {
                fprintf(stderr, "'%s' requires an argument!\n", argv[index]);
                exit(EXIT_FAILURE);
        }

#ifdef _WIN32
        val = _strtoui64(argv[index + 1], &endptr, 0);
#else
        val = strtoull(argv[index + 1], &endptr, 0);
#endif
        if (endptr == argv[index + 1] || (endptr != NULL && *endptr != '\0')) {
                fprintf(stderr, "Error converting '%s' as value for '%s'!\n", argv[index + 1],
                        argv[index]);
                exit(EXIT_FAILURE);
        }

        switch (dst_size) {
        case (sizeof(uint8_t)):
                *((uint8_t *) dst) = (uint8_t) val;
                break;
        case (sizeof(uint16_t)):
                *((uint16_t *) dst) = (uint16_t) val;
                break;
        case (sizeof(uint32_t)):
                *((uint32_t *) dst) = (uint32_t) val;
                break;
        case (sizeof(uint64_t)):
                *((uint64_t *) dst) = val;
                break;
        default:
                fprintf(stderr, "%s() invalid dst_size %u!\n", __func__, (unsigned) dst_size);
                exit(EXIT_FAILURE);
                break;
        }

        return index + 1;
}

/*
 * Check string argument is supported and if it is, return values associated
 * with it.
 */
static const union params *
check_string_arg(const char *param, const char *arg, const struct str_value_mapping *map,
                 const unsigned int num_avail_opts)
{
        unsigned int i;

        if (arg == NULL) {
                fprintf(stderr, "%s requires an argument\n", param);
                goto exit;
        }

        for (i = 0; i < num_avail_opts; i++)
                if (strcasecmp(arg, map[i].name) == 0)
                        return &(map[i].values);

        /* Argument is not listed in the available options */
        fprintf(stderr, "Invalid argument for %s\n", param);
exit:
        fprintf(stderr, "Accepted arguments: ");
        for (i = 0; i < num_avail_opts; i++)
                fprintf(stderr, "%s ", map[i].name);
        fprintf(stderr, "\n");

        return NULL;
}

static int
parse_range(const char *const *argv, const int index, const int argc,
            uint32_t range_values[NUM_RANGE])
{
        char *token;
        uint32_t number;
        unsigned int i;

        if (range_values == NULL || argv == NULL || index < 0 || argc < 0) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        if (index >= (argc - 1)) {
                fprintf(stderr, "'%s' requires an argument!\n", argv[index]);
                exit(EXIT_FAILURE);
        }

        char *copy_arg = strdup(argv[index + 1]);

        if (copy_arg == NULL) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        errno = 0;
        token = strtok(copy_arg, ":");

        /* Try parsing range (minimum, step and maximum values) */
        for (i = 0; i < NUM_RANGE; i++) {
                if (token == NULL)
                        goto no_range;

                number = strtoul(token, NULL, 10);

                if (errno != 0)
                        goto no_range;

                range_values[i] = number;
                token = strtok(NULL, ":");
        }

        if (token != NULL)
                goto no_range;

#ifndef PIN_BASED_CEC
        if (range_values[RANGE_MAX] < range_values[RANGE_MIN]) {
                fprintf(stderr, "Maximum value of range cannot be lower "
                                "than minimum value\n");
                exit(EXIT_FAILURE);
        }

        if (range_values[RANGE_STEP] == 0) {
                fprintf(stderr, "Step value in range cannot be 0\n");
                exit(EXIT_FAILURE);
        }
#endif
        goto end_range;
no_range:
        /* Try parsing as single value */
        get_next_num_arg(argv, index, argc, &job_sizes[RANGE_MIN], sizeof(job_sizes[RANGE_MIN]));

        job_sizes[RANGE_MAX] = job_sizes[RANGE_MIN];

end_range:
        free(copy_arg);
        return (index + 1);
}

int
main(int argc, char *argv[])
{
        int i;
        unsigned int arch_id;
        uint8_t arch_support[IMB_ARCH_NUM];
        const union params *values;
        unsigned int cipher_algo_set = 0;
        unsigned int hash_algo_set = 0;
        unsigned int aead_algo_set = 0;
        unsigned int safe_check = 0;

        for (i = 1; i < argc; i++)
                if (strcmp(argv[i], "-h") == 0) {
                        usage(argv[0]);
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "-v") == 0) {
                        verbose = 1;
                } else if (update_flags_and_archs(argv[i], enc_archs, &flags)) {
                        if (!update_flags_and_archs(argv[i], dec_archs, &flags)) {
                                fprintf(stderr, "Same archs should be available\n");
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--enc-arch") == 0) {

                        /* Use index 1 to skip arch_str_map.name = "NONE" */
                        values = check_string_arg(argv[i], argv[i + 1], arch_str_map + 1,
                                                  DIM(arch_str_map) - 1);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        nosimd_memset(enc_archs, 0, sizeof(enc_archs));
                        enc_archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--dec-arch") == 0) {
                        /* Use index 1 to skip arch_str_map.name = "NONE" */
                        values = check_string_arg(argv[i], argv[i + 1], arch_str_map + 1,
                                                  DIM(arch_str_map) - 1);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        nosimd_memset(dec_archs, 0, sizeof(dec_archs));
                        dec_archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--cipher-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], cipher_algo_str_map,
                                                  DIM(cipher_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode = values->job_params.cipher_mode;
                        custom_job_params.key_size = values->job_params.key_size;
                        custom_test = 1;
                        cipher_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--hash-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], hash_algo_str_map,
                                                  DIM(hash_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.hash_alg = values->job_params.hash_alg;
                        custom_test = 1;
                        hash_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--aead-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], aead_algo_str_map,
                                                  DIM(aead_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode = values->job_params.cipher_mode;
                        custom_job_params.key_size = values->job_params.key_size;
                        custom_job_params.hash_alg = values->job_params.hash_alg;
                        custom_test = 1;
                        aead_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--job-size") == 0) {
                        /* Try parsing the argument as a range first */
                        i = parse_range((const char *const *) argv, i, argc, job_sizes);
                        if (job_sizes[RANGE_MAX] > JOB_SIZE_TOP) {
                                fprintf(stderr, "Invalid job size %u (max %d)\n",
                                        (unsigned) job_sizes[RANGE_MAX], JOB_SIZE_TOP);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--cipher-iv-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &cipher_iv_size,
                                             sizeof(cipher_iv_size));
                        if (cipher_iv_size > MAX_IV_SIZE) {
                                fprintf(stderr,
                                        "IV size cannot be "
                                        "higher than %d\n",
                                        MAX_IV_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--auth-iv-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &auth_iv_size,
                                             sizeof(auth_iv_size));
                        if (auth_iv_size > MAX_IV_SIZE) {
                                fprintf(stderr,
                                        "IV size cannot be "
                                        "higher than %d\n",
                                        MAX_IV_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--tag-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &auth_tag_size,
                                             sizeof(auth_tag_size));
                        if (auth_tag_size > MAX_TAG_SIZE) {
                                fprintf(stderr,
                                        "Tag size cannot be "
                                        "higher than %d\n",
                                        MAX_TAG_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--num-jobs") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &max_num_jobs,
                                             sizeof(max_num_jobs));
                        if (max_num_jobs > MAX_NUM_JOBS) {
                                fprintf(stderr,
                                        "Number of jobs cannot be "
                                        "higher than %d\n",
                                        MAX_NUM_JOBS);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--safe-check") == 0) {
                        safe_check = 1;
                } else if (strcmp(argv[i], "--safe-retries") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &safe_retries,
                                             sizeof(safe_retries));
                        if (safe_retries > MAX_SAFE_RETRIES) {
                                fprintf(stderr,
                                        "Number of retries cannot be "
                                        "higher than %d\n",
                                        MAX_SAFE_RETRIES);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--imix") == 0) {
                        imix_enabled = 1;
                } else if (strcmp(argv[i], "--avx-sse") == 0) {
                        is_avx_sse_check_possible = avx_sse_detectability();
                        if (!is_avx_sse_check_possible)
                                fprintf(stderr, "XGETBV not available\n");
                } else if (strcmp(argv[i], "--burst-api") == 0) {
                        burst_api = 1;
                } else if (strcmp(argv[i], "--offset") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &offset,
                                             sizeof(offset));
                } else {
                        usage(argv[0]);
                        return EXIT_FAILURE;
                }

        if (custom_test) {
                if (aead_algo_set && (cipher_algo_set || hash_algo_set)) {
                        fprintf(stderr, "AEAD algorithm cannot be used "
                                        "combined with another cipher/hash "
                                        "algorithm\n");
                        return EXIT_FAILURE;
                }
        }

        if (job_sizes[RANGE_MIN] == 0) {
                fprintf(stderr, "Buffer size cannot be 0 unless only "
                                "an AEAD algorithm is tested\n");
                return EXIT_FAILURE;
        }

        /* detect available architectures and features*/
        if (detect_arch(arch_support) < 0)
                return EXIT_FAILURE;

        /* disable tests depending on instruction sets supported */
        for (arch_id = IMB_ARCH_SSE; arch_id < IMB_ARCH_NUM; arch_id++) {
                if (arch_support[arch_id] == 0) {
                        enc_archs[arch_id] = 0;
                        dec_archs[arch_id] = 0;
                        fprintf(stderr, "%s not supported. Disabling %s tests\n",
                                arch_str_map[arch_id].name, arch_str_map[arch_id].name);
                }
        }

        IMB_MGR *p_mgr = alloc_mb_mgr(flags);

        if (p_mgr == NULL) {
                fprintf(stderr, "Error allocating MB_MGR structure!\n");
                return EXIT_FAILURE;
        }

        if (safe_check && ((p_mgr->features & IMB_FEATURE_SAFE_DATA) == 0)) {
                fprintf(stderr, "Library needs to be compiled with SAFE_DATA "
                                "if --safe-check is enabled\n");
                free_mb_mgr(p_mgr);
                return EXIT_FAILURE;
        }
        free_mb_mgr(p_mgr);

        srand(SEED);

        if (safe_check)
                generate_patterns();

        run_tests(safe_check);

        fprintf(stdout, "All tests passed\n");

        return EXIT_SUCCESS;
}
