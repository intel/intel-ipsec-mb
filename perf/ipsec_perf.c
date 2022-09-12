/**********************************************************************
  Copyright(c) 2017-2022, Intel Corporation All rights reserved.

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
#include <signal.h>
#include <sys/time.h>
#endif

#ifdef _WIN32
#include <malloc.h> /* memalign() or _aligned_malloc()/aligned_free() */
#include <windows.h>
#include <process.h>
#include <intrin.h>
#define strdup _strdup
#undef __forceinline
#define __forceinline static __forceinline
#define __func__ __FUNCTION__
#define strcasecmp _stricmp
#else
#include <stdlib.h>
#include <x86intrin.h>
#define __forceinline static inline __attribute__((always_inline))
#include <unistd.h>
#include <pthread.h>
#if defined (__FreeBSD__)
#include <sys/cpuset.h>
typedef cpuset_t cpu_set_t;
#else
#include <sched.h>
#endif
#endif

#include <intel-ipsec-mb.h>

#include "msr.h"
#include "misc.h"

/* memory size for test buffers */
#define BUFSIZE (512 * 1024 * 1024)
/* maximum size of a test buffer */
#define JOB_SIZE_TOP (16 * 1024)
/* min size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MIN 16
/* max size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MAX (2 * 1024)
/* number of bytes to increase buffer size when testing range of buffers */
#define DEFAULT_JOB_SIZE_STEP 16
/* max number of elements in list */
#define MAX_LIST 32
/* max offset applied to a buffer - this is to avoid collisions in L1 */
#define MAX_BUFFER_OFFSET 4096
/* max value of sha_size_incr */
#define MAX_SHA_SIZE_INCR  128
/* region size for one buffer rounded up to 4K page size */
#define REGION_SIZE (((JOB_SIZE_TOP + (MAX_BUFFER_OFFSET + \
                                       MAX_SHA_SIZE_INCR)) + 4095) & (~4095))
/* number of test buffers */
#define NUM_OFFSETS (BUFSIZE / REGION_SIZE)
#define NUM_RUNS 16
/* maximum number of 128-bit expanded keys */
#define KEYS_PER_JOB 15

#define AAD_SIZE_MAX JOB_SIZE_TOP
#define CCM_AAD_SIZE_MAX 46
#define DEFAULT_GCM_AAD_SIZE 12
#define DEFAULT_CCM_AAD_SIZE 8
#define DEFAULT_CHACHA_POLY_AAD_SIZE 12
#define DEFAULT_SNOW_V_AEAD_AAD_SIZE 16

#define ITER_SCALE_SMOKE 2048
#define ITER_SCALE_SHORT 200000
#define ITER_SCALE_LONG  2000000

#define BITS(x) (sizeof(x) * 8)
#define DIM(x) (sizeof(x)/sizeof(x[0]))
#define DIV_ROUND_UP(x, y) ((x + y - 1) / y)

#define MAX_NUM_THREADS 16 /* Maximum number of threads that can be created */

#define IA32_MSR_FIXED_CTR_CTRL      0x38D
#define IA32_MSR_PERF_GLOBAL_CTR     0x38F
#define IA32_MSR_CPU_UNHALTED_THREAD 0x30A

#define DEFAULT_BURST_SIZE 32
#define MAX_BURST_SIZE 256

enum arch_type_e {
        ARCH_SSE = 0,
        ARCH_AVX,
        ARCH_AVX2,
        ARCH_AVX512,
        NUM_ARCHS
};

/* This enum will be mostly translated to IMB_CIPHER_MODE
 * (make sure to update c_mode_names list in print_times function)  */
enum test_cipher_mode_e {
        TEST_CBC = 1,
        TEST_CNTR,
        TEST_CNTR8, /* CNTR with increased buffer by 8 */
        TEST_CNTR_BITLEN, /* CNTR-BITLEN */
        TEST_CNTR_BITLEN4, /* CNTR-BITLEN with 4 less bits in the last byte */
        TEST_ECB,
        TEST_CBCS_1_9,
        TEST_NULL_CIPHER,
        TEST_AESDOCSIS,
        TEST_AESDOCSIS8, /* AES DOCSIS with increased buffer size by 8 */
        TEST_DESDOCSIS,
        TEST_DESDOCSIS4, /* DES DOCSIS with increased buffer size by 4 */
        TEST_GCM, /* Additional field used by GCM, not translated */
        TEST_CCM,
        TEST_DES,
        TEST_3DES,
        TEST_PON_CNTR,
        TEST_PON_NO_CNTR,
        TEST_ZUC_EEA3,
        TEST_SNOW3G_UEA2,
        TEST_KASUMI_UEA1,
        TEST_CHACHA20,
        TEST_AEAD_CHACHA20,
        TEST_SNOW_V,
        TEST_SNOW_V_AEAD,
        TEST_NUM_CIPHER_TESTS
};

/* This enum will be mostly translated to IMB_HASH_ALG
 * (make sure to update h_alg_names list in print_times function)  */
enum test_hash_alg_e {
        TEST_SHA1_HMAC = 1,
        TEST_SHA_224_HMAC,
        TEST_SHA_256_HMAC,
        TEST_SHA_384_HMAC,
        TEST_SHA_512_HMAC,
        TEST_XCBC,
        TEST_MD5,
        TEST_HASH_CMAC, /* added here to be included in AES tests */
        TEST_SHA1,
        TEST_SHA_224,
        TEST_SHA_256,
        TEST_SHA_384,
        TEST_SHA_512,
        TEST_HASH_CMAC_BITLEN,
        TEST_HASH_CMAC_256,
        TEST_NULL_HASH,
        TEST_DOCSIS_CRC32,
        TEST_HASH_GCM, /* Additional field used by GCM, not translated */
        TEST_CUSTOM_HASH, /* unused */
        TEST_HASH_CCM,
        TEST_PON_CRC_BIP,
        TEST_ZUC_EIA3,
        TEST_SNOW3G_UIA2,
        TEST_KASUMI_UIA1,
        TEST_AES_GMAC_128,
        TEST_AES_GMAC_192,
        TEST_AES_GMAC_256,
        TEST_HASH_POLY1305,
        TEST_AEAD_POLY1305,
        TEST_ZUC256_EIA3,
        TEST_AUTH_SNOW_V_AEAD,
        TEST_CRC32_ETHERNET_FCS,
        TEST_CRC32_SCTP,
        TEST_CRC32_WIMAX_OFDMA_DATA,
        TEST_CRC24_LTE_A,
        TEST_CRC24_LTE_B,
        TEST_CRC16_X25,
        TEST_CRC16_FP_DATA,
        TEST_CRC11_FP_HEADER,
        TEST_CRC10_IUUP_DATA,
        TEST_CRC8_WIMAX_OFDMA_HCS,
        TEST_CRC7_FP_HEADER,
        TEST_CRC6_IUUP_HEADER,
        TEST_AUTH_GHASH,
        TEST_NUM_HASH_TESTS
};

/* Struct storing cipher parameters */
struct params_s {
        IMB_CIPHER_DIRECTION	cipher_dir;
        enum test_cipher_mode_e	cipher_mode;
        enum test_hash_alg_e	hash_alg;
        uint32_t		aes_key_size;
        uint32_t		size_aes;
        uint64_t		aad_size;
        uint32_t		num_sizes;
        uint32_t                core;
};

struct custom_job_params {
        enum test_cipher_mode_e cipher_mode;
        enum test_hash_alg_e    hash_alg;
        uint32_t                aes_key_size;
        IMB_CIPHER_DIRECTION    cipher_dir;
};

union params {
        enum arch_type_e         arch_type;
        struct custom_job_params job_params;
};

struct str_value_mapping {
        const char      *name;
        union params    values;
};

const struct str_value_mapping arch_str_map[] = {
        {.name = "SSE",    .values.arch_type = ARCH_SSE },
        {.name = "AVX",    .values.arch_type = ARCH_AVX },
        {.name = "AVX2",   .values.arch_type = ARCH_AVX2 },
        {.name = "AVX512", .values.arch_type = ARCH_AVX512 }
};

const struct str_value_mapping cipher_algo_str_map[] = {
        {
                .name = "aes-cbc-128",
                .values.job_params = {
                        .cipher_mode = TEST_CBC,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-cbc-192",
                .values.job_params = {
                        .cipher_mode = TEST_CBC,
                        .aes_key_size = IMB_KEY_192_BYTES
                }
        },
        {
                .name = "aes-cbc-256",
                .values.job_params = {
                        .cipher_mode = TEST_CBC,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-ctr-128",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-ctr-192",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR,
                        .aes_key_size = IMB_KEY_192_BYTES
                }
        },
        {
                .name = "aes-ctr-256",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-ctr8-128",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR8,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-ctr8-192",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR8,
                        .aes_key_size = IMB_KEY_192_BYTES
                }
        },
        {
                .name = "aes-ctr8-256",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR8,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-ctr-bit-128",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR_BITLEN,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-ctr-bit-192",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR_BITLEN,
                        .aes_key_size = IMB_KEY_192_BYTES
                }
        },
        {
                .name = "aes-ctr-bit-256",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR_BITLEN,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-ctr-bit4-128",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR_BITLEN4,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-ctr-bit4-192",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR_BITLEN4,
                        .aes_key_size = IMB_KEY_192_BYTES
                }
        },
        {
                .name = "aes-ctr-bit4-256",
                .values.job_params = {
                        .cipher_mode = TEST_CNTR_BITLEN4,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-ecb-128",
                .values.job_params = {
                        .cipher_mode = TEST_ECB,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-ecb-192",
                .values.job_params = {
                        .cipher_mode = TEST_ECB,
                        .aes_key_size = IMB_KEY_192_BYTES
                }
        },
        {
                .name = "aes-ecb-256",
                .values.job_params = {
                        .cipher_mode = TEST_ECB,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-docsis-128",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-docsis8-128",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS8,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-docsis-256",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-docsis8-256",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS8,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "des-docsis",
                .values.job_params = {
                        .cipher_mode = TEST_DESDOCSIS,
                        .aes_key_size = 8
                }
        },
        {
                .name = "des-docsis4",
                .values.job_params = {
                        .cipher_mode = TEST_DESDOCSIS4,
                        .aes_key_size = 8
                }
        },
        {
                .name = "des-cbc",
                .values.job_params = {
                        .cipher_mode = TEST_DES,
                        .aes_key_size = 8
                }
        },
        {
                .name = "3des-cbc",
                .values.job_params = {
                        .cipher_mode = TEST_3DES,
                        .aes_key_size = 8
                }
        },
        {
                .name = "zuc-eea3",
                .values.job_params = {
                        .cipher_mode = TEST_ZUC_EEA3,
                        .aes_key_size = 16
                }
        },
        {
                .name = "zuc-eea3-256",
                .values.job_params = {
                        .cipher_mode = TEST_ZUC_EEA3,
                        .aes_key_size = 32
                }
        },
        {
                .name = "snow3g-uea2",
                .values.job_params = {
                        .cipher_mode = TEST_SNOW3G_UEA2,
                        .aes_key_size = 16
                }
        },
        {
                .name = "kasumi-uea1",
                .values.job_params = {
                        .cipher_mode = TEST_KASUMI_UEA1,
                        .aes_key_size = 16
                }
        },
        {
                .name = "aes-cbcs-1-9",
                .values.job_params = {
                        .cipher_mode = TEST_CBCS_1_9,
                        .aes_key_size = 16
                }
        },
        {
                .name = "chacha20",
                .values.job_params = {
                        .cipher_mode = TEST_CHACHA20,
                        .aes_key_size = 32
                }
        },
        {
                .name = "snow-v",
                .values.job_params = {
                        .cipher_mode = TEST_SNOW_V,
                        .aes_key_size = 32
                }
        },
        {
                .name = "null",
                .values.job_params = {
                        .cipher_mode = TEST_NULL_CIPHER,
                        .aes_key_size = 0
                }
        }
};

const struct str_value_mapping hash_algo_str_map[] = {
        {
                .name = "sha1-hmac",
                .values.job_params = {
                        .hash_alg = TEST_SHA1_HMAC
                }
        },
        {
                .name = "sha224-hmac",
                .values.job_params = {
                        .hash_alg = TEST_SHA_224_HMAC
                }
        },
        {
                .name = "sha256-hmac",
                .values.job_params = {
                        .hash_alg = TEST_SHA_256_HMAC
                }
        },
        {
                .name = "sha384-hmac",
                .values.job_params = {
                        .hash_alg = TEST_SHA_384_HMAC
                }
        },
        {
                .name = "sha512-hmac",
                .values.job_params = {
                        .hash_alg = TEST_SHA_512_HMAC
                }
        },
        {
                .name = "aes-xcbc",
                .values.job_params = {
                        .hash_alg = TEST_XCBC
                }
        },
        {
                .name = "md5-hmac",
                .values.job_params = {
                        .hash_alg = TEST_MD5
                }
        },
        {
                .name = "aes-cmac",
                .values.job_params = {
                        .hash_alg = TEST_HASH_CMAC
                }
        },
        {
                .name = "sha1",
                .values.job_params = {
                        .hash_alg = TEST_SHA1
                }
        },
        {
                .name = "sha224",
                .values.job_params = {
                        .hash_alg = TEST_SHA_224
                }
        },
        {
                .name = "sha256",
                .values.job_params = {
                        .hash_alg = TEST_SHA_256
                }
        },
        {
                .name = "sha384",
                .values.job_params = {
                        .hash_alg = TEST_SHA_384
                }
        },
        {
                .name = "sha512",
                .values.job_params = {
                        .hash_alg = TEST_SHA_512
                }
        },
        {
                .name = "null",
                .values.job_params = {
                        .hash_alg = TEST_NULL_HASH
                }
        },
        {
                .name = "aes-cmac-bitlen",
                .values.job_params = {
                        .hash_alg = TEST_HASH_CMAC_BITLEN
                }
        },
        {
                .name = "zuc-eia3",
                .values.job_params = {
                        .hash_alg = TEST_ZUC_EIA3,
                }
        },
        {
                .name = "snow3g-uia2",
                .values.job_params = {
                        .hash_alg = TEST_SNOW3G_UIA2,
                }
        },
        {
                .name = "kasumi-uia1",
                .values.job_params = {
                        .hash_alg = TEST_KASUMI_UIA1,
                }
        },
        {
                .name = "aes-gmac-128",
                .values.job_params = {
                        .hash_alg = TEST_AES_GMAC_128,
                }
        },
        {
                .name = "aes-gmac-192",
                .values.job_params = {
                        .hash_alg = TEST_AES_GMAC_192,
                }
        },
        {
                .name = "aes-gmac-256",
                .values.job_params = {
                        .hash_alg = TEST_AES_GMAC_256,
                }
        },
        {
                .name = "aes-cmac-256",
                .values.job_params = {
                        .hash_alg = TEST_HASH_CMAC_256,
                }
        },
        {
                .name = "poly-1305",
                .values.job_params = {
                        .hash_alg = TEST_HASH_POLY1305,
                }
        },
        {
                .name = "zuc-eia3-256",
                .values.job_params = {
                        .hash_alg = TEST_ZUC256_EIA3,
                }
        },
        {
                .name = "crc32-ethernet-fcs",
                .values.job_params = {
                        .hash_alg = TEST_CRC32_ETHERNET_FCS,
                }
        },
        {
                .name = "crc32-sctp",
                .values.job_params = {
                        .hash_alg = TEST_CRC32_SCTP,
                }
        },
        {
                .name = "crc32-wimax-ofdma-data",
                .values.job_params = {
                        .hash_alg = TEST_CRC32_WIMAX_OFDMA_DATA,
                }
        },
        {
                .name = "crc24-lte-a",
                .values.job_params = {
                        .hash_alg = TEST_CRC24_LTE_A,
                }
        },
        {
                .name = "crc24-lte-b",
                .values.job_params = {
                        .hash_alg = TEST_CRC24_LTE_B,
                }
        },
        {
                .name = "crc16-x25",
                .values.job_params = {
                        .hash_alg = TEST_CRC16_X25,
                }
        },
        {
                .name = "crc16-fp-data",
                .values.job_params = {
                        .hash_alg = TEST_CRC16_FP_DATA,
                }
        },
        {
                .name = "crc11-fp-header",
                .values.job_params = {
                        .hash_alg = TEST_CRC11_FP_HEADER,
                }
        },
        {
                .name = "crc10-iuup-data",
                .values.job_params = {
                        .hash_alg = TEST_CRC10_IUUP_DATA,
                }
        },
        {
                .name = "crc8-wimax-ofdma-hcs",
                .values.job_params = {
                        .hash_alg = TEST_CRC8_WIMAX_OFDMA_HCS,
                }
        },
        {
                .name = "crc7-fp-header",
                .values.job_params = {
                        .hash_alg = TEST_CRC7_FP_HEADER,
                }
        },
        {
                .name = "crc6-iuup-header",
                .values.job_params = {
                        .hash_alg = TEST_CRC6_IUUP_HEADER,
                }
        },
        {
                .name = "ghash",
                .values.job_params = {
                        .hash_alg = TEST_AUTH_GHASH,
                }
        },
};

const struct str_value_mapping aead_algo_str_map[] = {
        {
                .name = "aes-gcm-128",
                .values.job_params = {
                        .cipher_mode = TEST_GCM,
                        .hash_alg = TEST_HASH_GCM,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-gcm-192",
                .values.job_params = {
                        .cipher_mode = TEST_GCM,
                        .hash_alg = TEST_HASH_GCM,
                        .aes_key_size = IMB_KEY_192_BYTES
                }
        },
        {
                .name = "aes-gcm-256",
                .values.job_params = {
                        .cipher_mode = TEST_GCM,
                        .hash_alg = TEST_HASH_GCM,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-ccm-128",
                .values.job_params = {
                        .cipher_mode = TEST_CCM,
                        .hash_alg = TEST_HASH_CCM,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-ccm-256",
                .values.job_params = {
                        .cipher_mode = TEST_CCM,
                        .hash_alg = TEST_HASH_CCM,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "pon-128",
                .values.job_params = {
                        .cipher_mode = TEST_PON_CNTR,
                        .hash_alg = TEST_PON_CRC_BIP,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "pon-128-no-ctr",
                .values.job_params = {
                        .cipher_mode = TEST_PON_NO_CNTR,
                        .hash_alg = TEST_PON_CRC_BIP,
                        .aes_key_size = 0
                }
        },
        {
                .name = "chacha20-poly1305",
                .values.job_params = {
                        .cipher_mode = TEST_AEAD_CHACHA20,
                        .hash_alg = TEST_AEAD_POLY1305,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-docsis-128-crc32",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS,
                        .hash_alg = TEST_DOCSIS_CRC32,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
                {
                .name = "aes-docsis8-128-crc32",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS8,
                        .hash_alg = TEST_DOCSIS_CRC32,
                        .aes_key_size = IMB_KEY_128_BYTES
                }
        },
        {
                .name = "aes-docsis-256-crc32",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS,
                        .hash_alg = TEST_DOCSIS_CRC32,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "aes-docsis8-256-crc32",
                .values.job_params = {
                        .cipher_mode = TEST_AESDOCSIS8,
                        .hash_alg = TEST_DOCSIS_CRC32,
                        .aes_key_size = IMB_KEY_256_BYTES
                }
        },
        {
                .name = "snow-v-aead",
                .values.job_params = {
                        .cipher_mode = TEST_SNOW_V_AEAD,
                        .aes_key_size = 32,
                        .hash_alg = TEST_AUTH_SNOW_V_AEAD
                }
        },
};

const struct str_value_mapping cipher_dir_str_map[] = {
        {.name = "encrypt", .values.job_params.cipher_dir = IMB_DIR_ENCRYPT},
        {.name = "decrypt", .values.job_params.cipher_dir = IMB_DIR_DECRYPT}
};

/* This struct stores all information about performed test case */
struct variant_s {
        enum arch_type_e arch;
        struct params_s params;
        uint64_t *avg_times;
};

/* Struct storing information to be passed to threads */
struct thread_info {
        int print_info;
        int core;
        IMB_MGR *p_mgr;
} t_info[MAX_NUM_THREADS];

enum cache_type_e {
        WARM = 0,
        COLD = 1
};

enum cache_type_e cache_type = WARM;

const uint32_t auth_tag_length_bytes[] = {
                12, /* SHA1_HMAC */
                14, /* SHA_224_HMAC */
                16, /* SHA_256_HMAC */
                24, /* SHA_384_HMAC */
                32, /* SHA_512_HMAC */
                12, /* AES_XCBC */
                12, /* MD5 */
                0,  /* NULL_HASH */
                16, /* AES_GMAC */
                0,  /* CUSTOM HASH */
                16, /* AES_CCM */
                16, /* AES_CMAC */
                20, /* PLAIN_SHA1 */
                28, /* PLAIN_SHA_224 */
                32, /* PLAIN_SHA_256 */
                48, /* PLAIN_SHA_384 */
                64, /* PLAIN_SHA_512 */
                4,  /* AES_CMAC_BITLEN (3GPP) */
                8,  /* PON */
                4,  /* ZUC-EIA3 */
                IMB_DOCSIS_CRC32_TAG_SIZE, /* DOCSIS_CRC32 */
                4,  /* SNOW3G-UIA2 */
                4,  /* KASUMI-UIA1 */
                16, /* IMB_AUTH_AES_GMAC_128 */
                16, /* IMB_AUTH_AES_GMAC_192 */
                16, /* IMB_AUTH_AES_GMAC_256 */
                16, /* AES_CMAC_256 */
                16, /* POLY1305 */
                16, /* AEAD CHACHA20-POLY1305 */
                16, /* AEAD CHACHA20 with SGL support*/
                4,  /* ZUC-256-EIA3 */
                16,  /* SNOW-V AEAD */
                16, /* AES-GCM with SGL support */
                4,  /* IMB_AUTH_CRC32_ETHERNET_FCS */
                4,  /* IMB_AUTH_CRC32_SCTP */
                4,  /* IMB_AUTH_CRC32_WIMAX_OFDMA_DATA */
                4,  /* IMB_AUTH_CRC24_LTE_A */
                4,  /* IMB_AUTH_CRC24_LTE_B */
                4,  /* IMB_AUTH_CRC16_X25 */
                4,  /* IMB_AUTH_CRC16_FP_DATA */
                4,  /* IMB_AUTH_CRC11_FP_HEADER */
                4,  /* IMB_AUTH_CRC10_IUUP_DATA */
                4,  /* IMB_AUTH_CRC8_WIMAX_OFDMA_HCS */
                4,  /* IMB_AUTH_CRC7_FP_HEADER */
                4,  /* IMB_AUTH_CRC6_IUUP_HEADER */
                16, /* IMB_AUTH_GHASH */
};
uint32_t index_limit;
uint32_t key_idxs[NUM_OFFSETS];
uint32_t offsets[NUM_OFFSETS];
uint32_t sha_size_incr = 24;

enum range {
        RANGE_MIN = 0,
        RANGE_STEP,
        RANGE_MAX,
        NUM_RANGE
};

uint32_t job_sizes[NUM_RANGE] = {DEFAULT_JOB_SIZE_MIN,
                                 DEFAULT_JOB_SIZE_STEP,
                                 DEFAULT_JOB_SIZE_MAX};
uint32_t job_size_list[MAX_LIST];
uint32_t job_size_count = 0;
uint32_t imix_list[MAX_LIST];
uint32_t distribution_total[MAX_LIST];
uint32_t *job_size_imix_list = NULL;
uint32_t *cipher_size_list = NULL;
uint32_t *hash_size_list = NULL;
uint64_t *xgem_hdr_list = NULL;
uint16_t imix_list_count = 0;
uint32_t average_job_size = 0;
uint32_t max_job_size = 0;

/* Size of IMIX list (needs to be multiple of 2) */
#define JOB_SIZE_IMIX_LIST 1024

uint32_t job_iter = 0;
uint32_t tag_size = 0;
uint64_t gcm_aad_size = DEFAULT_GCM_AAD_SIZE;
uint64_t ccm_aad_size = DEFAULT_CCM_AAD_SIZE;
uint64_t chacha_poly_aad_size = DEFAULT_CHACHA_POLY_AAD_SIZE;
uint64_t snow_v_aad_size = DEFAULT_SNOW_V_AEAD_AAD_SIZE;

struct custom_job_params custom_job_params = {
        .cipher_mode  = TEST_NULL_CIPHER,
        .hash_alg     = TEST_NULL_HASH,
        .aes_key_size = 0,
        .cipher_dir   = IMB_DIR_ENCRYPT
};

uint8_t archs[NUM_ARCHS] = {1, 1, 1, 1}; /* uses all function sets */
int use_job_api = 0;
int use_gcm_sgl_api = 0;
int use_unhalted_cycles = 0; /* read unhalted cycles instead of tsc */
uint64_t rd_cycles_cost = 0; /* cost of reading unhalted cycles */
uint64_t core_mask = 0; /* bitmap of selected cores */

uint64_t flags = 0; /* flags passed to alloc_mb_mgr() */

uint32_t iter_scale = ITER_SCALE_LONG;

#define PB_INIT_SIZE 50
#define PB_INIT_IDX  2 /* after \r and [ */
static uint32_t PB_SIZE = PB_INIT_SIZE;
static uint32_t PB_FINAL_IDX = (PB_INIT_SIZE + (PB_INIT_IDX - 1));
static char prog_bar[PB_INIT_SIZE + 4]; /* 50 + 4 for \r, [, ], \0 */
static uint32_t pb_idx = PB_INIT_IDX;
static uint32_t pb_mod = 0;

static int silent_progress_bar = 0;
static int plot_output_option = 0;

/* API types */
typedef enum  {
        TEST_API_JOB = 0,
        TEST_API_BURST,
        TEST_API_CIPHER_BURST,
        TEST_API_HASH_BURST,
        TEST_API_NUMOF
} TEST_API;

const char *str_api_list[TEST_API_NUMOF] = {"single job", "burst",
                                            "cipher-only burst",
                                            "hash-only burst"};

static TEST_API test_api = TEST_API_JOB; /* test job API by default */
static uint32_t burst_size = 0; /* num jobs to pass to burst API */
static uint32_t segment_size = 0; /* segment size to test SGL (0 = no SGL) */

static volatile int timebox_on = 1; /* flag to stop the test loop */
static int use_timebox = 1;         /* time-box feature on/off flag */

#ifdef LINUX
static void timebox_callback(int sig)
{
        (void) sig;
        timebox_on = 0;
}
#endif

#ifdef _WIN32
static void CALLBACK timebox_callback(PVOID lpParam, BOOLEAN TimerFired)
{
        (void) lpParam;
        (void) TimerFired;
        timebox_on = 0;
}
#endif

/* Return rdtsc to core cycle scale factor */
static double get_tsc_to_core_scale(const int turbo)
{
        int i, num_loops = 1;
        /* use enough cycles for accurate measurement */
        const uint64_t expected_cycles = 1000000000;
        uint64_t tsc_cycles;

        /* if turbo enabled then run longer */
        /* to allow frequency to stabilize */
        if (turbo)
                num_loops = 8;

        for (i = 0; i < num_loops; i++)
                tsc_cycles = measure_tsc(expected_cycles);

        return ((double)tsc_cycles / (double)expected_cycles);
}

static void prog_bar_init(const uint32_t total_num)
{
        if (silent_progress_bar)
                return;

        if (total_num < PB_SIZE) {
                PB_SIZE = total_num;
                PB_FINAL_IDX = (PB_SIZE + (PB_INIT_IDX - 1));
        }
        pb_idx = PB_INIT_IDX;
        pb_mod = total_num / PB_SIZE;

        /* 32 dec == ascii ' ' char */
        memset(prog_bar, 32, sizeof(prog_bar));
        prog_bar[0] = '\r';
        prog_bar[1] = '[';
        prog_bar[PB_FINAL_IDX + 1] = ']';
        prog_bar[PB_FINAL_IDX + 2] = '\0';

        fputs(prog_bar, stderr);
}

static void prog_bar_fini(void)
{
        if (silent_progress_bar)
                return;

        prog_bar[PB_FINAL_IDX] = 'X'; /* set final X */
        fputs(prog_bar, stderr);
}

static void prog_bar_update(const uint32_t num)
{
        if (silent_progress_bar)
                return;

        if ((pb_mod == 0) || num % pb_mod == 0) {
                /* print X at every ~50th variant */
                prog_bar[pb_idx] = 'X';
                fputs(prog_bar, stderr);

                /* don't overrun final idx */
                if (pb_idx < (PB_SIZE + 1))
                        pb_idx++;
        } else {
                const char pb_inter_chars[] = {'|', '/', '-', '\\'};
                /* print intermediate chars */
                prog_bar[pb_idx] = pb_inter_chars[num % DIM(pb_inter_chars)];
                fputs(prog_bar, stderr);
        }
}

/* Read unhalted cycles */
__forceinline uint64_t read_cycles(const uint32_t core)
{
        uint64_t val = 0;

        if (msr_read(core, IA32_MSR_CPU_UNHALTED_THREAD,
                     &val) != MACHINE_RETVAL_OK) {
                fprintf(stderr, "Error reading cycles "
                        "counter on core %u!\n", core);
                exit(EXIT_FAILURE);
        }

        return val;
}

/* Method used by qsort to compare 2 values */
static int compare_uint64_t(const void *a, const void *b)
{
        return (int)(int64_t)(*(const uint64_t *)a - *(const uint64_t *)b);
}

/* Get number of bits set in value */
static unsigned bitcount(const uint64_t val)
{
        unsigned i, bits = 0;

        for (i = 0; i < BITS(val); i++)
                if (val & (1ULL << i))
                        bits++;

        return bits;
}

/* Get the next core in core mask
   Set last_core to negative to start from beginning of core_mask */
static int next_core(const uint64_t core_mask,
                     const int last_core)
{
        int core = 0;

        if (last_core >= 0)
                core = last_core;

        while (((core_mask >> core) & 1) == 0) {
                core++;

                if (core >= (int)BITS(core_mask))
                        return -1;
        }

        return core;
}

/* Set CPU affinity for current thread */
static int set_affinity(const int cpu)
{
        int ret = 0;
        int num_cpus = 0;

        /* Get number of cpus in the system */
#ifdef _WIN32
        GROUP_AFFINITY NewGroupAffinity;

        memset(&NewGroupAffinity, 0, sizeof(GROUP_AFFINITY));
        num_cpus = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#else
        num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#endif
        if (num_cpus == 0) {
                fprintf(stderr, "Zero processors in the system!");
                return 1;
        }

        /* Check if selected core is valid */
        if (cpu < 0 || cpu >= num_cpus) {
                fprintf(stderr, "Invalid CPU selected! "
                        "Max valid CPU is %d\n", num_cpus - 1);
                return 1;
        }

#ifdef _WIN32
        NewGroupAffinity.Mask = 1ULL << cpu;
        ret = !SetThreadGroupAffinity(GetCurrentThread(),
                                      &NewGroupAffinity, NULL);
#else
        cpu_set_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(cpu, &cpuset);

        /* Set affinity of current process to cpu */
#if defined(__FreeBSD__)
	ret = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
				sizeof(cpuset), &cpuset);
#else
        ret = sched_setaffinity(0, sizeof(cpuset), &cpuset);
#endif
#endif /* _WIN32 */

        return ret;
}

/* Start counting unhalted cycles */
static int start_cycles_ctr(const uint32_t core)
{
        int ret;

        if (core >= BITS(core_mask))
                return 1;

        /* Disable cycles counter */
        ret = msr_write(core, IA32_MSR_PERF_GLOBAL_CTR, 0);
        if (ret != MACHINE_RETVAL_OK)
                return ret;

        /* Zero cycles counter */
        ret = msr_write(core, IA32_MSR_CPU_UNHALTED_THREAD, 0);
        if (ret != MACHINE_RETVAL_OK)
                return ret;

        /* Enable OS and user tracking in FixedCtr1 */
        ret = msr_write(core, IA32_MSR_FIXED_CTR_CTRL, 0x30);
        if (ret != MACHINE_RETVAL_OK)
                return ret;

        /* Enable cycles counter */
        return  msr_write(core, IA32_MSR_PERF_GLOBAL_CTR, (1ULL << 33));
}

/* Init MSR module */
static int init_msr_mod(void)
{
        unsigned max_core_count = 0;
#ifdef _WIN32
        max_core_count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#else
        max_core_count = sysconf(_SC_NPROCESSORS_CONF);
#endif
        if (max_core_count == 0) {
                fprintf(stderr, "Zero processors in the system!");
                return MACHINE_RETVAL_ERROR;
        }

        return machine_init(max_core_count);
}

/* Set the cost of reading unhalted cycles using RDMSR */
static int set_unhalted_cycle_cost(const int core, uint64_t *value)
{
        uint64_t time1, time2;

        if (value == NULL || core < 0)
                return 1;

        time1 = read_cycles(core);
        time2 = read_cycles(core);

        /* Calculate delta */
        *value = (time2 - time1);

        return 0;
}

/* Calculate the general cost of reading unhalted cycles (median) */
static int set_avg_unhalted_cycle_cost(const int core, uint64_t *value)
{
        unsigned i;
        uint64_t cycles[10];

        if (value == NULL || core_mask == 0 || core < 0)
                return 1;

        /* Fill cycles table with read cost values */
        for (i = 0; i < DIM(cycles); i++)
                if (set_unhalted_cycle_cost(core, &cycles[i]) != 0)
                        return 1;

        /* sort array */
        qsort(cycles, DIM(cycles), sizeof(uint64_t), compare_uint64_t);

        /* set median cost */
        *value = cycles[DIM(cycles)/2];

        return 0;
}

/* Freeing allocated memory */
static void free_mem(uint8_t **p_buffer, imb_uint128_t **p_keys)
{
        imb_uint128_t *keys = NULL;
        uint8_t *buf = NULL;

        if (p_keys != NULL) {
                keys = *p_keys;
                *p_keys = NULL;
        }

        if (p_buffer != NULL) {
                buf = *p_buffer;
                *p_buffer = NULL;
        }

#ifdef LINUX
        if (keys != NULL)
                free(keys);

        if (buf != NULL)
                free(buf);
#else
        if (keys != NULL)
                _aligned_free(keys);

        if (buf != NULL)
                _aligned_free(buf);
#endif
}

static const void *
get_key_pointer(const uint32_t index, const imb_uint128_t *p_keys)
{
        return (const void *) &p_keys[key_idxs[index]];
}

static uint8_t *get_src_buffer(const uint32_t index, uint8_t *p_buffer)
{
        return &p_buffer[offsets[index]];
}

static uint8_t *get_dst_buffer(const uint32_t index, uint8_t *p_buffer)
{
        return &p_buffer[offsets[index] + sha_size_incr];
}

static uint32_t get_next_index(uint32_t index)
{
        if (++index >= index_limit)
                index = 0;
        return index;
}

static void init_buf(void *pb, const size_t length)
{
        const size_t n = length / sizeof(uint64_t);
        size_t i = 0;

        if (pb == NULL)
                return;

        for (i = 0; i < n; i++)
                ((uint64_t *)pb)[i] = (uint64_t) rand();
}

/*
 * Packet and key memory allocation and initialization.
 * init_offsets() needs to be called prior to that so that
 * index_limit is set up accordingly to hot/cold selection.
 */
static void init_mem(uint8_t **p_buffer, imb_uint128_t **p_keys)
{
        const size_t bufs_size = index_limit * REGION_SIZE;
        const size_t keys_size =
                index_limit * KEYS_PER_JOB * sizeof(imb_uint128_t);
        const size_t alignment = 64;
        uint8_t *buf = NULL;
        imb_uint128_t *keys = NULL;
#ifdef LINUX
	int ret;
#endif

        if (p_keys == NULL || p_buffer == NULL) {
                fprintf(stderr, "Internal buffer allocation error!\n");
                exit(EXIT_FAILURE);
        }

#ifdef LINUX
        ret = posix_memalign((void **) &buf, alignment, bufs_size);

	if (ret != 0) {
                fprintf(stderr, "Could not malloc buf\n");
                exit(EXIT_FAILURE);
        }
#else
        buf = (uint8_t *) _aligned_malloc(bufs_size, alignment);
#endif
        if (!buf) {
                fprintf(stderr, "Could not malloc buf\n");
                exit(EXIT_FAILURE);
        }

#ifdef LINUX
        ret = posix_memalign((void **) &keys, alignment, keys_size);
	if (ret != 0) {
                fprintf(stderr, "Could not allocate memory for keys!\n");
                free_mem(&buf, &keys);
                exit(EXIT_FAILURE);
        }
#else
        keys = (imb_uint128_t *) _aligned_malloc(keys_size, alignment);
#endif
        if (!keys) {
                fprintf(stderr, "Could not allocate memory for keys!\n");
                free_mem(&buf, &keys);
                exit(EXIT_FAILURE);
        }

        *p_keys = keys;
        *p_buffer = buf;

        init_buf(buf, bufs_size);
        init_buf(keys, keys_size);
}

/*
 * Initialize packet buffer and keys offsets from
 * the start of the respective buffers
 */
static void init_offsets(const enum cache_type_e ctype)
{
        if (ctype == COLD) {
                uint32_t i;

                for (i = 0; i < NUM_OFFSETS; i++) {
                        offsets[i] = (i * REGION_SIZE) + (rand() & 0x3C0);
                        key_idxs[i] = i * KEYS_PER_JOB;
                }

                /* swap the entries at random */
                for (i = 0; i < NUM_OFFSETS; i++) {
                        const uint32_t swap_idx = (rand() % NUM_OFFSETS);
                        const uint32_t tmp_offset = offsets[swap_idx];
                        const uint32_t tmp_keyidx = key_idxs[swap_idx];

                        offsets[swap_idx] = offsets[i];
                        key_idxs[swap_idx] = key_idxs[i];
                        offsets[i] = tmp_offset;
                        key_idxs[i] = tmp_keyidx;
                }

                index_limit = NUM_OFFSETS;
        } else { /* WARM */
                uint32_t i;

                index_limit = 16;

                for (i = 0; i < index_limit; i++) {
                        /*
                         * Each buffer starts at different offset from
                         * start of the page.
                         * The most optimum determined difference between
                         * offsets is 4 cache lines.
                         */
                        const uint32_t offset_step = (4 * 64);
                        const uint32_t L1_way_size = 4096;

                        key_idxs[i] = i * KEYS_PER_JOB;
                        offsets[i] = i * REGION_SIZE +
                                ((i * offset_step) & (L1_way_size - 1));
                }
        }
}

/*
 * This function translates enum test_ciper_mode_e to be used by ipsec_mb
 * library
 */
static IMB_CIPHER_MODE
translate_cipher_mode(const enum test_cipher_mode_e test_mode)
{
        IMB_CIPHER_MODE c_mode = IMB_CIPHER_NULL;

        switch (test_mode) {
        case TEST_CBC:
                c_mode = IMB_CIPHER_CBC;
                break;
        case TEST_CNTR:
        case TEST_CNTR8:
                c_mode = IMB_CIPHER_CNTR;
                break;
        case TEST_CNTR_BITLEN:
        case TEST_CNTR_BITLEN4:
                c_mode = IMB_CIPHER_CNTR_BITLEN;
                break;
        case TEST_ECB:
                c_mode = IMB_CIPHER_ECB;
                break;
        case TEST_NULL_CIPHER:
                c_mode = IMB_CIPHER_NULL;
                break;
        case TEST_AESDOCSIS:
        case TEST_AESDOCSIS8:
                c_mode = IMB_CIPHER_DOCSIS_SEC_BPI;
                break;
        case TEST_DESDOCSIS:
        case TEST_DESDOCSIS4:
                c_mode = IMB_CIPHER_DOCSIS_DES;
                break;
        case TEST_GCM:
                if (segment_size != 0)
                        c_mode = IMB_CIPHER_GCM_SGL;
                else
                        c_mode = IMB_CIPHER_GCM;
                break;
        case TEST_CCM:
                c_mode = IMB_CIPHER_CCM;
                break;
        case TEST_DES:
                c_mode = IMB_CIPHER_DES;
                break;
        case TEST_3DES:
                c_mode = IMB_CIPHER_DES3;
                break;
        case TEST_PON_CNTR:
        case TEST_PON_NO_CNTR:
                c_mode = IMB_CIPHER_PON_AES_CNTR;
                break;
        case TEST_ZUC_EEA3:
                c_mode = IMB_CIPHER_ZUC_EEA3;
                break;
        case TEST_SNOW3G_UEA2:
                c_mode = IMB_CIPHER_SNOW3G_UEA2_BITLEN;
                break;
        case TEST_KASUMI_UEA1:
                c_mode = IMB_CIPHER_KASUMI_UEA1_BITLEN;
                break;
        case TEST_CBCS_1_9:
                c_mode = IMB_CIPHER_CBCS_1_9;
                break;
        case TEST_CHACHA20:
                c_mode = IMB_CIPHER_CHACHA20;
                break;
        case TEST_AEAD_CHACHA20:
                if (segment_size != 0)
                        c_mode = IMB_CIPHER_CHACHA20_POLY1305_SGL;
                else
                        c_mode = IMB_CIPHER_CHACHA20_POLY1305;

                break;
        case TEST_SNOW_V:
                c_mode = IMB_CIPHER_SNOW_V;
                break;
        case TEST_SNOW_V_AEAD:
                c_mode = IMB_CIPHER_SNOW_V_AEAD;
                break;
        default:
                break;
        }
        return c_mode;
}

static uint32_t
get_next_size(const uint32_t index)
{
        const uint32_t i = index & (JOB_SIZE_IMIX_LIST - 1);

        return job_size_imix_list[i];
}

static inline void
set_job_fields(IMB_JOB *job, uint8_t *p_buffer, imb_uint128_t *p_keys,
               const uint32_t i, const uint32_t index)
{
        uint32_t list_idx;

        /* If IMIX testing is being done, set the buffer size to cipher and hash
         * going through the list of sizes precalculated */
        if (imix_list_count != 0) {
                list_idx = i & (JOB_SIZE_IMIX_LIST - 1);

                job->msg_len_to_cipher_in_bytes = cipher_size_list[list_idx];
                job->msg_len_to_hash_in_bytes = hash_size_list[list_idx];
        }

        if (job->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                uint64_t *p_src =
                        (uint64_t *) get_src_buffer(index, p_buffer);

                job->src = (const uint8_t *)p_src;
                if (imix_list_count != 0)
                        p_src[0] = xgem_hdr_list[list_idx];
                else
                        p_src[0] = xgem_hdr_list[0];
        } else
                job->src = get_src_buffer(index, p_buffer);

        job->dst = get_dst_buffer(index, p_buffer);
        if (job->cipher_mode == IMB_CIPHER_GCM) {
                job->u.GCM.aad = job->src;
        } else if (job->cipher_mode == IMB_CIPHER_CCM) {
                job->u.CCM.aad = job->src;
                job->enc_keys = job->dec_keys =
                        (const uint32_t *) get_key_pointer(index,
                                                           p_keys);
        } else if (job->cipher_mode == IMB_CIPHER_DES3) {
                static const void *ks_ptr[3];

                ks_ptr[0] = ks_ptr[1] = ks_ptr[2] =
                        get_key_pointer(index, p_keys);
                job->enc_keys =
                        job->dec_keys = ks_ptr;
        } else if (job->cipher_mode == IMB_CIPHER_CHACHA20_POLY1305) {
                job->u.CHACHA20_POLY1305.aad = job->src;
        } else if (job->cipher_mode == IMB_CIPHER_SNOW_V_AEAD) {
                job->u.SNOW_V_AEAD.aad = job->src;
                job->enc_keys = job->dec_keys =
                        (const uint32_t *) get_key_pointer(index,
                                                           p_keys);
        /* Force destination buffer to start 8 bytes after source */
        } else if (job->cipher_mode == IMB_CIPHER_PON_AES_CNTR) {
                job->dst = get_src_buffer(index, p_buffer) + 8;
                job->enc_keys = job->dec_keys =
                        (const uint32_t *) get_key_pointer(index,
                                                           p_keys);
        } else {
                job->enc_keys = job->dec_keys =
                        (const uint32_t *) get_key_pointer(index,
                                                           p_keys);
        }
}

static inline void
set_sgl_job_fields(IMB_JOB *job, uint8_t *p_buffer, imb_uint128_t *p_keys,
                   const uint32_t size_idx, const uint32_t buf_index,
                   struct IMB_SGL_IOV *sgl, struct gcm_context_data *gcm_ctx,
                   struct chacha20_poly1305_context_data *cp_ctx)
{
        uint8_t *src = get_src_buffer(buf_index, p_buffer);
        uint8_t *dst = get_dst_buffer(buf_index, p_buffer);
        uint8_t *aad = src;
        uint32_t buf_size;

        job->src = src;
        job->dst = dst;

        /* If IMIX testing is being done, set the buffer size to cipher and hash
         * going through the list of sizes precalculated */
        if (imix_list_count != 0) {
                uint32_t list_idx = size_idx & (JOB_SIZE_IMIX_LIST - 1);

                job->msg_len_to_cipher_in_bytes = cipher_size_list[list_idx];
        }
        buf_size = (uint32_t) job->msg_len_to_cipher_in_bytes;
        if (job->cipher_mode == IMB_CIPHER_GCM_SGL) {
                job->u.GCM.aad = aad;
                job->u.GCM.ctx = gcm_ctx;
        } else {
                job->u.CHACHA20_POLY1305.aad = aad;
                job->u.CHACHA20_POLY1305.ctx = cp_ctx;
        }
        job->enc_keys = job->dec_keys =
                (const uint32_t *) get_key_pointer(buf_index,
                                   p_keys);
        job->sgl_state = IMB_SGL_ALL;

        const uint32_t num_segs = buf_size / segment_size;
        const uint32_t final_seg_sz = buf_size % segment_size;
        unsigned i;

        job->num_sgl_io_segs = num_segs;

        for (i = 0; i < num_segs; i++) {
                sgl[i].in = &src[i * segment_size];
                sgl[i].out = &dst[i * segment_size];
                sgl[i].len = segment_size;
        }
        if (final_seg_sz != 0) {
                sgl[i].in = &src[num_segs * segment_size];
                sgl[i].out = &dst[num_segs * segment_size];
                sgl[i].len = final_seg_sz;
                (job->num_sgl_io_segs)++;
        }
        job->sgl_io_segs = sgl;
};

static void
set_size_lists(uint32_t *cipher_size_list, uint32_t *hash_size_list,
               uint64_t *xgem_hdr_list, struct params_s *params)
{
        unsigned int i, list_size;
        uint32_t job_size;

        if (imix_list_count != 0)
                list_size = JOB_SIZE_IMIX_LIST;
        else
                list_size = 1;

        for (i = 0; i < list_size; i++) {
                if (imix_list_count != 0)
                        job_size = job_size_imix_list[i];
                else
                        job_size = params->size_aes;

                if ((params->cipher_mode == TEST_AESDOCSIS8) ||
                    (params->cipher_mode == TEST_CNTR8))
                        cipher_size_list[i] = job_size + 8;
                else if (params->cipher_mode == TEST_DESDOCSIS4)
                        cipher_size_list[i] = job_size + 4;
                else if ((params->cipher_mode == TEST_CNTR_BITLEN) ||
                         (params->cipher_mode == TEST_SNOW3G_UEA2) ||
                         (params->cipher_mode == TEST_KASUMI_UEA1))
                        cipher_size_list[i] = job_size * 8;
                else if (params->cipher_mode == TEST_CNTR_BITLEN4)
                        cipher_size_list[i] = job_size * 8 - 4;
                else if ((params->cipher_mode == TEST_NULL_CIPHER) ||
                         (params->cipher_mode == TEST_PON_NO_CNTR))
                        cipher_size_list[i] = 0;
                else if (params->cipher_mode == TEST_PON_CNTR) {
                        if (job_size < 8)
                                cipher_size_list[i] = 8;
                        else
                                cipher_size_list[i] =
                                        (job_size + 3) & 0xfffffffc;
                } else
                        cipher_size_list[i] = job_size;

                if ((params->hash_alg == TEST_HASH_CCM) ||
                    (params->hash_alg == TEST_HASH_GCM))
                        hash_size_list[i] = job_size;
                else
                        hash_size_list[i] = job_size + sha_size_incr;

                /*
                 * CMAC bit level version is done in bits (length is
                 * converted to bits and it is decreased by 4 bits,
                 * to force the CMAC bitlen path)
                 */
                if (params->hash_alg == TEST_HASH_CMAC_BITLEN)
                        hash_size_list[i] = hash_size_list[i] * 8 - 4;
                else if ((params->hash_alg == TEST_ZUC_EIA3) ||
                         (params->hash_alg == TEST_ZUC256_EIA3) ||
                         (params->hash_alg == TEST_SNOW3G_UIA2))
                        hash_size_list[i] *= 8;
                else if (params->hash_alg == TEST_PON_CRC_BIP) {
                        sha_size_incr = 8;
                        if (job_size < 8)
                                hash_size_list[i] = 8;
                        else
                                hash_size_list[i] = (job_size + 3) & 0xfffffffc;
                        hash_size_list[i] += sha_size_incr;
                } else if (params->hash_alg == TEST_NULL_HASH)
                        hash_size_list[i] = 0;

                if (((params->cipher_mode == TEST_AESDOCSIS) ||
                    (params->cipher_mode == TEST_AESDOCSIS8)) &&
                    (params->hash_alg == TEST_DOCSIS_CRC32)) {
                        const uint32_t ciph_adjust = /* SA + DA */
                               IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE - 2;
                               /* ETH TYPE */

                        hash_size_list[i] = cipher_size_list[i] + ciph_adjust;
                        cipher_size_list[i] -= IMB_DOCSIS_CRC32_TAG_SIZE;
                }

                if (params->hash_alg == TEST_PON_CRC_BIP) {
                        /* create XGEM header template */
                        const uint64_t pli =
                                (job_size << 2) & 0xffff;

                        xgem_hdr_list[i] = ((pli >> 8) & 0xff) |
                                        ((pli & 0xff) << 8);
                }

        }
}

/* Performs test using AES_HMAC or DOCSIS */
static uint64_t
do_test(IMB_MGR *mb_mgr, struct params_s *params,
        const uint32_t num_iter, uint8_t *p_buffer, imb_uint128_t *p_keys)
{
        IMB_JOB *job;
        IMB_JOB job_template;
        uint32_t i;
        static uint32_t index = 0;
        static DECLARE_ALIGNED(imb_uint128_t iv, 16);
        static DECLARE_ALIGNED(imb_uint128_t auth_iv, 16);
        static uint32_t ipad[5], opad[5], digest[3];
        static DECLARE_ALIGNED(uint32_t k1_expanded[11 * 4], 16);
        static DECLARE_ALIGNED(uint8_t	k2[16], 16);
        static DECLARE_ALIGNED(uint8_t	k3[16], 16);
        static DECLARE_ALIGNED(struct gcm_key_data gdata_key, 512);
        uint64_t time = 0;
        uint32_t aux;
        uint8_t gcm_key[32];
        uint8_t next_iv[IMB_AES_BLOCK_SIZE];
        IMB_JOB jobs[MAX_BURST_SIZE];
        struct gcm_context_data gcm_ctx[MAX_BURST_SIZE];
        struct chacha20_poly1305_context_data cp_ctx[MAX_BURST_SIZE];
        struct IMB_SGL_IOV *sgl[MAX_BURST_SIZE] = {NULL};
        uint32_t max_num_segs = 1;

        memset(&job_template, 0, sizeof(IMB_JOB));

        /* Set cipher and hash length arrays to be used in each job,
           and set the XGEM header in case PON is used. */
        set_size_lists(cipher_size_list, hash_size_list, xgem_hdr_list, params);

        if (segment_size != 0)
                max_num_segs = DIV_ROUND_UP(job_sizes[RANGE_MAX],
                                            segment_size);

        for (i = 0; i < MAX_BURST_SIZE; i++) {
                sgl[i] = malloc(sizeof(struct IMB_SGL_IOV) *
                                max_num_segs);
                if (sgl[i] == NULL) {
                        fprintf(stderr, "malloc() failed\n");
                        goto exit;
                }
        }

        /*
         * If single size is used, set the cipher and hash lengths in the
         * job template, so they don't have to be set in every job
         */
        if (imix_list_count == 0) {
                job_template.msg_len_to_cipher_in_bytes = cipher_size_list[0];
                job_template.msg_len_to_hash_in_bytes = hash_size_list[0];
        }
        job_template.hash_start_src_offset_in_bytes = 0;
        job_template.cipher_start_src_offset_in_bytes = sha_size_incr;
        job_template.iv = (uint8_t *) &iv;
        job_template.iv_len_in_bytes = 16;

        job_template.auth_tag_output = (uint8_t *) digest;

        switch (params->hash_alg) {
        case TEST_SHA1:
                job_template.hash_alg = IMB_AUTH_SHA_1;
                break;
        case TEST_SHA_224:
                job_template.hash_alg = IMB_AUTH_SHA_224;
                break;
        case TEST_SHA_256:
                job_template.hash_alg = IMB_AUTH_SHA_256;
                break;
        case TEST_SHA_384:
                job_template.hash_alg = IMB_AUTH_SHA_384;
                break;
        case TEST_SHA_512:
                job_template.hash_alg = IMB_AUTH_SHA_512;
                break;
        case TEST_XCBC:
                job_template.u.XCBC._k1_expanded = k1_expanded;
                job_template.u.XCBC._k2 = k2;
                job_template.u.XCBC._k3 = k3;
                job_template.hash_alg = IMB_AUTH_AES_XCBC;
                break;
        case TEST_HASH_CCM:
                job_template.hash_alg = IMB_AUTH_AES_CCM;
                break;
        case TEST_HASH_GCM:
                if (segment_size != 0)
                        job_template.hash_alg = IMB_AUTH_GCM_SGL;
                else
                        job_template.hash_alg = IMB_AUTH_AES_GMAC;
                break;
        case TEST_DOCSIS_CRC32:
                job_template.hash_alg = IMB_AUTH_DOCSIS_CRC32;
                break;
        case TEST_NULL_HASH:
                job_template.hash_alg = IMB_AUTH_NULL;
                break;
        case TEST_HASH_CMAC:
                job_template.u.CMAC._key_expanded = k1_expanded;
                job_template.u.CMAC._skey1 = k2;
                job_template.u.CMAC._skey2 = k3;
                job_template.hash_alg = IMB_AUTH_AES_CMAC;
                break;
        case TEST_HASH_CMAC_BITLEN:
                job_template.u.CMAC._key_expanded = k1_expanded;
                job_template.u.CMAC._skey1 = k2;
                job_template.u.CMAC._skey2 = k3;
                job_template.hash_alg = IMB_AUTH_AES_CMAC_BITLEN;
                break;
        case TEST_HASH_CMAC_256:
                job_template.u.CMAC._key_expanded = k1_expanded;
                job_template.u.CMAC._skey1 = k2;
                job_template.u.CMAC._skey2 = k3;
                job_template.hash_alg = IMB_AUTH_AES_CMAC_256;
                break;
        case TEST_HASH_POLY1305:
                job_template.u.POLY1305._key = k1_expanded;
                job_template.hash_alg = IMB_AUTH_POLY1305;
                break;
        case TEST_AEAD_POLY1305:
                if (segment_size != 0)
                        job_template.hash_alg = IMB_AUTH_CHACHA20_POLY1305_SGL;
                else
                        job_template.hash_alg = IMB_AUTH_CHACHA20_POLY1305;
                break;
        case TEST_PON_CRC_BIP:
                job_template.hash_alg = IMB_AUTH_PON_CRC_BIP;
                job_template.cipher_start_src_offset_in_bytes = 8;
                break;
        case TEST_ZUC_EIA3:
                job_template.hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN;
                job_template.u.ZUC_EIA3._key = k3;
                job_template.u.ZUC_EIA3._iv = (uint8_t *) &auth_iv;
                break;
        case TEST_ZUC256_EIA3:
                job_template.hash_alg = IMB_AUTH_ZUC256_EIA3_BITLEN;
                job_template.u.ZUC_EIA3._key = k3;
                job_template.u.ZUC_EIA3._iv = (uint8_t *) &auth_iv;
                break;
        case TEST_SNOW3G_UIA2:
                job_template.hash_alg = IMB_AUTH_SNOW3G_UIA2_BITLEN;
                job_template.u.SNOW3G_UIA2._key = k3;
                job_template.u.SNOW3G_UIA2._iv = (uint8_t *)&auth_iv;
                break;
        case TEST_KASUMI_UIA1:
                job_template.hash_alg = IMB_AUTH_KASUMI_UIA1;
                job_template.u.KASUMI_UIA1._key = k3;
                break;
        case TEST_AES_GMAC_128:
                job_template.hash_alg = IMB_AUTH_AES_GMAC_128;
                IMB_AES128_GCM_PRE(mb_mgr, gcm_key, &gdata_key);
                job_template.u.GMAC._key = &gdata_key;
                job_template.u.GMAC._iv = (uint8_t *) &auth_iv;
                job_template.u.GMAC.iv_len_in_bytes = 12;
                break;
        case TEST_AES_GMAC_192:
                job_template.hash_alg = IMB_AUTH_AES_GMAC_192;
                IMB_AES192_GCM_PRE(mb_mgr, gcm_key, &gdata_key);
                job_template.u.GMAC._key = &gdata_key;
                job_template.u.GMAC._iv = (uint8_t *) &auth_iv;
                job_template.u.GMAC.iv_len_in_bytes = 12;
                break;
        case TEST_AES_GMAC_256:
                job_template.hash_alg = IMB_AUTH_AES_GMAC_256;
                IMB_AES256_GCM_PRE(mb_mgr, gcm_key, &gdata_key);
                job_template.u.GMAC._key = &gdata_key;
                job_template.u.GMAC._iv = (uint8_t *) &auth_iv;
                job_template.u.GMAC.iv_len_in_bytes = 12;
                break;
        case TEST_AUTH_GHASH:
                job_template.hash_alg = IMB_AUTH_GHASH;
                IMB_GHASH_PRE(mb_mgr, gcm_key, &gdata_key);
                job_template.u.GHASH._key = &gdata_key;
                job_template.u.GHASH._init_tag = (uint8_t *) &auth_iv;
                break;
        case TEST_AUTH_SNOW_V_AEAD:
                job_template.hash_alg = IMB_AUTH_SNOW_V_AEAD;
                break;
        case TEST_CRC32_ETHERNET_FCS:
                job_template.hash_alg = IMB_AUTH_CRC32_ETHERNET_FCS;
                break;
        case TEST_CRC32_SCTP:
                job_template.hash_alg = IMB_AUTH_CRC32_SCTP;
                break;
        case TEST_CRC32_WIMAX_OFDMA_DATA:
                job_template.hash_alg = IMB_AUTH_CRC32_WIMAX_OFDMA_DATA;
                break;
        case TEST_CRC24_LTE_A:
                job_template.hash_alg = IMB_AUTH_CRC24_LTE_A;
                break;
        case TEST_CRC24_LTE_B:
                job_template.hash_alg = IMB_AUTH_CRC24_LTE_B;
                break;
        case TEST_CRC16_X25:
                job_template.hash_alg = IMB_AUTH_CRC16_X25;
                break;
        case TEST_CRC16_FP_DATA:
                job_template.hash_alg = IMB_AUTH_CRC16_FP_DATA;
                break;
        case TEST_CRC11_FP_HEADER:
                job_template.hash_alg = IMB_AUTH_CRC11_FP_HEADER;
                break;
        case TEST_CRC10_IUUP_DATA:
                job_template.hash_alg = IMB_AUTH_CRC10_IUUP_DATA;
                break;
        case TEST_CRC8_WIMAX_OFDMA_HCS:
                job_template.hash_alg = IMB_AUTH_CRC8_WIMAX_OFDMA_HCS;
                break;
        case TEST_CRC7_FP_HEADER:
                job_template.hash_alg = IMB_AUTH_CRC7_FP_HEADER;
                break;
        case TEST_CRC6_IUUP_HEADER:
                job_template.hash_alg = IMB_AUTH_CRC6_IUUP_HEADER;
                break;
        default:
                /* HMAC hash alg is SHA1 or MD5 */
                job_template.u.HMAC._hashed_auth_key_xor_ipad =
                        (uint8_t *) ipad;
                job_template.u.HMAC._hashed_auth_key_xor_opad =
                        (uint8_t *) opad;
                job_template.hash_alg = (IMB_HASH_ALG) params->hash_alg;
                break;
        }
        if (tag_size == 0)
                job_template.auth_tag_output_len_in_bytes =
                    (uint64_t) auth_tag_length_bytes[job_template.hash_alg - 1];
        else
                job_template.auth_tag_output_len_in_bytes = tag_size;

        job_template.cipher_direction = params->cipher_dir;

        if (params->cipher_mode == TEST_NULL_CIPHER) {
                job_template.chain_order = IMB_ORDER_HASH_CIPHER;
        } else if (params->cipher_mode == TEST_CCM ||
                   ((params->cipher_mode == TEST_AESDOCSIS ||
                     params->cipher_mode == TEST_AESDOCSIS8) &&
                    params->hash_alg == TEST_DOCSIS_CRC32)) {
                if (job_template.cipher_direction == IMB_DIR_ENCRYPT)
                        job_template.chain_order = IMB_ORDER_HASH_CIPHER;
                else
                        job_template.chain_order = IMB_ORDER_CIPHER_HASH;
        } else {
                if (job_template.cipher_direction == IMB_DIR_ENCRYPT)
                        job_template.chain_order = IMB_ORDER_CIPHER_HASH;
                else
                        job_template.chain_order = IMB_ORDER_HASH_CIPHER;
        }

        /* Translating enum to the API's one */
        job_template.cipher_mode = translate_cipher_mode(params->cipher_mode);
        job_template.key_len_in_bytes = params->aes_key_size;
        if (job_template.cipher_mode == IMB_CIPHER_GCM ||
            job_template.cipher_mode == IMB_CIPHER_GCM_SGL) {
                switch (params->aes_key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_PRE(mb_mgr, gcm_key, &gdata_key);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_PRE(mb_mgr, gcm_key, &gdata_key);
                        break;
                case IMB_KEY_256_BYTES:
                default:
                        IMB_AES256_GCM_PRE(mb_mgr, gcm_key, &gdata_key);
                        break;
                }
                job_template.enc_keys = &gdata_key;
                job_template.dec_keys = &gdata_key;
                job_template.u.GCM.aad_len_in_bytes = params->aad_size;
                job_template.iv_len_in_bytes = 12;
        } else if (job_template.cipher_mode == IMB_CIPHER_CCM) {
                job_template.hash_start_src_offset_in_bytes = 0;
                job_template.cipher_start_src_offset_in_bytes = 0;
                job_template.u.CCM.aad_len_in_bytes = params->aad_size;
                job_template.iv_len_in_bytes = 13;
        } else if (job_template.cipher_mode == IMB_CIPHER_DES ||
                   job_template.cipher_mode == IMB_CIPHER_DOCSIS_DES) {
                job_template.key_len_in_bytes = 8;
                job_template.iv_len_in_bytes = 8;
        } else if (job_template.cipher_mode == IMB_CIPHER_DES3) {
                job_template.key_len_in_bytes = 24;
                job_template.iv_len_in_bytes = 8;
        } else if (job_template.cipher_mode == IMB_CIPHER_ZUC_EEA3) {
                if (params->aes_key_size == 16) {
                        job_template.key_len_in_bytes = 16;
                        job_template.iv_len_in_bytes = 16;
                } else {
                        job_template.key_len_in_bytes = 32;
                        job_template.iv_len_in_bytes = 25;
                }
        } else if (job_template.cipher_mode == IMB_CIPHER_DOCSIS_SEC_BPI &&
                   job_template.hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                const uint64_t ciph_adjust = /* SA + DA */
                        IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE - 2 /* ETH TYPE */;

                job_template.cipher_start_src_offset_in_bytes = ciph_adjust;
                job_template.hash_start_src_offset_in_bytes = 0;
        } else if (job_template.cipher_mode == IMB_CIPHER_SNOW3G_UEA2_BITLEN) {
                job_template.cipher_start_src_offset_in_bits = 0;
                job_template.key_len_in_bytes = 16;
                job_template.iv_len_in_bytes = 16;
        } else if (job_template.cipher_mode == IMB_CIPHER_KASUMI_UEA1_BITLEN) {
                job_template.cipher_start_src_offset_in_bits = 0;
                job_template.key_len_in_bytes = 16;
                job_template.iv_len_in_bytes = 8;
        } else if (job_template.cipher_mode == IMB_CIPHER_CBCS_1_9) {
                job_template.key_len_in_bytes = 16; /* cbcs-128 support only */
                job_template.cipher_fields.CBCS.next_iv = next_iv;
        } else if (job_template.cipher_mode == IMB_CIPHER_ECB)
                job_template.iv_len_in_bytes = 0;
        else if (job_template.cipher_mode == IMB_CIPHER_CHACHA20)
                job_template.iv_len_in_bytes = 12;
        else if (job_template.cipher_mode == IMB_CIPHER_CHACHA20_POLY1305 ||
                 job_template.cipher_mode == IMB_CIPHER_CHACHA20_POLY1305_SGL) {
                job_template.hash_start_src_offset_in_bytes = 0;
                job_template.cipher_start_src_offset_in_bytes = 0;
                job_template.enc_keys = k1_expanded;
                job_template.dec_keys = k1_expanded;
                job_template.u.CHACHA20_POLY1305.aad_len_in_bytes =
                        params->aad_size;
                job_template.iv_len_in_bytes = 12;
        } else if (job_template.cipher_mode == IMB_CIPHER_SNOW_V)
                job_template.iv_len_in_bytes = 16;
        else if (job_template.cipher_mode == IMB_CIPHER_SNOW_V_AEAD &&
                job_template.hash_alg == IMB_AUTH_SNOW_V_AEAD) {
                job_template.key_len_in_bytes = 32;
                job_template.iv_len_in_bytes = 16;
                job_template.u.SNOW_V_AEAD.aad_len_in_bytes =
                        params->aad_size;
        }

#define TIMEOUT_MS 100 /*< max time for one packet size to be tested for */

        uint32_t jobs_done = 0; /*< to track how many jobs done over time */
#ifdef _WIN32
        HANDLE hTimebox = NULL;
        HANDLE hTimeboxQueue = NULL;
#endif

        if (use_timebox) {
#ifdef LINUX
                struct itimerval it_next;

                /* set up one shot timer */
                it_next.it_interval.tv_sec = 0;
                it_next.it_interval.tv_usec = 0;
                it_next.it_value.tv_sec = TIMEOUT_MS / 1000;
                it_next.it_value.tv_usec = (TIMEOUT_MS % 1000) * 1000;
                if (setitimer(ITIMER_REAL, &it_next, NULL)) {
                        perror("setitimer(one-shot)");
                        goto exit;
                }
#else /* _WIN32 */
                /* create the timer queue */
                hTimeboxQueue = CreateTimerQueue();
                if (NULL == hTimeboxQueue) {
                        fprintf(stderr, "CreateTimerQueue() error %u\n",
                                (unsigned) GetLastError());
                        goto exit;
                }

                /* set a timer to call the timebox */
                if (!CreateTimerQueueTimer(&hTimebox, hTimeboxQueue,
                                           (WAITORTIMERCALLBACK)
                                           timebox_callback,
                                           NULL, TIMEOUT_MS, 0, 0)) {
                        fprintf(stderr, "CreateTimerQueueTimer() error %u\n",
                                (unsigned) GetLastError());
                        goto exit;
                }
#endif
                timebox_on = 1;
        }

#ifndef _WIN32
        if (use_unhalted_cycles)
                time = read_cycles(params->core);
        else
#endif
                time = __rdtscp(&aux);

        /* test burst api */
        if (test_api == TEST_API_BURST) {
                uint32_t num_jobs = num_iter;
                IMB_JOB *jobs[IMB_MAX_BURST_SIZE] = {NULL};

                while (num_jobs && timebox_on) {
                        uint32_t n = (num_jobs / burst_size) ?
                                burst_size : num_jobs;

                        while (IMB_GET_NEXT_BURST(mb_mgr, n, jobs) < n)
                                IMB_FLUSH_BURST(mb_mgr, n, jobs);

                        /* set all job params */
                        for (i = 0; i < n; i++) {
                                IMB_JOB *job = jobs[i];
                                *job = job_template;

                                if (segment_size != 0)
                                        set_sgl_job_fields(job, p_buffer,
                                                           p_keys, i,
                                                           index, sgl[i],
                                                           &gcm_ctx[i],
                                                           &cp_ctx[i]);
                                else
                                        set_job_fields(job, p_buffer, p_keys,
                                                       i, index);

                                index = get_next_index(index);

                        }
                        /* submit burst */
#ifdef DEBUG
                        jobs_done += IMB_SUBMIT_BURST(mb_mgr, n, jobs);
                        if (jobs_done == 0) {
                                const int err = imb_get_errno(mb_mgr);

                                if (err != 0) {
                                        printf("submit_burst error %d : '%s'\n",
                                               err, imb_get_strerror(err));
                                }
                        }
#else
                        jobs_done +=
                                IMB_SUBMIT_BURST_NOCHECK(mb_mgr, n, jobs);
#endif
                        num_jobs -= n;
                }
                jobs_done +=
                        IMB_FLUSH_BURST(mb_mgr, IMB_MAX_BURST_SIZE, jobs);

                /* test cipher-only burst api */
        } else if (test_api == TEST_API_CIPHER_BURST) {
                IMB_JOB *jt = &job_template;
                uint32_t num_jobs = num_iter;
                uint32_t list_idx;

                while (num_jobs && timebox_on) {
                        uint32_t n_jobs =
                                (num_jobs / burst_size) ? burst_size : num_jobs;

                        /* set all job params */
                        for (i = 0; i < n_jobs; i++) {
                                job = &jobs[i];

                                /* If IMIX testing is being done, set the buffer
                                 * size to cipher going through the
                                 * list of sizes precalculated */
                                if (imix_list_count != 0) {
                                        list_idx = i & (JOB_SIZE_IMIX_LIST - 1);
                                        job->msg_len_to_cipher_in_bytes =
                                                cipher_size_list[list_idx];
                                } else
                                        job->msg_len_to_cipher_in_bytes =
                                                jt->msg_len_to_cipher_in_bytes;

                                job->src = get_src_buffer(index, p_buffer);
                                job->dst = get_dst_buffer(index, p_buffer);
                                job->enc_keys = job->dec_keys =
                                        (const uint32_t *)
                                        get_key_pointer(index, p_keys);
                                job->cipher_start_src_offset_in_bytes =
                                        jt->cipher_start_src_offset_in_bytes;
                                job->iv = jt->iv;
                                job->iv_len_in_bytes = jt->iv_len_in_bytes;

                                index = get_next_index(index);
                        }
                        /* submit cipher-only burst */
#ifdef DEBUG
                        const uint32_t completed_jobs =
                                IMB_SUBMIT_CIPHER_BURST(mb_mgr, jobs, n_jobs,
                                                        jt->cipher_mode,
                                                        jt->cipher_direction,
                                                        jt->key_len_in_bytes);

                        if (completed_jobs != n_jobs) {
                                const int err = imb_get_errno(mb_mgr);

                                if (err != 0) {
                                        printf("submit_cipher_burst error "
                                               "%d : '%s'\n", err,
                                               imb_get_strerror(err));
                                }
                        }
#else
                        IMB_SUBMIT_CIPHER_BURST_NOCHECK(mb_mgr, jobs, n_jobs,
                                                        jt->cipher_mode,
                                                        jt->cipher_direction,
                                                        jt->key_len_in_bytes);
#endif
                        num_jobs -= n_jobs;
                }
                jobs_done = num_iter - num_jobs;

                /* test hash-only burst api */
        } else if (test_api == TEST_API_HASH_BURST) {
                IMB_JOB *jt = &job_template;
                uint32_t num_jobs = num_iter;
                uint32_t list_idx;

                while (num_jobs && timebox_on) {
                        uint32_t n_jobs =
                                (num_jobs / burst_size) ? burst_size : num_jobs;

                        /* set all job params */
                        for (i = 0; i < n_jobs; i++) {
                                job = &jobs[i];

                                /* If IMIX testing is being done, set the buffer
                                 * size to cipher going through the
                                 * list of sizes precalculated */
                                if (imix_list_count != 0) {
                                        list_idx = i & (JOB_SIZE_IMIX_LIST - 1);
                                        job->msg_len_to_hash_in_bytes =
                                                hash_size_list[list_idx];
                                } else
                                        job->msg_len_to_hash_in_bytes =
                                                jt->msg_len_to_hash_in_bytes;

                                job->src = get_src_buffer(index, p_buffer);
                                job->hash_start_src_offset_in_bytes =
                                        jt->hash_start_src_offset_in_bytes;
                                job->auth_tag_output_len_in_bytes =
                                        jt->auth_tag_output_len_in_bytes;
                                job->u.HMAC._hashed_auth_key_xor_ipad =
                                        jt->u.HMAC._hashed_auth_key_xor_ipad;
                                job->u.HMAC._hashed_auth_key_xor_opad =
                                        jt->u.HMAC._hashed_auth_key_xor_opad;
                                job->auth_tag_output = jt->auth_tag_output;

                                index = get_next_index(index);
                        }
                        /* submit hash-only burst */
#ifdef DEBUG
                        const uint32_t completed_jobs =
                                IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, n_jobs,
                                                      jt->hash_alg);

                        if (completed_jobs != n_jobs) {
                                const int err = imb_get_errno(mb_mgr);

                                if (err != 0) {
                                        printf("submit_hash_burst error "
                                               "%d : '%s'\n", err,
                                               imb_get_strerror(err));
                                }
                        }
#else
                        IMB_SUBMIT_HASH_BURST_NOCHECK(mb_mgr, jobs, n_jobs,
                                                        jt->hash_alg);
#endif
                        num_jobs -= n_jobs;
                }
                jobs_done = num_iter - num_jobs;

        } else { /* test job api */
                for (i = 0; (i < num_iter) && timebox_on; i++) {
                        job = IMB_GET_NEXT_JOB(mb_mgr);
                        *job = job_template;

                        if (segment_size != 0)
                                set_sgl_job_fields(job, p_buffer, p_keys,
                                                   i, index,
                                                   sgl[0], &gcm_ctx[0],
                                                   &cp_ctx[0]);
                        else
                                set_job_fields(job, p_buffer, p_keys, i, index);

                        index = get_next_index(index);
#ifdef DEBUG
                        job = IMB_SUBMIT_JOB(mb_mgr);
#else
                        job = IMB_SUBMIT_JOB_NOCHECK(mb_mgr);
#endif
                        while (job) {
#ifdef DEBUG
                                if (job->status != IMB_STATUS_COMPLETED) {
                                        fprintf(stderr,
                                                "failed job, status:%d\n",
                                                job->status);
                                        goto exit;
                                }
#endif
                                job = IMB_GET_COMPLETED_JOB(mb_mgr);
                        }
                }
                jobs_done = i;

                while ((job = IMB_FLUSH_JOB(mb_mgr))) {
#ifdef DEBUG
                        if (job->status != IMB_STATUS_COMPLETED) {
                                const int errc = imb_get_errno(mb_mgr);

                                fprintf(stderr,
                                        "failed job, status:%d, "
                                        "error code:%d, %s\n", job->status,
                                        errc, imb_get_strerror(errc));
                                goto exit;
                        }
#else
                        (void)job;
#endif
                }

        } /* if test_api */

        for (i = 0; i < MAX_BURST_SIZE; i++) {
                free(sgl[i]);
                sgl[i] = NULL;
        }

#ifndef _WIN32
        if (use_unhalted_cycles)
                time = (read_cycles(params->core) - rd_cycles_cost) - time;
        else
#endif
                time = __rdtscp(&aux) - time;

        if (use_timebox) {
#ifdef LINUX
                /* disarm the timer */
                struct itimerval it_disarm;

                memset(&it_disarm, 0, sizeof(it_disarm));

                if (setitimer(ITIMER_REAL, &it_disarm, NULL)) {
                        perror("setitimer(disarm)");
                        goto exit;
                }
#else /* _WIN32 */
                /* delete all timeboxes in the timer queue */
                if (!DeleteTimerQueue(hTimeboxQueue))
                        fprintf(stderr, "DeleteTimerQueue() error %u\n",
                                (unsigned) GetLastError());
#endif

                /* calculate return value */
                if (jobs_done == 0)
                        return 0;

                return time / jobs_done;
        }

        if (!num_iter)
                return time;

        return time / num_iter;

exit:
        for (i = 0; i < MAX_BURST_SIZE; i++)
                free(sgl[i]);

        exit(EXIT_FAILURE);
}

static void
run_gcm_sgl(aes_gcm_init_t init, aes_gcm_enc_dec_update_t update,
            aes_gcm_enc_dec_finalize_t finalize,
            struct gcm_key_data *gdata_key,
            struct gcm_context_data *gdata_ctx,
            uint8_t *p_buffer, uint32_t buf_size,
            const void *aad, const uint64_t aad_size,
            const uint32_t num_iter)
{
        uint32_t i;
        static uint32_t index = 0;
        uint8_t auth_tag[12];
        DECLARE_ALIGNED(uint8_t iv[16], 16);

        /* SGL */
        if (segment_size != 0) {
                for (i = 0; i < num_iter; i++) {
                        uint8_t *pb = get_dst_buffer(index, p_buffer);

                        if (imix_list_count != 0)
                                buf_size = get_next_size(i);

                        const uint32_t num_segs = buf_size / segment_size;
                        const uint32_t final_seg_sz = buf_size % segment_size;
                        uint32_t j;

                        init(gdata_key, gdata_ctx, iv, aad, aad_size);
                        for (j = 0; j < num_segs; j++)
                                update(gdata_key, gdata_ctx,
                                       &pb[j*segment_size],
                                       &pb[j*segment_size],
                                       segment_size);
                        if (final_seg_sz != 0)
                                update(gdata_key, gdata_ctx,
                                       &pb[j*segment_size],
                                       &pb[j*segment_size],
                                       final_seg_sz);
                        finalize(gdata_key, gdata_ctx, auth_tag,
                                 sizeof(auth_tag));

                        index = get_next_index(index);
                }
        } else {
                for (i = 0; i < num_iter; i++) {
                        uint8_t *pb = get_dst_buffer(index, p_buffer);

                        if (imix_list_count != 0)
                                buf_size = get_next_size(i);

                        init(gdata_key, gdata_ctx, iv, aad, aad_size);
                        update(gdata_key, gdata_ctx, pb, pb, buf_size);
                        finalize(gdata_key, gdata_ctx, auth_tag,
                                 sizeof(auth_tag));

                        index = get_next_index(index);
                }
        }
}

static void
run_gcm(aes_gcm_enc_dec_t enc_dec,
        struct gcm_key_data *gdata_key,
        struct gcm_context_data *gdata_ctx,
        uint8_t *p_buffer, uint32_t buf_size,
        const void *aad, const uint64_t aad_size,
        const uint32_t num_iter)
{
        uint32_t i;
        uint32_t index = 0;
        uint8_t auth_tag[12];
        DECLARE_ALIGNED(uint8_t iv[16], 16);

        for (i = 0; i < num_iter; i++) {
                uint8_t *pb = get_dst_buffer(index, p_buffer);

                if (imix_list_count != 0)
                        buf_size = get_next_size(i);

                enc_dec(gdata_key, gdata_ctx, pb, pb,
                        buf_size, iv, aad, aad_size,
                        auth_tag, sizeof(auth_tag));

                index = get_next_index(index);
        }
}

/* Performs test using GCM */
static uint64_t
do_test_gcm(struct params_s *params,
            const uint32_t num_iter, IMB_MGR *mb_mgr,
            uint8_t *p_buffer, imb_uint128_t *p_keys)
{
        static DECLARE_ALIGNED(struct gcm_key_data gdata_key, 512);
        static DECLARE_ALIGNED(struct gcm_context_data gdata_ctx, 64);
        uint8_t *key;
        uint8_t *aad = NULL;
        uint64_t time = 0;
        uint32_t aux;

        /* Force SGL API if segment size is not 0 */
        if (segment_size != 0)
                use_gcm_sgl_api = 1;

        key = (uint8_t *) malloc(sizeof(uint8_t) * params->aes_key_size);
        if (!key) {
                fprintf(stderr, "Could not malloc key\n");
                free_mem(&p_buffer, &p_keys);
                exit(EXIT_FAILURE);
        }

        aad = (uint8_t *) malloc(sizeof(uint8_t) * params->aad_size);
        if (!aad) {
                free(key);
                fprintf(stderr, "Could not malloc AAD\n");
                free_mem(&p_buffer, &p_keys);
                exit(EXIT_FAILURE);
        }
        memset(key, 0, params->aes_key_size);

        switch (params->aes_key_size) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_PRE(mb_mgr, key, &gdata_key);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_PRE(mb_mgr, key, &gdata_key);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_PRE(mb_mgr, key, &gdata_key);
                break;
        }

        if (params->cipher_dir == IMB_DIR_ENCRYPT) {
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = read_cycles(params->core);
                else
#endif
                        time = __rdtscp(&aux);

                if (params->aes_key_size == IMB_KEY_128_BYTES) {
                        if (use_gcm_sgl_api)
                                run_gcm_sgl(mb_mgr->gcm128_init,
                                            mb_mgr->gcm128_enc_update,
                                            mb_mgr->gcm128_enc_finalize,
                                            &gdata_key, &gdata_ctx,
                                            p_buffer, params->size_aes,
                                            aad, params->aad_size,
                                            num_iter);
                        else
                                run_gcm(mb_mgr->gcm128_enc,
                                        &gdata_key, &gdata_ctx,
                                        p_buffer, params->size_aes,
                                        aad, params->aad_size,
                                        num_iter);
                } else if (params->aes_key_size == IMB_KEY_192_BYTES) {
                        if (use_gcm_sgl_api)
                                run_gcm_sgl(mb_mgr->gcm192_init,
                                            mb_mgr->gcm192_enc_update,
                                            mb_mgr->gcm192_enc_finalize,
                                            &gdata_key, &gdata_ctx,
                                            p_buffer, params->size_aes,
                                            aad, params->aad_size,
                                            num_iter);
                        else
                                run_gcm(mb_mgr->gcm192_enc,
                                        &gdata_key, &gdata_ctx,
                                        p_buffer, params->size_aes,
                                        aad, params->aad_size,
                                        num_iter);
                } else { /* 256 */
                        if (use_gcm_sgl_api)
                                run_gcm_sgl(mb_mgr->gcm256_init,
                                            mb_mgr->gcm256_enc_update,
                                            mb_mgr->gcm256_enc_finalize,
                                            &gdata_key, &gdata_ctx,
                                            p_buffer, params->size_aes,
                                            aad, params->aad_size,
                                            num_iter);
                        else
                                run_gcm(mb_mgr->gcm256_enc,
                                        &gdata_key, &gdata_ctx,
                                        p_buffer, params->size_aes,
                                        aad, params->aad_size,
                                        num_iter);
                }
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = (read_cycles(params->core) -
                                rd_cycles_cost) - time;
                else
#endif
                        time = __rdtscp(&aux) - time;
        } else { /*DECRYPT*/
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = read_cycles(params->core);
                else
#endif
                        time = __rdtscp(&aux);

                if (params->aes_key_size == IMB_KEY_128_BYTES) {
                        if (use_gcm_sgl_api)
                                run_gcm_sgl(mb_mgr->gcm128_init,
                                            mb_mgr->gcm128_dec_update,
                                            mb_mgr->gcm128_dec_finalize,
                                            &gdata_key, &gdata_ctx,
                                            p_buffer, params->size_aes,
                                            aad, params->aad_size,
                                            num_iter);
                        else
                                run_gcm(mb_mgr->gcm128_dec,
                                        &gdata_key, &gdata_ctx,
                                        p_buffer, params->size_aes,
                                        aad, params->aad_size,
                                        num_iter);
                } else if (params->aes_key_size == IMB_KEY_192_BYTES) {
                        if (use_gcm_sgl_api)
                                run_gcm_sgl(mb_mgr->gcm192_init,
                                            mb_mgr->gcm192_dec_update,
                                            mb_mgr->gcm192_dec_finalize,
                                            &gdata_key, &gdata_ctx,
                                            p_buffer, params->size_aes,
                                            aad, params->aad_size,
                                            num_iter);
                        else
                                run_gcm(mb_mgr->gcm192_dec,
                                        &gdata_key, &gdata_ctx,
                                        p_buffer, params->size_aes,
                                        aad, params->aad_size,
                                        num_iter);
                } else { /* 256 */
                        if (use_gcm_sgl_api)
                                run_gcm_sgl(mb_mgr->gcm256_init,
                                            mb_mgr->gcm256_dec_update,
                                            mb_mgr->gcm256_dec_finalize,
                                            &gdata_key, &gdata_ctx,
                                            p_buffer, params->size_aes,
                                            aad, params->aad_size,
                                            num_iter);
                        else
                                run_gcm(mb_mgr->gcm256_dec,
                                        &gdata_key, &gdata_ctx,
                                        p_buffer, params->size_aes,
                                        aad, params->aad_size,
                                        num_iter);
                }
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = (read_cycles(params->core) -
                                rd_cycles_cost) - time;
                else
#endif
                        time = __rdtscp(&aux) - time;
        }

        free(key);
        free(aad);

        if (!num_iter)
                return time;

        return time / num_iter;
}

/* Performs test using CHACHA20-POLY1305 direct API */
static uint64_t
do_test_chacha_poly(struct params_s *params,
                    const uint32_t num_iter, IMB_MGR *mb_mgr,
                    uint8_t *p_buffer, imb_uint128_t *p_keys)
{
        uint8_t key[32];
        uint8_t auth_tag[16];
        DECLARE_ALIGNED(uint8_t iv[16], 16);
        uint8_t *aad = NULL;
        uint64_t time = 0;
        uint32_t aux;
        struct chacha20_poly1305_context_data chacha_ctx;
        static uint32_t index = 0;
        uint32_t num_segs;
        uint32_t final_seg_sz;
        unsigned i, j;

        aad = (uint8_t *) malloc(sizeof(uint8_t) * params->aad_size);
        if (!aad) {
                fprintf(stderr, "Could not malloc AAD\n");
                free_mem(&p_buffer, &p_keys);
                exit(EXIT_FAILURE);
        }

        if (segment_size != 0) {
                num_segs = params->size_aes / segment_size;
                final_seg_sz = params->size_aes % segment_size;
        } else {
                num_segs = 0;
                final_seg_sz = params->size_aes;
        }

#ifndef _WIN32
        if (use_unhalted_cycles)
                time = read_cycles(params->core);
        else
#endif
                time = __rdtscp(&aux);

        for (i = 0; i < num_iter; i++) {
                uint8_t *pb = get_dst_buffer(index, p_buffer);

                if (imix_list_count != 0) {
                        uint32_t buf_size = get_next_size(i);

                        if (segment_size != 0) {
                                num_segs = buf_size / segment_size;
                                final_seg_sz = buf_size % segment_size;
                        } else {
                                num_segs = 0;
                                final_seg_sz = buf_size;
                        }
                }

                IMB_CHACHA20_POLY1305_INIT(mb_mgr, key, &chacha_ctx, iv,
                                           aad, params->aad_size);

                if (params->cipher_dir == IMB_DIR_ENCRYPT) {
                        for (j = 0; j < num_segs; j++)
                                IMB_CHACHA20_POLY1305_ENC_UPDATE(mb_mgr, key,
                                                         &chacha_ctx,
                                                         &pb[j*segment_size],
                                                         &pb[j*segment_size],
                                                         segment_size);
                        if (final_seg_sz != 0)
                                IMB_CHACHA20_POLY1305_ENC_UPDATE(mb_mgr, key,
                                                         &chacha_ctx,
                                                         &pb[j*segment_size],
                                                         &pb[j*segment_size],
                                                         final_seg_sz);
                        IMB_CHACHA20_POLY1305_ENC_FINALIZE(mb_mgr,
                                                           &chacha_ctx,
                                                           auth_tag,
                                                           sizeof(auth_tag));
                } else { /* IMB_DIR_DECRYPT */
                        for (j = 0; j < num_segs; j++)
                                IMB_CHACHA20_POLY1305_ENC_UPDATE(mb_mgr, key,
                                                         &chacha_ctx,
                                                         &pb[j*segment_size],
                                                         &pb[j*segment_size],
                                                         segment_size);
                        if (final_seg_sz != 0)
                                IMB_CHACHA20_POLY1305_DEC_UPDATE(mb_mgr, key,
                                                         &chacha_ctx,
                                                         &pb[j*segment_size],
                                                         &pb[j*segment_size],
                                                         final_seg_sz);
                        IMB_CHACHA20_POLY1305_DEC_FINALIZE(mb_mgr,
                                                           &chacha_ctx,
                                                           auth_tag,
                                                           sizeof(auth_tag));
                }
                index = get_next_index(index);
        }
#ifndef _WIN32
        if (use_unhalted_cycles)
                time = (read_cycles(params->core) -
                        rd_cycles_cost) - time;
        else
#endif
                time = __rdtscp(&aux) - time;

        free(aad);

        if (!num_iter)
                return time;

        return time / num_iter;
}

/* Performs test using GCM */
static uint64_t
do_test_ghash(struct params_s *params,
              const uint32_t num_iter, IMB_MGR *mb_mgr,
              uint8_t *p_buffer, imb_uint128_t *p_keys)
{
        static DECLARE_ALIGNED(struct gcm_key_data gdata_key, 512);
        uint64_t time = 0;
        uint32_t aux;
        uint32_t i, index = 0;
        uint8_t auth_tag[16];

        IMB_GHASH_PRE(mb_mgr, p_keys, &gdata_key);

#ifndef _WIN32
        if (use_unhalted_cycles)
                time = read_cycles(params->core);
        else
#endif
                time = __rdtscp(&aux);

        if (imix_list_count != 0) {
                for (i = 0; i < num_iter; i++) {
                        uint8_t *pb = get_dst_buffer(index, p_buffer);
                        const uint32_t buf_size = get_next_size(i);

                        IMB_GHASH(mb_mgr, &gdata_key, pb, buf_size,
                                  auth_tag, sizeof(auth_tag));
                        index = get_next_index(index);
                }
        } else {
                for (i = 0; i < num_iter; i++) {
                        uint8_t *pb = get_dst_buffer(index, p_buffer);
                        const uint32_t buf_size = params->size_aes;

                        IMB_GHASH(mb_mgr, &gdata_key, pb, buf_size,
                                  auth_tag, sizeof(auth_tag));
                        index = get_next_index(index);
                }
        }

#ifndef _WIN32
        if (use_unhalted_cycles)
                time = (read_cycles(params->core) -
                        rd_cycles_cost) - time;
        else
#endif
                time = __rdtscp(&aux) - time;

        if (!num_iter)
                return time;

        return time / num_iter;
}

/* Computes mean of set of times after dropping bottom and top quarters */
static uint64_t
mean_median(uint64_t *array, uint32_t size,
            uint8_t *p_buffer, imb_uint128_t *p_keys)
{
        const uint32_t quarter = size / 4;
        uint32_t i;
        uint64_t sum;

        /* these are single threaded runs, so we skip
         * the hardware thread related skew clipping
         * thus skipping "ignore first and last eighth"
         */

        /* ignore lowest and highest quarter */
        qsort(array, size, sizeof(uint64_t), compare_uint64_t);

        /* dropping the bottom and top quarters
         * after sorting to remove noise/variations
         */
        array += quarter;
        size -= quarter * 2;


        if ((size == 0) || (size & 0x80000000)) {
                fprintf(stderr, "Not enough data points!\n");
                free_mem(&p_buffer, &p_keys);
                exit(EXIT_FAILURE);
        }
        sum = 0;
        for (i = 0; i < size; i++)
                sum += array[i];

        sum = (sum + size / 2) / size;
        return sum;
}

/* Runs test for each buffer size and stores averaged execution time */
static void
process_variant(IMB_MGR *mgr, const enum arch_type_e arch,
                struct params_s *params,
                struct variant_s *variant_ptr, const uint32_t run,
                uint8_t *p_buffer, imb_uint128_t *p_keys)
{
        uint32_t sizes = params->num_sizes;
        uint64_t *times = &variant_ptr->avg_times[run];
        uint32_t sz;
        uint32_t size_aes;

        if (imix_list_count != 0)
                sizes = 1;

        for (sz = 0; sz < sizes; sz++) {
                if (job_size_count == 0)
                        size_aes = job_sizes[RANGE_MIN] +
                                        (sz * job_sizes[RANGE_STEP]);
                else
                        size_aes = job_size_list[sz];

                uint32_t num_iter;

                params->aad_size = 0;
                if (params->cipher_mode == TEST_GCM)
                        params->aad_size = gcm_aad_size;

                if (params->cipher_mode == TEST_CCM)
                        params->aad_size = ccm_aad_size;

                if (params->cipher_mode == TEST_AEAD_CHACHA20)
                        params->aad_size = chacha_poly_aad_size;

                if (params->cipher_mode == TEST_SNOW_V_AEAD)
                        params->aad_size = snow_v_aad_size;

                /*
                 * If job size == 0, check AAD size
                 * (only allowed for GCM/CCM)
                 */
                if (size_aes == 0 && params->aad_size != 0)
                        num_iter = (iter_scale >= (uint32_t)params->aad_size) ?
                                   (iter_scale / (uint32_t)params->aad_size) :
                                   1;
                else if (size_aes != 0)
                        num_iter = (iter_scale >= size_aes) ?
                                   (iter_scale / size_aes) : 1;
                else
                        num_iter = iter_scale;

                params->size_aes = size_aes;
                if (params->cipher_mode == TEST_GCM && (!use_job_api)) {
                        if (job_iter == 0)
                                *times = do_test_gcm(params, 2 * num_iter, mgr,
                                                     p_buffer, p_keys);
                        else
                                *times = do_test_gcm(params, job_iter, mgr,
                                                     p_buffer, p_keys);
                } else if (params->cipher_mode == TEST_AEAD_CHACHA20 &&
                           (!use_job_api)) {
                        if (job_iter == 0)
                                *times = do_test_chacha_poly(params,
                                                     2 * num_iter, mgr,
                                                     p_buffer, p_keys);
                        else
                                *times = do_test_chacha_poly(params,
                                                     job_iter, mgr,
                                                     p_buffer, p_keys);
                } else if (params->hash_alg == TEST_AUTH_GHASH &&
                           (!use_job_api)) {
                        if (job_iter == 0)
                                *times = do_test_ghash(params, 2 * num_iter,
                                                       mgr, p_buffer, p_keys);
                        else
                                *times = do_test_ghash(params, job_iter, mgr,
                                                       p_buffer, p_keys);
                } else {
                        if (job_iter == 0)
                                *times = do_test(mgr, params, num_iter,
                                                 p_buffer, p_keys);
                        else
                                *times = do_test(mgr, params, job_iter,
                                                 p_buffer, p_keys);
                }
                times += NUM_RUNS;
        }

        variant_ptr->params = *params;
        variant_ptr->arch = arch;
}

/* Generates output containing averaged times for each test variant */
static void
print_times(struct variant_s *variant_list, struct params_s *params,
            const uint32_t total_variants, uint8_t *p_buffer,
            imb_uint128_t *p_keys)
{
        /* If IMIX is used, only show the average size */
        const uint32_t sizes = (imix_list_count != 0) ? 1 : params->num_sizes;
        uint32_t col;
        uint32_t sz;

        if (plot_output_option == 0) {
                const char *func_names[4] = {
                        "SSE", "AVX", "AVX2", "AVX512"
                };
                const char *c_mode_names[TEST_NUM_CIPHER_TESTS - 1] = {
                        "CBC", "CNTR", "CNTR+8", "CNTR_BITLEN", "CNTR_BITLEN4",
                        "ECB", "CBCS_1_9", "NULL_CIPHER", "DOCAES", "DOCAES+8",
                        "DOCDES", "DOCDES+4", "GCM", "CCM", "DES", "3DES",
                        "PON", "PON_NO_CTR", "ZUC_EEA3", "SNOW3G_UEA2_BITLEN",
                        "KASUMI_UEA1_BITLEN", "CHACHA20", "CHACHA20_AEAD",
                        "SNOW_V", "SNOW_V_AEAD"
                };
                const char *c_dir_names[2] = {
                        "ENCRYPT", "DECRYPT"
                };
                const char *h_alg_names[TEST_NUM_HASH_TESTS - 1] = {
                        "SHA1_HMAC", "SHA_224_HMAC", "SHA_256_HMAC",
                        "SHA_384_HMAC", "SHA_512_HMAC", "XCBC",
                        "MD5", "CMAC", "SHA1", "SHA_224", "SHA_256",
                        "SHA_384", "SHA_512", "CMAC_BITLEN", "CMAC_256",
                        "NULL_HASH", "CRC32", "GCM", "CUSTOM", "CCM",
                        "BIP-CRC32", "ZUC_EIA3_BITLEN", "SNOW3G_UIA2_BITLEN",
                        "KASUMI_UIA1", "GMAC-128", "GMAC-192", "GMAC-256",
                        "POLY1305", "POLY1305_AEAD", "ZUC256_EIA3",
                        "SNOW_V_AEAD", "CRC32_ETH_FCS", "CRC32_SCTP",
                        "CRC32_WIMAX_DATA", "CRC24_LTE_A", "CR24_LTE_B",
                        "CR16_X25", "CRC16_FP_DATA", "CRC11_FP_HEADER",
                        "CRC10_IUUP_DATA", "CRC8_WIMAX_HCS", "CRC7_FP_HEADER",
                        "CRC6_IUUP_HEADER", "GHASH"
                };
                struct params_s par;

                printf("ARCH");
                for (col = 0; col < total_variants; col++)
                        printf("\t%s", func_names[variant_list[col].arch]);
                printf("\n");
                printf("CIPHER");
                for (col = 0; col < total_variants; col++) {
                        par = variant_list[col].params;

                        const uint8_t c_mode = par.cipher_mode - TEST_CBC;

                        printf("\t%s", c_mode_names[c_mode]);
                }
                printf("\n");
                printf("DIR");
                for (col = 0; col < total_variants; col++) {
                        par = variant_list[col].params;

                        const uint8_t c_dir = par.cipher_dir - IMB_DIR_ENCRYPT;

                        printf("\t%s", c_dir_names[c_dir]);
                }
                printf("\n");
                printf("HASH_ALG");
                for (col = 0; col < total_variants; col++) {
                        par = variant_list[col].params;

                        const uint8_t h_alg = par.hash_alg - TEST_SHA1_HMAC;

                        printf("\t%s", h_alg_names[h_alg]);
                }
                printf("\n");
                printf("KEY_SIZE");
                for (col = 0; col < total_variants; col++) {
                        par = variant_list[col].params;
                        printf("\tAES-%u", par.aes_key_size * 8);
                }
                printf("\n");
        }

        for (sz = 0; sz < sizes; sz++) {
                if (imix_list_count != 0)
                        printf("%u", average_job_size);
                else if (job_size_count == 0)
                        printf("%d", job_sizes[RANGE_MIN] +
                                     (sz * job_sizes[RANGE_STEP]));
                else
                        printf("%d", job_size_list[sz]);
                for (col = 0; col < total_variants; col++) {
                        uint64_t *time_ptr =
                                &variant_list[col].avg_times[sz * NUM_RUNS];
                        const unsigned long long val =
                                mean_median(time_ptr, NUM_RUNS,
                                            p_buffer, p_keys);

                        printf("\t%llu", val);
                }
                printf("\n");
        }
}

/* Prepares data structure for test variants storage, sets test configuration */
#ifdef _WIN32
static void
#else
static void *
#endif
run_tests(void *arg)
{
        uint32_t i;
        struct thread_info *info = (struct thread_info *)arg;
        IMB_MGR *p_mgr = NULL;
        struct params_s params;
        enum arch_type_e arch;
        uint32_t at_size, run;
        uint32_t variant;
        uint32_t total_variants = 0;
        struct variant_s *variant_ptr = NULL;
        struct variant_s *variant_list = NULL;
        const uint32_t min_size = job_sizes[RANGE_MIN];
        const uint32_t max_size = job_sizes[RANGE_MAX];
        const uint32_t step_size = job_sizes[RANGE_STEP];
        uint8_t *buf = NULL;
        imb_uint128_t *keys = NULL;

        p_mgr = info->p_mgr;

        memset(&params, 0, sizeof(params));

        if (job_size_count == 0)
                params.num_sizes = ((max_size - min_size) / step_size) + 1;
        else
                params.num_sizes = job_size_count;

        params.core = (uint32_t)info->core;

        /* if cores selected then set affinity */
        if (core_mask)
                if (set_affinity(info->core) != 0) {
                        fprintf(stderr, "Failed to set cpu "
                                "affinity on core %d\n", info->core);
                        goto exit_failure;
                }

        /* If unhalted cycles selected and this is
           the primary thread then start counter */
        if (use_unhalted_cycles && info->print_info) {
                int ret;

                ret = start_cycles_ctr(params.core);
                if (ret != 0) {
                        fprintf(stderr, "Failed to start cycles "
                                "counter on core %u\n", params.core);
                        goto exit_failure;
                }
                /* Get average cost of reading counter */
                ret = set_avg_unhalted_cycle_cost(params.core, &rd_cycles_cost);
                if (ret != 0 || rd_cycles_cost == 0) {
                        fprintf(stderr, "Error calculating unhalted "
                                "cycles read overhead!\n");
                        goto exit_failure;
                } else
                        fprintf(stderr, "Started counting unhalted cycles on "
                                "core %u\nUnhalted cycles read cost = %lu "
                                "cycles\n", params.core,
                                (unsigned long)rd_cycles_cost);
        }

        init_mem(&buf, &keys);

        /* Calculating number of all variants */
        for (arch = ARCH_SSE; arch < NUM_ARCHS; arch++) {
                if (archs[arch] == 0)
                        continue;
                total_variants++;
        }

        if (total_variants == 0) {
                fprintf(stderr, "No tests to be run\n");
                goto exit;
        }

        if (info->print_info && !silent_progress_bar)
                fprintf(stderr, "Total number of combinations (algos, "
                        "key sizes, cipher directions) to test = %u\n",
                        total_variants);

        variant_list = (struct variant_s *)
                malloc(total_variants * sizeof(struct variant_s));
        if (variant_list == NULL) {
                fprintf(stderr, "Cannot allocate memory\n");
                goto exit_failure;
        }
        memset(variant_list, 0, total_variants * sizeof(struct variant_s));

        at_size = NUM_RUNS * params.num_sizes * sizeof(uint64_t);
        for (variant = 0, variant_ptr = variant_list;
             variant < total_variants;
             variant++, variant_ptr++) {
                variant_ptr->avg_times = (uint64_t *) malloc(at_size);
                if (!variant_ptr->avg_times) {
                        fprintf(stderr, "Cannot allocate memory\n");
                        goto exit_failure;
                }
        }

        for (run = 0; run < NUM_RUNS; run++) {
                if (info->print_info)
                        fprintf(stderr, "\nStarting run %u of %d%c",
                                run + 1, NUM_RUNS,
                                silent_progress_bar ? '\r' : '\n' );

                variant = 0;
                variant_ptr = variant_list;

                if (iter_scale == ITER_SCALE_SMOKE && run != 0)
                        continue;

                if (info->print_info)
                        prog_bar_init(total_variants);

                params.cipher_dir = custom_job_params.cipher_dir;
                params.aes_key_size = custom_job_params.aes_key_size;
                params.cipher_mode = custom_job_params.cipher_mode;
                params.hash_alg = custom_job_params.hash_alg;

                /* Performing tests for each selected architecture */
                for (arch = ARCH_SSE; arch <= ARCH_AVX512; arch++) {
                        if (archs[arch] == 0)
                                continue;

                        switch (arch) {
                        case ARCH_SSE:
                                init_mb_mgr_sse(p_mgr);
                                break;
                        case ARCH_AVX:
                                init_mb_mgr_avx(p_mgr);
                                break;
                        case ARCH_AVX2:
                                init_mb_mgr_avx2(p_mgr);
                                break;
                        default: /* ARCH_AV512 */
                                init_mb_mgr_avx512(p_mgr);
                                break;
                        }

                        if (imb_get_errno(p_mgr) != 0) {
                                printf("Error initializing MB_MGR! %s\n",
                                       imb_get_strerror(imb_get_errno(p_mgr)));
                                goto exit_failure;
                        }

                        process_variant(p_mgr, arch, &params,
                                        variant_ptr, run, buf, keys);

                        /* update and print progress bar */
                        if (info->print_info)
                                prog_bar_update(variant);

                        variant++;
                        variant_ptr++;
                }
                if (info->print_info)
                        prog_bar_fini();

        } /* end for run */
        if (info->print_info == 1 && iter_scale != ITER_SCALE_SMOKE) {
                fprintf(stderr, "\n");
                print_times(variant_list, &params, total_variants, buf, keys);
        }

exit:
        if (variant_list != NULL) {
                /* Freeing variants list */
                for (i = 0; i < total_variants; i++)
                        free(variant_list[i].avg_times);
                free(variant_list);
        }
        free_mem(&buf, &keys);
        free_mb_mgr(p_mgr);
#ifndef _WIN32
        return NULL;

#else
        return;
#endif
exit_failure:
        if (variant_list != NULL) {
                /* Freeing variants list */
                for (i = 0; i < total_variants; i++)
                        free(variant_list[i].avg_times);
                free(variant_list);
        }
        free_mem(&buf, &keys);
        free_mb_mgr(p_mgr);
        exit(EXIT_FAILURE);
}

static void usage(void)
{
        fprintf(stderr, "Usage: ipsec_perf <ALGORITHM> [ARGS]\n"
                "\nALGORITHM can be one or more of:\n"
                "--cipher-algo: Select cipher algorithm to run on the custom test\n"
                "--hash-algo: Select hash algorithm to run on the custom test\n"
                "--aead-algo: Select AEAD algorithm to run on the custom test\n"
                "             Note: AEAD algorithms cannot be used with "
                "cipher or hash algorithms\n"
                "\nARGS can be zero or more of:\n"
                "-h: print this message\n"
                "-c: Use cold cache, it uses warm as default\n"
                "-w: Use warm cache\n"
                "--arch: run only tests on specified architecture (SSE/AVX/AVX2/AVX512)\n"
                "--arch-best: detect available architectures and run only on the best one\n"
                "--cipher-dir: Select cipher direction to run on the custom test  "
                "(encrypt/decrypt) (default = encrypt)\n"
                "-o val: Use <val> for the SHA size increment, default is 24\n"
                "--shani-on: use SHA extensions, default: auto-detect\n"
                "--shani-off: don't use SHA extensions\n"
                "--gfni-on: use Galois Field extensions, default: auto-detect\n"
                "--gfni-off: don't use Galois Field extensions\n"
                "--force-job-api: use JOB API"
                " (direct API used for GCM/GHASH/CHACHA20_POLY1305 API by default)\n"
                "--gcm-sgl-api: use direct SGL API for GCM perf tests"
                " (direct GCM API is default)\n"
                "--threads num: <num> for the number of threads to run"
                " Max: %d\n"
                "--cores mask: <mask> CPU's to run threads\n"
                "--unhalted-cycles: measure using unhalted cycles (requires root).\n"
                "                   Note: RDTSC is used by default.\n"
                "--quick: reduces number of test iterations by x10\n"
                "         (less precise but quicker)\n"
                "--smoke: very quick, imprecise and without print out\n"
                "         (for validation only)\n"
                "--job-size: size of the cipher & MAC job in bytes. It can be:\n"
                "            - single value: test single size\n"
                "            - list: test multiple sizes separated by commas\n"
                "            - range: test multiple sizes with following format"
                " min:step:max (e.g. 16:16:256)\n"
                "            (-o still applies for MAC)\n"
                "--segment-size: size of segment to test SGL (default: 0)\n"
                "--imix: set numbers that establish occurrence proportions"
                " between packet sizes.\n"
                "        It requires a list of sizes through --job-size.\n"
                "        (e.g. --imix 4,6 --job-size 64,128 will generate\n"
                "        a series of job sizes where on average 4 out of 10\n"
                "        packets will be 64B long and 6 out of 10 packets\n"
                "        will be 128B long)\n"
                "--aad-size: size of AAD for AEAD algorithms\n"
                "--job-iter: number of tests iterations for each job size\n"
                "--no-progress-bar: Don't display progress bar\n"
                "--print-info: Display system and algorithm information\n"
                "--turbo: Run extended TSC to core scaling measurement\n"
                "        (Use when turbo enabled)\n"
                "--no-tsc-detect: don't check TSC to core scaling\n"
                "--tag-size: modify tag size\n"
                "--plot: Adjust text output for direct use with plot output\n"
                "--no-time-box: disables 100ms watchdog timer on "
                "an algorithm@packet-size performance test\n"
                "--burst-api: use burst API for perf tests\n"
                "--cipher-burst-api: use cipher-only burst API for perf tests\n"
                "--hash-burst-api: use hash-only burst API for perf tests\n"
                "--burst-size: number of jobs to submit per burst\n",
                MAX_NUM_THREADS + 1);
}

static int
get_next_num_arg(const char * const *argv, const int index, const int argc,
                 void *dst, const size_t dst_size)
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
                fprintf(stderr, "Error converting '%s' as value for '%s'!\n",
                        argv[index + 1], argv[index]);
                exit(EXIT_FAILURE);
        }

        switch (dst_size) {
        case (sizeof(uint8_t)):
                *((uint8_t *)dst) = (uint8_t) val;
                break;
        case (sizeof(uint16_t)):
                *((uint16_t *)dst) = (uint16_t) val;
                break;
        case (sizeof(uint32_t)):
                *((uint32_t *)dst) = (uint32_t) val;
                break;
        case (sizeof(uint64_t)):
                *((uint64_t *)dst) = val;
                break;
        default:
                fprintf(stderr, "%s() invalid dst_size %u!\n",
                        __func__, (unsigned) dst_size);
                exit(EXIT_FAILURE);
                break;
        }

        return index + 1;
}

static int
detect_arch(unsigned int arch_support[NUM_ARCHS])
{
        const uint64_t detect_sse =
                IMB_FEATURE_SSE4_2 | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx =
                IMB_FEATURE_AVX | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx2 = IMB_FEATURE_AVX2 | detect_avx;
        const uint64_t detect_avx512 = IMB_FEATURE_AVX512_SKX | detect_avx2;
        IMB_MGR *p_mgr = NULL;
        enum arch_type_e arch_id;

        if (arch_support == NULL) {
                fprintf(stderr, "Array not passed correctly\n");
                return -1;
        }

        for (arch_id = ARCH_SSE; arch_id < NUM_ARCHS; arch_id++)
                arch_support[arch_id] = 1;

        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                fprintf(stderr, "Architecture detect error!\n");
                return -1;
        }

        if ((p_mgr->features & detect_avx512) != detect_avx512)
                arch_support[ARCH_AVX512] = 0;

        if ((p_mgr->features & detect_avx2) != detect_avx2)
                arch_support[ARCH_AVX2] = 0;

        if ((p_mgr->features & detect_avx) != detect_avx)
                arch_support[ARCH_AVX] = 0;

        if ((p_mgr->features & detect_sse) != detect_sse)
                arch_support[ARCH_SSE] = 0;

        free_mb_mgr(p_mgr);

        return 0;
}

/*
 * Check string argument is supported and if it is, return values associated
 * with it.
 */
static const union params *
check_string_arg(const char *param, const char *arg,
                 const struct str_value_mapping *map,
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
parse_list(const char * const *argv, const int index, const int argc,
           uint32_t *list, uint32_t *min, uint32_t *max)
{
        char *token;
        uint32_t number;
        uint8_t count = 0;
        uint32_t temp_min;
        uint32_t temp_max;

        if (list == NULL || argv == NULL || index < 0 || argc < 0) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        if (index >= (argc - 1)) {
                fprintf(stderr, "'%s' requires an argument!\n", argv[index]);
                exit(EXIT_FAILURE);
        }

        char *copy_arg = strdup(argv[index + 1]);

        if (copy_arg == NULL)
                return -1;

        errno = 0;
        token = strtok(copy_arg, ",");

        /* Parse first value */
        if (token != NULL) {
                number = strtoul(token, NULL, 10);

                if (errno || number == 0)
                        goto err_list;

                list[count++] = number;
                temp_min = number;
                temp_max = number;
        } else
                goto err_list;

        token = strtok(NULL, ",");

        while (token != NULL) {
                if (count == MAX_LIST) {
                        fprintf(stderr, "Using only the first %d sizes\n",
                                MAX_LIST);
                        break;
                }

                number = strtoul(token, NULL, 10);

                if (errno || number == 0)
                        goto err_list;

                list[count++] = number;

                if (number < temp_min)
                        temp_min = number;
                if (number > temp_max)
                        temp_max = number;

                token = strtok(NULL, ",");
        }

        if (min)
                *min = temp_min;
        if (max)
                *max = temp_max;

        free(copy_arg);
        return count;

err_list:
        free(copy_arg);
        fprintf(stderr, "Could not parse list of sizes\n");
        exit(EXIT_FAILURE);
}

static int
parse_range(const char * const *argv, const int index, const int argc,
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

        if (range_values[RANGE_MAX] < range_values[RANGE_MIN]) {
                fprintf(stderr, "Maximum value of range cannot be lower "
                        "than minimum value\n");
                exit(EXIT_FAILURE);
        }

        if (range_values[RANGE_STEP] == 0) {
                fprintf(stderr, "Step value in range cannot be 0\n");
                exit(EXIT_FAILURE);
        }

        goto end_range;
no_range:
        /* Try parsing as a list/single value */
        job_size_count = parse_list(argv, index, argc, job_size_list,
                                    &job_sizes[RANGE_MIN],
                                    &job_sizes[RANGE_MAX]);
end_range:
        free(copy_arg);
        return (index + 1);

}

/**
 * @brief Update table of supported architectures
 *
 * @param arch_support [in/out] table of architectures to run tests on
 *
 * @return  0 - architectures identified correctly
 *         -1 - bad input or issues with alloc_mb_mgr
 */
static int
detect_best_arch(uint8_t arch_support[NUM_ARCHS])
{
        const uint64_t detect_sse =
                IMB_FEATURE_SSE4_2 | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx =
                IMB_FEATURE_AVX | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx2 = IMB_FEATURE_AVX2 | detect_avx;
        const uint64_t detect_avx512 = IMB_FEATURE_AVX512_SKX | detect_avx2;
        IMB_MGR *p_mgr = NULL;
        uint64_t detected_features = 0;

        if (arch_support == NULL) {
                fprintf(stderr, "Arch detection: wrong argument!\n");
                return -1;
        }

        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                fprintf(stderr, "Arch detection: initialization error!\n");
                return -1;
        }

        detected_features = p_mgr->features;

        free_mb_mgr(p_mgr);

        memset(arch_support, 0, NUM_ARCHS * sizeof(arch_support[0]));

        if ((detected_features & detect_avx512) == detect_avx512) {
                arch_support[ARCH_AVX512] = 1;
                return 0;
        }

        if ((detected_features & detect_avx2) == detect_avx2) {
                arch_support[ARCH_AVX2] = 1;
                return 0;
        }

        if ((detected_features & detect_avx) == detect_avx) {
                arch_support[ARCH_AVX] = 1;
                return 0;
        }

        if ((detected_features & detect_sse) == detect_sse) {
                arch_support[ARCH_SSE] = 1;
                return 0;
        }

        fprintf(stderr, "Arch detection: no architecture available!\n");
        return -1;
}

/**
 * @brief Print system and application information
 */
static void print_info(void)
{
        uint32_t i;
        uint32_t supported_archs[NUM_ARCHS];
        uint8_t arch_tab[NUM_ARCHS];

        /* detect and print all archs */
        if (detect_arch(supported_archs) < 0)
                goto print_info_err;

        printf("Supported architectures: ");
        for (i = 0; i < DIM(arch_str_map); i++)
                if (supported_archs[i])
                        printf("%s ", arch_str_map[i].name);
        printf("\n");

        /* detect and print best arch */
        if (detect_best_arch(arch_tab) != 0)
                goto print_info_err;

        for (i = 0; i < DIM(arch_str_map); i++)
                if (arch_tab[i]) {
                        printf("Best architecture: %s\n",
                               arch_str_map[i].name);
                        break;
                }

        /* print supported algorithms */
        printf("Supported cipher algorithms: ");
        for (i = 0; i < DIM(cipher_algo_str_map); i++)
                printf("%s ", cipher_algo_str_map[i].name);
        printf("\n");

        printf("Supported hash algorithms: ");
        for (i = 0; i < DIM(hash_algo_str_map); i++)
                printf("%s ", hash_algo_str_map[i].name);
        printf("\n");

        printf("Supported aead algorithms: ");
        for (i = 0; i < DIM(aead_algo_str_map); i++)
                printf("%s ", aead_algo_str_map[i].name);
        printf("\n");

        return;

 print_info_err:
        fprintf(stderr, "%s() error!\n", __func__);
        exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
        uint32_t num_t = 0;
        int i, core = 0;
        struct thread_info *thread_info_p = t_info;
        unsigned int arch_id;
        unsigned int arch_support[NUM_ARCHS];
        const union params *values;
        unsigned int cipher_algo_set = 0;
        unsigned int hash_algo_set = 0;
        unsigned int aead_algo_set = 0;
        unsigned int cipher_dir_set = 0;
        /* 1 size by default on job sizes list */
        uint32_t num_sizes_list = 1;
        int turbo_enabled = 0;
        int tsc_detect = 1;

#ifdef _WIN32
        HANDLE threads[MAX_NUM_THREADS];
#else
        pthread_t tids[MAX_NUM_THREADS];
#endif

        for (i = 1; i < argc; i++)
                if (strcmp(argv[i], "-h") == 0) {
                        usage();
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "-c") == 0) {
                        cache_type = COLD;
                        fprintf(stderr, "Cold cache, ");
                } else if (strcmp(argv[i], "-w") == 0) {
                        cache_type = WARM;
                        fprintf(stderr, "Warm cache, ");
                } else if (strcmp(argv[i], "--shani-on") == 0) {
                        flags &= (~IMB_FLAG_SHANI_OFF);
                } else if (strcmp(argv[i], "--shani-off") == 0) {
                        flags |= IMB_FLAG_SHANI_OFF;
                } else if (strcmp(argv[i], "--gfni-on") == 0) {
                        flags &= (~IMB_FLAG_GFNI_OFF);
                } else if (strcmp(argv[i], "--gfni-off") == 0) {
                        flags |= IMB_FLAG_GFNI_OFF;
                } else if (strcmp(argv[i], "--force-job-api") == 0) {
                        use_job_api = 1;
                } else if (strcmp(argv[i], "--gcm-sgl-api") == 0) {
                        use_gcm_sgl_api = 1;
                } else if (strcmp(argv[i], "--quick") == 0) {
                        iter_scale = ITER_SCALE_SHORT;
                } else if (strcmp(argv[i], "--smoke") == 0) {
                        iter_scale = ITER_SCALE_SMOKE;
                } else if (strcmp(argv[i], "--plot") == 0) {
                        plot_output_option = 1;
                } else if (strcmp(argv[i], "--arch") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                                  arch_str_map,
                                                  DIM(arch_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        memset(archs, 0, sizeof(archs));
                        archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--arch-best") == 0) {
                        if (detect_best_arch(archs) != 0)
                                return EXIT_FAILURE;
                } else if (strcmp(argv[i], "--cipher-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                        cipher_algo_str_map,
                                        DIM(cipher_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode =
                                        values->job_params.cipher_mode;
                        custom_job_params.aes_key_size =
                                        values->job_params.aes_key_size;
                        cipher_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--cipher-dir") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                        cipher_dir_str_map,
                                        DIM(cipher_dir_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_dir =
                                        values->job_params.cipher_dir;
                        cipher_dir_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--hash-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                        hash_algo_str_map,
                                        DIM(hash_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.hash_alg =
                                        values->job_params.hash_alg;
                        hash_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--aead-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                        aead_algo_str_map,
                                        DIM(aead_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode =
                                        values->job_params.cipher_mode;
                        custom_job_params.aes_key_size =
                                        values->job_params.aes_key_size;
                        custom_job_params.hash_alg =
                                        values->job_params.hash_alg;
                        aead_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "-o") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &sha_size_incr,
                                             sizeof(sha_size_incr));
                } else if (strcmp(argv[i], "--job-size") == 0) {
                        /* Try parsing the argument as a range first */
                        i = parse_range((const char * const *)argv, i, argc,
                                          job_sizes);
                        if (job_sizes[RANGE_MAX] > JOB_SIZE_TOP) {
                                fprintf(stderr,
                                       "Invalid job size %u (max %d)\n",
                                       (unsigned) job_sizes[RANGE_MAX],
                                       JOB_SIZE_TOP);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--imix") == 0) {
                        imix_list_count = parse_list((const char * const *)argv,
                                          i, argc, imix_list, NULL, NULL);
                        if (imix_list_count == 0) {
                                fprintf(stderr,
                                       "Invalid IMIX distribution list\n");
                                return EXIT_FAILURE;
                        }
                        i++;
                } else if (strcmp(argv[i], "--aad-size") == 0) {
                        /* Get AAD size for both GCM and CCM */
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &gcm_aad_size,
                                             sizeof(gcm_aad_size));
                        if (gcm_aad_size > AAD_SIZE_MAX) {
                                fprintf(stderr,
                                        "Invalid AAD size %u (max %d)!\n",
                                        (unsigned) gcm_aad_size,
                                        AAD_SIZE_MAX);
                                return EXIT_FAILURE;
                        }
                        ccm_aad_size = gcm_aad_size;
                        chacha_poly_aad_size = gcm_aad_size;
                        snow_v_aad_size = gcm_aad_size;
                } else if (strcmp(argv[i], "--job-iter") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &job_iter, sizeof(job_iter));
                } else if (strcmp(argv[i], "--threads") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &num_t, sizeof(num_t));
                        if (num_t > (MAX_NUM_THREADS + 1)) {
                                fprintf(stderr, "Invalid number of threads!\n");
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--cores") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &core_mask,
                                             sizeof(core_mask));
                } else if (strcmp(argv[i], "--unhalted-cycles") == 0) {
                        use_unhalted_cycles = 1;
                } else if (strcmp(argv[i], "--no-progress-bar") == 0) {
                        silent_progress_bar = 1;
                } else if (strcmp(argv[i], "--print-info") == 0) {
                        print_info();
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "--turbo") == 0) {
                        turbo_enabled = 1;
                } else if (strcmp(argv[i], "--no-tsc-detect") == 0) {
                        tsc_detect = 0;
                } else if (strcmp(argv[i], "--tag-size") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &tag_size, sizeof(tag_size));
                } else if (strcmp(argv[i], "--burst-api") == 0) {
                        test_api = TEST_API_BURST;
                } else if (strcmp(argv[i], "--cipher-burst-api") == 0) {
                        test_api = TEST_API_CIPHER_BURST;
                } else if (strcmp(argv[i], "--hash-burst-api") == 0) {
                        test_api = TEST_API_HASH_BURST;
                } else if (strcmp(argv[i], "--burst-size") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &burst_size,
                                             sizeof(burst_size));
                        if (burst_size > (MAX_BURST_SIZE)) {
                                fprintf(stderr, "Burst size cannot be "
                                        "more than %d\n", MAX_BURST_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--segment-size") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &segment_size,
                                             sizeof(segment_size));
                        if (segment_size > (JOB_SIZE_TOP)) {
                                fprintf(stderr, "Segment size cannot be "
                                        "more than %d\n", JOB_SIZE_TOP);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--no-time-box") == 0) {
                        use_timebox = 0;
                } else {
                        usage();
                        return EXIT_FAILURE;
                }

        if (burst_size != 0 && test_api == TEST_API_JOB) {
                fprintf(stderr, "--burst-size can only be used with "
                        "--burst-api, --cipher-burst-api or "
                        "--hash-burst-api options\n");
                return EXIT_FAILURE;
        }

        if (test_api != TEST_API_JOB && burst_size == 0)
                burst_size = DEFAULT_BURST_SIZE;

        /* currently only AES-CBC & CTR supported by cipher-only burst API */
        if (test_api == TEST_API_CIPHER_BURST &&
            (custom_job_params.cipher_mode != TEST_CBC &&
             custom_job_params.cipher_mode != TEST_CNTR)) {
                fprintf(stderr, "Unsupported cipher-only burst "
                        "API algorithm selected\n");
                return EXIT_FAILURE;
        }

        /* currently only HMAC-SHAx algs supported by hash-only burst API */
        if (test_api == TEST_API_HASH_BURST &&
            ((custom_job_params.hash_alg != TEST_SHA1_HMAC) &&
             (custom_job_params.hash_alg != TEST_SHA_224_HMAC) &&
             (custom_job_params.hash_alg != TEST_SHA_256_HMAC) &&
             (custom_job_params.hash_alg != TEST_SHA_384_HMAC) &&
             (custom_job_params.hash_alg != TEST_SHA_512_HMAC))) {
                fprintf(stderr,
                        "Unsupported hash-only burst API algorithm selected\n");
                return EXIT_FAILURE;
        }

        if (aead_algo_set == 0 && cipher_algo_set == 0 &&
            hash_algo_set == 0) {
                fprintf(stderr, "No cipher, hash or "
                        "AEAD algorithms selected\n");
                usage();
                return EXIT_FAILURE;
        }

        if (aead_algo_set && (cipher_algo_set || hash_algo_set)) {
                fprintf(stderr, "AEAD algorithm cannot be used "
                        "combined with another cipher/hash "
                        "algorithm\n");
                return EXIT_FAILURE;
        }

        if (cipher_algo_set == 0 && aead_algo_set == 0 && cipher_dir_set) {
                fprintf(stderr, "--cipher-dir can only be used with "
                                "--cipher-algo or --aead-algo\n");
                return EXIT_FAILURE;
        }

        if (custom_job_params.cipher_mode == TEST_CCM) {
                if (ccm_aad_size > CCM_AAD_SIZE_MAX) {
                        fprintf(stderr, "AAD cannot be higher than %d in CCM\n",
                                CCM_AAD_SIZE_MAX);
                        return EXIT_FAILURE;
                }
        }

        if ((imix_list_count != 0)) {
                if (imix_list_count != job_size_count) {
                        fprintf(stderr,
                                "IMIX distribution list must have the same "
                                "number of items as the job list\n");
                        return EXIT_FAILURE;
                }
                job_size_imix_list = malloc(JOB_SIZE_IMIX_LIST*4);
                if (job_size_imix_list == NULL) {
                        fprintf(stderr,
                                "Memory allocation for IMIX list failed\n");
                        return EXIT_FAILURE;
                }

                num_sizes_list = JOB_SIZE_IMIX_LIST;
		/*
		 * Calculate accumulated distribution of
		 * probabilities per job size
		 */
		distribution_total[0] = imix_list[0];
		for (i = 1; i < (int)imix_list_count; i++)
			distribution_total[i] = imix_list[i] +
				distribution_total[i-1];

                /* Use always same seed */
                srand(0);
		/* Calculate a random sequence of packet sizes,
                   based on distribution */
		for (i = 0; i < (int)JOB_SIZE_IMIX_LIST; i++) {
			uint16_t random_number = rand() %
				distribution_total[imix_list_count - 1];
                        uint16_t j;

			for (j = 0; j < imix_list_count; j++)
				if (random_number < distribution_total[j])
					break;

			job_size_imix_list[i] = job_size_list[j];
		}

		/* Calculate average buffer size for the IMIX distribution */
		for (i = 0; i < (int)imix_list_count; i++)
			average_job_size += job_size_list[i] *
				imix_list[i];

		average_job_size /=
				distribution_total[imix_list_count - 1];
        }
        cipher_size_list = (uint32_t *) malloc(sizeof(uint32_t) *
                                num_sizes_list);
        if (cipher_size_list == NULL) {
                fprintf(stderr, "Could not malloc cipher size list\n");
                exit(EXIT_FAILURE);
        }
        hash_size_list = (uint32_t *) malloc(sizeof(uint32_t) *
                                num_sizes_list);
        if (hash_size_list == NULL) {
                fprintf(stderr, "Could not malloc hash size list\n");
                exit(EXIT_FAILURE);
        }
        xgem_hdr_list = (uint64_t *) malloc(sizeof(uint64_t) *
                                num_sizes_list);
        if (xgem_hdr_list == NULL) {
                fprintf(stderr, "Could not malloc xgem hdr list\n");
                exit(EXIT_FAILURE);
        }

        if (job_sizes[RANGE_MIN] == 0 && aead_algo_set == 0) {
                fprintf(stderr, "Buffer size cannot be 0 unless only "
                        "an AEAD algorithm is tested\n");
                return EXIT_FAILURE;
        }

        /* Check num cores >= number of threads */
        if ((core_mask != 0 && num_t != 0) && (num_t > bitcount(core_mask))) {
                fprintf(stderr, "Insufficient number of cores in "
                        "core mask (0x%lx) to run %u threads!\n",
                        (unsigned long) core_mask, num_t);
                return EXIT_FAILURE;
        }

        /* Check timebox option vs number of threads bigger than 1 */
        if (use_timebox && num_t > 1) {
                fprintf(stderr,
                        "Time-box feature, enabled by default, doesn't work "
                        "safely with number of threads bigger than one! Please "
                        "use '--no-time-box' option to disable\n");
                return EXIT_FAILURE;
        }

        /* if cycles selected then init MSR module */
        if (use_unhalted_cycles) {
                if (core_mask == 0) {
                        fprintf(stderr, "Must specify core mask "
                                "when reading unhalted cycles!\n");
                        return EXIT_FAILURE;
                }

                if (init_msr_mod() != 0) {
                        fprintf(stderr, "Error initializing MSR module!\n");
                        return EXIT_FAILURE;
                }
        }

        if (detect_arch(arch_support) < 0)
                return EXIT_FAILURE;

        /* disable tests depending on instruction sets supported */
        for (arch_id = 0; arch_id < NUM_ARCHS; arch_id++) {
                if (archs[arch_id] == 1 && arch_support[arch_id] == 0) {
                        archs[arch_id] = 0;
                        fprintf(stderr,
                                "%s not supported. Disabling %s tests\n",
                                arch_str_map[arch_id].name,
                                arch_str_map[arch_id].name);
                }
        }

        if (tsc_detect)
                fprintf(stderr, "TSC scaling to core cycles: %.3f\n",
                        get_tsc_to_core_scale(turbo_enabled));

        fprintf(stderr,
                "Authentication size = cipher size + %u\n"
                "Tool version: %s\n"
                "Library version: %s\n",
                sha_size_incr, IMB_VERSION_STR, imb_get_version_str());

        if (!use_job_api)
                fprintf(stderr, "API type: direct\n");
        else {
                fprintf(stderr, "API type: %s", str_api_list[test_api]);
                if (test_api != TEST_API_JOB)
                        fprintf(stderr, " (burst size = %u)\n", burst_size);
                else
                        fprintf(stderr, "\n");
        }

        if (custom_job_params.cipher_mode == TEST_GCM)
                fprintf(stderr, "GCM AAD = %"PRIu64"\n", gcm_aad_size);

        if (custom_job_params.cipher_mode == TEST_CCM)
                fprintf(stderr, "CCM AAD = %"PRIu64"\n", ccm_aad_size);

        if (archs[ARCH_SSE]) {
                IMB_MGR *p_mgr = alloc_mb_mgr(flags);

                if (p_mgr == NULL) {
                        fprintf(stderr, "Error allocating MB_MGR structure!\n");
                        return EXIT_FAILURE;
                }
                init_mb_mgr_sse(p_mgr);
                fprintf(stderr, "%s SHA extensions (shani) for SSE arch\n",
                        (p_mgr->features & IMB_FEATURE_SHANI) ?
                        "Using" : "Not using");
                free_mb_mgr(p_mgr);
        }

        memset(t_info, 0, sizeof(t_info));
        init_offsets(cache_type);

        srand(ITER_SCALE_LONG + ITER_SCALE_SHORT + ITER_SCALE_SMOKE);

#ifdef LINUX
        if (use_timebox) {
                /* set up timebox callback function */
                if (signal(SIGALRM, timebox_callback) == SIG_ERR) {
                        perror("signal(SIGALRM)");
                        return EXIT_FAILURE;
                }
        }
#endif

        if (num_t > 1) {
                uint32_t n;

                for (n = 0; n < (num_t - 1); n++, thread_info_p++) {
                        /* Set core if selected */
                        if (core_mask) {
                                core = next_core(core_mask, core);
                                thread_info_p->core = core++;
                        }

                        /* Allocate MB manager for each thread */
                        thread_info_p->p_mgr = alloc_mb_mgr(flags);
                        if (thread_info_p->p_mgr == NULL) {
                                fprintf(stderr, "Failed to allocate MB_MGR "
                                        "structure for thread %u!\n",
                                        (unsigned)(n + 1));
                                exit(EXIT_FAILURE);
                        }
#ifdef _WIN32
                        threads[n] = (HANDLE)
                                _beginthread(&run_tests, 0,
                                             (void *)thread_info_p);
#else
                        pthread_attr_t attr;

                        pthread_attr_init(&attr);
                        pthread_create(&tids[n], &attr, run_tests,
                                       (void *)thread_info_p);
#endif
                }
        }

        thread_info_p->print_info = 1;
        thread_info_p->p_mgr = alloc_mb_mgr(flags);
        if (thread_info_p->p_mgr == NULL) {
                fprintf(stderr, "Failed to allocate MB_MGR "
                        "structure for main thread!\n");
                exit(EXIT_FAILURE);
        }
        if (core_mask) {
                core = next_core(core_mask, core);
                thread_info_p->core = core;
        }

        run_tests((void *)thread_info_p);
        if (num_t > 1) {
                uint32_t n;

#ifdef _WIN32
                WaitForMultipleObjects(num_t, threads, FALSE, INFINITE);
#endif
                for (n = 0; n < (num_t - 1); n++) {
                        fprintf(stderr, "Waiting on thread %u to finish...\n",
                                (unsigned)(n + 2));
#ifdef _WIN32
                        CloseHandle(threads[n]);
#else
                        pthread_join(tids[n], NULL);
#endif
                }
        }

        if (use_unhalted_cycles)
                machine_fini();

        free(job_size_imix_list);
        free(cipher_size_list);
        free(hash_size_list);
        free(xgem_hdr_list);

        return EXIT_SUCCESS;
}
