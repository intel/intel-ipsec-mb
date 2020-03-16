/**********************************************************************
  Copyright(c) 2019-2020, Intel Corporation All rights reserved.

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
#include <malloc.h> /* memalign() or _aligned_malloc()/aligned_free() */
#include "misc.h"

#ifdef _WIN32
#include <intrin.h>
#define strdup _strdup
#define BSWAP64 _byteswap_uint64
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

#define AAD_SIZE 12
#define MAX_IV_SIZE 16

/* Maximum key and digest size for SHA-512 */
#define MAX_KEY_SIZE    SHA_512_BLOCK_SIZE
#define MAX_DIGEST_SIZE SHA512_DIGEST_SIZE_IN_BYTES

#define DIM(x) (sizeof(x)/sizeof(x[0]))

#define SEED 0xdeadcafe
#define PT_PATTERN 0x44444444
#define CIPH_KEY_PATTERN 0x33333333
#define AUTH_KEY_PATTERN 0xCCCCCCCC
#define STACK_DEPTH 8192

enum arch_type_e {
        ARCH_SSE = 0,
        ARCH_AESNI_EMU,
        ARCH_AVX,
        ARCH_AVX2,
        ARCH_AVX512,
        NUM_ARCHS
};

/* Struct storing cipher parameters */
struct params_s {
        JOB_CIPHER_MODE         cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        JOB_HASH_ALG            hash_alg; /* SHA-1 or others... */
        uint32_t		key_size;
        uint32_t		buf_size;
        uint64_t		aad_size;
        uint32_t		num_sizes;
};

/* Struct storing all expanded keys */
struct cipher_auth_keys {
        uint8_t temp_buf[SHA_512_BLOCK_SIZE];
        DECLARE_ALIGNED(uint32_t dust[15 * 4], 16);
        uint8_t ipad[SHA512_DIGEST_SIZE_IN_BYTES];
        uint8_t opad[SHA512_DIGEST_SIZE_IN_BYTES];
        DECLARE_ALIGNED(uint32_t k1_expanded[15 * 4], 16);
        DECLARE_ALIGNED(uint8_t	k2[16], 16);
        DECLARE_ALIGNED(uint8_t	k3[16], 16);
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);
        DECLARE_ALIGNED(struct gcm_key_data gdata_key, 64);
};

/* Struct storing all necessary data for crypto operations */
struct data {
        uint8_t test_buf[JOB_SIZE_TOP];
        uint8_t src_dst_buf[JOB_SIZE_TOP];
        uint8_t aad[AAD_SIZE];
        uint8_t in_digest[MAX_DIGEST_SIZE];
        uint8_t out_digest[MAX_DIGEST_SIZE];
        uint8_t cipher_iv[MAX_IV_SIZE];
        uint8_t auth_iv[MAX_IV_SIZE];
        uint8_t ciph_key[MAX_KEY_SIZE];
        uint8_t auth_key[MAX_KEY_SIZE];
        struct cipher_auth_keys enc_keys;
        struct cipher_auth_keys dec_keys;
};

struct custom_job_params {
        JOB_CIPHER_MODE         cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        JOB_HASH_ALG            hash_alg; /* SHA-1 or others... */
        uint32_t                key_size;
};

union params {
        enum arch_type_e         arch_type;
        struct custom_job_params job_params;
};

struct str_value_mapping {
        const char      *name;
        union params    values;
};

struct str_value_mapping arch_str_map[] = {
        {.name = "SSE",         .values.arch_type = ARCH_SSE },
        {.name = "AESNI_EMU",   .values.arch_type = ARCH_AESNI_EMU },
        {.name = "AVX",         .values.arch_type = ARCH_AVX },
        {.name = "AVX2",        .values.arch_type = ARCH_AVX2 },
        {.name = "AVX512",      .values.arch_type = ARCH_AVX512 }
};

struct str_value_mapping cipher_algo_str_map[] = {
        {
                .name = "aes-cbc-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CBC,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "aes-cbc-192",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CBC,
                        .key_size = IMB_KEY_AES_192_BYTES
                }
        },
        {
                .name = "aes-cbc-256",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CBC,
                        .key_size = IMB_KEY_AES_256_BYTES
                }
        },
        {
                .name = "aes-ctr-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CNTR,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "aes-ctr-192",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CNTR,
                        .key_size = IMB_KEY_AES_192_BYTES
                }
        },
        {
                .name = "aes-ctr-256",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CNTR,
                        .key_size = IMB_KEY_AES_256_BYTES
                }
        },
        {
                .name = "aes-ctr-bit-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CNTR_BITLEN,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "aes-ctr-bit-192",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CNTR_BITLEN,
                        .key_size = IMB_KEY_AES_192_BYTES
                }
        },
        {
                .name = "aes-ctr-bit-256",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CNTR_BITLEN,
                        .key_size = IMB_KEY_AES_256_BYTES
                }
        },
        {
                .name = "aes-ecb-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_ECB,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "aes-ecb-192",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_ECB,
                        .key_size = IMB_KEY_AES_192_BYTES
                }
        },
        {
                .name = "aes-ecb-256",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_ECB,
                        .key_size = IMB_KEY_AES_256_BYTES
                }
        },
        {
                .name = "aes-docsis-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "aes-docsis-256",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI,
                        .key_size = IMB_KEY_AES_256_BYTES
                }
        },
        {
                .name = "des-docsis",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_DOCSIS_DES,
                        .key_size = 8
                }
        },
        {
                .name = "des-cbc",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_DES,
                        .key_size = 8
                }
        },
        {
                .name = "3des-cbc",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_DES3,
                        .key_size = 24
                }
        },
        {
                .name = "zuc-eea3",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_ZUC_EEA3,
                        .key_size = 16
                }
        },
        {
                .name = "snow3g-uea2",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_SNOW3G_UEA2_BITLEN,
                        .key_size = 16
                }
        },
        {
                .name = "kasumi-uea1",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_KASUMI_UEA1_BITLEN,
                        .key_size = 16
                }
        },
        {
                .name = "null",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_NULL,
                        .key_size = 0
                }
        }
};

struct str_value_mapping hash_algo_str_map[] = {
        {
                .name = "sha1-hmac",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_1
                }
        },
        {
                .name = "sha224-hmac",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_224
                }
        },
        {
                .name = "sha256-hmac",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_256
                }
        },
        {
                .name = "sha384-hmac",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_384
                }
        },
        {
                .name = "sha512-hmac",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_HMAC_SHA_512
                }
        },
        {
                .name = "aes-xcbc",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_XCBC
                }
        },
        {
                .name = "md5-hmac",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_MD5
                }
        },
        {
                .name = "aes-cmac",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_CMAC
                }
        },
        {
                .name = "null",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_NULL
                }
        },
        {
                .name = "aes-cmac-bitlen",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_AES_CMAC_BITLEN
                }
        },
        {
                .name = "sha1",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_1
                }
        },
        {
                .name = "sha224",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_224
                }
        },
        {
                .name = "sha256",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_256
                }
        },
        {
                .name = "sha384",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_384
                }
        },
        {
                .name = "sha512",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SHA_512
                }
        },
        {
                .name = "zuc-eia3",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN,
                }
        },
        {
                .name = "snow3g-uia2",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_SNOW3G_UIA2_BITLEN,
                }
        },
        {
                .name = "kasumi-uia1",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_KASUMI_UIA1,
                }
        },
        {
                .name = "docsis-crc32",
                .values.job_params = {
                        .hash_alg = IMB_AUTH_DOCSIS_CRC32,
                }
        }
};

struct str_value_mapping aead_algo_str_map[] = {
        {
                .name = "aes-gcm-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_GCM,
                        .hash_alg = IMB_AUTH_AES_GMAC,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "aes-gcm-192",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_GCM,
                        .hash_alg = IMB_AUTH_AES_GMAC,
                        .key_size = IMB_KEY_AES_192_BYTES
                }
        },
        {
                .name = "aes-gcm-256",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_GCM,
                        .hash_alg = IMB_AUTH_AES_GMAC,
                        .key_size = IMB_KEY_AES_256_BYTES
                }
        },
        {
                .name = "aes-ccm-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_CCM,
                        .hash_alg = IMB_AUTH_AES_CCM,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "pon-128",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_PON_AES_CNTR,
                        .hash_alg = IMB_AUTH_PON_CRC_BIP,
                        .key_size = IMB_KEY_AES_128_BYTES
                }
        },
        {
                .name = "pon-128-no-ctr",
                .values.job_params = {
                        .cipher_mode = IMB_CIPHER_PON_AES_CNTR,
                        .hash_alg = IMB_AUTH_PON_CRC_BIP,
                        .key_size = 0
                }
        },
};

/* This struct stores all information about performed test case */
struct variant_s {
        uint32_t arch;
        struct params_s params;
        uint64_t *avg_times;
};

const uint8_t auth_tag_length_bytes[] = {
                12, /* IMB_AUTH_HMAC_SHA_1 */
                14, /* IMB_AUTH_HMAC_SHA_224 */
                16, /* IMB_AUTH_HMAC_SHA_256 */
                24, /* IMB_AUTH_HMAC_SHA_384 */
                32, /* IMB_AUTH_HMAC_SHA_512 */
                12, /* IMB_AUTH_AES_XCBC */
                12, /* IMB_AUTH_MD5 */
                0,  /* IMB_AUTH_NULL */
                16, /* IMB_AUTH_AES_GMAC */
                0,  /* IMB_AUTH_CUSTOM HASH */
                16, /* IMB_AES_CCM */
                16, /* IMB_AES_CMAC */
                20, /* IMB_PLAIN_SHA1 */
                28, /* IMB_PLAIN_SHA_224 */
                32, /* IMB_PLAIN_SHA_256 */
                48, /* IMB_PLAIN_SHA_384 */
                64, /* IMB_PLAIN_SHA_512 */
                4,  /* IMB_AES_CMAC_BITLEN (3GPP) */
                8,  /* IMB_PON */
                4,  /* IMB_ZUC_EIA3_BITLEN */
                DOCSIS_CRC32_TAG_SIZE, /* IMB_AUTH_DOCSIS_CRC32 */
                4,  /* IMB_AUTH_SNOW3G_UIA2_BITLEN (3GPP) */
                4,  /* IMB_AUTH_KASUMI_UIA1 (3GPP) */
};

/* Minimum, maximum and step values of key sizes */
const uint8_t key_sizes[][3] = {
                {16, 32, 8}, /* IMB_CIPHER_CBC */
                {16, 32, 8}, /* IMB_CIPHER_CNTR */
                {0, 0, 1},   /* IMB_CIPHER_NULL */
                {16, 32, 16}, /* IMB_CIPHER_DOCSIS_SEC_BPI */
                {16, 32, 8}, /* IMB_CIPHER_GCM */
                {0, 0, 1},   /* IMB_CIPHER_CUSTOM */
                {8, 8, 1},   /* IMB_CIPHER_DES */
                {8, 8, 1},   /* IMB_CIPHER_DOCSIS_DES */
                {16, 16, 1}, /* IMB_CIPHER_CCM */
                {24, 24, 1}, /* IMB_CIPHER_DES3 */
                {16, 16, 1}, /* IMB_CIPHER_PON_AES_CNTR */
                {16, 32, 8}, /* IMB_CIPHER_ECB */
                {16, 32, 8}, /* IMB_CIPHER_CNTR_BITLEN */
                {16, 16, 1}, /* IMB_CIPHER_ZUC_EEA3 */
                {16, 16, 1}, /* IMB_CIPHER_SNOW3G_UEA2 */
                {16, 16, 1}, /* IMB_CIPHER_KASUMI_UEA1_BITLEN */
};

uint8_t custom_test = 0;
uint8_t verbose = 0;

enum range {
        RANGE_MIN = 0,
        RANGE_STEP,
        RANGE_MAX,
        NUM_RANGE
};

uint32_t job_sizes[NUM_RANGE] = {DEFAULT_JOB_SIZE_MIN,
                                 DEFAULT_JOB_SIZE_STEP,
                                 DEFAULT_JOB_SIZE_MAX};
uint32_t job_iter = DEFAULT_JOB_ITER;

struct custom_job_params custom_job_params = {
        .cipher_mode  = IMB_CIPHER_NULL,
        .hash_alg     = IMB_AUTH_NULL,
        .key_size = 0
};

/* AESNI_EMU disabled by default */
uint8_t enc_archs[NUM_ARCHS] = {1, 0, 1, 1, 1};
uint8_t dec_archs[NUM_ARCHS] = {1, 0, 1, 1, 1};

uint64_t flags = 0; /* flags passed to alloc_mb_mgr() */

/** Generate random buffer */
static void
generate_random_buf(uint8_t *buf, const uint32_t length)
{
        uint32_t i;

        for (i = 0; i < length; i++)
                buf[i] = (uint8_t) rand();
}

/*
 * Searches across a block of memory if a pattern is present
 * (indicating there is some left over sensitive data)
 *
 * Returns 0 if pattern is present or -1 if not present
 */
static int
search_patterns(const void *ptr, const size_t mem_size)
{
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        size_t i;

        if (mem_size < 4)
                return -1;

        for (i = 0; i <= (mem_size - 4); i++) {
                const uint32_t string = ((const uint32_t *) ptr8)[0];
                int ret = -1;

                if (string == CIPH_KEY_PATTERN) {
                        fprintf(stderr, "Part of CIPHER_KEY is present\n");
                        ret = 0;
                }
                if (string == AUTH_KEY_PATTERN) {
                        fprintf(stderr, "Part of AUTH_KEY is present\n");
                        ret = 0;
                }
                if (string == PT_PATTERN) {
                        fprintf(stderr,
                                "Part of plain/ciphertext is present\n");
                        ret = 0;
                }
                if (ret == 0) {
                        fprintf(stderr, "Offset = %zu bytes, Addr = %p\n",
                                i, ptr8);
                        return 0;
                }
                ptr8++;
        }

        return -1;
}

static void
byte_hexdump(const char *message, const uint8_t *ptr, const uint32_t len)
{
        uint32_t ctr;

        printf("%s:\n", message);
        for (ctr = 0; ctr < len; ctr++) {
                printf("0x%02X ", ptr[ctr] & 0xff);
                if (!((ctr + 1) % 16))
                        printf("\n");
        }
        printf("\n");
        printf("\n");
};

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
                        printf("AEAD algo = %s\n", aead_algo_str_map[i].name);
                        return;
                }
        }

        for (i = 0; i < DIM(cipher_algo_str_map); i++) {
                job_params = &cipher_algo_str_map[i].values.job_params;
                if (job_params->cipher_mode == params->cipher_mode &&
                    job_params->key_size == params->key_size) {
                        printf("Cipher algo = %s ",
                               cipher_algo_str_map[i].name);
                        break;
                }
        }
        for (i = 0; i < DIM(hash_algo_str_map); i++) {
                job_params = &hash_algo_str_map[i].values.job_params;
                if (job_params->hash_alg == params->hash_alg) {
                        printf("Hash algo = %s\n", hash_algo_str_map[i].name);
                        break;
                }
        }
}

static void
print_arch_info(const enum arch_type_e arch)
{
        uint32_t i;

        for (i = 0; i < DIM(arch_str_map); i++) {
                if (arch_str_map[i].values.arch_type == arch)
                        printf("Architecture = %s\n",
                               arch_str_map[i].name);
        }
}

static int
fill_job(IMB_JOB *job, const struct params_s *params,
         uint8_t *buf, uint8_t *digest, const uint8_t *aad,
         const uint32_t buf_size, const uint8_t tag_size,
         JOB_CIPHER_DIRECTION cipher_dir,
         struct cipher_auth_keys *keys, uint8_t *cipher_iv,
         uint8_t *auth_iv)
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

        /* Force partial byte, by substracting 3 bits from the full length */
        if (params->cipher_mode == IMB_CIPHER_CNTR_BITLEN)
                job->msg_len_to_cipher_in_bits = buf_size * 8 - 3;
        else
                job->msg_len_to_cipher_in_bytes = buf_size;

        job->msg_len_to_hash_in_bytes = buf_size;
        job->hash_start_src_offset_in_bytes = 0;
        job->cipher_start_src_offset_in_bytes = 0;
        job->iv = cipher_iv;

        if (params->cipher_mode == IMB_CIPHER_PON_AES_CNTR) {
                /* Substract XGEM header */
                job->msg_len_to_cipher_in_bytes -= 8;
                job->cipher_start_src_offset_in_bytes = 8;
                /* If no crypto needed, set msg_len_to_cipher to 0 */
                if (params->key_size == 0)
                        job->msg_len_to_cipher_in_bytes = 0;
        }

        if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32 &&
            params->cipher_mode == IMB_CIPHER_DOCSIS_SEC_BPI) {
                if (buf_size >=
                    (DOCSIS_CRC32_MIN_ETH_PDU_SIZE + DOCSIS_CRC32_TAG_SIZE)) {
                        const uint64_t cipher_adjust = /* SA + DA only */
                                DOCSIS_CRC32_MIN_ETH_PDU_SIZE - 2;

                        job->cipher_start_src_offset_in_bytes += cipher_adjust;
                        job->msg_len_to_cipher_in_bytes -= cipher_adjust;
                        job->msg_len_to_hash_in_bytes -= DOCSIS_CRC32_TAG_SIZE;
                } else if (buf_size > DOCSIS_CRC32_TAG_SIZE) {
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes -= DOCSIS_CRC32_TAG_SIZE;
                } else {
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes = 0;
                }
        }

        /* In-place operation */
        job->src = buf;
        job->dst = buf + job->cipher_start_src_offset_in_bytes;
        job->auth_tag_output = digest;

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
                job->msg_len_to_hash_in_bits =
                        (job->msg_len_to_hash_in_bytes * 8) - 4;
                break;
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_MD5:
                /* HMAC hash alg is SHA1 or MD5 */
                job->u.HMAC._hashed_auth_key_xor_ipad =
                        (uint8_t *) ipad;
                job->u.HMAC._hashed_auth_key_xor_opad =
                        (uint8_t *) opad;
                break;
        case IMB_AUTH_ZUC_EIA3_BITLEN:
                job->u.ZUC_EIA3._key  = k2;
                job->u.ZUC_EIA3._iv  = auth_iv;
                break;
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                job->u.SNOW3G_UIA2._key = k2;
                job->u.SNOW3G_UIA2._iv = auth_iv;
                job->msg_len_to_hash_in_bits =
                        (job->msg_len_to_hash_in_bytes * 8);
                break;
        case IMB_AUTH_KASUMI_UIA1:
                job->u.KASUMI_UIA1._key = k2;
                break;
        case IMB_AUTH_PON_CRC_BIP:
        case IMB_AUTH_NULL:
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_AES_CCM:
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
                /* No operation needed */
                break;
        case IMB_AUTH_DOCSIS_CRC32:
                break;
        default:
                printf("Unsupported hash algorithm\n");
                return -1;
        }

        job->auth_tag_output_len_in_bytes = tag_size;

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

        switch (job->cipher_mode) {
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_DOCSIS_SEC_BPI:
                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_PON_AES_CNTR:
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_CNTR_BITLEN:
                job->enc_keys = enc_keys;
                job->dec_keys = enc_keys;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_GCM:
                job->enc_keys = gdata_key;
                job->dec_keys = gdata_key;
                job->u.GCM.aad_len_in_bytes = params->aad_size;
                job->u.GCM.aad = aad;
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_CCM:
                job->msg_len_to_cipher_in_bytes = buf_size;
                job->msg_len_to_hash_in_bytes = buf_size;
                job->hash_start_src_offset_in_bytes = 0;
                job->cipher_start_src_offset_in_bytes = 0;
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
                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv_len_in_bytes = 0;
                break;
        case IMB_CIPHER_ZUC_EEA3:
                job->enc_keys = k2;
                job->dec_keys = k2;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                job->enc_keys = k2;
                job->dec_keys = k2;
                job->iv_len_in_bytes = 16;
                job->cipher_start_src_offset_in_bits = 0;
                job->msg_len_to_cipher_in_bits =
                        (job->msg_len_to_cipher_in_bytes * 8);
                break;
        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                job->enc_keys = k2;
                job->dec_keys = k2;
                job->iv_len_in_bytes = 8;
                job->cipher_start_src_offset_in_bits = 0;
                job->msg_len_to_cipher_in_bits =
                        (job->msg_len_to_cipher_in_bytes * 8);
                break;
        case IMB_CIPHER_NULL:
                /* No operation needed */
                break;
        default:
                printf("Unsupported cipher mode\n");
                return -1;
        }

        return 0;
}

static int
prepare_keys(IMB_MGR *mb_mgr, struct cipher_auth_keys *keys,
             const uint8_t *ciph_key, const uint8_t *auth_key,
             const struct params_s *params,
             const unsigned int force_pattern)
{
        uint8_t *buf = keys->temp_buf;
        uint32_t *dust = keys->dust;
        uint32_t *k1_expanded = keys->k1_expanded;
        uint8_t *k2 = keys->k2;
        uint8_t *k3 = keys->k3;
        uint32_t *enc_keys = keys->enc_keys;
        uint32_t *dec_keys = keys->dec_keys;
        uint8_t *ipad = keys->ipad;
        uint8_t *opad = keys->opad;
        struct gcm_key_data *gdata_key = &keys->gdata_key;
        uint8_t i;

        /* Set all expanded keys to CIPH_KEY_PATTERN/AUTH_KEY_PATTERN
         * if flag is set */
        if (force_pattern) {
                switch (params->hash_alg) {
                case IMB_AUTH_AES_XCBC:
                        memset(k1_expanded, AUTH_KEY_PATTERN,
                               sizeof(keys->k1_expanded));
                        break;
                case IMB_AUTH_AES_CMAC:
                case IMB_AUTH_AES_CMAC_BITLEN:
                        memset(k1_expanded, AUTH_KEY_PATTERN,
                               sizeof(keys->k1_expanded));
                        memset(k2, AUTH_KEY_PATTERN, sizeof(keys->k2));
                        memset(k3, AUTH_KEY_PATTERN, sizeof(keys->k3));
                        break;
                case IMB_AUTH_HMAC_SHA_1:
                case IMB_AUTH_HMAC_SHA_224:
                case IMB_AUTH_HMAC_SHA_256:
                case IMB_AUTH_HMAC_SHA_384:
                case IMB_AUTH_HMAC_SHA_512:
                case IMB_AUTH_MD5:
                        memset(ipad, AUTH_KEY_PATTERN, sizeof(keys->ipad));
                        memset(opad, AUTH_KEY_PATTERN, sizeof(keys->opad));
                        break;
                case IMB_AUTH_ZUC_EIA3_BITLEN:
                case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                case IMB_AUTH_KASUMI_UIA1:
                        memset(k3, AUTH_KEY_PATTERN, sizeof(keys->k3));
                        break;
                case IMB_AUTH_AES_CCM:
                case IMB_AUTH_AES_GMAC:
                case IMB_AUTH_NULL:
                case IMB_AUTH_SHA_1:
                case IMB_AUTH_SHA_224:
                case IMB_AUTH_SHA_256:
                case IMB_AUTH_SHA_384:
                case IMB_AUTH_SHA_512:
                case IMB_AUTH_PON_CRC_BIP:
                case IMB_AUTH_DOCSIS_CRC32:
                        /* No operation needed */
                        break;
                default:
                        fprintf(stderr, "Unsupported hash algo\n");
                        return -1;
                }

                switch (params->cipher_mode) {
                case IMB_CIPHER_GCM:
                        memset(gdata_key, CIPH_KEY_PATTERN,
                                sizeof(keys->gdata_key));
                        break;
                case IMB_CIPHER_PON_AES_CNTR:
                case IMB_CIPHER_CBC:
                case IMB_CIPHER_CCM:
                case IMB_CIPHER_CNTR:
                case IMB_CIPHER_CNTR_BITLEN:
                case IMB_CIPHER_DOCSIS_SEC_BPI:
                case IMB_CIPHER_ECB:
                        memset(enc_keys, CIPH_KEY_PATTERN,
                               sizeof(keys->enc_keys));
                        memset(dec_keys, CIPH_KEY_PATTERN,
                               sizeof(keys->dec_keys));
                        break;
                case IMB_CIPHER_DES:
                case IMB_CIPHER_DES3:
                case IMB_CIPHER_DOCSIS_DES:
                        memset(enc_keys, CIPH_KEY_PATTERN,
                               sizeof(keys->enc_keys));
                        break;
                case IMB_CIPHER_ZUC_EEA3:
                case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                        memset(k2, CIPH_KEY_PATTERN, sizeof(keys->k2));
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
        case IMB_AUTH_HMAC_SHA_1:
                /* compute ipad hash */
                memset(buf, 0x36, SHA1_BLOCK_SIZE);
                for (i = 0; i < SHA1_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA1_ONE_BLOCK(mb_mgr, buf, ipad);

                /* compute opad hash */
                memset(buf, 0x5c, SHA1_BLOCK_SIZE);
                for (i = 0; i < SHA1_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA1_ONE_BLOCK(mb_mgr, buf, opad);

                break;
        case IMB_AUTH_HMAC_SHA_224:
                /* compute ipad hash */
                memset(buf, 0x36, SHA_256_BLOCK_SIZE);
                for (i = 0; i < SHA_256_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA224_ONE_BLOCK(mb_mgr, buf, ipad);

                /* compute opad hash */
                memset(buf, 0x5c, SHA_256_BLOCK_SIZE);
                for (i = 0; i < SHA_256_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA224_ONE_BLOCK(mb_mgr, buf, opad);

                break;
        case IMB_AUTH_HMAC_SHA_256:
                /* compute ipad hash */
                memset(buf, 0x36, SHA_256_BLOCK_SIZE);
                for (i = 0; i < SHA_256_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA256_ONE_BLOCK(mb_mgr, buf, ipad);

                /* compute opad hash */
                memset(buf, 0x5c, SHA_256_BLOCK_SIZE);
                for (i = 0; i < SHA_256_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA256_ONE_BLOCK(mb_mgr, buf, opad);

                break;
        case IMB_AUTH_HMAC_SHA_384:
                /* compute ipad hash */
                memset(buf, 0x36, SHA_384_BLOCK_SIZE);
                for (i = 0; i < SHA_384_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA384_ONE_BLOCK(mb_mgr, buf, ipad);

                /* compute opad hash */
                memset(buf, 0x5c, SHA_384_BLOCK_SIZE);
                for (i = 0; i < SHA_384_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA384_ONE_BLOCK(mb_mgr, buf, opad);

                break;
        case IMB_AUTH_HMAC_SHA_512:
                /* compute ipad hash */
                memset(buf, 0x36, SHA_512_BLOCK_SIZE);
                for (i = 0; i < SHA_512_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA512_ONE_BLOCK(mb_mgr, buf, ipad);

                /* compute opad hash */
                memset(buf, 0x5c, SHA_512_BLOCK_SIZE);
                for (i = 0; i < SHA_512_BLOCK_SIZE; i++)
                        buf[i] ^= auth_key[i];
                IMB_SHA512_ONE_BLOCK(mb_mgr, buf, opad);

                break;
        case IMB_AUTH_MD5:
                /* compute ipad hash */
                memset(buf, 0x36, 64);
                for (i = 0; i < 64; i++)
                        buf[i] ^= auth_key[i];
                IMB_MD5_ONE_BLOCK(mb_mgr, buf, ipad);

                /* compute opad hash */
                memset(buf, 0x5c, 64);
                for (i = 0; i < 64; i++)
                        buf[i] ^= auth_key[i];
                IMB_MD5_ONE_BLOCK(mb_mgr, buf, opad);

                break;
        case IMB_AUTH_ZUC_EIA3_BITLEN:
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
        case IMB_AUTH_KASUMI_UIA1:
                memcpy(k3, auth_key, sizeof(keys->k3));
                break;
        case IMB_AUTH_AES_CCM:
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_NULL:
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
        case IMB_AUTH_PON_CRC_BIP:
        case IMB_AUTH_DOCSIS_CRC32:
                /* No operation needed */
                break;
        default:
                fprintf(stderr, "Unsupported hash algo\n");
                return -1;
        }

        switch (params->cipher_mode) {
        case IMB_CIPHER_GCM:
                switch (params->key_size) {
                case IMB_KEY_AES_128_BYTES:
                        IMB_AES128_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                case IMB_KEY_AES_192_BYTES:
                        IMB_AES192_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                case IMB_KEY_AES_256_BYTES:
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
                        IMB_AES_KEYEXP_128(mb_mgr, ciph_key, enc_keys,
                                           dec_keys);
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
                switch (params->key_size) {
                case IMB_KEY_AES_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, ciph_key, enc_keys,
                                           dec_keys);
                        break;
                case IMB_KEY_AES_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, ciph_key, enc_keys,
                                          dec_keys);
                        break;
                case IMB_KEY_AES_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, ciph_key, enc_keys,
                                           dec_keys);
                        break;
                default:
                        fprintf(stderr, "Wrong key size\n");
                        return -1;
                }
                break;
        case IMB_CIPHER_DES:
        case IMB_CIPHER_DES3:
        case IMB_CIPHER_DOCSIS_DES:
                des_key_schedule((uint64_t *) enc_keys, ciph_key);
                break;
        case IMB_CIPHER_ZUC_EEA3:
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                memcpy(k2, ciph_key, sizeof(keys->k2));
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
modify_pon_test_buf(uint8_t *test_buf, const struct params_s *params,
                    const IMB_JOB *job, const uint64_t xgem_hdr)
{
        /* Set plaintext CRC in test buffer for PON */
        uint32_t *buf32 = (uint32_t *) &test_buf[8 + params->buf_size - 4];
        uint64_t *buf64 = (uint64_t *) test_buf;
        const uint32_t *tag32 = (uint32_t *) job->auth_tag_output;
        const uint64_t hec_mask = BSWAP64(0xfffffffffffe000);
        const uint64_t xgem_hdr_out = ((const uint64_t *)job->src)[0];

        if (params->buf_size >= 5)
                buf32[0] = tag32[1];

        /* Check if any bits apart from HEC are modified */
        if ((xgem_hdr_out & hec_mask) != (xgem_hdr & hec_mask)) {
                fprintf(stderr, "XGEM header overwritten outside HEC\n");
                fprintf(stderr, "Original XGEM header: %"PRIx64"\n",
                        xgem_hdr & hec_mask);
                fprintf(stderr, "Output XGEM header: %"PRIx64"\n",
                        xgem_hdr_out & hec_mask);
                return -1;
        }

        /* Modify original XGEM header to include calculated HEC */
        buf64[0] = xgem_hdr_out;

        return 0;
}

/* Modify the test buffer to set the CRC value, so the final
 * decrypted message can be compared against the test buffer */
static void
modify_docsis_crc32_test_buf(uint8_t *test_buf, const struct params_s *params,
                             const IMB_JOB *job)
{
        if (params->buf_size >=
            (DOCSIS_CRC32_MIN_ETH_PDU_SIZE + DOCSIS_CRC32_TAG_SIZE)) {
                /* Set plaintext CRC32 in the test buffer */
                memcpy(&test_buf[params->buf_size - DOCSIS_CRC32_TAG_SIZE],
                       job->auth_tag_output, DOCSIS_CRC32_TAG_SIZE);
        }
}

/*
 * Checks for sensitive information in registers, stack and MB_MGR
 * (in this order, to try to minimize pollution of the data left out
 *  after the job completion, due to these actual checks).
 *
 *  Returns -1 if sensitive information was found or 0 if not.
 */
static int
perform_safe_checks(IMB_MGR *mgr, const enum arch_type_e arch,
                    const char *dir)
{
        uint8_t *rsp_ptr;
        uint32_t simd_size = 0;

        dump_gps();
        switch (arch) {
        case ARCH_SSE:
        case ARCH_AESNI_EMU:
                dump_xmms_sse();
                simd_size = XMM_MEM_SIZE;
                break;
        case ARCH_AVX:
                dump_xmms_avx();
                simd_size = XMM_MEM_SIZE;
                break;
        case ARCH_AVX2:
                dump_ymms();
                simd_size = YMM_MEM_SIZE;
                break;
        case ARCH_AVX512:
                dump_zmms();
                simd_size = ZMM_MEM_SIZE;
                break;
        default:
                fprintf(stderr,
                        "Error getting the architecture\n");
                return -1;
        }
        if (search_patterns(gps, GP_MEM_SIZE) == 0) {
                fprintf(stderr, "Pattern found in GP registers "
                        "after %s data\n", dir);
                return -1;
        }
        if (search_patterns(simd_regs, simd_size) == 0) {
                fprintf(stderr, "Pattern found in SIMD "
                        "registers after %s data\n", dir);
                return -1;
        }
        rsp_ptr = rdrsp();
        if (search_patterns((rsp_ptr - STACK_DEPTH),
                            STACK_DEPTH) == 0) {
                fprintf(stderr, "Pattern found in stack after "
                        "%s data\n", dir);
                return -1;
        }
        if (search_patterns(mgr, sizeof(IMB_MGR)) == 0) {
                fprintf(stderr, "Pattern found in MB_MGR after "
                                "%s data\n", dir);
                return -1;
        }

        return 0;
}

static void
clear_scratch_simd(const enum arch_type_e arch)
{
        switch (arch) {
        case ARCH_SSE:
        case ARCH_AESNI_EMU:
                clear_scratch_xmms_sse();
                break;
        case ARCH_AVX:
                clear_scratch_xmms_avx();
                break;
        case ARCH_AVX2:
                clear_scratch_ymms();
                break;
        case ARCH_AVX512:
                clear_scratch_zmms();
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                exit(EXIT_FAILURE);
        }
}

/* Performs test using AES_HMAC or DOCSIS */
static int
do_test(IMB_MGR *enc_mb_mgr, const enum arch_type_e enc_arch,
        IMB_MGR *dec_mb_mgr, const enum arch_type_e dec_arch,
        const struct params_s *params, struct data *data,
        const unsigned safe_check)
{
        IMB_JOB *job;
        uint32_t i;
        int ret = -1;
        uint32_t buf_size = params->buf_size;
        uint8_t tag_size = auth_tag_length_bytes[params->hash_alg - 1];
        uint64_t xgem_hdr = 0;
        uint8_t tag_size_to_check = tag_size;
        struct cipher_auth_keys *enc_keys = &data->enc_keys;
        struct cipher_auth_keys *dec_keys = &data->dec_keys;
        uint8_t *aad = data->aad;
        uint8_t *cipher_iv = data->cipher_iv;
        uint8_t *auth_iv = data->auth_iv;
        uint8_t *in_digest = data->in_digest;
        uint8_t *out_digest = data->out_digest;
        uint8_t *test_buf = data->test_buf;
        uint8_t *src_dst_buf = data->src_dst_buf;
        uint8_t *ciph_key = data->ciph_key;
        uint8_t *auth_key = data->auth_key;

        if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                /* Buf size is XGEM payload, including CRC,
                 * allocate space for XGEM header and padding */
                buf_size = buf_size + 8;
                if (buf_size % 8)
                        buf_size = (buf_size + 8) & 0xfffffff8;
                /* Only first 4 bytes are checked, corresponding to BIP */
                tag_size_to_check = 4;
        }

        if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                if (params->buf_size >=
                    (DOCSIS_CRC32_MIN_ETH_PDU_SIZE + DOCSIS_CRC32_TAG_SIZE))
                        tag_size_to_check = DOCSIS_CRC32_TAG_SIZE;
                else
                        tag_size_to_check = 0;
        }

        /* If performing a test searching for sensitive information,
         * set keys and plaintext to known values,
         * so they can be searched later on in the MB_MGR structure and stack.
         * Otherwise, just randomize the data */
        if (safe_check) {
                memset(test_buf, PT_PATTERN, buf_size);
                memset(ciph_key, CIPH_KEY_PATTERN, MAX_KEY_SIZE);
                memset(auth_key, AUTH_KEY_PATTERN, MAX_KEY_SIZE);
        } else {
                generate_random_buf(test_buf, buf_size);
                generate_random_buf(ciph_key, MAX_KEY_SIZE);
                generate_random_buf(auth_key, MAX_KEY_SIZE);
                generate_random_buf(cipher_iv, MAX_IV_SIZE);
                generate_random_buf(auth_iv, MAX_IV_SIZE);
                generate_random_buf(aad, AAD_SIZE);
        }

        /* For PON, construct the XGEM header, setting valid PLI */
        if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                /* create XGEM header template */
                const uint64_t pli = ((params->buf_size) << 2) & 0xffff;
                uint64_t *p_src = (uint64_t *)test_buf;

                xgem_hdr = ((pli >> 8) & 0xff) | ((pli & 0xff) << 8);
                p_src[0] = xgem_hdr;
        }

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
                uint8_t *rsp_ptr;

                /* Clear scratch registers before expanding keys to prevent
                 * other functions from storing sensitive data in stack */
                clear_scratch_simd(enc_arch);
                if (prepare_keys(enc_mb_mgr, enc_keys, ciph_key, auth_key,
                                 params, 0) < 0)
                        goto exit;

                rsp_ptr = rdrsp();
                if (search_patterns((rsp_ptr - STACK_DEPTH),
                                     STACK_DEPTH) == 0) {
                        fprintf(stderr, "Pattern found in stack after "
                                "expanding encryption keys\n");
                        goto exit;
                }

                if (prepare_keys(dec_mb_mgr, dec_keys, ciph_key, auth_key,
                                 params, 0) < 0)
                        goto exit;

                rsp_ptr = rdrsp();
                if (search_patterns((rsp_ptr - STACK_DEPTH),
                                     STACK_DEPTH) == 0) {
                        fprintf(stderr, "Pattern found in stack after "
                                "expanding decryption keys\n");
                        goto exit;
                }

                if (prepare_keys(enc_mb_mgr, enc_keys, ciph_key, auth_key,
                                 params, 1) < 0)
                        goto exit;

                if (prepare_keys(dec_mb_mgr, dec_keys, ciph_key, auth_key,
                                 params, 1) < 0)
                        goto exit;
        } else {
                if (prepare_keys(enc_mb_mgr, enc_keys, ciph_key, auth_key,
                                 params, 0) < 0)
                        goto exit;

                if (prepare_keys(dec_mb_mgr, dec_keys, ciph_key, auth_key,
                                 params, 0) < 0)
                        goto exit;
        }

        for (i = 0; i < job_iter; i++) {
                job = IMB_GET_NEXT_JOB(enc_mb_mgr);
                /*
                 * Encrypt + generate digest from encrypted message
                 * using architecture under test
                 */
                memcpy(src_dst_buf, test_buf, buf_size);
                if (fill_job(job, params, src_dst_buf, in_digest, aad,
                             buf_size, tag_size, IMB_DIR_ENCRYPT, enc_keys,
                             cipher_iv, auth_iv) < 0)
                        goto exit;

                /* Randomize memory for input digest */
                generate_random_buf(in_digest, tag_size);

                /* Clear scratch registers before submitting job to prevent
                 * other functions from storing sensitive data in stack */
                if (safe_check)
                        clear_scratch_simd(enc_arch);
                job = IMB_SUBMIT_JOB(enc_mb_mgr);

                if (!job)
                        job = IMB_FLUSH_JOB(enc_mb_mgr);

                if (!job) {
                        fprintf(stderr, "job not returned\n");
                        goto exit;
                }

                /* Check that the registers, stack and MB_MGR do not contain any
                 * sensitive information after job is returned */
                if (safe_check)
                        if (perform_safe_checks(enc_mb_mgr, enc_arch,
                                                "encrypting") < 0)
                                goto exit;

                if (job->status != STS_COMPLETED) {
                        fprintf(stderr, "failed job, status:%d\n",
                                job->status);
                        goto exit;
                }

                if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                        if (modify_pon_test_buf(test_buf, params, job,
                                                xgem_hdr) < 0)
                                goto exit;
                }

                if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32)
                        modify_docsis_crc32_test_buf(test_buf, params, job);

                job = IMB_GET_NEXT_JOB(dec_mb_mgr);

                /* Randomize memory for input digest */
                generate_random_buf(out_digest, tag_size);

                /*
                 * Generate digest from encrypted message and decrypt
                 * using reference architecture
                 */
                if (fill_job(job, params, src_dst_buf, out_digest, aad,
                             buf_size, tag_size, IMB_DIR_DECRYPT, dec_keys,
                             cipher_iv, auth_iv) < 0)
                        goto exit;

                /* Clear scratch registers before submitting job to prevent
                 * other functions from storing sensitive data in stack */
                if (safe_check)
                        clear_scratch_simd(dec_arch);
                job = IMB_SUBMIT_JOB(dec_mb_mgr);

                if (!job)
                        job = IMB_FLUSH_JOB(dec_mb_mgr);

                /* Check that the registers, stack and MB_MGR do not contain any
                 * sensitive information after job is returned */
                if (safe_check)
                        if (perform_safe_checks(dec_mb_mgr, dec_arch,
                            "decrypting") < 0)
                                goto exit;

                if (!job) {
                        fprintf(stderr, "job not returned\n");
                        goto exit;
                }

                if (job->status != STS_COMPLETED) {
                        fprintf(stderr, "failed job, status:%d\n",
                                job->status);
                        goto exit;
                }

                if (safe_check)
                        continue;

                if (params->hash_alg != IMB_AUTH_NULL &&
                    memcmp(in_digest, out_digest, tag_size_to_check) != 0) {
                        fprintf(stderr,
                                "\nInput and output tags don't match\n");
                        byte_hexdump("Input digest", in_digest,
                                     tag_size_to_check);
                        byte_hexdump("Output digest", out_digest,
                                     tag_size_to_check);
                        goto exit;
                }

                if (params->cipher_mode != IMB_CIPHER_NULL &&
                    memcmp(src_dst_buf, test_buf, buf_size) != 0) {
                        fprintf(stderr,
                                "\nDecrypted text and plaintext don't match\n");
                        byte_hexdump("Plaintext (orig)", test_buf, buf_size);
                        byte_hexdump("Decrypted msg", src_dst_buf, buf_size);
                        goto exit;
                }

                if ((params->hash_alg == IMB_AUTH_PON_CRC_BIP) &&
                    (params->buf_size > 4)) {
                        const uint64_t plen = params->buf_size - 4;

                        if (memcmp(src_dst_buf + 8 + plen,
                                   out_digest + 4, 4) != 0) {
                                fprintf(stderr, "\nDecrypted CRC and calculated"
                                        " CRC don't match\n");
                                byte_hexdump("Decrypted CRC",
                                             src_dst_buf + 8 + plen, 4);
                                byte_hexdump("Calculated CRC",
                                             out_digest + 4, 4);
                                goto exit;
                        }
                }
        }

        ret = 0;

exit:
        if (ret < 0) {
                printf("Failures in\n");
                print_algo_info(params);
                printf("Encrypting ");
                print_arch_info(enc_arch);
                printf("Decrypting ");
                print_arch_info(dec_arch);
                printf("Buffer size = %u\n", params->buf_size);
                printf("Key size = %u\n", params->key_size);
                printf("Tag size = %u\n", tag_size);
        }

        return ret;
}

/* Runs test for each buffer size */
static void
process_variant(IMB_MGR *enc_mgr, const enum arch_type_e enc_arch,
                IMB_MGR *dec_mgr, const enum arch_type_e dec_arch,
                struct params_s *params, struct data *variant_data,
                const unsigned int safe_check)
{
        const uint32_t sizes = params->num_sizes;
        uint32_t sz;

        if (verbose) {
                printf("Testing ");
                print_algo_info(params);
        }

        /* Reset the variant data */
        memset(variant_data, 0, sizeof(struct data));

        for (sz = 0; sz < sizes; sz++) {
                const uint32_t buf_size = job_sizes[RANGE_MIN] +
                                        (sz * job_sizes[RANGE_STEP]);
                params->aad_size = AAD_SIZE;

                params->buf_size = buf_size;

                /*
                 * CBC and ECB operation modes do not support lengths which are
                 * non-multiple of block size
                 */
                if (params->cipher_mode == IMB_CIPHER_CBC ||
                    params->cipher_mode == IMB_CIPHER_ECB)
                        if ((buf_size % AES_BLOCK_SIZE)  != 0)
                                continue;

                if (params->cipher_mode == IMB_CIPHER_DES ||
                    params->cipher_mode == IMB_CIPHER_DES3)
                        if ((buf_size % DES_BLOCK_SIZE)  != 0)
                                continue;

                /*
                 * KASUMI-UIA1 needs to be at least 9 bytes
                 * (IV + direction bit + '1' + 0s to align to byte boundary)
                 */
                if (params->hash_alg == IMB_AUTH_KASUMI_UIA1)
                        if (buf_size < (KASUMI_BLOCK_SIZE + 1))
                                continue;

                /* Check for sensitive data first, then normal cross
                 * architecture validation */
                if (safe_check && do_test(enc_mgr, enc_arch, dec_mgr, dec_arch,
                                          params, variant_data, 1) < 0)
                        exit(EXIT_FAILURE);

                if (do_test(enc_mgr, enc_arch, dec_mgr, dec_arch,
                            params, variant_data, 0) < 0)
                        exit(EXIT_FAILURE);

        }
}

/* Sets cipher direction and key size  */
static void
run_test(const enum arch_type_e enc_arch, const enum arch_type_e dec_arch,
         struct params_s *params, struct data *variant_data,
         const unsigned int safe_check)
{
        IMB_MGR *enc_mgr = NULL;
        IMB_MGR *dec_mgr = NULL;

        if (enc_arch == ARCH_AESNI_EMU)
                enc_mgr = alloc_mb_mgr(flags | IMB_FLAG_AESNI_OFF);
        else
                enc_mgr = alloc_mb_mgr(flags);

        if (enc_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        switch (enc_arch) {
        case ARCH_SSE:
        case ARCH_AESNI_EMU:
                init_mb_mgr_sse(enc_mgr);
                break;
        case ARCH_AVX:
                init_mb_mgr_avx(enc_mgr);
                break;
        case ARCH_AVX2:
                init_mb_mgr_avx2(enc_mgr);
                break;
        case ARCH_AVX512:
                init_mb_mgr_avx512(enc_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                exit(EXIT_FAILURE);
        }

        if (dec_arch == ARCH_AESNI_EMU)
                dec_mgr = alloc_mb_mgr(flags | IMB_FLAG_AESNI_OFF);
        else
                dec_mgr = alloc_mb_mgr(flags);

        if (dec_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        switch (dec_arch) {
        case ARCH_SSE:
        case ARCH_AESNI_EMU:
                init_mb_mgr_sse(dec_mgr);
                break;
        case ARCH_AVX:
                init_mb_mgr_avx(dec_mgr);
                break;
        case ARCH_AVX2:
                init_mb_mgr_avx2(dec_mgr);
                break;
        case ARCH_AVX512:
                init_mb_mgr_avx512(dec_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                exit(EXIT_FAILURE);
        }

        if (custom_test) {
                params->key_size = custom_job_params.key_size;
                params->cipher_mode = custom_job_params.cipher_mode;
                params->hash_alg = custom_job_params.hash_alg;
                process_variant(enc_mgr, enc_arch, dec_mgr, dec_arch, params,
                                variant_data, safe_check);
                goto exit;
        }

        JOB_HASH_ALG    hash_alg;
        JOB_CIPHER_MODE c_mode;

        for (c_mode = IMB_CIPHER_CBC; c_mode <= IMB_CIPHER_KASUMI_UEA1_BITLEN;
             c_mode++) {
                /* Skip IMB_CIPHER_CUSTOM */
                if (c_mode == IMB_CIPHER_CUSTOM)
                        continue;
                params->cipher_mode = c_mode;
                uint8_t min_sz = key_sizes[c_mode - 1][0];
                uint8_t max_sz = key_sizes[c_mode - 1][1];
                uint8_t step_sz = key_sizes[c_mode - 1][2];
                uint8_t key_sz;

                for (key_sz = min_sz; key_sz <= max_sz; key_sz += step_sz) {
                        params->key_size = key_sz;
                        for (hash_alg = IMB_AUTH_HMAC_SHA_1;
                             hash_alg <= IMB_AUTH_KASUMI_UIA1;
                             hash_alg++) {
                                /* Skip IMB_AUTH_CUSTOM */
                                if (hash_alg == IMB_AUTH_CUSTOM)
                                        continue;

                                /* Skip not supported combinations */
                                if ((c_mode == IMB_CIPHER_GCM &&
                                    hash_alg != IMB_AUTH_AES_GMAC) ||
                                    (c_mode != IMB_CIPHER_GCM &&
                                    hash_alg == IMB_AUTH_AES_GMAC))
                                        continue;
                                if ((c_mode == IMB_CIPHER_CCM &&
                                    hash_alg != IMB_AUTH_AES_CCM) ||
                                    (c_mode != IMB_CIPHER_CCM &&
                                    hash_alg == IMB_AUTH_AES_CCM))
                                        continue;
                                if ((c_mode == IMB_CIPHER_PON_AES_CNTR &&
                                    hash_alg != IMB_AUTH_PON_CRC_BIP) ||
                                    (c_mode != IMB_CIPHER_PON_AES_CNTR &&
                                    hash_alg == IMB_AUTH_PON_CRC_BIP))
                                        continue;
                                if (c_mode == IMB_CIPHER_DOCSIS_SEC_BPI &&
                                    (hash_alg != IMB_AUTH_NULL &&
                                     hash_alg != IMB_AUTH_DOCSIS_CRC32))
                                        continue;
                                if (c_mode != IMB_CIPHER_DOCSIS_SEC_BPI &&
                                    hash_alg == IMB_AUTH_DOCSIS_CRC32)
                                        continue;

                                params->hash_alg = hash_alg;
                                process_variant(enc_mgr, enc_arch, dec_mgr,
                                                dec_arch, params, variant_data,
                                                safe_check);
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
        enum arch_type_e enc_arch, dec_arch;
        const uint32_t min_size = job_sizes[RANGE_MIN];
        const uint32_t max_size = job_sizes[RANGE_MAX];
        const uint32_t step_size = job_sizes[RANGE_STEP];

        params.num_sizes = ((max_size - min_size) / step_size) + 1;

        variant_data = malloc(sizeof(struct data));

        if (variant_data == NULL) {
                fprintf(stderr, "Test data could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        if (verbose) {
                if (min_size == max_size)
                        printf("Testing buffer size = %u bytes\n", min_size);
                else
                        printf("Testing buffer sizes from %u to %u "
                               "in steps of %u bytes\n",
                               min_size, max_size, step_size);
        }
        /* Performing tests for each selected architecture */
        for (enc_arch = ARCH_SSE; enc_arch < NUM_ARCHS; enc_arch++) {
                if (enc_archs[enc_arch] == 0)
                        continue;
                printf("\nEncrypting with ");
                print_arch_info(enc_arch);

                for (dec_arch = ARCH_SSE; dec_arch < NUM_ARCHS; dec_arch++) {
                        if (dec_archs[dec_arch] == 0)
                                continue;
                        printf("\tDecrypting with ");
                        print_arch_info(dec_arch);
                        run_test(enc_arch, dec_arch, &params, variant_data,
                                 safe_check);
                }

        } /* end for run */

        free(variant_data);
}

static void usage(void)
{
        fprintf(stderr, "Usage: exhaustive_test [args], "
                "where args are zero or more\n"
                "-h: print this message\n"
                "-v: verbose, prints extra information\n"
                "--enc-arch: encrypting with architecture "
                "(AESNI_EMU/SSE/AVX/AVX2/AVX512)\n"
                "--dec-arch: decrypting with architecture "
                "(AESNI_EMU/SSE/AVX/AVX2/AVX512)\n"
                "--cipher-algo: Select cipher algorithm to run on the custom "
                "test\n"
                "--hash-algo: Select hash algorithm to run on the custom test\n"
                "--aead-algo: Select AEAD algorithm to run on the custom test\n"
                "--no-avx512: Don't do AVX512\n"
                "--no-avx2: Don't do AVX2\n"
                "--no-avx: Don't do AVX\n"
                "--no-sse: Don't do SSE\n"
                "--aesni-emu: Do AESNI_EMU (disabled by default)\n"
                "--shani-on: use SHA extensions, default: auto-detect\n"
                "--shani-off: don't use SHA extensions\n"
                "--job-size: size of the cipher & MAC job in bytes. "
                "It can be:\n"
                "            - single value: test single size\n"
                "            - range: test multiple sizes with following format"
                " min:step:max (e.g. 16:16:256)\n"
                "            (-o still applies for MAC)\n"
                "--job-iter: number of tests iterations for each job size\n"
                "--safe-check: check if keys, IVs, plaintext or tags "
                "get cleared from IMB_MGR upon job completion (off by default; "
                "requires library compiled with SAFE_DATA)\n");
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

        if ((p_mgr->features & detect_sse) != detect_sse) {
                arch_support[ARCH_SSE] = 0;
                arch_support[ARCH_AESNI_EMU] = 0;
        }

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
                if (strcmp(arg, map[i].name) == 0)
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
        /* Try parsing as single value */
        get_next_num_arg(argv, index, argc, &job_sizes[RANGE_MIN],
                     sizeof(job_sizes[RANGE_MIN]));

        job_sizes[RANGE_MAX] = job_sizes[RANGE_MIN];

end_range:
        free(copy_arg);
        return (index + 1);

}

int main(int argc, char *argv[])
{
        int i;
        unsigned int arch_id;
        unsigned int arch_support[NUM_ARCHS];
        const union params *values;
        unsigned int cipher_algo_set = 0;
        unsigned int hash_algo_set = 0;
        unsigned int aead_algo_set = 0;
        unsigned int safe_check = 0;

        for (i = 1; i < argc; i++)
                if (strcmp(argv[i], "-h") == 0) {
                        usage();
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "-v") == 0) {
                        verbose = 1;
                } else if (strcmp(argv[i], "--no-avx512") == 0) {
                        enc_archs[ARCH_AVX512] = 0;
                        dec_archs[ARCH_AVX512] = 0;
                } else if (strcmp(argv[i], "--no-avx2") == 0) {
                        enc_archs[ARCH_AVX2] = 0;
                        dec_archs[ARCH_AVX2] = 0;
                } else if (strcmp(argv[i], "--no-avx") == 0) {
                        enc_archs[ARCH_AVX] = 0;
                        dec_archs[ARCH_AVX] = 0;
                } else if (strcmp(argv[i], "--no-sse") == 0) {
                        enc_archs[ARCH_SSE] = 0;
                        dec_archs[ARCH_SSE] = 0;
                } else if (strcmp(argv[i], "--aesni-emu") == 0) {
                        enc_archs[ARCH_AESNI_EMU] = 1;
                        dec_archs[ARCH_AESNI_EMU] = 1;
                } else if (strcmp(argv[i], "--shani-on") == 0) {
                        flags &= (~IMB_FLAG_SHANI_OFF);
                } else if (strcmp(argv[i], "--shani-off") == 0) {
                        flags |= IMB_FLAG_SHANI_OFF;
                } else if (strcmp(argv[i], "--enc-arch") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                                  arch_str_map,
                                                  DIM(arch_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        memset(enc_archs, 0, sizeof(enc_archs));
                        enc_archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--dec-arch") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                                  arch_str_map,
                                                  DIM(arch_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        memset(dec_archs, 0, sizeof(dec_archs));
                        dec_archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--cipher-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                        cipher_algo_str_map,
                                        DIM(cipher_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode =
                                        values->job_params.cipher_mode;
                        custom_job_params.key_size =
                                        values->job_params.key_size;
                        custom_test = 1;
                        cipher_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--hash-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i+1],
                                        hash_algo_str_map,
                                        DIM(hash_algo_str_map));
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.hash_alg =
                                        values->job_params.hash_alg;
                        custom_test = 1;
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
                        custom_job_params.key_size =
                                        values->job_params.key_size;
                        custom_job_params.hash_alg =
                                        values->job_params.hash_alg;
                        custom_test = 1;
                        aead_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--job-size") == 0) {
                        /* Try parsing the argument as a range first */
                        i = parse_range((const char * const *)argv, i, argc,
                                          job_sizes);
                        if (job_sizes[RANGE_MAX] > JOB_SIZE_TOP) {
                                fprintf(stderr,
                                       "Invalid job size %u (max %u)\n",
                                       (unsigned) job_sizes[RANGE_MAX],
                                       JOB_SIZE_TOP);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--job-iter") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &job_iter, sizeof(job_iter));
                } else if (strcmp(argv[i], "--safe-check") == 0) {
                        safe_check = 1;
                } else {
                        usage();
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

        if (detect_arch(arch_support) < 0)
                return EXIT_FAILURE;

        /* disable tests depending on instruction sets supported */
        for (arch_id = 0; arch_id < NUM_ARCHS; arch_id++) {
                if (arch_support[arch_id] == 0) {
                        enc_archs[arch_id] = 0;
                        dec_archs[arch_id] = 0;
                        fprintf(stderr,
                                "%s not supported. Disabling %s tests\n",
                                arch_str_map[arch_id].name,
                                arch_str_map[arch_id].name);
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
        if (enc_archs[ARCH_SSE] || dec_archs[ARCH_SSE]) {
                init_mb_mgr_sse(p_mgr);
                fprintf(stderr, "%s SHA extensions (shani) for SSE arch\n",
                        (p_mgr->features & IMB_FEATURE_SHANI) ?
                        "Using" : "Not using");
        }
        free_mb_mgr(p_mgr);

        srand(SEED);

        run_tests(safe_check);

        return EXIT_SUCCESS;
}
