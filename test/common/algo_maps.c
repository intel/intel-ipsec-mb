/**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stddef.h>

#include "algo_maps.h"
#include "utils.h"

const struct str_value_mapping arch_str_map[] = {
        { .name = "NONE", .values.arch_type = IMB_ARCH_NONE },
        { .name = "SSE", .values.arch_type = IMB_ARCH_SSE },
        { .name = "AVX2", .values.arch_type = IMB_ARCH_AVX2 },
        { .name = "AVX512", .values.arch_type = IMB_ARCH_AVX512 },
        { .name = "AVX10", .values.arch_type = IMB_ARCH_AVX10 }
};

const struct str_value_mapping cipher_dir_str_map[] = {
        { .name = "ENCRYPT", .values.cipher_dir = IMB_DIR_ENCRYPT },
        { .name = "DECRYPT", .values.cipher_dir = IMB_DIR_DECRYPT }
};

const struct str_value_mapping cipher_algo_str_map[] = {
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
        { .name = "SNOW3G-UEA2",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SNOW3G_UEA2, .key_size = 16 } },
        { .name = "KASUMI-F8",
          .values.job_params = { .cipher_mode = IMB_CIPHER_KASUMI_UEA1, .key_size = 16 } },
        { .name = "CHACHA20-256",
          .values.job_params = { .cipher_mode = IMB_CIPHER_CHACHA20, .key_size = 32 } },
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
          .values.job_params = { .cipher_mode = IMB_CIPHER_CFB, .key_size = IMB_KEY_256_BYTES } },
        { .name = "ZUC-NEA6",
          .values.job_params = { .cipher_mode = IMB_CIPHER_ZUC_NEA6,
                                 .key_size = IMB_KEY_256_BYTES } },
        { .name = "SNOW5G-NEA4",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SNOW5G_NEA4, .key_size = 32 } },
        { .name = "AES-NEA5",
          .values.job_params = { .cipher_mode = IMB_CIPHER_AES_NEA5, .key_size = 32 } }
};

const struct str_value_mapping hash_algo_str_map[] = {
        { .name = "HMAC-SHA1", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA_1 } },
        { .name = "HMAC-SHA224", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA_224 } },
        { .name = "HMAC-SHA256", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA_256 } },
        { .name = "HMAC-SHA384", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA_384 } },
        { .name = "HMAC-SHA512", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA_512 } },
        { .name = "AES-XCBC-128", .values.job_params = { .hash_alg = IMB_AUTH_AES_XCBC } },
        { .name = "HMAC-MD5", .values.job_params = { .hash_alg = IMB_AUTH_MD5 } },
        { .name = "AES-CMAC-128", .values.job_params = { .hash_alg = IMB_AUTH_AES_CMAC } },
        { .name = "NULL-HASH", .values.job_params = { .hash_alg = IMB_AUTH_NULL } },
        { .name = "SHA1", .values.job_params = { .hash_alg = IMB_AUTH_SHA_1 } },
        { .name = "SHA224", .values.job_params = { .hash_alg = IMB_AUTH_SHA_224 } },
        { .name = "SHA256", .values.job_params = { .hash_alg = IMB_AUTH_SHA_256 } },
        { .name = "SHA384", .values.job_params = { .hash_alg = IMB_AUTH_SHA_384 } },
        { .name = "SHA512", .values.job_params = { .hash_alg = IMB_AUTH_SHA_512 } },
        { .name = "ZUC-EIA3", .values.job_params = { .hash_alg = IMB_AUTH_ZUC_EIA3 } },
        { .name = "SNOW3G-UIA2", .values.job_params = { .hash_alg = IMB_AUTH_SNOW3G_UIA2 } },
        { .name = "KASUMI-F9", .values.job_params = { .hash_alg = IMB_AUTH_KASUMI_UIA1 } },
        { .name = "AES-GMAC-128", .values.job_params = { .hash_alg = IMB_AUTH_AES_GMAC_128 } },
        { .name = "AES-GMAC-192", .values.job_params = { .hash_alg = IMB_AUTH_AES_GMAC_192 } },
        { .name = "AES-GMAC-256", .values.job_params = { .hash_alg = IMB_AUTH_AES_GMAC_256 } },
        { .name = "AES-CMAC-256", .values.job_params = { .hash_alg = IMB_AUTH_AES_CMAC_256 } },
        { .name = "POLY1305", .values.job_params = { .hash_alg = IMB_AUTH_POLY1305 } },
        { .name = "GHASH", .values.job_params = { .hash_alg = IMB_AUTH_GHASH } },
        { .name = "ETH-CRC32", .values.job_params = { .hash_alg = IMB_AUTH_CRC32_ETHERNET_FCS } },
        { .name = "SCTP-CRC32", .values.job_params = { .hash_alg = IMB_AUTH_CRC32_SCTP } },
        { .name = "WIMAX-OFDMA-CRC32",
          .values.job_params = { .hash_alg = IMB_AUTH_CRC32_WIMAX_OFDMA_DATA } },
        { .name = "LTE-A-CRC24", .values.job_params = { .hash_alg = IMB_AUTH_CRC24_LTE_A } },
        { .name = "LTE-B-CRC24", .values.job_params = { .hash_alg = IMB_AUTH_CRC24_LTE_B } },
        { .name = "X25-CRC16", .values.job_params = { .hash_alg = IMB_AUTH_CRC16_X25 } },
        { .name = "FP-CRC16", .values.job_params = { .hash_alg = IMB_AUTH_CRC16_FP_DATA } },
        { .name = "FP-CRC11", .values.job_params = { .hash_alg = IMB_AUTH_CRC11_FP_HEADER } },
        { .name = "IUUP-CRC10", .values.job_params = { .hash_alg = IMB_AUTH_CRC10_IUUP_DATA } },
        { .name = "WIMAX-OFDMA-CRC8",
          .values.job_params = { .hash_alg = IMB_AUTH_CRC8_WIMAX_OFDMA_HCS } },
        { .name = "FP-CRC7", .values.job_params = { .hash_alg = IMB_AUTH_CRC7_FP_HEADER } },
        { .name = "IUUP-CRC6", .values.job_params = { .hash_alg = IMB_AUTH_CRC6_IUUP_HEADER } },
        { .name = "SM3", .values.job_params = { .hash_alg = IMB_AUTH_SM3 } },
        { .name = "HMAC-SM3", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SM3 } },
        { .name = "SHA3-224", .values.job_params = { .hash_alg = IMB_AUTH_SHA3_224 } },
        { .name = "SHA3-256", .values.job_params = { .hash_alg = IMB_AUTH_SHA3_256 } },
        { .name = "SHA3-384", .values.job_params = { .hash_alg = IMB_AUTH_SHA3_384 } },
        { .name = "SHA3-512", .values.job_params = { .hash_alg = IMB_AUTH_SHA3_512 } },
        { .name = "SHAKE-128", .values.job_params = { .hash_alg = IMB_AUTH_SHAKE128 } },
        { .name = "SHAKE-256", .values.job_params = { .hash_alg = IMB_AUTH_SHAKE256 } },
        { .name = "AES-NIA5", .values.job_params = { .hash_alg = IMB_AUTH_AES_NIA5 } },
        { .name = "ZUC-NIA6", .values.job_params = { .hash_alg = IMB_AUTH_ZUC_NIA6 } },
        { .name = "SNOW5G-NIA4", .values.job_params = { .hash_alg = IMB_AUTH_SNOW5G_NIA4 } },
        { .name = "HMAC-SHA3-224", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA3_224 } },
        { .name = "HMAC-SHA3-256", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA3_256 } },
        { .name = "HMAC-SHA3-384", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA3_384 } },
        { .name = "HMAC-SHA3-512", .values.job_params = { .hash_alg = IMB_AUTH_HMAC_SHA3_512 } }
};

const struct str_value_mapping aead_algo_str_map[] = {
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
        { .name = "SM4-GCM",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SM4_GCM,
                                 .hash_alg = IMB_AUTH_SM4_GCM,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "DOCSIS-SEC-128-CRC32",
          .values.job_params = { .cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI,
                                 .hash_alg = IMB_AUTH_DOCSIS_CRC32,
                                 .key_size = IMB_KEY_128_BYTES } },
        { .name = "AES-NCA5",
          .values.job_params = { .cipher_mode = IMB_CIPHER_AES_NCA5,
                                 .hash_alg = IMB_AUTH_AES_NCA5,
                                 .key_size = IMB_KEY_256_BYTES } },
        { .name = "ZUC-NCA6",
          .values.job_params = { .cipher_mode = IMB_CIPHER_ZUC_NCA6,
                                 .hash_alg = IMB_AUTH_ZUC_NCA6,
                                 .key_size = IMB_KEY_256_BYTES } },
        { .name = "SNOW5G-NCA4",
          .values.job_params = { .cipher_mode = IMB_CIPHER_SNOW5G_NCA4,
                                 .hash_alg = IMB_AUTH_SNOW5G_NCA4,
                                 .key_size = IMB_KEY_256_BYTES } }
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
        8,                         /* IMB_PON */
        4,                         /* IMB_AUTH_ZUC_EIA3 */
        IMB_DOCSIS_CRC32_TAG_SIZE, /* IMB_AUTH_DOCSIS_CRC32 */
        4,                         /* IMB_AUTH_SNOW3G_UIA2 (3GPP) */
        4,                         /* IMB_AUTH_KASUMI_UIA1 (3GPP) */
        16,                        /* IMB_AUTH_AES_GMAC_128 */
        16,                        /* IMB_AUTH_AES_GMAC_192 */
        16,                        /* IMB_AUTH_AES_GMAC_256 */
        16,                        /* IMB_AUTH_AES_CMAC_256 */
        16,                        /* IMB_AUTH_POLY1305 */
        16,                        /* IMB_AUTH_CHACHA20_POLY1305 */
        16,                        /* IMB_AUTH_CHACHA20_POLY1305_SGL */
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
        28,                        /* IMB_AUTH_SHA3_224 */
        32,                        /* IMB_AUTH_SHA3_256 */
        48,                        /* IMB_AUTH_SHA3_384 */
        64,                        /* IMB_AUTH_SHA3_512 */
        16,                        /* IMB_AUTH_SHAKE128 */
        32,                        /* IMB_AUTH_SHAKE256 */
        4,                         /* IMB_AUTH_AES_NIA5 */
        4,                         /* IMB_AUTH_AES_NCA5 */
        4,                         /* IMB_AUTH_ZUC_NIA6 */
        4,                         /* IMB_AUTH_ZUC_NCA6 */
        4,                         /* IMB_AUTH_SNOW5G_NIA4 */
        4,                         /* IMB_AUTH_SNOW5G_NCA4 */
        28,                        /* IMB_AUTH_HMAC_SHA3_224 */
        32,                        /* IMB_AUTH_HMAC_SHA3_256 */
        48,                        /* IMB_AUTH_HMAC_SHA3_384 */
        64,                        /* IMB_AUTH_HMAC_SHA3_512 */
};

/* Minimum, maximum and step values of key sizes */
const uint8_t key_sizes[][3] = {
        { 16, 32, 8 },  /* IMB_CIPHER_CBC */
        { 16, 32, 8 },  /* IMB_CIPHER_CNTR */
        { 0, 0, 1 },    /* IMB_CIPHER_NULL */
        { 16, 32, 16 }, /* IMB_CIPHER_DOCSIS_SEC_BPI */
        { 16, 32, 8 },  /* IMB_CIPHER_GCM */
        { 8, 8, 1 },    /* IMB_CIPHER_DES */
        { 8, 8, 1 },    /* IMB_CIPHER_DOCSIS_DES */
        { 16, 32, 16 }, /* IMB_CIPHER_CCM */
        { 24, 24, 1 },  /* IMB_CIPHER_DES3 */
        { 16, 16, 1 },  /* IMB_CIPHER_PON_AES_CNTR */
        { 16, 32, 8 },  /* IMB_CIPHER_ECB */
        { 16, 16, 1 },  /* IMB_CIPHER_ZUC_EEA3 */
        { 16, 16, 1 },  /* IMB_CIPHER_SNOW3G_UEA2 */
        { 16, 16, 1 },  /* IMB_CIPHER_KASUMI_UEA1 */
        { 32, 32, 1 },  /* IMB_CIPHER_CHACHA20 */
        { 32, 32, 1 },  /* IMB_CIPHER_CHACHA20_POLY1305 */
        { 32, 32, 1 },  /* IMB_CIPHER_CHACHA20_POLY1305_SGL */
        { 16, 32, 8 },  /* IMB_CIPHER_GCM_SGL */
        { 16, 16, 1 },  /* IMB_CIPHER_SM4_ECB */
        { 16, 16, 1 },  /* IMB_CIPHER_SM4_CBC */
        { 16, 32, 8 },  /* IMB_CIPHER_CFB */
        { 16, 16, 1 },  /* IMB_CIPHER_SM4_CNTR */
        { 16, 16, 1 },  /* IMB_CIPHER_SM4_GCM */
        { 32, 32, 1 },  /* IMB_CIPHER_ZUC_NEA6 */
        { 32, 32, 1 },  /* IMB_CIPHER_SNOW5G_NEA4 */
        { 32, 32, 1 },  /* IMB_CIPHER_AES_NEA5 */
        { 32, 32, 1 },  /* IMB_CIPHER_AES_NCA5 */
        { 32, 32, 1 },  /* IMB_CIPHER_ZUC_NCA6 */
        { 32, 32, 1 },  /* IMB_CIPHER_SNOW5G_NCA4 */
};

const size_t num_arch_str_map = DIM(arch_str_map);
const size_t num_cipher_dir_str_map = DIM(cipher_dir_str_map);
const size_t num_cipher_algo_str_map = DIM(cipher_algo_str_map);
const size_t num_hash_algo_str_map = DIM(hash_algo_str_map);
const size_t num_aead_algo_str_map = DIM(aead_algo_str_map);
