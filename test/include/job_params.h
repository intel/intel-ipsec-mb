/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_JOB_PARAMS_H
#define TESTAPP_JOB_PARAMS_H

#include <stdint.h>

#include <intel-ipsec-mb.h>

/* Maximum key and digest size for SHA-512 */
#define MAX_KEY_SIZE    IMB_SHA_512_BLOCK_SIZE
#define MAX_DIGEST_SIZE IMB_SHA512_DIGEST_SIZE_IN_BYTES

/* Maximum AAD size tested with AES-GCM */
#define MAX_GCM_AAD_SIZE 1024
/* Maximum AAD size tested with AES-CCM */
#define MAX_CCM_AAD_SIZE 46
/* Number of authentication tag sizes tested with AES-CCM (4,6,8,10,12,14,16) */
#define NUM_TAG_SIZES 7
/* Size of the AAD buffer, has to fit the largest AAD size tested */
#define MAX_AAD_SIZE MAX_GCM_AAD_SIZE

/**
 * @brief Test parameters describing a single algorithm and message size
 */
struct params_s {
        IMB_CIPHER_MODE cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        IMB_HASH_ALG hash_alg;       /* SHA-1 or others... */
        uint32_t key_size;
        uint32_t buf_size;
        uint32_t aad_size;
        uint32_t num_sizes;
};

/**
 * @brief Expanded cipher and authentication keys
 *
 * Holds key schedules for all supported algorithms, so that the same
 * structure can be used no matter which algorithm is under test.
 */
struct cipher_auth_keys {
        uint8_t temp_buf[IMB_SHA_512_BLOCK_SIZE];
        DECLARE_ALIGNED(uint32_t dust[15 * 4], 16);
        uint8_t ipad[IMB_SHA3_MAX_BLOCK_SIZE]; /* largest ipad/opad block: SHA3-224 rate = 144B */
        uint8_t opad[IMB_SHA3_MAX_BLOCK_SIZE];
        DECLARE_ALIGNED(uint32_t k1_expanded[15 * 4], 16);
        DECLARE_ALIGNED(uint8_t k2[32], 16);
        DECLARE_ALIGNED(uint8_t k3[16], 16);
        /* cipher key storage for algorithms taking the key directly (wireless ciphers,
         * CHACHA20); kept separate from k2 so that combined cipher + authentication jobs
         * hold distinct cipher and authentication keys
         */
        DECLARE_ALIGNED(uint8_t ck[32], 16);
        DECLARE_ALIGNED(uint8_t nia4_key[32], 16); /* SNOW5G-NIA4 256-bit key */
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);
        DECLARE_ALIGNED(struct gcm_key_data gdata_key, 64);
};

/**
 * @brief Byte patterns to fill expanded keys with instead of expanding them
 *
 * Used by the safe check application to place known patterns in the key
 * schedules, so that they can be searched for after job processing.
 *
 * @see fill_keys()
 */
struct key_fill_pattern {
        uint8_t cipher_key; /* pattern to fill the cipher key schedule with */
        uint8_t auth_key;   /* pattern to fill the hash key schedule with */
};

/**
 * @brief Context of a single submitted job
 *
 * Keeps track of the buffers and the values that need to be verified
 * or restored after the job has been completed.
 */
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

/**
 * @brief Algorithm parameters selected with a command line option
 */
struct custom_job_params {
        IMB_CIPHER_MODE cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        IMB_HASH_ALG hash_alg;       /* SHA-1 or others... */
        uint32_t key_size;
};

/**
 * @brief Value associated with a command line argument name
 */
union params {
        IMB_ARCH arch_type;
        IMB_CIPHER_DIRECTION cipher_dir;
        struct custom_job_params job_params;
};

/**
 * @brief Command line argument name to parameter value mapping
 */
struct str_value_mapping {
        const char *name;
        union params values;
};

/**
 * @brief Indexes of the message size range values
 */
enum range { RANGE_MIN = 0, RANGE_STEP, RANGE_MAX, NUM_RANGE };

#endif /* TESTAPP_JOB_PARAMS_H */
