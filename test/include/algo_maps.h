/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_ALGO_MAPS_H
#define TESTAPP_ALGO_MAPS_H

#include <stdint.h>
#include <stddef.h>

#include "job_params.h"

/**
 * @brief Architecture name to IMB_ARCH value mapping
 *
 * The first entry is IMB_ARCH_NONE and it is usually skipped
 * when the mapping is used to parse command line arguments.
 *
 * @see num_arch_str_map
 */
extern const struct str_value_mapping arch_str_map[];

/**
 * @brief Cipher direction name to IMB_CIPHER_DIRECTION value mapping
 *
 * @see num_cipher_dir_str_map
 */
extern const struct str_value_mapping cipher_dir_str_map[];

/**
 * @brief Cipher algorithm name to cipher mode and key size mapping
 *
 * @see num_cipher_algo_str_map
 */
extern const struct str_value_mapping cipher_algo_str_map[];

/**
 * @brief Hash algorithm name to hash algorithm value mapping
 *
 * @see num_hash_algo_str_map
 */
extern const struct str_value_mapping hash_algo_str_map[];

/**
 * @brief AEAD algorithm name to cipher mode, hash algorithm and key size mapping
 *
 * @see num_aead_algo_str_map
 */
extern const struct str_value_mapping aead_algo_str_map[];

/**
 * @brief Number of entries in arch_str_map[]
 */
extern const size_t num_arch_str_map;

/**
 * @brief Number of entries in cipher_dir_str_map[]
 */
extern const size_t num_cipher_dir_str_map;

/**
 * @brief Number of entries in cipher_algo_str_map[]
 */
extern const size_t num_cipher_algo_str_map;

/**
 * @brief Number of entries in hash_algo_str_map[]
 */
extern const size_t num_hash_algo_str_map;

/**
 * @brief Number of entries in aead_algo_str_map[]
 */
extern const size_t num_aead_algo_str_map;

/**
 * @brief Default authentication tag length in bytes
 *
 * Indexed with an IMB_HASH_ALG value decremented by one, e.g.
 * auth_tag_len_bytes[IMB_AUTH_HMAC_SHA_1 - 1].
 */
extern const uint8_t auth_tag_len_bytes[];

/**
 * @brief Cipher key size minimum, maximum and step in bytes
 *
 * Indexed with an IMB_CIPHER_MODE value decremented by one, e.g.
 * key_sizes[IMB_CIPHER_CBC - 1]. The second index selects
 * minimum (0), maximum (1) and step (2) key size.
 */
extern const uint8_t key_sizes[][3];

#endif /* TESTAPP_ALGO_MAPS_H */
