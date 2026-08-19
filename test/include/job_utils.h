/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_JOB_UTILS_H
#define TESTAPP_JOB_UTILS_H

#include <stdint.h>
#include <stddef.h>

#include <intel-ipsec-mb.h>

#include "job_params.h"

/**
 * @brief Cipher IV size in bytes (0 => use algorithm default)
 */
extern uint32_t cipher_iv_size;

/**
 * @brief Authentication IV size in bytes (0 => use algorithm default)
 */
extern uint32_t auth_iv_size;

/**
 * @brief Authentication tag size in bytes (0 => use algorithm default)
 */
extern uint8_t auth_tag_size;

/**
 * @brief Source buffer offset applied to cipher and hash operations
 *
 * Used to exercise the library with non-zero source and destination offsets.
 */
extern uint64_t offset;

/**
 * @brief AVX-SSE transition check availability
 *
 * Set by the application at start-up, usually with avx_sse_detectability().
 *
 * @see avx_sse_check()
 */
extern int is_avx_sse_check_possible;

/**
 * @brief Checks for and reports AVX to SSE transition issues
 *
 * Detects dirty upper halves of YMM/ZMM registers left after a job
 * has been processed. Nothing is checked when
 * \a is_avx_sse_check_possible is zero.
 * Detected issues are reported on the standard output.
 *
 * @param [in] ctx_str      Context string added to the error message,
 *                          e.g. name of the API that has been called
 * @param [in] hash_alg     Hash algorithm used by the job
 * @param [in] cipher_mode  Cipher mode used by the job
 *
 * @see is_avx_sse_check_possible
 */
void
avx_sse_check(const char *ctx_str, const IMB_HASH_ALG hash_alg, const IMB_CIPHER_MODE cipher_mode);

/**
 * @brief Prints name of the algorithm(s) selected by the test parameters
 *
 * The AEAD algorithm name is printed if the cipher mode, hash algorithm
 * and key size match one of the AEAD algorithms.
 * Otherwise the cipher algorithm and hash algorithm names are printed.
 *
 * @param [in] params  Pointer to the test parameters
 */
void
print_algo_info(const struct params_s *params);

/**
 * @brief Expands cipher and authentication keys for the selected algorithms
 *
 * Runs the key expansion functions matching the cipher mode, hash algorithm
 * and key size from \a params and stores the key schedules in \a keys.
 *
 * If \a pattern is not NULL then no key expansion is done. Instead, the key
 * schedules that the selected algorithms use are filled with the byte
 * patterns from \a pattern. This allows an application to search memory for
 * key material after job processing (see the safe check application).
 * Key schedules not used by the selected algorithms are left untouched in
 * both cases.
 *
 * @param [in] mb_mgr     Pointer to the initialized IMB_MGR
 * @param [out] keys      Pointer to the expanded cipher and hash keys
 * @param [in] ciph_key   Pointer to the cipher key, at least MAX_KEY_SIZE bytes
 * @param [in] auth_key   Pointer to the hash key, at least MAX_KEY_SIZE bytes
 * @param [in] params     Pointer to the test parameters
 * @param [in] pattern    Byte patterns to fill the key schedules with,
 *                        NULL to expand \a ciph_key and \a auth_key
 *
 * @return Operation status
 * @retval 0 keys prepared
 * @retval -1 unsupported cipher mode, hash algorithm or key size
 */
int
fill_keys(IMB_MGR *mb_mgr, struct cipher_auth_keys *keys, const uint8_t *ciph_key,
          const uint8_t *auth_key, const struct params_s *params,
          const struct key_fill_pattern *pattern);

/**
 * @brief Fills in the context of a single job and prepares its message
 *
 * Sets up the buffer pointers, the message size and the tag size to be
 * verified after the job has been completed. PON and DOCSIS message sizes
 * and tag sizes are adjusted to the algorithm requirements, including
 * the XGEM header for PON.
 *
 * The message is written by the \a fill_test_buf callback, which allows
 * an application to use random data or a known byte pattern
 * (see the safe check application).
 * The digest buffer to verify against is filled with random data.
 *
 * @param [out] ctx           Pointer to the job context to fill in
 * @param [in] params         Pointer to the test parameters
 * @param [in] buf_size       Message size in bytes
 * @param [in] max_buf_size   Size of \a test_buf and \a src_dst_buf in bytes
 * @param [in] in_digest      Pointer to the digest buffer to be produced
 * @param [in] out_digest     Pointer to the digest buffer to verify against
 * @param [in] tag_size       Authentication tag size in bytes
 * @param [in] test_buf       Pointer to the message buffer
 * @param [in] src_dst_buf    Pointer to the source/destination buffer
 * @param [in] fill_test_buf  Function filling \a test_buf with the message
 *
 * @return Operation status
 * @retval 0 context filled in
 * @retval -1 message size too big for the selected algorithm
 */
int
set_job_ctx(struct job_ctx *ctx, const struct params_s *params, const uint32_t buf_size,
            const uint32_t max_buf_size, uint8_t *in_digest, uint8_t *out_digest,
            const uint8_t tag_size, uint8_t *test_buf, uint8_t *src_dst_buf,
            void (*fill_test_buf)(uint8_t *buf, const uint32_t size));

/**
 * @brief Fills in a job structure with the test parameters
 *
 * Sets up all job fields required by the selected cipher mode and
 * hash algorithm, including key pointers, IV's, AAD and tag length.
 * The job index is stored in \a job->user_data so that job completion
 * order can be verified later on.
 *
 * @param [out] job         Pointer to the job structure to fill in
 * @param [in] params       Pointer to the test parameters
 * @param [in] buf          Pointer to the source/destination buffer
 * @param [in] digest       Pointer to the digest buffer
 * @param [in] aad          Pointer to the additional authenticated data buffer
 * @param [in] buf_size     Message size in bytes
 * @param [in] tag_size     Authentication tag size in bytes
 * @param [in] cipher_dir   Cipher direction (encrypt or decrypt)
 * @param [in] keys         Pointer to the expanded cipher and hash keys
 * @param [in] cipher_iv    Pointer to the cipher IV buffer
 * @param [in] auth_iv      Pointer to the authentication IV buffer
 * @param [in] index        Job index, stored in \a job->user_data
 *
 * @return Operation status
 * @retval 0 job filled in
 * @retval -1 unsupported cipher mode or hash algorithm
 */
int
fill_job(IMB_JOB *job, const struct params_s *params, uint8_t *buf, uint8_t *digest,
         const uint8_t *aad, const uint32_t buf_size, const uint8_t tag_size,
         IMB_CIPHER_DIRECTION cipher_dir, struct cipher_auth_keys *keys, uint8_t *cipher_iv,
         uint8_t *auth_iv, const unsigned index);

/**
 * @brief Checks if cipher mode and hash algorithm can be used together
 *
 * Filters out combinations that are not supported by the library
 * (e.g. AES-GCM with a hash algorithm other than AES-GMAC) and
 * combinations that are not supported by the test applications
 * (e.g. SGL algorithms).
 *
 * @param [in] c_mode    Cipher mode
 * @param [in] hash_alg  Hash algorithm
 *
 * @return Combination status
 * @retval 1 combination is valid
 * @retval 0 combination is not valid
 */
int
is_valid_combination(const IMB_CIPHER_MODE c_mode, const IMB_HASH_ALG hash_alg);

/**
 * @brief Checks if a message size can be used with the selected algorithms
 *
 * Filters out sizes that are not a multiple of the cipher block size
 * and sizes that are too small for the selected hash algorithm.
 *
 * @param [in] params    Pointer to the test parameters
 * @param [in] buf_size  Message size in bytes
 *
 * @return Message size status
 * @retval 1 size is valid
 * @retval 0 size is not valid
 */
int
is_valid_job_size(const struct params_s *params, const uint32_t buf_size);

/**
 * @brief Produces a random message size for IMIX (mixed size) tests
 *
 * The returned size meets the cipher block size and hash algorithm
 * requirements checked by is_valid_job_size().
 *
 * @param [in] params    Pointer to the test parameters
 * @param [in] max_size  Maximum message size in bytes
 *
 * @return Random message size in bytes
 *
 * @see is_valid_job_size()
 */
uint32_t
generate_imix_job_size(const struct params_s *params, const uint32_t max_size);

/**
 * @brief Returns the maximum AAD size to be tested for the selected algorithms
 *
 * Only AES-GCM and AES-CCM take additional authenticated data,
 * zero is returned for all the other algorithms.
 *
 * @param [in] params  Pointer to the test parameters
 *
 * @return Maximum AAD size in bytes
 */
uint32_t
get_max_aad_size(const struct params_s *params);

/**
 * @brief Fills in the list of authentication tag sizes to be tested
 *
 * A single tag size is used by most of the algorithms. AES-CCM supports
 * a range of tag sizes, so all of them get tested.
 * If the tag size has been selected by the user then only that size
 * is returned.
 *
 * @param [in] params      Pointer to the test parameters
 * @param [out] tag_sizes  Array of NUM_TAG_SIZES entries to fill in
 *
 * @return Number of tag sizes filled in
 *
 * @see auth_tag_size
 */
unsigned
get_tag_sizes(const struct params_s *params, uint8_t tag_sizes[NUM_TAG_SIZES]);

/**
 * @brief Reads a numeric command line argument
 *
 * Converts argument at \a index + 1 and stores it at \a dst.
 * Exits the application with EXIT_FAILURE on a missing or invalid argument.
 *
 * @param [in] argv      Array of command line arguments
 * @param [in] index     Index of the option the argument belongs to
 * @param [in] argc      Number of command line arguments
 * @param [out] dst      Pointer to the location to store the value at
 * @param [in] dst_size  Size of the destination in bytes,
 *                       1, 2, 4 or 8 bytes are supported
 *
 * @return Index of the last consumed argument (\a index + 1)
 */
int
get_next_num_arg(const char *const *argv, const int index, const int argc, void *dst,
                 const size_t dst_size);

/**
 * @brief Looks up a string command line argument in a name to value mapping
 *
 * The list of accepted arguments is printed on the standard error
 * output if the argument is missing or not supported.
 *
 * @param [in] param           Name of the option, used in error messages
 * @param [in] arg             Argument to look up
 * @param [in] map             Array of name to value mappings
 * @param [in] num_avail_opts  Number of entries in \a map
 *
 * @return Pointer to the values associated with \a arg
 * @retval NULL argument is missing or not supported
 */
const union params *
check_string_arg(const char *param, const char *arg, const struct str_value_mapping *map,
                 const size_t num_avail_opts);

/**
 * @brief Reads a message size range command line argument
 *
 * The argument is expected in the min:step:max format.
 * If it cannot be parsed as a range then it is read as a single value
 * and both minimum and maximum are set to it.
 * Exits the application with EXIT_FAILURE on a missing or invalid argument.
 *
 * @param [in] argv           Array of command line arguments
 * @param [in] index          Index of the option the argument belongs to
 * @param [in] argc           Number of command line arguments
 * @param [out] range_values  Array to store minimum, step and maximum values in
 *
 * @return Index of the last consumed argument (\a index + 1)
 */
int
parse_range(const char *const *argv, const int index, const int argc,
            uint32_t range_values[NUM_RANGE]);

#endif /* TESTAPP_JOB_UTILS_H */
