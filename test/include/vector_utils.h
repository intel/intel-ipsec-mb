/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_VECTOR_UTILS_H
#define TESTAPP_VECTOR_UTILS_H

#include <stddef.h>

/**
 * @brief Chained cipher + MAC test vector (ChainedCipherMacTest schema).
 *
 * Optional fields (cipherIv, macKey, macIv) are NULL with size 0 when not
 * present in the JSON file. The array is terminated by an entry with
 * msg == NULL.
 */
struct chained_test {
        size_t cipherKeySize; /* bits */
        size_t cipherIvSize;  /* bits */
        size_t macKeySize;    /* bits */
        size_t macIvSize;     /* bits */
        size_t tagSize;       /* bits */
        size_t msgSize;       /* bits */
        size_t tcId;
        const char *cipherAlg; /* group-level cipher algorithm name */
        const char *macAlg;    /* group-level MAC algorithm name */
        const char *order;     /* "hash_cipher" or "cipher_hash" */
        const char *cipherKey;
        const char *cipherIv;
        const char *macKey;
        const char *macIv;
        const char *msg;
        const char *ct;
        const char *tag;
        int resultValid;
};

struct mac_test;
struct cipher_test;
struct aead_test;
struct sig_sign_test;
struct sig_verify_test;
struct kem_test;
struct test_json_alloc_ctx;

/**
 * @brief Load vectors from a MAC-format JSON file into a sentinel-terminated
 *        struct mac_test array.
 *
 * @param [in] path path to vector JSON file
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
json_load_mac_test(const char *path, struct mac_test **out_vectors,
                   struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load vectors from a CIPHER-format JSON file into a
 *        sentinel-terminated struct cipher_test array.
 *
 * @param [in] path path to vector JSON file
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
json_load_cipher_test(const char *path, struct cipher_test **out_vectors,
                      struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load vectors from an AEAD-format JSON file into a
 *        sentinel-terminated struct aead_test array.
 *
 * @param [in] path path to vector JSON file
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
json_load_aead_test(const char *path, struct aead_test **out_vectors,
                    struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load vectors from a signature-scheme sign-format JSON file into a
 *        sentinel-terminated struct sig_sign_test array.
 *
 * @param [in] path path to vector JSON file
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
json_load_sig_sign_test(const char *path, struct sig_sign_test **out_vectors,
                        struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load vectors from a signature-scheme verify-format JSON file into a
 *        sentinel-terminated struct sig_verify_test array.
 *
 * @param [in] path path to vector JSON file
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
json_load_sig_verify_test(const char *path, struct sig_verify_test **out_vectors,
                          struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load vectors from a KEM-format JSON file (any of the four ML-KEM
 *        Wycheproof vector schema families - see kem_test.h) into a
 *        sentinel-terminated struct kem_test array.
 *
 * @param [in] path path to vector JSON file
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
json_load_kem_test(const char *path, struct kem_test **out_vectors,
                   struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load vectors from a chained cipher + MAC JSON file into a
 *        sentinel-terminated struct chained_test array.
 *
 * @param [in] path path to vector JSON file
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
json_load_chained_test(const char *path, struct chained_test **out_vectors,
                       struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Free vector data created by json_load_mac_test() or
 *        json_load_cipher_test() or json_load_aead_test() or
 *        json_load_sig_sign_test() or json_load_sig_verify_test() or
 *        json_load_kem_test() or json_load_chained_test().
 */
void
json_free_test_ctx(struct test_json_alloc_ctx *ctx);

/**
 * @brief Load MAC-format vectors from a file in the given vector directory.
 *
 * @param [in] vector_dir directory containing vector files
 * @param [in] file_name  vector file name (not a full path)
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
load_mac_vectors(const char *vector_dir, const char *file_name, struct mac_test **out_vectors,
                 struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load cipher-format vectors from a file in the given vector directory.
 *
 * @param [in] vector_dir directory containing vector files
 * @param [in] file_name  vector file name (not a full path)
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
load_cipher_vectors(const char *vector_dir, const char *file_name, struct cipher_test **out_vectors,
                    struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load AEAD-format vectors from a file in the given vector directory.
 *
 * @param [in] vector_dir directory containing vector files
 * @param [in] file_name  vector file name (not a full path)
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
load_aead_vectors(const char *vector_dir, const char *file_name, struct aead_test **out_vectors,
                  struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load signature-scheme sign-format vectors from a file in the given
 *        vector directory.
 *
 * @param [in] vector_dir directory containing vector files
 * @param [in] file_name  vector file name (not a full path)
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
load_sig_sign_vectors(const char *vector_dir, const char *file_name,
                      struct sig_sign_test **out_vectors, struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load signature-scheme verify-format vectors from a file in the
 *        given vector directory.
 *
 * @param [in] vector_dir directory containing vector files
 * @param [in] file_name  vector file name (not a full path)
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
load_sig_verify_vectors(const char *vector_dir, const char *file_name,
                        struct sig_verify_test **out_vectors, struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load KEM-format vectors from a file in the given vector directory
 *        (any of the four ML-KEM Wycheproof vector schema families - see
 *        kem_test.h).
 *
 * @param [in] vector_dir directory containing vector files
 * @param [in] file_name  vector file name (not a full path)
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
load_kem_vectors(const char *vector_dir, const char *file_name, struct kem_test **out_vectors,
                 struct test_json_alloc_ctx **out_ctx);

/**
 * @brief Load chained cipher + MAC vectors from a file in the given vector
 *        directory.
 *
 * @param [in] vector_dir directory containing vector files
 * @param [in] file_name  vector file name (not a full path)
 * @param [out] out_vectors loaded vectors on success
 * @param [out] out_ctx allocator context to be passed to json_free_test_ctx()
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 error (parse error printed to stderr)
 */
int
load_chained_vectors(const char *vector_dir, const char *file_name,
                     struct chained_test **out_vectors, struct test_json_alloc_ctx **out_ctx);

#endif /* TESTAPP_VECTOR_UTILS_H */
