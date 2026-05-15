/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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
*****************************************************************************/

#ifndef TESTAPP_VECTOR_UTILS_H
#define TESTAPP_VECTOR_UTILS_H

struct mac_test;
struct cipher_test;
struct aead_test;
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
 * @brief Free vector data created by json_load_mac_test() or
 *        json_load_cipher_test() or json_load_aead_test().
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

#endif /* TESTAPP_VECTOR_UTILS_H */
