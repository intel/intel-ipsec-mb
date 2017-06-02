/*
 * Copyright (c) 2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Author: Shuzo Ichiyoshi
 */

#ifndef _IPSEC_MB_ASM_H_
#define _IPSEC_MB_ASM_H_

struct gcm_data;

/* SSE */
extern void aes_cbc_enc_128_x4(struct AES_ARGS_x8 *args, UINT64 len_in_bytes);
extern void aes_cbc_enc_192_x4(struct AES_ARGS_x8 *args, UINT64 len_in_bytes);
extern void aes_cbc_enc_256_x4(struct AES_ARGS_x8 *args, UINT64 len_in_bytes);
extern void aes128_ecbenc_x3_sse(const void *in, const struct aes_exp_key *enc_ekey,
                                 UINT128 *out1, UINT128 *out2, UINT128 *out3);
extern struct JOB_AES_HMAC *submit_job_aes128_enc_sse(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_aes192_enc_sse(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_aes256_enc_sse(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sse(struct MB_MGR_HMAC_SHA1_OOO *state,
                                                struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_ni_sse(struct MB_MGR_HMAC_SHA1_OOO *state,
                                                   struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_224_sse(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_224_ni_sse(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                           struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_256_sse(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_256_ni_sse(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                           struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_384_sse(struct MB_MGR_HMAC_SHA512_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_512_sse(struct MB_MGR_HMAC_SHA512_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_md5_sse(struct MB_MGR_HMAC_MD5_OOO *state,
                                                    struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_aes_xcbc_sse(struct MB_MGR_AES_XCBC_OOO *state,
                                                    struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *flush_job_aes128_enc_sse(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *flush_job_aes192_enc_sse(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *flush_job_aes256_enc_sse(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sse(struct MB_MGR_HMAC_SHA1_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_224_sse(struct MB_MGR_HMAC_SHA256_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_256_sse(struct MB_MGR_HMAC_SHA256_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_384_sse(struct MB_MGR_HMAC_SHA512_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_512_sse(struct MB_MGR_HMAC_SHA512_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_md5_sse(struct MB_MGR_HMAC_MD5_OOO *state);
extern struct JOB_AES_HMAC *flush_job_aes_xcbc_sse(struct MB_MGR_AES_XCBC_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_ni_sse(struct MB_MGR_HMAC_SHA1_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_224_ni_sse(struct MB_MGR_HMAC_SHA256_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_256_ni_sse(struct MB_MGR_HMAC_SHA256_OOO *state);
extern void sha1_one_block_sse(const void *data, void *digest);
extern void sha224_one_block_sse(const void *data, void *digest);
extern void sha256_one_block_sse(const void *data, void *digest);
extern void sha384_one_block_sse(const void *data, void *digest);
extern void sha512_one_block_sse(const void *data, void *digest);
extern void md5_one_block_sse(const void *data, void *digest);
extern void aes_xcbc_expand_key_sse(const void *key, UINT128 *k1_exp, UINT128 *k2, UINT128 *k3);
extern void aes_cfb_128_one_sse(void *out, const void *in, const union AES_IV *iv,
                                const struct aes_exp_key *keys, UINT64 len);
extern void aes_keyexp_128_sse(const void *key,
                               struct aes_exp_key *enc_exp_keys,
                               struct aes_exp_key *dec_exp_keys);
extern void aes_keyexp_192_sse(const void *key,
                               struct aes_exp_key *enc_exp_keys,
                               struct aes_exp_key *dec_exp_keys);
extern void aes_keyexp_256_sse(const void *key,
                               struct aes_exp_key *enc_exp_keys,
                               struct aes_exp_key *dec_exp_keys);
extern void aes_keyexp_128_enc_sse(const void *key, struct aes_exp_key *enc_exp_keys);
extern void aes_keyexp_192_enc_sse(const void *key, struct aes_exp_key *enc_exp_keys);
extern void aes_keyexp_256_enc_sse(const void *key, struct aes_exp_key *enc_exp_keys);
extern void aesni_gcm128_precomp_sse(struct gcm_data *gdata);
extern void aesni_gcm192_precomp_sse(struct gcm_data *gdata);
extern void aesni_gcm256_precomp_sse(struct gcm_data *gdata);

extern void aesni_gcm128_enc_sse(struct gcm_data *gdata,
                                 void *out, const void *in, UINT64 len,
                                 const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                 void *tag, UINT64 tag_len);
extern void aesni_gcm192_enc_sse(struct gcm_data *gdata,
                                 void *out, const void *in, UINT64 len,
                                 const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                 void *tag, UINT64 tag_len);
extern void aesni_gcm256_enc_sse(struct gcm_data *gdata,
                                 void *out, const void *in, UINT64 len,
                                 const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                 void *tag, UINT64 tag_len);
extern void aesni_gcm128_dec_sse(struct gcm_data *gdata,
                                 void *out, const void *in, UINT64 len,
                                 const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                 void *tag, UINT64 tag_len);
extern void aesni_gcm192_dec_sse(struct gcm_data *gdata,
                                 void *out, const void *in, UINT64 len,
                                 const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                 void *tag, UINT64 tag_len);
extern void aesni_gcm256_dec_sse(struct gcm_data *gdata,
                                 void *out, const void *in, UINT64 len,
                                 const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                 void *tag, UINT64 tag_len);
extern void aes_cbc_dec_128_sse(const void *in, const union AES_IV *IV,
                                const struct aes_exp_key *keys,
                                void *out, UINT64 len_bytes);
extern void aes_cbc_dec_192_sse(const void *in, const union AES_IV *IV,
                                const struct aes_exp_key *keys,
                                void *out, UINT64 len_bytes);
extern void aes_cbc_dec_256_sse(const void *in, const union AES_IV *IV,
                                const struct aes_exp_key *keys,
                                void *out, UINT64 len_bytes);
extern void aes_cntr_256_sse(const void *in, const union AES_IV *IV,
                             const struct aes_exp_key *keys,
                             void *out, UINT64 len_bytes);
extern void aes_cntr_192_sse(const void *in, const union AES_IV *IV,
                             const struct aes_exp_key *keys,
                             void *out, UINT64 len_bytes);
extern void aes_cntr_128_sse(const void *in, const union AES_IV *IV,
                             const struct aes_exp_key *keys,
                             void *out, UINT64 len_bytes);
extern void md5_one_block_sse(const void *data, void *digest);


/* AVX */
extern void aes_cbc_enc_128_x8(struct AES_ARGS_x8 *args, UINT64 len_in_bytes);
extern void aes_cbc_enc_192_x8(struct AES_ARGS_x8 *args, UINT64 len_in_bytes);
extern void aes_cbc_enc_256_x8(struct AES_ARGS_x8 *args, UINT64 len_in_bytes);
extern void aes128_ecbenc_x3_avx(const void *in, const struct aes_exp_key *enc_ekey,
                                 UINT128 *out1, UINT128 *out2, UINT128 *out3);
extern struct JOB_AES_HMAC *submit_job_aes128_enc_avx(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_aes192_enc_avx(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_aes256_enc_avx(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_aes_xcbc_avx(struct MB_MGR_AES_XCBC_OOO *state,
                                                    struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_avx(struct MB_MGR_HMAC_SHA1_OOO *state,
                                                struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_224_avx(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_256_avx(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_384_avx(struct MB_MGR_HMAC_SHA512_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_sha_512_avx(struct MB_MGR_HMAC_SHA512_OOO *state,
                                                        struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *submit_job_hmac_md5_avx(struct MB_MGR_HMAC_MD5_OOO *state,
                                                    struct JOB_AES_HMAC * job);
extern struct JOB_AES_HMAC *flush_job_aes128_enc_avx(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *flush_job_aes192_enc_avx(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *flush_job_aes256_enc_avx(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *flush_job_aes_xcbc_avx(struct MB_MGR_AES_XCBC_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_avx(struct MB_MGR_HMAC_SHA1_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_224_avx(struct MB_MGR_HMAC_SHA256_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_256_avx(struct MB_MGR_HMAC_SHA256_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_384_avx(struct MB_MGR_HMAC_SHA512_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_sha_512_avx(struct MB_MGR_HMAC_SHA512_OOO *state);
extern struct JOB_AES_HMAC *flush_job_hmac_md5_avx(struct MB_MGR_HMAC_MD5_OOO *state);
extern void aes_cfb_128_one_avx(void *dst, const void *src, const union AES_IV *iv,
                                const struct aes_exp_key *ekey, UINT64 len);
extern void sha1_one_block_avx(const void *data, void *digest);
extern void sha224_one_block_avx(const void *data, void *digest);
extern void sha256_one_block_avx(const void *data, void *digest);
extern void sha384_one_block_avx(const void *data, void *digest);
extern void sha512_one_block_avx(const void *data, void *digest);
extern void aes_xcbc_expand_key_avx(const void *key,
                                    UINT128 *k1_exp, UINT128 *k2, UINT128 *k3);
extern void aes_keyexp_128_avx(const void *key,
                               struct aes_exp_key *enc_exp_keys,
                               struct aes_exp_key *dec_exp_keys);
extern void aes_keyexp_192_avx(const void *key,
                               struct aes_exp_key *enc_exp_keys,
                               struct aes_exp_key *dec_exp_keys);
extern void aes_keyexp_256_avx(const void *key,
                               struct aes_exp_key *enc_exp_keys,
                               struct aes_exp_key *dec_exp_keys);
extern void aes_keyexp_128_enc_avx(const void *key, struct aes_exp_key *enc_exp_keys);
extern void aes_keyexp_192_enc_avx(const void *key, struct aes_exp_key *enc_exp_keys);
extern void aes_keyexp_256_enc_avx(const void *key, struct aes_exp_key *enc_exp_keys);
extern void aesni_gcm128_precomp_avx_gen2(struct gcm_data *gdata);
extern void aesni_gcm192_precomp_avx_gen2(struct gcm_data *gdata);
extern void aesni_gcm256_precomp_avx_gen2(struct gcm_data *gdata);
extern void aesni_gcm128_enc_avx_gen2(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm192_enc_avx_gen2(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm256_enc_avx_gen2(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm128_dec_avx_gen2(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm192_dec_avx_gen2(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm256_dec_avx_gen2(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aes_cbc_dec_128_avx(const void *in, const union AES_IV *IV,
                                const struct aes_exp_key *keys, void *out, UINT64 len_bytes);
extern void aes_cbc_dec_192_avx(const void *in, const union AES_IV *IV,
                                const struct aes_exp_key *keys, void *out, UINT64 len_bytes);
extern void aes_cbc_dec_256_avx(const void *in, const union AES_IV *IV,
                                const struct aes_exp_key *keys, void *out, UINT64 len_bytes);
extern void aes_cntr_256_avx(const void *in, const union AES_IV *IV,
                             const struct aes_exp_key *keys, void *out, UINT64 len_bytes);
extern void aes_cntr_192_avx(const void *in, const union AES_IV *IV,
                             const struct aes_exp_key *keys, void *out, UINT64 len_bytes);
extern void aes_cntr_128_avx(const void *in, const union AES_IV *IV,
                             const struct aes_exp_key *keys, void *out, UINT64 len_bytes);

/* AVX2 */
struct JOB_AES_HMAC * submit_job_hmac_avx2(struct MB_MGR_HMAC_SHA1_OOO *state,
                                           struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * submit_job_hmac_sha_224_avx2(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                   struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * submit_job_hmac_sha_256_avx2(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                   struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * submit_job_hmac_sha_384_avx2(struct MB_MGR_HMAC_SHA512_OOO *state,
                                                   struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * submit_job_hmac_sha_512_avx2(struct MB_MGR_HMAC_SHA512_OOO *state,
                                                   struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * submit_job_hmac_md5_avx2(struct MB_MGR_HMAC_MD5_OOO *state,
                                               struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * flush_job_hmac_avx2(struct MB_MGR_HMAC_SHA1_OOO *state);
struct JOB_AES_HMAC * flush_job_hmac_sha_224_avx2(struct MB_MGR_HMAC_SHA256_OOO *state);
struct JOB_AES_HMAC * flush_job_hmac_sha_256_avx2(struct MB_MGR_HMAC_SHA256_OOO *state);
struct JOB_AES_HMAC * flush_job_hmac_sha_384_avx2(struct MB_MGR_HMAC_SHA512_OOO *state);
struct JOB_AES_HMAC * flush_job_hmac_sha_512_avx2(struct MB_MGR_HMAC_SHA512_OOO *state);
struct JOB_AES_HMAC * flush_job_hmac_md5_avx2(struct MB_MGR_HMAC_MD5_OOO *state);
extern void aesni_gcm128_precomp_avx_gen4(struct gcm_data *gdata);
extern void aesni_gcm192_precomp_avx_gen4(struct gcm_data *gdata);
extern void aesni_gcm256_precomp_avx_gen4(struct gcm_data *gdata);
extern void aesni_gcm128_enc_avx_gen4(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm192_enc_avx_gen4(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm256_enc_avx_gen4(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm128_dec_avx_gen4(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm192_dec_avx_gen4(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);
extern void aesni_gcm256_dec_avx_gen4(struct gcm_data *gdata,
                                      void *out, const void *in, UINT64 len,
                                      const union AES_IV *iv, const void *aad, UINT64 aad_len,
                                      void *tag, UINT64 tag_len);

/* AVX512 */
struct JOB_AES_HMAC * submit_job_hmac_avx512(struct MB_MGR_HMAC_SHA1_OOO *state,
                                             struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * flush_job_hmac_avx512(struct MB_MGR_HMAC_SHA1_OOO *state);
struct JOB_AES_HMAC * submit_job_hmac_sha_224_avx512(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                     struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * flush_job_hmac_sha_224_avx512(struct MB_MGR_HMAC_SHA256_OOO *state);
struct JOB_AES_HMAC * submit_job_hmac_sha_256_avx512(struct MB_MGR_HMAC_SHA256_OOO *state,
                                                     struct JOB_AES_HMAC * job);
struct JOB_AES_HMAC * flush_job_hmac_sha_256_avx512(struct MB_MGR_HMAC_SHA256_OOO *state);

#endif	/* !_IPSEC_MB_ASM_H_ */
