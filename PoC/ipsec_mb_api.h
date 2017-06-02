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

#ifndef _IPSEC_MB_API_H_
#define _IPSEC_MB_API_H_

#include "ipsec_mb_types.h"

/*
 * key expander
 */
extern void HMAC_SHA1_key_expand(const void *raw, unsigned len,
                                 struct hmac_exp_key *hkey);
extern void HMAC_SHA224_key_expand(const void *raw, unsigned len,
                                   struct hmac_exp_key *hkey);
extern void HMAC_SHA256_key_expand(const void *raw, unsigned len,
                                   struct hmac_exp_key *hkey);
extern void HMAC_SHA384_key_expand(const void *raw, unsigned len,
                                   struct hmac_exp_key *hkey);
extern void HMAC_SHA512_key_expand(const void *raw, unsigned len,
                                   struct hmac_exp_key *hkey);
extern void HMAC_MD5_key_expand(const void *raw, unsigned len,
                                struct hmac_exp_key *hkey);
extern void GMAC_AES128_key_expand(const struct aes_exp_key *enc,
                                   struct gmac_exp_key *ekey);
extern void GMAC_AES192_key_expand(const struct aes_exp_key *enc,
                                   struct gmac_exp_key *ekey);
extern void GMAC_AES256_key_expand(const struct aes_exp_key *enc,
                                   struct gmac_exp_key *ekey);
extern void XCBC_AES128_key_expand(const void *raw, struct xcbc_exp_key *xcbc);

extern void AES128_key_expand(const void *raw,
                              struct aes_exp_key *enc,
                              struct aes_exp_key *dec);
extern void AES192_key_expand(const void *raw,
                              struct aes_exp_key *enc,
                              struct aes_exp_key *dec);
extern void AES256_key_expand(const void *raw,
                              struct aes_exp_key *enc,
                              struct aes_exp_key *dec);
extern void AES128_enckey_expand(const void *raw,
                                 struct aes_exp_key *enc);
extern void AES192_enckey_expand(const void *raw,
                                 struct aes_exp_key *enc);
extern void AES256_enckey_expand(const void *raw,
                                 struct aes_exp_key *enc);
extern void SHA1_one_block(const void *data,
                           void *digest);
extern void SHA224_one_block(const void *data,
                             void *digest);
extern void SHA256_one_block(const void *data,
                             void *digest);
extern void SHA384_one_block(const void *data,
                             void *digest);
extern void SHA512_one_block(const void *data,
                             void *digest);
extern void MD5_one_block(const void *data,
                          void *digest);
extern void AES128_ecbenc_x3(const void *in,
                             const struct aes_exp_key *enc_ekey,
                             UINT128 *out1,
                             UINT128 *out2,
                             UINT128 *out3);
extern void AES128_cbc_dec(const void *src,
                           const union AES_IV *iv,
                           const struct aes_exp_key *k,
                           void *dst,
                           UINT64 len);
extern void AES192_cbc_dec(const void *src,
                           const union AES_IV *iv,
                           const struct aes_exp_key *k,
                           void *dst,
                           UINT64 len);
extern void AES256_cbc_dec(const void *src,
                           const union AES_IV *iv,
                           const struct aes_exp_key *k,
                           void *dst,
                           UINT64 len);
extern void AES128_ctr(const void *src,
                       const union AES_IV *iv,
                       const struct aes_exp_key *k,
                       void *dst,
                       UINT64 len);
extern void AES192_ctr(const void *src,
                       const union AES_IV *iv,
                       const struct aes_exp_key *k,
                       void *dst,
                       UINT64 len);
extern void AES256_ctr(const void *src,
                       const union AES_IV *iv,
                       const struct aes_exp_key *k,
                       void *dst,
                       UINT64 len);
extern void AES128_gcm_enc(const struct aes_exp_key *ekey,
                           const struct gmac_exp_key *gkey,
                           void *out, const void *in, UINT64 len,
                           const union AES_IV *iv,
                           const void *aad, UINT64 aad_len,
                           void *tag, UINT64 tag_len);
extern void AES128_gcm_dec(const struct aes_exp_key *ekey,
                           const struct gmac_exp_key *gkey,
                           void *out, const void *in, UINT64 len,
                           const union AES_IV *iv,
                           const void *aad, UINT64 aad_len,
                           void *tag, UINT64 tag_len);
extern void AES192_gcm_enc(const struct aes_exp_key *ekey,
                           const struct gmac_exp_key *gkey,
                           void *out, const void *in, UINT64 len,
                           const union AES_IV *iv,
                           const void *aad, UINT64 aad_len,
                           void *tag, UINT64 tag_len);
extern void AES192_gcm_dec(const struct aes_exp_key *ekey,
                           const struct gmac_exp_key *gkey,
                           void *out, const void *in, UINT64 len,
                           const union AES_IV *iv,
                           const void *aad, UINT64 aad_len,
                           void *tag, UINT64 tag_len);
extern void AES256_gcm_enc(const struct aes_exp_key *ekey,
                           const struct gmac_exp_key *gkey,
                           void *out, const void *in, UINT64 len,
                           const union AES_IV *iv,
                           const void *aad, UINT64 aad_len,
                           void *tag, UINT64 tag_len);
extern void AES256_gcm_dec(const struct aes_exp_key *ekey,
                           const struct gmac_exp_key *gkey,
                           void *out, const void *in, UINT64 len,
                           const union AES_IV *iv,
                           const void *aad, UINT64 aad_len,
                           void *tag, UINT64 tag_len);
extern void AES128_cfb_one(void *dst,
                           const void *src,
                           const union AES_IV *iv,
                           const struct aes_exp_key *ekey,
                           UINT64 len);

/******************************************************************************
 * Private Functions in IPsec_MB
 ******************************************************************************/
extern void init_aes_ooo(struct MB_MGR_AES_OOO *state);
extern void init_xcbc_ooo(struct MB_MGR_AES_XCBC_OOO *state);
extern void init_sha1_ooo(struct MB_MGR_HMAC_SHA1_OOO *state);
extern void init_sha224_ooo(struct MB_MGR_HMAC_SHA256_OOO *state);
extern void init_sha256_ooo(struct MB_MGR_HMAC_SHA256_OOO *state);
extern void init_sha384_ooo(struct MB_MGR_HMAC_SHA512_OOO *state);
extern void init_sha512_ooo(struct MB_MGR_HMAC_SHA512_OOO *state);
extern void init_md5_ooo(struct MB_MGR_HMAC_MD5_OOO *state);
extern void AES128_cbc_enc(struct AES_ARGS_x8 *args,
                           UINT64 len_in_bytes);
extern void AES192_cbc_enc(struct AES_ARGS_x8 *args,
                           UINT64 len_in_bytes);
extern void AES256_cbc_enc(struct AES_ARGS_x8 *args,
                           UINT64 len_in_bytes);
extern struct JOB_AES_HMAC *JOB_SUBMIT_aes128_cbc_enc(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_aes128_cbc_enc(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_aes192_cbc_enc(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_aes192_cbc_enc(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_aes256_cbc_enc(struct MB_MGR_AES_OOO *state,
                                                      struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_aes256_cbc_enc(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_sha1(struct MB_MGR_HMAC_SHA1_OOO *state,
                                            struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_flush_sha1(struct MB_MGR_HMAC_SHA1_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_sha224(struct MB_MGR_HMAC_SHA256_OOO *state,
                                              struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_sha224(struct MB_MGR_HMAC_SHA256_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_sha256(struct MB_MGR_HMAC_SHA256_OOO *state,
                                              struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_sha256(struct MB_MGR_HMAC_SHA256_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_sha384(struct MB_MGR_HMAC_SHA512_OOO *state,
                                              struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_sha384(struct MB_MGR_HMAC_SHA512_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_sha512(struct MB_MGR_HMAC_SHA512_OOO *state,
                                              struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_sha512(struct MB_MGR_HMAC_SHA512_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_md5(struct MB_MGR_HMAC_MD5_OOO *state,
                                           struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_md5(struct MB_MGR_HMAC_MD5_OOO *state);
extern struct JOB_AES_HMAC *JOB_SUBMIT_aes_xcbc(struct MB_MGR_AES_XCBC_OOO *state,
                                                struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *JOB_FLUSH_aes_xcbc(struct MB_MGR_AES_XCBC_OOO *state);

#endif	/* !_IPSEC_MB_API_H_ */
