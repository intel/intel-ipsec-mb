/*
 * Copyright (c) 2012-2016, Intel Corporation
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

#ifndef _AUX_FUNCS_H_
#define _AUX_FUNCS_H_

void sha1_one_block_sse(const void *data, void *digest);
void sha224_one_block_sse(const void *data, void *digest);
void sha256_one_block_sse(const void *data, void *digest);
void sha384_one_block_sse(const void *data, void *digest);
void sha512_one_block_sse(const void *data, void *digest);
void md5_one_block_sse(const void *data, void *digest);

void aes_keyexp_128_sse(const void *key,
                        void *enc_exp_keys,
                        void *dec_exp_keys);

void aes_keyexp_192_sse(const void *key,
                        void *enc_exp_keys,
                        void *dec_exp_keys);

void aes_keyexp_256_sse(const void *key,
                        void *enc_exp_keys,
                        void *dec_exp_keys);

void aes_xcbc_expand_key_sse(const void *key,
                             void *k1_exp,
                             void *k2,
                             void *k3);

void aes_keyexp_128_enc_sse(const void *key, void *enc_exp_keys);
void aes_keyexp_192_enc_sse(const void *key, void *enc_exp_keys);
void aes_keyexp_256_enc_sse(const void *key, void *enc_exp_keys);

void aes_ecbenc_128_sse(const void *in, const void *enc_exp_keys, void *out);
void aes_ecbenc_192_sse(const void *in, const void *enc_exp_keys, void *out);
void aes_ecbenc_256_sse(const void *in, const void *enc_exp_keys, void *out);

////////////////////////////////////////////////////////////////////////

void sha1_one_block_avx(const void *data, void *digest);
void sha224_one_block_avx(const void *data, void *digest);
void sha256_one_block_avx(const void *data, void *digest);
void sha384_one_block_avx(const void *data, void *digest);
void sha512_one_block_avx(const void *data, void *digest);
#define md5_one_block_avx       md5_one_block_sse

void aes_keyexp_128_avx(const void *key,
                        void *enc_exp_keys,
                        void *dec_exp_keys);

void aes_keyexp_192_avx(const void *key,
                        void *enc_exp_keys,
                        void *dec_exp_keys);

void aes_keyexp_256_avx(const void *key,
                        void *enc_exp_keys,
                        void *dec_exp_keys);

void aes_xcbc_expand_key_avx(const void *key,
                             void *k1_exp,
                             void *k2,
                             void *k3);

void aes_keyexp_128_enc_avx(const void *key, void *enc_exp_keys);
void aes_keyexp_192_enc_avx(const void *key, void *enc_exp_keys);
void aes_keyexp_256_enc_avx(const void *key, void *enc_exp_keys);

void aes_ecbenc_128_avx(const void *in, const void *enc_exp_keys, void *out);
void aes_ecbenc_192_avx(const void *in, const void *enc_exp_keys, void *out);
void aes_ecbenc_256_avx(const void *in, const void *enc_exp_keys, void *out);

////////////////////////////////////////////////////////////////////////

#define sha1_one_block_avx2      sha1_one_block_avx
#define sha224_one_block_avx2    sha224_one_block_avx
#define sha256_one_block_avx2    sha256_one_block_avx
#define sha384_one_block_avx2    sha384_one_block_avx
#define sha512_one_block_avx2    sha512_one_block_avx
#define md5_one_block_avx2       md5_one_block_avx
#define aes_keyexp_128_avx2      aes_keyexp_128_avx
#define aes_keyexp_192_avx2      aes_keyexp_192_avx
#define aes_keyexp_256_avx2      aes_keyexp_256_avx
#define aes_xcbc_expand_key_avx2 aes_xcbc_expand_key_avx
#define aes_keyexp_128_enc_avx2  aes_keyexp_128_enc_avx
#define aes_keyexp_192_enc_avx2  aes_keyexp_192_enc_avx
#define aes_keyexp_256_enc_avx2  aes_keyexp_256_enc_avx
#define aes_ecbenc_128_avx2	 aes_ecbenc_128_avx
#define aes_ecbenc_192_avx2	 aes_ecbenc_192_avx
#define aes_ecbenc_256_avx2	 aes_ecbenc_256_avx

#define sha1_one_block_avx512      sha1_one_block_avx2
#define sha224_one_block_avx512    sha224_one_block_avx2
#define sha256_one_block_avx512    sha256_one_block_avx2
#define sha384_one_block_avx512    sha384_one_block_avx2
#define sha512_one_block_avx512    sha512_one_block_avx2
#define md5_one_block_avx512       md5_one_block_avx2
#define aes_keyexp_128_avx512      aes_keyexp_128_avx2
#define aes_keyexp_192_avx512      aes_keyexp_192_avx2
#define aes_keyexp_256_avx512      aes_keyexp_256_avx2
#define aes_xcbc_expand_key_avx512 aes_xcbc_expand_key_avx2
#define aes_keyexp_128_enc_avx512  aes_keyexp_128_enc_avx2
#define aes_keyexp_192_enc_avx512  aes_keyexp_192_enc_avx2
#define aes_keyexp_256_enc_avx512  aes_keyexp_256_enc_avx2
#define aes_ecbenc_128_avx512	   aes_ecbenc_128_avx2
#define aes_ecbenc_192_avx512	   aes_ecbenc_192_avx2
#define aes_ecbenc_256_avx512	   aes_ecbenc_256_avx2

#endif /* !_AUX_FUNCS_H_ */
