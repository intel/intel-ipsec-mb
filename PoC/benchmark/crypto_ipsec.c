/*
 * Copyright (c) 2017 Deadcafe Beef(deadcafe.beef@gmail.com)
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

#include <stdio.h>
#include <stdlib.h>

#include "crypto_ipsec.h"

const unsigned auth_alg_icv_len[] = {
        [SHA1]        = 12,
        [SHA_256]     = 16,
        [SHA_384]     = 24,
        [SHA_512]     = 32,
        [AES_XCBC]    = 12,
        [NULL_HASH]   = 0,
        [GMAC_AES]    = 16,
};

/*
 * keys for test
 */
static union auth_exp_key auth_key_hmac_sha1   __attribute__((aligned(16)));
static union auth_exp_key auth_key_hmac_sha256 __attribute__((aligned(16)));
static union auth_exp_key auth_key_hmac_sha384 __attribute__((aligned(16)));
static union auth_exp_key auth_key_hmac_sha512 __attribute__((aligned(16)));
static union auth_exp_key auth_key_xcbc        __attribute__((aligned(16)));

static union auth_exp_key auth_key_gmac128     __attribute__((aligned(16)));
static union auth_exp_key auth_key_gmac192     __attribute__((aligned(16)));
static union auth_exp_key auth_key_gmac256     __attribute__((aligned(16)));

static struct aes_exp_key cipher_key_aes128_enc __attribute__((aligned(16)));
static struct aes_exp_key cipher_key_aes128_dec __attribute__((aligned(16)));
static struct aes_exp_key cipher_key_aes192_enc __attribute__((aligned(16)));

static struct aes_exp_key cipher_key_aes192_dec __attribute__((aligned(16)));
static struct aes_exp_key cipher_key_aes256_enc __attribute__((aligned(16)));
static struct aes_exp_key cipher_key_aes256_dec __attribute__((aligned(16)));

#define	ENABLE_CBC
#define	ENABLE_CTR
#define	ENABLE_GCM
#define ENABLE_CIPHER_NULL
#define ENABLE_AUTH_NULL

const struct crypto_attr_s crypto_attr[] = {

        /******************************************************************/
        /* CBC */
#ifdef ENABLE_CBC
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA1,
                .auth_key_len   = SHA1_DIGEST_SIZE,
                .tag_len        = HMAC_SHA1_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_dec,
                .auth_key       = &auth_key_hmac_sha1,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA1,
                .auth_key_len   = SHA1_DIGEST_SIZE,
                .tag_len        = HMAC_SHA1_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_dec,
                .auth_key       = &auth_key_hmac_sha1,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA1,
                .auth_key_len   = SHA1_DIGEST_SIZE,
                .tag_len        = HMAC_SHA1_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_dec,
                .auth_key       = &auth_key_hmac_sha1,
        },

        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_256,
                .auth_key_len   = SHA_256_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_256_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_dec,
                .auth_key       = &auth_key_hmac_sha256,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_256,
                .auth_key_len   = SHA_256_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_256_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_dec,
                .auth_key       = &auth_key_hmac_sha256,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_256,
                .auth_key_len   = SHA_256_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_256_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_dec,
                .auth_key       = &auth_key_hmac_sha256,
        },

        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_384,
                .auth_key_len   = SHA_384_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_384_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_dec,
                .auth_key       = &auth_key_hmac_sha384,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_384,
                .auth_key_len   = SHA_384_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_384_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_dec,
                .auth_key       = &auth_key_hmac_sha384,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_384,
                .auth_key_len   = SHA_384_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_384_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_dec,
                .auth_key       = &auth_key_hmac_sha384,
        },

        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_512,
                .auth_key_len   = SHA_512_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_512_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_dec,
                .auth_key       = &auth_key_hmac_sha512,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_512,
                .auth_key_len   = SHA_512_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_512_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_dec,
                .auth_key       = &auth_key_hmac_sha512,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = SHA_512,
                .auth_key_len   = SHA_512_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_512_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_dec,
                .auth_key       = &auth_key_hmac_sha512,
        },

        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = AES_XCBC,
                .auth_key_len   = AES_128_BYTES,
                .tag_len        = AES_XCBC_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_dec,
                .auth_key       = &auth_key_xcbc,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = AES_XCBC,
                .auth_key_len   = AES_128_BYTES,
                .tag_len        = AES_XCBC_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_dec,
                .auth_key       = &auth_key_xcbc,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = AES_XCBC,
                .auth_key_len   = AES_128_BYTES,
                .tag_len        = AES_XCBC_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_dec,
                .auth_key       = &auth_key_xcbc,
        },

#ifdef ENABLE_AUTH_NULL
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = NULL_HASH,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_dec,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = NULL_HASH,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_dec,
        },
        {
                .cipher_mode    = CBC,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CBC_BLOCK_SIZE,
                .iv_len         = 16,
                .hash_alg       = NULL_HASH,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_dec,
        },
#endif	/* ENABLE_AUTH_NULL */
#endif	/* ENABLE_CBC */

#ifdef ENABLE_CTR
        /* CTR */
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA1,
                .auth_key_len   = SHA1_DIGEST_SIZE,
                .tag_len        = HMAC_SHA1_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_enc,
                .auth_key       = &auth_key_hmac_sha1,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA1,
                .auth_key_len   = SHA1_DIGEST_SIZE,
                .tag_len        = HMAC_SHA1_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_enc,
                .auth_key       = &auth_key_hmac_sha1,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA1,
                .auth_key_len   = SHA1_DIGEST_SIZE,
                .tag_len        = HMAC_SHA1_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_enc,
                .auth_key       = &auth_key_hmac_sha1,
        },

        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_256,
                .auth_key_len   = SHA_256_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_256_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_enc,
                .auth_key       = &auth_key_hmac_sha256,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_256,
                .auth_key_len   = SHA_256_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_256_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_enc,
                .auth_key       = &auth_key_hmac_sha256,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_256,
                .auth_key_len   = SHA_256_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_256_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_enc,
                .auth_key       = &auth_key_hmac_sha256,
        },

        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_384,
                .auth_key_len   = SHA_384_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_384_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_enc,
                .auth_key       = &auth_key_hmac_sha384,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_384,
                .auth_key_len   = SHA_384_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_384_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_enc,
                .auth_key       = &auth_key_hmac_sha384,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_384,
                .auth_key_len   = SHA_384_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_384_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_enc,
                .auth_key       = &auth_key_hmac_sha384,
        },

        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_512,
                .auth_key_len   = SHA_512_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_512_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_enc,
                .auth_key       = &auth_key_hmac_sha512,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_512,
                .auth_key_len   = SHA_512_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_512_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_enc,
                .auth_key       = &auth_key_hmac_sha512,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = SHA_512,
                .auth_key_len   = SHA_512_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_512_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_enc,
                .auth_key       = &auth_key_hmac_sha512,
        },

        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = AES_XCBC,
                .auth_key_len   = AES_128_BYTES,
                .tag_len        = AES_XCBC_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_enc,
                .auth_key       = &auth_key_xcbc,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = AES_XCBC,
                .auth_key_len   = AES_128_BYTES,
                .tag_len        = AES_XCBC_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_enc,
                .auth_key       = &auth_key_xcbc,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = AES_XCBC,
                .auth_key_len   = AES_128_BYTES,
                .tag_len        = AES_XCBC_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_enc,
                .auth_key       = &auth_key_xcbc,
        },

#ifdef ENABLE_AUTH_NULL
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = NULL_HASH,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_enc,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = NULL_HASH,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_enc,
        },
        {
                .cipher_mode    = CNTR,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_CTR_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = NULL_HASH,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_enc,
        },
#endif	/* ENABLE_AUTH_NULL */
#endif	/* ENABLE_CTR */

#ifdef ENABLE_GCM

        /* GCM */
        {
                .cipher_mode    = GCM,
                .cipher_key_len = AES_128_BYTES,
                .block_size     = CIPHER_AES_GCM_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = GMAC_AES,
                .tag_len        = GMAC_TAG_SIZE,
                .enc_key        = &cipher_key_aes128_enc,
                .dec_key        = &cipher_key_aes128_enc,
                .auth_key       = &auth_key_gmac128,
        },
        {
                .cipher_mode    = GCM,
                .cipher_key_len = AES_192_BYTES,
                .block_size     = CIPHER_AES_GCM_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = GMAC_AES,
                .tag_len        = GMAC_TAG_SIZE,
                .enc_key        = &cipher_key_aes192_enc,
                .dec_key        = &cipher_key_aes192_enc,
                .auth_key       = &auth_key_gmac192,
        },
        {
                .cipher_mode    = GCM,
                .cipher_key_len = AES_256_BYTES,
                .block_size     = CIPHER_AES_GCM_BLOCK_SIZE,
                .iv_len         = 8,
                .hash_alg       = GMAC_AES,
                .tag_len        = GMAC_TAG_SIZE,
                .enc_key        = &cipher_key_aes256_enc,
                .dec_key        = &cipher_key_aes256_enc,
                .auth_key       = &auth_key_gmac256,
        },
#endif	/* ENABLE_GCM */

#ifdef	ENABLE_CIPHER_NULL
        /* NULL */
        {
                .cipher_mode    = NULL_CIPHER,
                .block_size     = CIPHER_NULL_BLOCK_SIZE,
                .hash_alg       = SHA1,
                .auth_key_len   = SHA1_DIGEST_SIZE,
                .tag_len        = HMAC_SHA1_TAG_SIZE,
                .auth_key       = &auth_key_hmac_sha1,
        },
        {
                .cipher_mode    = NULL_CIPHER,
                .block_size     = CIPHER_NULL_BLOCK_SIZE,
                .hash_alg       = SHA_256,
                .auth_key_len   = SHA_256_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_256_TAG_SIZE,
                .auth_key       = &auth_key_hmac_sha256,
        },
        {
                .cipher_mode    = NULL_CIPHER,
                .block_size     = CIPHER_NULL_BLOCK_SIZE,
                .hash_alg       = SHA_384,
                .auth_key_len   = SHA_384_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_384_TAG_SIZE,
                .auth_key       = &auth_key_hmac_sha384,
        },
        {
                .cipher_mode    = NULL_CIPHER,
                .block_size     = CIPHER_NULL_BLOCK_SIZE,
                .hash_alg       = SHA_512,
                .auth_key_len   = SHA_512_DIGEST_SIZE,
                .tag_len        = HMAC_SHA_512_TAG_SIZE,
                .auth_key       = &auth_key_hmac_sha512,
        },
        {
                .cipher_mode    = NULL_CIPHER,
                .block_size     = CIPHER_NULL_BLOCK_SIZE,
                .hash_alg       = AES_XCBC,
                .auth_key_len   = AES128_KEY_SIZE,
                .tag_len        = AES_XCBC_TAG_SIZE,
                .auth_key       = &auth_key_xcbc,
        },

#ifdef ENABLE_AUTH_NULL
        {
                .cipher_mode    = NULL_CIPHER,
                .block_size     = CIPHER_NULL_BLOCK_SIZE,
                .hash_alg       = NULL_HASH,
        },
#endif	/* ENABLE_AUTH_NULL */
#endif	/* ENABLE_CIPHER_NULL */
};

unsigned
arrayof_crypto_attr(void)
{
        return ARRAYOF(crypto_attr);
}

void
init_key(void)
{
        uint8_t cipher_key[32] = {
                0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        };
        uint8_t auth_key[64];

        /*
         * initialize AES keys
         */
        AES128_key_expand(cipher_key, &cipher_key_aes128_enc, &cipher_key_aes128_dec);
        AES192_key_expand(cipher_key, &cipher_key_aes192_enc, &cipher_key_aes192_dec);
        AES256_key_expand(cipher_key, &cipher_key_aes256_enc, &cipher_key_aes256_dec);

        HMAC_SHA1_key_expand(auth_key,   SHA1_DIGEST_SIZE,    &auth_key_hmac_sha1.hmac);
        HMAC_SHA256_key_expand(auth_key, SHA_256_DIGEST_SIZE, &auth_key_hmac_sha256.hmac);
        HMAC_SHA384_key_expand(auth_key, SHA_384_DIGEST_SIZE, &auth_key_hmac_sha384.hmac);
        HMAC_SHA512_key_expand(auth_key, SHA_512_DIGEST_SIZE, &auth_key_hmac_sha512.hmac);
        XCBC_AES128_key_expand(auth_key, &auth_key_xcbc.xcbc);

        GMAC_AES128_key_expand(&cipher_key_aes128_enc, &auth_key_gmac128.gmac);
        GMAC_AES192_key_expand(&cipher_key_aes192_enc, &auth_key_gmac192.gmac);
        GMAC_AES256_key_expand(&cipher_key_aes256_enc, &auth_key_gmac256.gmac);
}
