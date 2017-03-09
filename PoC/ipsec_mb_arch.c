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

#include "ipsec_mb.h"
#include "ipsec_mb_api.h"
#include "ipsec_mb_asm.h"

#if 1
# include <string.h>
# define MEMSET(_p, _c, _s)	memset((_p), (_c), (_s))
# define MEMCPY(_d, _s, _z)	memcpy((_d), (_s), (_z))
#endif

/******************************************************************************
 * GCM context
 ******************************************************************************/
struct gcm_ctx {
        UINT128 aad_hash;
        UINT64 aad_length;
        UINT64 in_length;
        UINT128 partial_block_enc_key;
        union AES_IV orig_IV;
        union AES_IV current_counter;
        UINT64 partial_block_length;
        UINT64 _reserved;
} __packed;

struct gcm_data {
        struct aes_exp_key aes_key;
        struct gmac_exp_key gmac_key;
        struct gcm_ctx ctx;
} __packed;


/******************************************************************************
 * Arch
 ******************************************************************************/
enum VEC_ARCH {
        VEC_ARCH_SSE = 0,
        VEC_ARCH_AVX,
        VEC_ARCH_AVX2,
        VEC_ARCH_AVX512,

        VEC_ARCH_SSE_SHANI,	/* not yet */
        VEC_ARCH_AVX_SHANI,	/* not yet */
        VEC_ARCH_AVX2_SHANI,	/* not yet */
        VEC_ARCH_AVX512_SHANI,	/* not yet */
};

static unsigned CPUID_FLAGS = (1u << CPUID_AESNI) | (1u << CPUID_PCLMULQDQ);
static enum VEC_ARCH VEC_ARCH = VEC_ARCH_SSE;

/******************************************************************************
 *	Number of Width per Arch
 ******************************************************************************/

/* lane bit width: 4 or 8 (0xf or 0xff) */
static const UINT8 aes_lane_widths[] = {
        [VEC_ARCH_SSE]          = 8,
        [VEC_ARCH_AVX]          = 4,
        [VEC_ARCH_AVX2]         = 4,
        [VEC_ARCH_AVX512]       = 4,

        [VEC_ARCH_SSE_SHANI]    = 8,
        [VEC_ARCH_AVX_SHANI]    = 4,
        [VEC_ARCH_AVX2_SHANI]   = 4,
        [VEC_ARCH_AVX512_SHANI] = 4,
};

static const UINT8 sha1_lane_widths[] = {
        [VEC_ARCH_SSE]          = 8,
        [VEC_ARCH_AVX]          = 8,
        [VEC_ARCH_AVX2]         = 4,
        [VEC_ARCH_AVX512]       = 4,

        [VEC_ARCH_SSE_SHANI]    = 8,
        [VEC_ARCH_AVX_SHANI]    = 8,
        [VEC_ARCH_AVX2_SHANI]   = 4,
        [VEC_ARCH_AVX512_SHANI] = 4,
};

static const UINT8 sha224_lane_widths[] = {
        [VEC_ARCH_SSE]          = 8,
        [VEC_ARCH_AVX]          = 8,
        [VEC_ARCH_AVX2]         = 4,
        [VEC_ARCH_AVX512]       = 4,

        [VEC_ARCH_SSE_SHANI]    = 8,
        [VEC_ARCH_AVX_SHANI]    = 8,
        [VEC_ARCH_AVX2_SHANI]   = 4,
        [VEC_ARCH_AVX512_SHANI] = 4,
};

static const UINT8 sha256_lane_widths[] = {
        [VEC_ARCH_SSE]          = 8,
        [VEC_ARCH_AVX]          = 8,
        [VEC_ARCH_AVX2]         = 4,
        [VEC_ARCH_AVX512]       = 4,

        [VEC_ARCH_SSE_SHANI]    = 8,
        [VEC_ARCH_AVX_SHANI]    = 8,
        [VEC_ARCH_AVX2_SHANI]   = 4,
        [VEC_ARCH_AVX512_SHANI] = 4,
};

static const UINT8 sha384_lane_widths[] = {
        [VEC_ARCH_SSE]          = 8,
        [VEC_ARCH_AVX]          = 8,
        [VEC_ARCH_AVX2]         = 8,
        [VEC_ARCH_AVX512]       = 8,

        [VEC_ARCH_SSE_SHANI]    = 8,	/* no-SHANI */
        [VEC_ARCH_AVX_SHANI]    = 8,	/* no-SHANI */
        [VEC_ARCH_AVX2_SHANI]   = 8,	/* no-SHANI */
        [VEC_ARCH_AVX512_SHANI] = 8,	/* no-SHANI */
};

static const UINT8 sha512_lane_widths[] = {
        [VEC_ARCH_SSE]          = 8,
        [VEC_ARCH_AVX]          = 8,
        [VEC_ARCH_AVX2]         = 8,
        [VEC_ARCH_AVX512]       = 8,

        [VEC_ARCH_SSE_SHANI]    = 8,	/* no-SHANI */
        [VEC_ARCH_AVX_SHANI]    = 8,	/* no-SHANI */
        [VEC_ARCH_AVX2_SHANI]   = 8,	/* no-SHANI */
        [VEC_ARCH_AVX512_SHANI] = 8,	/* no-SHANI */
};

static const UINT8 md5_lane_widths[] = {
        [VEC_ARCH_SSE]          = 4,
        [VEC_ARCH_AVX]          = 4,
        [VEC_ARCH_AVX2]         = 4,
        [VEC_ARCH_AVX512]       = 4,

        [VEC_ARCH_SSE_SHANI]    = 4,
        [VEC_ARCH_AVX_SHANI]    = 4,
        [VEC_ARCH_AVX2_SHANI]   = 4,
        [VEC_ARCH_AVX512_SHANI] = 4,
};

static const UINT8 xcbc_lane_widths[] = {
        [VEC_ARCH_SSE]          = 8,
        [VEC_ARCH_AVX]          = 4,
        [VEC_ARCH_AVX2]         = 4,
        [VEC_ARCH_AVX512]       = 4,

        [VEC_ARCH_SSE_SHANI]    = 8,
        [VEC_ARCH_AVX_SHANI]    = 4,
        [VEC_ARCH_AVX2_SHANI]   = 4,
        [VEC_ARCH_AVX512_SHANI] = 4,
};

/******************************************************************************
 *	Number of Lanes per Arch
 ******************************************************************************/
static const UINT8 aes_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_AES_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_AES_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_AES_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_AES_LANES,

        [VEC_ARCH_SSE_SHANI]    = SSE_NUM_AES_LANES,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_AES_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_AES_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_AES_LANES,
};

static const UINT8 sha1_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_SHA1_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_SHA1_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_SHA1_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_SHA1_LANES,

        [VEC_ARCH_SSE_SHANI]    = 2,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_SHA1_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_SHA1_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_SHA1_LANES,
};

static const UINT8 sha224_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_SHA224_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_SHA224_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_SHA224_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_SHA224_LANES,

        [VEC_ARCH_SSE_SHANI]    = 2,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_SHA224_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_SHA224_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_SHA224_LANES,
};

static const UINT8 sha256_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_SHA256_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_SHA256_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_SHA256_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_SHA256_LANES,

        [VEC_ARCH_SSE_SHANI]    = 2,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_SHA256_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_SHA256_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_SHA256_LANES,
};

static const UINT8 sha384_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_SHA384_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_SHA384_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_SHA384_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_SHA384_LANES,

        [VEC_ARCH_SSE_SHANI]    = SSE_NUM_SHA384_LANES,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_SHA384_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_SHA384_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_SHA384_LANES,
};

static const UINT8 sha512_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_SHA512_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_SHA512_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_SHA512_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_SHA512_LANES,

        [VEC_ARCH_SSE_SHANI]    = SSE_NUM_SHA512_LANES,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_SHA512_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_SHA512_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_SHA512_LANES,
};

static const UINT8 md5_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_MD5_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_MD5_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_MD5_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_MD5_LANES,

        [VEC_ARCH_SSE_SHANI]    = SSE_NUM_MD5_LANES,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_MD5_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_MD5_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_MD5_LANES,
};

static const UINT8 xcbc_lanes[] = {
        [VEC_ARCH_SSE]          = SSE_NUM_XCBC_LANES,
        [VEC_ARCH_AVX]          = AVX_NUM_XCBC_LANES,
        [VEC_ARCH_AVX2]         = AVX2_NUM_XCBC_LANES,
        [VEC_ARCH_AVX512]       = AVX512_NUM_XCBC_LANES,

        [VEC_ARCH_SSE_SHANI]    = SSE_NUM_XCBC_LANES,
        [VEC_ARCH_AVX_SHANI]    = AVX_NUM_XCBC_LANES,
        [VEC_ARCH_AVX2_SHANI]   = AVX2_NUM_XCBC_LANES,
        [VEC_ARCH_AVX512_SHANI] = AVX512_NUM_XCBC_LANES,
};

/******************************************************************************
 * Cyrpto Operation types
 ******************************************************************************/
static void (*AES128_key_expand_p)(const void *raw, struct aes_exp_key *enc,
                                   struct aes_exp_key *dec) = aes_keyexp_128_sse;
static void (*AES192_key_expand_p)(const void *raw, struct aes_exp_key *enc,
                                   struct aes_exp_key *dec) = aes_keyexp_192_sse;
static void (*AES256_key_expand_p)(const void *raw, struct aes_exp_key *enc,
                                   struct aes_exp_key *dec) = aes_keyexp_256_sse;
static void (*AES128_enckey_expand_p)(const void *raw,
                                      struct aes_exp_key *enc) = aes_keyexp_128_enc_sse;
static void (*AES192_enckey_expand_p)(const void *raw,
                                      struct aes_exp_key *enc) = aes_keyexp_192_enc_sse;
static void (*AES256_enckey_expand_p)(const void *raw,
                                      struct aes_exp_key *enc) = aes_keyexp_256_enc_sse;
static void (*SHA1_one_block_p)(const void *data, void *digest) = sha1_one_block_sse;
static void (*SHA224_one_block_p)(const void *data, void *digest) = sha224_one_block_sse;
static void (*SHA256_one_block_p)(const void *data, void *digest) = sha256_one_block_sse;
static void (*SHA384_one_block_p)(const void *data, void *digest) = sha256_one_block_sse;
static void (*SHA512_one_block_p)(const void *data, void *digest) = sha512_one_block_sse;
static void (*MD5_one_block_p)(const void *data, void *digest) = md5_one_block_sse;
static void (*AES128_ecbenc_x3_p)(const void *in, const struct aes_exp_key *enc_ekey,
                                  UINT128 *out1, UINT128 *out2, UINT128 *out3) = aes128_ecbenc_x3_sse;
static void (*AES128_cbc_dec_p)(const void *src, const union AES_IV *iv,
                                const struct aes_exp_key *k,
                                void *dst, UINT64 len) = aes_cbc_dec_128_sse;
static void (*AES192_cbc_dec_p)(const void *src, const union AES_IV *iv,
                                const struct aes_exp_key *k,
                                void *dst, UINT64 len) = aes_cbc_dec_192_sse;
static void (*AES256_cbc_dec_p)(const void *src, const union AES_IV *iv,
                                const struct aes_exp_key *k,
                                void *dst, UINT64 len) = aes_cbc_dec_256_sse;
static void (*AES128_ctr_p)(const void *src, const union AES_IV *iv,
                            const struct aes_exp_key *k,
                            void *dst, UINT64 len) = aes_cntr_128_sse;
static void (*AES192_ctr_p)(const void *src, const union AES_IV *iv,
                            const struct aes_exp_key *k,
                            void *dst, UINT64 len) = aes_cntr_192_sse;
static void (*AES256_ctr_p)(const void *src, const union AES_IV *iv,
                            const struct aes_exp_key *k,
                            void *dst, UINT64 len) = aes_cntr_256_sse;
static void (*AES128_gcm_key_setup_p)(struct gcm_data *gdata) = aesni_gcm128_precomp_sse;
static void (*AES192_gcm_key_setup_p)(struct gcm_data *gdata) = aesni_gcm192_precomp_sse;
static void (*AES256_gcm_key_setup_p)(struct gcm_data *gdata) = aesni_gcm256_precomp_sse;
static void (*AES128_cfb_one_p)(void *dst, const void *src,
                                const union AES_IV *iv,
                                const struct aes_exp_key *ekey,
                                UINT64 len) = aes_cfb_128_one_sse;
static void (*AES128_gcm_enc_p)(struct gcm_data *, void *out, const void *in, UINT64 len,
                                const union AES_IV *iv,
                                const void *aad, UINT64 aad_len,
                                void *tag, UINT64 tag_len) = aesni_gcm128_enc_sse;
static void (*AES128_gcm_dec_p)(struct gcm_data *, void *out, const void *in, UINT64 len,
                                const union AES_IV *iv,
                                const void *aad, UINT64 aad_len,
                                void *tag, UINT64 tag_len) = aesni_gcm128_dec_sse;
static void (*AES192_gcm_enc_p)(struct gcm_data *, void *out, const void *in, UINT64 len,
                                const union AES_IV *iv,
                                const void *aad, UINT64 aad_len,
                                void *tag, UINT64 tag_len) = aesni_gcm192_enc_sse;
static void (*AES192_gcm_dec_p)(struct gcm_data *, void *out, const void *in, UINT64 len,
                                const union AES_IV *iv,
                                const void *aad, UINT64 aad_len,
                                void *tag, UINT64 tag_len) = aesni_gcm192_dec_sse;
static void (*AES256_gcm_enc_p)(struct gcm_data *, void *out, const void *in, UINT64 len,
                                const union AES_IV *iv,
                                const void *aad, UINT64 aad_len,
                                void *tag, UINT64 tag_len) = aesni_gcm256_enc_sse;
static void (*AES256_gcm_dec_p)(struct gcm_data *, void *out, const void *in, UINT64 len,
                                const union AES_IV *iv,
                                const void *aad, UINT64 aad_len,
                                void *tag, UINT64 tag_len) = aesni_gcm256_dec_sse;
static void (*AES128_cbc_enc_p)(struct AES_ARGS_x8 *args, UINT64 len_in_bytes) = aes_cbc_enc_128_x4;
static void (*AES192_cbc_enc_p)(struct AES_ARGS_x8 *args, UINT64 len_in_bytes) = aes_cbc_enc_192_x4;
static void (*AES256_cbc_enc_p)(struct AES_ARGS_x8 *args, UINT64 len_in_bytes) = aes_cbc_enc_256_x4;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_aes128_cbc_enc_p)(struct MB_MGR_AES_OOO *,
                                                           struct JOB_AES_HMAC *) = submit_job_aes128_enc_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_aes128_cbc_enc_p)(struct MB_MGR_AES_OOO *) = flush_job_aes128_enc_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_aes192_cbc_enc_p)(struct MB_MGR_AES_OOO *,
                                                           struct JOB_AES_HMAC *) = submit_job_aes192_enc_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_aes192_cbc_enc_p)(struct MB_MGR_AES_OOO *) = flush_job_aes192_enc_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_aes256_cbc_enc_p)(struct MB_MGR_AES_OOO *,
                                                           struct JOB_AES_HMAC *) = submit_job_aes256_enc_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_aes256_cbc_enc_p)(struct MB_MGR_AES_OOO *) = flush_job_aes256_enc_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_sha1_p)(struct MB_MGR_HMAC_SHA1_OOO *,
                                                 struct JOB_AES_HMAC *) = submit_job_hmac_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_sha1_p)(struct MB_MGR_HMAC_SHA1_OOO *) = flush_job_hmac_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_sha224_p)(struct MB_MGR_HMAC_SHA256_OOO *,
                                                   struct JOB_AES_HMAC *) = submit_job_hmac_sha_224_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_sha224_p)(struct MB_MGR_HMAC_SHA256_OOO *) = flush_job_hmac_sha_224_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_sha256_p)(struct MB_MGR_HMAC_SHA256_OOO *,
                                                   struct JOB_AES_HMAC *) = submit_job_hmac_sha_256_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_sha256_p)(struct MB_MGR_HMAC_SHA256_OOO *) = flush_job_hmac_sha_256_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_sha384_p)(struct MB_MGR_HMAC_SHA512_OOO *,
                                                   struct JOB_AES_HMAC *) = submit_job_hmac_sha_384_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_sha384_p)(struct MB_MGR_HMAC_SHA512_OOO *) = flush_job_hmac_sha_384_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_sha512_p)(struct MB_MGR_HMAC_SHA512_OOO *,
                                                   struct JOB_AES_HMAC *) = submit_job_hmac_sha_512_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_sha512_p)(struct MB_MGR_HMAC_SHA512_OOO *) = flush_job_hmac_sha_512_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_md5_p)(struct MB_MGR_HMAC_MD5_OOO *,
                                                struct JOB_AES_HMAC *) = submit_job_hmac_md5_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_md5_p)(struct MB_MGR_HMAC_MD5_OOO *) = flush_job_hmac_md5_sse;
static struct JOB_AES_HMAC *(*JOB_SUBMIT_aes_xcbc_p)(struct MB_MGR_AES_XCBC_OOO *,
                                                     struct JOB_AES_HMAC *) = submit_job_aes_xcbc_sse;
static struct JOB_AES_HMAC *(*JOB_FLUSH_aes_xcbc_p)(struct MB_MGR_AES_XCBC_OOO *) = flush_job_aes_xcbc_sse;

/******************************************************************************
 * ASM Wrapper Functions
 ******************************************************************************/
extern inline void
AES128_key_expand(const void *raw,
                  struct aes_exp_key *enc,
                  struct aes_exp_key *dec)
{
        (*AES128_key_expand_p)(raw, enc, dec);
}

extern inline void
AES192_key_expand(const void *raw,
                  struct aes_exp_key *enc,
                  struct aes_exp_key *dec)
{
        (*AES192_key_expand_p)(raw, enc, dec);
}

extern inline void
AES256_key_expand(const void *raw,
                  struct aes_exp_key *enc,
                  struct aes_exp_key *dec)
{
        (*AES256_key_expand_p)(raw, enc, dec);
}

extern inline void
AES128_enckey_expand(const void *raw,
                     struct aes_exp_key *enc)
{
        (*AES128_enckey_expand_p)(raw, enc);
}

extern inline void
AES192_enckey_expand(const void *raw,
                     struct aes_exp_key *enc)
{
        (*AES192_enckey_expand_p)(raw, enc);
}

extern inline void
AES256_enckey_expand(const void *raw,
                     struct aes_exp_key *enc)
{
        (*AES256_enckey_expand_p)(raw, enc);
}

extern inline void
SHA1_one_block(const void *data,
               void *digest)
{
        (*SHA1_one_block_p)(data, digest);
}

extern inline void
SHA224_one_block(const void *data,
                 void *digest)
{
        (*SHA224_one_block_p)(data, digest);
}

extern inline void
SHA256_one_block(const void *data,
                 void *digest)
{
        (*SHA256_one_block_p)(data, digest);
}

extern inline void
SHA384_one_block(const void *data,
                 void *digest)
{
        (*SHA384_one_block_p)(data, digest);
}

extern inline void
SHA512_one_block(const void *data,
                 void *digest)
{
        (*SHA512_one_block_p)(data, digest);
}

extern inline void
MD5_one_block(const void *data,
              void *digest)
{
        (*MD5_one_block_p)(data, digest);
}

extern inline void
AES128_ecbenc_x3(const void *in,
                 const struct aes_exp_key *enc_ekey,
                 UINT128 *out1,
                 UINT128 *out2,
                 UINT128 *out3)
{
        (*AES128_ecbenc_x3_p)(in, enc_ekey, out1, out2, out3);
}

extern inline void
AES128_cbc_dec(const void *src,
               const union AES_IV *iv,
               const struct aes_exp_key *k,
               void *dst,
               UINT64 len)
{
        (*AES128_cbc_dec_p)(src, iv, k, dst, len);
}

extern inline void
AES192_cbc_dec(const void *src,
               const union AES_IV *iv,
               const struct aes_exp_key *k,
               void *dst,
               UINT64 len)
{
        (*AES192_cbc_dec_p)(src, iv, k, dst, len);

}

extern inline void
AES256_cbc_dec(const void *src,
               const union AES_IV *iv,
               const struct aes_exp_key *k,
               void *dst,
               UINT64 len)
{
        (*AES256_cbc_dec_p)(src, iv, k, dst, len);
}

extern inline void
AES128_ctr(const void *src,
           const union AES_IV *iv,
           const struct aes_exp_key *k,
           void *dst,
           UINT64 len)
{
        (*AES128_ctr_p)(src, iv, k, dst, len);
}

extern inline void
AES192_ctr(const void *src,
           const union AES_IV *iv,
           const struct aes_exp_key *k,
           void *dst,
           UINT64 len)
{
        (*AES192_ctr_p)(src, iv, k, dst, len);
}

extern inline void
AES256_ctr(const void *src,
           const union AES_IV *iv,
           const struct aes_exp_key *k,
           void *dst,
           UINT64 len)
{
        (*AES256_ctr_p)(src, iv, k, dst, len);

}

extern inline void
AES128_cbc_enc(struct AES_ARGS_x8 *args,
               UINT64 len_in_bytes)
{
        (*AES128_cbc_enc_p)(args, len_in_bytes);
}

extern inline void
AES192_cbc_enc(struct AES_ARGS_x8 *args,
               UINT64 len_in_bytes)
{
        (*AES192_cbc_enc_p)(args, len_in_bytes);
}

extern inline void
AES256_cbc_enc(struct AES_ARGS_x8 *args,
               UINT64 len_in_bytes)
{
        (*AES256_cbc_enc_p)(args, len_in_bytes);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_aes128_cbc_enc(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_aes128_cbc_enc_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_aes128_cbc_enc(struct MB_MGR_AES_OOO *state)
{
        return (*JOB_FLUSH_aes128_cbc_enc_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_aes192_cbc_enc(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_aes192_cbc_enc_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_aes192_cbc_enc(struct MB_MGR_AES_OOO *state)
{
        return (*JOB_FLUSH_aes192_cbc_enc_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_aes256_cbc_enc(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_aes256_cbc_enc_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_aes256_cbc_enc(struct MB_MGR_AES_OOO *state)
{
        return (*JOB_FLUSH_aes256_cbc_enc_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_sha1(struct MB_MGR_HMAC_SHA1_OOO *state,
                struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_sha1_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_flush_sha1(struct MB_MGR_HMAC_SHA1_OOO *state)
{
        return (*JOB_FLUSH_sha1_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_sha224(struct MB_MGR_HMAC_SHA256_OOO *state,
                  struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_sha224_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_sha224(struct MB_MGR_HMAC_SHA256_OOO *state)
{
        return (*JOB_FLUSH_sha224_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_sha256(struct MB_MGR_HMAC_SHA256_OOO *state,
                  struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_sha256_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_sha256(struct MB_MGR_HMAC_SHA256_OOO *state)
{
        return (*JOB_FLUSH_sha256_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_sha384(struct MB_MGR_HMAC_SHA512_OOO *state,
                  struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_sha384_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_sha384(struct MB_MGR_HMAC_SHA512_OOO *state)
{
        return (*JOB_FLUSH_sha384_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_sha512(struct MB_MGR_HMAC_SHA512_OOO *state,
                  struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_sha512_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_sha512(struct MB_MGR_HMAC_SHA512_OOO *state)
{
        return (*JOB_FLUSH_sha512_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_md5(struct MB_MGR_HMAC_MD5_OOO *state,
               struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_md5_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_md5(struct MB_MGR_HMAC_MD5_OOO *state)
{
        return (*JOB_FLUSH_md5_p)(state);
}

extern inline struct JOB_AES_HMAC *
JOB_SUBMIT_aes_xcbc(struct MB_MGR_AES_XCBC_OOO *state,
                    struct JOB_AES_HMAC *job)
{
        return (*JOB_SUBMIT_aes_xcbc_p)(state, job);
}

extern inline struct JOB_AES_HMAC *
JOB_FLUSH_aes_xcbc(struct MB_MGR_AES_XCBC_OOO *state)
{
        return (*JOB_FLUSH_aes_xcbc_p)(state);
}

extern inline void
AES128_cfb_one(void *dst,
               const void *src,
               const union AES_IV *iv,
               const struct aes_exp_key *ekey,
               UINT64 len)
{
        (*AES128_cfb_one_p)(dst, src, iv, ekey, len);
}


/******************************************************************************
 * Legacy GCM
 ******************************************************************************/
static inline void
AES128_gcm_key_setup_raw(struct gcm_data *gdata)
{
        (*AES128_gcm_key_setup_p)(gdata);
}

static inline void
AES192_gcm_key_setup_raw(struct gcm_data *gdata)
{
        (*AES192_gcm_key_setup_p)(gdata);
}

static inline void
AES256_gcm_key_setup_raw(struct gcm_data *gdata)
{
        (*AES256_gcm_key_setup_p)(gdata);
}

static inline void
AES128_gcm_enc_raw(struct gcm_data *gdata,
                   void *out, const void *in, UINT64 len,
                   const union AES_IV *iv,
                   const void *aad, UINT64 aad_len,
                   void *tag, UINT64 tag_len)
{
        (*AES128_gcm_enc_p)(gdata, out, in, len, iv, aad, aad_len, tag, tag_len);
}

static inline void
AES128_gcm_dec_raw(struct gcm_data *gdata,
                   void *out, const void *in, UINT64 len,
                   const union AES_IV *iv,
                   const void *aad, UINT64 aad_len,
                   void *tag, UINT64 tag_len)
{
        (*AES128_gcm_dec_p)(gdata, out, in, len, iv, aad, aad_len, tag, tag_len);
}

static inline void
AES192_gcm_enc_raw(struct gcm_data *gdata,
                   void *out, const void *in, UINT64 len,
                   const union AES_IV *iv,
                   const void *aad, UINT64 aad_len,
                   void *tag, UINT64 tag_len)
{
        (*AES192_gcm_enc_p)(gdata, out, in, len, iv, aad, aad_len, tag, tag_len);
}

static inline void
AES192_gcm_dec_raw(struct gcm_data *gdata,
                   void *out, const void *in, UINT64 len,
                   const union AES_IV *iv,
                   const void *aad, UINT64 aad_len,
                   void *tag, UINT64 tag_len)
{
        (*AES192_gcm_dec_p)(gdata, out, in, len, iv, aad, aad_len, tag, tag_len);
}

static inline void
AES256_gcm_enc_raw(struct gcm_data *gdata,
                   void *out, const void *in, UINT64 len,
                   const union AES_IV *iv,
                   const void *aad, UINT64 aad_len,
                   void *tag, UINT64 tag_len)
{
        (*AES256_gcm_enc_p)(gdata, out, in, len, iv, aad, aad_len, tag, tag_len);
}

static inline void
AES256_gcm_dec_raw(struct gcm_data *gdata,
                   void *out, const void *in, UINT64 len,
                   const union AES_IV *iv,
                   const void *aad, UINT64 aad_len,
                   void *tag, UINT64 tag_len)
{
        (*AES256_gcm_dec_p)(gdata, out, in, len, iv, aad, aad_len, tag, tag_len);
}

/*
 *
 */
static void
set_sse_handler(void)
{
        AES128_key_expand_p         = aes_keyexp_128_sse;
        AES192_key_expand_p         = aes_keyexp_192_sse;
        AES256_key_expand_p         = aes_keyexp_256_sse;
        AES128_enckey_expand_p      = aes_keyexp_128_enc_sse;
        AES192_enckey_expand_p      = aes_keyexp_192_enc_sse;
        AES256_enckey_expand_p      = aes_keyexp_256_enc_sse;
        SHA1_one_block_p            = sha1_one_block_sse;
        SHA224_one_block_p          = sha224_one_block_sse;
        SHA256_one_block_p          = sha256_one_block_sse;
        SHA384_one_block_p          = sha256_one_block_sse;
        SHA512_one_block_p          = sha512_one_block_sse;
        MD5_one_block_p             = md5_one_block_sse;
        AES128_ecbenc_x3_p          = aes128_ecbenc_x3_sse;
        AES128_cbc_dec_p            = aes_cbc_dec_128_sse;
        AES192_cbc_dec_p            = aes_cbc_dec_192_sse;
        AES256_cbc_dec_p            = aes_cbc_dec_256_sse;
        AES128_ctr_p                = aes_cntr_128_sse;
        AES192_ctr_p                = aes_cntr_192_sse;
        AES256_ctr_p                = aes_cntr_256_sse;
        AES128_cfb_one_p            = aes_cfb_128_one_sse;
        AES128_gcm_key_setup_p      = aesni_gcm128_precomp_sse;
        AES192_gcm_key_setup_p      = aesni_gcm192_precomp_sse;
        AES256_gcm_key_setup_p      = aesni_gcm256_precomp_sse;
        AES128_gcm_enc_p            = aesni_gcm128_enc_sse;
        AES128_gcm_dec_p            = aesni_gcm128_dec_sse;
        AES192_gcm_enc_p            = aesni_gcm192_enc_sse;
        AES192_gcm_dec_p            = aesni_gcm192_dec_sse;
        AES256_gcm_enc_p            = aesni_gcm256_enc_sse;
        AES256_gcm_dec_p            = aesni_gcm256_dec_sse;
        AES128_cbc_enc_p            = aes_cbc_enc_128_x4;
        AES192_cbc_enc_p            = aes_cbc_enc_192_x4;
        AES256_cbc_enc_p            = aes_cbc_enc_256_x4;
        JOB_SUBMIT_aes128_cbc_enc_p = submit_job_aes128_enc_sse;
        JOB_FLUSH_aes128_cbc_enc_p  = flush_job_aes128_enc_sse;
        JOB_SUBMIT_aes192_cbc_enc_p = submit_job_aes192_enc_sse;
        JOB_FLUSH_aes192_cbc_enc_p  = flush_job_aes192_enc_sse;
        JOB_SUBMIT_aes256_cbc_enc_p = submit_job_aes256_enc_sse;
        JOB_FLUSH_aes256_cbc_enc_p  = flush_job_aes256_enc_sse;
        JOB_SUBMIT_sha1_p           = submit_job_hmac_sse;
        JOB_FLUSH_sha1_p            = flush_job_hmac_sse;
        JOB_SUBMIT_sha224_p         = submit_job_hmac_sha_224_sse;
        JOB_FLUSH_sha224_p          = flush_job_hmac_sha_224_sse;
        JOB_SUBMIT_sha256_p         = submit_job_hmac_sha_256_sse;
        JOB_FLUSH_sha256_p          = flush_job_hmac_sha_256_sse;
        JOB_SUBMIT_sha384_p         = submit_job_hmac_sha_384_sse;
        JOB_FLUSH_sha384_p          = flush_job_hmac_sha_384_sse;
        JOB_SUBMIT_sha512_p         = submit_job_hmac_sha_512_sse;
        JOB_FLUSH_sha512_p          = flush_job_hmac_sha_512_sse;
        JOB_SUBMIT_md5_p            = submit_job_hmac_md5_sse;
        JOB_FLUSH_md5_p             = flush_job_hmac_md5_sse;
        JOB_SUBMIT_aes_xcbc_p       = submit_job_aes_xcbc_sse;
        JOB_FLUSH_aes_xcbc_p        = flush_job_aes_xcbc_sse;
}

/*
 *
 */
static void
set_sse_shani_handler(void)
{
        JOB_SUBMIT_sha1_p   = submit_job_hmac_ni_sse;
        JOB_FLUSH_sha1_p    = flush_job_hmac_ni_sse;
        JOB_SUBMIT_sha224_p = submit_job_hmac_sha_224_sse;
        JOB_FLUSH_sha224_p  = flush_job_hmac_sha_224_ni_sse;
        JOB_SUBMIT_sha256_p = submit_job_hmac_sha_256_ni_sse;
        JOB_FLUSH_sha256_p  = flush_job_hmac_sha_256_ni_sse;
}

/*
 *
 */
static void
set_avx_handler(void)
{
        AES128_key_expand_p         = aes_keyexp_128_avx;
        AES192_key_expand_p         = aes_keyexp_192_avx;
        AES256_key_expand_p         = aes_keyexp_256_avx;
        AES128_enckey_expand_p      = aes_keyexp_128_enc_avx;
        AES192_enckey_expand_p      = aes_keyexp_192_enc_avx;
        AES256_enckey_expand_p      = aes_keyexp_256_enc_avx;
        SHA1_one_block_p            = sha1_one_block_avx;
        SHA224_one_block_p          = sha224_one_block_avx;
        SHA256_one_block_p          = sha256_one_block_avx;
        SHA384_one_block_p          = sha384_one_block_avx;
        SHA512_one_block_p          = sha512_one_block_avx;
        AES128_ecbenc_x3_p          = aes128_ecbenc_x3_avx;
        AES128_cbc_dec_p            = aes_cbc_dec_128_avx;
        AES192_cbc_dec_p            = aes_cbc_dec_192_avx;
        AES256_cbc_dec_p            = aes_cbc_dec_256_avx;
        AES128_ctr_p                = aes_cntr_128_avx;
        AES192_ctr_p                = aes_cntr_192_avx;
        AES256_ctr_p                = aes_cntr_256_avx;
        AES128_cfb_one_p            = aes_cfb_128_one_avx;
        AES128_gcm_key_setup_p      = aesni_gcm128_precomp_avx_gen2;
        AES192_gcm_key_setup_p      = aesni_gcm192_precomp_avx_gen2;
        AES256_gcm_key_setup_p      = aesni_gcm256_precomp_avx_gen2;
        AES128_gcm_enc_p            = aesni_gcm128_enc_avx_gen2;
        AES128_gcm_dec_p            = aesni_gcm128_dec_avx_gen2;
        AES192_gcm_enc_p            = aesni_gcm192_enc_avx_gen2;
        AES192_gcm_dec_p            = aesni_gcm192_dec_avx_gen2;
        AES256_gcm_enc_p            = aesni_gcm256_enc_avx_gen2;
        AES256_gcm_dec_p            = aesni_gcm256_dec_avx_gen2;
        AES128_cbc_enc_p            = aes_cbc_enc_128_x8;
        AES192_cbc_enc_p            = aes_cbc_enc_192_x8;
        AES256_cbc_enc_p            = aes_cbc_enc_256_x8;
        JOB_SUBMIT_aes128_cbc_enc_p = submit_job_aes128_enc_avx;
        JOB_FLUSH_aes128_cbc_enc_p  = flush_job_aes128_enc_avx;
        JOB_SUBMIT_aes192_cbc_enc_p = submit_job_aes192_enc_avx;
        JOB_FLUSH_aes192_cbc_enc_p  = flush_job_aes192_enc_avx;
        JOB_SUBMIT_aes256_cbc_enc_p = submit_job_aes256_enc_avx;
        JOB_FLUSH_aes256_cbc_enc_p  = flush_job_aes256_enc_avx;
        JOB_SUBMIT_sha1_p           = submit_job_hmac_avx;
        JOB_FLUSH_sha1_p            = flush_job_hmac_avx;
        JOB_SUBMIT_sha224_p         = submit_job_hmac_sha_224_avx;
        JOB_FLUSH_sha224_p          = flush_job_hmac_sha_224_avx;
        JOB_SUBMIT_sha256_p         = submit_job_hmac_sha_256_avx;
        JOB_FLUSH_sha256_p          = flush_job_hmac_sha_256_avx;
        JOB_SUBMIT_sha384_p         = submit_job_hmac_sha_384_avx;
        JOB_FLUSH_sha384_p          = flush_job_hmac_sha_384_avx;
        JOB_SUBMIT_sha512_p         = submit_job_hmac_sha_512_avx;
        JOB_FLUSH_sha512_p          = flush_job_hmac_sha_512_avx;
        JOB_SUBMIT_md5_p            = submit_job_hmac_md5_avx;
        JOB_FLUSH_md5_p             = flush_job_hmac_md5_avx;
        JOB_SUBMIT_aes_xcbc_p       = submit_job_aes_xcbc_avx;
        JOB_FLUSH_aes_xcbc_p        = flush_job_aes_xcbc_avx;
}

/*
 *
 */
static void
set_avx_shani_handler(void)
{
        /* not yet */
}

/*
 *
 */
static void
set_avx2_handler(void)
{
        AES128_gcm_key_setup_p      = aesni_gcm128_precomp_avx_gen4;
        AES192_gcm_key_setup_p      = aesni_gcm192_precomp_avx_gen4;
        AES256_gcm_key_setup_p      = aesni_gcm256_precomp_avx_gen4;
        AES128_gcm_enc_p            = aesni_gcm128_enc_avx_gen4;
        AES128_gcm_dec_p            = aesni_gcm128_dec_avx_gen4;
        AES192_gcm_enc_p            = aesni_gcm192_enc_avx_gen4;
        AES192_gcm_dec_p            = aesni_gcm192_dec_avx_gen4;
        AES256_gcm_enc_p            = aesni_gcm256_enc_avx_gen4;
        AES256_gcm_dec_p            = aesni_gcm256_dec_avx_gen4;

        JOB_SUBMIT_sha1_p           = submit_job_hmac_avx2;
        JOB_FLUSH_sha1_p            = flush_job_hmac_avx2;
        JOB_SUBMIT_sha224_p         = submit_job_hmac_sha_224_avx2;
        JOB_FLUSH_sha224_p          = flush_job_hmac_sha_224_avx2;
        JOB_SUBMIT_sha256_p         = submit_job_hmac_sha_256_avx2;
        JOB_FLUSH_sha256_p          = flush_job_hmac_sha_256_avx2;
        JOB_SUBMIT_sha384_p         = submit_job_hmac_sha_384_avx2;
        JOB_FLUSH_sha384_p          = flush_job_hmac_sha_384_avx2;
        JOB_SUBMIT_sha512_p         = submit_job_hmac_sha_512_avx2;
        JOB_FLUSH_sha512_p          = flush_job_hmac_sha_512_avx2;
        JOB_SUBMIT_md5_p            = submit_job_hmac_md5_avx2;
        JOB_FLUSH_md5_p             = flush_job_hmac_md5_avx2;
}

/*
 *
 */
static void
set_avx2_shani_handler(void)
{
        /* not yet */
}

/*
 *
 */
static void
set_avx512_handler(void)
{
        JOB_SUBMIT_sha1_p           = submit_job_hmac_avx512;
        JOB_FLUSH_sha1_p            = flush_job_hmac_avx512;
        JOB_SUBMIT_sha224_p         = submit_job_hmac_sha_224_avx512;
        JOB_FLUSH_sha224_p          = flush_job_hmac_sha_224_avx512;
        JOB_SUBMIT_sha256_p         = submit_job_hmac_sha_256_avx512;
        JOB_FLUSH_sha256_p          = flush_job_hmac_sha_256_avx512;
}

/*
 *
 */
static void
set_avx512_shani_handler(void)
{
        /* not yet */
}


static const UINT32 xcbc_seed[] = {
        0x01010101, 0x01010101, 0x01010101, 0x01010101,
        0x02020202, 0x02020202, 0x02020202, 0x02020202,
        0x03030303, 0x03030303, 0x03030303, 0x03030303
};

/*
 *
 */
void
XCBC_AES128_key_expand(const void *raw,
                       struct xcbc_exp_key *xcbc)
{
        DECLARE_ALIGNED(struct aes_exp_key ekey, 16);

        AES128_enckey_expand(raw, &ekey);
        AES128_ecbenc_x3(xcbc_seed, &ekey, xcbc->k1.expanded_keys, &xcbc->k2, &xcbc->k3);
        AES128_enckey_expand(xcbc->k1.expanded_keys, &xcbc->k1);
}

/*
 * Poc GCM code
 */
void
GMAC_AES128_key_expand(const struct aes_exp_key *ekey,
                       struct gmac_exp_key *gkey)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        AES128_gcm_key_setup_raw(&gdata);
        memcpy(gkey, &gdata.gmac_key, sizeof(*gkey));

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
GMAC_AES192_key_expand(const struct aes_exp_key *ekey,
                       struct gmac_exp_key *gkey)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        AES192_gcm_key_setup_raw(&gdata);
        memcpy(gkey, &gdata.gmac_key, sizeof(*gkey));

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
GMAC_AES256_key_expand(const struct aes_exp_key *ekey,
                       struct gmac_exp_key *gkey)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        AES256_gcm_key_setup_raw(&gdata);
        memcpy(gkey, &gdata.gmac_key, sizeof(*gkey));

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
AES128_gcm_enc(const struct aes_exp_key *ekey,
               const struct gmac_exp_key *gkey,
               void *out, const void *in, UINT64 len,
               const union AES_IV *iv,
               const void *aad, UINT64 aad_len,
               void *tag, UINT64 tag_len)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        memcpy(&gdata.gmac_key, gkey, sizeof(gdata.gmac_key));
        AES128_gcm_enc_raw(&gdata, out, in, len, iv, aad, aad_len, tag, tag_len);

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
AES128_gcm_dec(const struct aes_exp_key *ekey,
               const struct gmac_exp_key *gkey,
               void *out, const void *in, UINT64 len,
               const union AES_IV *iv,
               const void *aad, UINT64 aad_len,
               void *tag, UINT64 tag_len)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        memcpy(&gdata.gmac_key, gkey, sizeof(gdata.gmac_key));
        AES128_gcm_dec_raw(&gdata, out, in, len, iv, aad, aad_len, tag, tag_len);

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
AES192_gcm_enc(const struct aes_exp_key *ekey,
               const struct gmac_exp_key *gkey,
               void *out, const void *in, UINT64 len,
               const union AES_IV *iv,
               const void *aad, UINT64 aad_len,
               void *tag, UINT64 tag_len)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        memcpy(&gdata.gmac_key, gkey, sizeof(gdata.gmac_key));
        AES192_gcm_enc_raw(&gdata, out, in, len, iv, aad, aad_len, tag, tag_len);

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
AES192_gcm_dec(const struct aes_exp_key *ekey,
               const struct gmac_exp_key *gkey,
               void *out, const void *in, UINT64 len,
               const union AES_IV *iv,
               const void *aad, UINT64 aad_len,
               void *tag, UINT64 tag_len)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        memcpy(&gdata.gmac_key, gkey, sizeof(gdata.gmac_key));
        AES192_gcm_dec_raw(&gdata, out, in, len, iv, aad, aad_len, tag, tag_len);

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
AES256_gcm_enc(const struct aes_exp_key *ekey,
               const struct gmac_exp_key *gkey,
               void *out, const void *in, UINT64 len,
               const union AES_IV *iv,
               const void *aad, UINT64 aad_len,
               void *tag, UINT64 tag_len)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        memcpy(&gdata.gmac_key, gkey, sizeof(gdata.gmac_key));
        AES256_gcm_enc_raw(&gdata, out, in, len, iv, aad, aad_len, tag, tag_len);

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*
 *
 */
void
AES256_gcm_dec(const struct aes_exp_key *ekey,
               const struct gmac_exp_key *gkey,
               void *out, const void *in, UINT64 len,
               const union AES_IV *iv,
               const void *aad, UINT64 aad_len,
               void *tag, UINT64 tag_len)
{
        DECLARE_ALIGNED(struct gcm_data gdata, 16);

        memcpy(&gdata.aes_key, ekey, sizeof(gdata.aes_key));
        memcpy(&gdata.gmac_key, gkey, sizeof(gdata.gmac_key));
        AES256_gcm_dec_raw(&gdata, out, in, len, iv, aad, aad_len, tag, tag_len);

        MEMSET(&gdata, 0, sizeof(gdata));
}

/*************
 *
 ************/
static inline void
hmac_key_expand(void (*one_block_hash)(const void *, void *),
                unsigned block_bytes,
                const UINT8 *raw_key,
                unsigned key_len,
                struct hmac_exp_key *hkey)
{
        UINT8 ipad_buf[block_bytes] __attribute__((aligned(16)));
        UINT8 opad_buf[block_bytes] __attribute__((aligned(16)));
        unsigned i;

        /* XXX: not supported long key */
        if (key_len > block_bytes)
                key_len = block_bytes;

        for (i = 0; i < key_len; i++) {
                ipad_buf[i] = raw_key[i] ^ 0x36;
                opad_buf[i] = raw_key[i] ^ 0x5c;
        }
        while (i < block_bytes) {
                ipad_buf[i] = 0x36;
                opad_buf[i] = 0x5c;
                i++;
        }
        one_block_hash(ipad_buf, hkey->ipad);
        one_block_hash(opad_buf, hkey->opad);

        MEMSET(ipad_buf, 0, block_bytes);
        MEMSET(opad_buf, 0, block_bytes);
}

/*
 *
 */
void
HMAC_SHA1_key_expand(const void *raw, unsigned len,
                     struct hmac_exp_key *hkey)
{
        hmac_key_expand(SHA1_one_block, SHA1_BLOCK_SIZE, raw, len, hkey);
}

/*
 *
 */
void
HMAC_SHA224_key_expand(const void *raw, unsigned len,
                       struct hmac_exp_key *hkey)
{
        hmac_key_expand(SHA224_one_block, SHA_224_BLOCK_SIZE, raw, len, hkey);
}

/*
 *
 */
void
HMAC_SHA256_key_expand(const void *raw, unsigned len,
                       struct hmac_exp_key *hkey)
{
        hmac_key_expand(SHA256_one_block, SHA_256_BLOCK_SIZE, raw, len, hkey);
}

/*
 *
 */
void
HMAC_SHA384_key_expand(const void *raw, unsigned len,
                       struct hmac_exp_key *hkey)
{
        hmac_key_expand(SHA384_one_block, SHA_384_BLOCK_SIZE, raw, len, hkey);
}

/*
 *
 */
void
HMAC_SHA512_key_expand(const void *raw, unsigned len,
                       struct hmac_exp_key *hkey)
{
        hmac_key_expand(SHA512_one_block, SHA_512_BLOCK_SIZE, raw, len, hkey);
}

/*
 *
 */
void
HMAC_MD5_key_expand(const void *raw, unsigned len,
                    struct hmac_exp_key *hkey)
{
        hmac_key_expand(MD5_one_block, MD5_BLOCK_SIZE, raw, len, hkey);
}

/*
 *
 */
static inline UINT16
BSWAP16(UINT16 v)
{
        UINT16 r = v << 8;
        return r | (v >> 8);
}

/*
 *
 */
void
init_aes_ooo(struct MB_MGR_AES_OOO *state)
{
        UINT64 unused_lanes = 0;
        UINT64 terminator = 0;
        UINT64 width = aes_lane_widths[VEC_ARCH];
        unsigned i;

        for (i = 0; i < width; i++) {
                terminator <<= 1;
                terminator |= 1;
        }

        for (i = 0; i < aes_lanes[VEC_ARCH]; i++) {
                state->lens[i] = 0;
                state->job_in_lane[i] = NULL;
                unused_lanes |= (i << (width * i));
        }
        unused_lanes |= (terminator << (width * i));
        state->unused_lanes = unused_lanes;

        for ( ; i < ARRAYOF(state->lens); i++)
                state->lens[i] = 0xffff;
}

/*
 *
 */
void
init_xcbc_ooo(struct MB_MGR_AES_XCBC_OOO *state)
{
        UINT64 unused_lanes = 0;
        UINT64 terminator = 0;
        UINT64 width = xcbc_lane_widths[VEC_ARCH];
        unsigned i;

        for (i = 0; i < width; i++) {
                terminator <<= 1;
                terminator |= 1;
        }

        for (i = 0; i < xcbc_lanes[VEC_ARCH]; i++) {
                state->lens[i] = 0;
                state->ldata[i].job_in_lane = NULL;
                MEMSET(&state->ldata[i].final_block[AES_BLOCK_SIZE],
                       0,
                       sizeof(state->ldata[i].final_block) - AES_BLOCK_SIZE);
                state->ldata[i].final_block[AES_BLOCK_SIZE] = 0x80;
                unused_lanes |= (i << (width * i));
        }
        unused_lanes |= (terminator << (width * i));
        state->unused_lanes = unused_lanes;

        for ( ; i < ARRAYOF(state->lens); i++) {
                state->lens[i] = 0xffff;
        }
}

/*
 * block_size: block size in bytes
 * digest_size: digest size in bytes
 */
#define INIT_HMAC(state, lanes, width, block_size, digest_size)         \
do {                                                        		\
        UINT64 _unused_lanes = 0;                                       \
        UINT64 _terminator = 0;                                         \
        unsigned _i;                                                    \
        for (_i = 0; _i < (width); _i++) {                              \
                _terminator <<= 1;                                      \
                _terminator |= 1;                                       \
        }                                                               \
        for (_i = 0; _i < (lanes); _i++) {                              \
                (state)->lens[_i] = 0;                                  \
                _unused_lanes |= (_i << ((width) * _i));                \
        }                                                               \
        _unused_lanes |= (_terminator << ((width) * _i));               \
        (state)->unused_lanes = _unused_lanes;                          \
        for ( ; _i < ARRAYOF((state)->lens); _i++) {                    \
                (state)->lens[_i] = 0xffff;                             \
        }                                                               \
        for (_i = 0; _i < (lanes); _i++) {                              \
                BE16 *_len_p;                                           \
                (state)->ldata[_i].job_in_lane = NULL;                  \
                MEMSET(&(state)->ldata[_i].extra_block[block_size],     \
                       0x00,                                            \
                       sizeof((state)->ldata[_i].extra_block) - block_size); \
                (state)->ldata[_i].extra_block[(block_size)] = 0x80;    \
                MEMSET(&(state)->ldata[_i].outer_block[digest_size],    \
                       0x00,                                            \
                       sizeof((state)->ldata[_i].outer_block) - (digest_size)); \
                (state)->ldata[_i].outer_block[(digest_size)] = 0x80;   \
                _len_p = (UINT16 *) (&(state)->ldata[_i].outer_block[sizeof((state)->ldata[_i].outer_block)]); \
                _len_p -= 1;                                            \
                *_len_p = BSWAP16((block_size + digest_size) << 3);     \
        }                                                               \
 } while (0)

/*
 *
 */
void
init_sha1_ooo(struct MB_MGR_HMAC_SHA1_OOO *state)
{
        INIT_HMAC(state,
                  sha1_lanes[VEC_ARCH],
                  sha1_lane_widths[VEC_ARCH],
                  SHA1_BLOCK_SIZE,
                  SHA1_DIGEST_SIZE);
}

/*
 *
 */
void
init_sha224_ooo(struct MB_MGR_HMAC_SHA256_OOO *state)
{
        INIT_HMAC(state,
                  sha224_lanes[VEC_ARCH],
                  sha224_lane_widths[VEC_ARCH],
                  SHA_224_BLOCK_SIZE,
                  SHA_224_DIGEST_SIZE);
}

/*
 *
 */
void
init_sha256_ooo(struct MB_MGR_HMAC_SHA256_OOO *state)
{
        INIT_HMAC(state,
                  sha256_lanes[VEC_ARCH],
                  sha256_lane_widths[VEC_ARCH],
                  SHA_256_BLOCK_SIZE,
                  SHA_256_DIGEST_SIZE);
}

/*
 *
 */
void
init_sha384_ooo(struct MB_MGR_HMAC_SHA512_OOO *state)
{
        INIT_HMAC(state,
                  sha384_lanes[VEC_ARCH],
                  sha384_lane_widths[VEC_ARCH],
                  SHA_384_BLOCK_SIZE,
                  SHA_384_DIGEST_SIZE);
}

/*
 *
 */
void
init_sha512_ooo(struct MB_MGR_HMAC_SHA512_OOO *state)
{
        INIT_HMAC(state,
                  sha512_lanes[VEC_ARCH],
                  sha512_lane_widths[VEC_ARCH],
                  SHA_512_BLOCK_SIZE,
                  SHA_512_DIGEST_SIZE);
}

/*
 *
 */
void
init_md5_ooo(struct MB_MGR_HMAC_MD5_OOO *state)
{
        INIT_HMAC(state,
                  md5_lanes[VEC_ARCH],
                  md5_lane_widths[VEC_ARCH],
                  MD5_BLOCK_SIZE,
                  MD5_DIGEST_SIZE);
}

/******************************************************************************
 * CPUID
 ******************************************************************************/
enum cpuid_reg_e {
        CPUID_REG_EAX = 0,
        CPUID_REG_EBX,
        CPUID_REG_ECX,
        CPUID_REG_EDX,
        CPUID_REG_NB,
};

struct cpuid_s {
        unsigned reg[CPUID_REG_NB];
};

#define CPUID_SUB_LEAF_UNSPEC   0
#define CPUID_BASIC             0x0U
#define CPUID_EXT               0x80000000U

static inline int
cpuid_exec(struct cpuid_s *cpuid,
           const unsigned op,
           unsigned sub)
{
        __asm__ __volatile__ ("cpuid" :
                              "=a" (cpuid->reg[CPUID_REG_EAX]),
                              "=b" (cpuid->reg[CPUID_REG_EBX]),
                              "=c" (cpuid->reg[CPUID_REG_ECX]),
                              "=d" (cpuid->reg[CPUID_REG_EDX]) : "a" (op),
                              "c" (sub));

        /* all Zero then invalid */
        return (cpuid->reg[CPUID_REG_EAX] |
                cpuid->reg[CPUID_REG_EBX] |
                cpuid->reg[CPUID_REG_ECX] |
                cpuid->reg[CPUID_REG_EDX]) ? 0 : -1;
}

/*
 *
 */
static unsigned
cpuid_reg_read(unsigned op,
               unsigned sub,
               enum cpuid_reg_e reg_id)
{
        struct cpuid_s cpuid;

        if (!cpuid_exec(&cpuid, CPUID_EXT & op, 0)) {
                if (cpuid.reg[CPUID_REG_EAX] >= op) {
                        if (!cpuid_exec(&cpuid, op, sub)) {
                                TRACE("op:%x sub:%x reg:%d val:%x\n",
                                      op, sub, reg_id, cpuid.reg[reg_id]);
                                return cpuid.reg[reg_id];
                        }
                } else {
                        TRACE("not supported:%u op:%u\n",
                              cpuid.reg[CPUID_REG_EAX], op);
                }
        }
        return 0;
}

/*
 * AESNI:     CPUID.01H:ECX.AESNI[bit 25] = 1
 * PCLMULQDQ: CPUID.01H:ECX.PCLMULQDQ[bit 1] = 1
 * AVX:
 * AVX2
 * AVX512:
 * SHANI:
 */

struct cpuid_list {
        unsigned flag;
        unsigned op;
        enum cpuid_reg_e reg;
        unsigned mask;
};

static const struct cpuid_list cpuid_list[] = {
        {
                .flag = (1u << CPUID_AESNI),
                .op   = CPUID_BASIC | 0x01,
                .reg  = CPUID_REG_ECX,
                .mask = (1u << 25),
        },
        {
                .flag = (1u << CPUID_PCLMULQDQ),
                .op   = CPUID_BASIC | 0x01,
                .reg  = CPUID_REG_ECX,
                .mask = (1u << 1),
        },
        {
                .flag = (1u << CPUID_AVX),
                .op   = CPUID_BASIC | 0x01,
                .reg  = CPUID_REG_ECX,
                .mask = (1u << 28),
        },
        {
                .flag = (1u << CPUID_AVX2),
                .op   = CPUID_BASIC | 0x07,
                .reg  = CPUID_REG_EBX,
                .mask = (1u << 5),
        },
        {
                .flag = (1u << CPUID_AVX512F),
                .op   = CPUID_BASIC | 0x07,
                .reg  = CPUID_REG_ECX,
                .mask = (1u << 16),
        },
        {
                .flag = (1u << CPUID_SHANI),
                .op   = CPUID_BASIC | 0x07,
                .reg  = CPUID_REG_ECX,
                .mask = (1u << 29),
        },
};

static unsigned
cpuid_flags_get(void)
{
        unsigned flags = 0;

        for (unsigned i = 0; i < ARRAYOF(cpuid_list); i++) {
                if (cpuid_reg_read(cpuid_list[i].op, 0, cpuid_list[i].reg) &
                    cpuid_list[i].mask)
                        flags |= cpuid_list[i].flag;
        }
        return flags;
}

/*
 *
 */
unsigned
ipsec_mb_cpuid_get(void)
{
        return CPUID_FLAGS;
}

/*
 *
 */
int
ipsec_mb_cpuid_set(unsigned flags)
{
        enum VEC_ARCH arch;

        TRACE("CPUID:0x%ux\n", flags);
        if (CPUID_FLAGS == flags)
                return 0;

        if (!flags)
                flags = cpuid_flags_get();

        if (flags & ~((1u << CPUID_AESNI)      |
                      (1u << CPUID_PCLMULQDQ)  |
                      (1u << CPUID_AVX)        |
                      (1u << CPUID_AVX2)       |
                      (1u << CPUID_AVX512F)     |
                      (1u << CPUID_SHANI))) {
                TRACE("invalid flags\n");
                return -1;	/* invalid */
        }

        if (!(flags & (1u << CPUID_AESNI)) ||
            !(flags & (1u << CPUID_PCLMULQDQ))) {
                TRACE("not AES-NI nor PCLMULQDQ\n");
                return -1;
        } else {
                set_sse_handler();
                arch = VEC_ARCH_SSE;
                if (flags & (1u << CPUID_SHANI)) {
                        set_sse_shani_handler();
                        arch = VEC_ARCH_SSE_SHANI;
                }
        }

        if (flags & (1u << CPUID_AVX)) {
                set_avx_handler();
                arch = VEC_ARCH_AVX;
                if (flags & (1u << CPUID_SHANI)) {
                        set_avx_shani_handler();
                        arch = VEC_ARCH_AVX_SHANI;
                }
        }

        if (flags & (1u << CPUID_AVX2)) {
                set_avx2_handler();
                arch = VEC_ARCH_AVX2;
                if (flags & (1u << CPUID_SHANI)) {
                        set_avx2_shani_handler();
                        arch = VEC_ARCH_AVX2_SHANI;
                }
        }

        if (flags & (1u << CPUID_AVX512F)) {
                set_avx512_handler();
                arch = VEC_ARCH_AVX512;
                if (flags & (1u << CPUID_SHANI)) {
                        set_avx512_shani_handler();
                        arch = VEC_ARCH_AVX512_SHANI;
                }
        }

        CPUID_FLAGS = flags;
        VEC_ARCH = arch;
        return 0;
}

