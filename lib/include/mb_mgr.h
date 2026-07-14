/*******************************************************************************
  Copyright (c) 2024, Intel Corporation

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
*******************************************************************************/

#ifndef MB_MGR_H
#define MB_MGR_H

#include <stdint.h>
#include "intel-ipsec-mb.h"

typedef void (*init_mb_mgr_t)(struct IMB_MGR *);
typedef IMB_JOB *(*get_next_job_t)(struct IMB_MGR *);
typedef IMB_JOB *(*submit_job_t)(struct IMB_MGR *);
typedef IMB_JOB *(*get_completed_job_t)(struct IMB_MGR *);
typedef IMB_JOB *(*flush_job_t)(struct IMB_MGR *);
typedef uint32_t (*queue_size_t)(struct IMB_MGR *);
typedef uint32_t (*burst_fn_t)(struct IMB_MGR *, const uint32_t, struct IMB_JOB **);
typedef uint32_t (*submit_cipher_burst_t)(struct IMB_MGR *, struct IMB_JOB *, const uint32_t,
                                          const IMB_CIPHER_MODE cipher,
                                          const IMB_CIPHER_DIRECTION dir,
                                          const IMB_KEY_SIZE_BYTES key_size);
typedef uint32_t (*submit_hash_burst_t)(struct IMB_MGR *, struct IMB_JOB *, const uint32_t,
                                        const IMB_HASH_ALG hash);
typedef void (*keyexp_t)(const void *, void *, void *);
typedef void (*cmac_subkey_gen_t)(const void *, void *, void *);
typedef void (*hash_one_block_t)(const void *, void *);
typedef void (*hash_fn_t)(const void *, const uint64_t, void *);
typedef void (*sha3_fn_t)(const uint8_t *, const uint64_t, uint8_t *);
typedef void (*shake_fn_t)(const uint8_t *, const uint64_t, uint8_t *, const uint64_t);
typedef void (*xcbc_keyexp_t)(const void *, void *, void *, void *);
typedef int (*des_keysched_t)(uint64_t *, const void *);
typedef void (*aes_cfb_t)(void *, const void *, const void *, const void *, uint64_t);
typedef void (*aes_gcm_enc_dec_t)(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                  uint8_t const *, uint64_t, const uint8_t *, uint8_t const *,
                                  uint64_t, uint8_t *, uint64_t);
typedef void (*aes_gcm_enc_dec_iv_t)(const struct gcm_key_data *, struct gcm_context_data *,
                                     uint8_t *, uint8_t const *, const uint64_t, const uint8_t *,
                                     uint8_t const *, const uint64_t, uint8_t *, const uint64_t,
                                     const uint64_t);
typedef void (*aes_gcm_init_t)(const struct gcm_key_data *, struct gcm_context_data *,
                               const uint8_t *, uint8_t const *, uint64_t);
typedef void (*aes_gcm_init_var_iv_t)(const struct gcm_key_data *, struct gcm_context_data *,
                                      const uint8_t *, const uint64_t, const uint8_t *,
                                      const uint64_t);
typedef void (*aes_gcm_enc_dec_update_t)(const struct gcm_key_data *, struct gcm_context_data *,
                                         uint8_t *, const uint8_t *, uint64_t);
typedef void (*aes_gcm_enc_dec_finalize_t)(const struct gcm_key_data *, struct gcm_context_data *,
                                           uint8_t *, uint64_t);
typedef void (*aes_gcm_precomp_t)(struct gcm_key_data *);
typedef void (*aes_gcm_pre_t)(const void *, struct gcm_key_data *);

typedef void (*aes_gmac_init_t)(const struct gcm_key_data *, struct gcm_context_data *,
                                const uint8_t *, const uint64_t);
typedef void (*aes_gmac_update_t)(const struct gcm_key_data *, struct gcm_context_data *,
                                  const uint8_t *, const uint64_t);
typedef void (*aes_gmac_finalize_t)(const struct gcm_key_data *, struct gcm_context_data *,
                                    uint8_t *, const uint64_t);

typedef void (*chacha_poly_init_t)(const void *, struct chacha20_poly1305_context_data *,
                                   const void *, const void *, const uint64_t);
typedef void (*chacha_poly_enc_dec_update_t)(const void *, struct chacha20_poly1305_context_data *,
                                             void *, const void *, const uint64_t);
typedef void (*chacha_poly_finalize_t)(struct chacha20_poly1305_context_data *, void *,
                                       const uint64_t);
typedef void (*ghash_t)(const struct gcm_key_data *, const void *, const uint64_t, void *,
                        const uint64_t);

typedef void (*kasumi_f8_1_buffer_t)(const kasumi_key_sched_t *, const uint64_t, const void *,
                                     void *, const uint32_t);
typedef void (*kasumi_f9_1_buffer_t)(const kasumi_key_sched_t *, const void *, const uint32_t,
                                     void *);
typedef int (*kasumi_init_f8_key_sched_t)(const void *, kasumi_key_sched_t *);
typedef int (*kasumi_init_f9_key_sched_t)(const void *, kasumi_key_sched_t *);
typedef size_t (*kasumi_key_sched_size_t)(void);

typedef void (*snow3g_f8_1_buffer_t)(const snow3g_key_schedule_t *, const void *, const void *,
                                     void *, const uint32_t);

typedef void (*snow3g_f9_1_buffer_t)(const snow3g_key_schedule_t *, const void *, const void *,
                                     const uint64_t, void *);

typedef int (*snow3g_init_key_sched_t)(const void *, snow3g_key_schedule_t *);

typedef size_t (*snow3g_key_sched_size_t)(void);

typedef uint32_t (*hec_32_t)(const uint8_t *);
typedef uint64_t (*hec_64_t)(const uint8_t *);

typedef uint32_t (*crc32_fn_t)(const void *, const uint64_t);

typedef void (*aes_ecb_quic_t)(const void *, const void *, void *out, uint64_t);

typedef IMB_JOB *(*chacha20_poly1305_quic_t)(struct IMB_MGR *, IMB_JOB *);

typedef void (*chacha20_hp_quic_t)(const void *, const void *const *, void **, const uint64_t);

typedef void (*sm4_keyexp_t)(const void *, void *, void *);

#define IMB_MAX_JOBS (IMB_MAX_BURST_SIZE * 2)

struct IMB_MGR {

        uint64_t flags;    /**< passed to alloc_mb_mgr() */
        uint64_t features; /**< reflects features of multi-buffer instance */

        uint32_t used_arch_type; /**< Architecture type being used */
        uint32_t used_arch;      /**< Architecture being used */

        int imb_errno; /**< per mb_mgr error status */

        /**
         * ARCH handlers / API
         * Careful as changes here can break ABI compatibility
         * (always include function pointers at the end of the list,
         * before "earliest_job")
         */
        get_next_job_t get_next_job;
        submit_job_t submit_job;
        submit_job_t submit_job_nocheck;
        get_completed_job_t get_completed_job;
        flush_job_t flush_job;
        queue_size_t queue_size;
        keyexp_t keyexp_128;
        keyexp_t keyexp_192;
        keyexp_t keyexp_256;
        cmac_subkey_gen_t cmac_subkey_gen_128;
        xcbc_keyexp_t xcbc_keyexp;
        des_keysched_t des_key_sched;
        hash_one_block_t sha1_one_block;
        hash_one_block_t sha224_one_block;
        hash_one_block_t sha256_one_block;
        hash_one_block_t sha384_one_block;
        hash_one_block_t sha512_one_block;
        hash_one_block_t md5_one_block;
        hash_fn_t sha1;
        hash_fn_t sha224;
        hash_fn_t sha256;
        hash_fn_t sha384;
        hash_fn_t sha512;
        sha3_fn_t sha3_224;
        sha3_fn_t sha3_256;
        sha3_fn_t sha3_384;
        sha3_fn_t sha3_512;
        shake_fn_t shake128;
        shake_fn_t shake256;
        aes_cfb_t aes128_cfb_one;

        aes_gcm_enc_dec_t gcm128_enc;
        aes_gcm_enc_dec_t gcm192_enc;
        aes_gcm_enc_dec_t gcm256_enc;
        aes_gcm_enc_dec_t gcm128_dec;
        aes_gcm_enc_dec_t gcm192_dec;
        aes_gcm_enc_dec_t gcm256_dec;
        aes_gcm_init_t gcm128_init;
        aes_gcm_init_t gcm192_init;
        aes_gcm_init_t gcm256_init;
        aes_gcm_enc_dec_update_t gcm128_enc_update;
        aes_gcm_enc_dec_update_t gcm192_enc_update;
        aes_gcm_enc_dec_update_t gcm256_enc_update;
        aes_gcm_enc_dec_update_t gcm128_dec_update;
        aes_gcm_enc_dec_update_t gcm192_dec_update;
        aes_gcm_enc_dec_update_t gcm256_dec_update;
        aes_gcm_enc_dec_finalize_t gcm128_enc_finalize;
        aes_gcm_enc_dec_finalize_t gcm192_enc_finalize;
        aes_gcm_enc_dec_finalize_t gcm256_enc_finalize;
        aes_gcm_enc_dec_finalize_t gcm128_dec_finalize;
        aes_gcm_enc_dec_finalize_t gcm192_dec_finalize;
        aes_gcm_enc_dec_finalize_t gcm256_dec_finalize;
        aes_gcm_precomp_t gcm128_precomp;
        aes_gcm_precomp_t gcm192_precomp;
        aes_gcm_precomp_t gcm256_precomp;
        aes_gcm_pre_t gcm128_pre;
        aes_gcm_pre_t gcm192_pre;
        aes_gcm_pre_t gcm256_pre;

        kasumi_f8_1_buffer_t f8_1_buffer;
        kasumi_f9_1_buffer_t f9_1_buffer;
        kasumi_init_f8_key_sched_t kasumi_init_f8_key_sched;
        kasumi_init_f9_key_sched_t kasumi_init_f9_key_sched;
        kasumi_key_sched_size_t kasumi_key_sched_size;

        snow3g_f8_1_buffer_t snow3g_f8_1_buffer;
        snow3g_f9_1_buffer_t snow3g_f9_1_buffer;
        snow3g_init_key_sched_t snow3g_init_key_sched;
        snow3g_key_sched_size_t snow3g_key_sched_size;

        ghash_t ghash;
        aes_gcm_init_var_iv_t gcm128_init_var_iv;
        aes_gcm_init_var_iv_t gcm192_init_var_iv;
        aes_gcm_init_var_iv_t gcm256_init_var_iv;

        aes_gmac_init_t gmac128_init;
        aes_gmac_init_t gmac192_init;
        aes_gmac_init_t gmac256_init;
        aes_gmac_update_t gmac128_update;
        aes_gmac_update_t gmac192_update;
        aes_gmac_update_t gmac256_update;
        aes_gmac_finalize_t gmac128_finalize;
        aes_gmac_finalize_t gmac192_finalize;
        aes_gmac_finalize_t gmac256_finalize;
        hec_32_t hec_32;
        hec_64_t hec_64;
        cmac_subkey_gen_t cmac_subkey_gen_256;
        aes_gcm_pre_t ghash_pre;
        crc32_fn_t crc32_ethernet_fcs;
        crc32_fn_t crc16_x25;
        crc32_fn_t crc32_sctp;
        crc32_fn_t crc24_lte_a;
        crc32_fn_t crc24_lte_b;
        crc32_fn_t crc16_fp_data;
        crc32_fn_t crc11_fp_header;
        crc32_fn_t crc7_fp_header;
        crc32_fn_t crc10_iuup_data;
        crc32_fn_t crc6_iuup_header;
        crc32_fn_t crc32_wimax_ofdma_data;
        crc32_fn_t crc8_wimax_ofdma_hcs;

        chacha_poly_init_t chacha20_poly1305_init;
        chacha_poly_enc_dec_update_t chacha20_poly1305_enc_update;
        chacha_poly_enc_dec_update_t chacha20_poly1305_dec_update;
        chacha_poly_finalize_t chacha20_poly1305_finalize;

        burst_fn_t get_next_burst;
        burst_fn_t submit_burst;
        burst_fn_t submit_burst_nocheck;
        burst_fn_t flush_burst;
        submit_cipher_burst_t submit_cipher_burst;
        submit_cipher_burst_t submit_cipher_burst_nocheck;
        submit_hash_burst_t submit_hash_burst;
        submit_hash_burst_t submit_hash_burst_nocheck;
        aes_cfb_t aes256_cfb_one;

        aes_ecb_quic_t aes_ecb_128_quic;
        aes_ecb_quic_t aes_ecb_256_quic;

        void (*set_suite_id)(struct IMB_MGR *, IMB_JOB *);

        chacha20_poly1305_quic_t chacha20_poly1305_quic;
        chacha20_hp_quic_t chacha20_hp_quic;

        sm4_keyexp_t sm4_keyexp;

        imb_self_test_cb_t self_test_cb_fn;
        void *self_test_cb_arg;

        submit_cipher_burst_t submit_aead_burst;
        submit_cipher_burst_t submit_aead_burst_nocheck;

        /* in-order scheduler fields */
        int earliest_job; /**< byte offset, -1 if none */
        int next_job;     /**< byte offset */
        IMB_JOB jobs[IMB_MAX_JOBS];

        /* out of order managers */
        void *aes128_ooo;
        void *aes192_ooo;
        void *aes256_ooo;
        void *docsis128_sec_ooo;
        void *docsis128_crc32_sec_ooo;
        void *docsis256_sec_ooo;
        void *docsis256_crc32_sec_ooo;
        void *des_enc_ooo;
        void *des_dec_ooo;
        void *des3_enc_ooo;
        void *des3_dec_ooo;
        void *docsis_des_enc_ooo;
        void *docsis_des_dec_ooo;

        void *hmac_sha_1_ooo;
        void *hmac_sha_224_ooo;
        void *hmac_sha_256_ooo;
        void *hmac_sha_384_ooo;
        void *hmac_sha_512_ooo;
        void *hmac_md5_ooo;
        void *aes_xcbc_ooo;
        void *aes_ccm_ooo;
        void *aes_cmac_ooo;
        void *zuc_eea3_ooo;
        void *zuc_eia3_ooo;
        void *aes256_ccm_ooo;
        void *aes256_cmac_ooo;
        void *snow3g_uea2_ooo;
        void *snow3g_uia2_ooo;
        void *sha_1_ooo;
        void *sha_224_ooo;
        void *sha_256_ooo;
        void *sha_384_ooo;
        void *sha_512_ooo;
        void *sha3_224_ooo;
        void *sha3_256_ooo;
        void *sha3_384_ooo;
        void *sha3_512_ooo;
        void *shake128_ooo;
        void *shake256_ooo;
        void *aes_cfb_128_ooo;
        void *aes_cfb_192_ooo;
        void *aes_cfb_256_ooo;
        void *zuc_nea6_ooo;
        void *zuc_nia6_ooo;
        void *zuc_nca6_enc_ooo;
        void *zuc_nca6_dec_ooo;
        void *snow5g_ooo;
        void *snow5g_nia4_ooo;
        void *snow5g_nca4_enc_ooo;
        void *snow5g_nca4_dec_ooo;
        void *end_ooo; /* add new out-of-order managers above this line */
};

/*
 * Wrapper macros to call arch API's set up
 * at init phase of multi-buffer manager.
 *
 * For example, after calling init_mb_mgr_sse(&mgr)
 * The 'mgr' structure be set up so that:
 *   mgr.get_next_job will point to get_next_job_sse(),
 *   mgr.submit_job will point to submit_job_sse(),
 *   mgr.submit_job_nocheck will point to submit_job_nocheck_sse(),
 *   mgr.get_completed_job will point to get_completed_job_sse(),
 *   mgr.flush_job will point to flush_job_sse(),
 *   mgr.queue_size will point to queue_size_sse()
 *   mgr.keyexp_128 will point to aes_keyexp_128_sse()
 *   mgr.keyexp_192 will point to aes_keyexp_192_sse()
 *   mgr.keyexp_256 will point to aes_keyexp_256_sse()
 *   etc.
 *
 */

#define CALL_GET_NEXT_JOB(_mgr)       ((_mgr)->get_next_job((_mgr)))
#define CALL_SUBMIT_JOB(_mgr)         ((_mgr)->submit_job((_mgr)))
#define CALL_SUBMIT_JOB_NOCHECK(_mgr) ((_mgr)->submit_job_nocheck((_mgr)))
#define CALL_GET_COMPLETED_JOB(_mgr)  ((_mgr)->get_completed_job((_mgr)))
#define CALL_FLUSH_JOB(_mgr)          ((_mgr)->flush_job((_mgr)))
#define CALL_QUEUE_SIZE(_mgr)         ((_mgr)->queue_size((_mgr)))
#define CALL_GET_NEXT_BURST(_mgr, _n_jobs, _jobs)                                                  \
        ((_mgr)->get_next_burst((_mgr), (_n_jobs), (_jobs)))
#define CALL_SUBMIT_BURST(_mgr, _n_jobs, _jobs) ((_mgr)->submit_burst((_mgr), (_n_jobs), (_jobs)))
#define CALL_SUBMIT_BURST_NOCHECK(_mgr, _n_jobs, _jobs)                                            \
        ((_mgr)->submit_burst_nocheck((_mgr), (_n_jobs), (_jobs)))
#define CALL_FLUSH_BURST(_mgr, _max_jobs, _jobs) ((_mgr)->flush_burst((_mgr), (_max_jobs), (_jobs)))
#define CALL_SUBMIT_CIPHER_BURST(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)                   \
        ((_mgr)->submit_cipher_burst((_mgr), (_jobs), (_n_jobs), (_cipher), (_dir), (_key_size)))
#define CALL_SUBMIT_CIPHER_BURST_NOCHECK(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)           \
        ((_mgr)->submit_cipher_burst_nocheck((_mgr), (_jobs), (_n_jobs), (_cipher), (_dir),        \
                                             (_key_size)))
#define CALL_SUBMIT_HASH_BURST(_mgr, _jobs, _n_jobs, _hash)                                        \
        ((_mgr)->submit_hash_burst((_mgr), (_jobs), (_n_jobs), (_hash)))
#define CALL_SUBMIT_HASH_BURST_NOCHECK(_mgr, _jobs, _n_jobs, _hash)                                \
        ((_mgr)->submit_hash_burst_nocheck((_mgr), (_jobs), (_n_jobs), (_hash)))
#define CALL_SUBMIT_AEAD_BURST(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)                     \
        ((_mgr)->submit_aead_burst((_mgr), (_jobs), (_n_jobs), (_cipher), (_dir), (_key_size)))
#define CALL_SUBMIT_AEAD_BURST_NOCHECK(_mgr, _jobs, _n_jobs, _cipher, _dir, _key_size)             \
        ((_mgr)->submit_aead_burst_nocheck((_mgr), (_jobs), (_n_jobs), (_cipher), (_dir),          \
                                           (_key_size)))
#define CALL_AES_KEYEXP_128(_mgr, _key, _enc_exp_key, _dec_exp_key)                                \
        ((_mgr)->keyexp_128((_key), (_enc_exp_key), (_dec_exp_key)))
#define CALL_AES_KEYEXP_192(_mgr, _key, _enc_exp_key, _dec_exp_key)                                \
        ((_mgr)->keyexp_192((_key), (_enc_exp_key), (_dec_exp_key)))
#define CALL_AES_KEYEXP_256(_mgr, _key, _enc_exp_key, _dec_exp_key)                                \
        ((_mgr)->keyexp_256((_key), (_enc_exp_key), (_dec_exp_key)))
#define CALL_AES_CMAC_SUBKEY_GEN_128(_mgr, _exp_key, _key1, _key2)                                 \
        ((_mgr)->cmac_subkey_gen_128((_exp_key), (_key1), (_key2)))
#define CALL_AES_CMAC_SUBKEY_GEN_256(_mgr, _exp_key, _key1, _key2)                                 \
        ((_mgr)->cmac_subkey_gen_256((_exp_key), (_key1), (_key2)))
#define CALL_AES_XCBC_KEYEXP(_mgr, _key, _exp_key, _exp_key2, _exp_key3)                           \
        ((_mgr)->xcbc_keyexp((_key), (_exp_key), (_exp_key2), (_exp_key3)))
#define CALL_DES_KEYSCHED(_mgr, _exp_key, _key)  ((_mgr)->des_key_sched((_exp_key), (_key)))
#define CALL_SHA1_ONE_BLOCK(_mgr, _src, _tag)    ((_mgr)->sha1_one_block((_src), (_tag)))
#define CALL_SHA1(_mgr, _src, _length, _tag)     ((_mgr)->sha1((_src), (_length), (_tag)))
#define CALL_SHA224_ONE_BLOCK(_mgr, _src, _tag)  ((_mgr)->sha224_one_block((_src), (_tag)))
#define CALL_SHA224(_mgr, _src, _length, _tag)   ((_mgr)->sha224((_src), (_length), (_tag)))
#define CALL_SHA256_ONE_BLOCK(_mgr, _src, _tag)  ((_mgr)->sha256_one_block((_src), (_tag)))
#define CALL_SHA256(_mgr, _src, _length, _tag)   ((_mgr)->sha256((_src), (_length), (_tag)))
#define CALL_SHA384_ONE_BLOCK(_mgr, _src, _tag)  ((_mgr)->sha384_one_block((_src), (_tag)))
#define CALL_SHA384(_mgr, _src, _length, _tag)   ((_mgr)->sha384((_src), (_length), (_tag)))
#define CALL_SHA512_ONE_BLOCK(_mgr, _src, _tag)  ((_mgr)->sha512_one_block((_src), (_tag)))
#define CALL_SHA512(_mgr, _src, _length, _tag)   ((_mgr)->sha512((_src), (_length), (_tag)))
#define CALL_SHA3_224(_mgr, _src, _length, _tag) ((_mgr)->sha3_224((_src), (_length), (_tag)))
#define CALL_SHA3_256(_mgr, _src, _length, _tag) ((_mgr)->sha3_256((_src), (_length), (_tag)))
#define CALL_SHA3_384(_mgr, _src, _length, _tag) ((_mgr)->sha3_384((_src), (_length), (_tag)))
#define CALL_SHA3_512(_mgr, _src, _length, _tag) ((_mgr)->sha3_512((_src), (_length), (_tag)))
#define CALL_SHAKE128(_mgr, _src, _length, _tag, _outlen)                                          \
        ((_mgr)->shake128((_src), (_length), (_tag), (_outlen)))
#define CALL_SHAKE256(_mgr, _src, _length, _tag, _outlen)                                          \
        ((_mgr)->shake256((_src), (_length), (_tag), (_outlen)))
#define CALL_MD5_ONE_BLOCK(_mgr, _src, _tag) ((_mgr)->md5_one_block((_src), (_tag)))
#define CALL_AES128_CFB_ONE(_mgr, _dst, _src, _iv, _exp_key, _len)                                 \
        ((_mgr)->aes128_cfb_one((_dst), (_src), (_iv), (_exp_key), (_len)))
#define CALL_AES256_CFB_ONE(_mgr, _dst, _src, _iv, _exp_key, _len)                                 \
        ((_mgr)->aes256_cfb_one((_dst), (_src), (_iv), (_exp_key), (_len)))
#define CALL_AES128_GCM_ENC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl) \
        ((_mgr)->gcm128_enc((_exp_key), (_ctx), (_dst), (_src), (_len), (_iv), (_aad), (_aadl),    \
                            (_tag), (_tagl)))
#define CALL_AES192_GCM_ENC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl) \
        ((_mgr)->gcm192_enc((_exp_key), (_ctx), (_dst), (_src), (_len), (_iv), (_aad), (_aadl),    \
                            (_tag), (_tagl)))
#define CALL_AES256_GCM_ENC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl) \
        ((_mgr)->gcm256_enc((_exp_key), (_ctx), (_dst), (_src), (_len), (_iv), (_aad), (_aadl),    \
                            (_tag), (_tagl)))

#define CALL_AES128_GCM_DEC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl) \
        ((_mgr)->gcm128_dec((_exp_key), (_ctx), (_dst), (_src), (_len), (_iv), (_aad), (_aadl),    \
                            (_tag), (_tagl)))
#define CALL_AES192_GCM_DEC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl) \
        ((_mgr)->gcm192_dec((_exp_key), (_ctx), (_dst), (_src), (_len), (_iv), (_aad), (_aadl),    \
                            (_tag), (_tagl)))
#define CALL_AES256_GCM_DEC(_mgr, _exp_key, _ctx, _dst, _src, _len, _iv, _aad, _aadl, _tag, _tagl) \
        ((_mgr)->gcm256_dec((_exp_key), (_ctx), (_dst), (_src), (_len), (_iv), (_aad), (_aadl),    \
                            (_tag), (_tagl)))
#define CALL_AES128_GCM_INIT(_mgr, _exp_key, _ctx, _iv, _aad, _aadl)                               \
        ((_mgr)->gcm128_init((_exp_key), (_ctx), (_iv), (_aad), (_aadl)))
#define CALL_AES192_GCM_INIT(_mgr, _exp_key, _ctx, _iv, _aad, _aadl)                               \
        ((_mgr)->gcm192_init((_exp_key), (_ctx), (_iv), (_aad), (_aadl)))
#define CALL_AES256_GCM_INIT(_mgr, _exp_key, _ctx, _iv, _aad, _aadl)                               \
        ((_mgr)->gcm256_init((_exp_key), (_ctx), (_iv), (_aad), (_aadl)))
#define CALL_AES128_GCM_INIT_VAR_IV(_mgr, _exp_key, _ctx, _iv, _ivl, _aad, _aadl)                  \
        ((_mgr)->gcm128_init_var_iv((_exp_key), (_ctx), (_iv), (_ivl), (_aad), (_aadl)))
#define CALL_AES192_GCM_INIT_VAR_IV(_mgr, _exp_key, _ctx, _iv, _ivl, _aad, _aadl)                  \
        ((_mgr)->gcm192_init_var_iv((_exp_key), (_ctx), (_iv), (_ivl), (_aad), (_aadl)))
#define CALL_AES256_GCM_INIT_VAR_IV(_mgr, _exp_key, _ctx, _iv, _ivl, _aad, _aadl)                  \
        ((_mgr)->gcm256_init_var_iv((_exp_key), (_ctx), (_iv), (_ivl), (_aad), (_aadl)))
#define CALL_AES128_GCM_ENC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                         \
        ((_mgr)->gcm128_enc_update((_exp_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_AES192_GCM_ENC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                         \
        ((_mgr)->gcm192_enc_update((_exp_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_AES256_GCM_ENC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                         \
        ((_mgr)->gcm256_enc_update((_exp_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_AES128_GCM_DEC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                         \
        ((_mgr)->gcm128_dec_update((_exp_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_AES192_GCM_DEC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                         \
        ((_mgr)->gcm192_dec_update((_exp_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_AES256_GCM_DEC_UPDATE(_mgr, _exp_key, _ctx, _dst, _src, _len)                         \
        ((_mgr)->gcm256_dec_update((_exp_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_AES128_GCM_ENC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                            \
        ((_mgr)->gcm128_enc_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES192_GCM_ENC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                            \
        ((_mgr)->gcm192_enc_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES256_GCM_ENC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                            \
        ((_mgr)->gcm256_enc_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES128_GCM_DEC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                            \
        ((_mgr)->gcm128_dec_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES192_GCM_DEC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                            \
        ((_mgr)->gcm192_dec_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES256_GCM_DEC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                            \
        ((_mgr)->gcm256_dec_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES128_GMAC_INIT(_mgr, _exp_key, _ctx, _iv, _ivl)                                     \
        ((_mgr)->gmac128_init((_exp_key), (_ctx), (_iv), (_ivl)))
#define CALL_AES192_GMAC_INIT(_mgr, _exp_key, _ctx, _iv, _ivl)                                     \
        ((_mgr)->gmac192_init((_exp_key), (_ctx), (_iv), (_ivl)))
#define CALL_AES256_GMAC_INIT(_mgr, _exp_key, _ctx, _iv, _ivl)                                     \
        ((_mgr)->gmac256_init((_exp_key), (_ctx), (_iv), (_ivl)))
#define CALL_AES128_GMAC_UPDATE(_mgr, _exp_key, _ctx, _src, _len)                                  \
        ((_mgr)->gmac128_update((_exp_key), (_ctx), (_src), (_len)))
#define CALL_AES192_GMAC_UPDATE(_mgr, _exp_key, _ctx, _src, _len)                                  \
        ((_mgr)->gmac192_update((_exp_key), (_ctx), (_src), (_len)))
#define CALL_AES256_GMAC_UPDATE(_mgr, _exp_key, _ctx, _src, _len)                                  \
        ((_mgr)->gmac256_update((_exp_key), (_ctx), (_src), (_len)))
#define CALL_AES128_GMAC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                               \
        ((_mgr)->gmac128_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES192_GMAC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                               \
        ((_mgr)->gmac192_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES256_GMAC_FINALIZE(_mgr, _exp_key, _ctx, _tag, _tagl)                               \
        ((_mgr)->gmac256_finalize((_exp_key), (_ctx), (_tag), (_tagl)))
#define CALL_AES128_GCM_PRECOMP(_mgr, _key)       ((_mgr)->gcm128_precomp((_key)))
#define CALL_AES192_GCM_PRECOMP(_mgr, _key)       ((_mgr)->gcm192_precomp((_key)))
#define CALL_AES256_GCM_PRECOMP(_mgr, _key)       ((_mgr)->gcm256_precomp((_key)))
#define CALL_AES128_GCM_PRE(_mgr, _key, _exp_key) ((_mgr)->gcm128_pre((_key), (_exp_key)))
#define CALL_AES192_GCM_PRE(_mgr, _key, _exp_key) ((_mgr)->gcm192_pre((_key), (_exp_key)))
#define CALL_AES256_GCM_PRE(_mgr, _key, _exp_key) ((_mgr)->gcm256_pre((_key), (_exp_key)))
#define CALL_GHASH_PRE(_mgr, _key, _exp_key)      ((_mgr)->ghash_pre((_key), (_exp_key)))
#define CALL_GHASH(_mgr, _exp_key, _src, _len, _tag, _tagl)                                        \
        ((_mgr)->ghash((_exp_key), (_src), (_len), (_tag), (_tagl)))
#define CALL_CHACHA20_POLY1305_INIT(_mgr, _key, _ctx, _iv, _aad, _aadl)                            \
        ((_mgr)->chacha20_poly1305_init((_key), (_ctx), (_iv), (_aad), (_aadl)))
#define CALL_CHACHA20_POLY1305_ENC_UPDATE(_mgr, _key, _ctx, _dst, _src, _len)                      \
        ((_mgr)->chacha20_poly1305_enc_update((_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_CHACHA20_POLY1305_DEC_UPDATE(_mgr, _key, _ctx, _dst, _src, _len)                      \
        ((_mgr)->chacha20_poly1305_dec_update((_key), (_ctx), (_dst), (_src), (_len)))
#define CALL_CHACHA20_POLY1305_ENC_FINALIZE(_mgr, _ctx, _tag, _tagl)                               \
        ((_mgr)->chacha20_poly1305_finalize((_ctx), (_tag), (_tagl)))
#define CALL_CHACHA20_POLY1305_DEC_FINALIZE(_mgr, _ctx, _tag, _tagl)                               \
        ((_mgr)->chacha20_poly1305_finalize((_ctx), (_tag), (_tagl)))
#define CALL_KASUMI_F8_1_BUFFER(_mgr, _exp_key, _iv, _src, _dst, _len)                             \
        ((_mgr)->f8_1_buffer((_exp_key), (_iv), (_src), (_dst), (_len)))
#define CALL_KASUMI_F9_1_BUFFER(_mgr, _exp_key, _src, _len, _tag)                                  \
        ((_mgr)->f9_1_buffer((_exp_key), (_src), (_len), (_tag)))
#define CALL_KASUMI_INIT_F8_KEY_SCHED(_mgr, _key, _exp_key)                                        \
        ((_mgr)->kasumi_init_f8_key_sched((_key), (_exp_key)))
#define CALL_KASUMI_INIT_F9_KEY_SCHED(_mgr, _key, _exp_key)                                        \
        ((_mgr)->kasumi_init_f9_key_sched((_key), (_exp_key)))
#define CALL_KASUMI_KEY_SCHED_SIZE(_mgr) ((_mgr)->kasumi_key_sched_size())
#define CALL_SNOW3G_F8_1_BUFFER(_mgr, _exp_key, _iv, _src, _dst, _len)                             \
        ((_mgr)->snow3g_f8_1_buffer((_exp_key), (_iv), (_src), (_dst), (_len)))
#define CALL_SNOW3G_F9_1_BUFFER(_mgr, _exp_key, _iv, _src, _len, _tag)                             \
        ((_mgr)->snow3g_f9_1_buffer((_exp_key), (_iv), (_src), (_len), (_tag)))
#define CALL_SNOW3G_INIT_KEY_SCHED(_mgr, _key, _exp_key)                                           \
        ((_mgr)->snow3g_init_key_sched((_key), (_exp_key)))
#define CALL_SNOW3G_KEY_SCHED_SIZE(_mgr)              ((_mgr)->snow3g_key_sched_size())
#define CALL_HEC_32(_mgr, _src)                       ((_mgr)->hec_32(_src))
#define CALL_HEC_64(_mgr, _src)                       ((_mgr)->hec_64(_src))
#define CALL_CRC32_ETHERNET_FCS(_mgr, _src, _len)     (_mgr)->crc32_ethernet_fcs(_src, _len)
#define CALL_CRC16_X25(_mgr, _src, _len)              (_mgr)->crc16_x25(_src, _len)
#define CALL_CRC32_SCTP(_mgr, _src, _len)             (_mgr)->crc32_sctp(_src, _len)
#define CALL_CRC24_LTE_A(_mgr, _src, _len)            (_mgr)->crc24_lte_a(_src, _len)
#define CALL_CRC24_LTE_B(_mgr, _src, _len)            (_mgr)->crc24_lte_b(_src, _len)
#define CALL_CRC16_FP_DATA(_mgr, _src, _len)          (_mgr)->crc16_fp_data(_src, _len)
#define CALL_CRC11_FP_HEADER(_mgr, _src, _len)        (_mgr)->crc11_fp_header(_src, _len)
#define CALL_CRC7_FP_HEADER(_mgr, _src, _len)         (_mgr)->crc7_fp_header(_src, _len)
#define CALL_CRC10_IUUP_DATA(_mgr, _src, _len)        (_mgr)->crc10_iuup_data(_src, _len)
#define CALL_CRC6_IUUP_HEADER(_mgr, _src, _len)       (_mgr)->crc6_iuup_header(_src, _len)
#define CALL_CRC32_WIMAX_OFDMA_DATA(_mgr, _src, _len) (_mgr)->crc32_wimax_ofdma_data(_src, _len)
#define CALL_CRC8_WIMAX_OFDMA_HCS(_mgr, _src, _len)   (_mgr)->crc8_wimax_ofdma_hcs(_src, _len)
#define CALL_SM4_KEYEXP(_mgr, _key, _exp_enc_key, _exp_dec_key)                                    \
        ((_mgr)->sm4_keyexp((_key), (_exp_enc_key), (_exp_dec_key)))

/* ========================================================================= */
/* Internal function declarations for assembly implementations */
/* ========================================================================= */

/* AES key expansion functions */
IMB_DLL_LOCAL void
aes_keyexp_128_sse(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_192_sse(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_256_sse(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_128_avx2(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_192_avx2(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_256_avx2(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_128_avx512(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_192_avx512(const void *key, void *enc_exp_keys, void *dec_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_256_avx512(const void *key, void *enc_exp_keys, void *dec_exp_keys);

/* AES-CMAC subkey generation functions */
IMB_DLL_LOCAL void
aes_cmac_subkey_gen_sse(const void *key_exp, void *subkey1, void *subkey2);
IMB_DLL_LOCAL void
aes_cmac_subkey_gen_avx2(const void *key_exp, void *subkey1, void *subkey2);
IMB_DLL_LOCAL void
aes_cmac_subkey_gen_avx512(const void *key_exp, void *subkey1, void *subkey2);

/* AES-XCBC key expansion functions */
IMB_DLL_LOCAL void
aes_xcbc_expand_key_sse(const void *key, void *k1, void *k2, void *k3);
IMB_DLL_LOCAL void
aes_xcbc_expand_key_avx(const void *key, void *k1, void *k2, void *k3);
IMB_DLL_LOCAL void
aes_xcbc_expand_key_avx2(const void *key, void *k1, void *k2, void *k3);
IMB_DLL_LOCAL void
aes_xcbc_expand_key_avx512(const void *key, void *k1, void *k2, void *k3);

/* MD5 one block functions */
IMB_DLL_LOCAL void
md5_one_block_sse(const void *data, void *digest);
IMB_DLL_LOCAL void
md5_one_block_avx2(const void *data, void *digest);
IMB_DLL_LOCAL void
md5_one_block_avx512(const void *data, void *digest);

/* AES-GCM architecture-specific functions - for internal use only */
/* These are the actual SSE/AVX implementations called by the wrapper functions */

/* GCM encryption - SSE */
IMB_DLL_LOCAL void
aes_gcm_enc_128_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                    uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                    uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_192_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                    uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                    uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_256_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                    uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                    uint8_t *, uint64_t);

/* GCM encryption - AVX GEN4 */
IMB_DLL_LOCAL void
aes_gcm_enc_128_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                         uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                         uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_192_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                         uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                         uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_256_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                         uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                         uint8_t *, uint64_t);

/* GCM decryption - SSE */
IMB_DLL_LOCAL void
aes_gcm_dec_128_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                    uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                    uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_192_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                    uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                    uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_256_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                    uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                    uint8_t *, uint64_t);

/* GCM decryption - AVX GEN4 */
IMB_DLL_LOCAL void
aes_gcm_dec_128_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                         uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                         uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_192_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                         uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                         uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_256_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                         uint8_t const *, uint64_t, const uint8_t *, uint8_t const *, uint64_t,
                         uint8_t *, uint64_t);

/* GCM init/update/finalize - SSE */
IMB_DLL_LOCAL void
aes_gcm_init_128_sse(const struct gcm_key_data *, struct gcm_context_data *, const uint8_t *,
                     uint8_t const *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_init_192_sse(const struct gcm_key_data *, struct gcm_context_data *, const uint8_t *,
                     uint8_t const *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_init_256_sse(const struct gcm_key_data *, struct gcm_context_data *, const uint8_t *,
                     uint8_t const *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_128_update_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                           const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_192_update_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                           const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_256_update_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                           const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_128_update_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                           const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_192_update_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                           const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_256_update_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                           const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_128_finalize_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                             uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_192_finalize_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                             uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_256_finalize_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                             uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_128_finalize_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                             uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_192_finalize_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                             uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_256_finalize_sse(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                             uint64_t);

/* GCM init/update/finalize - AVX GEN4 */
IMB_DLL_LOCAL void
aes_gcm_init_128_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, const uint8_t *,
                          uint8_t const *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_init_192_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, const uint8_t *,
                          uint8_t const *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_init_256_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, const uint8_t *,
                          uint8_t const *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_128_update_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_192_update_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_256_update_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_128_update_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_192_update_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_256_update_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                const uint8_t *, uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_128_finalize_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                  uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_192_finalize_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                  uint64_t);
IMB_DLL_LOCAL void
aes_gcm_enc_256_finalize_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                  uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_128_finalize_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                  uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_192_finalize_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                  uint64_t);
IMB_DLL_LOCAL void
aes_gcm_dec_256_finalize_avx_gen4(const struct gcm_key_data *, struct gcm_context_data *, uint8_t *,
                                  uint64_t);

/* GCM precomp and pre functions - SSE */
IMB_DLL_LOCAL void
aes_gcm_precomp_128_sse(struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_precomp_192_sse(struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_precomp_256_sse(struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_pre_128_sse(const void *, struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_pre_192_sse(const void *, struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_pre_256_sse(const void *, struct gcm_key_data *);

/* GCM precomp and pre functions - AVX GEN4 */
IMB_DLL_LOCAL void
aes_gcm_precomp_128_avx_gen4(struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_precomp_192_avx_gen4(struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_precomp_256_avx_gen4(struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_pre_128_avx_gen4(const void *, struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_pre_192_avx_gen4(const void *, struct gcm_key_data *);
IMB_DLL_LOCAL void
aes_gcm_pre_256_avx_gen4(const void *, struct gcm_key_data *);

/* Architecture-specific MB_MGR wrapper functions */
/* SSE */
IMB_DLL_LOCAL IMB_JOB *
submit_job_sse(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
flush_job_sse(IMB_MGR *);
IMB_DLL_LOCAL uint32_t
queue_size_sse(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
submit_job_nocheck_sse(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_next_job_sse(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_completed_job_sse(IMB_MGR *);

/* AVX2 */
IMB_DLL_LOCAL IMB_JOB *
submit_job_avx2(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
flush_job_avx2(IMB_MGR *);
IMB_DLL_LOCAL uint32_t
queue_size_avx2(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
submit_job_nocheck_avx2(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_next_job_avx2(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_completed_job_avx2(IMB_MGR *);

/* AVX512 */
IMB_DLL_LOCAL IMB_JOB *
submit_job_avx512(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
flush_job_avx512(IMB_MGR *);
IMB_DLL_LOCAL uint32_t
queue_size_avx512(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
submit_job_nocheck_avx512(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_next_job_avx512(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_completed_job_avx512(IMB_MGR *);

/* AVX10 */
IMB_DLL_LOCAL IMB_JOB *
submit_job_avx10(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
flush_job_avx10(IMB_MGR *);
IMB_DLL_LOCAL uint32_t
queue_size_avx10(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
submit_job_nocheck_avx10(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_next_job_avx10(IMB_MGR *);
IMB_DLL_LOCAL IMB_JOB *
get_completed_job_avx10(IMB_MGR *);

/* AES key expansion enc-only variants */
IMB_DLL_LOCAL void
aes_keyexp_128_enc_sse(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_192_enc_sse(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_256_enc_sse(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_128_enc_avx(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_192_enc_avx(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_256_enc_avx(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_128_enc_avx2(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_192_enc_avx2(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_256_enc_avx2(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_128_enc_avx512(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_192_enc_avx512(const void *key, void *enc_exp_keys);
IMB_DLL_LOCAL void
aes_keyexp_256_enc_avx512(const void *key, void *enc_exp_keys);

#endif /* MB_MGR_H */
