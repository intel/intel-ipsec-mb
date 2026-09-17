/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Fail-closed handling of a self-test failure.
 *
 * After the power-up self-test fails, every IMB_MGR function pointer is
 * redirected to a stub that records IMB_ERR_SELFTEST and returns without
 * producing any output, so no cryptographic operation can be performed
 * through a manager whose self-test did not pass.
 */

#include <stddef.h>
#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "mb_mgr.h"
#include "error.h"
#include "arch_x86_64.h"

/* ------------------------------------------------------------------------- */
/* Stubs taking IMB_MGR - per manager error status can be set               */
/* ------------------------------------------------------------------------- */

static IMB_JOB *
st_job(struct IMB_MGR *state)
{
        imb_set_errno(state, IMB_ERR_SELFTEST);
        return NULL;
}

static uint32_t
st_queue_size(struct IMB_MGR *state)
{
        imb_set_errno(state, IMB_ERR_SELFTEST);
        return 0;
}

static uint32_t
st_burst(struct IMB_MGR *state, const uint32_t n_jobs, struct IMB_JOB **jobs)
{
        (void) n_jobs;
        (void) jobs;
        imb_set_errno(state, IMB_ERR_SELFTEST);
        return 0;
}

static uint32_t
st_cipher_burst(struct IMB_MGR *state, struct IMB_JOB *jobs, const uint32_t n_jobs,
                const IMB_CIPHER_MODE cipher, const IMB_CIPHER_DIRECTION dir,
                const IMB_KEY_SIZE_BYTES key_size)
{
        (void) jobs;
        (void) n_jobs;
        (void) cipher;
        (void) dir;
        (void) key_size;
        imb_set_errno(state, IMB_ERR_SELFTEST);
        return 0;
}

static uint32_t
st_hash_burst(struct IMB_MGR *state, struct IMB_JOB *jobs, const uint32_t n_jobs,
              const IMB_HASH_ALG hash)
{
        (void) jobs;
        (void) n_jobs;
        (void) hash;
        imb_set_errno(state, IMB_ERR_SELFTEST);
        return 0;
}

static void
st_set_suite_id(struct IMB_MGR *state, IMB_JOB *job)
{
        (void) job;
        imb_set_errno(state, IMB_ERR_SELFTEST);
}

/* ------------------------------------------------------------------------- */
/* Stubs without IMB_MGR - only the process wide error status can be set     */
/* ------------------------------------------------------------------------- */

static void
st_void_3p(const void *a, void *b, void *c)
{
        (void) a;
        (void) b;
        (void) c;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_void_2p(const void *a, void *b)
{
        (void) a;
        (void) b;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_hash_fn(const void *a, const uint64_t len, void *b)
{
        (void) a;
        (void) len;
        (void) b;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_sha3_fn(const uint8_t *a, const uint64_t len, uint8_t *b)
{
        (void) a;
        (void) len;
        (void) b;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_shake_fn(const uint8_t *a, const uint64_t len, uint8_t *b, const uint64_t out_len)
{
        (void) a;
        (void) len;
        (void) b;
        (void) out_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_xcbc_keyexp(const void *a, void *b, void *c, void *d)
{
        (void) a;
        (void) b;
        (void) c;
        (void) d;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static int
st_des_keysched(uint64_t *ks, const void *key)
{
        (void) ks;
        (void) key;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
        return -1;
}

static void
st_aes_cfb(void *out, const void *in, const void *iv, const void *keys, uint64_t len)
{
        (void) out;
        (void) in;
        (void) iv;
        (void) keys;
        (void) len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gcm_enc_dec(const struct gcm_key_data *kd, struct gcm_context_data *ctx, uint8_t *out,
               uint8_t const *in, uint64_t len, const uint8_t *iv, uint8_t const *aad,
               uint64_t aad_len, uint8_t *tag, uint64_t tag_len)
{
        (void) kd;
        (void) ctx;
        (void) out;
        (void) in;
        (void) len;
        (void) iv;
        (void) aad;
        (void) aad_len;
        (void) tag;
        (void) tag_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gcm_init(const struct gcm_key_data *kd, struct gcm_context_data *ctx, const uint8_t *iv,
            uint8_t const *aad, uint64_t aad_len)
{
        (void) kd;
        (void) ctx;
        (void) iv;
        (void) aad;
        (void) aad_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gcm_init_var_iv(const struct gcm_key_data *kd, struct gcm_context_data *ctx, const uint8_t *iv,
                   const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len)
{
        (void) kd;
        (void) ctx;
        (void) iv;
        (void) iv_len;
        (void) aad;
        (void) aad_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gcm_update(const struct gcm_key_data *kd, struct gcm_context_data *ctx, uint8_t *out,
              const uint8_t *in, uint64_t len)
{
        (void) kd;
        (void) ctx;
        (void) out;
        (void) in;
        (void) len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gcm_finalize(const struct gcm_key_data *kd, struct gcm_context_data *ctx, uint8_t *tag,
                uint64_t tag_len)
{
        (void) kd;
        (void) ctx;
        (void) tag;
        (void) tag_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gcm_precomp(struct gcm_key_data *kd)
{
        (void) kd;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gcm_pre(const void *key, struct gcm_key_data *kd)
{
        (void) key;
        (void) kd;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gmac_init(const struct gcm_key_data *kd, struct gcm_context_data *ctx, const uint8_t *iv,
             const uint64_t iv_len)
{
        (void) kd;
        (void) ctx;
        (void) iv;
        (void) iv_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gmac_update(const struct gcm_key_data *kd, struct gcm_context_data *ctx, const uint8_t *in,
               const uint64_t len)
{
        (void) kd;
        (void) ctx;
        (void) in;
        (void) len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_gmac_finalize(const struct gcm_key_data *kd, struct gcm_context_data *ctx, uint8_t *tag,
                 const uint64_t tag_len)
{
        (void) kd;
        (void) ctx;
        (void) tag;
        (void) tag_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_ghash(const struct gcm_key_data *kd, const void *in, const uint64_t len, void *tag,
         const uint64_t tag_len)
{
        (void) kd;
        (void) in;
        (void) len;
        (void) tag;
        (void) tag_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_chacha_poly_init(const void *key, struct chacha20_poly1305_context_data *ctx, const void *iv,
                    const void *aad, const uint64_t aad_len)
{
        (void) key;
        (void) ctx;
        (void) iv;
        (void) aad;
        (void) aad_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_chacha_poly_update(const void *key, struct chacha20_poly1305_context_data *ctx, void *out,
                      const void *in, const uint64_t len)
{
        (void) key;
        (void) ctx;
        (void) out;
        (void) in;
        (void) len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_chacha_poly_finalize(struct chacha20_poly1305_context_data *ctx, void *tag,
                        const uint64_t tag_len)
{
        (void) ctx;
        (void) tag;
        (void) tag_len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_kasumi_f8_1(const kasumi_key_sched_t *ks, const uint64_t iv, const void *in, void *out,
               const uint32_t len)
{
        (void) ks;
        (void) iv;
        (void) in;
        (void) out;
        (void) len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static void
st_kasumi_f9_1(const kasumi_key_sched_t *ks, const void *in, const uint32_t len, void *tag)
{
        (void) ks;
        (void) in;
        (void) len;
        (void) tag;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
}

static int
st_kasumi_key_sched(const void *key, kasumi_key_sched_t *ks)
{
        (void) key;
        (void) ks;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
        return -1;
}

static size_t
st_key_sched_size(void)
{
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
        return 0;
}

static int
st_snow3g_key_sched(const void *key, snow3g_key_schedule_t *ks)
{
        (void) key;
        (void) ks;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
        return -1;
}

static uint32_t
st_hec_32(const uint8_t *in)
{
        (void) in;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
        return 0;
}

static uint64_t
st_hec_64(const uint8_t *in)
{
        (void) in;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
        return 0;
}

static uint32_t
st_crc(const void *in, const uint64_t len)
{
        (void) in;
        (void) len;
        imb_set_errno(NULL, IMB_ERR_SELFTEST);
        return 0;
}

/* ------------------------------------------------------------------------- */

IMB_DLL_LOCAL void
self_test_fail_closed(IMB_MGR *state)
{
        if (state == NULL)
                return;

        /* job API */
        state->get_next_job = st_job;
        state->submit_job = st_job;
        state->submit_job_nocheck = st_job;
        state->get_completed_job = st_job;
        state->flush_job = st_job;
        state->queue_size = st_queue_size;

        /* burst API */
        state->get_next_burst = st_burst;
        state->submit_burst = st_burst;
        state->submit_burst_nocheck = st_burst;
        state->flush_burst = st_burst;
        state->submit_cipher_burst = st_cipher_burst;
        state->submit_cipher_burst_nocheck = st_cipher_burst;
        state->submit_hash_burst = st_hash_burst;
        state->submit_hash_burst_nocheck = st_hash_burst;
        state->submit_aead_burst = st_cipher_burst;
        state->submit_aead_burst_nocheck = st_cipher_burst;
        state->set_suite_id = st_set_suite_id;

        /* key expansion */
        state->keyexp_128 = st_void_3p;
        state->keyexp_192 = st_void_3p;
        state->keyexp_256 = st_void_3p;
        state->cmac_subkey_gen_128 = st_void_3p;
        state->cmac_subkey_gen_256 = st_void_3p;
        state->xcbc_keyexp = st_xcbc_keyexp;
        state->des_key_sched = st_des_keysched;
        state->sm4_keyexp = st_void_3p;

        /* hash */
        state->sha1_one_block = st_void_2p;
        state->sha224_one_block = st_void_2p;
        state->sha256_one_block = st_void_2p;
        state->sha384_one_block = st_void_2p;
        state->sha512_one_block = st_void_2p;
        state->md5_one_block = st_void_2p;
        state->sm3_one_block = st_void_2p;
        state->sha1 = st_hash_fn;
        state->sha224 = st_hash_fn;
        state->sha256 = st_hash_fn;
        state->sha384 = st_hash_fn;
        state->sha512 = st_hash_fn;
        state->sm3 = st_hash_fn;
        state->sha3_224 = st_sha3_fn;
        state->sha3_256 = st_sha3_fn;
        state->sha3_384 = st_sha3_fn;
        state->sha3_512 = st_sha3_fn;
        state->shake128 = st_shake_fn;
        state->shake256 = st_shake_fn;

        /* AES-CFB */
        state->aes128_cfb_one = st_aes_cfb;
        state->aes256_cfb_one = st_aes_cfb;

        /* AES-GCM */
        state->gcm128_enc = st_gcm_enc_dec;
        state->gcm192_enc = st_gcm_enc_dec;
        state->gcm256_enc = st_gcm_enc_dec;
        state->gcm128_dec = st_gcm_enc_dec;
        state->gcm192_dec = st_gcm_enc_dec;
        state->gcm256_dec = st_gcm_enc_dec;
        state->gcm128_init = st_gcm_init;
        state->gcm192_init = st_gcm_init;
        state->gcm256_init = st_gcm_init;
        state->gcm128_init_var_iv = st_gcm_init_var_iv;
        state->gcm192_init_var_iv = st_gcm_init_var_iv;
        state->gcm256_init_var_iv = st_gcm_init_var_iv;
        state->gcm128_enc_update = st_gcm_update;
        state->gcm192_enc_update = st_gcm_update;
        state->gcm256_enc_update = st_gcm_update;
        state->gcm128_dec_update = st_gcm_update;
        state->gcm192_dec_update = st_gcm_update;
        state->gcm256_dec_update = st_gcm_update;
        state->gcm128_enc_finalize = st_gcm_finalize;
        state->gcm192_enc_finalize = st_gcm_finalize;
        state->gcm256_enc_finalize = st_gcm_finalize;
        state->gcm128_dec_finalize = st_gcm_finalize;
        state->gcm192_dec_finalize = st_gcm_finalize;
        state->gcm256_dec_finalize = st_gcm_finalize;
        state->gcm128_precomp = st_gcm_precomp;
        state->gcm192_precomp = st_gcm_precomp;
        state->gcm256_precomp = st_gcm_precomp;
        state->gcm128_pre = st_gcm_pre;
        state->gcm192_pre = st_gcm_pre;
        state->gcm256_pre = st_gcm_pre;
        state->ghash_pre = st_gcm_pre;
        state->ghash = st_ghash;

        /* AES-GMAC */
        state->gmac128_init = st_gmac_init;
        state->gmac192_init = st_gmac_init;
        state->gmac256_init = st_gmac_init;
        state->gmac128_update = st_gmac_update;
        state->gmac192_update = st_gmac_update;
        state->gmac256_update = st_gmac_update;
        state->gmac128_finalize = st_gmac_finalize;
        state->gmac192_finalize = st_gmac_finalize;
        state->gmac256_finalize = st_gmac_finalize;

        /* ChaCha20-Poly1305 */
        state->chacha20_poly1305_init = st_chacha_poly_init;
        state->chacha20_poly1305_enc_update = st_chacha_poly_update;
        state->chacha20_poly1305_dec_update = st_chacha_poly_update;
        state->chacha20_poly1305_finalize = st_chacha_poly_finalize;

        /* KASUMI / SNOW3G */
        state->f8_1_buffer = st_kasumi_f8_1;
        state->f9_1_buffer = st_kasumi_f9_1;
        state->kasumi_init_f8_key_sched = st_kasumi_key_sched;
        state->kasumi_init_f9_key_sched = st_kasumi_key_sched;
        state->kasumi_key_sched_size = st_key_sched_size;
        state->snow3g_init_key_sched = st_snow3g_key_sched;
        state->snow3g_key_sched_size = st_key_sched_size;

        /* HEC / CRC */
        state->hec_32 = st_hec_32;
        state->hec_64 = st_hec_64;
        state->crc32_ethernet_fcs = st_crc;
        state->crc16_x25 = st_crc;
        state->crc32_sctp = st_crc;
        state->crc24_lte_a = st_crc;
        state->crc24_lte_b = st_crc;
        state->crc16_fp_data = st_crc;
        state->crc11_fp_header = st_crc;
        state->crc7_fp_header = st_crc;
        state->crc10_iuup_data = st_crc;
        state->crc6_iuup_header = st_crc;
        state->crc32_wimax_ofdma_data = st_crc;
        state->crc8_wimax_ofdma_hcs = st_crc;

        imb_set_errno(state, IMB_ERR_SELFTEST);
}
