/**********************************************************************
  Copyright(c) 2011-2023 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcmp() */

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "aead_test.h"

/* 0 - no extra messages, 1 - additional messages */
#define VERBOSE 0

#define AAD_SZ       24
#define IV_SZ        12
#define DIGEST_SZ    16
#define MAX_KEY_SZ   32
#define GCM_MAX_JOBS 32

int
gcm_test(IMB_MGR *p_mgr);

extern const struct aead_test gcm_test_json[];

typedef int (*gcm_enc_dec_fn_t)(IMB_MGR *, const struct gcm_key_data *, struct gcm_context_data *,
                                uint8_t *, const uint8_t *, uint64_t, const uint8_t *,
                                const uint64_t, const uint8_t *, uint64_t, uint8_t *, uint64_t,
                                IMB_KEY_SIZE_BYTES);

typedef int (*gcm_enc_dec_many_fn_t)(IMB_MGR *, const struct gcm_key_data *,
                                     struct gcm_context_data **, uint8_t **, const uint8_t *,
                                     const uint64_t, const uint8_t *, const uint64_t,
                                     const uint8_t *, const uint64_t, uint8_t **, const uint64_t,
                                     const IMB_KEY_SIZE_BYTES, const uint32_t);

static IMB_MGR *p_gcm_mgr = NULL;

static int
check_data(const uint8_t *test, const uint8_t *expected, uint64_t len, const char *data_name)
{
        int mismatch;
        int is_error = 0;

        if (len == 0)
                return is_error;

        if (test == NULL || expected == NULL || data_name == NULL)
                return 1;

        mismatch = memcmp(test, expected, len);
        if (mismatch) {
                uint64_t a;

                is_error = 1;
                printf("  expected results don't match %s \t\t", data_name);
                for (a = 0; a < len; a++) {
                        if (test[a] != expected[a]) {
                                printf(" '%x' != '%x' at %llx of %llx\n", test[a], expected[a],
                                       (unsigned long long) a, (unsigned long long) len);
                                break;
                        }
                }
        }
        return is_error;
}

static void
imb_aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv,
                const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len,
                IMB_KEY_SIZE_BYTES key_len)
{
        switch (key_len) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                   auth_tag_len);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                   auth_tag_len);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                   auth_tag_len);
                break;
        }
}

static void
imb_aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv,
                const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len,
                IMB_KEY_SIZE_BYTES key_len)
{
        switch (key_len) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                   auth_tag_len);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                   auth_tag_len);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                   auth_tag_len);
                break;
        }
}

static void
imb_aes_gcm_init(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                 const uint8_t *iv, const uint64_t iv_len, const uint8_t *aad, uint64_t aad_len,
                 IMB_KEY_SIZE_BYTES key_len)
{
        switch (key_len) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_INIT_VAR_IV(p_mgr, key, ctx, iv, iv_len, aad, aad_len);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_INIT_VAR_IV(p_mgr, key, ctx, iv, iv_len, aad, aad_len);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_INIT_VAR_IV(p_mgr, key, ctx, iv, iv_len, aad, aad_len);
                break;
        }
}

static void
imb_aes_gcm_enc_update(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                       uint8_t *out, const uint8_t *in, uint64_t len, IMB_KEY_SIZE_BYTES key_len)
{
        switch (key_len) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_ENC_UPDATE(p_mgr, key, ctx, out, in, len);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_ENC_UPDATE(p_mgr, key, ctx, out, in, len);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_ENC_UPDATE(p_mgr, key, ctx, out, in, len);
                break;
        }
}

static void
imb_aes_gcm_dec_update(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                       uint8_t *out, const uint8_t *in, uint64_t len, IMB_KEY_SIZE_BYTES key_len)
{
        switch (key_len) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_DEC_UPDATE(p_mgr, key, ctx, out, in, len);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_DEC_UPDATE(p_mgr, key, ctx, out, in, len);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_DEC_UPDATE(p_mgr, key, ctx, out, in, len);
                break;
        }
}

static void
imb_aes_gcm_enc_finalize(IMB_MGR *p_mgr, const struct gcm_key_data *key,
                         struct gcm_context_data *ctx, uint8_t *auth_tag, uint64_t auth_tag_len,
                         IMB_KEY_SIZE_BYTES key_len)
{
        switch (key_len) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_ENC_FINALIZE(p_mgr, key, ctx, auth_tag, auth_tag_len);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_ENC_FINALIZE(p_mgr, key, ctx, auth_tag, auth_tag_len);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_ENC_FINALIZE(p_mgr, key, ctx, auth_tag, auth_tag_len);
                break;
        }
}

static void
imb_aes_gcm_dec_finalize(IMB_MGR *p_mgr, const struct gcm_key_data *key,
                         struct gcm_context_data *ctx, uint8_t *auth_tag, uint64_t auth_tag_len,
                         IMB_KEY_SIZE_BYTES key_len)
{
        switch (key_len) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_DEC_FINALIZE(p_mgr, key, ctx, auth_tag, auth_tag_len);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_DEC_FINALIZE(p_mgr, key, ctx, auth_tag, auth_tag_len);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_DEC_FINALIZE(p_mgr, key, ctx, auth_tag, auth_tag_len);
                break;
        }
}

/*****************************************************************************
 * RAW API
 *****************************************************************************/
static int
aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
            uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv, const uint64_t iv_len,
            const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len,
            IMB_KEY_SIZE_BYTES key_len)
{
        if (iv_len == 12) {
                imb_aes_gcm_enc(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                auth_tag_len, key_len);
        } else {
                imb_aes_gcm_init(p_mgr, key, ctx, iv, iv_len, aad, aad_len, key_len);
                imb_aes_gcm_enc_update(p_mgr, key, ctx, out, in, len, key_len);
                imb_aes_gcm_enc_finalize(p_mgr, key, ctx, auth_tag, auth_tag_len, key_len);
        }
        return 0;
}

static int
aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
            uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv, const uint64_t iv_len,
            const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len,
            IMB_KEY_SIZE_BYTES key_len)
{
        if (iv_len == 12) {
                imb_aes_gcm_dec(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                auth_tag_len, key_len);
        } else {
                imb_aes_gcm_init(p_mgr, key, ctx, iv, iv_len, aad, aad_len, key_len);
                imb_aes_gcm_dec_update(p_mgr, key, ctx, out, in, len, key_len);
                imb_aes_gcm_dec_finalize(p_mgr, key, ctx, auth_tag, auth_tag_len, key_len);
        }
        return 0;
}

/*****************************************************************************
 * RAW SGL API
 *****************************************************************************/
static int
sgl_aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv,
                const uint64_t iv_len, const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag,
                uint64_t auth_tag_len, IMB_KEY_SIZE_BYTES key_len)
{
        imb_aes_gcm_init(p_mgr, key, ctx, iv, iv_len, aad, aad_len, key_len);
        imb_aes_gcm_enc_update(p_mgr, key, ctx, out, in, len, key_len);
        imb_aes_gcm_enc_finalize(p_mgr, key, ctx, auth_tag, auth_tag_len, key_len);
        return 0;
}

static int
sgl_aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv,
                const uint64_t iv_len, const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag,
                uint64_t auth_tag_len, IMB_KEY_SIZE_BYTES key_len)
{
        imb_aes_gcm_init(p_mgr, key, ctx, iv, iv_len, aad, aad_len, key_len);
        imb_aes_gcm_dec_update(p_mgr, key, ctx, out, in, len, key_len);
        imb_aes_gcm_dec_finalize(p_mgr, key, ctx, auth_tag, auth_tag_len, key_len);
        return 0;
}

/*****************************************************************************
 * QUIC API
 *****************************************************************************/
static int
quic_aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                 uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv,
                 const uint64_t iv_len, const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag,
                 uint64_t auth_tag_len, IMB_KEY_SIZE_BYTES key_len)
{
        if (iv_len != 12)
                return aes_gcm_enc(p_mgr, key, ctx, out, in, len, iv, iv_len, aad, aad_len,
                                   auth_tag, auth_tag_len, key_len);

        imb_quic_aes_gcm(p_mgr, key, key_len, IMB_DIR_ENCRYPT, (void **) &out,
                         (const void *const *) &in, &len, (const void *const *) &iv,
                         (const void *const *) &aad, aad_len, (void **) &auth_tag, auth_tag_len, 1);

        const int err = imb_get_errno(p_mgr);

        if (err != 0) {
                printf("QUIC GCM encrypt error %d, %s\n", err, imb_get_strerror(err));
                return 1;
        }
        return 0;
}

static int
quic_aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                 uint8_t *out, const uint8_t *in, uint64_t len, const uint8_t *iv,
                 const uint64_t iv_len, const uint8_t *aad, uint64_t aad_len, uint8_t *auth_tag,
                 uint64_t auth_tag_len, IMB_KEY_SIZE_BYTES key_len)
{
        if (iv_len != 12)
                return aes_gcm_dec(p_mgr, key, ctx, out, in, len, iv, iv_len, aad, aad_len,
                                   auth_tag, auth_tag_len, key_len);

        imb_quic_aes_gcm(p_mgr, key, key_len, IMB_DIR_DECRYPT, (void **) &out,
                         (const void *const *) &in, &len, (const void *const *) &iv,
                         (const void *const *) &aad, aad_len, (void **) &auth_tag, auth_tag_len, 1);

        const int err = imb_get_errno(p_mgr);

        if (err != 0) {
                printf("QUIC GCM decrypt error %d, %s\n", err, imb_get_strerror(err));
                return 1;
        }
        return 0;
}

/*****************************************************************************
 * burst API
 *****************************************************************************/
static int
aes_gcm_burst(IMB_MGR *mb_mgr, const IMB_CIPHER_DIRECTION cipher_dir,
              const struct gcm_key_data *key, const uint64_t key_len, uint8_t **const out,
              const uint8_t *in, const uint64_t len, const uint8_t *iv, const uint64_t iv_len,
              const uint8_t *aad, const uint64_t aad_len, uint8_t **const auth_tag,
              const uint64_t auth_tag_len, struct gcm_context_data **const ctx,
              const IMB_CIPHER_MODE cipher_mode, const IMB_SGL_STATE sgl_state,
              const uint32_t num_jobs)
{
        IMB_JOB *job, *jobs[GCM_MAX_JOBS];
        uint32_t i;

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];

                job->cipher_mode = cipher_mode;
                job->chain_order = (cipher_dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_CIPHER_HASH
                                                                   : IMB_ORDER_HASH_CIPHER;
                job->enc_keys = key;
                job->dec_keys = key;
                job->key_len_in_bytes = key_len;
                job->src = in;
                job->dst = out[i];
                job->msg_len_to_cipher_in_bytes = len;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = iv;
                job->iv_len_in_bytes = iv_len;
                job->u.GCM.aad = aad;
                job->u.GCM.aad_len_in_bytes = aad_len;
                job->auth_tag_output = auth_tag[i];
                job->auth_tag_output_len_in_bytes = auth_tag_len;
                job->cipher_direction = cipher_dir;
                if (cipher_mode == IMB_CIPHER_GCM_SGL) {
                        job->u.GCM.ctx = ctx[i];
                        job->sgl_state = sgl_state;
                        job->hash_alg = IMB_AUTH_GCM_SGL;
                } else
                        job->hash_alg = IMB_AUTH_AES_GMAC;

                imb_set_session(mb_mgr, job);
        }

        const uint32_t completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);

        if (completed_jobs != num_jobs) {
                int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                        return -1;
                } else {
                        printf("submit_burst error: not enough "
                               "jobs returned!\n");
                        return -1;
                }
        }

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %u status not complete!\n", i + 1);
                        return -1;
                }
        }

        return 0;
}

static int
burst_aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data **ctx,
                  uint8_t **out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                  const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                  uint8_t **auth_tag, const uint64_t auth_tag_len, const IMB_KEY_SIZE_BYTES key_len,
                  const uint32_t num_jobs)
{
        return aes_gcm_burst(p_mgr, IMB_DIR_ENCRYPT, key, key_len, out, in, len, iv, iv_len, aad,
                             aad_len, auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM, 0, num_jobs);
}

static int
burst_quic_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data **ctx,
                   uint8_t **out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                   const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                   uint8_t **auth_tag, const uint64_t auth_tag_len,
                   const IMB_KEY_SIZE_BYTES key_len, const uint32_t num_jobs)
{
        if (iv_len != 12) {
                return burst_aes_gcm_enc(p_mgr, key, ctx, out, in, len, iv, iv_len, aad, aad_len,
                                         auth_tag, auth_tag_len, key_len, num_jobs);
        }

        const void *in_array[GCM_MAX_JOBS];
        uint64_t len_array[GCM_MAX_JOBS];
        const void *iv_array[GCM_MAX_JOBS];
        const void *aad_array[GCM_MAX_JOBS];
        uint32_t i;

        for (i = 0; i < num_jobs; i++) {
                in_array[i] = (const void *) in;
                len_array[i] = len;
                iv_array[i] = (const void *) iv;
                aad_array[i] = (const void *) aad;
        }

        imb_quic_aes_gcm(p_mgr, key, key_len, IMB_DIR_ENCRYPT, (void **) out, in_array, len_array,
                         iv_array, aad_array, aad_len, (void **) auth_tag, auth_tag_len, num_jobs);

        const int err = imb_get_errno(p_mgr);

        if (err != 0) {
                printf("QUIC GCM burst-encrypt error %d, %s\n", err, imb_get_strerror(err));
                return 1;
        }
        return 0;
}

static int
burst_aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data **ctx,
                  uint8_t **out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                  const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                  uint8_t **auth_tag, const uint64_t auth_tag_len, const IMB_KEY_SIZE_BYTES key_len,
                  const uint32_t num_jobs)
{
        return aes_gcm_burst(p_mgr, IMB_DIR_DECRYPT, key, key_len, out, in, len, iv, iv_len, aad,
                             aad_len, auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM, 0, num_jobs);
}

static int
burst_quic_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data **ctx,
                   uint8_t **out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                   const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                   uint8_t **auth_tag, const uint64_t auth_tag_len,
                   const IMB_KEY_SIZE_BYTES key_len, const uint32_t num_jobs)
{
        if (iv_len != 12) {
                return burst_aes_gcm_dec(p_mgr, key, ctx, out, in, len, iv, iv_len, aad, aad_len,
                                         auth_tag, auth_tag_len, key_len, num_jobs);
        }

        const void *in_array[GCM_MAX_JOBS];
        uint64_t len_array[GCM_MAX_JOBS];
        const void *iv_array[GCM_MAX_JOBS];
        const void *aad_array[GCM_MAX_JOBS];
        uint32_t i;

        for (i = 0; i < num_jobs; i++) {
                in_array[i] = (const void *) in;
                len_array[i] = len;
                iv_array[i] = (const void *) iv;
                aad_array[i] = (const void *) aad;
        }

        imb_quic_aes_gcm(p_mgr, key, key_len, IMB_DIR_DECRYPT, (void **) out, in_array, len_array,
                         iv_array, aad_array, aad_len, (void **) auth_tag, auth_tag_len, num_jobs);

        const int err = imb_get_errno(p_mgr);

        if (err != 0) {
                printf("QUIC GCM burst-decrypt error %d, %s\n", err, imb_get_strerror(err));
                return 1;
        }
        return 0;
}

static int
burst_sgl_aes_gcm(IMB_MGR *p_mgr, IMB_CIPHER_DIRECTION cipher_dir, const struct gcm_key_data *key,
                  struct gcm_context_data **ctx, uint8_t **out, const uint8_t *in,
                  const uint64_t len, const uint8_t *iv, const uint64_t iv_len, const uint8_t *aad,
                  const uint64_t aad_len, uint8_t **auth_tag, const uint64_t auth_tag_len,
                  const IMB_KEY_SIZE_BYTES key_len, const uint32_t num_jobs)
{
        if (aes_gcm_burst(p_mgr, cipher_dir, key, key_len, out, in, len, iv, iv_len, aad, aad_len,
                          auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM_SGL, IMB_SGL_INIT,
                          num_jobs) < 0)
                return -1;
        if (aes_gcm_burst(p_mgr, cipher_dir, key, key_len, out, in, len, iv, iv_len, aad, aad_len,
                          auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM_SGL, IMB_SGL_UPDATE,
                          num_jobs) < 0)
                return -1;
        if (aes_gcm_burst(p_mgr, cipher_dir, key, key_len, out, in, len, iv, iv_len, aad, aad_len,
                          auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM_SGL, IMB_SGL_COMPLETE,
                          num_jobs) < 0)
                return -1;

        return 0;
}

static int
burst_sgl_aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data **ctx,
                      uint8_t **out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                      const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                      uint8_t **auth_tag, const uint64_t auth_tag_len,
                      const IMB_KEY_SIZE_BYTES key_len, const uint32_t num_jobs)
{
        return burst_sgl_aes_gcm(p_mgr, IMB_DIR_ENCRYPT, key, ctx, out, in, len, iv, iv_len, aad,
                                 aad_len, auth_tag, auth_tag_len, key_len, num_jobs);
}

static int
burst_sgl_aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data **ctx,
                      uint8_t **out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                      const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                      uint8_t **auth_tag, const uint64_t auth_tag_len,
                      const IMB_KEY_SIZE_BYTES key_len, const uint32_t num_jobs)
{
        return burst_sgl_aes_gcm(p_mgr, IMB_DIR_DECRYPT, key, ctx, out, in, len, iv, iv_len, aad,
                                 aad_len, auth_tag, auth_tag_len, key_len, num_jobs);
}

/*****************************************************************************
 * job API
 *****************************************************************************/
static int
aes_gcm_job(IMB_MGR *mb_mgr, IMB_CIPHER_DIRECTION cipher_dir, const struct gcm_key_data *key,
            const uint64_t key_len, uint8_t *out, const uint8_t *in, const uint64_t len,
            const uint8_t *iv, const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
            uint8_t *auth_tag, const uint64_t auth_tag_len, struct gcm_context_data *ctx,
            const IMB_CIPHER_MODE cipher_mode, const IMB_SGL_STATE sgl_state)
{
        IMB_JOB *job;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        if (!job) {
                fprintf(stderr, "failed to get job\n");
                return -1;
        }

        job->cipher_mode = cipher_mode;
        job->chain_order =
                (cipher_dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;
        job->enc_keys = key;
        job->dec_keys = key;
        job->key_len_in_bytes = key_len;
        job->src = in;
        job->dst = out;
        job->msg_len_to_cipher_in_bytes = len;
        job->cipher_start_src_offset_in_bytes = UINT64_C(0);
        job->iv = iv;
        job->iv_len_in_bytes = iv_len;
        job->u.GCM.aad = aad;
        job->u.GCM.aad_len_in_bytes = aad_len;
        job->auth_tag_output = auth_tag;
        job->auth_tag_output_len_in_bytes = auth_tag_len;
        job->cipher_direction = cipher_dir;
        if (cipher_mode == IMB_CIPHER_GCM_SGL) {
                job->u.GCM.ctx = ctx;
                job->sgl_state = sgl_state;
                job->hash_alg = IMB_AUTH_GCM_SGL;
        } else
                job->hash_alg = IMB_AUTH_AES_GMAC;
        job = IMB_SUBMIT_JOB(mb_mgr);

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "failed job, status:%d\n", job->status);
                return -1;
        }

        return 0;
}

static int
job_aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                uint8_t *auth_tag, const uint64_t auth_tag_len, const IMB_KEY_SIZE_BYTES key_len)
{
        return aes_gcm_job(p_mgr, IMB_DIR_ENCRYPT, key, key_len, out, in, len, iv, iv_len, aad,
                           aad_len, auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM, 0);
}

static int
job_aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                uint8_t *auth_tag, const uint64_t auth_tag_len, const IMB_KEY_SIZE_BYTES key_len)
{
        return aes_gcm_job(p_mgr, IMB_DIR_DECRYPT, key, key_len, out, in, len, iv, iv_len, aad,
                           aad_len, auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM, 0);
}

static int
job_sgl_aes_gcm(IMB_MGR *p_mgr, const IMB_CIPHER_DIRECTION cipher_dir,
                const struct gcm_key_data *key, struct gcm_context_data *ctx, uint8_t *out,
                const uint8_t *in, const uint64_t len, const uint8_t *iv, const uint64_t iv_len,
                const uint8_t *aad, const uint64_t aad_len, uint8_t *auth_tag,
                const uint64_t auth_tag_len, const IMB_KEY_SIZE_BYTES key_len)
{
        if (aes_gcm_job(p_mgr, cipher_dir, key, key_len, out, in, len, iv, iv_len, aad, aad_len,
                        auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM_SGL, IMB_SGL_INIT) < 0)
                return -1;
        if (aes_gcm_job(p_mgr, cipher_dir, key, key_len, out, in, len, iv, iv_len, aad, aad_len,
                        auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM_SGL, IMB_SGL_UPDATE) < 0)
                return -1;
        if (aes_gcm_job(p_mgr, cipher_dir, key, key_len, out, in, len, iv, iv_len, aad, aad_len,
                        auth_tag, auth_tag_len, ctx, IMB_CIPHER_GCM_SGL, IMB_SGL_COMPLETE) < 0)
                return -1;
        return 0;
}

static int
aes_gcm_single_job_sgl(IMB_MGR *mb_mgr, IMB_CIPHER_DIRECTION cipher_dir,
                       const struct gcm_key_data *key, const uint64_t key_len,
                       struct IMB_SGL_IOV *sgl_segs, const unsigned num_sgl_segs, const uint8_t *iv,
                       const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                       uint8_t *auth_tag, const uint64_t auth_tag_len, struct gcm_context_data *ctx)
{
        IMB_JOB *job;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        if (!job) {
                fprintf(stderr, "failed to get job\n");
                return -1;
        }

        job->cipher_mode = IMB_CIPHER_GCM_SGL;
        job->cipher_direction = cipher_dir;
        job->hash_alg = IMB_AUTH_GCM_SGL;
        job->chain_order =
                (cipher_dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;
        job->enc_keys = key;
        job->dec_keys = key;
        job->key_len_in_bytes = key_len;
        job->num_sgl_io_segs = num_sgl_segs;
        job->sgl_io_segs = sgl_segs;
        job->cipher_start_src_offset_in_bytes = UINT64_C(0);
        job->iv = iv;
        job->iv_len_in_bytes = iv_len;
        job->u.GCM.aad = aad;
        job->u.GCM.aad_len_in_bytes = aad_len;
        job->auth_tag_output = auth_tag;
        job->auth_tag_output_len_in_bytes = auth_tag_len;
        job->u.GCM.ctx = ctx;
        job->sgl_state = IMB_SGL_ALL;
        job = IMB_SUBMIT_JOB(mb_mgr);

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "failed job, status:%d\n", job->status);
                return -1;
        }

        return 0;
}

static int
job_sgl_aes_gcm_enc(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                    const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                    uint8_t *auth_tag, const uint64_t auth_tag_len,
                    const IMB_KEY_SIZE_BYTES key_len)
{
        return job_sgl_aes_gcm(p_mgr, IMB_DIR_ENCRYPT, key, ctx, out, in, len, iv, iv_len, aad,
                               aad_len, auth_tag, auth_tag_len, key_len);
}

static int
job_sgl_aes_gcm_dec(IMB_MGR *p_mgr, const struct gcm_key_data *key, struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
                    const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len,
                    uint8_t *auth_tag, const uint64_t auth_tag_len,
                    const IMB_KEY_SIZE_BYTES key_len)
{
        return job_sgl_aes_gcm(p_mgr, IMB_DIR_DECRYPT, key, ctx, out, in, len, iv, iv_len, aad,
                               aad_len, auth_tag, auth_tag_len, key_len);
}

/*****************************************************************************/

static void
test_gcm_vectors(struct aead_test const *vector, gcm_enc_dec_fn_t encfn, gcm_enc_dec_fn_t decfn,
                 struct test_suite_context *ts)
{
        struct gcm_key_data gdata_key;
        struct gcm_context_data gdata_ctx;
        int is_error = 0;
        /* Temporary array for the calculated vectors */
        uint8_t *ct_test = NULL;
        uint8_t *pt_test = NULL;
        uint8_t *T_test = NULL;
        uint8_t *T2_test = NULL;
        const uint8_t *iv = (const void *) vector->iv;
        const uint64_t iv_len = vector->ivSize / 8;

        if (vector->msgSize / 8 != 0) {
                /* Allocate space for the calculated ciphertext */
                ct_test = malloc(vector->msgSize / 8);
                if (ct_test == NULL) {
                        fprintf(stderr, "Can't allocate ciphertext memory\n");
                        goto test_gcm_vectors_exit;
                }
                /* Allocate space for the calculated plaintext */
                pt_test = malloc(vector->msgSize / 8);
                if (pt_test == NULL) {
                        fprintf(stderr, "Can't allocate plaintext memory\n");
                        goto test_gcm_vectors_exit;
                }
        }

        T_test = malloc(vector->tagSize / 8);
        if (T_test == NULL) {
                fprintf(stderr, "Can't allocate tag memory\n");
                goto test_gcm_vectors_exit;
        }
        memset(T_test, 0, vector->tagSize / 8);

        T2_test = malloc(vector->tagSize / 8);
        if (T2_test == NULL) {
                fprintf(stderr, "Can't allocate tag(2) memory\n");
                goto test_gcm_vectors_exit;
        }
        memset(T2_test, 0, vector->tagSize / 8);

        /* This is only required once for a given key */
        switch (vector->keySize / 8) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_PRE(p_gcm_mgr, vector->key, &gdata_key);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_PRE(p_gcm_mgr, vector->key, &gdata_key);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_PRE(p_gcm_mgr, vector->key, &gdata_key);
                break;
        }

        /*
         * Encrypt
         */
        is_error = encfn(p_gcm_mgr, &gdata_key, &gdata_ctx, ct_test, (const void *) vector->msg,
                         vector->msgSize / 8, iv, iv_len, (const void *) vector->aad,
                         vector->aadSize / 8, T_test, vector->tagSize / 8, vector->keySize / 8);
        is_error |= check_data(ct_test, (const void *) vector->ct, vector->msgSize / 8,
                               "encrypted cipher text (C)");
        is_error |= check_data(T_test, (const void *) vector->tag, vector->tagSize / 8, "tag (T)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

        /* test of in-place encrypt */
        memory_copy(pt_test, (const void *) vector->msg, vector->msgSize / 8);
        is_error = encfn(p_gcm_mgr, &gdata_key, &gdata_ctx, pt_test, pt_test, vector->msgSize / 8,
                         iv, iv_len, (const void *) vector->aad, vector->aadSize / 8, T_test,
                         vector->tagSize / 8, vector->keySize / 8);
        is_error |= check_data(pt_test, (const void *) vector->ct, vector->msgSize / 8,
                               "encrypted cipher text(in-place)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

        memory_set(ct_test, 0, vector->msgSize / 8);
        memory_set(T_test, 0, vector->tagSize / 8);

        /*
         * Decrypt
         */
        is_error = decfn(p_gcm_mgr, &gdata_key, &gdata_ctx, pt_test, (const void *) vector->ct,
                         vector->msgSize / 8, iv, iv_len, (const void *) vector->aad,
                         vector->aadSize / 8, T_test, vector->tagSize / 8, vector->keySize / 8);
        is_error |= check_data(pt_test, (const void *) vector->msg, vector->msgSize / 8,
                               "decrypted plain text (P)");
        /*
         * GCM decryption outputs a 16 byte tag value
         * that must be verified against the expected tag value
         */
        is_error |= check_data(T_test, (const void *) vector->tag, vector->tagSize / 8,
                               "decrypted tag (T)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

        /* test in in-place decrypt */
        memory_copy(ct_test, (const void *) vector->ct, vector->msgSize / 8);
        is_error = decfn(p_gcm_mgr, &gdata_key, &gdata_ctx, ct_test, ct_test, vector->msgSize / 8,
                         iv, iv_len, (const void *) vector->aad, vector->aadSize / 8, T_test,
                         vector->tagSize / 8, vector->keySize / 8);
        is_error |= check_data(ct_test, (const void *) vector->msg, vector->msgSize / 8,
                               "plain text (P) - in-place");
        is_error |= check_data(T_test, (const void *) vector->tag, vector->tagSize / 8,
                               "decrypted tag (T) - in-place");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);
        /* enc -> dec */
        is_error = encfn(p_gcm_mgr, &gdata_key, &gdata_ctx, ct_test, (const void *) vector->msg,
                         vector->msgSize / 8, iv, iv_len, (const void *) vector->aad,
                         vector->aadSize / 8, T_test, vector->tagSize / 8, vector->keySize / 8);

        memory_set(pt_test, 0, vector->msgSize / 8);

        is_error |= decfn(p_gcm_mgr, &gdata_key, &gdata_ctx, pt_test, ct_test, vector->msgSize / 8,
                          iv, iv_len, (const void *) vector->aad, vector->aadSize / 8, T2_test,
                          vector->tagSize / 8, vector->keySize / 8);
        is_error |= check_data(pt_test, (const void *) vector->msg, vector->msgSize / 8,
                               "self decrypted plain text (P)");
        is_error |= check_data(T_test, T2_test, vector->tagSize / 8, "self decrypted tag (T)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

test_gcm_vectors_exit:
        if (NULL != ct_test)
                free(ct_test);
        if (NULL != pt_test)
                free(pt_test);
        if (NULL != T_test)
                free(T_test);
        if (NULL != T2_test)
                free(T2_test);
}

static void
test_gcm_vectors_burst(struct aead_test const *vector, gcm_enc_dec_many_fn_t encfn,
                       gcm_enc_dec_many_fn_t decfn, struct test_suite_context *ts)
{
        struct gcm_key_data gdata_key;
        int is_error = 0;
        /* Temporary array for the calculated vectors */
        struct gcm_context_data **gdata_ctx = NULL;
        uint8_t **ct_test = NULL;
        uint8_t **pt_test = NULL;
        uint8_t **T_test = NULL;
        const uint8_t *iv = (const void *) vector->iv;
        const uint64_t iv_len = vector->ivSize / 8;
        uint32_t i, j;
        const uint32_t num_jobs = GCM_MAX_JOBS;

        /* Allocate space for the calculated ciphertext */
        ct_test = malloc(num_jobs * sizeof(void *));
        if (ct_test == NULL) {
                fprintf(stderr, "Can't allocate ciphertext memory\n");
                goto test_gcm_vectors_burst_exit;
        }
        memset(ct_test, 0, num_jobs * sizeof(void *));

        /* Allocate space for the calculated plaintext */
        pt_test = malloc(num_jobs * sizeof(void *));
        if (pt_test == NULL) {
                fprintf(stderr, "Can't allocate plaintext memory\n");
                goto test_gcm_vectors_burst_exit;
        }
        memset(pt_test, 0, num_jobs * sizeof(void *));

        /* Allocate space for the GCM context data */
        gdata_ctx = malloc(num_jobs * sizeof(void *));
        if (gdata_ctx == NULL) {
                fprintf(stderr, "Can't allocate GCM ctx memory\n");
                goto test_gcm_vectors_burst_exit;
        }
        memset(gdata_ctx, 0, num_jobs * sizeof(void *));

        /* Allocate space for the calculated tag */
        T_test = malloc(num_jobs * sizeof(void *));
        if (T_test == NULL) {
                fprintf(stderr, "Can't allocate tag memory\n");
                goto test_gcm_vectors_burst_exit;
        }
        memset(T_test, 0, num_jobs * sizeof(void *));

        /* Zero buffers */
        for (i = 0; i < num_jobs; i++) {
                if (vector->msgSize / 8 != 0) {
                        ct_test[i] = malloc(vector->msgSize / 8);
                        if (ct_test[i] == NULL)
                                goto test_gcm_vectors_burst_exit;
                        memset(ct_test[i], 0, vector->msgSize / 8);

                        pt_test[i] = malloc(vector->msgSize / 8);
                        if (pt_test[i] == NULL)
                                goto test_gcm_vectors_burst_exit;
                        memset(pt_test[i], 0, vector->msgSize / 8);
                }

                gdata_ctx[i] = malloc(sizeof(struct gcm_context_data));
                if (gdata_ctx[i] == NULL)
                        goto test_gcm_vectors_burst_exit;
                memset(gdata_ctx[i], 0, sizeof(struct gcm_context_data));

                T_test[i] = malloc(vector->tagSize / 8);
                if (T_test[i] == NULL)
                        goto test_gcm_vectors_burst_exit;
                memset(T_test[i], 0, vector->tagSize / 8);
        }

        /* This is only required once for a given key */
        switch (vector->keySize / 8) {
        case IMB_KEY_128_BYTES:
                IMB_AES128_GCM_PRE(p_gcm_mgr, vector->key, &gdata_key);
                break;
        case IMB_KEY_192_BYTES:
                IMB_AES192_GCM_PRE(p_gcm_mgr, vector->key, &gdata_key);
                break;
        case IMB_KEY_256_BYTES:
        default:
                IMB_AES256_GCM_PRE(p_gcm_mgr, vector->key, &gdata_key);
                break;
        }

        /* Test encrypt and decrypt */
        for (i = 0; i < num_jobs; i++) {
                /*
                 * Encrypt
                 */
                is_error = encfn(p_gcm_mgr, &gdata_key, gdata_ctx, ct_test,
                                 (const void *) vector->msg, vector->msgSize / 8, iv, iv_len,
                                 (const void *) vector->aad, vector->aadSize / 8, T_test,
                                 vector->tagSize / 8, vector->keySize / 8, i + 1);

                for (j = 0; j <= i; j++) {
                        is_error |=
                                check_data(ct_test[j], (const void *) vector->ct,
                                           vector->msgSize / 8, "encrypted cipher text (burst)");
                        is_error |= check_data(T_test[j], (const void *) vector->tag,
                                               vector->tagSize / 8, "tag (burst)");
                }
                if (is_error)
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
                /*
                 * Decrypt
                 */
                is_error = decfn(p_gcm_mgr, &gdata_key, gdata_ctx, pt_test,
                                 (const void *) vector->ct, vector->msgSize / 8, iv, iv_len,
                                 (const void *) vector->aad, vector->aadSize / 8, T_test,
                                 vector->tagSize / 8, vector->keySize / 8, i + 1);

                for (j = 0; j <= i; j++) {
                        is_error |= check_data(pt_test[j], (const void *) vector->msg,
                                               vector->msgSize / 8, "decrypted plain text (burst)");
                        /*
                         * GCM decryption outputs a 16 byte tag value
                         * that must be verified against the expected tag value
                         */
                        is_error |= check_data(T_test[j], (const void *) vector->tag,
                                               vector->tagSize / 8, "decrypted tag (burst)");
                }
                if (is_error)
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
        }

test_gcm_vectors_burst_exit:
        if (NULL != ct_test) {
                for (i = 0; i < num_jobs; i++)
                        free(ct_test[i]);
                free(ct_test);
        }
        if (NULL != pt_test) {
                for (i = 0; i < num_jobs; i++)
                        free(pt_test[i]);
                free(pt_test);
        }
        if (NULL != gdata_ctx) {
                for (i = 0; i < num_jobs; i++)
                        free(gdata_ctx[i]);
                free(gdata_ctx);
        }
        if (NULL != T_test) {
                for (i = 0; i < num_jobs; i++)
                        free(T_test[i]);
                free(T_test);
        }
}

static void
test_gcm_std_vectors(struct test_suite_context *ts128, struct test_suite_context *ts192,
                     struct test_suite_context *ts256, const struct aead_test *v,
                     const int test_sgl_api)
{

        printf("AES-GCM (%s API) standard test vectors:\n", test_sgl_api ? "SGL" : "Direct/JOB");
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  Keylen:%zu IVlen:%zu "
                               "PTLen:%zu AADlen:%zu Tlen:%zu\n",
                               v->tcId, v->keySize / 8, v->ivSize / 8, v->msgSize / 8,
                               v->aadSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        if (test_sgl_api) {
                                test_gcm_vectors(v, sgl_aes_gcm_enc, sgl_aes_gcm_dec, ts128);
                                test_gcm_vectors(v, job_sgl_aes_gcm_enc, job_sgl_aes_gcm_dec,
                                                 ts128);
                                test_gcm_vectors_burst(v, burst_sgl_aes_gcm_enc,
                                                       burst_sgl_aes_gcm_dec, ts128);
                        } else {
                                test_gcm_vectors(v, aes_gcm_enc, aes_gcm_dec, ts128);
                                test_gcm_vectors(v, job_aes_gcm_enc, job_aes_gcm_dec, ts128);
                                test_gcm_vectors_burst(v, burst_aes_gcm_enc, burst_aes_gcm_dec,
                                                       ts128);
                                test_gcm_vectors(v, quic_aes_gcm_enc, quic_aes_gcm_dec, ts128);
                                test_gcm_vectors_burst(v, burst_quic_gcm_enc, burst_quic_gcm_dec,
                                                       ts128);
                        }
                        break;
                case IMB_KEY_192_BYTES:
                        if (test_sgl_api) {
                                test_gcm_vectors(v, sgl_aes_gcm_enc, sgl_aes_gcm_dec, ts192);
                                test_gcm_vectors(v, job_sgl_aes_gcm_enc, job_sgl_aes_gcm_dec,
                                                 ts192);
                                test_gcm_vectors_burst(v, burst_sgl_aes_gcm_enc,
                                                       burst_sgl_aes_gcm_dec, ts192);
                        } else {
                                test_gcm_vectors(v, aes_gcm_enc, aes_gcm_dec, ts192);
                                test_gcm_vectors(v, job_aes_gcm_enc, job_aes_gcm_dec, ts192);
                                test_gcm_vectors_burst(v, burst_aes_gcm_enc, burst_aes_gcm_dec,
                                                       ts192);
                                /* AES-192 is not supported by QUIC */
                        }
                        break;
                case IMB_KEY_256_BYTES:
                        if (test_sgl_api) {
                                test_gcm_vectors(v, sgl_aes_gcm_enc, sgl_aes_gcm_dec, ts256);
                                test_gcm_vectors(v, job_sgl_aes_gcm_enc, job_sgl_aes_gcm_dec,
                                                 ts256);
                                test_gcm_vectors_burst(v, burst_sgl_aes_gcm_enc,
                                                       burst_sgl_aes_gcm_dec, ts256);

                        } else {
                                test_gcm_vectors(v, aes_gcm_enc, aes_gcm_dec, ts256);
                                test_gcm_vectors(v, job_aes_gcm_enc, job_aes_gcm_dec, ts256);
                                test_gcm_vectors_burst(v, burst_aes_gcm_enc, burst_aes_gcm_dec,
                                                       ts256);
                                test_gcm_vectors(v, quic_aes_gcm_enc, quic_aes_gcm_dec, ts256);
                                test_gcm_vectors_burst(v, burst_quic_gcm_enc, burst_quic_gcm_dec,
                                                       ts256);
                        }
                        break;
                default:
                        printf("ERROR: wrong key size error in the table\n");
                        return;
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static int
test_single_job_sgl(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const uint32_t key_sz,
                    const uint32_t buffer_sz, const uint32_t seg_sz,
                    const IMB_CIPHER_DIRECTION cipher_dir)
{
        uint8_t *in_buffer = NULL;
        uint8_t **segments = NULL;
        uint8_t linear_digest[DIGEST_SZ];
        uint8_t sgl_digest[DIGEST_SZ];
        uint8_t k[MAX_KEY_SZ];
        unsigned int i;
        uint8_t aad[AAD_SZ];
        uint8_t iv[IV_SZ];
        struct gcm_context_data gcm_ctx;
        struct gcm_key_data key;
        uint32_t last_seg_sz = buffer_sz % seg_sz;
        struct IMB_SGL_IOV *sgl_segs = NULL;
        const uint32_t num_segments = DIV_ROUND_UP(buffer_sz, seg_sz);
        int ret = -1;

        if (last_seg_sz == 0)
                last_seg_sz = seg_sz;

        sgl_segs = malloc(sizeof(struct IMB_SGL_IOV) * num_segments);
        if (sgl_segs == NULL) {
                fprintf(stderr, "Could not allocate memory for SGL segments\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        in_buffer = malloc(buffer_sz);
        if (in_buffer == NULL) {
                fprintf(stderr, "Could not allocate memory for input buffer\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        /*
         * Initialize tags with different values, to make sure the comparison
         * is false if they are not updated by the library
         */
        memset(sgl_digest, 0, DIGEST_SZ);
        memset(linear_digest, 0xFF, DIGEST_SZ);

        generate_random_buf(in_buffer, buffer_sz);
        generate_random_buf(k, key_sz);
        generate_random_buf(iv, IV_SZ);
        generate_random_buf(aad, AAD_SZ);

        if (key_sz == IMB_KEY_128_BYTES)
                IMB_AES128_GCM_PRE(mb_mgr, k, &key);
        else if (key_sz == IMB_KEY_192_BYTES)
                IMB_AES192_GCM_PRE(mb_mgr, k, &key);
        else /* key_sz == 32 */
                IMB_AES256_GCM_PRE(mb_mgr, k, &key);

        segments = malloc(num_segments * sizeof(*segments));
        if (segments == NULL) {
                fprintf(stderr, "Could not allocate memory for segments array\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memset(segments, 0, num_segments * sizeof(*segments));

        for (i = 0; i < (num_segments - 1); i++) {
                segments[i] = malloc(seg_sz);
                if (segments[i] == NULL) {
                        fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                }
                memcpy(segments[i], in_buffer + seg_sz * i, seg_sz);
                sgl_segs[i].in = segments[i];
                sgl_segs[i].out = segments[i];
                sgl_segs[i].len = seg_sz;
        }
        segments[i] = malloc(last_seg_sz);
        if (segments[i] == NULL) {
                fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memcpy(segments[i], in_buffer + seg_sz * i, last_seg_sz);
        sgl_segs[i].in = segments[i];
        sgl_segs[i].out = segments[i];
        sgl_segs[i].len = last_seg_sz;

        /* Process linear (single segment) buffer */
        if (aes_gcm_job(mb_mgr, cipher_dir, &key, key_sz, in_buffer, in_buffer, buffer_sz, iv,
                        IV_SZ, aad, AAD_SZ, linear_digest, DIGEST_SZ, &gcm_ctx, IMB_CIPHER_GCM,
                        0) < 0) {
                test_suite_update(ctx, 0, 1);
                goto exit;
        } else
                test_suite_update(ctx, 1, 0);

        /* Process multi-segment buffer */
        aes_gcm_single_job_sgl(mb_mgr, cipher_dir, &key, key_sz, sgl_segs, num_segments, iv, IV_SZ,
                               aad, AAD_SZ, sgl_digest, DIGEST_SZ, &gcm_ctx);

        for (i = 0; i < (num_segments - 1); i++) {
                if (memcmp(in_buffer + i * seg_sz, segments[i], seg_sz) != 0) {
                        printf("ciphertext mismatched in segment number %u "
                               "(segment size = %u)\n",
                               i, seg_sz);
                        hexdump(stderr, "Expected output", in_buffer + i * seg_sz, seg_sz);
                        hexdump(stderr, "SGL output", segments[i], seg_sz);
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                }
        }
        /* Check last segment */
        if (memcmp(in_buffer + i * seg_sz, segments[i], last_seg_sz) != 0) {
                printf("ciphertext mismatched "
                       "in segment number %u (segment size = %u)\n",
                       i, seg_sz);
                hexdump(stderr, "Expected output", in_buffer + i * seg_sz, last_seg_sz);
                hexdump(stderr, "SGL output", segments[i], last_seg_sz);
                test_suite_update(ctx, 0, 1);
        }
        if (memcmp(sgl_digest, linear_digest, 16) != 0) {
                printf("hash mismatched (segment size = %u)\n", seg_sz);
                hexdump(stderr, "Expected digest", linear_digest, DIGEST_SZ);
                hexdump(stderr, "SGL digest", sgl_digest, DIGEST_SZ);
                test_suite_update(ctx, 0, 1);
        } else {
                test_suite_update(ctx, 1, 0);
                ret = 0;
        }

exit:
        free(sgl_segs);
        free(in_buffer);
        if (segments != NULL) {
                for (i = 0; i < num_segments; i++)
                        free(segments[i]);
                free(segments);
        }
        return ret;
}

static int
test_sgl(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const uint32_t key_sz,
         const uint32_t buffer_sz, const uint32_t seg_sz, const IMB_CIPHER_DIRECTION cipher_dir,
         const unsigned job_api)
{
        uint8_t *in_buffer = NULL;
        uint8_t **segments = NULL;
        uint32_t *segment_sizes = NULL;
        uint32_t num_segments;
        uint8_t linear_digest[DIGEST_SZ];
        uint8_t sgl_digest[DIGEST_SZ];
        uint8_t k[MAX_KEY_SZ];
        unsigned int i;
        uint8_t aad[AAD_SZ];
        uint8_t iv[IV_SZ];
        struct gcm_context_data gcm_ctx;
        struct gcm_key_data key;
        uint32_t last_seg_sz = buffer_sz % seg_sz;
        int ret = -1;

        num_segments = (buffer_sz + (seg_sz - 1)) / seg_sz;
        if (last_seg_sz == 0)
                last_seg_sz = seg_sz;

        in_buffer = malloc(buffer_sz);
        if (in_buffer == NULL) {
                fprintf(stderr, "Could not allocate memory for input buffer\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        /*
         * Initialize tags with different values, to make sure the comparison
         * is false if they are not updated by the library
         */
        memset(sgl_digest, 0, DIGEST_SZ);
        memset(linear_digest, 0xFF, DIGEST_SZ);

        generate_random_buf(in_buffer, buffer_sz);
        generate_random_buf(k, key_sz);
        generate_random_buf(iv, IV_SZ);
        generate_random_buf(aad, AAD_SZ);

        if (key_sz == IMB_KEY_128_BYTES)
                IMB_AES128_GCM_PRE(mb_mgr, k, &key);
        else if (key_sz == IMB_KEY_192_BYTES)
                IMB_AES192_GCM_PRE(mb_mgr, k, &key);
        else /* key_sz == 32 */
                IMB_AES256_GCM_PRE(mb_mgr, k, &key);

        segments = malloc(num_segments * sizeof(*segments));
        if (segments == NULL) {
                fprintf(stderr, "Could not allocate memory for segments array\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memset(segments, 0, num_segments * sizeof(*segments));

        segment_sizes = malloc(num_segments * sizeof(*segment_sizes));
        if (segment_sizes == NULL) {
                fprintf(stderr, "Could not allocate memory for array of sizes\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        for (i = 0; i < (num_segments - 1); i++) {
                segments[i] = malloc(seg_sz);
                if (segments[i] == NULL) {
                        fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                }
                memcpy(segments[i], in_buffer + seg_sz * i, seg_sz);
                segment_sizes[i] = seg_sz;
        }
        segments[i] = malloc(last_seg_sz);
        if (segments[i] == NULL) {
                fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memcpy(segments[i], in_buffer + seg_sz * i, last_seg_sz);
        segment_sizes[i] = last_seg_sz;

        /* Process linear (single segment) buffer */
        if (aes_gcm_job(mb_mgr, cipher_dir, &key, key_sz, in_buffer, in_buffer, buffer_sz, iv,
                        IV_SZ, aad, AAD_SZ, linear_digest, DIGEST_SZ, &gcm_ctx, IMB_CIPHER_GCM,
                        0) < 0) {
                test_suite_update(ctx, 0, 1);
                goto exit;
        } else
                test_suite_update(ctx, 1, 0);

        /* Process multi-segment buffer */
        if (job_api) {
                if (aes_gcm_job(mb_mgr, cipher_dir, &key, key_sz, NULL, NULL, 0, iv, IV_SZ, aad,
                                AAD_SZ, NULL, 0, &gcm_ctx, IMB_CIPHER_GCM_SGL, IMB_SGL_INIT) < 0) {
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                } else
                        test_suite_update(ctx, 1, 0);
        } else {
                imb_aes_gcm_init(mb_mgr, &key, &gcm_ctx, iv, IV_SZ, aad, AAD_SZ, key_sz);
                test_suite_update(ctx, 1, 0);
        }

        for (i = 0; i < (num_segments + 1); i++) {
                uint64_t seg_size = 0;
                uint8_t *seg_ptr = NULL;

                if (i < num_segments) {
                        seg_size = segment_sizes[i];
                        seg_ptr = segments[i];
                }
#if VERBOSE != 0
                printf("gcm-sgl: job-api=%c, segment=%u, #segments=%u, "
                       "size=%u bytes\n",
                       job_api ? 'y' : 'n', i, num_segments, (unsigned) seg_size);
#endif
                if (job_api) {
                        if (aes_gcm_job(mb_mgr, cipher_dir, &key, key_sz, seg_ptr, seg_ptr,
                                        seg_size, iv, IV_SZ, NULL, 0, NULL, 0, &gcm_ctx,
                                        IMB_CIPHER_GCM_SGL, IMB_SGL_UPDATE) < 0) {
                                test_suite_update(ctx, 0, 1);
                                goto exit;
                        }
                } else {
                        if (cipher_dir == IMB_DIR_ENCRYPT) {
                                imb_aes_gcm_enc_update(mb_mgr, &key, &gcm_ctx, seg_ptr, seg_ptr,
                                                       seg_size, key_sz);
                        } else {
                                imb_aes_gcm_dec_update(mb_mgr, &key, &gcm_ctx, seg_ptr, seg_ptr,
                                                       seg_size, key_sz);
                        }
                }
        }

        if (job_api) {
                if (aes_gcm_job(mb_mgr, cipher_dir, &key, key_sz, NULL, NULL, 0, iv, IV_SZ, NULL, 0,
                                sgl_digest, DIGEST_SZ, &gcm_ctx, IMB_CIPHER_GCM_SGL,
                                IMB_SGL_COMPLETE) < 0) {
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                }
        } else {
                if (cipher_dir == IMB_DIR_ENCRYPT)
                        imb_aes_gcm_enc_finalize(mb_mgr, &key, &gcm_ctx, sgl_digest, DIGEST_SZ,
                                                 key_sz);
                else
                        imb_aes_gcm_dec_finalize(mb_mgr, &key, &gcm_ctx, sgl_digest, DIGEST_SZ,
                                                 key_sz);
        }

        for (i = 0; i < (num_segments - 1); i++) {
                if (memcmp(in_buffer + i * seg_sz, segments[i], seg_sz) != 0) {
                        printf("ciphertext mismatched in segment number %u "
                               "(segment size = %u)\n",
                               i, seg_sz);
                        hexdump(stderr, "Expected output", in_buffer + i * seg_sz, seg_sz);
                        hexdump(stderr, "SGL output", segments[i], seg_sz);
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                }
        }
        /* Check last segment */
        if (memcmp(in_buffer + i * seg_sz, segments[i], last_seg_sz) != 0) {
                printf("ciphertext mismatched in segment number %u (segment size = %u)\n", i,
                       seg_sz);
                hexdump(stderr, "Expected output", in_buffer + i * seg_sz, last_seg_sz);
                hexdump(stderr, "SGL output", segments[i], last_seg_sz);
                test_suite_update(ctx, 0, 1);
        }
        if (memcmp(sgl_digest, linear_digest, 16) != 0) {
                printf("hash mismatched (segment size = %u)\n", seg_sz);
                hexdump(stderr, "Expected digest", linear_digest, DIGEST_SZ);
                hexdump(stderr, "SGL digest", sgl_digest, DIGEST_SZ);
                test_suite_update(ctx, 0, 1);
        } else {
                test_suite_update(ctx, 1, 0);
                ret = 0;
        }

exit:
        free(in_buffer);
        if (segments != NULL) {
                for (i = 0; i < num_segments; i++)
                        free(segments[i]);
                free(segments);
        }
        free(segment_sizes);

        return ret;
}

int
gcm_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts128, ts192, ts256;
        struct test_suite_context *ctx;
        uint32_t key_sz;
        const uint32_t buf_sz = 2032;
        const uint32_t seg_sz_step = 4;
        const uint32_t max_seg_sz = 2048;
        int errors = 0;

        p_gcm_mgr = p_mgr;

        test_suite_start(&ts128, "AES-GCM-128");
        test_suite_start(&ts192, "AES-GCM-192");
        test_suite_start(&ts256, "AES-GCM-256");
        test_gcm_std_vectors(&ts128, &ts192, &ts256, gcm_test_json, 0);
        errors = test_suite_end(&ts128);
        errors += test_suite_end(&ts192);
        errors += test_suite_end(&ts256);

        test_suite_start(&ts128, "SGL-GCM-128");
        test_suite_start(&ts192, "SGL-GCM-192");
        test_suite_start(&ts256, "SGL-GCM-256");
        test_gcm_std_vectors(&ts128, &ts192, &ts256, gcm_test_json, 1);
        /* SGL test comparing linear buffer with segmented buffers */
        for (key_sz = IMB_KEY_128_BYTES; key_sz <= IMB_KEY_256_BYTES; key_sz += 16) {
                if (key_sz == IMB_KEY_128_BYTES)
                        ctx = &ts128;
                else if (key_sz == IMB_KEY_192_BYTES)
                        ctx = &ts192;
                else
                        ctx = &ts256;

                uint32_t seg_sz;

                for (seg_sz = seg_sz_step; seg_sz <= max_seg_sz; seg_sz += seg_sz_step) {
                        /* Job API */
                        if (test_sgl(p_mgr, ctx, key_sz, buf_sz, seg_sz, IMB_DIR_ENCRYPT, 1) != 0)
                                break;
                        if (test_sgl(p_mgr, ctx, key_sz, buf_sz, seg_sz, IMB_DIR_DECRYPT, 1) != 0)
                                break;
                        /* Single job SGL API */
                        if (test_single_job_sgl(p_mgr, ctx, key_sz, buf_sz, seg_sz,
                                                IMB_DIR_ENCRYPT) != 0)
                                break;
                        if (test_single_job_sgl(p_mgr, ctx, key_sz, buf_sz, seg_sz,
                                                IMB_DIR_DECRYPT) != 0)
                                break;
                        /* Direct API */
                        if (test_sgl(p_mgr, ctx, key_sz, buf_sz, seg_sz, IMB_DIR_ENCRYPT, 0) != 0)
                                break;
                        if (test_sgl(p_mgr, ctx, key_sz, buf_sz, seg_sz, IMB_DIR_DECRYPT, 0) != 0)
                                break;
                }
        }

        errors += test_suite_end(&ts128);
        errors += test_suite_end(&ts192);
        errors += test_suite_end(&ts256);

        return errors;
}
