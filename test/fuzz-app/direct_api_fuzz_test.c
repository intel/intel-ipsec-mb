/**********************************************************************
  Copyright(c) 2022-2023, Intel Corporation All rights reserved.

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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <malloc.h>
#include <intel-ipsec-mb.h>
#include "utils.h"

int
LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int
LLVMFuzzerInitialize(int *, char ***);

IMB_ARCH arch = IMB_ARCH_NONE;

static void
parse_matched(int argc, char **argv)
{
        for (int i = 0; i < argc; i++) {
                if (strcmp(argv[i], "SSE") == 0)
                        arch = IMB_ARCH_SSE;
                else if (strcmp(argv[i], "AVX") == 0)
                        arch = IMB_ARCH_AVX;
                else if (strcmp(argv[i], "AVX2") == 0)
                        arch = IMB_ARCH_AVX2;
                else if (strcmp(argv[i], "AVX512") == 0)
                        arch = IMB_ARCH_AVX512;
        }
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
        for (int i = 0; i < *argc; i++) {
                /*
                 * Check if the current argument matches the
                 * argument we are looking for.
                 */
                if (strcmp((*argv)[i], "custom") == 0) {
                        parse_matched(*argc - (i + 1), &((*argv)[i + 1]));
                        /*
                         *  Remove the matching argument and all arguments
                         * after it from the command line.
                         */
                        *argc = i;

                        break;
                }
        }
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static void
fill_data(void *d, const size_t d_size, const void *s, const size_t s_size)
{
        if (d == NULL || d_size == 0)
                return;

        memset(d, 0, d_size);

        if (s == NULL || s_size == 0)
                return;

        const size_t m_size = (s_size > d_size) ? d_size : s_size;
        memcpy(d, s, m_size);
}

/* ========================================================================== */
/* ========================================================================== */

static snow3g_key_schedule_t *snow3g_exp_key = NULL;
static uint8_t *snow3g_iv = NULL;
static uint32_t *snow3g_digest = NULL;

static void
snow3g_end(void)
{
        if (snow3g_digest != NULL)
                free(snow3g_digest);
        if (snow3g_exp_key != NULL)
                free(snow3g_exp_key);
        if (snow3g_iv != NULL)
                free(snow3g_iv);
        snow3g_exp_key = NULL;
        snow3g_iv = NULL;
        snow3g_digest = NULL;
}

static int
snow3g_start(void)
{
        snow3g_exp_key = (snow3g_key_schedule_t *) malloc(sizeof(snow3g_key_schedule_t));
        snow3g_iv = (uint8_t *) malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
        snow3g_digest = (uint32_t *) malloc(IMB_SNOW3G_DIGEST_LEN);
        if (snow3g_iv == NULL || snow3g_exp_key == NULL || snow3g_digest) {
                snow3g_end();
                return -1;
        }
        return 0;
}

static int
test_snow3g_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < sizeof(snow3g_key_schedule_t))
                return -1;

        if (snow3g_start())
                return -1;

        IMB_SNOW3G_INIT_KEY_SCHED(p_mgr, buff, snow3g_exp_key);

        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_1_buff_bit(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        const size_t dataSizeBits = dataSize * 8;
        const size_t offsetBits = buff[0] % dataSizeBits;
        const uint64_t lenBits = dataSizeBits - offsetBits;

        IMB_SNOW3G_F8_1_BUFFER_BIT(p_mgr, snow3g_exp_key, snow3g_iv, buff, buff, lenBits,
                                   offsetBits);
        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        IMB_SNOW3G_F8_1_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, buff, buff, dataSize);
        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_2_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        IMB_SNOW3G_F8_2_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, snow3g_iv, buff, buff, dataSize,
                               buff, buff, dataSize);
        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        IMB_SNOW3G_F8_4_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv,
                               buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize,
                               buff, buff, dataSize);
        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_8_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        IMB_SNOW3G_F8_8_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv,
                               snow3g_iv, snow3g_iv, snow3g_iv, snow3g_iv, buff, buff, dataSize,
                               buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize,
                               buff, buff, dataSize, buff, buff, dataSize, buff, buff, dataSize,
                               buff, buff, dataSize);
        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];

        for (int i = 0; i < 8; i++) {
                iv[i] = snow3g_iv;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_SNOW3G_F8_N_BUFFER(p_mgr, snow3g_exp_key, iv, in, out, len, 8);
        snow3g_end();
        return 0;
}

struct test_snow3g_mb {
        size_t n;
        const void **iv;
        const void **in;
        void **out;
        uint32_t *len;
        const snow3g_key_schedule_t **key;
};

static void
test_snow3g_mb_free(struct test_snow3g_mb *ts)
{
        if (ts->key != NULL)
                free(ts->key);
        if (ts->iv != NULL)
                free(ts->iv);
        if (ts->out != NULL)
                free(ts->out);
        if (ts->in != NULL)
                free(ts->in);
        if (ts->len != NULL)
                free(ts->len);
        memset(ts, 0, sizeof(*ts));
}

static int
test_snow3g_mb_alloc(struct test_snow3g_mb *ts, const size_t n)
{
        ts->n = n;
        ts->key = malloc(n * sizeof(ts->key[0]));
        ts->iv = malloc(n * sizeof(ts->iv[0]));
        ts->in = malloc(n * sizeof(ts->in[0]));
        ts->out = malloc(n * sizeof(ts->out[0]));
        ts->len = malloc(n * sizeof(ts->len[0]));

        if (ts->key == NULL || ts->iv == NULL || ts->in == NULL || ts->out == NULL ||
            ts->len == NULL) {
                test_snow3g_mb_free(ts);
                return -1;
        }

        return 0;
}

static void
test_snow3g_mb_set1(struct test_snow3g_mb *ts, const snow3g_key_schedule_t *key, const void *iv,
                    const void *in, void *out, const uint32_t len)
{
        for (size_t i = 0; i < ts->n; i++) {
                ts->key[i] = key;
                ts->iv[i] = iv;
                ts->in[i] = in;
                ts->out[i] = out;
                ts->len[i] = len;
        }
}

static int
test_snow3g_f8_8_multikey(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        struct test_snow3g_mb ts;
        const uint32_t n = 8;

        if (test_snow3g_mb_alloc(&ts, n) != 0) {
                snow3g_end();
                return -1;
        }
        test_snow3g_mb_set1(&ts, snow3g_exp_key, snow3g_iv, buff, buff, (uint32_t) dataSize);
        IMB_SNOW3G_F8_8_BUFFER_MULTIKEY(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len);
        test_snow3g_mb_free(&ts);
        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_n_multikey(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;

        struct test_snow3g_mb ts;
        const uint32_t n = 9;

        if (test_snow3g_mb_alloc(&ts, n) != 0) {
                snow3g_end();
                return -1;
        }
        test_snow3g_mb_set1(&ts, snow3g_exp_key, snow3g_iv, buff, buff, (uint32_t) dataSize);
        IMB_SNOW3G_F8_N_BUFFER_MULTIKEY(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len, n);
        test_snow3g_mb_free(&ts);
        snow3g_end();
        return 0;
}

static int
test_snow3g_f9_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (snow3g_start())
                return -1;
        IMB_SNOW3G_F9_1_BUFFER(p_mgr, snow3g_exp_key, snow3g_iv, buff, dataSize, snow3g_digest);
        snow3g_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static struct gcm_key_data *gcm_key = NULL;
static struct gcm_context_data *gcm_ctx = NULL;
static uint8_t *gcm_iv = NULL;
static uint8_t *gcm_aad = NULL;
static uint64_t gcm_aad_len;
static uint8_t *gcm_auth_tag = NULL;
static uint64_t gcm_tag_len;

static void
gcm_end(void)
{
        if (gcm_key != NULL)
                free(gcm_key);
        if (gcm_ctx != NULL)
                free(gcm_ctx);
        if (gcm_iv != NULL)
                free(gcm_iv);
        if (gcm_aad != NULL)
                free(gcm_aad);
        if (gcm_auth_tag != NULL)
                free(gcm_auth_tag);
        gcm_key = NULL;
        gcm_ctx = NULL;
        gcm_iv = NULL;
        gcm_aad = NULL;
        gcm_aad_len = 0;
        gcm_auth_tag = NULL;
        gcm_tag_len = 0;
}

static int
gcm_start(const size_t dataSize, const uint8_t *data)
{
        gcm_key = (struct gcm_key_data *) memalign(16, sizeof(struct gcm_key_data));
        gcm_ctx = (struct gcm_context_data *) memalign(16, sizeof(struct gcm_context_data));
        gcm_iv = (uint8_t *) malloc(IMB_GCM_IV_DATA_LEN);
        gcm_aad_len = dataSize;
        gcm_aad = (uint8_t *) malloc(gcm_aad_len);
        gcm_tag_len = dataSize;
        gcm_auth_tag = (uint8_t *) malloc(gcm_tag_len);
        if (gcm_key == NULL || gcm_ctx == NULL || gcm_iv == NULL || gcm_aad == NULL ||
            gcm_auth_tag == NULL) {
                gcm_end();
                return -1;
        }
        fill_data(gcm_key, sizeof(struct gcm_key_data), data, dataSize);
        fill_data(gcm_ctx, sizeof(struct gcm_context_data), data, dataSize);
        fill_data(gcm_iv, IMB_GCM_IV_DATA_LEN, data, dataSize);
        fill_data(gcm_aad, gcm_aad_len, data, dataSize);
        fill_data(gcm_auth_tag, gcm_tag_len, data, dataSize);
        return 0;
}

static int
test_aes_gcm_precomp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        if (dataSize >= IMB_KEY_256_BYTES)
                IMB_AES256_GCM_PRECOMP(p_mgr, gcm_key);
        else if (dataSize >= IMB_KEY_192_BYTES)
                IMB_AES192_GCM_PRECOMP(p_mgr, gcm_key);
        else
                IMB_AES128_GCM_PRECOMP(p_mgr, gcm_key);

        gcm_end();
        return 0;
}

static int
test_aes128_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

static int
test_aes_gcm_pre(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KEY_128_BYTES)
                return -1;

        if (gcm_start(dataSize, buff) != 0)
                return -1;

        if (dataSize >= IMB_KEY_256_BYTES)
                IMB_AES256_GCM_PRE(p_mgr, buff, gcm_key);
        else if (dataSize >= IMB_KEY_192_BYTES)
                IMB_AES192_GCM_PRE(p_mgr, buff, gcm_key);
        else
                IMB_AES128_GCM_PRE(p_mgr, buff, gcm_key);

        gcm_end();
        return 0;
}

static int
test_aes128_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes128_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES192_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES192_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes128_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES128_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES128_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes128_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES128_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES128_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;

        IMB_AES192_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES192_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES192_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES192_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES192_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES192_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES256_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES256_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES256_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES256_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_aes128_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        /* use GCM AAD field as GMAC IV */
        IMB_AES128_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
        IMB_AES128_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
        IMB_AES128_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        /* use GCM AAD field as GMAC IV */
        IMB_AES192_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
        IMB_AES192_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
        IMB_AES192_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        /* use GCM AAD field as GMAC IV */
        IMB_AES256_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
        IMB_AES256_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
        IMB_AES256_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_ghash_pre(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        /* GHASH key size */
        if (dataSize < 16)
                return -1;

        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_GHASH_PRE(p_mgr, buff, gcm_key);

        gcm_end();
        return 0;
}

static int
test_ghash(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_GHASH(p_mgr, gcm_key, buff, dataSize, gcm_auth_tag, gcm_tag_len);

        gcm_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint8_t *zuc_iv = NULL;
static uint8_t *zuc_key = NULL;
static uint32_t *zuc_tag = NULL;

static void
zuc_end(void)
{
        if (zuc_key != NULL)
                free(zuc_key);
        if (zuc_iv != NULL)
                free(zuc_iv);
        if (zuc_tag != NULL)
                free(zuc_tag);
        zuc_key = NULL;
        zuc_iv = NULL;
        zuc_tag = NULL;
}

static int
zuc_start(const size_t dataSize, const uint8_t *data)
{
        zuc_key = (uint8_t *) malloc(IMB_ZUC_KEY_LEN_IN_BYTES);
        zuc_iv = (uint8_t *) malloc(IMB_ZUC_IV_LEN_IN_BYTES);
        zuc_tag = (uint32_t *) malloc(IMB_ZUC_DIGEST_LEN_IN_BYTES);

        if (zuc_key == NULL || zuc_iv == NULL || zuc_tag == NULL) {
                zuc_end();
                return -1;
        }
        fill_data(zuc_key, IMB_ZUC_KEY_LEN_IN_BYTES, data, dataSize);
        fill_data(zuc_iv, IMB_ZUC_IV_LEN_IN_BYTES, data, dataSize);
        fill_data(zuc_tag, IMB_ZUC_DIGEST_LEN_IN_BYTES, data, dataSize);
        return 0;
}

static int
test_zuc_eea3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (zuc_start(dataSize, buff) != 0)
                return -1;

        IMB_ZUC_EEA3_1_BUFFER(p_mgr, zuc_key, zuc_iv, buff, buff, dataSize);
        zuc_end();
        return 0;
}

struct test_zuc_mb {
        size_t n;
        const void **key;
        const void **iv;
        const void **in;
        void **out; /* eea3 specific */
        uint32_t *len;
        uint32_t **tag; /* eia3 specific */
};

static void
test_zuc_mb_free(struct test_zuc_mb *ts)
{
        if (ts->key != NULL)
                free(ts->key);
        if (ts->iv != NULL)
                free(ts->iv);
        if (ts->out != NULL)
                free(ts->out);
        if (ts->in != NULL)
                free(ts->in);
        if (ts->len != NULL)
                free(ts->len);
        if (ts->tag != NULL)
                free(ts->tag);
        memset(ts, 0, sizeof(*ts));
}

static int
test_zuc_mb_alloc(struct test_zuc_mb *ts, const size_t n)
{
        ts->n = n;

        ts->key = malloc(n * sizeof(ts->key[0]));
        ts->iv = malloc(n * sizeof(ts->iv[0]));
        ts->in = malloc(n * sizeof(ts->in[0]));
        ts->out = malloc(n * sizeof(ts->out[0]));
        ts->len = malloc(n * sizeof(ts->len[0]));

        ts->tag = malloc(n * sizeof(ts->tag[0]));

        if (ts->key == NULL || ts->iv == NULL || ts->in == NULL || ts->out == NULL ||
            ts->len == NULL || ts->tag == NULL) {
                test_zuc_mb_free(ts);
                return -1;
        }

        return 0;
}

static void
test_zuc_mb_set1(struct test_zuc_mb *ts, const void *key, const void *iv, const void *in, void *out,
                 const uint32_t len, uint32_t *tag)
{
        for (size_t i = 0; i < ts->n; i++) {
                ts->key[i] = key;
                ts->iv[i] = iv;
                ts->in[i] = in;
                ts->out[i] = out;
                ts->len[i] = len;
                ts->tag[i] = tag;
        }
}

static int
test_zuc_eea3_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (zuc_start(dataSize, buff) != 0)
                return -1;

        struct test_zuc_mb ts;
        const uint32_t n = 4;

        if (test_zuc_mb_alloc(&ts, n) != 0) {
                zuc_end();
                return -1;
        }
        test_zuc_mb_set1(&ts, zuc_key, zuc_iv, buff, buff, dataSize, NULL);
        IMB_ZUC_EEA3_4_BUFFER(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len);
        test_zuc_mb_free(&ts);
        zuc_end();
        return 0;
}

static int
test_zuc_eea3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (zuc_start(dataSize, buff) != 0)
                return -1;

        struct test_zuc_mb ts;
        const uint32_t n = 8;

        if (test_zuc_mb_alloc(&ts, n) != 0) {
                zuc_end();
                return -1;
        }
        test_zuc_mb_set1(&ts, zuc_key, zuc_iv, buff, buff, dataSize, NULL);
        IMB_ZUC_EEA3_N_BUFFER(p_mgr, ts.key, ts.iv, ts.in, ts.out, ts.len, n);
        test_zuc_mb_free(&ts);
        zuc_end();
        return 0;
}

static int
test_zuc_eia3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (zuc_start(dataSize, buff) != 0)
                return -1;

        const uint32_t len = dataSize * 8;

        IMB_ZUC_EIA3_1_BUFFER(p_mgr, zuc_key, zuc_iv, buff, len, zuc_tag);
        zuc_end();
        return 0;
}

static int
test_zuc_eia3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_ZUC_KEY_LEN_IN_BYTES)
                return -1;

        struct test_zuc_mb ts;
        const uint32_t n = 9;

        if (test_zuc_mb_alloc(&ts, n) != 0) {
                zuc_end();
                return -1;
        }
        test_zuc_mb_set1(&ts, zuc_key, zuc_iv, buff, NULL, dataSize * 8, zuc_tag);
        IMB_ZUC_EIA3_N_BUFFER(p_mgr, ts.key, ts.iv, ts.in, ts.len, ts.tag, n);
        test_zuc_mb_free(&ts);
        zuc_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint8_t *ccp_key = NULL;
static struct chacha20_poly1305_context_data *ccp_ctx = NULL;
static uint8_t *ccp_iv = NULL;
static uint8_t *ccp_aad = NULL;
static uint64_t ccp_aad_len;
static uint8_t *ccp_auth_tag = NULL;
static uint64_t ccp_tag_len;

static void
ccp_end(void)
{
        if (ccp_key != NULL)
                free(ccp_key);
        if (ccp_ctx != NULL)
                free(ccp_ctx);
        if (ccp_iv != NULL)
                free(ccp_iv);
        if (ccp_aad != NULL)
                free(ccp_aad);
        if (ccp_auth_tag != NULL)
                free(ccp_auth_tag);
        ccp_key = NULL;
        ccp_ctx = NULL;
        ccp_iv = NULL;
        ccp_aad = NULL;
        ccp_aad_len = 0;
        ccp_auth_tag = NULL;
        ccp_tag_len = 0;
}

static int
ccp_start(const size_t dataSize, const uint8_t *data)
{
        ccp_key = (uint8_t *) malloc(IMB_CHACHA20_POLY1305_KEY_SIZE);
        ccp_ctx = (struct chacha20_poly1305_context_data *) memalign(
                16, sizeof(struct chacha20_poly1305_context_data));
        ccp_iv = (uint8_t *) malloc(IMB_CHACHA20_POLY1305_IV_SIZE);
        ccp_aad_len = dataSize;
        ccp_aad = (uint8_t *) malloc(ccp_aad_len);
        ccp_tag_len = dataSize;
        ccp_auth_tag = (uint8_t *) malloc(ccp_tag_len);
        if (ccp_key == NULL || ccp_ctx == NULL || ccp_iv == NULL || ccp_aad == NULL ||
            ccp_auth_tag == NULL) {
                ccp_end();
                return -1;
        }
        fill_data(ccp_key, IMB_CHACHA20_POLY1305_KEY_SIZE, data, dataSize);
        fill_data(ccp_ctx, sizeof(struct chacha20_poly1305_context_data), data, dataSize);
        fill_data(ccp_iv, IMB_CHACHA20_POLY1305_IV_SIZE, data, dataSize);
        fill_data(ccp_aad, ccp_aad_len, data, dataSize);
        fill_data(ccp_auth_tag, ccp_tag_len, data, dataSize);
        return 0;
}

static int
test_chacha_poly_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (ccp_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_CHACHA20_POLY1305_INIT(p_mgr, ccp_key, ccp_ctx, ccp_iv, ccp_aad, ccp_aad_len);
        IMB_CHACHA20_POLY1305_ENC_UPDATE(p_mgr, ccp_key, ccp_ctx, out, in, len);
        IMB_CHACHA20_POLY1305_ENC_FINALIZE(p_mgr, ccp_ctx, ccp_auth_tag, ccp_tag_len);

        ccp_end();
        return 0;
}

static int
test_chacha_poly_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (ccp_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_CHACHA20_POLY1305_INIT(p_mgr, ccp_key, ccp_ctx, ccp_iv, ccp_aad, ccp_aad_len);
        IMB_CHACHA20_POLY1305_DEC_UPDATE(p_mgr, ccp_key, ccp_ctx, out, in, len);
        IMB_CHACHA20_POLY1305_DEC_FINALIZE(p_mgr, ccp_ctx, ccp_auth_tag, ccp_tag_len);

        ccp_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_crc32_ethernet_fcs(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC32_ETHERNET_FCS(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc16_x25(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC16_X25(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc32_sctp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC32_SCTP(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc24_lte_a(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC24_LTE_A(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc24_lte_b(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC24_LTE_B(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc16_fp_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC16_FP_DATA(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc11_fp_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC11_FP_HEADER(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc7_fp_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC7_FP_HEADER(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc10_iuup_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC10_IUUP_DATA(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc6_iuup_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC6_IUUP_HEADER(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc32_wimax_ofdma_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC32_WIMAX_OFDMA_DATA(p_mgr, buff, dataSize);
        return 0;
}

static int
test_crc8_wimax_ofdma_hcs(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_CRC8_WIMAX_OFDMA_HCS(p_mgr, buff, dataSize);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint64_t *kasumi_iv = NULL;
static kasumi_key_sched_t *kasumi_key = NULL;
static uint32_t *kasumi_tag = NULL;

static void
kasumi_end(void)
{
        if (kasumi_key != NULL)
                free(kasumi_key);
        if (kasumi_iv != NULL)
                free(kasumi_iv);
        if (kasumi_tag != NULL)
                free(kasumi_tag);
        kasumi_key = NULL;
        kasumi_iv = NULL;
        kasumi_tag = NULL;
}

static int
kasumi_start(const size_t dataSize, const uint8_t *data)
{
        kasumi_key = (kasumi_key_sched_t *) malloc(sizeof(kasumi_key_sched_t));
        kasumi_iv = (uint64_t *) malloc(IMB_KASUMI_IV_SIZE);
        kasumi_tag = (uint32_t *) malloc(IMB_KASUMI_DIGEST_SIZE);

        if (kasumi_key == NULL || kasumi_iv == NULL || kasumi_tag == NULL) {
                kasumi_end();
                return -1;
        }
        fill_data(kasumi_key, sizeof(kasumi_key_sched_t), data, dataSize);
        fill_data(kasumi_iv, IMB_KASUMI_IV_SIZE, data, dataSize);
        fill_data(kasumi_tag, IMB_KASUMI_DIGEST_SIZE, data, dataSize);
        return 0;
}

static int
test_kasumi_f8_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_KEY_SIZE)
                return -1;

        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        IMB_KASUMI_INIT_F8_KEY_SCHED(p_mgr, buff, kasumi_key);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f8_1_buff_bit(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        const uint32_t offset = (dataSize > 0) ? (buff[0] % (dataSize * 8)) : 0;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = (dataSize * 8) - offset;

        IMB_KASUMI_F8_1_BUFFER_BIT(p_mgr, kasumi_key, kasumi_iv[0], in, out, len, offset);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f8_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_KASUMI_F8_1_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], in, out, len);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f8_2_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_KASUMI_F8_2_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], kasumi_iv[0], in, out, len, in, out,
                               len);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f8_3_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_KASUMI_F8_3_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], kasumi_iv[0], kasumi_iv[0], in, out,
                               in, out, in, out, len);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f8_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_KASUMI_F8_4_BUFFER(p_mgr, kasumi_key, kasumi_iv[0], kasumi_iv[0], kasumi_iv[0],
                               kasumi_iv[0], in, out, in, out, in, out, in, out, len);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f8_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        uint64_t *iv = malloc(8 * IMB_KASUMI_IV_SIZE);

        if (iv == NULL)
                return -1;

        if (kasumi_start(dataSize, buff) != 0) {
                free(iv);
                return -1;
        }

        const void *in[8];
        void *out[8];
        uint32_t len[8];

        for (int i = 0; i < 8; i++) {
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_KASUMI_F8_N_BUFFER(p_mgr, kasumi_key, iv, in, out, len, 8);
        kasumi_end();
        free(iv);
        return 0;
}

static int
test_kasumi_f9_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_KASUMI_F9_1_BUFFER(p_mgr, kasumi_key, in, len, kasumi_tag);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f9_1_buff_user(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        const uint8_t *in = buff;
        const uint64_t len = dataSize * 8;

        const uint64_t iv = (dataSize > 0) ? (uint64_t) buff[0] : 0;
        const uint32_t dir = (dataSize > 0) ? (uint32_t) buff[0] * 8 : 0;

        IMB_KASUMI_F9_1_BUFFER_USER(p_mgr, kasumi_key, iv, in, len, kasumi_tag, dir);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f9_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_KEY_SIZE)
                return -1;

        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        IMB_KASUMI_INIT_F9_KEY_SCHED(p_mgr, buff, kasumi_key);
        kasumi_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_clear_mem(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        imb_clear_mem(buff, dataSize);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_quic_aes_gcm(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < 1)
                return -1;

        if (gcm_start(dataSize, buff) != 0)
                return -1;

        const uint64_t n = (uint64_t) buff[0];
        const IMB_CIPHER_DIRECTION cipher_dir = (IMB_CIPHER_DIRECTION) (buff[0] >> 6);
        const IMB_KEY_SIZE_BYTES key_size = (IMB_KEY_SIZE_BYTES) buff[0];

        void *dst[n];
        const void *src[n];
        const void *aad[n];
        void *t[n];
        uint64_t l[n];
        const void *iv[n];

        for (uint64_t i = 0; i < n; i++) {
                dst[i] = buff;
                src[i] = buff;
                aad[i] = gcm_aad;
                t[i] = gcm_auth_tag;
                l[i] = dataSize;
                iv[i] = gcm_iv;
        }
        imb_quic_aes_gcm(p_mgr, gcm_key, key_size, cipher_dir, dst, src, l, iv, aad, gcm_aad_len, t,
                         gcm_tag_len, n);
        gcm_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct {
        int (*func)(IMB_MGR *mb_mgr, uint8_t *buff, size_t dataSize);
        const char *func_name;
} direct_apis[] = {
        { test_snow3g_init_key_sched, "test_snow3g_init_key_sched" },
        { test_snow3g_f8_1_buff_bit, "test_snow3g_f8_1_buff_bit" },
        { test_snow3g_f8_1_buff, "test_snow3g_f8_1_buff" },
        { test_snow3g_f8_2_buff, "test_snow3g_f8_2_buff" },
        { test_snow3g_f8_4_buff, "test_snow3g_f8_4_buff" },
        { test_snow3g_f8_8_buff, "test_snow3g_f8_8_buff" },
        { test_snow3g_f8_n_buff, "test_snow3g_f8_n_buff" },
        { test_snow3g_f8_8_multikey, "test_snow3g_f8_8_multikey" },
        { test_snow3g_f8_n_multikey, "test_snow3g_f8_n_multikey" },
        { test_snow3g_f9_1_buff, "test_snow3g_f9_1_buff" },

        { test_aes_gcm_pre, "test_aes_gcm_pre" },
        { test_aes_gcm_precomp, "test_aes_gcm_precomp" },
        { test_aes128_gcm_enc_sgl, "test_aes128_gcm_enc_sgl" },
        { test_aes128_gcm_dec_sgl, "test_aes128_gcm_dec_sgl" },
        { test_aes192_gcm_enc_sgl, "test_aes192_gcm_enc_sgl" },
        { test_aes192_gcm_dec_sgl, "test_aes192_gcm_dec_sgl" },
        { test_aes256_gcm_enc_sgl, "test_aes256_gcm_enc_sgl" },
        { test_aes256_gcm_dec_sgl, "test_aes256_gcm_dec_sgl" },
        { test_aes128_gcm_enc, "test_aes128_gcm_enc" },
        { test_aes128_gcm_dec, "test_aes128_gcm_dec" },
        { test_aes192_gcm_enc, "test_aes192_gcm_enc" },
        { test_aes192_gcm_dec, "test_aes192_gcm_dec" },
        { test_aes256_gcm_enc, "test_aes256_gcm_enc" },
        { test_aes256_gcm_dec, "test_aes256_gcm_dec" },
        { test_aes128_gcm_init_var_iv, "test_aes128_gcm_init_var_iv" },
        { test_aes192_gcm_init_var_iv, "test_aes192_gcm_init_var_iv" },
        { test_aes256_gcm_init_var_iv, "test_aes256_gcm_init_var_iv" },

        { test_aes128_gmac, "test_aes128_gmac" },
        { test_aes192_gmac, "test_aes192_gmac" },
        { test_aes256_gmac, "test_aes256_gmac" },

        { test_ghash, "test_ghash" },
        { test_ghash_pre, "test_ghash_pre" },

        { test_zuc_eea3_1_buff, "test_zuc_eea3_1_buff" },
        { test_zuc_eea3_4_buff, "test_zuc_eea3_4_buff" },
        { test_zuc_eea3_n_buff, "test_zuc_eea3_n_buff" },
        { test_zuc_eia3_1_buff, "test_zuc_eia3_1_buff" },
        { test_zuc_eia3_n_buff, "test_zuc_eia3_n_buff" },

        { test_chacha_poly_enc, "test_chacha_poly_enc" },
        { test_chacha_poly_dec, "test_chacha_poly_dec" },

        { test_crc32_ethernet_fcs, "test_crc32_ethernet_fcs" },
        { test_crc16_x25, "test_crc16_x25" },
        { test_crc32_sctp, "test_crc32_sctp" },
        { test_crc16_fp_data, "test_crc16_fp_data" },
        { test_crc11_fp_header, "test_crc11_fp_header" },
        { test_crc24_lte_a, "test_crc24_lte_a" },
        { test_crc24_lte_b, "test_crc24_lte_b" },
        { test_crc7_fp_header, "test_crc7_fp_header" },
        { test_crc10_iuup_data, "test_crc10_iuup_data" },
        { test_crc6_iuup_header, "test_crc6_iuup_header" },
        { test_crc32_wimax_ofdma_data, "test_crc32_wimax_ofdma_data" },
        { test_crc8_wimax_ofdma_hcs, "test_crc8_wimax_ofdma_hcs" },

        { test_kasumi_f8_init_key_sched, "test_kasumi_f8_init_key_sched" },
        { test_kasumi_f8_1_buff_bit, "test_kasumi_f8_1_buff_bit" },
        { test_kasumi_f8_1_buff, "test_kasumi_f8_1_buff" },
        { test_kasumi_f8_2_buff, "test_kasumi_f8_2_buff" },
        { test_kasumi_f8_3_buff, "test_kasumi_f8_3_buff" },
        { test_kasumi_f8_4_buff, "test_kasumi_f8_4_buff" },
        { test_kasumi_f8_n_buff, "test_kasumi_f8_n_buff" },
        { test_kasumi_f9_1_buff, "test_kasumi_f9_1_buff" },
        { test_kasumi_f9_1_buff_user, "test_kasumi_f9_1_buff_user" },
        { test_kasumi_f9_init_key_sched, "test_kasumi_f9_init_key_sched" },

        { test_imb_clear_mem, "test_imb_clear_mem" },

        { test_imb_quic_aes_gcm, "test_imb_quic_aes_gcm" },
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize)
{
        static IMB_MGR *p_mgr = NULL;

        if (dataSize < sizeof(int))
                return -1;

        const size_t newDataSize = dataSize - sizeof(int);
        uint8_t *buff = malloc(newDataSize);

        if (buff == NULL)
                return -1;

        memcpy(buff, &data[sizeof(int)], newDataSize);

        /* allocate multi-buffer manager */
        if (p_mgr == NULL) {
                p_mgr = alloc_mb_mgr(0);
                if (p_mgr == NULL) {
                        printf("Error allocating MB_MGR structure!\n");
                        free(buff);
                        return -1;
                }

                IMB_ARCH arch_to_run = IMB_ARCH_NUM;

                if (arch == IMB_ARCH_SSE)
                        init_mb_mgr_sse(p_mgr);
                else if (arch == IMB_ARCH_AVX)
                        init_mb_mgr_avx(p_mgr);
                else if (arch == IMB_ARCH_AVX2)
                        init_mb_mgr_avx2(p_mgr);
                else if (arch == IMB_ARCH_AVX512)
                        init_mb_mgr_avx512(p_mgr);
                else
                        init_mb_mgr_auto(p_mgr, &arch_to_run);
        }

        const int idx = ((const int *) data)[0] % DIM(direct_apis);
        const int ret = direct_apis[idx].func(p_mgr, buff, newDataSize);

        free(buff);
        return ret;
}
