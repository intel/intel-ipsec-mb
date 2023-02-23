/**********************************************************************
  Copyright(c) 2022, Intel Corporation All rights reserved.

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
#include <intel-ipsec-mb.h>
#include "utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int LLVMFuzzerInitialize(int *, char ***);

enum ar {
        SSE = 1,
        AVX,
        AVX2,
        AVX512
};

enum ar arch;

int count = 8;

static void parse_matched(int argc, char **argv)
{
        int i;

        for (i = 0; i < argc; i++) {
                if (strcmp(argv[i], "SSE") == 0)
                        arch = SSE;
                else if (strcmp(argv[i], "AVX") == 0)
                        arch = AVX;
                else if (strcmp(argv[i], "AVX2") == 0)
                        arch = AVX2;
                else if (strcmp(argv[i], "AVX512") == 0)
                        arch = AVX512;
        }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
        int i;

        for (i = 0; i < *argc; i++) {
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

static void test_snow3g_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff,
                                size_t dataSize)
{
        const void *init_key = buff;
        snow3g_key_schedule_t exp_key_s;
        snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        IMB_SNOW3G_INIT_KEY_SCHED(p_mgr, init_key, exp_key);
}

static void test_snow3g_f8_1_buff_bit(IMB_MGR *p_mgr, uint8_t *buff,
                                      size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;

        len = len * 8;
        const uint8_t *iv = buff;
        const uint32_t offset = *(uint32_t *)buff;

        IMB_SNOW3G_F8_1_BUFFER_BIT(p_mgr, exp_key, iv, in, out, len, offset);
}

static void test_snow3g_f8_1_buff(IMB_MGR *p_mgr, uint8_t *buff,
                                  size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;

        IMB_SNOW3G_F8_1_BUFFER(p_mgr, exp_key, iv, in, out, len);
}

static void test_snow3g_f8_2_buff(IMB_MGR *p_mgr, uint8_t *buff,
                                  size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;

        IMB_SNOW3G_F8_2_BUFFER(p_mgr, exp_key, iv, iv, in,
                               out, len, in, out, len);
}

static void test_snow3g_f8_4_buff(IMB_MGR *p_mgr, uint8_t *buff,
                                  size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;

        IMB_SNOW3G_F8_4_BUFFER(p_mgr, exp_key, iv, iv, iv,
                               iv, in, out, len, in, out,
                               len, in, out, len,
                               in, out, len);
}

static void test_snow3g_f8_8_buff(IMB_MGR *p_mgr, uint8_t *buff,
                                  size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;

        IMB_SNOW3G_F8_8_BUFFER(p_mgr, exp_key, iv, iv, iv,
                               iv, iv, iv, iv, iv,
                               in, out, len, in, out, len,
                               in, out, len,
                               in, out, len, in, out,
                               len, in, out, len, in,
                               out, len, in, out, len);
}

static void test_snow3g_f8_n_buff(IMB_MGR *p_mgr, uint8_t *buff,
                                  size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];

        for (int i = 0; i < 8; i++) {
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_SNOW3G_F8_N_BUFFER(p_mgr, exp_key, iv, in, out, len, count);
}

static void test_snow3g_f8_8_multikey(IMB_MGR *p_mgr, uint8_t *buff,
                                      size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];

        for (int i = 0; i < 8; i++) {
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_SNOW3G_F8_8_BUFFER_MULTIKEY(p_mgr, &exp_key, iv, in, out, len);
}

static void test_snow3g_f8_n_multikey(IMB_MGR *p_mgr, uint8_t *buff,
                                      size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];

        for (int i = 0; i < 8; i++) {
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_SNOW3G_F8_N_BUFFER_MULTIKEY(p_mgr, &exp_key, iv, in, out, len,
                                        count);
}

static void test_snow3g_f9_1_buff(IMB_MGR *p_mgr, uint8_t *buff,
                                  size_t dataSize)
{
        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        if (dataSize < sizeof(exp_key_s))
                return;

        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        uint8_t *auth_tag = buff;

        IMB_SNOW3G_F9_1_BUFFER(p_mgr, exp_key, iv, in, len, auth_tag);
}

static void test_aes128_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;


        IMB_AES128_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad,
                           aad_len, auth_tag, tag_len);
}

static void test_aes128_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES128_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad,
                           aad_len, auth_tag, tag_len);
}

static void test_aes192_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES192_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad,
                           aad_len, auth_tag, tag_len);
}

static void test_aes192_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff,  size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES192_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad,
                           aad_len, auth_tag, tag_len);
}

static void test_aes256_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES256_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad,
                           aad_len, auth_tag, tag_len);
}

static void test_aes256_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES256_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad,
                           aad_len, auth_tag, tag_len);
}

static void test_aes128_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff,
                                    size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES128_GCM_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_AES128_GCM_ENC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_AES128_GCM_ENC_FINALIZE(p_mgr, key, ctx, auth_tag, tag_len);
}

static void test_aes128_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff,
                                    size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES128_GCM_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_AES128_GCM_DEC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_AES128_GCM_DEC_FINALIZE(p_mgr, key, ctx, auth_tag, tag_len);
}

static void test_aes192_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff,
                                    size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES192_GCM_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_AES192_GCM_ENC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_AES192_GCM_ENC_FINALIZE(p_mgr, key, ctx, auth_tag, tag_len);
}

static void test_aes192_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff,
                                    size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES192_GCM_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_AES192_GCM_DEC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_AES192_GCM_DEC_FINALIZE(p_mgr, key, ctx, auth_tag, tag_len);
}

static void test_aes256_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff,
                                    size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;
        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES256_GCM_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_AES256_GCM_ENC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_AES256_GCM_ENC_FINALIZE(p_mgr, key, ctx, auth_tag, tag_len);
}

static void test_aes256_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff,
                                    size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return;

        const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *)buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES256_GCM_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_AES256_GCM_DEC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_AES256_GCM_DEC_FINALIZE(p_mgr, key, ctx, auth_tag, tag_len);
}

static void test_zuc_eea3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key = buff;

        if (dataSize < 16)
                return;

        void *out = buff;
        const void *in = buff;
	const uint32_t len = dataSize;
	const void *iv = (const void *) buff;

        IMB_ZUC_EEA3_1_BUFFER(p_mgr, key, iv, in, out, len);
}

static void test_zuc_eea3_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key[4];

        if (dataSize < 16)
                return;

        const void *iv[4];
        const void *in[4];
        void *out[4];
        uint32_t len[4];

        for (int i = 0; i < 4; i++) {
                key[i] = buff;
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_ZUC_EEA3_4_BUFFER(p_mgr, key, iv, in, out, len);
}

static void test_zuc_eea3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key[8];

        if (dataSize < 16)
                return;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];

        for (int i = 0; i < count; i++) {
                key[i] = buff;
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_ZUC_EEA3_N_BUFFER(p_mgr, key, iv, in, out, len, count);
}

static void test_zuc_eia3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key = buff;

        if (dataSize < 16)
                return;

        const void *in = buff;
	uint32_t len = dataSize * 8;
	const void *iv = (const void *) buff;
        uint32_t *tag = (uint32_t *)buff;

        IMB_ZUC_EIA3_1_BUFFER(p_mgr, key, iv, in, len, tag);
}

static void test_zuc_eia3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key[8];

        if (dataSize < 16)
                return;

        const void *iv[8];
        const void *in[8];
        void *tag_ptr_array[8];
        uint32_t len[8];
        uint32_t *tag[8];

        for (int i = 0; i < count; i++) {
                key[i] = buff;
                iv[i] = buff;
                in[i] = buff;
                tag_ptr_array[i] = buff;
                tag[i] = (uint32_t *)buff;
                len[i] = dataSize * 8;
        }

        IMB_ZUC_EIA3_N_BUFFER(p_mgr, key, iv, in, len, tag, count);
}

static void test_chacha_poly_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < sizeof(struct chacha20_poly1305_context_data))
                return;

        struct chacha20_poly1305_context_data *ctx =
                (struct chacha20_poly1305_context_data *)buff;
        const void *key = buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = dataSize;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_CHACHA20_POLY1305_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_CHACHA20_POLY1305_ENC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_CHACHA20_POLY1305_ENC_FINALIZE(p_mgr, ctx, auth_tag, tag_len);
}

static void test_chacha_poly_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < sizeof(struct chacha20_poly1305_context_data))
                return;

        struct chacha20_poly1305_context_data *ctx =
                (struct chacha20_poly1305_context_data *)buff;
        const void *key = buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = dataSize;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_CHACHA20_POLY1305_INIT(p_mgr, key, ctx, iv, aad, aad_len);
        IMB_CHACHA20_POLY1305_DEC_UPDATE(p_mgr, key, ctx, out, in, len);
        IMB_CHACHA20_POLY1305_DEC_FINALIZE(p_mgr, ctx, auth_tag, tag_len);
}


struct {
        void (*func)(IMB_MGR *mb_mgr, uint8_t *buff, size_t dataSize);
        const char *func_name;
} direct_apis[] = {
        {test_snow3g_init_key_sched, "test_snow3g_init_key_sched"},
        {test_snow3g_f8_1_buff_bit, "test_snow3g_f8_1_buff_bit"},
        {test_snow3g_f8_1_buff, "test_snow3g_f8_1_buff"},
        {test_snow3g_f8_2_buff, "test_snow3g_f8_2_buff"},
        {test_snow3g_f8_4_buff, "test_snow3g_f8_4_buff"},
        {test_snow3g_f8_8_buff, "test_snow3g_f8_8_buff"},
        {test_snow3g_f8_n_buff, "test_snow3g_f8_n_buff"},
        {test_snow3g_f8_8_multikey, "test_snow3g_f8_8_multikey"},
        {test_snow3g_f8_n_multikey, "test_snow3g_f8_n_multikey"},
        {test_snow3g_f9_1_buff, "test_snow3g_f9_1_buff"},
        {test_aes128_gcm_enc_sgl, "test_aes128_gcm_enc_sgl"},
        {test_aes128_gcm_dec_sgl, "test_aes128_gcm_dec_sgl"},
        {test_aes192_gcm_enc_sgl, "test_aes192_gcm_enc_sgl"},
        {test_aes192_gcm_dec_sgl, "test_aes192_gcm_dec_sgl"},
        {test_aes256_gcm_enc_sgl, "test_aes256_gcm_enc_sgl"},
        {test_aes256_gcm_dec_sgl, "test_aes256_gcm_dec_sgl"},
        {test_aes128_gcm_enc, "test_aes128_gcm_enc"},
        {test_aes128_gcm_dec, "test_aes128_gcm_dec"},
        {test_aes192_gcm_enc, "test_aes192_gcm_enc"},
        {test_aes192_gcm_dec, "test_aes192_gcm_dec"},
        {test_aes256_gcm_enc, "test_aes256_gcm_enc"},
        {test_aes256_gcm_dec, "test_aes256_gcm_dec"},
        {test_zuc_eea3_1_buff, "test_zuc_eea3_1_buff"},
        {test_zuc_eea3_4_buff, "test_zuc_eea3_4_buff"},
        {test_zuc_eea3_n_buff, "test_zuc_eea3_n_buff"},
        {test_zuc_eia3_1_buff, "test_zuc_eia3_1_buff"},
        {test_zuc_eia3_n_buff, "test_zuc_eia3_n_buff"},
        {test_chacha_poly_enc, "test_chacha_poly_enc"},
        {test_chacha_poly_dec, "test_chacha_poly_dec"},
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize)
{
        IMB_ARCH arch_to_run = IMB_ARCH_NUM;
        static IMB_MGR *p_mgr = NULL;
        uint8_t *buff;

        buff = malloc(dataSize);
        if (buff == NULL)
                return EXIT_FAILURE;
        memcpy(buff, data, dataSize);

        /* allocate multi-buffer manager */
        if (p_mgr == NULL) {
                p_mgr = alloc_mb_mgr(0);
                if (p_mgr == NULL) {
                        printf("Error allocating MB_MGR structure!\n");
                        free(buff);
                        return EXIT_FAILURE;
                }

                if (arch == SSE)
                        init_mb_mgr_sse(p_mgr);
                else if (arch == AVX)
                        init_mb_mgr_avx(p_mgr);
                else if (arch == AVX2)
                        init_mb_mgr_avx2(p_mgr);
                else if (arch == AVX512)
                        init_mb_mgr_avx512(p_mgr);
                else
                        init_mb_mgr_auto(p_mgr, &arch_to_run);
        }

        const int idx = data[0]%DIM(direct_apis);

        direct_apis[idx].func(p_mgr, buff, dataSize);

        free(buff);
        return 0;
}
