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
#include <intel-ipsec-mb.h>
#include "utils.h"

int
LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int
LLVMFuzzerInitialize(int *, char ***);

enum ar { SSE = 1, AVX, AVX2, AVX512 };

enum ar arch;

static void
parse_matched(int argc, char **argv)
{
        for (int i = 0; i < argc; i++) {
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

static int
test_snow3g_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *init_key = buff;
        snow3g_key_schedule_t exp_key;

        if (dataSize < sizeof(exp_key))
                return -1;

        IMB_SNOW3G_INIT_KEY_SCHED(p_mgr, init_key, &exp_key);
        return 0;
}

static int
test_snow3g_f8_1_buff_bit(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES || dataSize < sizeof(snow3g_key_schedule_t))
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *iv = buff;
        const size_t dataSizeBits = dataSize * 8;
        const size_t offsetBits = buff[0] % dataSizeBits;
        const uint64_t lenBits = dataSizeBits - offsetBits;
        snow3g_key_schedule_t exp_key;

        IMB_SNOW3G_F8_1_BUFFER_BIT(p_mgr, &exp_key, iv, in, out, lenBits, offsetBits);
        return 0;
}

static int
test_snow3g_f8_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        snow3g_key_schedule_t exp_key;

        IMB_SNOW3G_F8_1_BUFFER(p_mgr, &exp_key, iv, in, out, len);
        return 0;
}

static int
test_snow3g_f8_2_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        snow3g_key_schedule_t exp_key;

        IMB_SNOW3G_F8_2_BUFFER(p_mgr, &exp_key, iv, iv, in, out, len, in, out, len);
        return 0;
}

static int
test_snow3g_f8_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        snow3g_key_schedule_t exp_key;

        IMB_SNOW3G_F8_4_BUFFER(p_mgr, &exp_key, iv, iv, iv, iv, in, out, len, in, out, len, in, out,
                               len, in, out, len);
        return 0;
}

static int
test_snow3g_f8_8_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        snow3g_key_schedule_t exp_key;

        IMB_SNOW3G_F8_8_BUFFER(p_mgr, &exp_key, iv, iv, iv, iv, iv, iv, iv, iv, in, out, len, in,
                               out, len, in, out, len, in, out, len, in, out, len, in, out, len, in,
                               out, len, in, out, len);
        return 0;
}

static int
test_snow3g_f8_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES)
                return -1;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];
        snow3g_key_schedule_t exp_key;

        for (int i = 0; i < 8; i++) {
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_SNOW3G_F8_N_BUFFER(p_mgr, &exp_key, iv, in, out, len, 8);
        return 0;
}

static int
test_snow3g_f8_8_multikey(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES)
                return -1;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];
        snow3g_key_schedule_t key_sched;
        const snow3g_key_schedule_t *exp_key[8];

        for (int i = 0; i < 8; i++) {
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
                exp_key[i] = &key_sched;
        }

        IMB_SNOW3G_F8_8_BUFFER_MULTIKEY(p_mgr, exp_key, iv, in, out, len);
        return 0;
}

static int
test_snow3g_f8_n_multikey(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_SNOW3G_IV_LEN_IN_BYTES)
                return -1;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];
        snow3g_key_schedule_t key_sched;
        const snow3g_key_schedule_t *exp_key[8];

        for (int i = 0; i < 8; i++) {
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
                exp_key[i] = &key_sched;
        }

        IMB_SNOW3G_F8_N_BUFFER_MULTIKEY(p_mgr, exp_key, iv, in, out, len, 8);
        return 0;
}

static int
test_snow3g_f9_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        snow3g_key_schedule_t exp_key;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        uint8_t *auth_tag = buff;

        IMB_SNOW3G_F9_1_BUFFER(p_mgr, &exp_key, iv, in, len, auth_tag);
        return 0;
}

static int
test_aes128_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES128_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag, tag_len);
        return 0;
}

static int
test_aes128_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES128_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag, tag_len);
        return 0;
}

static int
test_aes192_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES192_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag, tag_len);
        return 0;
}

static int
test_aes192_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES192_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag, tag_len);
        return 0;
}

static int
test_aes256_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES256_GCM_ENC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag, tag_len);
        return 0;
}

static int
test_aes256_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        uint64_t aad_len = (uint64_t) *buff;
        uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;

        IMB_AES256_GCM_DEC(p_mgr, key, ctx, out, in, len, iv, aad, aad_len, auth_tag, tag_len);
        return 0;
}

static int
test_aes128_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
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
        return 0;
}

static int
test_aes128_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
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
        return 0;
}

static int
test_aes192_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
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
        return 0;
}

static int
test_aes192_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
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
        return 0;
}

static int
test_aes256_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
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
        return 0;
}

static int
test_aes256_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if ((dataSize < sizeof(struct gcm_key_data)) ||
            (dataSize < sizeof(struct gcm_context_data)))
                return -1;

        const struct gcm_key_data *key = (const struct gcm_key_data *) buff;
        struct gcm_context_data *ctx = (struct gcm_context_data *) buff;
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
        return 0;
}

static int
test_zuc_eea3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key = buff;

        if (dataSize < IMB_ZUC_KEY_LEN_IN_BYTES)
                return -1;

        void *out = buff;
        const void *in = buff;
        const uint32_t len = dataSize;
        const void *iv = (const void *) buff;

        IMB_ZUC_EEA3_1_BUFFER(p_mgr, key, iv, in, out, len);
        return 0;
}

static int
test_zuc_eea3_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key[4];

        if (dataSize < IMB_ZUC_KEY_LEN_IN_BYTES)
                return -1;

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
        return 0;
}

static int
test_zuc_eea3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key[8];

        if (dataSize < IMB_ZUC_KEY_LEN_IN_BYTES)
                return -1;

        const void *iv[8];
        const void *in[8];
        void *out[8];
        uint32_t len[8];

        for (int i = 0; i < 8; i++) {
                key[i] = buff;
                iv[i] = buff;
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_ZUC_EEA3_N_BUFFER(p_mgr, key, iv, in, out, len, 8);
        return 0;
}

static int
test_zuc_eia3_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key = buff;

        if (dataSize < IMB_ZUC_KEY_LEN_IN_BYTES)
                return -1;

        const void *in = buff;
        uint32_t len = dataSize * 8;
        const void *iv = (const void *) buff;
        uint32_t *tag = (uint32_t *) buff;

        IMB_ZUC_EIA3_1_BUFFER(p_mgr, key, iv, in, len, tag);
        return 0;
}

static int
test_zuc_eia3_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_ZUC_KEY_LEN_IN_BYTES)
                return -1;

        const void *iv[8];
        const void *in[8];
        void *tag_ptr_array[8];
        uint32_t len[8];
        uint32_t *tag[8];
        const void *key[8];

        for (int i = 0; i < 8; i++) {
                key[i] = buff;
                iv[i] = buff;
                in[i] = buff;
                tag_ptr_array[i] = buff;
                tag[i] = (uint32_t *) buff;
                len[i] = dataSize * 8;
        }

        IMB_ZUC_EIA3_N_BUFFER(p_mgr, key, iv, in, len, tag, 8);
        return 0;
}

static int
test_chacha_poly_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_CHACHA20_POLY1305_KEY_SIZE || dataSize < IMB_CHACHA20_POLY1305_IV_SIZE)
                return -1;

        struct chacha20_poly1305_context_data ctx;
        const void *key = buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        const uint64_t aad_len = dataSize;
        uint8_t auth_tag[256];
        const uint64_t tag_len = (uint64_t) buff[0];

        IMB_CHACHA20_POLY1305_INIT(p_mgr, key, &ctx, iv, aad, aad_len);
        IMB_CHACHA20_POLY1305_ENC_UPDATE(p_mgr, key, &ctx, out, in, len);
        IMB_CHACHA20_POLY1305_ENC_FINALIZE(p_mgr, &ctx, auth_tag, tag_len);
        return 0;
}

static int
test_chacha_poly_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_CHACHA20_POLY1305_KEY_SIZE || dataSize < IMB_CHACHA20_POLY1305_IV_SIZE)
                return -1;

        struct chacha20_poly1305_context_data ctx;
        const void *key = buff;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;
        const uint8_t *iv = buff;
        const uint8_t *aad = buff;
        const uint64_t aad_len = dataSize;
        uint8_t auth_tag[256];
        const uint64_t tag_len = (uint64_t) buff[0];

        IMB_CHACHA20_POLY1305_INIT(p_mgr, key, &ctx, iv, aad, aad_len);
        IMB_CHACHA20_POLY1305_DEC_UPDATE(p_mgr, key, &ctx, out, in, len);
        IMB_CHACHA20_POLY1305_DEC_FINALIZE(p_mgr, &ctx, auth_tag, tag_len);
        return 0;
}

static int
test_crc32_ethernet_fcs(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC32_ETHERNET_FCS(p_mgr, in, len);
        return 0;
}

static int
test_crc16_x25(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC16_X25(p_mgr, in, len);
        return 0;
}

static int
test_crc32_sctp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC32_SCTP(p_mgr, in, len);
        return 0;
}

static int
test_crc24_lte_a(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC24_LTE_A(p_mgr, in, len);
        return 0;
}

static int
test_crc24_lte_b(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC24_LTE_B(p_mgr, in, len);
        return 0;
}

static int
test_crc16_fp_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC16_FP_DATA(p_mgr, in, len);
        return 0;
}

static int
test_crc11_fp_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC11_FP_HEADER(p_mgr, in, len);
        return 0;
}

static int
test_crc7_fp_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC7_FP_HEADER(p_mgr, in, len);
        return 0;
}

static int
test_crc10_iuup_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC10_IUUP_DATA(p_mgr, in, len);
        return 0;
}

static int
test_crc6_iuup_header(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC6_IUUP_HEADER(p_mgr, in, len);
        return 0;
}

static int
test_crc32_wimax_ofdma_data(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC32_WIMAX_OFDMA_DATA(p_mgr, in, len);
        return 0;
}

static int
test_crc8_wimax_ofdma_hcs(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *in = buff;
        const uint64_t len = dataSize;

        IMB_CRC8_WIMAX_OFDMA_HCS(p_mgr, in, len);
        return 0;
}

static int
test_kasumi_f8_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key = buff;
        kasumi_key_sched_t exp_key;

        if (dataSize < IMB_KASUMI_KEY_SIZE)
                return -1;

        IMB_KASUMI_INIT_F8_KEY_SCHED(p_mgr, key, &exp_key);
        return 0;
}

static int
test_kasumi_f8_1_buff_bit(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_IV_SIZE)
                return -1;

        kasumi_key_sched_t exp_key;
        const uint32_t offset = ((uint32_t) *buff * 8) % (dataSize * 8);
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = (dataSize * 8) - offset;
        const uint64_t iv = *((uint64_t *) buff);

        IMB_KASUMI_F8_1_BUFFER_BIT(p_mgr, &exp_key, iv, in, out, len, offset);
        return 0;
}

static int
test_kasumi_f8_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_IV_SIZE)
                return -1;

        kasumi_key_sched_t exp_key;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint64_t iv = *((uint64_t *) buff);

        IMB_KASUMI_F8_1_BUFFER(p_mgr, &exp_key, iv, in, out, len);
        return 0;
}

static int
test_kasumi_f8_2_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_IV_SIZE)
                return -1;

        kasumi_key_sched_t exp_key;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint64_t iv = *((uint64_t *) buff);

        IMB_KASUMI_F8_2_BUFFER(p_mgr, &exp_key, iv, iv, in, out, len, in, out, len);
        return 0;
}

static int
test_kasumi_f8_3_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_IV_SIZE)
                return -1;

        kasumi_key_sched_t exp_key;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint64_t iv = *((uint64_t *) buff);

        IMB_KASUMI_F8_3_BUFFER(p_mgr, &exp_key, iv, iv, iv, in, out, in, out, in, out, len);
        return 0;
}

static int
test_kasumi_f8_4_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_IV_SIZE)
                return -1;

        kasumi_key_sched_t exp_key;
        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;
        const uint64_t iv = *((uint64_t *) buff);

        IMB_KASUMI_F8_4_BUFFER(p_mgr, &exp_key, iv, iv, iv, iv, in, out, in, out, in, out, in, out,
                               len);
        return 0;
}

static int
test_kasumi_f8_n_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        kasumi_key_sched_t exp_key;
        const uint64_t *iv = (uint64_t *) buff;
        const void *in[8];
        void *out[8];
        uint32_t len[8];

        if (dataSize < (IMB_KASUMI_IV_SIZE * 8))
                return -1;

        for (int i = 0; i < 8; i++) {
                in[i] = buff;
                out[i] = buff;
                len[i] = dataSize;
        }

        IMB_KASUMI_F8_N_BUFFER(p_mgr, &exp_key, iv, in, out, len, 8);
        return 0;
}

static int
test_kasumi_f9_1_buff(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const kasumi_key_sched_t exp_key_s;
        const kasumi_key_sched_t *exp_key = &exp_key_s;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;
        uint8_t *tag = buff;

        if (dataSize < IMB_KASUMI_DIGEST_SIZE)
                return -1;

        IMB_KASUMI_F9_1_BUFFER(p_mgr, exp_key, in, len, tag);
        return 0;
}

static int
test_kasumi_f9_1_buff_user(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        kasumi_key_sched_t exp_key;
        const uint8_t *in = buff;
        const uint64_t len = dataSize * 8;
        uint8_t *tag = buff;
        const uint64_t iv = (uint64_t) buff;
        const uint32_t dir = (uint32_t) *buff * 8;

        if (dataSize < IMB_KASUMI_IV_SIZE)
                return -1;

        IMB_KASUMI_F9_1_BUFFER_USER(p_mgr, &exp_key, iv, in, len, tag, dir);
        return 0;
}

static int
test_kasumi_f9_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const void *key = buff;
        kasumi_key_sched_t exp_key;

        if (dataSize < IMB_KASUMI_KEY_SIZE)
                return -1;

        IMB_KASUMI_INIT_F9_KEY_SCHED(p_mgr, key, &exp_key);
        return 0;
}

static int
test_imb_clear_mem(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        imb_clear_mem(buff, dataSize);
        return 0;
}

static int
test_imb_quic_aes_gcm(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct quic_aes_gcm_ctx {
                IMB_KEY_SIZE_BYTES key_size;
                IMB_CIPHER_DIRECTION cipher_dir;
                uint8_t aad_len;
                uint8_t tag_len;
                uint8_t num_packets;
                uint8_t data;
        };
        struct quic_aes_gcm_ctx *ctx = (struct quic_aes_gcm_ctx *) buff;

        if (dataSize <= sizeof(*ctx) || dataSize < 16)
                return -1;

        struct gcm_key_data key;
        uint8_t tag[256];

        const uint64_t n = (uint64_t) ctx->num_packets;
        const uint64_t len = dataSize - sizeof(struct quic_aes_gcm_ctx) + sizeof(ctx->data);
        const uint64_t tag_len = (uint64_t) ctx->tag_len;
        const uint64_t aad_len = ((uint64_t) ctx->aad_len) > len ? len : ((uint64_t) ctx->aad_len);

        void *dst[n];
        const void *src[n];
        const void *aad[n];
        void *t[n];
        uint64_t l[n];
        const void *iv[n];

        for (uint64_t i = 0; i < n; i++) {
                dst[i] = &ctx->data;
                src[i] = &ctx->data;
                aad[i] = &ctx->data;
                t[i] = tag;
                l[i] = len;
                iv[i] = buff;
        }
        imb_quic_aes_gcm(p_mgr, &key, ctx->key_size, ctx->cipher_dir, dst, src, l, iv, aad, aad_len,
                         t, tag_len, n);
        return 0;
}

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

        const int idx = ((const int *) data)[0] % DIM(direct_apis);
        const int ret = direct_apis[idx].func(p_mgr, buff, newDataSize);

        free(buff);
        return ret;
}
