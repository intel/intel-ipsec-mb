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

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int LLVMFuzzerInitialize(int *, char ***);

enum algorithm {
        GCM = 1,
        SNOW3G
};

enum key_size {
        SIZE_128 = 1,
        SIZE_192,
        SIZE_256
};

enum direction {
        ENCRYPT = 1,
        DECRYPT
};

enum api_id {
        SGL = 1
};

enum algorithm algo;
enum key_size keysize;
enum direction dir;
enum api_id api;

static void parse_matched(int argc, char **argv)
{
        int i;

        for (i = 0; i < argc; i++) {
                if (strcmp(argv[i], "GCM") == 0) {
                        i++;
                        algo = GCM;
                        if (strcmp(argv[i], "128") == 0)
                                keysize = SIZE_128;
                        else if (strcmp(argv[i], "192") == 0)
                                keysize = SIZE_192;
                        else if (strcmp(argv[i], "256") == 0)
                                keysize = SIZE_256;
                } else if (strcmp(argv[i], "SGL") == 0)
                        api = SGL;
                else if (strcmp(argv[i], "SNOW3G") == 0) {
                        algo = SNOW3G;
                } else if (strcmp(argv[i], "ENCRYPT") == 0)
                        dir = ENCRYPT;
                else if (strcmp(argv[i], "DECRYPT") == 0)
                        dir = DECRYPT;
        }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
        int i;

        for (i = 0; i < *argc; i++) {
                 /*
                  * Check if the current argument matches the
                  *  argument we are looking for.
                 */
                if (strcmp((*argv)[i], "custom") == 0) {
                        parse_matched(*argc - (i + 1), &((*argv)[i + 1]));
                        /*
                         * Remove the matching argument and all arguments
                         * after it from the command line.
                         */
                        *argc = i;

                        break;
                }
        }

        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize)
{
        IMB_MGR *p_mgr = NULL;
        IMB_ARCH arch;
        const char *ar = getenv("ARCH");
	uint8_t *buff;
	/* Setting minimum datasize to always fill GCM data structure  */
        if ((dataSize < sizeof(struct gcm_key_data)) ||
	    (dataSize < sizeof(struct gcm_context_data)))
                return 0;

	buff = malloc(dataSize);
        if (buff == NULL)
                return EXIT_FAILURE;
	memcpy(buff, data, dataSize);


	const struct gcm_key_data *key = (const struct gcm_key_data *)buff;
	struct gcm_context_data *ctx = (struct gcm_context_data *)buff;

        const snow3g_key_schedule_t exp_key_s;
        const snow3g_key_schedule_t *exp_key = &exp_key_s;

        const snow3g_key_schedule_t *const exp_key_s_multi;
        const snow3g_key_schedule_t *const *exp_key_multi = &exp_key_s_multi;

        snow3g_key_schedule_t exp_key_init;
        snow3g_key_schedule_t *exp_key_i = &exp_key_init;

	uint8_t *out = buff;
        uint8_t *out2 = buff;
        uint8_t *out3 = buff;
        uint8_t *out4 = buff;
        uint8_t *out5 = buff;
        uint8_t *out6 = buff;
        uint8_t *out7 = buff;
        uint8_t *out8 = buff;
        void *out_multi = buff;

        const uint8_t *in = buff;
	const uint8_t *in2 = buff;
	const uint8_t *in3 = buff;
	const uint8_t *in4 = buff;
	const uint8_t *in5 = buff;
	const uint8_t *in6 = buff;
	const uint8_t *in7 = buff;
	const uint8_t *in8 = buff;
        const void *const in_multi = buff;

	uint64_t len = dataSize;
        uint64_t len2 = dataSize;
        uint64_t len3 = dataSize;
	uint64_t len4 = dataSize;
	uint64_t len5 = dataSize;
	uint64_t len6 = dataSize;
	uint64_t len7 = dataSize;
	uint64_t len8 = dataSize;
        const void *const len_multi = buff;

	const uint8_t *iv = buff;
        const uint8_t *iv2 = buff;
        const uint8_t *iv3 = buff;
        const uint8_t *iv4 = buff;
        const uint8_t *iv5 = buff;
        const uint8_t *iv6 = buff;
        const uint8_t *iv7 = buff;
	const uint8_t *iv8 = buff;
        const void *const iv_multi = buff;

        const uint8_t *aad = buff;
	uint64_t aad_len = (uint64_t) *buff;
	uint8_t *auth_tag = buff;
        uint64_t tag_len = (uint64_t) *buff;
        const uint32_t offset = (uint32_t) *buff;
        const void *init_key = buff;

        const void *iv_n[8];
        const void *in_n[8];
        void *out_n[8];
        uint32_t len_n[8];
        const uint32_t count = 8;

        for (int i = 0; i < 8; i++) {
                iv_n[i] = buff;
                in_n[i] = buff;
                out_n[i] = buff;
                len_n[i] = dataSize;
        }

        /* allocate multi-buffer manager */
        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                printf("Error allocating MB_MGR structure!\n");
                free(buff);
                return EXIT_FAILURE;
        }

	if (ar == NULL) {
                init_mb_mgr_auto(p_mgr, &arch);
        } else {
                if (strcasecmp(ar, "AVX") == 0)
                        init_mb_mgr_avx(p_mgr);
                else if (strcasecmp(ar, "AVX2") == 0)
                        init_mb_mgr_avx2(p_mgr);
                else if (strcasecmp(ar, "AVX512") == 0)
                        init_mb_mgr_avx512(p_mgr);
                else if (strcasecmp(ar, "SSE") == 0)
                        init_mb_mgr_sse(p_mgr);
                else
                        init_mb_mgr_auto(p_mgr, &arch);
        }

        if (algo == GCM) {
                if (keysize == SIZE_128) {
                        /* 128 key size */
                        if (dir == ENCRYPT) {
                                if (api == SGL) {
                                        IMB_AES128_GCM_ENC(p_mgr, key,
                                                           ctx, out, in, len,
                                                           iv, aad, aad_len,
                                                           auth_tag,
                                                           tag_len);
                                } else {
                                        IMB_AES128_GCM_INIT(p_mgr, key, ctx,
                                                            iv, aad, aad_len);
                                        IMB_AES128_GCM_ENC_UPDATE(p_mgr, key,
                                                                  ctx, out,
                                                                  in, len);
                                        IMB_AES128_GCM_ENC_FINALIZE(p_mgr, key,
                                                                    ctx,
                                                                    auth_tag,
                                                                    tag_len);
                                }
                        } else if (dir == DECRYPT) {
                                if (api == SGL) {
                                        IMB_AES128_GCM_DEC(p_mgr, key,
                                                           ctx, out, in, len,
                                                           iv, aad, aad_len,
                                                           auth_tag,
                                                           tag_len);
                                } else {
                                        IMB_AES128_GCM_INIT(p_mgr, key, ctx,
                                                            iv, aad, aad_len);
                                        IMB_AES128_GCM_DEC_UPDATE(p_mgr, key,
                                                                  ctx, out,
                                                                  in, len);
                                        IMB_AES128_GCM_DEC_FINALIZE(p_mgr, key,
                                                                    ctx,
                                                                    auth_tag,
                                                                    tag_len);
                                }
                        }
                } else if (keysize == SIZE_192) {
                        /* 192 key size */
                        if (dir == ENCRYPT) {
                                if (api == SGL) {
                                        IMB_AES192_GCM_ENC(p_mgr, key,
                                                           ctx, out, in, len,
                                                           iv, aad, aad_len,
                                                           auth_tag,
                                                           tag_len);
                                } else {
                                        IMB_AES192_GCM_INIT(p_mgr, key, ctx,
                                                            iv, aad, aad_len);
                                        IMB_AES192_GCM_ENC_UPDATE(p_mgr, key,
                                                                  ctx, out,
                                                                  in, len);
                                        IMB_AES192_GCM_ENC_FINALIZE(p_mgr, key,
                                                                    ctx,
                                                                    auth_tag,
                                                                    tag_len);
                                }
                        } else if (dir == DECRYPT) {
                                if (api == SGL) {
                                        IMB_AES192_GCM_DEC(p_mgr, key,
                                                           ctx, out, in, len,
                                                           iv, aad, aad_len,
                                                           auth_tag,
                                                           tag_len);
                                } else {
                                        IMB_AES192_GCM_INIT(p_mgr, key, ctx,
                                                            iv, aad, aad_len);
                                        IMB_AES192_GCM_DEC_UPDATE(p_mgr, key,
                                                                  ctx, out,
                                                                  in, len);
                                        IMB_AES192_GCM_DEC_FINALIZE(p_mgr, key,
                                                                    ctx,
                                                                    auth_tag,
                                                                    tag_len);
                                }
                        }
                } else if (keysize == SIZE_256) {
                        /* 256 key size */
                        if (dir == ENCRYPT) {
                                if (api == SGL) {
                                        IMB_AES256_GCM_ENC(p_mgr, key,
                                                           ctx, out, in, len,
                                                           iv, aad, aad_len,
                                                           auth_tag,
                                                           tag_len);
                                } else {
                                        IMB_AES256_GCM_INIT(p_mgr, key, ctx,
                                                            iv, aad, aad_len);
                                        IMB_AES256_GCM_ENC_UPDATE(p_mgr, key,
                                                                  ctx, out,
                                                                  in, len);
                                        IMB_AES256_GCM_ENC_FINALIZE(p_mgr, key,
                                                                    ctx,
                                                                    auth_tag,
                                                                    tag_len);
                                }
                        } else if (dir == DECRYPT) {
                                if (api == SGL) {
                                        IMB_AES256_GCM_DEC(p_mgr, key,
                                                           ctx, out, in, len,
                                                           iv, aad, aad_len,
                                                           auth_tag,
                                                           tag_len);
                                } else {
                                        IMB_AES256_GCM_INIT(p_mgr, key, ctx,
                                                            iv, aad, aad_len);
                                        IMB_AES256_GCM_DEC_UPDATE(p_mgr, key,
                                                                  ctx, out,
                                                                  in, len);
                                        IMB_AES256_GCM_DEC_FINALIZE(p_mgr, key,
                                                                    ctx,
                                                                    auth_tag,
                                                                    tag_len);
                                }
                        }
                }
        } else if (algo == SNOW3G) {
                IMB_SNOW3G_INIT_KEY_SCHED(p_mgr, init_key, exp_key_i);
                IMB_SNOW3G_F8_1_BUFFER_BIT(p_mgr, exp_key, iv, in, out,
                                           len, offset);
                IMB_SNOW3G_F8_1_BUFFER(p_mgr, exp_key, iv, in, out,
                                       len);
                IMB_SNOW3G_F8_2_BUFFER(p_mgr, exp_key, iv, iv2, in,
                                               out, len, in2, out2, len2);
                IMB_SNOW3G_F8_4_BUFFER(p_mgr, exp_key, iv, iv2, iv3,
                                       iv4, in, out, len, in2, out2,
                                       len2, in3, out3, len3,
                                       in4, out4, len4);
                IMB_SNOW3G_F8_8_BUFFER(p_mgr, exp_key, iv, iv2, iv3,
                                       iv4, iv5, iv6, iv7, iv8,
                                       in, out, len, in2, out2, len2,
                                       in3, out3, len3,
                                       in4, out4, len4, in5, out5,
                                       len5, in6, out6, len6, in7,
                                       out7, len7, in8, out8, len8);
                IMB_SNOW3G_F8_N_BUFFER(p_mgr, exp_key, iv_n,
                                       in_n, out_n,
                                       len_n, count);
                IMB_SNOW3G_F8_8_BUFFER_MULTIKEY(p_mgr, exp_key_multi,
                                                iv_multi, in_multi,
                                                out_multi, len_multi);
                IMB_SNOW3G_F8_N_BUFFER_MULTIKEY(p_mgr, exp_key_multi,
                                                iv_n, in_n,
                                                out_n, len_n,
                                                count);
                IMB_SNOW3G_F9_1_BUFFER(p_mgr, exp_key, iv,
                                       in, len, auth_tag);
        }
        free_mb_mgr(p_mgr);
	free(buff);
        return 0;
}
