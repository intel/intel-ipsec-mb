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

int algo;
int keysize;
int dir;
int api;

static void parse_matched(int argc, char **argv)
{
        int i;

        for (i = 0; i < argc; i++) {
                if (strcmp(argv[i], "GCM") == 0) {
                        i++;
                        algo = 1;
                        if (strcmp(argv[i], "128") == 0)
                                keysize = 1;
                        else if (strcmp(argv[i], "192") == 0)
                                keysize = 2;
                        else if (strcmp(argv[i], "256") == 0)
                                keysize = 3;
                } else if (strcmp(argv[i], "SGL") == 0)
                        api = 1;
                else if (strcmp(argv[i], "ENCRYPT") == 0)
                        dir = 1;
                else if (strcmp(argv[i], "DECRYPT") == 0)
                        dir = 2;
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
	memcpy(buff, data, dataSize);

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

	/* allocate multi-buffer manager */
        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                printf("Error allocating MB_MGR structure!\n");
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

        if (algo == 1) {
                if (keysize == 1) {
                        /* 128 key size */
                        if (dir == 1) {
                                if (api == 1) {
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
                        } else if (dir == 2) {
                                if (api == 1) {
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
                } else if (keysize == 2) {
                        /* 192 key size */
                        if (dir == 1) {
                                if (api == 1) {
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
                        } else if (dir == 2) {
                                if (api == 1) {
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
                } else if (keysize == 3) {
                        /* 256 key size */
                        if (dir == 1) {
                                if (api == 1) {
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
                        } else if (dir == 2) {
                                if (api == 1) {
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
        }

        free_mb_mgr(p_mgr);
	free(buff);
        return 0;
}
