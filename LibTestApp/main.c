/*
 * Copyright (c) 2012-2017, Intel Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mb_mgr.h>
#include <aux_funcs.h>

#include "gcm_ctr_vectors_test.h"

#define TEST_SSE  1
#define TEST_AVX  2
#define TEST_AVX2 3

#define TEST TEST_SSE
#include "do_test.h"
#undef TEST
#define TEST TEST_AVX
#include "do_test.h"
#undef TEST
#define TEST TEST_AVX2
#include "do_test.h"
#undef TEST
#define TEST TEST_AVX512
#include "do_test.h"


#ifndef NO_ADDON
static struct JOB_AES_HMAC *
cipher_addon(struct MB_MGR *state __attribute__((unused)),
             struct JOB_AES_HMAC *job)
{

        if (job->status & STS_COMPLETED_AES) {
                fprintf(stderr, "%s already ciphered\n", __func__);
        } else {
                if (job->cipher_direction == ENCRYPT)
                        fprintf(stderr, "%s encrypted\n", __func__);
                else
                        fprintf(stderr, "%s decrypted\n", __func__);
                job->status |= STS_COMPLETED_AES;
        }
        return job;
}

static struct JOB_AES_HMAC *
hash_addon(struct MB_MGR *state __attribute__((unused)),
           struct JOB_AES_HMAC *job)
{
        if (job->status & STS_COMPLETED_HMAC) {
                fprintf(stderr, "%s already hashed\n", __func__);
        } else {
                fprintf(stderr, "%s hashed\n", __func__);
                job->status |= STS_COMPLETED_HMAC;
        }

        return job;
}

struct cipher_attr_s {
        const char *name;
        JOB_CIPHER_MODE mode;
        unsigned key_len;
        unsigned iv_len;
        JOB_CIPHER_DIRECTION dir;
        JOB_CHAIN_ORDER chain_order;
};

struct auth_attr_s {
        const char *name;
        JOB_HASH_ALG hash;
        unsigned tag_len;
};

static const struct auth_attr_s AUTH_ATTR[] = {
        {
                .name = "SHA1",
                .hash = SHA1,
                .tag_len = 12,
        },
        {
                .name = "SHA224",
                .hash = SHA_224,
                .tag_len = 14,
        },
        {
                .name = "SHA256",
                .hash = SHA_256,
                .tag_len = 16,
        },
        {
                .name = "SHA384",
                .hash = SHA_384,
                .tag_len = 24,
        },
        {
                .name = "SHA512",
                .hash = SHA_512,
                .tag_len = 32,
        },
        {
                .name = "MD5",
                .hash = MD5,
                .tag_len = 12,
        },
        {
                .name = "HASH_ADDON",
                .hash = HASH_ADDON,
                .tag_len = -1,
        },
};

static const struct cipher_attr_s  CIPHER_ATTR[] = {
        {
                .name = "CBC128-enc",
                .mode = CBC,
                .key_len = 16,
                .iv_len = 16,
                .dir = ENCRYPT,
                .chain_order = CIPHER_HASH,
        },
        {
                .name = "CBC192-enc",
                .mode = CBC,
                .key_len = 24,
                .iv_len = 16,
                .dir = ENCRYPT,
                .chain_order = CIPHER_HASH,
        },
        {
                .name = "CBC256-enc",
                .mode = CBC,
                .key_len = 32,
                .iv_len = 16,
                .dir = ENCRYPT,
                .chain_order = CIPHER_HASH,
        },
        {
                .name = "CBC128-dec",
                .mode = CBC,
                .key_len = 16,
                .iv_len = 16,
                .dir = DECRYPT,
                .chain_order = HASH_CIPHER,
        },
        {
                .name = "CBC192-dec",
                .mode = CBC,
                .key_len = 24,
                .iv_len = 16,
                .dir = DECRYPT,
                .chain_order = HASH_CIPHER,
        },
        {
                .name = "CBC256-dec",
                .mode = CBC,
                .key_len = 32,
                .iv_len = 16,
                .dir = DECRYPT,
                .chain_order = HASH_CIPHER,
        },



        {
                .name = "CTR128-enc",
                .mode = CNTR,
                .key_len = 16,
                .iv_len = 8,
                .dir = ENCRYPT,
                .chain_order = CIPHER_HASH,
        },
        {
                .name = "CTR192-enc",
                .mode = CNTR,
                .key_len = 24,
                .iv_len = 8,
                .dir = ENCRYPT,
                .chain_order = CIPHER_HASH,
        },
        {
                .name = "CTR256-enc",
                .mode = CNTR,
                .key_len = 32,
                .iv_len = 8,
                .dir = ENCRYPT,
                .chain_order = CIPHER_HASH,
        },
        {
                .name = "CTR128-dec",
                .mode = CNTR,
                .key_len = 16,
                .iv_len = 8,
                .dir = DECRYPT,
                .chain_order = HASH_CIPHER,
        },
        {
                .name = "CTR192-dec",
                .mode = CNTR,
                .key_len = 24,
                .iv_len = 8,
                .dir = DECRYPT,
                .chain_order = HASH_CIPHER,
        },
        {
                .name = "CTR256-dec",
                .mode = CNTR,
                .key_len = 32,
                .iv_len = 8,
                .dir = DECRYPT,
                .chain_order = HASH_CIPHER,
        },


        {
                .name = "CIPHER_ADDON-enc",
                .mode = CIPHER_ADDON,
                .key_len = -1,
                .iv_len = -1,
                .dir = ENCRYPT,
                .chain_order = CIPHER_HASH,
        },
        {
                .name = "CIPHER_ADDON-dec",
                .mode = CIPHER_ADDON,
                .key_len = -1,
                .iv_len = -1,
                .dir = DECRYPT,
                .chain_order = HASH_CIPHER,
        },
};

static const struct cipher_attr_s *
get_cipher_attr(void)
{
        int n = random();

        n %= (sizeof(CIPHER_ATTR) / sizeof(CIPHER_ATTR[0]));
        //        fprintf(stderr, "cipher:%s\n", CIPHER_ATTR[n].name);
        return &CIPHER_ATTR[n];
}

static const struct auth_attr_s *
get_auth_attr(void)
{
        int n = random();

        n %= (sizeof(AUTH_ATTR) / sizeof(AUTH_ATTR[0]));
        //        fprintf(stderr, "auth:%s\n", AUTH_ATTR[n].name);
        return &AUTH_ATTR[n];
}

static void
addon_test(struct MB_MGR *state)
{
        struct packet_s {
                char iv[16];
                char data[16];
                char tag[32];
        };
        struct packet_s *pkt = NULL;
        unsigned cipher_key_len[] = {
                16, 24, 32,
        };
        JOB_HASH_ALG hash_alg[] = {
                SHA1, SHA_224, SHA_256, SHA_384, SHA_512, MD5,
        };
        char any_key[512];
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);
        DECLARE_ALIGNED(uint8_t ipad_hash[5*4], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[5*4], 16);
        unsigned tag_len[] = {
                12, 14, 16, 24, 32, 12,
        };
        JOB_CIPHER_DIRECTION cipher_dir[] = {
                ENCRYPT, DECRYPT,
        };
        JOB_CHAIN_ORDER chain_order[] = {
                CIPHER_HASH, HASH_CIPHER,
        };

        set_mb_mgr_addon(state, cipher_addon, hash_addon, NULL, NULL);

        if ((pkt = calloc(1000, sizeof(*pkt))) != NULL) {
                const struct auth_attr_s *auth_attr;
                const struct cipher_attr_s *cipher_attr;
                struct JOB_AES_HMAC *job;
                unsigned loops = 10000;


                while (loops--) {
                        struct packet_s *p = pkt;

                        for (unsigned i = 0; i < 1000; i++) {

                                cipher_attr = get_cipher_attr();
                                auth_attr = get_auth_attr();

                                while ((job = IMB_GET_NEXT_JOB(state)) == NULL) {
                                        job = IMB_FLUSH_JOB(state);
                                        if (job->status != STS_COMPLETED)
                                                fprintf(stderr, "failed job status:%d\n",
                                                        job->status);
                                }

                                job->aes_enc_key_expanded = enc_keys;
                                job->aes_dec_key_expanded = dec_keys;
                                job->aes_key_len_in_bytes = cipher_attr->key_len;
                                job->src = (const UINT8 *) p;
                                job->dst = p->data;
                                job->cipher_start_src_offset_in_bytes = 16;
                                job->msg_len_to_cipher_in_bytes = 16;
                                job->hash_start_src_offset_in_bytes = 0;
                                job->msg_len_to_hash_in_bytes = 32;
                                job->iv = p->iv;
                                job->iv_len_in_bytes = cipher_attr->iv_len;
                                job->auth_tag_output = p->tag;
                                job->auth_tag_output_len_in_bytes = auth_attr->tag_len;
                                job->u.HMAC._hashed_auth_key_xor_ipad = (const UINT8 *) ipad_hash;
                                job->u.HMAC._hashed_auth_key_xor_opad = (const UINT8 *) opad_hash;
                                job->cipher_mode = cipher_attr->mode;
                                job->cipher_direction = cipher_attr->dir;
                                job->chain_order = cipher_attr->chain_order;
                                job->hash_alg = auth_attr->hash;

                                job = IMB_SUBMIT_JOB_NOCHECK(state);
                                while (job) {
                                        if (job->status != STS_COMPLETED)
                                                fprintf(stderr, "failed job status:%d\n",
                                                        job->status);
                                        job = IMB_GET_COMPLETED_JOB(state);
                                }
                                p++;
                        }
                }

                while ((job = IMB_FLUSH_JOB(state)) != NULL) {
                        if (job->status != STS_COMPLETED)
                                fprintf(stderr, "failed job status:%d\n",
                                        job->status);
                }
                free(pkt);
        }
}
#endif /* !NO_ADDON */

static void
usage(const char *name)
{
	fprintf(stderr,
                "Usage: %s [args], where args are zero or more\n"
		"--no-avx512: Don't do AVX512\n"
		"--no-avx2: Don't do AVX2\n"
		"--no-avx: Don't do AVX\n"
		"--no-sse: Don't do SSE\n"
		"--shani-on: use SHA extensions, default: auto-detect\n"
		"--shani-off: don't use SHA extensions\n", name);
}

int
main(int argc, char **argv)
{
        int i, do_sse = 1, do_avx = 1, do_avx2 = 1, do_avx512 = 1;
        MB_MGR mb_mgr;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[i], "--no-avx512") == 0) {
			do_avx512 = 0;
		} else if (strcmp(argv[i], "--no-avx2") == 0) {
			do_avx2 = 0;
		} else if (strcmp(argv[i], "--no-avx") == 0) {
			do_avx = 0;
		} else if (strcmp(argv[i], "--no-sse") == 0) {
			do_sse = 0;
		} else if (strcmp(argv[i], "--shani-on") == 0) {
			sse_sha_ext_usage = SHA_EXT_PRESENT;
		} else if (strcmp(argv[i], "--shani-off") == 0) {
			sse_sha_ext_usage = SHA_EXT_NOT_PRESENT;
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

        if (do_sse) {
                printf("Testing SSE interface\n");
                init_mb_mgr_sse(&mb_mgr);
                known_answer_test_sse(&mb_mgr);
                do_test_sse(&mb_mgr);
                ctr_test(ARCH_SSE, &mb_mgr);
                gcm_test(ARCH_SSE);
#ifndef NO_ADDON
                addon_test(&mb_mgr);
#endif /* !NO_ADDON */
        }

        if (do_avx) {
                printf("Testing AVX interface\n");
                init_mb_mgr_avx(&mb_mgr);
                known_answer_test_avx(&mb_mgr);
                do_test_avx(&mb_mgr);
                ctr_test(ARCH_AVX, &mb_mgr);
                gcm_test(ARCH_AVX);
        }

        if (do_avx2) {
                printf("Testing AVX2 interface\n");
                init_mb_mgr_avx2(&mb_mgr);
                known_answer_test_avx2(&mb_mgr);
                do_test_avx2(&mb_mgr);
                ctr_test(ARCH_AVX2, &mb_mgr);
                gcm_test(ARCH_AVX2);
        }

        if (do_avx512) {
                printf("Testing AVX512 interface\n");
                init_mb_mgr_avx512(&mb_mgr);
                known_answer_test_avx512(&mb_mgr);
                do_test_avx512(&mb_mgr);
                ctr_test(ARCH_AVX512, &mb_mgr);
                gcm_test(ARCH_AVX512);
        }

        printf("Test completed\n");

        return EXIT_SUCCESS;
}
