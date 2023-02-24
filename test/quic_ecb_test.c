/*****************************************************************************
 Copyright (c) 2023, Intel Corporation

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
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <intel-ipsec-mb.h>

#include "utils.h"

int quic_ecb_test(struct IMB_MGR *mb_mgr);

struct quic_ecb_vector {
	const uint8_t *K;          /* key */
	const uint8_t *P;          /* plain text (16 bytes) */
        const uint8_t *C;          /* cipher text - same length as plain text */
        uint32_t       Klen;       /* key length */
};

/* 128-bit */
static const uint8_t ecb_128_K1[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t ecb_128_P1[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static const uint8_t ecb_128_C1[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
};

/* 192-bit */
static const uint8_t ecb_192_K20[] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};
static const uint8_t ecb_192_P20[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};
static const uint8_t ecb_192_P21[] = {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};
static const uint8_t ecb_192_P22[] = {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
};
static const uint8_t ecb_192_P23[] = {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const uint8_t ecb_192_C20[] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
};
static const uint8_t ecb_192_C21[] = {
        0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
        0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
};
static const uint8_t ecb_192_C22[] = {
        0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
        0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
};
static const uint8_t ecb_192_C23[] = {
        0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
        0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e
};

/* 256-bit */
static const uint8_t ecb_256_K30[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
static const uint8_t ecb_256_P30[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};
static const uint8_t ecb_256_P31[] = {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
};
static const uint8_t ecb_256_P32[] = {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
};
static const uint8_t ecb_256_P33[] = {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const uint8_t ecb_256_C30[] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
};
static const uint8_t ecb_256_C31[] = {
        0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
        0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
};
static const uint8_t ecb_256_C32[] = {
        0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
        0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
};
static const uint8_t ecb_256_C33[] = {
        0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
        0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
};

static const struct quic_ecb_vector quic_ecb_vectors[] = {
        {ecb_128_K1,  ecb_128_P1, ecb_128_C1, sizeof(ecb_128_K1)},
        {ecb_192_K20, ecb_192_P20, ecb_192_C20, sizeof(ecb_192_K20)},
        {ecb_192_K20, ecb_192_P21, ecb_192_C21, sizeof(ecb_192_K20)},
        {ecb_192_K20, ecb_192_P22, ecb_192_C22, sizeof(ecb_192_K20)},
        {ecb_192_K20, ecb_192_P23, ecb_192_C23, sizeof(ecb_192_K20)},
        {ecb_256_K30, ecb_256_P30, ecb_256_C30, sizeof(ecb_256_K30)},
        {ecb_256_K30, ecb_256_P31, ecb_256_C31, sizeof(ecb_256_K30)},
        {ecb_256_K30, ecb_256_P32, ecb_256_C32, sizeof(ecb_256_K30)},
        {ecb_256_K30, ecb_256_P33, ecb_256_C33, sizeof(ecb_256_K30)},
};

static int
test_quic_ecb_many(struct IMB_MGR *mb_mgr,
                   void *enc_keys,
                   const uint8_t *in_text,
                   const uint8_t *out_text,
                   const int in_place,
                   const int key_len,
                   const int num_jobs)
{
        const unsigned text_len = 16;
        const unsigned out_len = 5;
        uint8_t **src_bufs = malloc(num_jobs * sizeof(void *));
        uint8_t **dst_bufs = malloc(num_jobs * sizeof(void *));
        int i, ret = -1;

        for (i = 0; i < num_jobs; i++) {
                src_bufs[i] = malloc(text_len);
                memcpy(src_bufs[i], in_text, text_len);

                dst_bufs[i] = malloc(out_len);
                memset(dst_bufs[i], -1, out_len);
        }

        if (in_place) {
                imb_quic_hp_aes_ecb(mb_mgr, enc_keys,
                                    (void **) src_bufs,
                                    (const void * const*) src_bufs,
                                    num_jobs, key_len);
        } else {
                imb_quic_hp_aes_ecb(mb_mgr, enc_keys,
                                    (void **) dst_bufs,
                                    (const void * const*) src_bufs,
                                    num_jobs, key_len);
        }

        const int err = imb_get_errno(mb_mgr);

        if (err != 0) {
                printf("QUIC AES-ECB error status:%d, %s\n", err,
                       imb_get_strerror(err));
                goto end;
        }

        for (i = 0; i < num_jobs; i++) {
                const uint8_t *d = (in_place) ? src_bufs[i] : dst_bufs[i];

                if (memcmp(d, out_text, out_len) != 0) {
                        printf("QUIC AES-ECB %d vector mismatched\n", i);
                        hexdump(stderr, "Expected",
                                out_text, out_len);
                        hexdump(stderr, "Received",
                                d, out_len);
                        goto end;
                }
        }

        ret = 0;

 end:
        for (i = 0; i < num_jobs; i++) {
                free(src_bufs[i]);
                free(dst_bufs[i]);
        }
        free(src_bufs);
        free(dst_bufs);
        return ret;
}

static void
test_quic_ecb_vectors(struct IMB_MGR *mb_mgr, const int vec_cnt,
                      const struct quic_ecb_vector *vec_tab, const char *banner,
                      const int num_jobs,
                      struct test_suite_context *ts128,
                      struct test_suite_context *ts192,
                      struct test_suite_context *ts256)
{
	int vect;
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);

	printf("%s (N jobs = %d):\n", banner, num_jobs);
	for (vect = 0; vect < vec_cnt; vect++) {
                struct test_suite_context *ctx = NULL;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("[%d/%d] Standard vector key_len:%d\n",
                               vect + 1, vec_cnt,
                               (int) vec_tab[vect].Klen);
#else
                        printf(".");
#endif
                }

                switch (vec_tab[vect].Klen) {
                case 16:
                        IMB_AES_KEYEXP_128(mb_mgr, vec_tab[vect].K, enc_keys,
                                           dec_keys);
                        ctx = ts128;
                        break;
                case 24:
                        IMB_AES_KEYEXP_192(mb_mgr, vec_tab[vect].K, enc_keys,
                                           dec_keys);
                        ctx = ts192;
                        break;
                case 32:
                default:
                        IMB_AES_KEYEXP_256(mb_mgr, vec_tab[vect].K, enc_keys,
                                           dec_keys);
                        ctx = ts256;
                        break;
                }

                if (test_quic_ecb_many(mb_mgr, enc_keys,
                                       vec_tab[vect].P, vec_tab[vect].C, 0,
                                       vec_tab[vect].Klen, num_jobs)) {
                        printf("error #%d encrypt\n", vect + 1);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_quic_ecb_many(mb_mgr, enc_keys,
                                       vec_tab[vect].P, vec_tab[vect].C, 1,
                                       vec_tab[vect].Klen, num_jobs)) {
                        printf("error #%d encrypt in-place\n", vect + 1);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
	}

        if (!quiet_mode)
                printf("\n");
}

int
quic_ecb_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts128, ts192, ts256;
        const int num_jobs_tab[] = {
                1, 3, 4, 5, 7, 8, 9, 15, 16, 17
        };
        unsigned i;
        int errors = 0;

        test_suite_start(&ts128, "QUIC-HP-AES-ECB-128");
        test_suite_start(&ts192, "QUIC-HP-AES-ECB-192");
        test_suite_start(&ts256, "QUIC-HP-AES-ECB-256");

        for (i = 0; i < DIM(num_jobs_tab); i++)
                test_quic_ecb_vectors(mb_mgr, DIM(quic_ecb_vectors),
                                      quic_ecb_vectors,
                                      "QUIC-HP-AES-ECB test vectors",
                                      num_jobs_tab[i],
                                      &ts128, &ts192, &ts256);

        errors = test_suite_end(&ts128);
        errors += test_suite_end(&ts192);
        errors += test_suite_end(&ts256);

	return errors;
}
