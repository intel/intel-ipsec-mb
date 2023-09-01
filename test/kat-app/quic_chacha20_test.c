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

int
quic_chacha20_test(struct IMB_MGR *mb_mgr);

struct quic_chacha20_vector {
        const uint8_t *K; /* key */
        const uint8_t *P; /* plain text (16 bytes) */
        const uint8_t *C; /* cipher text - same length as plain text */
};

/* From section A.5 of https://www.rfc-editor.org/rfc/rfc9001.pdf */
static const uint8_t chacha20_256_K1[] = { 0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
                                           0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b,
                                           0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0,
                                           0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4 };
static const uint8_t chacha20_256_P1[] = { 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
                                           0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb };
static const uint8_t chacha20_256_C1[] = { 0xae, 0xfe, 0xfe, 0x7d, 0x03 };

static const struct quic_chacha20_vector quic_chacha20_vectors[] = {
        { chacha20_256_K1, chacha20_256_P1, chacha20_256_C1 },
};

static int
test_quic_chacha20_many(struct IMB_MGR *mb_mgr, const void *key, const uint8_t *in_text,
                        const uint8_t *out_text, const int in_place, const int num_jobs)
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
                imb_quic_hp_chacha20(mb_mgr, key, (void **) src_bufs,
                                     (const void *const *) src_bufs, num_jobs);
        } else {
                imb_quic_hp_chacha20(mb_mgr, key, (void **) dst_bufs,
                                     (const void *const *) src_bufs, num_jobs);
        }

        const int err = imb_get_errno(mb_mgr);

        if (err != 0) {
                printf("QUIC CHACHA20 error status:%d, %s\n", err, imb_get_strerror(err));
                goto end;
        }

        for (i = 0; i < num_jobs; i++) {
                const uint8_t *d = (in_place) ? src_bufs[i] : dst_bufs[i];

                if (memcmp(d, out_text, out_len) != 0) {
                        printf("QUIC CHACHA20 %d vector mismatched\n", i);
                        hexdump(stderr, "Expected", out_text, out_len);
                        hexdump(stderr, "Received", d, out_len);
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
test_quic_chacha20_vectors(struct IMB_MGR *mb_mgr, const int vec_cnt,
                           const struct quic_chacha20_vector *vec_tab, const char *banner,
                           const int num_jobs, struct test_suite_context *ts256)
{
        int vect;

        if (!quiet_mode)
                printf("%s (N jobs = %d):\n", banner, num_jobs);
        for (vect = 0; vect < vec_cnt; vect++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("[%d/%d] Standard vector\n", vect + 1, vec_cnt);
#else
                        printf(".");
#endif
                }

                if (test_quic_chacha20_many(mb_mgr, vec_tab[vect].K, vec_tab[vect].P,
                                            vec_tab[vect].C, 0, num_jobs)) {
                        printf("error #%d encrypt\n", vect + 1);
                        test_suite_update(ts256, 0, 1);
                } else {
                        test_suite_update(ts256, 1, 0);
                }

                if (test_quic_chacha20_many(mb_mgr, vec_tab[vect].K, vec_tab[vect].P,
                                            vec_tab[vect].C, 1, num_jobs)) {
                        printf("error #%d encrypt in-place\n", vect + 1);
                        test_suite_update(ts256, 0, 1);
                } else {
                        test_suite_update(ts256, 1, 0);
                }
        }

        if (!quiet_mode)
                printf("\n");
}

int
quic_chacha20_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts256;
        unsigned i;
        int errors = 0;

        test_suite_start(&ts256, "QUIC-HP-CHACHA20-256");

        for (i = 1; i <= 32; i++)
                test_quic_chacha20_vectors(mb_mgr, DIM(quic_chacha20_vectors),
                                           quic_chacha20_vectors, "QUIC-HP-CHACHA20 test vectors",
                                           i, &ts256);

        errors = test_suite_end(&ts256);

        return errors;
}
