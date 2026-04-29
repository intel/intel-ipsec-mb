/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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

/*
 * SHAKE128 / SHAKE256 multi-buffer (OOO manager) test.
 *
 * Tests focus on behaviour unique to the multi-buffer path:
 *   1. Single-lane (flush path) at various output lengths.
 *   2. Full 4-lane simultaneous submit (all lanes occupied at once).
 *   3. More than 4 jobs (forces flush of completed lanes mid-stream).
 *   4. Output lengths that exceed the XOF rate (multi-squeeze loops).
 *   5. Cross-validation: MB output == single-buffer reference output.
 *
 * All NIST SHAKE128 / SHAKE256 vectors used here are taken from
 * FIPS 202 and the NIST CAVS Known-Answer-Test files.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"

/* ========================================================================= */
/* KAT vectors                                                                */
/* ========================================================================= */

/* SHAKE128_RATE = 168, SHAKE256_RATE = 136 */
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

/* ---------- SHAKE128 fixed KAT vectors ------------------------------------ */

/* empty message, 256-byte output (exercises multi-squeeze for SHAKE128) */
static const uint8_t shake128_ref0_256[] = {
        /* bytes   0- 63 */
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85,
        0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66,
        0xef, 0x26, 0x3c, 0xb1, 0xee, 0xa9, 0x88, 0x00, 0x4b, 0x93, 0x10, 0x3c, 0xfb, 0x0a, 0xee,
        0xfd, 0x2a, 0x68, 0x6e, 0x01, 0xfa, 0x4a, 0x58, 0xe8, 0xa3, 0x63, 0x9c, 0xa8, 0xa1, 0xe3,
        0xf9, 0xae, 0x57, 0xe2,
        /* bytes  64-127 */
        0x35, 0xb8, 0xcc, 0x87, 0x3c, 0x23, 0xdc, 0x62, 0xb8, 0xd2, 0x60, 0x16, 0x9a, 0xfa, 0x2f,
        0x75, 0xab, 0x91, 0x6a, 0x58, 0xd9, 0x74, 0x91, 0x88, 0x35, 0xd2, 0x5e, 0x6a, 0x43, 0x50,
        0x85, 0xb2, 0xba, 0xdf, 0xd6, 0xdf, 0xaa, 0xc3, 0x59, 0xa5, 0xef, 0xbb, 0x7b, 0xcc, 0x4b,
        0x59, 0xd5, 0x38, 0xdf, 0x9a, 0x04, 0x30, 0x2e, 0x10, 0xc8, 0xbc, 0x1c, 0xbf, 0x1a, 0x0b,
        0x3a, 0x51, 0x20, 0xea,
        /* bytes 128-191 */
        0x17, 0xcd, 0xa7, 0xcf, 0xad, 0x76, 0x5f, 0x56, 0x23, 0x47, 0x4d, 0x36, 0x8c, 0xcc, 0xa8,
        0xaf, 0x00, 0x07, 0xcd, 0x9f, 0x5e, 0x4c, 0x84, 0x9f, 0x16, 0x7a, 0x58, 0x0b, 0x14, 0xaa,
        0xbd, 0xef, 0xae, 0xe7, 0xee, 0xf4, 0x7c, 0xb0, 0xfc, 0xa9, 0x76, 0x7b, 0xe1, 0xfd, 0xa6,
        0x94, 0x19, 0xdf, 0xb9, 0x27, 0xe9, 0xdf, 0x07, 0x34, 0x8b, 0x19, 0x66, 0x91, 0xab, 0xae,
        0xb5, 0x80, 0xb3, 0x2d,
        /* bytes 192-255 */
        0xef, 0x58, 0x53, 0x8b, 0x8d, 0x23, 0xf8, 0x77, 0x32, 0xea, 0x63, 0xb0, 0x2b, 0x4f, 0xa0,
        0xf4, 0x87, 0x33, 0x60, 0xe2, 0x84, 0x19, 0x28, 0xcd, 0x60, 0xdd, 0x4c, 0xee, 0x8c, 0xc0,
        0xd4, 0xc9, 0x22, 0xa9, 0x61, 0x88, 0xd0, 0x32, 0x67, 0x5c, 0x8a, 0xc8, 0x50, 0x93, 0x3c,
        0x7a, 0xff, 0x15, 0x33, 0xb9, 0x4c, 0x83, 0x4a, 0xdb, 0xb6, 0x9c, 0x61, 0x15, 0xba, 0xd4,
        0x69, 0x2d, 0x86, 0x19
};

/* ---------- SHAKE256 fixed KAT vectors ------------------------------------ */

/* empty message, 256-byte output (exercises multi-squeeze for SHAKE256) */
static const uint8_t shake256_ref0_256[] = {
        /* bytes   0- 63 */
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb,
        0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5,
        0x76, 0x2f, 0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, 0xcb, 0x05, 0x01, 0x9d, 0x67,
        0xb5, 0x92, 0xf6, 0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86, 0x40, 0x29, 0x2e, 0xac,
        0xb3, 0xb7, 0xc4, 0xbe,
        /* bytes  64-127 */
        0x14, 0x1e, 0x96, 0x61, 0x6f, 0xb1, 0x39, 0x57, 0x69, 0x2c, 0xc7, 0xed, 0xd0, 0xb4, 0x5a,
        0xe3, 0xdc, 0x07, 0x22, 0x3c, 0x8e, 0x92, 0x93, 0x7b, 0xef, 0x84, 0xbc, 0x0e, 0xab, 0x86,
        0x28, 0x53, 0x34, 0x9e, 0xc7, 0x55, 0x46, 0xf5, 0x8f, 0xb7, 0xc2, 0x77, 0x5c, 0x38, 0x46,
        0x2c, 0x50, 0x10, 0xd8, 0x46, 0xc1, 0x85, 0xc1, 0x51, 0x11, 0xe5, 0x95, 0x52, 0x2a, 0x6b,
        0xcd, 0x16, 0xcf, 0x86,
        /* bytes 128-191 */
        0xf3, 0xd1, 0x22, 0x10, 0x9e, 0x3b, 0x1f, 0xdd, 0x94, 0x3b, 0x6a, 0xec, 0x46, 0x8a, 0x2d,
        0x62, 0x1a, 0x7c, 0x06, 0xc6, 0xa9, 0x57, 0xc6, 0x2b, 0x54, 0xda, 0xfc, 0x3b, 0xe8, 0x75,
        0x67, 0xd6, 0x77, 0x23, 0x13, 0x95, 0xf6, 0x14, 0x72, 0x93, 0xb6, 0x8c, 0xea, 0xb7, 0xa9,
        0xe0, 0xc5, 0x8d, 0x86, 0x4e, 0x8e, 0xfd, 0xe4, 0xe1, 0xb9, 0xa4, 0x6c, 0xbe, 0x85, 0x47,
        0x13, 0x67, 0x2f, 0x5c,
        /* bytes 192-255 */
        0xaa, 0xae, 0x31, 0x4e, 0xd9, 0x08, 0x3d, 0xab, 0x4b, 0x09, 0x9f, 0x8e, 0x30, 0x0f, 0x01,
        0xb8, 0x65, 0x0f, 0x1f, 0x4b, 0x1d, 0x8f, 0xcf, 0x3f, 0x3c, 0xb5, 0x3f, 0xb8, 0xe9, 0xeb,
        0x2e, 0xa2, 0x03, 0xbd, 0xc9, 0x70, 0xf5, 0x0a, 0xe5, 0x54, 0x28, 0xa9, 0x1f, 0x7f, 0x53,
        0xac, 0x26, 0x6b, 0x28, 0x41, 0x9c, 0x37, 0x78, 0xa1, 0x5f, 0xd2, 0x48, 0xd3, 0x39, 0xed,
        0xe7, 0x85, 0xfb, 0x7f
};

/* ========================================================================= */
/* Test helpers                                                               */
/* ========================================================================= */

typedef struct {
        const uint8_t *msg;      /* input message (NULL means empty) */
        size_t msg_len;          /* message length in bytes */
        const uint8_t *expected; /* expected output digest */
        size_t out_len;          /* output length in bytes */
        const char *name;        /* human-readable test name */
        IMB_HASH_ALG alg;        /* IMB_AUTH_SHAKE128 or IMB_AUTH_SHAKE256 */
} shake_mb_vec_t;

static const shake_mb_vec_t shake128_vecs[] = {
        /* multi-squeeze (outlen > SHAKE128_RATE = 168): unique to the OOO path */
        { NULL, 0, shake128_ref0_256, 256, "SHAKE128 empty/256B", IMB_AUTH_SHAKE128 },
};

static const shake_mb_vec_t shake256_vecs[] = {
        /* multi-squeeze (outlen > SHAKE256_RATE = 136): unique to the OOO path */
        { NULL, 0, shake256_ref0_256, 256, "SHAKE256 empty/256B", IMB_AUTH_SHAKE256 },
};

static int
run_shake_mb_jobs(struct IMB_MGR *mb_mgr, const shake_mb_vec_t *vec, int num_jobs)
{
        uint8_t padding[16];
        uint8_t ref[512] = { 0 }; /* single-buffer reference (up to 256B for KAT) */
        uint8_t **outs = NULL;
        IMB_JOB *job;
        int i, jobs_rx = 0, ret = -1;
        static const uint8_t empty_msg[1] = { 0 };
        const uint8_t *src_msg = vec->msg ? vec->msg : NULL;
        size_t src_len = vec->msg_len;

        /* Compute single-buffer reference for this vector */
        if (vec->alg == IMB_AUTH_SHAKE128)
                mb_mgr->shake128(src_msg, src_len, ref, vec->out_len);
        else
                mb_mgr->shake256(src_msg, src_len, ref, vec->out_len);

        /* Verify single-buffer output matches expected KAT vector */
        if (memcmp(ref, vec->expected, vec->out_len)) {
                printf("%s: single-buffer reference mismatch with KAT vector\n", vec->name);
                hexdump(stderr, "Got", ref, vec->out_len);
                hexdump(stderr, "Expected", vec->expected, vec->out_len);
                goto end;
        }

        memset(padding, 0xAB, sizeof(padding));

        outs = calloc(num_jobs, sizeof(uint8_t *));
        if (!outs)
                goto end;

        for (i = 0; i < num_jobs; i++) {
                outs[i] = malloc(sizeof(padding) + vec->out_len + sizeof(padding));
                if (!outs[i])
                        goto end;
                memset(outs[i], 0xAB, sizeof(padding) + vec->out_len + sizeof(padding));
        }

        /* drain any leftover jobs */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                memset(job, 0, sizeof(*job));
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->hash_alg = vec->alg;
                job->src = (vec->msg != NULL) ? vec->msg : empty_msg;
                job->msg_len_to_hash_in_bytes = vec->msg_len;
                job->auth_tag_output = outs[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->out_len;
                job->user_data = outs[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED) {
                                printf("%s: submit job error status %d\n", vec->name, job->status);
                                goto end;
                        }
                        /* check padding guards */
                        if (memcmp(padding, job->user_data, sizeof(padding)) ||
                            memcmp(padding,
                                   (uint8_t *) job->user_data + sizeof(padding) + vec->out_len,
                                   sizeof(padding))) {
                                printf("%s: output buffer overrun detected\n", vec->name);
                                goto end;
                        }
                        if (memcmp(vec->expected, (uint8_t *) job->user_data + sizeof(padding),
                                   vec->out_len)) {
                                printf("%s: digest mismatch (num_jobs=%d)\n", vec->name, num_jobs);
                                hexdump(stderr, "Got", (uint8_t *) job->user_data + sizeof(padding),
                                        vec->out_len);
                                hexdump(stderr, "Expected", vec->expected, vec->out_len);
                                goto end;
                        }
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("%s: flush job error status %d\n", vec->name, job->status);
                        goto end;
                }
                if (memcmp(padding, job->user_data, sizeof(padding)) ||
                    memcmp(padding, (uint8_t *) job->user_data + sizeof(padding) + vec->out_len,
                           sizeof(padding))) {
                        printf("%s: output buffer overrun (flush)\n", vec->name);
                        goto end;
                }
                if (memcmp(vec->expected, (uint8_t *) job->user_data + sizeof(padding),
                           vec->out_len)) {
                        printf("%s: digest mismatch (flush, num_jobs=%d)\n", vec->name, num_jobs);
                        hexdump(stderr, "Got", (uint8_t *) job->user_data + sizeof(padding),
                                vec->out_len);
                        hexdump(stderr, "Expected", vec->expected, vec->out_len);
                        goto end;
                }
        }

        if (jobs_rx != num_jobs) {
                printf("%s: expected %d jobs, received %d\n", vec->name, num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;
end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;
        if (outs) {
                for (i = 0; i < num_jobs; i++)
                        if (outs[i])
                                free(outs[i]);
                free(outs);
        }
        return ret;
}

/*
 * Cross-validation: compare multi-buffer output against single-buffer
 * reference (state->shake128 / state->shake256) for a range of outlen values.
 */
static int
run_shake_mb_xval(struct IMB_MGR *mb_mgr, const IMB_HASH_ALG alg, const char *alg_name,
                  struct test_suite_context *ctx)
{
        /* Test messages */
        static const struct {
                size_t len;
                uint8_t data[32];
        } msgs[] = {
                { 0, { 0 } },
                { 1, { 0x00 } },
                { 3, { 0xab, 0xcd, 0xef } },
                { 32, { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f } },
        };
        /* Output lengths to test: covers < rate, = rate, and > rate */
        const int rate = (alg == IMB_AUTH_SHAKE128) ? SHAKE128_RATE : SHAKE256_RATE;
        const int outlens[] = {
                1, 7, 16, 32, 64, rate - 1, rate, rate + 1, rate * 2 - 1, rate * 2
        };
        int errors = 0;
        unsigned mi, oi;
        static const uint8_t empty[1] = { 0 };

        for (mi = 0; mi < DIM(msgs); mi++) {
                for (oi = 0; oi < DIM(outlens); oi++) {
                        const int outlen = outlens[oi];
                        uint8_t ref[512], got[512];
                        IMB_JOB *job;
                        int ok;

                        memset(ref, 0, sizeof(ref));
                        memset(got, 0, sizeof(got));

                        /* single-buffer reference */
                        if (alg == IMB_AUTH_SHAKE128)
                                mb_mgr->shake128(msgs[mi].len ? msgs[mi].data : empty, msgs[mi].len,
                                                 ref, outlen);
                        else
                                mb_mgr->shake256(msgs[mi].len ? msgs[mi].data : empty, msgs[mi].len,
                                                 ref, outlen);

                        /* multi-buffer job */
                        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                                ;
                        job = IMB_GET_NEXT_JOB(mb_mgr);
                        memset(job, 0, sizeof(*job));
                        job->cipher_mode = IMB_CIPHER_NULL;
                        job->cipher_direction = IMB_DIR_ENCRYPT;
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
                        job->hash_alg = alg;
                        job->src = msgs[mi].len ? msgs[mi].data : empty;
                        job->msg_len_to_hash_in_bytes = msgs[mi].len;
                        job->auth_tag_output = got;
                        job->auth_tag_output_len_in_bytes = outlen;
                        job = IMB_SUBMIT_JOB(mb_mgr);
                        if (!job)
                                job = IMB_FLUSH_JOB(mb_mgr);

                        if (!job || job->status != IMB_STATUS_COMPLETED) {
                                printf("%s xval: job error (msg=%u outlen=%d)\n", alg_name, mi,
                                       outlen);
                                test_suite_update(ctx, 0, 1);
                                errors++;
                                continue;
                        }

                        ok = (memcmp(ref, got, outlen) == 0);
                        test_suite_update(ctx, ok, !ok);
                        if (!ok) {
                                printf("%s xval mismatch: msg_len=%zu outlen=%d\n", alg_name,
                                       msgs[mi].len, outlen);
                                hexdump(stderr, "ref", ref, outlen);
                                hexdump(stderr, "got", got, outlen);
                                errors++;
                        }
                }
        }
        return errors;
}

/* ========================================================================= */
/* Public entry point                                                         */
/* ========================================================================= */
int
shake_test(struct IMB_MGR *mb_mgr);

int
shake_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context shake128_ctx, shake256_ctx;
        int errors = 0;
        unsigned vi;

        if (!(mb_mgr->features & IMB_FEATURE_AVX512_SKX))
                return 0;

        test_suite_start(&shake128_ctx, "SHAKE128_MB");
        test_suite_start(&shake256_ctx, "SHAKE256_MB");

        if (!quiet_mode)
                printf("SHAKE128 multi-buffer KAT tests:\n");

        /* ---- SHAKE128 KAT: 1, 2, 3, 4, 5 simultaneous jobs ---- */
        for (vi = 0; vi < DIM(shake128_vecs); vi++) {
                const shake_mb_vec_t *v = &shake128_vecs[vi];
                int nj;

                for (nj = 1; nj <= 5; nj++) {
                        int ok = (run_shake_mb_jobs(mb_mgr, v, nj) == 0);
                        test_suite_update(&shake128_ctx, ok, !ok);
                        if (!ok)
                                printf("  FAIL: %s (num_jobs=%d)\n", v->name, nj);
                }
        }

        if (!quiet_mode)
                printf("SHAKE256 multi-buffer KAT tests:\n");

        /* ---- SHAKE256 KAT: 1, 2, 3, 4, 5 simultaneous jobs ---- */
        for (vi = 0; vi < DIM(shake256_vecs); vi++) {
                const shake_mb_vec_t *v = &shake256_vecs[vi];
                int nj;

                for (nj = 1; nj <= 5; nj++) {
                        int ok = (run_shake_mb_jobs(mb_mgr, v, nj) == 0);
                        test_suite_update(&shake256_ctx, ok, !ok);
                        if (!ok)
                                printf("  FAIL: %s (num_jobs=%d)\n", v->name, nj);
                }
        }

        if (!quiet_mode)
                printf("SHAKE128 cross-validation (MB vs single-buffer):\n");
        errors += run_shake_mb_xval(mb_mgr, IMB_AUTH_SHAKE128, "SHAKE128", &shake128_ctx);

        if (!quiet_mode)
                printf("SHAKE256 cross-validation (MB vs single-buffer):\n");
        errors += run_shake_mb_xval(mb_mgr, IMB_AUTH_SHAKE256, "SHAKE256", &shake256_ctx);

        errors += test_suite_end(&shake128_ctx);
        errors += test_suite_end(&shake256_ctx);

        return errors;
}
