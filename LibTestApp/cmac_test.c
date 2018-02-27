/*****************************************************************************
 Copyright (c) 2018, Intel Corporation

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

#include <mb_mgr.h>
#include <aux_funcs.h>
#include "gcm_ctr_vectors_test.h"

int cmac_test(const enum arch_type arch, struct MB_MGR *mb_mgr);

/*
 * Test vectors from https://tools.ietf.org/html/rfc4493
 */

/*
 *  Subkey Generation
 *  K              2b7e1516 28aed2a6 abf71588 09cf4f3c
 *  AES-128(key,0) 7df76b0c 1ab899b3 3e42f047 b91b546f
 *  K1             fbeed618 35713366 7c85e08f 7236a8de
 *  K2             f7ddac30 6ae266cc f90bc11e e46d513b
 */
static const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t sub_key1[16] = {
        0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66,
        0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde
};
static const uint8_t sub_key2[16] = {
        0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc,
        0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b
};

/*
 *  Example 1: len = 0
 *  M              <empty string>
 *  AES-CMAC       bb1d6929 e9593728 7fa37d12 9b756746
 */
static const uint8_t T_1[16] = {
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
};

/*
 *  Example 2: len = 16
 *  M              6bc1bee2 2e409f96 e93d7e11 7393172a
 *  AES-CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c
 */
static const uint8_t T_2[16] = {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
};

/*
 *  Example 3: len = 40
 *  M              6bc1bee2 2e409f96 e93d7e11 7393172a
 *                 ae2d8a57 1e03ac9c 9eb76fac 45af8e51
 *                 30c81c46 a35ce411
 *  AES-CMAC       dfa66747 de9ae630 30ca3261 1497c827
 */
static const uint8_t T_3[16] = {
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
};

/*
 *  Example 4: len = 64
 *  M              6bc1bee2 2e409f96 e93d7e11 7393172a
 *                 ae2d8a57 1e03ac9c 9eb76fac 45af8e51
 *                 30c81c46 a35ce411 e5fbc119 1a0a52ef
 *                 f69f2445 df4f9b17 ad2b417b e66c3710
 *  AES-CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
 */
static const uint8_t T_4[16] = {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
};

static const uint8_t M[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const struct cmac_rfc4493_vector {
        const uint8_t *key;
        const uint8_t *sub_key1;
        const uint8_t *sub_key2;
        const uint8_t *M;
        size_t len;
        const uint8_t *T;
        size_t T_len;
} cmac_vectors[] = {
        { key, sub_key1, sub_key2, M, 0,  T_1, 16 },
        { key, sub_key1, sub_key2, M, 16, T_2, 16 },
        { key, sub_key1, sub_key2, M, 40, T_3, 16 },
        { key, sub_key1, sub_key2, M, 64, T_4, 16 },
        { key, sub_key1, sub_key2, M, 0,  T_1, 12 },
        { key, sub_key1, sub_key2, M, 16, T_2, 12 },
        { key, sub_key1, sub_key2, M, 40, T_3, 12 },
        { key, sub_key1, sub_key2, M, 64, T_4, 12 },
};

#ifdef _WIN32
#define snprintf _snprintf
#endif

static void
hexdump(FILE *fp,
        const char *msg,
        const void *p,
        size_t len)
{
        unsigned int i, out, ofs;
        const unsigned char *data = p;

        fprintf(fp, "%s\n", msg);

        ofs = 0;
        while (ofs < len) {
                char line[120];

                out = snprintf(line, sizeof(line), "%08x:", ofs);
                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        out += snprintf(line + out, sizeof(line) - out,
                                        " %02x", (data[ofs + i] & 0xff));
                for (; i <= 16; i++)
                        out += snprintf(line + out, sizeof(line) - out, " | ");
                for (i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];

                        if ((c < ' ') || (c > '~'))
                                c = '.';
                        out += snprintf(line + out,
                                        sizeof(line) - out, "%c", c);
                }
                fprintf(fp, "%s\n", line);
        }
}

static int
cmac_job_ok(const struct cmac_rfc4493_vector *vec,
            const struct JOB_AES_HMAC *job,
            const uint8_t *auth,
            const uint8_t *padding,
            const size_t sizeof_padding)
{
        const size_t auth_len = job->auth_tag_output_len_in_bytes;

        if (job->status != STS_COMPLETED) {
                printf("%d Error status:%d", __LINE__, job->status);
                return 0;
        }

        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + auth_len],
                   sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target",
                        &auth[sizeof_padding + auth_len], sizeof_padding);
                return 0;
        }

        if (memcmp(padding, &auth[0], sizeof_padding)) {
                printf("hash overwrite head\n");
                hexdump(stderr, "Target", &auth[0], sizeof_padding);
                return 0;
        }

        if (memcmp(vec->T, &auth[sizeof_padding], auth_len)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding],
                        auth_len);
                hexdump(stderr, "Expected", vec->T,
                        auth_len);
                return 0;
        }
        return 1;
}

static int
test_cmac(struct MB_MGR *mb_mgr,
          const struct cmac_rfc4493_vector *vec,
          const int dir,
          const int num_jobs)
{
        DECLARE_ALIGNED(uint32_t expkey[4*15], 16);
        DECLARE_ALIGNED(uint32_t dust[4*15], 16);
        uint32_t skey1[4], skey2[4];
        struct JOB_AES_HMAC *job;
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int i = 0, jobs_rx = 0, ret = -1;

        if (auths == NULL) {
		fprintf(stderr, "Can't allocate buffer memory\n");
		goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                auths[i] = malloc(16 + (sizeof(padding) * 2));
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(auths[i], -1, 16 + (sizeof(padding) * 2));
        }

        IMB_AES_KEYEXP_128(mb_mgr, vec->key, expkey, dust);
        IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, expkey, skey1, skey2);

        if (memcmp(vec->sub_key1, skey1, sizeof(skey1))) {
                printf("sub-key1 mismatched\n");
                hexdump(stderr, "Received", &skey1[0], sizeof(skey1));
                hexdump(stderr, "Expected", vec->sub_key1, sizeof(skey1));
		goto end;
        }

        if (memcmp(vec->sub_key2, skey2, sizeof(skey2))) {
                printf("sub-key2 mismatched\n");
                hexdump(stderr, "Received", &skey2[0], sizeof(skey2));
                hexdump(stderr, "Expected", vec->sub_key2, sizeof(skey2));
		goto end;
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = HASH_CIPHER;
                job->cipher_mode = NULL_CIPHER;

                job->hash_alg = AES_CMAC;
                job->src = vec->M;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->len;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->T_len;

                job->u.CMAC._key_expanded = expkey;
                job->u.CMAC._skey1 = skey1;
                job->u.CMAC._skey2 = skey2;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (num_jobs < 4) {
                                printf("%d Unexpected return from submit_job\n",
                                       __LINE__);
                                goto end;
                        }
                        if (!cmac_job_ok(vec, job, job->user_data, padding,
                                         sizeof(padding)))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (!cmac_job_ok(vec, job, job->user_data, padding,
                                 sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

 end:
        for (i = 0; i < num_jobs; i++) {
                if (auths[i] != NULL)
                        free(auths[i]);
        }

 end2:
        if (auths != NULL)
                free(auths);

        return ret;
}

static int
test_cmac_std_vectors(struct MB_MGR *mb_mgr, const int num_jobs)
{
	const int vectors_cnt = sizeof(cmac_vectors) / sizeof(cmac_vectors[0]);
	int vect;
	int errors = 0;

	printf("AES-CMAC standard test vectors (N jobs = %d):\n", num_jobs);
	for (vect = 1; vect <= vectors_cnt; vect++) {
                const int idx = vect - 1;
#ifdef DEBUG
		printf("Standard vector [%d/%d] M len, T len:%d\n",
                       vect, vectors_cnt,
                       (int) cmac_vectors[idx].len
                       (int) cmac_vectors[idx].T_len);
#else
		printf(".");
#endif

                if (test_cmac(mb_mgr, &cmac_vectors[idx], ENCRYPT, num_jobs)) {
                        printf("error #%d encrypt\n", vect);
                        errors++;
                }

                if (test_cmac(mb_mgr, &cmac_vectors[idx], DECRYPT, num_jobs)) {
                        printf("error #%d decrypt\n", vect);
                        errors++;
                }

	}
	printf("\n");
	return errors;
}

int
cmac_test(const enum arch_type arch,
          struct MB_MGR *mb_mgr)
{
        int errors = 0;

        (void) arch; /* unused */

        errors += test_cmac_std_vectors(mb_mgr, 1);
        errors += test_cmac_std_vectors(mb_mgr, 3);
        errors += test_cmac_std_vectors(mb_mgr, 4);
        errors += test_cmac_std_vectors(mb_mgr, 5);
        errors += test_cmac_std_vectors(mb_mgr, 7);
        errors += test_cmac_std_vectors(mb_mgr, 8);
        errors += test_cmac_std_vectors(mb_mgr, 9);

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

	return errors;
}
