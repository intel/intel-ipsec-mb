/**********************************************************************
  Copyright(c) 2011-2017 Intel Corporation All rights reserved.

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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>		// for memcmp

#include <gcm_defines.h>
#include "gcm_vectors.h"
#include "gcm_std_vectors_test.h"

typedef void (*gcm_enc_dec_fn_t)(struct gcm_data *,
                                 uint8_t *, uint8_t const *, uint64_t,
                                 uint8_t *, uint8_t const *, uint64_t,
                                 uint8_t *, uint64_t);
typedef void (*gcm_pre_fn_t)(const void *, struct gcm_data *);

static gcm_pre_fn_t aesni_gcm128_pre = NULL;
static gcm_enc_dec_fn_t aesni_gcm128_enc = NULL;
static gcm_enc_dec_fn_t aesni_gcm128_dec = NULL;

static gcm_pre_fn_t aesni_gcm192_pre = NULL;
static gcm_enc_dec_fn_t aesni_gcm192_enc = NULL;
static gcm_enc_dec_fn_t aesni_gcm192_dec = NULL;

static gcm_pre_fn_t aesni_gcm256_pre = NULL;
static gcm_enc_dec_fn_t aesni_gcm256_enc = NULL;
static gcm_enc_dec_fn_t aesni_gcm256_dec = NULL;

static int check_data(uint8_t * test, uint8_t * expected, uint64_t len,
                      char *data_name)
{
	int mismatch;
	int is_error = 0;

	mismatch = memcmp(test, expected, len);
	if (mismatch) {
                uint64_t a;

		is_error = 1;
		printf("  expected results don't match %s \t\t", data_name);
                for (a = 0; a < len; a++) {
                        if (test[a] != expected[a]) {
                                printf(" '%x' != '%x' at %lx of %lx\n",
                                       test[a], expected[a], a, len);
                                break;
                        }
                }
	}
	return is_error;
}

static int test_gcm128_std_vectors(gcm_vector const *vector)
{
	struct gcm_data gdata;
	int is_error = 0;
	// Temporary array for the calculated vectors
	uint8_t *ct_test = NULL;
	uint8_t *pt_test = NULL;
	uint8_t *IV_c = NULL;
	uint8_t *T_test = NULL;
	uint8_t *T2_test = NULL;
	uint8_t const IVend[] = GCM_IV_END_MARK;
	uint64_t IV_alloc_len = 0;

	// Allocate space for the calculated ciphertext
	ct_test = malloc(vector->Plen);
	if (ct_test == NULL) {
		fprintf(stderr, "Can't allocate ciphertext memory\n");
		return 1;
	}
	// Allocate space for the calculated ciphertext
	pt_test = malloc(vector->Plen);
	if (pt_test == NULL) {
		fprintf(stderr, "Can't allocate plaintext memory\n");
		return 1;
	}
	IV_alloc_len = vector->IVlen + sizeof(IVend);
	// Allocate space for the calculated ciphertext
	IV_c = malloc(IV_alloc_len);
	if (IV_c == NULL) {
		fprintf(stderr, "Can't allocate ciphertext memory\n");
		return 1;
	}
	//Add end marker to the IV data
	memcpy(IV_c, vector->IV, vector->IVlen);
	memcpy(&IV_c[vector->IVlen], IVend, sizeof(IVend));

	T_test = malloc(vector->Tlen);
	T2_test = malloc(vector->Tlen);
	if ((T_test == NULL) || (T2_test == NULL)) {
		fprintf(stderr, "Can't allocate tag memory\n");
		return 1;
	}
	// This is only required once for a given key
	aesni_gcm128_pre(vector->K, &gdata);

	////
	// Encrypt
	////
	aesni_gcm128_enc(&gdata, ct_test, vector->P, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->C, vector->Plen,
                               "encrypted cypher text (C)");
	is_error |= check_data(T_test, vector->T, vector->Tlen, "tag (T)");

	// test of in-place encrypt
	memcpy(pt_test, vector->P, vector->Plen);
	aesni_gcm128_enc(&gdata, pt_test, pt_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->C, vector->Plen,
                               "encrypted cypher text(in-place)");
	memset(ct_test, 0, vector->Plen);
	memset(T_test, 0, vector->Tlen);

	////
	// Decrypt
	////
	aesni_gcm128_dec(&gdata, pt_test, vector->C, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->P, vector->Plen,
                               "decrypted plain text (P)");
	// GCM decryption outputs a 16 byte tag value
        // that must be verified against the expected tag value
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T)");

	// test in in-place decrypt
	memcpy(ct_test, vector->C, vector->Plen);
	aesni_gcm128_dec(&gdata, ct_test, ct_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->P, vector->Plen,
                               "plain text (P) - in-place");
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T) - in-place");
	// enc -> dec
	aesni_gcm128_enc(&gdata, ct_test, vector->P, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	memset(pt_test, 0, vector->Plen);
	aesni_gcm128_dec(&gdata, pt_test, ct_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T2_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->P, vector->Plen,
                               "self decrypted plain text (P)");
	is_error |= check_data(T_test, T2_test, vector->Tlen,
                               "self decrypted tag (T)");

	memset(pt_test, 0, vector->Plen);

	if (NULL != ct_test)
		free(ct_test);
	if (NULL != pt_test)
		free(pt_test);
	if (NULL != IV_c)
		free(IV_c);
	if (NULL != T_test)
		free(T_test);
	if (NULL != T2_test)
		free(T2_test);

	return is_error;
}

static int test_gcm192_std_vectors(gcm_vector const *vector)
{
	struct gcm_data gdata;
	int is_error = 0;
	// Temporary array for the calculated vectors
	uint8_t *ct_test = NULL;
	uint8_t *pt_test = NULL;
	uint8_t *IV_c = NULL;
	uint8_t *T_test = NULL;
	uint8_t *T2_test = NULL;
	uint8_t const IVend[] = GCM_IV_END_MARK;
	uint64_t IV_alloc_len = 0;

	// Allocate space for the calculated ciphertext
	ct_test = malloc(vector->Plen);
	// Allocate space for the calculated ciphertext
	pt_test = malloc(vector->Plen);
	if ((ct_test == NULL) || (pt_test == NULL)) {
		fprintf(stderr, "Can't allocate ciphertext or plaintext memory\n");
		return 1;
	}
	IV_alloc_len = vector->IVlen + sizeof(IVend);
	// Allocate space for the calculated ciphertext
	IV_c = malloc(IV_alloc_len);
	if (IV_c == NULL) {
		fprintf(stderr, "Can't allocate ciphertext memory\n");
		return 1;
	}
	//Add end marker to the IV data
	memcpy(IV_c, vector->IV, vector->IVlen);
	memcpy(&IV_c[vector->IVlen], IVend, sizeof(IVend));

	T_test = malloc(vector->Tlen);
	T2_test = malloc(vector->Tlen);
	if (T_test == NULL) {
		fprintf(stderr, "Can't allocate tag memory\n");
		return 1;
	}
	// This is only required once for a given key
	aesni_gcm192_pre(vector->K, &gdata);

	////
	// Encrypt
	////
	memset(ct_test, 0, vector->Plen);
	aesni_gcm192_enc(&gdata, ct_test, vector->P, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->C, vector->Plen,
                               "encrypted cypher text (C)");
	is_error |= check_data(T_test, vector->T, vector->Tlen, "tag (T)");

	// test of in-place encrypt
	memcpy(pt_test, vector->P, vector->Plen);
	aesni_gcm192_enc(&gdata, pt_test, pt_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->C, vector->Plen,
                               "encrypted cypher text(in-place)");
	memset(ct_test, 0, vector->Plen);
	memset(T_test, 0, vector->Tlen);

	////
	// Decrypt
	////
	aesni_gcm192_dec(&gdata, pt_test, vector->C, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->P, vector->Plen,
                               "decrypted plain text (P)");
	// GCM decryption outputs a 16 byte tag value
        // that must be verified against the expected tag value
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T)");

	// test in in-place decrypt
	memcpy(ct_test, vector->C, vector->Plen);
	aesni_gcm192_dec(&gdata, ct_test, ct_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->P, vector->Plen,
                               "plain text (P) - in-place");
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T) - in-place");
	// enc -> dec
	aesni_gcm192_enc(&gdata, ct_test, vector->P, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	memset(pt_test, 0, vector->Plen);
	aesni_gcm192_dec(&gdata, pt_test, ct_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T2_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->P, vector->Plen,
                               "self decrypted plain text (P)");
	is_error |= check_data(T_test, T2_test, vector->Tlen,
                               "self decrypted tag (T)");

	if (NULL != ct_test)
		free(ct_test);
	if (NULL != pt_test)
		free(pt_test);
	if (NULL != IV_c)
		free(IV_c);
	if (NULL != T_test)
		free(T_test);
	if (NULL != T2_test)
		free(T2_test);

	return is_error;
}

static int test_gcm256_std_vectors(gcm_vector const *vector)
{
	struct gcm_data gdata;
	int is_error = 0;
	// Temporary array for the calculated vectors
	uint8_t *ct_test = NULL;
	uint8_t *pt_test = NULL;
	uint8_t *IV_c = NULL;
	uint8_t *T_test = NULL;
	uint8_t *T2_test = NULL;
	uint8_t const IVend[] = GCM_IV_END_MARK;
	uint64_t IV_alloc_len = 0;

	// Allocate space for the calculated ciphertext
	ct_test = malloc(vector->Plen);
	// Allocate space for the calculated ciphertext
	pt_test = malloc(vector->Plen);
	if ((ct_test == NULL) || (pt_test == NULL)) {
		fprintf(stderr, "Can't allocate ciphertext or plaintext memory\n");
		return 1;
	}
	IV_alloc_len = vector->IVlen + sizeof(IVend);
	// Allocate space for the calculated ciphertext
	IV_c = malloc(IV_alloc_len);
	if (IV_c == NULL) {
		fprintf(stderr, "Can't allocate ciphertext memory\n");
		return 1;
	}
	//Add end marker to the IV data
	memcpy(IV_c, vector->IV, vector->IVlen);
	memcpy(&IV_c[vector->IVlen], IVend, sizeof(IVend));

	T_test = malloc(vector->Tlen);
	T2_test = malloc(vector->Tlen);
	if (T_test == NULL) {
		fprintf(stderr, "Can't allocate tag memory\n");
		return 1;
	}
	// This is only required once for a given key
	aesni_gcm256_pre(vector->K, &gdata);

	////
	// Encrypt
	////
	memset(ct_test, 0, vector->Plen);
	aesni_gcm256_enc(&gdata, ct_test, vector->P, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->C, vector->Plen,
                               "encrypted cypher text (C)");
	is_error |= check_data(T_test, vector->T, vector->Tlen, "tag (T)");

	// test of in-place encrypt
	memcpy(pt_test, vector->P, vector->Plen);
	aesni_gcm256_enc(&gdata, pt_test, pt_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->C, vector->Plen,
                               "encrypted cypher text(in-place)");
	memset(ct_test, 0, vector->Plen);
	memset(T_test, 0, vector->Tlen);

	////
	// Decrypt
	////
	aesni_gcm256_dec(&gdata, pt_test, vector->C, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->P, vector->Plen,
                               "decrypted plain text (P)");
	// GCM decryption outputs a 16 byte tag value
        // that must be verified against the expected tag value
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T)");

	// test in in-place decrypt
	memcpy(ct_test, vector->C, vector->Plen);
	aesni_gcm256_dec(&gdata, ct_test, ct_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->P, vector->Plen,
                               "plain text (P) - in-place");
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T) - in-place");
	// enc -> dec
	aesni_gcm256_enc(&gdata, ct_test, vector->P, vector->Plen,
			 IV_c, vector->A, vector->Alen, T_test, vector->Tlen);
	memset(pt_test, 0, vector->Plen);
	aesni_gcm256_dec(&gdata, pt_test, ct_test, vector->Plen, IV_c,
			 vector->A, vector->Alen, T2_test, vector->Tlen);
	is_error |=
                check_data(pt_test, vector->P, vector->Plen,
                           "self decrypted plain text (P)");
	is_error |= check_data(T_test, T2_test, vector->Tlen,
                               "self decrypted tag (T)");

	if (NULL != ct_test)
		free(ct_test);
	if (NULL != pt_test)
		free(pt_test);
	if (NULL != IV_c)
		free(IV_c);
	if (NULL != T_test)
		free(T_test);
	if (NULL != T2_test)
		free(T2_test);

	return is_error;
}

static int test_gcm_std_vectors(void)
{
	int const vectors_cnt = sizeof(gcm_vectors) / sizeof(gcm_vectors[0]);
	int vect;
	int is_error = 0;

	printf("AES-GCM standard test vectors:\n");
	for (vect = 0; ((vect < vectors_cnt) /*&& (1 == is_error) */ ); vect++) {
#ifdef DEBUG
		printf("Standard vector %d/%d  Keylen:%d IVlen:%d PTLen:%d "
                       "AADlen:%d Tlen:%d\n",
                       vect, vectors_cnt - 1,
                       (int) gcm_vectors[vect].Klen,
                       (int) gcm_vectors[vect].IVlen,
                       (int) gcm_vectors[vect].Plen,
                       (int) gcm_vectors[vect].Alen,
                       (int) gcm_vectors[vect].Tlen);
#else
		printf(".");
#endif
                switch (gcm_vectors[vect].Klen) {
                case BITS_128:
			is_error |= test_gcm128_std_vectors(&gcm_vectors[vect]);
                        break;
                case BITS_192:
                        is_error |= test_gcm192_std_vectors(&gcm_vectors[vect]);
                        break;
                case BITS_256:
			is_error |= test_gcm256_std_vectors(&gcm_vectors[vect]);
                        break;
                default:
                        is_error = -1;
                        break;
                }
		if (0 != is_error)
			return is_error;
	}
	printf("\n");
	return is_error;
}

int gcm_test(const enum arch_type arch)
{
	int errors = 0;

        switch(arch) {
        case ARCH_SSE:
                aesni_gcm128_pre = aesni_gcm128_pre_sse;
                aesni_gcm128_enc = aesni_gcm128_enc_sse;
                aesni_gcm128_dec = aesni_gcm128_dec_sse;
                aesni_gcm192_pre = aesni_gcm192_pre_sse;
                aesni_gcm192_enc = aesni_gcm192_enc_sse;
                aesni_gcm192_dec = aesni_gcm192_dec_sse;
                aesni_gcm256_pre = aesni_gcm256_pre_sse;
                aesni_gcm256_enc = aesni_gcm256_enc_sse;
                aesni_gcm256_dec = aesni_gcm256_dec_sse;
                break;
        case ARCH_AVX:
                aesni_gcm128_pre = aesni_gcm128_pre_avx_gen2;
                aesni_gcm128_enc = aesni_gcm128_enc_avx_gen2;
                aesni_gcm128_dec = aesni_gcm128_dec_avx_gen2;
                aesni_gcm192_pre = aesni_gcm192_pre_avx_gen2;
                aesni_gcm192_enc = aesni_gcm192_enc_avx_gen2;
                aesni_gcm192_dec = aesni_gcm192_dec_avx_gen2;
                aesni_gcm256_pre = aesni_gcm256_pre_avx_gen2;
                aesni_gcm256_enc = aesni_gcm256_enc_avx_gen2;
                aesni_gcm256_dec = aesni_gcm256_dec_avx_gen2;
                break;
        case ARCH_AVX2:
                aesni_gcm128_pre = aesni_gcm128_pre_avx_gen4;
                aesni_gcm128_enc = aesni_gcm128_enc_avx_gen4;
                aesni_gcm128_dec = aesni_gcm128_dec_avx_gen4;
                aesni_gcm192_pre = aesni_gcm192_pre_avx_gen4;
                aesni_gcm192_enc = aesni_gcm192_enc_avx_gen4;
                aesni_gcm192_dec = aesni_gcm192_dec_avx_gen4;
                aesni_gcm256_pre = aesni_gcm256_pre_avx_gen4;
                aesni_gcm256_enc = aesni_gcm256_enc_avx_gen4;
                aesni_gcm256_dec = aesni_gcm256_dec_avx_gen4;
                break;
        default:
                printf("Invalid architecture type %d selected!\n", arch);
                return 1;
        }
        
	errors = test_gcm_std_vectors();

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

	return errors;
}
