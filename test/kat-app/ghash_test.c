#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>		/* for memcmp() */

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"

int ghash_test(struct IMB_MGR *mb_mgr);

static const uint8_t K23[] = {
	0xA1, 0xF6, 0x25, 0x8C, 0x87, 0x7D, 0x5F, 0xCD,
	0x89, 0x64, 0x48, 0x45, 0x38, 0xBF, 0xC9, 0x2C
};

static const uint8_t P23[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t T23[] = {
	0x9E, 0xE5, 0xA5, 0x1F, 0xBE, 0x28, 0xA1, 0x15,
	0x3E, 0xF1, 0x96, 0xF5, 0x0B, 0xBF, 0x03, 0xCA
};

static const uint8_t K24[] = {
	0x1F, 0x0A, 0x6D, 0xCC, 0x67, 0xB1, 0x87, 0x22,
	0x98, 0x22, 0x77, 0x91, 0xDD, 0xA1, 0x9B, 0x6A
};

static const uint8_t P24[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

static const uint8_t T24[] = {
	0xB5, 0x40, 0xDA, 0x44, 0xA3, 0x8C, 0x9C, 0x2B,
	0x95, 0x8E, 0x4B, 0x0B
};

static const uint8_t K25[] = {
	0x1F, 0x0A, 0x6D, 0xCC, 0x67, 0xB1, 0x87, 0x22,
	0x98, 0x22, 0x77, 0x91, 0xDD, 0xA1, 0x9B, 0x6A
};

static const uint8_t P25[] = {
    	0x05
};

static const uint8_t T25[] = {
	0xE6, 0xCE, 0x47, 0xB5, 0xFB, 0xF2, 0xEF, 0x37,
	0x51, 0xF1, 0x57, 0x53, 0xAD, 0x56, 0x4F, 0xED
};

static const uint8_t K33[] = {
	0x1f, 0x0f, 0x8a, 0x3a, 0xca, 0x64, 0x2e, 0xde,
	0xb1, 0xdf, 0x8a, 0x52, 0x9a, 0x29, 0x76, 0xee
};
static const uint8_t P33[] = {
	0x9b, 0xb5, 0x92, 0x9f, 0xa7, 0xaa, 0x83, 0xfd,
	0x0c, 0xd1, 0x83, 0x3a, 0x8e, 0xd5, 0x4d, 0xda,
	0x6a, 0xaf, 0xa1, 0xc7, 0xa1, 0x32, 0x3a, 0xd4,
	0x92, 0x9a, 0x2c, 0x83, 0xc6, 0x27, 0x92, 0x59,
	0x28, 0x90, 0x11, 0xde, 0x19, 0x4e, 0xd5, 0x16,
	0xef, 0x4f, 0x72, 0xeb, 0x79, 0x18, 0xd5, 0xb1,
	0xc5, 0x22, 0x40, 0x14, 0x92, 0xa2
};
static const uint8_t T33[] =  {
	0x8B, 0xA5, 0x3F, 0x5F, 0xD7, 0x0E, 0x55, 0x7C,
	0x30, 0xD4, 0xF2, 0xE1, 0x1A, 0x4F, 0xF8, 0xC7
};

static const struct gcm_ctr_vector ghash_vectors[] = {
	ghash_vector(23),
	ghash_vector(24),
	ghash_vector(25),
	ghash_vector(33)
};

static int check_data(const uint8_t *test, const uint8_t *expected,
                      uint64_t len, const char *data_name)
{
	int mismatch;
	int is_error = 0;

	if (len == 0)
		return is_error;

	if (test == NULL || expected == NULL|| data_name == NULL)
		return 1;

	mismatch = memcmp(test, expected, len);
	if (mismatch) {
		uint64_t a;

		is_error = 1;
		printf("  expected results don't match %s \t\t", data_name);
        	for (a = 0; a < len; a++)
			if (test[a] != expected[a]) {
				printf(" '%x' != '%x' at %llx of %llx\n", test[a], expected[a],
					(unsigned long long) a, (unsigned long long) len);
				break;
            		}
	}
	return is_error;
}

int ghash_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        int use_job_api = 0;

        test_suite_start(&ts, "GHASH");

        while (use_job_api < 2) {
		const int vectors_cnt = DIM(ghash_vectors);
		int vect;

		printf("GHASH test vectors (%s API):\n", use_job_api ? "job" : "direct");
		for (vect = 0; vect < vectors_cnt; vect++) {
			struct gcm_key_data gdata_key;
			struct gcm_ctr_vector const *vector = &ghash_vectors[vect];
			uint8_t T_test[16];

			memset(&gdata_key, 0, sizeof(struct gcm_key_data));
			memset(T_test, 0, sizeof(T_test));
			IMB_GHASH_PRE(mb_mgr, vector->K, &gdata_key);

			if (!use_job_api) {
				IMB_GHASH(mb_mgr, &gdata_key, vector->P,
					  vector->Plen, T_test, vector->Tlen);
			} else {
				IMB_JOB *job = IMB_GET_NEXT_JOB(mb_mgr);

				if (!job) {
					fprintf(stderr, "failed to get job for ghash\n");
					test_suite_update(&ts, 0, 1);
					return test_suite_end(&ts);
				}

				job->cipher_mode = IMB_CIPHER_NULL;
				job->hash_alg = IMB_AUTH_GHASH;
				job->u.GHASH._key = &gdata_key;
				job->u.GHASH._init_tag = T_test;
				job->src = vector->P;
				job->msg_len_to_hash_in_bytes = vector->Plen;
				job->hash_start_src_offset_in_bytes = UINT64_C(0);
				job->auth_tag_output = T_test;
				job->auth_tag_output_len_in_bytes = vector->Tlen;

				job = IMB_SUBMIT_JOB(mb_mgr);

				if (job == NULL)
					job = IMB_FLUSH_JOB(mb_mgr);
				if (job == NULL) {
					fprintf(stderr, "No job retrieved\n");
				}
				else if (job->status != IMB_STATUS_COMPLETED) {
					fprintf(stderr, "failed job, status:%d\n", job->status);
				}
			}

			if (check_data(T_test, vector->T, vector->Tlen, "generated tag (T)"))
				test_suite_update(&ts, 0, 1);
			else
				test_suite_update(&ts, 1, 0);
		}
		use_job_api++;
        }

        return test_suite_end(&ts);
}
