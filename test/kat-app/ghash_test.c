/**********************************************************************
  Copyright(c) 2023 Intel Corporation All rights reserved.

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
#include <string.h>		/* for memcmp() */

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "mac_test.h"

int ghash_test(struct IMB_MGR *mb_mgr);

extern const struct mac_test ghash_test_json[];

static int check_data(const uint8_t *test, const char *expected,
                      uint64_t len, const char *data_name)
{
	int mismatch;
	int is_error = 0;

	if (len == 0)
		return is_error;

	if (test == NULL || expected == NULL || data_name == NULL)
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
		const struct mac_test *vec = ghash_test_json;

		printf("GHASH test vectors (%s API):\n", use_job_api ? "job" : "direct");
		while (vec->msg != NULL) {
			struct gcm_key_data gdata_key;
			uint8_t T_test[16];

			memset(&gdata_key, 0, sizeof(struct gcm_key_data));
			memset(T_test, 0, sizeof(T_test));
			IMB_GHASH_PRE(mb_mgr, vec->key, &gdata_key);

			if (!use_job_api) {
				IMB_GHASH(mb_mgr, &gdata_key, vec->msg,
					  (vec->msgSize / 8), T_test, vec->tagSize / 8);
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
				job->src = (const void *) vec->msg;
				job->msg_len_to_hash_in_bytes = (vec->msgSize / 8);
				job->hash_start_src_offset_in_bytes = UINT64_C(0);
				job->auth_tag_output = T_test;
				job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

				job = IMB_SUBMIT_JOB(mb_mgr);

				if (job == NULL)
					job = IMB_FLUSH_JOB(mb_mgr);
				if (job == NULL)
					fprintf(stderr, "No job retrieved\n");
				else if (job->status != IMB_STATUS_COMPLETED)
					fprintf(stderr, "failed job, status:%d\n", job->status);
			}

			if (check_data(T_test, vec->tag, vec->tagSize / 8, "generated tag (T)"))
				test_suite_update(&ts, 0, 1);
			else
				test_suite_update(&ts, 1, 0);
			vec++;
		}
		use_job_api++;
        }

        return test_suite_end(&ts);
}
