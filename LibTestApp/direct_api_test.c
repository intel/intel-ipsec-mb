/*****************************************************************************
 Copyright (c) 2019, Intel Corporation

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
#include <setjmp.h>
#include <signal.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"

#define BUF_SIZE ((uint32_t)sizeof(struct gcm_key_data))

int
direct_api_test(const enum arch_type arch, struct MB_MGR *mb_mgr);

/* Used to restore environment after potential segfaults */
jmp_buf env;

#ifndef DEBUG
/* Signal handler to handle segfaults */
static void
seg_handler(int signum)
{
        (void) signum; /* unused */

        signal(SIGSEGV, seg_handler); /* reset handler */
        longjmp(env, 1); /* reset env */
}
#endif /* DEBUG */

/*
 * @brief Performs direct GCM API invalid param tests
 */
static int
test_gcm_api(struct MB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        struct gcm_key_data *key_data = (struct gcm_key_data *)out_buf;
        int seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occured!\n", __func__);
                return 1;
        }

        memset(out_buf, 0, text_len);
        memset(zero_buf, 0, text_len);

        /**
         * API are generally tested twice:
         * 1. test with all invalid params
         * 2. test with some valid params (in, out, len)
         *    and verify output buffer is not modified
         */

        /* GCM Encrypt API tests */
        IMB_AES128_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1,
                           NULL, NULL, -1, NULL, -1);
        IMB_AES128_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf,
                           text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_ENC, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1,
                           NULL, NULL, -1, NULL, -1);
        IMB_AES192_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf,
                           text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_ENC, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1,
                           NULL, NULL, -1, NULL, -1);
        IMB_AES256_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf,
                           text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_ENC, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        /* GCM Decrypt API tests */
        IMB_AES128_GCM_DEC(mgr, NULL, NULL, NULL, NULL, -1,
                           NULL, NULL, -1, NULL, -1);
        IMB_AES128_GCM_DEC(mgr, NULL, NULL, out_buf, zero_buf,
                           text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_DEC, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1,
                           NULL, NULL, -1, NULL, -1);
        IMB_AES192_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf,
                           text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_DEC, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_DEC(mgr, NULL, NULL, NULL, NULL, -1,
                           NULL, NULL, -1, NULL, -1);
        IMB_AES256_GCM_DEC(mgr, NULL, NULL, out_buf, zero_buf,
                           text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_DEC, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        /* GCM Init tests */
        IMB_AES128_GCM_INIT(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_INIT(mgr, NULL, (struct gcm_context_data *)out_buf,
                            NULL, NULL, text_len);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_INIT, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_INIT(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_INIT(mgr, NULL, (struct gcm_context_data *)out_buf,
                            NULL, NULL, text_len);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_INIT, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_INIT(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_INIT(mgr, NULL, (struct gcm_context_data *)out_buf,
                            NULL, NULL, text_len);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_INIT, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        /* GCM Encrypt update tests */
        IMB_AES128_GCM_ENC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_ENC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_ENC_UPDATE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_ENC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_ENC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_ENC_UPDATE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_ENC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_ENC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_ENC_UPDATE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        /* GCM Decrypt update tests */
        IMB_AES128_GCM_DEC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_DEC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_DEC_UPDATE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_DEC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_DEC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_DEC_UPDATE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_DEC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_DEC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_DEC_UPDATE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        /* GCM Encrypt complete tests */
        IMB_AES128_GCM_ENC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_ENC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_ENC_FINALIZE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_ENC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_ENC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_ENC_FINALIZE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_ENC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_ENC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_ENC_FINALIZE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        /* GCM Decrypt complete tests */
        IMB_AES128_GCM_DEC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_DEC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_DEC_FINALIZE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_DEC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_DEC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_DEC_FINALIZE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_DEC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_DEC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_DEC_FINALIZE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        /* GCM key data pre-processing tests */
        IMB_AES128_GCM_PRECOMP(mgr, NULL);
        printf(".");

        IMB_AES192_GCM_PRECOMP(mgr, NULL);
        printf(".");

        IMB_AES256_GCM_PRECOMP(mgr, NULL);
        printf(".");

        IMB_AES128_GCM_PRE(mgr, NULL, NULL);
        IMB_AES128_GCM_PRE(mgr, NULL, key_data);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_PRE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES192_GCM_PRE(mgr, NULL, NULL);
        IMB_AES192_GCM_PRE(mgr, NULL, key_data);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_PRE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        IMB_AES256_GCM_PRE(mgr, NULL, NULL);
        IMB_AES256_GCM_PRE(mgr, NULL, key_data);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_PRE, invalid "
                       "param test failed!\n", __func__);
                return 1;
        }
        printf(".");

        printf("\n");
        return 0;
}

int
direct_api_test(const enum arch_type arch, struct MB_MGR *mb_mgr)
{
        int errors = 0;
        (void) arch; /* unused */
#ifndef DEBUG
#ifdef _WIN32
        void *handler;
#else
        sighandler_t handler;
#endif
#endif
        printf("Invalid Direct API arguments test:\n");

        if ((mb_mgr->features & IMB_FEATURE_SAFE_PARAM) == 0) {
                printf("SAFE_PARAM feature disabled, skipping tests\n");
                return 0;
        }
#ifndef DEBUG
        handler = signal(SIGSEGV, seg_handler);
#endif

        errors += test_gcm_api(mb_mgr);

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

#ifndef DEBUG
        signal(SIGSEGV, handler);
#endif

	return errors;
}
