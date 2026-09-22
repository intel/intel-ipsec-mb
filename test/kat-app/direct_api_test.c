/*****************************************************************************
 Copyright (c) 2019-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"

#define BUF_SIZE ((uint32_t) sizeof(struct gcm_key_data))
#define NUM_BUFS 8

#ifdef _WIN32
#define __func__ __FUNCTION__
#endif

int
direct_api_test(struct IMB_MGR *mb_mgr);

/* Used to restore environment after potential segfaults */
jmp_buf env;

#ifndef DEBUG
#ifndef _WIN32
static void
seg_handler(int signum) __attribute__((noreturn));
#endif
/* Signal handler to handle segfaults */
static void
seg_handler(int signum)
{
        (void) signum; /* unused */

        signal(SIGSEGV, seg_handler); /* reset handler */
        longjmp(env, 1);              /* reset env */
}
#endif /* DEBUG */

static void
print_progress(void)
{
        if (!quiet_mode)
                printf(".");
}

/*
 * @brief Performs direct GCM API invalid param tests
 */
static int
test_gcm_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        struct gcm_key_data *key_data = (struct gcm_key_data *) out_buf;
        int seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
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
        IMB_AES128_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1, NULL, NULL, -1, NULL, -1);
        IMB_AES128_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf, text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_ENC, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1, NULL, NULL, -1, NULL, -1);
        IMB_AES192_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf, text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_ENC, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1, NULL, NULL, -1, NULL, -1);
        IMB_AES256_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf, text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_ENC, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        /* GCM Decrypt API tests */
        IMB_AES128_GCM_DEC(mgr, NULL, NULL, NULL, NULL, -1, NULL, NULL, -1, NULL, -1);
        IMB_AES128_GCM_DEC(mgr, NULL, NULL, out_buf, zero_buf, text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_DEC, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_ENC(mgr, NULL, NULL, NULL, NULL, -1, NULL, NULL, -1, NULL, -1);
        IMB_AES192_GCM_ENC(mgr, NULL, NULL, out_buf, zero_buf, text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_DEC, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_DEC(mgr, NULL, NULL, NULL, NULL, -1, NULL, NULL, -1, NULL, -1);
        IMB_AES256_GCM_DEC(mgr, NULL, NULL, out_buf, zero_buf, text_len, NULL, NULL, -1, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_DEC, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        /* GCM Init tests */
        IMB_AES128_GCM_INIT(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_INIT(mgr, NULL, (struct gcm_context_data *) out_buf, NULL, NULL, text_len);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_INIT, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_INIT(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_INIT(mgr, NULL, (struct gcm_context_data *) out_buf, NULL, NULL, text_len);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_INIT, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_INIT(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_INIT(mgr, NULL, (struct gcm_context_data *) out_buf, NULL, NULL, text_len);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_INIT, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        /* GCM Encrypt update tests */
        IMB_AES128_GCM_ENC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_ENC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_ENC_UPDATE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_ENC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_ENC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_ENC_UPDATE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_ENC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_ENC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_ENC_UPDATE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        /* GCM Decrypt update tests */
        IMB_AES128_GCM_DEC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_DEC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_DEC_UPDATE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_DEC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_DEC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_DEC_UPDATE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_DEC_UPDATE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_DEC_UPDATE(mgr, NULL, NULL, out_buf, zero_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_DEC_UPDATE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        /* GCM Encrypt complete tests */
        IMB_AES128_GCM_ENC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_ENC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_ENC_FINALIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_ENC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_ENC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_ENC_FINALIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_ENC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_ENC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_ENC_FINALIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        /* GCM Decrypt complete tests */
        IMB_AES128_GCM_DEC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES128_GCM_DEC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_DEC_FINALIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_DEC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES192_GCM_DEC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_DEC_FINALIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_DEC_FINALIZE(mgr, NULL, NULL, NULL, -1);
        IMB_AES256_GCM_DEC_FINALIZE(mgr, NULL, NULL, out_buf, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_DEC_FINALIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        /* GCM key data pre-processing tests */
        IMB_AES128_GCM_PRECOMP(mgr, NULL);
        print_progress();

        IMB_AES192_GCM_PRECOMP(mgr, NULL);
        print_progress();

        IMB_AES256_GCM_PRECOMP(mgr, NULL);
        print_progress();

        IMB_AES128_GCM_PRE(mgr, NULL, NULL);
        IMB_AES128_GCM_PRE(mgr, NULL, key_data);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_GCM_PRE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES192_GCM_PRE(mgr, NULL, NULL);
        IMB_AES192_GCM_PRE(mgr, NULL, key_data);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES192_GCM_PRE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES256_GCM_PRE(mgr, NULL, NULL);
        IMB_AES256_GCM_PRE(mgr, NULL, key_data);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES256_GCM_PRE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Performs direct Key expansion and
 *        generation API invalid param tests
 */
static int
test_key_exp_gen_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
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

        IMB_AES_KEYEXP_128(mgr, NULL, NULL, NULL);
        IMB_AES_KEYEXP_128(mgr, NULL, out_buf, zero_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES_KEYEXP_128, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES_KEYEXP_192(mgr, NULL, NULL, NULL);
        IMB_AES_KEYEXP_192(mgr, NULL, out_buf, zero_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES_KEYEXP_192, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES_KEYEXP_256(mgr, NULL, NULL, NULL);
        IMB_AES_KEYEXP_256(mgr, NULL, out_buf, zero_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES_KEYEXP_256, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES_CMAC_SUBKEY_GEN_128(mgr, NULL, NULL, NULL);
        IMB_AES_CMAC_SUBKEY_GEN_128(mgr, NULL, out_buf, zero_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES_CMAC_SUBKEY_GEN_128, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_AES_XCBC_KEYEXP(mgr, NULL, NULL, NULL, NULL);
        IMB_AES_XCBC_KEYEXP(mgr, NULL, out_buf, out_buf, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES_XCBC_KEYEXP, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_DES_KEYSCHED(mgr, NULL, NULL);
        IMB_DES_KEYSCHED(mgr, (uint64_t *) out_buf, NULL);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_DES_KEYSCHED, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Performs direct hash API invalid param tests
 */
static int
test_hash_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
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

        IMB_SHA1_ONE_BLOCK(mgr, NULL, NULL);
        IMB_SHA1_ONE_BLOCK(mgr, NULL, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA1_ONE_BLOCK, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA1(mgr, NULL, -1, NULL);
        IMB_SHA1(mgr, NULL, BUF_SIZE, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA1, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA224_ONE_BLOCK(mgr, NULL, NULL);
        IMB_SHA224_ONE_BLOCK(mgr, NULL, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA224_ONE_BLOCK, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA224(mgr, NULL, -1, NULL);
        IMB_SHA224(mgr, NULL, BUF_SIZE, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA224, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA256_ONE_BLOCK(mgr, NULL, NULL);
        IMB_SHA256_ONE_BLOCK(mgr, NULL, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA256_ONE_BLOCK, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA256(mgr, NULL, -1, NULL);
        IMB_SHA256(mgr, NULL, BUF_SIZE, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA256, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA384_ONE_BLOCK(mgr, NULL, NULL);
        IMB_SHA384_ONE_BLOCK(mgr, NULL, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA384_ONE_BLOCK, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA384(mgr, NULL, -1, NULL);
        IMB_SHA384(mgr, NULL, BUF_SIZE, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA384, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA512_ONE_BLOCK(mgr, NULL, NULL);
        IMB_SHA512_ONE_BLOCK(mgr, NULL, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA512_ONE_BLOCK, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_SHA512(mgr, NULL, -1, NULL);
        IMB_SHA512(mgr, NULL, BUF_SIZE, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_SHA512, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        IMB_MD5_ONE_BLOCK(mgr, NULL, NULL);
        IMB_MD5_ONE_BLOCK(mgr, NULL, out_buf);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_MD5_ONE_BLOCK, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Performs direct AES API invalid param tests
 */
static int
test_aes_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
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

        IMB_AES128_CFB_ONE(mgr, NULL, NULL, NULL, NULL, -1);
        IMB_AES128_CFB_ONE(mgr, out_buf, NULL, NULL, NULL, -1);
        if (memcmp(out_buf, zero_buf, text_len) != 0) {
                printf("%s: IMB_AES128_CFB_ONE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Performs direct ZUC API invalid param tests
 */
static int
test_zuc_api(void)
{
        const uint32_t text_len = BUF_SIZE;
        const uint32_t inv_len = -1;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int ret1, ret2, seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
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

        ret1 = zuc_eea3_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, NULL);
        ret2 = zuc_eea3_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: zuc_eea3_iv_gen, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        ret1 = zuc_eia3_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, NULL);
        ret2 = zuc_eia3_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: zuc_eia3_iv_gen, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Performs direct KASUMI API invalid param tests
 */
static int
test_kasumi_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        const uint32_t inv_len = -1;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int ret1, ret2, seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
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

        ret1 = kasumi_f8_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, NULL);
        ret2 = kasumi_f8_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: kasumi_f8_iv_gen, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        ret1 = kasumi_f9_iv_gen(inv_len, inv_len, NULL);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0) {
                printf("%s: kasumi_f9_iv_gen, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        ret1 = IMB_KASUMI_INIT_F8_KEY_SCHED(mgr, NULL, NULL);
        ret2 = IMB_KASUMI_INIT_F8_KEY_SCHED(mgr, NULL, (kasumi_key_sched_t *) out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: IMB_KASUMI_INIT_F8_KEY_SCHED, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        ret1 = IMB_KASUMI_INIT_F9_KEY_SCHED(mgr, NULL, NULL);
        ret2 = IMB_KASUMI_INIT_F9_KEY_SCHED(mgr, NULL, (kasumi_key_sched_t *) out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: IMB_KASUMI_INIT_F9_KEY_SCHED, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (IMB_KASUMI_KEY_SCHED_SIZE(mgr) == 0) {
                printf("%s: IMB_KASUMI_KEY_SCHED_SIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Performs direct SNOW3G API invalid param tests
 */
static int
test_snow3g_api(struct IMB_MGR *mgr)
{
        const uint32_t text_len = BUF_SIZE;
        const uint32_t inv_len = -1;
        uint8_t out_buf[BUF_SIZE];
        uint8_t zero_buf[BUF_SIZE];
        int ret1, ret2, seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
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

        ret1 = snow3g_f8_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, NULL);
        ret2 = snow3g_f8_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: snow3g_f8_iv_gen, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        ret1 = snow3g_f9_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, NULL);
        ret2 = snow3g_f9_iv_gen(inv_len, (const uint8_t) inv_len, (const uint8_t) inv_len, out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: snow3g_f9_iv_gen, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        ret1 = IMB_SNOW3G_INIT_KEY_SCHED(mgr, NULL, NULL);
        ret2 = IMB_SNOW3G_INIT_KEY_SCHED(mgr, NULL, (snow3g_key_schedule_t *) out_buf);
        if ((memcmp(out_buf, zero_buf, text_len) != 0) || ret1 == 0 || ret2 == 0) {
                printf("%s: IMB_SNOW3G_INIT_KEY_SCHED, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (IMB_SNOW3G_KEY_SCHED_SIZE(mgr) == 0) {
                printf("%s: IMB_SNOW3G_KEY_SCHED_SIZE, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

/*
 * @brief Performs direct clear memory API invalid param tests
 */
static int
test_clear_mem_api(void)
{
        const uint32_t text_len = BUF_SIZE;
        uint8_t out_buf[BUF_SIZE];
        uint8_t cmp_buf[BUF_SIZE];
        int seg_err; /* segfault flag */

        seg_err = setjmp(env);
        if (seg_err) {
                printf("%s: segfault occurred!\n", __func__);
                return 1;
        }

        memset(out_buf, 0xff, text_len);
        memset(cmp_buf, 0xff, text_len);

        /**
         * API are generally tested twice:
         * 1. test with all invalid params
         * 2. test with some valid params (in, out, len)
         *    and verify output buffer is not modified
         */

        imb_clear_mem(NULL, text_len);
        if (memcmp(out_buf, cmp_buf, text_len) != 0) {
                printf("%s: imb_clear_mem, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        imb_clear_mem(out_buf, 0);
        if (memcmp(out_buf, cmp_buf, text_len) != 0) {
                printf("%s: imb_clear_mem, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        imb_clear_mem(out_buf, text_len);
        if (memcmp(out_buf, cmp_buf, text_len) == 0) {
                printf("%s: imb_clear_mem, invalid "
                       "param test failed!\n",
                       __func__);
                return 1;
        }
        print_progress();

        if (!quiet_mode)
                printf("\n");
        return 0;
}

int
direct_api_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        int errors = 0, run = 0;
#ifndef DEBUG
#if defined(__linux__)
        sighandler_t handler;
#else
        void *handler;
#endif
#endif
        printf("Invalid Direct API arguments test:\n");
        test_suite_start(&ts, "INVALID-ARGS");

#ifndef DEBUG
        handler = signal(SIGSEGV, seg_handler);
#endif

        errors += test_clear_mem_api();
        run++;

        uint64_t features = 0;

        if (imb_get_features(mb_mgr, &features) != 0 ||
            ((features & IMB_FEATURE_SAFE_PARAM) == 0)) {
                printf("SAFE_PARAM feature disabled, "
                       "skipping remaining tests\n");
                goto dir_api_exit;
        }

        errors += test_gcm_api(mb_mgr);
        run++;

        errors += test_key_exp_gen_api(mb_mgr);
        run++;

        errors += test_hash_api(mb_mgr);
        run++;

        errors += test_aes_api(mb_mgr);
        run++;

        errors += test_zuc_api();
        run++;

        errors += test_kasumi_api(mb_mgr);
        run++;

        errors += test_snow3g_api(mb_mgr);
        run++;

        test_suite_update(&ts, run - errors, errors);

dir_api_exit:
        errors = test_suite_end(&ts);

#ifndef DEBUG
        signal(SIGSEGV, handler);
#endif
        return errors;
}
