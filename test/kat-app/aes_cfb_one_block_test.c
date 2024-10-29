/*****************************************************************************
 Copyright (c) 2023-2024, Intel Corporation

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
#include "cipher_test.h"

int
cfb_one_block_test(struct IMB_MGR *mb_mgr);

extern const struct cipher_test cfb_one_block_test_json[];

static int
cfb_validate_ok(const uint8_t *output, const uint8_t *in_text, const size_t plen,
                const uint32_t klen, const unsigned i, const unsigned is_enc, const int in_place)
{
        if (memcmp(output, in_text, plen) != 0) {
                printf("\nAES-CFB-ONE%s standard test vector %u %s (%s): fail\n",
                       (klen == 16) ? "128" : "256", i + 1, (is_enc) ? "encrypt" : "decrypt",
                       (in_place) ? "in-place" : "out-of-place");
                return 0;
        }

#ifdef DEBUG
        if (!quiet_mode) {
                printf("Standard test vector %u %s %s\n", i + 1,
                       (in_place) ? "in-place" : "out-of-place", (is_enc) ? "encrypt" : "decrypt");
        }
#endif
        return 1;
}

static int
cfb_validate(struct IMB_MGR *mb_mgr, const struct cipher_test *p_vec)
{
        uint8_t output1[16];
        uint8_t output2[16];
        const uint32_t kLength = (unsigned) p_vec->keySize / 8;
        DECLARE_ALIGNED(uint32_t keys_enc[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t keys_dec[15 * 4], 16);

        if (kLength == 16)
                IMB_AES_KEYEXP_128(mb_mgr, p_vec->key, keys_enc, keys_dec);
        else
                IMB_AES_KEYEXP_256(mb_mgr, p_vec->key, keys_enc, keys_dec);
        /* Out of place */

        /* encrypt test */
        if (kLength == 16)
                IMB_AES128_CFB_ONE(mb_mgr, output1, (const void *) p_vec->msg, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        else
                IMB_AES256_CFB_ONE(mb_mgr, output1, (const void *) p_vec->msg, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        if (!cfb_validate_ok(output1, (const void *) p_vec->ct, p_vec->msgSize / 8,
                             (unsigned) p_vec->keySize / 8, (unsigned) p_vec->tcId, 1, 0))
                return 0;

        /* decrypt test */
        if (kLength == 16)
                IMB_AES128_CFB_ONE(mb_mgr, output2, output1, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        else
                IMB_AES256_CFB_ONE(mb_mgr, output2, output1, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        if (!cfb_validate_ok(output2, (const void *) p_vec->msg, p_vec->msgSize / 8,
                             (unsigned) p_vec->keySize / 8, (unsigned) p_vec->tcId, 0, 0))
                return 0;
        /* In place */

        /* encrypt test */
        memcpy(output1, (const void *) p_vec->msg, p_vec->msgSize / 8);
        if (kLength == 16)
                IMB_AES128_CFB_ONE(mb_mgr, output1, output1, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        else
                IMB_AES256_CFB_ONE(mb_mgr, output1, output1, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        if (!cfb_validate_ok(output1, (const void *) p_vec->ct, p_vec->msgSize / 8,
                             (unsigned) p_vec->keySize / 8, (unsigned) p_vec->tcId, 1, 1))
                return 0;

        /* decrypt test */
        memcpy(output1, (const void *) p_vec->ct, p_vec->msgSize / 8);
        if (kLength == 16)
                IMB_AES128_CFB_ONE(mb_mgr, output1, output1, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        else
                IMB_AES256_CFB_ONE(mb_mgr, output1, output1, p_vec->iv, keys_enc,
                                   p_vec->msgSize / 8);
        if (!cfb_validate_ok(output1, (const void *) p_vec->msg, p_vec->msgSize / 8,
                             (unsigned) p_vec->keySize / 8, (unsigned) p_vec->tcId, 0, 1))
                return 0;
        return 1;
}

static void
cfb_test_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                 struct test_suite_context *ctx256)
{
        const struct cipher_test *v = cfb_one_block_test_json;

        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("AES-CFB-ONE Test Case %zu key_len:%zu\n", v->tcId, v->keySize);
#else
                        printf(".");
#endif
                }

                if (v->keySize == 128)
                        ctx = ctx128;
                else
                        ctx = ctx256;
                if (!cfb_validate(mb_mgr, v))
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }
        if (!quiet_mode)
                printf("\n");
}

int
cfb_one_block_test(struct IMB_MGR *mb_mgr)
{
        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx256;

        test_suite_start(&ctx128, "AES-CFB-128 ONE-BLOCK");
        test_suite_start(&ctx256, "AES-CFB-256 ONE-BLOCK");
        cfb_test_vectors(mb_mgr, &ctx128, &ctx256);
        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx256);

        return errors;
}
