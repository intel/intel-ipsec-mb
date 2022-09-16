/*****************************************************************************
 Copyright (c) 2012-2022, Intel Corporation

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "gcm_ctr_vectors_test.h"
#include "customop_test.h"
#include "utils.h"

extern int des_test(struct IMB_MGR *mb_mgr);
extern int ccm_test(struct IMB_MGR *mb_mgr);
extern int cmac_test(struct IMB_MGR *mb_mgr);
extern int hmac_sha1_test(struct IMB_MGR *mb_mgr);
extern int hmac_sha256_sha512_test(struct IMB_MGR *mb_mgr);
extern int hmac_md5_test(struct IMB_MGR *mb_mgr);
extern int aes_test(struct IMB_MGR *mb_mgr);
extern int ecb_test(struct IMB_MGR *mb_mgr);
extern int sha_test(struct IMB_MGR *mb_mgr);
extern int chained_test(struct IMB_MGR *mb_mgr);
extern int api_test(struct IMB_MGR *mb_mgr);
extern int pon_test(struct IMB_MGR *mb_mgr);
extern int zuc_test(struct IMB_MGR *mb_mgr);
extern int kasumi_test(struct IMB_MGR *mb_mgr);
extern int snow3g_test(struct IMB_MGR *mb_mgr);
extern int direct_api_test(struct IMB_MGR *mb_mgr);
extern int clear_mem_test(struct IMB_MGR *mb_mgr);
extern int hec_test(struct IMB_MGR *mb_mgr);
extern int xcbc_test(struct IMB_MGR *mb_mgr);
extern int aes_cbcs_test(struct IMB_MGR *mb_mgr);
extern int crc_test(struct IMB_MGR *mb_mgr);
extern int chacha_test(struct IMB_MGR *mb_mgr);
extern int poly1305_test(struct IMB_MGR *mb_mgr);
extern int chacha20_poly1305_test(struct IMB_MGR *mb_mgr);
extern int null_test(struct IMB_MGR *mb_mgr);
extern int snow_v_test(struct IMB_MGR *mb_mgr);
extern int direct_api_param_test(struct IMB_MGR *mb_mgr);

typedef int (*imb_test_t)(struct IMB_MGR *mb_mgr);

#include "do_test.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#define MAX_STR_LENGTH 32

struct imb_test {
        char str[MAX_STR_LENGTH];
        imb_test_t fn;
        unsigned enabled;
};

struct imb_test tests[] = {
        {
                .str = "KAT",
                .fn = known_answer_test,
                .enabled = 1
        },
        {
                .str = "DO_TEST",
                .fn = do_test,
                .enabled = 1
        },
        {
		.str = "CTR",
                .fn = ctr_test,
                .enabled = 1
        },
        {
                .str = "PON",
                .fn = pon_test,
                .enabled = 1
        },
        {
		.str = "XCBC",
                .fn = xcbc_test,
                .enabled = 1
        },
        {
                .str = "GCM",
                .fn = gcm_test,
                .enabled = 1
        },
        {
                .str = "CUSTOMOP",
                .fn = customop_test,
                .enabled = 1
        },
        {
                .str = "DES",
                .fn = des_test,
                .enabled = 1
        },
        {
                .str = "CCM",
                .fn = ccm_test,
                .enabled = 1
        },
        {
                .str = "CMAC",
                .fn = cmac_test,
                .enabled = 1
        },
        {
                .str = "ZUC",
                .fn = zuc_test,
                .enabled = 1
        },
        {
                .str = "KASUMI",
                .fn = kasumi_test,
                .enabled = 1
        },
        {
                .str = "SNOW3G",
                .fn = snow3g_test,
                .enabled = 1
        },
        {
                .str = "HMAC_SHA1",
                .fn = hmac_sha1_test,
                .enabled = 1
        },
        {
                .str = "HMAC_SHA256",
                .fn = hmac_sha256_sha512_test,
                .enabled = 1
        },
        {
                .str = "HMAC_MD5",
                .fn = hmac_md5_test,
                .enabled = 1
        },
        {
                .str = "AES",
                .fn = aes_test,
                .enabled = 1
        },
        {
                .str = "ECB",
                .fn = ecb_test,
                .enabled = 1
        },
        {
                .str = "SHA",
                .fn = sha_test,
                .enabled = 1
        },
        {
		.str = "CHAINED",
                .fn = chained_test,
                .enabled = 1
        },
        {
                .str = "HEC",
                .fn = hec_test,
                .enabled = 1
        },
        {
                .str = "AES_CBCS",
                .fn = aes_cbcs_test,
                .enabled = 1
        },
        {
                .str = "CHACHA",
                .fn = chacha_test,
                .enabled = 1
        },
        {
                .str = "POLY1305",
                .fn = poly1305_test,
                .enabled = 1
        },
        {
                .str = "API",
                .fn = api_test,
                .enabled = 1
        },
        {
                .str = "DIRECT_API",
                .fn = direct_api_test,
                .enabled = 1
        },
        {
                .str = "CLEAR_MEM",
                .fn = clear_mem_test,
                .enabled = 1
        },
        {
                .str = "CRC",
                .fn = crc_test,
                .enabled = 1
        },
        {
                .str = "CHACHA20_POLY1305",
                .fn = chacha20_poly1305_test,
                .enabled = 1
        },
        {
                .str = "NULL",
                .fn = null_test,
                .enabled = 1
        },
        {
                .str = "SNOW_V",
                .fn = snow_v_test,
                .enabled = 1
        },
        {
                .str = "DIRECT_API_PARAM",
                .fn = direct_api_param_test,
                .enabled = 1
        }
};

static void
usage(const char *name)
{
	fprintf(stderr,
                "Usage: %s [args], where args are zero or more\n"
                "--test-type TEST_NAME : Run single test type\n"
                "--stop-on-fail: Stop test execution if a test fails\n"
                "--no-aesni-emu: Don't do AESNI emulation\n"
                "--no-avx512: Don't do AVX512\n"
		"--no-avx2: Don't do AVX2\n"
		"--no-avx: Don't do AVX\n"
		"--no-sse: Don't do SSE\n"
                "--auto-detect: auto detects current architecture "
                "to run the tests\n  Note: Auto detection "
                "option now run by default and will be removed in the future\n"
                "--gfni-on: use Galois Field extensions, default: auto-detect\n"
                "--gfni-off: don't use Galois Field extensions\n"
		"--shani-on: use SHA extensions, default: auto-detect\n"
		"--shani-off: don't use SHA extensions\n", name);
}

static void
print_hw_features(void)
{
        const struct {
                uint64_t feat_val;
                const char *feat_name;
        } feat_tab[] = {
                { IMB_FEATURE_SHANI, "SHANI" },
                { IMB_FEATURE_AESNI, "AESNI" },
                { IMB_FEATURE_PCLMULQDQ, "PCLMULQDQ" },
                { IMB_FEATURE_CMOV, "CMOV" },
                { IMB_FEATURE_SSE4_2, "SSE4.2" },
                { IMB_FEATURE_AVX, "AVX" },
                { IMB_FEATURE_AVX2, "AVX2" },
                { IMB_FEATURE_AVX512_SKX, "AVX512(SKX)" },
                { IMB_FEATURE_VAES, "VAES" },
                { IMB_FEATURE_VPCLMULQDQ, "VPCLMULQDQ" },
                { IMB_FEATURE_GFNI, "GFNI" },
                { IMB_FEATURE_AVX512_IFMA, "AVX512-IFMA" },
                { IMB_FEATURE_BMI2, "BMI2" },
        };
        IMB_MGR *p_mgr = NULL;
        unsigned i;

        printf("Detected hardware features:\n");

        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                printf("\tERROR\n");
                return;
        }

        for (i = 0; i < IMB_DIM(feat_tab); i++) {
                const uint64_t val = feat_tab[i].feat_val;

                printf("\t%-*.*s : %s\n", 12, 12, feat_tab[i].feat_name,
                       ((p_mgr->features & val) == val) ? "OK" : "n/a");
        }

        free_mb_mgr(p_mgr);
}

/*
 * Check string argument is supported and if it is,
 * return index associated with it.
 */
static unsigned
check_test_string_arg(const char *param, const char *arg)
{
        unsigned test_idx;

        if (arg == NULL) {
                fprintf(stderr, "%s requires an argument\n", param);
                goto exit;
        }

        for (test_idx = 0; test_idx < DIM(tests); test_idx++)
                if (strcasecmp(arg, tests[test_idx].str) == 0)
                        return test_idx;

        /* Argument is not listed in the available options */
        fprintf(stderr, "Invalid argument for %s\n", param);
exit:
        fprintf(stderr, "Accepted arguments: ");
        for (test_idx = 0; test_idx < DIM(tests); test_idx++)
                fprintf(stderr, "%s ", tests[test_idx].str);
        fprintf(stderr, "\n");

        return DIM(tests);
}

/* Check if expected error for no AESNI Emulation support is returned */
static int
check_err_no_aesni_emu(const uint64_t feature_flags, IMB_MGR *p_mgr)
{
        if (((feature_flags & IMB_FEATURE_AESNI_EMU) == 0) &&
            (imb_get_errno(p_mgr) == IMB_ERR_NO_AESNI_EMU))
                return 1;

        return 0;
}

int
main(int argc, char **argv)
{
        uint8_t arch_support[IMB_ARCH_NUM];
        int i, atype, auto_detect = 0;
        uint64_t flags = 0;
        int errors = 0;
        unsigned int stop_on_fail = 0;
        const uint64_t feat_flags = imb_get_feature_flags();

        /* Check version number */
        if (imb_get_version() < IMB_VERSION(0, 50, 0))
                printf("Library version detection unsupported!\n");
        else
                printf("Detected library version: %s\n", imb_get_version_str());

        /* Print available CPU features */
        print_hw_features();

        /* Detect available architectures and features */
        if (detect_arch(arch_support) < 0)
                return EXIT_FAILURE;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return EXIT_SUCCESS;
		} else if (update_flags_and_archs(argv[i],
                                                  arch_support,
                                                  &flags))
			continue;
		else if (strcmp(argv[i], "--auto-detect") == 0)
                        (void) auto_detect; /* legacy option - to be removed */
		else if (strcmp(argv[i], "--stop-on-fail") == 0)
                        stop_on_fail = 1;
                else if (strcmp(argv[i], "--test-type") == 0) {
                        unsigned selected_test;

                        selected_test = check_test_string_arg(argv[i],
                                                              argv[i+1]);
                        if (selected_test == DIM(tests))
                                return EXIT_FAILURE;
                        else {
                                /* Disable all tests except the one passed */
                                unsigned test_idx;

                                for (test_idx = 0; test_idx < DIM(tests);
                                     test_idx++)
                                        if (test_idx != selected_test)
                                                tests[test_idx].enabled = 0;
                        }
                        i++;
                }
        }

        /* Go through architectures */
        for (atype = IMB_ARCH_NOAESNI; atype < IMB_ARCH_NUM; atype++) {
                IMB_MGR *p_mgr = NULL;
                unsigned test_idx;
                uint64_t used_flags = flags;

                if (!arch_support[atype])
                        continue;
                if (atype == IMB_ARCH_NOAESNI)
                        used_flags |= IMB_FLAG_AESNI_OFF;

                p_mgr = alloc_mb_mgr(used_flags);

                if (p_mgr == NULL) {
                        if (atype == IMB_ARCH_NOAESNI) {
                                if (check_err_no_aesni_emu(feat_flags, p_mgr)) {
                                        printf("AESNI Emulation is not enabled."
                                               " Skipping NOAESNI test.\n");
                                        continue;
                                }
                                printf("Expected %s error, got %s error\n",
                                       imb_get_strerror(IMB_ERR_NO_AESNI_EMU),
                                       imb_get_strerror(imb_get_errno(p_mgr)));
                        }
                        printf("Error allocating MB_MGR structure!\n");
                        return EXIT_FAILURE;
                }

                switch (atype) {
                case IMB_ARCH_SSE:
                case IMB_ARCH_NOAESNI:
                        init_mb_mgr_sse(p_mgr);
                        break;
                case IMB_ARCH_AVX:
                        init_mb_mgr_avx(p_mgr);
                        break;
                case IMB_ARCH_AVX2:
                        init_mb_mgr_avx2(p_mgr);
                        break;
                case IMB_ARCH_AVX512:
                        init_mb_mgr_avx512(p_mgr);
                        break;
                }

                if (p_mgr->features & IMB_FEATURE_SELF_TEST)
                        printf("SELF-TEST: %s\n",
                               (p_mgr->features & IMB_FEATURE_SELF_TEST_PASS) ?
                               "PASS" : "FAIL");
                else
                        printf("SELF-TEST: N/A (requires library >= v1.3)\n");

                if (imb_get_errno(p_mgr) != 0) {
                        printf("Error initializing MB_MGR structure! %s\n",
                               imb_get_strerror(imb_get_errno(p_mgr)));
                        free_mb_mgr(p_mgr);
                        return EXIT_FAILURE;
                }

                print_tested_arch(p_mgr->features, atype);

                for (test_idx = 0; test_idx < DIM(tests); test_idx++) {
                        if (tests[test_idx].enabled) {
                                errors += tests[test_idx].fn(p_mgr);
                                /*
                                 * Stop the execution if a failure is
                                 * encountered and stop_on_fail parameter is set
                                 */
                                if (errors && stop_on_fail) {
                                        free_mb_mgr(p_mgr);
                                        return EXIT_FAILURE;
                                }
                        }
                }

                free_mb_mgr(p_mgr);
        }

        if (errors) {
                printf("Test completed: FAIL\n");
                return EXIT_FAILURE;
        }

        printf("Test completed: PASS\n");

        return EXIT_SUCCESS;
}
