/*****************************************************************************
 Copyright (c) 2012-2020, Intel Corporation

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

extern int des_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int ccm_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int cmac_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int hmac_sha1_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int hmac_sha256_sha512_test(const enum arch_type arch,
                                   struct IMB_MGR *mb_mgr);
extern int hmac_md5_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int aes_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int ecb_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int sha_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int chained_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int api_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int pon_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int zuc_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int kasumi_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int snow3g_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int direct_api_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);
extern int clear_mem_test(const enum arch_type arch, struct IMB_MGR *mb_mgr);

#include "do_test.h"

static void
usage(const char *name)
{
	fprintf(stderr,
                "Usage: %s [args], where args are zero or more\n"
                "--no-aesni-emu: Don't do AESNI emulation\n"
                "--no-avx512: Don't do AVX512\n"
		"--no-avx2: Don't do AVX2\n"
		"--no-avx: Don't do AVX\n"
		"--no-sse: Don't do SSE\n"
                "--no-gcm: Don't run GCM tests\n"
                "--auto-detect: auto detects current architecture "
                "to run the tests\n"
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

static void
detect_arch(int *p_do_aesni_emu, int *p_do_sse, int *p_do_avx,
            int *p_do_avx2, int *p_do_avx512, int *p_do_pclmulqdq)
{
        const uint64_t detect_sse =
                IMB_FEATURE_SSE4_2 | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx =
                IMB_FEATURE_AVX | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx2 = IMB_FEATURE_AVX2 | detect_avx;
        const uint64_t detect_avx512 = IMB_FEATURE_AVX512_SKX | detect_avx2;
        const uint64_t detect_pclmulqdq = IMB_FEATURE_PCLMULQDQ;
        IMB_MGR *p_mgr = NULL;

        if (p_do_aesni_emu == NULL || p_do_sse == NULL ||
            p_do_avx == NULL || p_do_avx2 == NULL ||
            p_do_avx512 == NULL)
                return;

        *p_do_aesni_emu = 1;
        *p_do_sse = 1;
        *p_do_avx = 1;
        *p_do_avx2 = 1;
        *p_do_avx512 = 1;
        *p_do_pclmulqdq = 1;

        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                printf("Architecture auto detect error!\n");
                return;
        }

        if ((p_mgr->features & detect_avx512) != detect_avx512)
                *p_do_avx512 = 0;

        if ((p_mgr->features & detect_avx2) != detect_avx2)
                *p_do_avx2 = 0;

        if ((p_mgr->features & detect_avx) != detect_avx)
                *p_do_avx = 0;

        if ((p_mgr->features & detect_sse) != detect_sse)
                *p_do_sse = 0;

        if ((p_mgr->features & detect_pclmulqdq) != detect_pclmulqdq)
                *p_do_pclmulqdq = 0;

        free_mb_mgr(p_mgr);
}

int
main(int argc, char **argv)
{
        const char *arch_str_tab[ARCH_NUMOF] = {
                "SSE", "AVX", "AVX2", "AVX512", "NO_AESNI"
        };
        enum arch_type arch_type_tab[ARCH_NUMOF] = {
                ARCH_SSE, ARCH_AVX, ARCH_AVX2, ARCH_AVX512, ARCH_NO_AESNI
        };
        int i, do_sse = 1, do_avx = 1, do_avx2 = 1, do_avx512 = 1;
        int do_aesni_emu = 1, do_gcm = 1;
        int auto_detect = 0;
        IMB_MGR *p_mgr = NULL;
        uint64_t flags = 0;
        int errors = 0;

        /* Check version number */
        if (imb_get_version() < IMB_VERSION(0, 50, 0))
                printf("Library version detection unsupported!\n");
        else
                printf("Detected library version: %s\n", imb_get_version_str());

        /* Print available CPU features */
        print_hw_features();

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[i], "--no-aesni-emu") == 0) {
			do_aesni_emu = 0;
		} else if (strcmp(argv[i], "--no-avx512") == 0) {
			do_avx512 = 0;
		} else if (strcmp(argv[i], "--no-avx2") == 0) {
			do_avx2 = 0;
		} else if (strcmp(argv[i], "--no-avx") == 0) {
			do_avx = 0;
		} else if (strcmp(argv[i], "--no-sse") == 0) {
			do_sse = 0;
		} else if (strcmp(argv[i], "--shani-on") == 0) {
                        flags &= (~IMB_FLAG_SHANI_OFF);
		} else if (strcmp(argv[i], "--shani-off") == 0) {
                        flags |= IMB_FLAG_SHANI_OFF;
		} else if (strcmp(argv[i], "--no-gcm") == 0) {
                        do_gcm = 0;
		} else if (strcmp(argv[i], "--auto-detect") == 0) {
                        auto_detect = 1;
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

        if (auto_detect)
                detect_arch(&do_aesni_emu, &do_sse, &do_avx,
                            &do_avx2, &do_avx512, &do_gcm);

        for (i = 0; i < ARCH_NUMOF; i++) {
                const enum arch_type atype = arch_type_tab[i];

                switch (atype) {
                case ARCH_SSE:
                        if (!do_sse)
                                continue;
                        p_mgr = alloc_mb_mgr(flags);
                        if (p_mgr == NULL) {
                                printf("Error allocating MB_MGR structure!\n");
                                return EXIT_FAILURE;
                        }
                        init_mb_mgr_sse(p_mgr);
                        break;
                case ARCH_AVX:
                        if (!do_avx)
                                continue;
                        p_mgr = alloc_mb_mgr(flags);
                        if (p_mgr == NULL) {
                                printf("Error allocating MB_MGR structure!\n");
                                return EXIT_FAILURE;
                        }
                        init_mb_mgr_avx(p_mgr);
                        break;
                case ARCH_AVX2:
                        if (!do_avx2)
                                continue;
                        p_mgr = alloc_mb_mgr(flags);
                        if (p_mgr == NULL) {
                                printf("Error allocating MB_MGR structure!\n");
                                return EXIT_FAILURE;
                        }
                        init_mb_mgr_avx2(p_mgr);
                        break;
                case ARCH_AVX512:
                        if (!do_avx512)
                                continue;
                        p_mgr = alloc_mb_mgr(flags);
                        if (p_mgr == NULL) {
                                printf("Error allocating MB_MGR structure!\n");
                                return EXIT_FAILURE;
                        }
                        init_mb_mgr_avx512(p_mgr);
                        break;
                case ARCH_NO_AESNI:
                        if (!do_aesni_emu)
                                continue;
                        p_mgr = alloc_mb_mgr(flags | IMB_FLAG_AESNI_OFF);
                        if (p_mgr == NULL) {
                                printf("Error allocating MB_MGR structure!\n");
                                return EXIT_FAILURE;
                        }
                        init_mb_mgr_sse(p_mgr);
                        break;
                default:
                        printf("Architecture type '%d' error!\n", (int) atype);
                        continue;
                }

                printf("Testing %s interface\n", arch_str_tab[i]);

                errors += known_answer_test(p_mgr);
                errors += do_test(p_mgr);
                errors += ctr_test(atype, p_mgr);
                errors += pon_test(atype, p_mgr);
                if (do_gcm)
                        errors += gcm_test(p_mgr);
                errors += customop_test(p_mgr);
                errors += des_test(atype, p_mgr);
                errors += ccm_test(atype, p_mgr);
                errors += cmac_test(atype, p_mgr);
                errors += zuc_test(atype, p_mgr);
                errors += kasumi_test(atype, p_mgr);
                errors += snow3g_test(atype, p_mgr);
                errors += hmac_sha1_test(atype, p_mgr);
                errors += hmac_sha256_sha512_test(atype, p_mgr);
                errors += hmac_md5_test(atype, p_mgr);
                errors += aes_test(atype, p_mgr);
                errors += ecb_test(atype, p_mgr);
                errors += sha_test(atype, p_mgr);
                errors += chained_test(atype, p_mgr);
                errors += api_test(atype, p_mgr);
                errors += direct_api_test(atype, p_mgr);
                errors += clear_mem_test(atype, p_mgr);
                free_mb_mgr(p_mgr);
        }

        if (errors) {
                printf("Test completed: FAIL\n");
                return EXIT_FAILURE;
        }

        printf("Test completed: PASS\n");

        return EXIT_SUCCESS;
}
