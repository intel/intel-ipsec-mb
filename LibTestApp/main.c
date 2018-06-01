/*****************************************************************************
 Copyright (c) 2012-2018, Intel Corporation

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

extern int des_test(const enum arch_type arch, struct MB_MGR *mb_mgr);
extern int ccm_test(const enum arch_type arch, struct MB_MGR *mb_mgr);
extern int cmac_test(const enum arch_type arch, struct MB_MGR *mb_mgr);
extern int hmac_sha1_test(const enum arch_type arch, struct MB_MGR *mb_mgr);
extern int hmac_sha256_sha512_test(const enum arch_type arch,
                                   struct MB_MGR *mb_mgr);
extern int hmac_md5_test(const enum arch_type arch, struct MB_MGR *mb_mgr);

#include "do_test.h"

static void
usage(const char *name)
{
	fprintf(stderr,
                "Usage: %s [args], where args are zero or more\n"
		"--no-avx512: Don't do AVX512\n"
		"--no-avx2: Don't do AVX2\n"
		"--no-avx: Don't do AVX\n"
		"--no-sse: Don't do SSE\n"
		"--shani-on: use SHA extensions, default: auto-detect\n"
		"--shani-off: don't use SHA extensions\n", name);
}

int
main(int argc, char **argv)
{
        const char *arch_str_tab[ARCH_NUMOF] = {
                "SSE", "AVX", "AVX2", "AVX512"
        };
        enum arch_type arch_type_tab[ARCH_NUMOF] = {
                ARCH_SSE, ARCH_AVX, ARCH_AVX2, ARCH_AVX512
        };

        int i, do_sse = 1, do_avx = 1, do_avx2 = 1, do_avx512 = 1;
        MB_MGR *p_mgr = NULL;
        uint64_t flags = 0;
        int errors = 0;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return EXIT_SUCCESS;
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
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

        p_mgr = alloc_mb_mgr(flags);
        if (p_mgr == NULL) {
                printf("Error allocating MB_MGR structure!\n");
                return EXIT_FAILURE;
        }

        for (i = 0; i < ARCH_NUMOF; i++) {
                const enum arch_type atype = arch_type_tab[i];

                switch (atype) {
                case ARCH_SSE:
                        if (!do_sse)
                                continue;
                        init_mb_mgr_sse(p_mgr);
                        break;
                case ARCH_AVX:
                        if (!do_avx)
                                continue;
                        init_mb_mgr_avx(p_mgr);
                        break;
                case ARCH_AVX2:
                        if (!do_avx2)
                                continue;
                        init_mb_mgr_avx2(p_mgr);
                        break;
                case ARCH_AVX512:
                        if (!do_avx512)
                                continue;
                        init_mb_mgr_avx512(p_mgr);
                        break;
                default:
                        printf("Architecture type '%d' error!\n", (int) atype);
                        continue;
                }

                printf("Testing %s interface\n", arch_str_tab[i]);

                errors += known_answer_test(p_mgr);
                errors += do_test(p_mgr);
                errors += ctr_test(atype, p_mgr);
                errors += gcm_test(atype);
                errors += customop_test(p_mgr);
                errors += des_test(atype, p_mgr);
                errors += ccm_test(atype, p_mgr);
                errors += cmac_test(atype, p_mgr);
                errors += hmac_sha1_test(atype, p_mgr);
                errors += hmac_sha256_sha512_test(atype, p_mgr);
                errors += hmac_md5_test(atype, p_mgr);
        }

        free_mb_mgr(p_mgr);

        if (errors)
                printf("Test completed: FAIL\n");
        else
                printf("Test completed: PASS\n");

        return EXIT_SUCCESS;
}
