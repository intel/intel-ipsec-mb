/*
 * Copyright (c) 2012-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mb_mgr.h"
#include "aux_funcs.h"
#include "gcm_ctr_vectors_test.h"

#define TEST_SSE  1
#define TEST_AVX  2
#define TEST_AVX2 3

#define TEST TEST_SSE
#include "do_test.h"
#undef TEST
#define TEST TEST_AVX
#include "do_test.h"
#undef TEST
#define TEST TEST_AVX2
#include "do_test.h"
#undef TEST
#define TEST TEST_AVX512
#include "do_test.h"

int
main(int argc, char **argv)
{
        DECLARE_ALIGNED(MB_MGR mb_mgr, 32);

        memset(&mb_mgr, 0, sizeof(mb_mgr));

        printf("Testing SSE interface\n");
        init_mb_mgr_sse(&mb_mgr);
        known_answer_test_sse(&mb_mgr);
        do_test_sse(&mb_mgr);
        ctr_test(ARCH_SSE, &mb_mgr);
        gcm_test(ARCH_SSE, &mb_mgr);

        printf("Testing AVX interface\n");
        init_mb_mgr_avx(&mb_mgr);
        known_answer_test_avx(&mb_mgr);
        do_test_avx(&mb_mgr);
        ctr_test(ARCH_AVX, &mb_mgr);
        gcm_test(ARCH_AVX, &mb_mgr);

        printf("Testing AVX2 interface\n");
        init_mb_mgr_avx2(&mb_mgr);
        known_answer_test_avx2(&mb_mgr);
        do_test_avx2(&mb_mgr);
        ctr_test(ARCH_AVX2, &mb_mgr);
        gcm_test(ARCH_AVX2, &mb_mgr);

        printf("Testing AVX512 interface\n");
        init_mb_mgr_avx512(&mb_mgr);
        known_answer_test_avx512(&mb_mgr);
        do_test_avx512(&mb_mgr);
        ctr_test(ARCH_AVX512, &mb_mgr);
        gcm_test(ARCH_AVX512, &mb_mgr);

        printf("Test completed\n");

        return 0;
}
