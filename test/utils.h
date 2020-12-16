/*****************************************************************************
 Copyright (c) 2018-2020, Intel Corporation

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

#ifndef TESTAPP_UTILS_H
#define TESTAPP_UTILS_H

#include <intel-ipsec-mb.h>

#define DIM(_x) (sizeof(_x)/sizeof(_x[0]))

void hexdump(FILE *fp, const char *msg, const void *p, size_t len);
void hexdump_ex(FILE *fp, const char *msg, const void *p, size_t len,
                const void *start_ptr);

int arch_and_feature_set(char *arg, uint8_t *arch_support, uint64_t *features);
int detect_arch_and_features(uint8_t *arch_support, uint64_t *features);
void print_component(uint64_t features, IMB_ARCH arch);

struct test_suite_context {
        unsigned pass;
        unsigned fail;
        const char *alg_name;
};

void test_suite_start(struct test_suite_context *ctx, const char *alg_name);
void test_suite_update(struct test_suite_context *ctx, const unsigned passed,
                      const unsigned failed);
int test_suite_end(struct test_suite_context *ctx);

#endif /* TESTAPP_UTILS_H */
