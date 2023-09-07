/*****************************************************************************
 Copyright (c) 2023, Intel Corporation

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

/* SM4-ECB */
#include "cipher_test.h"
const struct cipher_test sm4_ecb_test_json[] = {
        /* Vectors from https://datatracker.ietf.org/doc/draft-ribose-cfrg-sm4/00/ and
           https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-04 */
        { 0, 128, 1, "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10", NULL,
          "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",
          "\x68\x1E\xDF\x34\xD2\x06\x96\x5E\x86\xB3\xE9\x4F\x53\x6E\x42\x46", 1, 128 },
        { 0, 128, 2, "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10", NULL,
          "\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xDD\xDD\xDD\xDD"
          "\xEE\xEE\xEE\xEE\xFF\xFF\xFF\xFF\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB",
          "\x5E\xC8\x14\x3D\xE5\x09\xCF\xF7\xB5\x17\x9F\x8F\x47\x4B\x86\x19"
          "\x2F\x1D\x30\x5A\x7F\xB1\x7D\xF9\x85\xF8\x1C\x84\x82\x19\x23\x04",
          1, 256 },
        { 0, 0, 0, NULL, NULL, NULL, NULL, 0, 0 }
};
