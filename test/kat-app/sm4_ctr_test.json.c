/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

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

/* SM4-CTR */
#include "cipher_test.h"
const struct cipher_test sm4_ctr_test_json[] = {
        /* Vectors from https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-04 and
           https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10 */
        { 128, 128, 1, "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",
          "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
          "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
          "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB",
          "\xAC\x32\x36\xCB\x97\x0C\xC2\x07\x91\x36\x4C\x39\x5A\x13\x42\xD1"
          "\xA3\xCB\xC1\x87\x8C\x6F\x30\xCD\x07\x4C\xCE\x38\x5C\xDD\x70\xC7"
          "\xF2\x34\xBC\x0E\x24\xC1\x19\x80\xFD\x12\x86\x31\x0C\xE3\x7B\x92"
          "\x6E\x02\xFC\xD0\xFA\xA0\xBA\xF3\x8B\x29\x33\x85\x1D\x82\x45\x14",
          1, 512 },
        { 128, 128, 2, "\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF",
          "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
          "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
          "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB",
          "\x5D\xCC\xCD\x25\xB9\x5A\xB0\x74\x17\xA0\x85\x12\xEE\x16\x0E\x2F"
          "\x8F\x66\x15\x21\xCB\xBA\xB4\x4C\xC8\x71\x38\x44\x5B\xC2\x9E\x5C"
          "\x0A\xE0\x29\x72\x05\xD6\x27\x04\x17\x3B\x21\x23\x9B\x88\x7F\x6C"
          "\x8C\xB5\xB8\x00\x91\x7A\x24\x88\x28\x4B\xDE\x9E\x16\xEA\x29\x06",
          1, 512 },
        { 0, 0, 0, NULL, NULL, NULL, NULL, 0, 0 }
};
