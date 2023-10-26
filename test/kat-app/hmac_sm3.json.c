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

#include "mac_test.h"

const struct mac_test hmac_sm3_test_kat_json[] = {
        /*
         * Test vectors from GM/T 0042-2015 Appendix D.3
         */
        { 296, 256, 1,
          "\x01\x02\x03\x04\x05\x06\x07\x08"
          "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
          "\x11\x12\x13\x14\x15\x16\x17\x18"
          "\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
          "\x21\x22\x23\x24\x25",
          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
          "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
          "\x22\x0b\xf5\x79\xde\xd5\x55\x39"
          "\x3f\x01\x59\xf6\x6c\x99\x87\x78"
          "\x22\xa3\xec\xf6\x10\xd1\x55\x21"
          "\x54\xb4\x1d\x44\xb9\x4d\xb3\xae",
          1, 400, NULL, 0 },
        { 0, 0, 0, NULL, NULL, NULL, 0, 0, NULL, 0 }
};
