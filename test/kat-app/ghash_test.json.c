/**********************************************************************
  Copyright(c) 2023 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

/* GHASH */
#include "mac_test.h"

const struct mac_test ghash_test_json[] = {
        {128, 128, 1,
         "\xa1\xf6\x25\x8c\x87\x7d\x5f\xcd\x89\x64\x48\x45\x38\xbf\xc9\x2c",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
         "\x9e\xe5\xa5\x1f\xbe\x28\xa1\x15\x3e\xf1\x96\xf5\x0b\xbf\x03\xca", 1, 128,
         NULL, 0},
        {128, 96, 2,
         "\x1f\x0a\x6d\xcc\x67\xb1\x87\x22\x98\x22\x77\x91\xdd\xa1\x9b\x6a",
         "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
         "\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
         "\xb5\x40\xda\x44\xa3\x8c\x9c\x2b\x95\x8e\x4b\x0b", 1, 256, NULL, 0},
        {128, 128, 3,
         "\x1f\x0a\x6d\xcc\x67\xb1\x87\x22\x98\x22\x77\x91\xdd\xa1\x9b\x6a", "\x05",
         "\xe6\xce\x47\xb5\xfb\xf2\xef\x37\x51\xf1\x57\x53\xad\x56\x4f\xed", 1, 8,
         NULL, 0},
        {128, 128, 4,
         "\x1f\x0f\x8a\x3a\xca\x64\x2e\xde\xb1\xdf\x8a\x52\x9a\x29\x76\xee",
         "\x9b\xb5\x92\x9f\xa7\xaa\x83\xfd\x0c\xd1\x83\x3a\x8e\xd5\x4d\xda\x6a\xaf"
         "\xa1\xc7\xa1\x32\x3a\xd4\x92\x9a\x2c\x83\xc6\x27\x92\x59\x28\x90\x11\xde"
         "\x19\x4e\xd5\x16\xef\x4f\x72\xeb\x79\x18\xd5\xb1\xc5\x22\x40\x14\x92\xa2",
         "\x8b\xa5\x3f\x5f\xd7\x0e\x55\x7c\x30\xd4\xf2\xe1\x1a\x4f\xf8\xc7", 1, 432,
         NULL, 0},
    {0, 0, 0, NULL, NULL, NULL, 0, 0, NULL, 0}
};
