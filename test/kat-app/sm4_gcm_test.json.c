/**********************************************************************
  Copyright(c) 2024 Intel Corporation All rights reserved.

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

#include "aead_test.h"
const struct aead_test sm4_gcm_test_json[] = {
        /* Vector from RFC-8998
          https://datatracker.ietf.org/doc/html/rfc8998
        */
        { 96, 128, 128, 1,
          "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
          "\xFE\xDC\xBA\x98\x76\x54\x32\x10",
          "\x00\x00\x12\x34\x56\x78\x00\x00"
          "\x00\x00\xAB\xCD",
          "\xFE\xED\xFA\xCE\xDE\xAD\xBE\xEF"
          "\xFE\xED\xFA\xCE\xDE\xAD\xBE\xEF"
          "\xAB\xAD\xDA\xD2",
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
          "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
          "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
          "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
          "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
          "\x17\xF3\x99\xF0\x8C\x67\xD5\xEE"
          "\x19\xD0\xDC\x99\x69\xC4\xBB\x7D"
          "\x5F\xD4\x6F\xD3\x75\x64\x89\x06"
          "\x91\x57\xB2\x82\xBB\x20\x07\x35"
          "\xD8\x27\x10\xCA\x5C\x22\xF0\xCC"
          "\xFA\x7C\xBF\x93\xD4\x96\xAC\x15"
          "\xA5\x68\x34\xCB\xCF\x98\xC3\x97"
          "\xB4\x02\x4A\x26\x91\x23\x3B\x8D",
          "\x83\xDE\x35\x41\xE4\xC2\xB5\x81"
          "\x77\xE0\x65\xA9\xBF\x7B\x62\xEC",
          1, 160, 512 },
        /* No plaintext, no AAD vector */
        { 96, 128, 128, 2,
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00",
          "", "", "",
          "\x23\x2f\x0c\xfe\x30\x8b\x49\xea"
          "\x6f\xc8\x82\x29\xb5\xdc\x85\x8d",
          1, 0, 0 },
        /* 16-byte plaintext with all zeros, no AAD */
        { 96, 128, 128, 3,
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00",
          "",
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x7d\xe2\xaa\x7f\x11\x10\x18\x82"
          "\x18\x06\x3b\xe1\xbf\xeb\x6d\x89",
          "\xb8\x51\xb5\xf3\x94\x93\x75\x2b"
          "\xe5\x08\xf1\xbb\x44\x82\xc5\x57",
          1, 0, 128 },
        /* No plaintext, 20-byte AAD */
        { 96, 128, 128, 4,
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00",
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00",
          "", "",
          "\x97\x20\x01\xb2\xd6\x04\xac\xcd"
          "\x37\x6d\x82\x9d\x35\x89\xf3\xd3",
          1, 160, 0 },
        /* Variable sized plaintext, AAD */
        { 96, 128, 128, 5,
          "\x69\x73\x51\xff\x4a\xec\x29\xcd"
          "\xba\xab\xf2\xfb\xe3\x46\x7c\xc2",
          "\x54\xf8\x1b\xe8\xe7\x8d\x76\x5a"
          "\x2e\x63\x33\x9f",
          "\xc9\x9a\x66\x32\x0d\xb7\x31\x58"
          "\xa3\x5a\x25\x5d\x05\x17\x58\xe9"
          "\x5e\xd4\xab\xb2\xcd\xc6\x9b\xb4"
          "\x54\x11\x0e\x82\x74\x41\x21\x3d"
          "\xdc\x87\x70\xe9\x3e\xa1\x41",
          "\xe1\xfc\x67\x3e\x01\x7e", "\x79\x0c\x5b\x40\xcb\xbe",
          "\x81\x96\xee\x15\x59\xac\xc9\x3d"
          "\xac\xc0\xdc\x7c\x9a\x40\x0e\x8d",
          1, 312, 48 },
        { 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0 }
};
