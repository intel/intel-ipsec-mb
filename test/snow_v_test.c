/**********************************************************************
  Copyright(c) 2021 Intel Corporation All rights reserved.

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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>		/* for memcmp() */
#include <assert.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"

#define MAX_BUFFER_LENGTH_IN_BYTES 128

int snow_v_test(IMB_MGR *p_mgr);
/**
 * Test vectors for SNOW-V-GCM from 'A new SNOW stream cipher called SNOW-V',
 * Patrik Ekdahl1, Thomas Johansson2, Alexander Maximov1 and Jing Yang2
**/

typedef struct snow_v_test_vectors_with_plain_0_s {
        uint8_t KEY[32];
        uint8_t IV[16];
        uint32_t length_in_bits;
        uint8_t ciphertext[MAX_BUFFER_LENGTH_IN_BYTES];
} snow_v_test_vectors_with_plain_0_t;

static const snow_v_test_vectors_with_plain_0_t snow_v_vectors_plain_0[] = {
        { /* == SNOW-V test vectors from spec #1 */
                {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                },
                {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                },
                128,
                {
                        0x69, 0xca, 0x6d, 0xaf, 0x9a, 0xe3, 0xb7, 0x2d,
                        0xb1, 0x34, 0xa8, 0x5a, 0x83, 0x7e, 0x41, 0x9d,
                        0xec, 0x08, 0xaa, 0xd3, 0x9d, 0x7b, 0x0f, 0x00,
                        0x9b, 0x60, 0xb2, 0x8c, 0x53, 0x43, 0x00, 0xed,
                        0x84, 0xab, 0xf5, 0x94, 0xfb, 0x08, 0xa7, 0xf1,
                        0xf3, 0xa2, 0xdf, 0x18, 0xe6, 0x17, 0x68, 0x3b,
                        0x48, 0x1f, 0xa3, 0x78, 0x07, 0x9d, 0xcf, 0x04,
                        0xdb, 0x53, 0xb5, 0xd6, 0x29, 0xa9, 0xeb, 0x9d,
                        0x03, 0x1c, 0x15, 0x9d, 0xcc, 0xd0, 0xa5, 0x0c,
                        0x4d, 0x5d, 0xbf, 0x51, 0x15, 0xd8, 0x70, 0x39,
                        0xc0, 0xd0, 0x3c, 0xa1, 0x37, 0x0c, 0x19, 0x40,
                        0x03, 0x47, 0xa0, 0xb4, 0xd2, 0xe9, 0xdb, 0xe5,
                        0xcb, 0xca, 0x60, 0x82, 0x14, 0xa2, 0x65, 0x82,
                        0xcf, 0x68, 0x09, 0x16, 0xb3, 0x45, 0x13, 0x21,
                        0x95, 0x4f, 0xdf, 0x30, 0x84, 0xaf, 0x02, 0xf6,
                        0xa8, 0xe2, 0x48, 0x1d, 0xe6, 0xbf, 0x82, 0x79
                }
        },
        { /* == SNOW-V test vectors from spec #2 */
                {
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                },
                {
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                },
                128,
                {
                        0x30, 0x76, 0x09, 0xfb, 0x10, 0x10, 0x12, 0x54,
                        0x4b, 0xc1, 0x75, 0xe3, 0x17, 0xfb, 0x25, 0xff,
                        0x33, 0x0d, 0x0d, 0xe2, 0x5a, 0xf6, 0xaa, 0xd1,
                        0x05, 0x05, 0xb8, 0x9b, 0x1e, 0x09, 0xa8, 0xec,
                        0xdd, 0x46, 0x72, 0xcc, 0xbb, 0x98, 0xc7, 0xf2,
                        0xc4, 0xe2, 0x4a, 0xf5, 0x27, 0x28, 0x36, 0xc8,
                        0x7c, 0xc7, 0x3a, 0x81, 0x76, 0xb3, 0x9c, 0xe9,
                        0x30, 0x3b, 0x3e, 0x76, 0x4e, 0x9b, 0xe3, 0xe7,
                        0x48, 0xf7, 0x65, 0x1a, 0x7c, 0x7e, 0x81, 0x3f,
                        0xd5, 0x24, 0x90, 0x23, 0x1e, 0x56, 0xf7, 0xc1,
                        0x44, 0xe4, 0x38, 0xe7, 0x77, 0x11, 0xa6, 0xb0,
                        0xba, 0xfb, 0x60, 0x45, 0x0c, 0x62, 0xd7, 0xd9,
                        0xb9, 0x24, 0x1d, 0x12, 0x44, 0xfc, 0xb4, 0x9d,
                        0xa1, 0xe5, 0x2b, 0x80, 0x13, 0xde, 0xcd, 0xd4,
                        0x86, 0x04, 0xff, 0xfc, 0x62, 0x67, 0x6e, 0x70,
                        0x3b, 0x3a, 0xb8, 0x49, 0xcb, 0xa6, 0xea, 0x09
                }
        },
        { /* == SNOW-V test vectors from spec #3 */
                {
                        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                        0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a,
                        0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa
                },
                {
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
                },
                128,
                {
                        0xaa, 0x81, 0xea, 0xfb, 0x8b, 0x86, 0x16, 0xce,
                        0x3e, 0x5c, 0xe2, 0x22, 0x24, 0x61, 0xc5, 0x0a,
                        0x6a, 0xb4, 0x48, 0x77, 0x56, 0xde, 0x4b, 0xd3,
                        0x1c, 0x90, 0x4f, 0x3d, 0x97, 0x8a, 0xfe, 0x56,
                        0x33, 0x4f, 0x10, 0xdd, 0xdf, 0x2b, 0x95, 0x31,
                        0x76, 0x9a, 0x71, 0x05, 0x0b, 0xe4, 0x38, 0x5f,
                        0xc2, 0xb6, 0x19, 0x2c, 0x7a, 0x85, 0x7b, 0xe8,
                        0xb4, 0xfc, 0x28, 0xb7, 0x09, 0xf0, 0x8f, 0x11,
                        0xf2, 0x06, 0x49, 0xe2, 0xee, 0xf2, 0x49, 0x80,
                        0xf8, 0x6c, 0x4c, 0x11, 0x36, 0x41, 0xfe, 0xd2,
                        0xf3, 0xf6, 0xfa, 0x2b, 0x91, 0x95, 0x12, 0x06,
                        0xb8, 0x01, 0xdb, 0x15, 0x46, 0x65, 0x17, 0xa6,
                        0x33, 0x0a, 0xdd, 0xa6, 0xb3, 0x5b, 0x26, 0x5e,
                        0xfd, 0x72, 0x2e, 0x86, 0x77, 0xb4, 0x8b, 0xfc,
                        0x15, 0xb4, 0x41, 0x18, 0xde, 0x52, 0xd0, 0x73,
                        0xb0, 0xad, 0x0f, 0xe7, 0x59, 0x4d, 0x62, 0x91
                }
        },

};

typedef struct snow_v_test_vectors_s {
	uint8_t KEY[32];
	uint8_t IV[16];
	uint64_t length_in_bits;
        uint8_t plaintext[MAX_BUFFER_LENGTH_IN_BYTES];
        /* use KEY and IV as in the structure fields */
	uint8_t ciphertext[MAX_BUFFER_LENGTH_IN_BYTES];
        /* fill IV with ones and KEY with zeros */
        uint8_t ciphertext_key_zero[MAX_BUFFER_LENGTH_IN_BYTES];
        /* fill KEY with ones and IV with zeros */
        uint8_t ciphertext_iv_zero[MAX_BUFFER_LENGTH_IN_BYTES];
        /* fill KEY and IV with zeros */
        uint8_t ciphertext_key_and_iv_zero[MAX_BUFFER_LENGTH_IN_BYTES];
        /* fill KEY and IV with ones */
        uint8_t ciphertext_key_and_iv_max[MAX_BUFFER_LENGTH_IN_BYTES];

} snow_v_test_vectors_t;

static const snow_v_test_vectors_t snow_v_vectors_cov[] = {
        {
                {
                        0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec,
                        0x29, 0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 0x46,
                        0x7c, 0xc2, 0x54, 0xf8, 0x1b, 0xe8, 0xe7, 0x8d,
                        0x76, 0x5a, 0x2e, 0x63, 0x33, 0x9f, 0xc9, 0x9a
                },
                {
                        0x66, 0x32, 0xd, 0xb7, 0x31, 0x58, 0xa3, 0x5a,
                        0x25, 0x5d, 0x5, 0x17, 0x58, 0xe9, 0x5e, 0xd4
                },
                0,
                { 0 },
                { 0 },
                { 0 },
                { 0 },
                { 0 },
                { 0 }
        },
        {
                {
                        0xb2, 0xcd, 0xc6, 0x9b, 0xb4, 0x54, 0x11, 0xe,
                        0x82, 0x74, 0x41, 0x21, 0x3d, 0xdc, 0x87, 0x70,
                        0xe9, 0x3e, 0xa1, 0x41, 0xe1, 0xfc, 0x67, 0x3e,
                        0x1, 0x7e, 0x97, 0xea, 0xdc, 0x6b, 0x96, 0x8f
                },
                {
                        0x38, 0x5c, 0x2a, 0xec, 0xb0, 0x3b, 0xfb, 0x32,
                        0xaf, 0x3c, 0x54, 0xec, 0x18, 0xdb, 0x5c, 0x2
                },
                1,
                { 0xab },
                { 0x11 },
                { 0x4f },
                { 0xd5 },
                { 0xc2 },
                { 0x9b }
        },
        {
                {
                        0x29, 0xd1, 0xe6, 0x5, 0x3c, 0x7c, 0x94, 0x75,
                        0xd8, 0xbe, 0x61, 0x89, 0xf9, 0x5c, 0xbb, 0xa8,
                        0x99, 0xf, 0x95, 0xb1, 0xeb, 0xf1, 0xb3, 0x5,
                        0xef, 0xf7, 0x0, 0xe9, 0xa1, 0x3a, 0xe5, 0xca
                },
                {
                        0xb, 0xcb, 0xd0, 0x48, 0x47, 0x64, 0xbd, 0x1f,
                        0x23, 0x1e, 0xa8, 0x1c, 0x7b, 0x64, 0xc5, 0x14
                },
                8,
                { 0x1a, 0xfe, 0x43, 0xfb, 0xfa, 0xaa, 0x3a, 0xfb },
                { 0x7e, 0x61, 0x35, 0x82, 0xd6, 0x19, 0x2e, 0x46 },
                { 0xfe, 0xca, 0x43, 0xb2, 0xf6, 0xd7, 0x5b, 0xc3 },
                { 0x64, 0xc7, 0x2c, 0x1f, 0xc3, 0x40, 0x2d, 0x9e },
                { 0x73, 0x34, 0x2e, 0x54, 0x60, 0x49, 0x8d, 0xd6 },
                { 0x2a, 0x88, 0x4a, 0x0, 0xea, 0xba, 0x28, 0xaf }
        },
        {
                {
                        0xaa, 0xd4, 0xac, 0xf2, 0x1b, 0x10, 0xaf, 0x3b,
                        0x33, 0xcd, 0xe3, 0x50, 0x48, 0x47, 0x15, 0x5c,
                        0xbb, 0x6f, 0x22, 0x19, 0xba, 0x9b, 0x7d, 0xf5,
                        0xb, 0xe1, 0x1a, 0x1c, 0x7f, 0x23, 0xf8, 0x29
                },
                {
                        0xf8, 0xa4, 0x1b, 0x13, 0xb5, 0xca, 0x4e, 0xe8,
                        0x98, 0x32, 0x38, 0xe0, 0x79, 0x4d, 0x3d, 0x34
                },
                15,
                {
                        0x73, 0x5a, 0xc5, 0x5e, 0x4b, 0x79, 0x63, 0x3b,
                        0x70, 0x64, 0x24, 0x11, 0x9e, 0x9, 0xdc
                },
                {
                        0x86, 0x50, 0x2c, 0xd8, 0xa5, 0x82, 0x9d, 0xe8,
                        0x99, 0x5, 0x97, 0xd2, 0x3, 0x1c, 0x91
                },
                {
                        0x97, 0x6e, 0xc5, 0x17, 0x47, 0x4, 0x2, 0x3,
                        0x38, 0x65, 0xe5, 0xc2, 0xa3, 0xe1, 0x49
                },
                {
                        0xd, 0x63, 0xaa, 0xba, 0x72, 0x93, 0x74, 0x5e,
                        0xae, 0x2f, 0x6c, 0xff, 0xaf, 0x5d, 0xb9
                },
                {
                        0x1a, 0x90, 0xa8, 0xf1, 0xd1, 0x9a, 0xd4, 0x16,
                        0xc1, 0x50, 0x8c, 0x4b, 0x1d, 0x77, 0x9d
                },
                {
                        0x43, 0x2c, 0xcc, 0xa5, 0x5b, 0x69, 0x71, 0x6f,
                        0x3b, 0xa5, 0x51, 0xf2, 0x89, 0xf2, 0xf9
                }
        },
        {
                {
                        0xbe, 0x70, 0xb5, 0x73, 0x3b, 0x4, 0x5c, 0xd3,
                        0x36, 0x94, 0xb3, 0xaf, 0xe2, 0xf0, 0xe4, 0x9e,
                        0x4f, 0x32, 0x15, 0x49, 0xfd, 0x82, 0x4e, 0xa9,
                        0x8, 0x70, 0xd4, 0xb2, 0x8a, 0x29, 0x54, 0x48
                },
                {
                        0x9a, 0xa, 0xbc, 0xd5, 0xe, 0x18, 0xa8, 0x44,
                        0xac, 0x5b, 0xf3, 0x8e, 0x4c, 0xd7, 0x2d, 0x9b
                },
                16,
                {
                        0xbc, 0x5f, 0x4e, 0x77, 0xfa, 0xcb, 0x6c, 0x5,
                        0xac, 0x86, 0x21, 0x2b, 0xaa, 0x1a, 0x55, 0xa2
                },
                {
                        0x64, 0x7, 0x67, 0x25, 0xc6, 0x69, 0x1d, 0x4,
                        0xb0, 0xad, 0x2e, 0xc6, 0x7f, 0x18, 0x95, 0x16
                },
                {
                        0x58, 0x6b, 0x4e, 0x3e, 0xf6, 0xb6, 0xd, 0x3d,
                        0xe4, 0x87, 0xe0, 0xf8, 0x97, 0xf2, 0xc0, 0x3b
                },
                {
                        0xc2, 0x66, 0x21, 0x93, 0xc3, 0x21, 0x7b, 0x60,
                        0x72, 0xcd, 0x69, 0xc5, 0x9b, 0x4e, 0x30, 0xb8
                },
                {
                        0xd5, 0x95, 0x23, 0xd8, 0x60, 0x28, 0xdb, 0x28,
                        0x1d, 0xb2, 0x89, 0x71, 0x29, 0x64, 0x14, 0x3f
                },
                {
                        0x8c, 0x29, 0x47, 0x8c, 0xea, 0xdb, 0x7e, 0x51,
                        0xe7, 0x47, 0x54, 0xc8, 0xbd, 0xe1, 0x70, 0x5d
                }
        },
        {
                {
                        0x32, 0x1c, 0xec, 0x4a, 0xc4, 0x30, 0xf6, 0x20,
                        0x23, 0x85, 0x6c, 0xfb, 0xb2, 0x7, 0x4, 0xf4,
                        0xec, 0xb, 0xb9, 0x20, 0xba, 0x86, 0xc3, 0x3e,
                        0x5, 0xf1, 0xec, 0xd9, 0x67, 0x33, 0xb7, 0x99
                },
                {
                        0x50, 0xa3, 0xe3, 0x14, 0xd3, 0xd9, 0x34, 0xf7,
                        0x5e, 0xa0, 0xf2, 0x10, 0xa8, 0xf6, 0x5, 0x94
                },
                17,
                {
                        0x9, 0x42, 0xe5, 0x6, 0xc4, 0x33, 0xaf, 0xcd,
                        0xa3, 0x84, 0x7f, 0x2d, 0xad, 0xd4, 0x76, 0x47,
                        0xde
                },
                {
                        0xcb, 0xfe, 0x27, 0xc0, 0xfb, 0xc7, 0xc5, 0xce,
                        0x6d, 0x9e, 0xf1, 0x34, 0xe3, 0x4a, 0x42, 0x75,
                        0x94
                },
                {
                        0xed, 0x76, 0xe5, 0x4f, 0xc8, 0x4e, 0xce, 0xf5,
                        0xeb, 0x85, 0xbe, 0xfe, 0x90, 0x3c, 0xe3, 0xde,
                        0x6b
                },
                {
                        0x77, 0x7b, 0x8a, 0xe2, 0xfd, 0xd9, 0xb8, 0xa8,
                        0x7d, 0xcf, 0x37, 0xc3, 0x9c, 0x80, 0x13, 0x5d,
                        0x10
                },
                {
                        0x60, 0x88, 0x88, 0xa9, 0x5e, 0xd0, 0x18, 0xe0,
                        0x12, 0xb0, 0xd7, 0x77, 0x2e, 0xaa, 0x37, 0xda,
                        0x32
                },
                {
                        0x39, 0x34, 0xec, 0xfd, 0xd4, 0x23, 0xbd, 0x99,
                        0xe8, 0x45, 0xa, 0xce, 0xba, 0x2f, 0x53, 0xb8,
                        0xed
                }
        },
        {
                {
                        0xaa, 0xd2, 0xb2, 0xd0, 0x85, 0xfa, 0x54, 0xd8,
                        0x35, 0xe8, 0xd4, 0x66, 0x82, 0x64, 0x98, 0xd9,
                        0xa8, 0x87, 0x75, 0x65, 0x70, 0x5a, 0x8a, 0x3f,
                        0x62, 0x80, 0x29, 0x44, 0xde, 0x7c, 0xa5, 0x89
                },
                {
                        0x4e, 0x57, 0x59, 0xd3, 0x51, 0xad, 0xac, 0x86,
                        0x95, 0x80, 0xec, 0x17, 0xe4, 0x85, 0xf1, 0x8c
                },
                48,
                {
                        0x1, 0xbe, 0xb4, 0xbc, 0x44, 0x78, 0xfa, 0x49,
                        0x69, 0xe6, 0x23, 0xd0, 0x1a, 0xda, 0x69, 0x6a,
                        0x7e, 0x4c, 0x7e, 0x51, 0x25, 0xb3, 0x48, 0x84,
                        0x53, 0x3a, 0x94, 0xfb, 0x31, 0x99, 0x90, 0x32,
                        0x57, 0x44, 0xee, 0x9b, 0xbc, 0xe9, 0xe5, 0x25,
                        0xcf, 0x8, 0xf5, 0xe9, 0xe2, 0x5e, 0x53, 0x60
                },
                {
                        0xa5, 0x16, 0xdc, 0xdb, 0xcf, 0x55, 0x89, 0x11,
                        0xbb, 0x59, 0x11, 0xb2, 0x9b, 0x91, 0xa5, 0x98,
                        0xcc, 0x4e, 0xde, 0x80, 0xb6, 0x90, 0xda, 0x36,
                        0xae, 0xbb, 0xcc, 0xdb, 0x72, 0x79, 0x38, 0xed,
                        0x59, 0xd6, 0x29, 0x31, 0x13, 0x0, 0xad, 0xae,
                        0x37, 0xfd, 0x9, 0xc6, 0x5c, 0x55, 0x57, 0x4c
                },
                {
                        0xe5, 0x8a, 0xb4, 0xf5, 0x48, 0x5, 0x9b, 0x71,
                        0x21, 0xe7, 0xe2, 0x3, 0x27, 0x32, 0xfc, 0xf3,
                        0xcb, 0x91, 0x75, 0x4b, 0x4b, 0x48, 0xc9, 0xde,
                        0xa0, 0xf9, 0x22, 0x1a, 0xd, 0xf1, 0x10, 0xb,
                        0x28, 0x1d, 0x8f, 0xbd, 0xe3, 0x2b, 0x7b, 0x23,
                        0x42, 0xec, 0x1f, 0xf9, 0xa8, 0xe6, 0xee, 0x47
                },
                {
                        0x7f, 0x87, 0xdb, 0x58, 0x7d, 0x92, 0xed, 0x2c,
                        0xb7, 0xad, 0x6b, 0x3e, 0x2b, 0x8e, 0xc, 0x70,
                        0xb0, 0x2b, 0x9, 0xd4, 0x31, 0x4e, 0x84, 0x2d,
                        0xc6, 0x54, 0xc6, 0x5, 0x4b, 0xdc, 0xaf, 0x39,
                        0xbc, 0x1f, 0xe0, 0x0, 0x9b, 0xf4, 0x8e, 0xe5,
                        0xb4, 0xef, 0xb8, 0x15, 0x52, 0x22, 0xb6, 0xee
                },
                {
                        0x68, 0x74, 0xd9, 0x13, 0xde, 0x9b, 0x4d, 0x64,
                        0xd8, 0xd2, 0x8b, 0x8a, 0x99, 0xa4, 0x28, 0xf7,
                        0x92, 0x44, 0xd4, 0x82, 0xb8, 0xc8, 0x47, 0x84,
                        0xc8, 0x5a, 0x26, 0x77, 0x62, 0xda, 0x90, 0xdf,
                        0xd3, 0xef, 0x1b, 0xf, 0x47, 0xe1, 0x42, 0xd4,
                        0x3c, 0xaa, 0x2a, 0xf1, 0x4, 0x49, 0x3b, 0x5b
                },
                {
                        0x31, 0xc8, 0xbd, 0x47, 0x54, 0x68, 0xe8, 0x1d,
                        0x22, 0x27, 0x56, 0x33, 0xd, 0x21, 0x4c, 0x95,
                        0x4d, 0x41, 0x73, 0xb3, 0x7f, 0x45, 0xe2, 0x55,
                        0x56, 0x3f, 0x2c, 0x60, 0x2f, 0x90, 0x38, 0xde,
                        0x8a, 0x2, 0x9c, 0x57, 0x7, 0x71, 0x22, 0xd7,
                        0xb, 0xea, 0xbf, 0x1c, 0xc5, 0x76, 0x65, 0xa8
                }
        },
        {
                {
                        0x77, 0x9, 0xd1, 0xa5, 0x96, 0xc1, 0xf4, 0x1f,
                        0x95, 0xaa, 0x82, 0xca, 0x6c, 0x49, 0xae, 0x90,
                        0xcd, 0x16, 0x68, 0xba, 0xac, 0x7a, 0xa6, 0xf2,
                        0xb4, 0xa8, 0xca, 0x99, 0xb2, 0xc2, 0x37, 0x2a
                },
                {
                        0xcb, 0x8, 0xcf, 0x61, 0xc9, 0xc3, 0x80, 0x5e,
                        0x6e, 0x3, 0x28, 0xda, 0x4c, 0xd7, 0x6a, 0x19
                },
                63,
                {
                        0xc, 0x66, 0xf1, 0x7c, 0xc0, 0x7c, 0xbb, 0x22,
                        0xfc, 0xe4, 0x66, 0xda, 0x61, 0xb, 0x63, 0xaf,
                        0x62, 0xbc, 0x83, 0xb4, 0x69, 0x2f, 0x3a, 0xff,
                        0xaf, 0x27, 0x16, 0x93, 0xac, 0x7, 0x1f, 0xb8,
                        0x6d, 0x11, 0x34, 0x2d, 0x8d, 0xef, 0x4f, 0x89,
                        0xd4, 0xb6, 0x63, 0x35, 0xc1, 0xc7, 0xe4, 0x24,
                        0x83, 0x67, 0xd8, 0xed, 0x96, 0x12, 0xec, 0x45,
                        0x39, 0x2, 0xd8, 0xe5, 0xa, 0xf8, 0x9d
                },
                {
                        0x76, 0xd2, 0x2e, 0xab, 0xd5, 0x9c, 0x1d, 0x76,
                        0xd8, 0xf2, 0x8f, 0x8d, 0xbe, 0x65, 0xae, 0x8b,
                        0x73, 0xed, 0xb4, 0x2a, 0xec, 0x60, 0xf5, 0xdc,
                        0x3c, 0x6d, 0x14, 0x70, 0x19, 0xbc, 0xc, 0xe7,
                        0x5c, 0xad, 0xc8, 0x17, 0x5d, 0x9e, 0xd6, 0x89,
                        0x62, 0x9b, 0x0, 0x59, 0x68, 0x3f, 0x67, 0xeb,
                        0x7d, 0x96, 0xfa, 0x26, 0xdf, 0xd2, 0x38, 0x48,
                        0x14, 0x1d, 0xcb, 0x3a, 0xc9, 0x23, 0x1e
                },
                {
                        0xe8, 0x52, 0xf1, 0x35, 0xcc, 0x1, 0xda, 0x1a,
                        0xb4, 0xe5, 0xa7, 0x9, 0x5c, 0xe3, 0xf6, 0x36,
                        0xd7, 0x61, 0x88, 0xae, 0x7, 0xd4, 0xbb, 0xa5,
                        0x5c, 0xe4, 0xa0, 0x72, 0x90, 0x6f, 0x9f, 0x81,
                        0x12, 0x48, 0x55, 0xb, 0xd2, 0x2d, 0xd1, 0x8f,
                        0x59, 0x52, 0x89, 0x25, 0x8b, 0x7f, 0x59, 0x3,
                        0xe7, 0x15, 0x21, 0x49, 0x1d, 0xf2, 0x6b, 0xfb,
                        0x66, 0x85, 0xc6, 0xac, 0x17, 0xe8, 0x9d
                },
                {
                        0x72, 0x5f, 0x9e, 0x98, 0xf9, 0x96, 0xac, 0x47,
                        0x22, 0xaf, 0x2e, 0x34, 0x50, 0x5f, 0x6, 0xb5,
                        0xac, 0xdb, 0xf4, 0x31, 0x7d, 0xd2, 0xf6, 0x56,
                        0x3a, 0x49, 0x44, 0x6d, 0xd6, 0x42, 0x20, 0xb3,
                        0x86, 0x4a, 0x3a, 0xb6, 0xaa, 0xf2, 0x24, 0x49,
                        0xaf, 0x51, 0x2e, 0xc9, 0x71, 0xbb, 0x1, 0xaa,
                        0xa, 0x4, 0xb, 0x28, 0xcf, 0xd5, 0x39, 0x9d,
                        0x7a, 0x38, 0x4d, 0xfa, 0xf7, 0xac, 0x47
                },
                {
                        0x65, 0xac, 0x9c, 0xd3, 0x5a, 0x9f, 0xc, 0xf,
                        0x4d, 0xd0, 0xce, 0x80, 0xe2, 0x75, 0x22, 0x32,
                        0x8e, 0xb4, 0x29, 0x67, 0xf4, 0x54, 0x35, 0xff,
                        0x34, 0x47, 0xa4, 0x1f, 0xff, 0x44, 0x1f, 0x55,
                        0xe9, 0xba, 0xc1, 0xb9, 0x76, 0xe7, 0xe8, 0x78,
                        0x27, 0x14, 0xbc, 0x2d, 0x27, 0xd0, 0x8c, 0x1f,
                        0xcb, 0x78, 0x7b, 0x95, 0x91, 0x8f, 0x23, 0x41,
                        0xe2, 0x51, 0x6d, 0x33, 0x23, 0x51, 0x76
                },
                {
                        0x3c, 0x10, 0xf8, 0x87, 0xd0, 0x6c, 0xa9, 0x76,
                        0xb7, 0x25, 0x13, 0x39, 0x76, 0xf0, 0x46, 0x50,
                        0x51, 0xb1, 0x8e, 0x56, 0x33, 0xd9, 0x90, 0x2e,
                        0xaa, 0x22, 0xae, 0x8, 0xb2, 0xe, 0xb7, 0x54,
                        0xb0, 0x57, 0x46, 0xe1, 0x36, 0x77, 0x88, 0x7b,
                        0x10, 0x54, 0x29, 0xc0, 0xe6, 0xef, 0xd2, 0xec,
                        0xff, 0xa0, 0xe2, 0x6c, 0xe0, 0xa1, 0x70, 0xac,
                        0x9, 0x39, 0xe6, 0x93, 0x44, 0x63, 0x7e
                }
        },
        {
                {
                        0x81, 0xeb, 0x61, 0xfd, 0xfe, 0xc3, 0x9b, 0x67,
                        0xbf, 0xd, 0xe9, 0x8c, 0x7e, 0x4e, 0x32, 0xbd,
                        0xf9, 0x7c, 0x8c, 0x6a, 0xc7, 0x5b, 0xa4, 0x3c,
                        0x2, 0xf4, 0xb2, 0xed, 0x72, 0x16, 0xec, 0xf3
                },
                {
                        0x1, 0x4d, 0xf0, 0x0, 0x10, 0x8b, 0x67, 0xcf,
                        0x99, 0x50, 0x5b, 0x17, 0x9f, 0x8e, 0xd4, 0x98
                },
                64,
                {
                        0xed, 0xd2, 0xd3, 0x99, 0x4c, 0x79, 0x8b, 0x0,
                        0x22, 0x56, 0x9a, 0xd4, 0x18, 0xd1, 0xfe, 0xe4,
                        0xd9, 0xcd, 0x45, 0xa3, 0x91, 0xc6, 0x1, 0xff,
                        0xc9, 0x2a, 0xd9, 0x15, 0x1, 0x43, 0x2f, 0xee,
                        0x15, 0x2, 0x87, 0x61, 0x7c, 0x13, 0x62, 0x9e,
                        0x69, 0xfc, 0x72, 0x81, 0xcd, 0x71, 0x65, 0xa6,
                        0x3e, 0xab, 0x49, 0xcf, 0x71, 0x4b, 0xce, 0x3a,
                        0x75, 0xa7, 0x4f, 0x76, 0xea, 0x7e, 0x64, 0xff
                },
                {
                        0xf8, 0x36, 0xe8, 0x7f, 0xa0, 0x90, 0x36, 0xff,
                        0x83, 0x61, 0xd0, 0x44, 0xd0, 0x2d, 0xec, 0x43,
                        0xdb, 0x28, 0xdc, 0x81, 0x43, 0xbe, 0x84, 0x81,
                        0xe0, 0x70, 0xeb, 0xbd, 0xb9, 0x71, 0x8d, 0x68,
                        0xbf, 0x78, 0x5a, 0xf3, 0x4e, 0x9, 0x5e, 0xdc,
                        0x59, 0xdb, 0xd3, 0x9c, 0x2d, 0x81, 0xbf, 0xf3,
                        0x65, 0x48, 0x95, 0xf5, 0xb9, 0x1f, 0xd5, 0xf3,
                        0x8b, 0x48, 0xc9, 0x86, 0x7a, 0x6, 0x3a, 0x3c
                },
                {
                        0x9, 0xe6, 0xd3, 0xd0, 0x40, 0x4, 0xea, 0x38,
                        0x6a, 0x57, 0x5b, 0x7, 0x25, 0x39, 0x6b, 0x7d,
                        0x6c, 0x10, 0x4e, 0xb9, 0xff, 0x3d, 0x80, 0xa5,
                        0x3a, 0xe9, 0x6f, 0xf4, 0x3d, 0x2b, 0xaf, 0xd7,
                        0x6a, 0x5b, 0xe6, 0x47, 0x23, 0xd1, 0xfc, 0x98,
                        0xe4, 0x18, 0x98, 0x91, 0x87, 0xc9, 0xd8, 0x81,
                        0x5a, 0xd9, 0xb0, 0x6b, 0xfa, 0xab, 0x49, 0x84,
                        0x2a, 0x20, 0x51, 0x3f, 0xf7, 0x6e, 0x64, 0x2c
                },
                {
                        0x93, 0xeb, 0xbc, 0x7d, 0x75, 0x93, 0x9c, 0x65,
                        0xfc, 0x1d, 0xd2, 0x3a, 0x29, 0x85, 0x9b, 0xfe,
                        0x17, 0xaa, 0x32, 0x26, 0x85, 0x3b, 0xcd, 0x56,
                        0x5c, 0x44, 0x8b, 0xeb, 0x7b, 0x6, 0x10, 0xe5,
                        0xfe, 0x59, 0x89, 0xfa, 0x5b, 0xe, 0x9, 0x5e,
                        0x12, 0x1b, 0x3f, 0x7d, 0x7d, 0xd, 0x80, 0x28,
                        0xb7, 0xc8, 0x9a, 0xa, 0x28, 0x8c, 0x1b, 0xe2,
                        0x36, 0x9d, 0xda, 0x69, 0x17, 0x2a, 0xbe, 0xe5
                },
                {
                        0x84, 0x18, 0xbe, 0x36, 0xd6, 0x9a, 0x3c, 0x2d,
                        0x93, 0x62, 0x32, 0x8e, 0x9b, 0xaf, 0xbf, 0x79,
                        0x35, 0xc5, 0xef, 0x70, 0xc, 0xbd, 0xe, 0xff,
                        0x52, 0x4a, 0x6b, 0x99, 0x52, 0x0, 0x2f, 0x3,
                        0x91, 0xa9, 0x72, 0xf5, 0x87, 0x1b, 0xc5, 0x6f,
                        0x9a, 0x5e, 0xad, 0x99, 0x2b, 0x66, 0xd, 0x9d,
                        0x76, 0xb4, 0xea, 0xb7, 0x76, 0xd6, 0x1, 0x3e,
                        0xae, 0xf4, 0xfa, 0xa0, 0xc3, 0xd7, 0x8f, 0x62
                },
                {
                        0xdd, 0xa4, 0xda, 0x62, 0x5c, 0x69, 0x99, 0x54,
                        0x69, 0x97, 0xef, 0x37, 0xf, 0x2a, 0xdb, 0x1b,
                        0xea, 0xc0, 0x48, 0x41, 0xcb, 0x30, 0xab, 0x2e,
                        0xcc, 0x2f, 0x61, 0x8e, 0x1f, 0x4a, 0x87, 0x2,
                        0xc8, 0x44, 0xf5, 0xad, 0xc7, 0x8b, 0xa5, 0x6c,
                        0xad, 0x1e, 0x38, 0x74, 0xea, 0x59, 0x53, 0x6e,
                        0x42, 0x6c, 0x73, 0x4e, 0x7, 0xf8, 0x52, 0xd3,
                        0x45, 0x9c, 0x71, 0x0, 0xa4, 0xe5, 0x87, 0x18
                }
        },
        {
                {
                        0xd5, 0x55, 0xd1, 0x6c, 0x33, 0xdd, 0xc2, 0xbc,
                        0xf7, 0xed, 0xde, 0x13, 0xef, 0xe5, 0x20, 0xc7,
                        0xe2, 0xab, 0xdd, 0xa4, 0x4d, 0x81, 0x88, 0x1c,
                        0x53, 0x1a, 0xee, 0xeb, 0x66, 0x24, 0x4c, 0x3b
                },
                {
                        0x79, 0x1e, 0xa8, 0xac, 0xfb, 0x6a, 0x68, 0xf3,
                        0x58, 0x46, 0x6, 0x47, 0x2b, 0x26, 0xe, 0xd
                },
                65,
                {
                        0xa, 0x61, 0x3, 0xd1, 0xbc, 0xa7, 0xd, 0xbe,
                        0x9b, 0xbf, 0xab, 0xe, 0xd5, 0x98, 0x1, 0xd6,
                        0xe5, 0xf2, 0xd6, 0xf6, 0x7d, 0x3e, 0xc5, 0x16,
                        0x8e, 0x21, 0x2e, 0x2d, 0xaf, 0x2, 0xc6, 0xb9,
                        0x63, 0xc9, 0x8a, 0x1f, 0x70, 0x97, 0xde, 0xc,
                        0x56, 0x89, 0x1a, 0x2b, 0x21, 0x1b, 0x1, 0x7,
                        0xd, 0xd8, 0xfd, 0x8b, 0x16, 0xc2, 0xa1, 0xa4,
                        0xe3, 0xcf, 0xd2, 0x92, 0xd2, 0x98, 0x4b, 0x35,
                        0x61
                },
                {
                        0x6e, 0x6e, 0xc4, 0xe0, 0x8a, 0x8e, 0xa6, 0x25,
                        0x2, 0x61, 0xa5, 0x70, 0xb9, 0xc6, 0x2c, 0x8c,
                        0x79, 0xc5, 0x3, 0x74, 0xee, 0x6b, 0x56, 0x1b,
                        0xff, 0x5b, 0x40, 0x6f, 0x17, 0x9, 0xd7, 0x12,
                        0xd, 0xe0, 0x9a, 0x6d, 0x5b, 0xe7, 0x21, 0x52,
                        0xde, 0xef, 0x46, 0x0, 0xdd, 0xfb, 0x22, 0xbf,
                        0xca, 0xc0, 0x4b, 0x2e, 0xf0, 0xc4, 0x22, 0x64,
                        0xbb, 0xc3, 0xae, 0x94, 0x13, 0xc0, 0x18, 0x5f,
                        0xf4
                },
                {
                        0xee, 0x55, 0x3, 0x98, 0xb0, 0xda, 0x6c, 0x86,
                        0xd3, 0xbe, 0x6a, 0xdd, 0xe8, 0x70, 0x94, 0x4f,
                        0x50, 0x2f, 0xdd, 0xec, 0x13, 0xc5, 0x44, 0x4c,
                        0x7d, 0xe2, 0x98, 0xcc, 0x93, 0x6a, 0x46, 0x80,
                        0x1c, 0x90, 0xeb, 0x39, 0x2f, 0x55, 0x40, 0xa,
                        0xdb, 0x6d, 0xf0, 0x3b, 0x6b, 0xa3, 0xbc, 0x20,
                        0x69, 0xaa, 0x4, 0x2f, 0x9d, 0x22, 0x26, 0x1a,
                        0xbc, 0x48, 0xcc, 0xdb, 0xcf, 0x88, 0x4b, 0xe6,
                        0xdd
                },
                {
                        0x74, 0x58, 0x6c, 0x35, 0x85, 0x4d, 0x1a, 0xdb,
                        0x45, 0xf4, 0xe3, 0xe0, 0xe4, 0xcc, 0x64, 0xcc,
                        0x2b, 0x95, 0xa1, 0x73, 0x69, 0xc3, 0x9, 0xbf,
                        0x1b, 0x4f, 0x7c, 0xd3, 0xd5, 0x47, 0xf9, 0xb2,
                        0x88, 0x92, 0x84, 0x84, 0x57, 0x8a, 0xb5, 0xcc,
                        0x2d, 0x6e, 0x57, 0xd7, 0x91, 0x67, 0xe4, 0x89,
                        0x84, 0xbb, 0x2e, 0x4e, 0x4f, 0x5, 0x74, 0x7c,
                        0xa0, 0xf5, 0x47, 0x8d, 0x2f, 0xcc, 0x91, 0x2f,
                        0x8a
                },
                {
                        0x63, 0xab, 0x6e, 0x7e, 0x26, 0x44, 0xba, 0x93,
                        0x2a, 0x8b, 0x3, 0x54, 0x56, 0xe6, 0x40, 0x4b,
                        0x9, 0xfa, 0x7c, 0x25, 0xe0, 0x45, 0xca, 0x16,
                        0x15, 0x41, 0x9c, 0xa1, 0xfc, 0x41, 0xc6, 0x54,
                        0xe7, 0x62, 0x7f, 0x8b, 0x8b, 0x9f, 0x79, 0xfd,
                        0xa5, 0x2b, 0xc5, 0x33, 0xc7, 0xc, 0x69, 0x3c,
                        0x45, 0xc7, 0x5e, 0xf3, 0x11, 0x5f, 0x6e, 0xa0,
                        0x38, 0x9c, 0x67, 0x44, 0xfb, 0x31, 0xa0, 0xa8,
                        0x62
                },
                {
                        0x3a, 0x17, 0xa, 0x2a, 0xac, 0xb7, 0x1f, 0xea,
                        0xd0, 0x7e, 0xde, 0xed, 0xc2, 0x63, 0x24, 0x29,
                        0xd6, 0xff, 0xdb, 0x14, 0x27, 0xc8, 0x6f, 0xc7,
                        0x8b, 0x24, 0x96, 0xb6, 0xb1, 0xb, 0x6e, 0x55,
                        0xbe, 0x8f, 0xf8, 0xd3, 0xcb, 0xf, 0x19, 0xfe,
                        0x92, 0x6b, 0x50, 0xde, 0x6, 0x33, 0x37, 0xcf,
                        0x71, 0x1f, 0xc7, 0xa, 0x60, 0x71, 0x3d, 0x4d,
                        0xd3, 0xf4, 0xec, 0xe4, 0x9c, 0x3, 0xa8, 0xd2,
                        0x29
                }
        }
};

static void
snow_v_single_test(IMB_MGR *p_mgr,
                   struct test_suite_context *ts,
                   const uint8_t *key,
                   const uint8_t *iv,
                   const uint8_t *plain,
                   const size_t size,
                   const uint8_t *expected)
{
        const size_t pad_size = 16;
        const size_t alloc_size = size + (2 * pad_size);
        const int pad_pattern = 0xa5;
        uint8_t *dst_ptr = NULL, *output = malloc(alloc_size);
        uint32_t pass = 0, fail = 0;
        struct IMB_JOB *job;

        if (output == NULL) {
                fprintf(stderr, "Error allocating %lu bytes!\n",
                        (unsigned long) alloc_size);
                exit(EXIT_FAILURE);
        }

        dst_ptr = &output[pad_size];

        /* Prime padding blocks with a pattern */
        memset(output, pad_pattern, pad_size);
        memset(&output[alloc_size - pad_size], pad_pattern, pad_size);

        job = IMB_GET_NEXT_JOB(p_mgr);

        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_SNOW_V;
        job->hash_alg = IMB_AUTH_NULL;
        job->key_len_in_bytes = 32;
        job->iv_len_in_bytes = 16;
        job->cipher_start_src_offset_in_bytes = 0;

        job->enc_keys = key;
        job->iv = iv;
        job->dst = dst_ptr;
        job->src = plain;
        job->msg_len_to_cipher_in_bytes = size;

        job = IMB_SUBMIT_JOB(p_mgr);
        if (job == NULL) {
                const int err = imb_get_errno(p_mgr);

                if (err != 0)
                        printf("Error: %s!\n", imb_get_strerror(err));
                fail++;
        } else {
                uint8_t pad_block[16];
                int fail_found = 0;

                /* check for vector match */
                if (memcmp(dst_ptr, expected, size) != 0) {
                        hexdump(stderr, "expected", expected, size);
                        hexdump(stderr, "received", &output[pad_size], size);
                        fail_found = 1;
                }

                /* check for buffer under/over-write */
                assert(sizeof(pad_block) == pad_size);
                memset(pad_block, pad_pattern, sizeof(pad_block));

                if (memcmp(pad_block, output, pad_size) != 0) {
                        hexdump(stderr, "underwrite detected", output,
                                pad_size);
                        fail_found = 1;
                }

                if (memcmp(pad_block, &output[alloc_size - pad_size],
                            pad_size) != 0) {
                        hexdump(stderr, "overwrite detected",
                                &output[alloc_size - pad_size], pad_size);
                        fail_found = 1;
                }

                if (fail_found)
                        fail++;
                else
                        pass++;
        }

        test_suite_update(ts, pass, fail);
        free(output);
}

static void
test_snow_v(struct test_suite_context *ts, IMB_MGR *p_mgr)
{
        uint8_t zero_key[32];
        uint8_t zero_iv[16];
        const uint8_t max_key[32] = {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };
        const uint8_t max_iv[16] = {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };
        uint8_t zero_plain[128];
        const size_t compare_size = sizeof(zero_plain);
        struct IMB_JOB *job;
        uint64_t i;

        /* flush the scheduler */
        while ((job = IMB_FLUSH_JOB(p_mgr)) != NULL)
        ;

        memset(zero_plain, 0, compare_size);

        printf("SNOW-V test vectors:\n");

        for (i = 0; i < DIM(snow_v_vectors_plain_0); i++)
                snow_v_single_test(p_mgr, ts,
                        snow_v_vectors_plain_0[i].KEY,
                        snow_v_vectors_plain_0[i].IV,
                        zero_plain, compare_size,
                        snow_v_vectors_plain_0[i].ciphertext);

        memset(zero_key, 0, sizeof(zero_key));
        memset(zero_iv, 0, sizeof(zero_iv));

        for (i = 0; i < DIM(snow_v_vectors_cov); i++) {
                /* Test random key and IV */
                snow_v_single_test(p_mgr, ts,
                        snow_v_vectors_cov[i].KEY,
                        snow_v_vectors_cov[i].IV,
                        snow_v_vectors_cov[i].plaintext,
                        snow_v_vectors_cov[i].length_in_bits,
                        snow_v_vectors_cov[i].ciphertext);
                /* Test zero key and IV */
                snow_v_single_test(p_mgr, ts,
                        zero_key,
                        zero_iv,
                        snow_v_vectors_cov[i].plaintext,
                        snow_v_vectors_cov[i].length_in_bits,
                        snow_v_vectors_cov[i].ciphertext_key_and_iv_zero);
                        /* Test max key and IV */
                snow_v_single_test(p_mgr, ts,
                        max_key,
                        max_iv,
                        snow_v_vectors_cov[i].plaintext,
                        snow_v_vectors_cov[i].length_in_bits,
                        snow_v_vectors_cov[i].ciphertext_key_and_iv_max);
                /* Test zero key and max IV */
                snow_v_single_test(p_mgr, ts,
                        zero_key,
                        max_iv,
                        snow_v_vectors_cov[i].plaintext,
                        snow_v_vectors_cov[i].length_in_bits,
                        snow_v_vectors_cov[i].ciphertext_key_zero);
                /* Test max key and zero IV */
                snow_v_single_test(p_mgr, ts,
                        max_key,
                        zero_iv,
                        snow_v_vectors_cov[i].plaintext,
                        snow_v_vectors_cov[i].length_in_bits,
                        snow_v_vectors_cov[i].ciphertext_iv_zero);
        }
}

int snow_v_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts_snow;
        int errors = 0;

        test_suite_start(&ts_snow, "SNOV-V");
        test_snow_v(&ts_snow, p_mgr);
        errors += test_suite_end(&ts_snow);

        return errors;
}
