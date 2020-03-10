/**********************************************************************
  Copyright(c) 2011-2020 Intel Corporation All rights reserved.

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

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"

/*
 * 60-Byte Packet Encryption Using GCM-AES-128
 *    http://www.ieee802.org/1/files/public/
 *        docs2011/bn-randall-test-vectors-0511-v1.pdf
 *
 * K:   AD7A2BD03EAC835A6F620FDCB506B345
 * IV:  12153524C0895E81B2C28465
 * AAD: D609B1F056637A0D46DF998D88E52E00
 *      B2C2846512153524C0895E81
 * P:   08000F101112131415161718191A1B1C
 *      1D1E1F202122232425262728292A2B2C
 *      2D2E2F303132333435363738393A0002
 * C:   701AFA1CC039C0D765128A665DAB6924
 *      3899BF7318CCDC81C9931DA17FBE8EDD
 *      7D17CB8B4C26FC81E3284F2B7FBA713D
 * AT:  4F8D55E7D3F06FD5A13C0C29B9D5B880
 * H:   73A23D80121DE2D5A850253FCF43120E
 */
static uint8_t K1[] = {
        0xAD, 0x7A, 0x2B, 0xD0, 0x3E, 0xAC, 0x83, 0x5A,
        0x6F, 0x62, 0x0F, 0xDC, 0xB5, 0x06, 0xB3, 0x45
};
static uint8_t P1[] = {
        0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
	0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
	0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x00, 0x02
};
static uint8_t IV1[] = {
        0x12, 0x15, 0x35, 0x24, 0xC0, 0x89, 0x5E, 0x81,
        0xB2, 0xC2, 0x84, 0x65
};
static uint8_t A1[] = {
        0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D,
        0x46, 0xDF, 0x99, 0x8D, 0x88, 0xE5, 0x2E, 0x00,
        0xB2, 0xC2, 0x84, 0x65, 0x12, 0x15, 0x35, 0x24,
        0xC0, 0x89, 0x5E, 0x81
};

#define A1_len sizeof(A1)

static uint8_t C1[] = {
        0x70, 0x1A, 0xFA, 0x1C, 0xC0, 0x39, 0xC0, 0xD7,
        0x65, 0x12, 0x8A, 0x66, 0x5D, 0xAB, 0x69, 0x24,
        0x38, 0x99, 0xBF, 0x73, 0x18, 0xCC, 0xDC, 0x81,
        0xC9, 0x93, 0x1D, 0xA1, 0x7F, 0xBE, 0x8E, 0xDD,
        0x7D, 0x17, 0xCB, 0x8B, 0x4C, 0x26, 0xFC, 0x81,
        0xE3, 0x28, 0x4F, 0x2B, 0x7F, 0xBA, 0x71, 0x3D
};
static uint8_t T1[] = {
        0x4F, 0x8D, 0x55, 0xE7, 0xD3, 0xF0, 0x6F, 0xD5,
        0xA1, 0x3C, 0x0C, 0x29, 0xB9, 0xD5, 0xB8, 0x80
};

/*
 * 54-Byte Packet Encryption Using GCM-AES-128
 *    http://www.ieee802.org/1/files/public/
 *        docs2011/bn-randall-test-vectors-0511-v1.pdf
 *
 * K:   071B113B0CA743FECCCF3D051F737382
 * IV:  F0761E8DCD3D000176D457ED
 * AAD: E20106D7CD0DF0761E8DCD3D88E54C2A
 *      76D457ED
 * P:   08000F101112131415161718191A1B1C
 *      1D1E1F202122232425262728292A2B2C
 *      2D2E2F30313233340004
 * C:   13B4C72B389DC5018E72A171DD85A5D3
 *      752274D3A019FBCAED09A425CD9B2E1C
 *      9B72EEE7C9DE7D52B3F3
 * AT:  D6A5284F4A6D3FE22A5D6C2B960494C3
 * H:   E4E01725D724C1215C7309AD34539257
 */
static uint8_t K2[] = {
        0x07, 0x1B, 0x11, 0x3B, 0x0C, 0xA7, 0x43, 0xFE,
        0xCC, 0xCF, 0x3D, 0x05, 0x1F, 0x73, 0x73, 0x82
};
static uint8_t P2[] = {
        0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
	0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
	0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x00, 0x04
};
static uint8_t IV2[] = {
        0xF0, 0x76, 0x1E, 0x8D, 0xCD, 0x3D, 0x00, 0x01,
        0x76, 0xD4, 0x57, 0xED
};
/* static uint8_t IV1p[] = {0, 0, 0, 1}; */
static uint8_t A2[] = {
        0xE2, 0x01, 0x06, 0xD7, 0xCD, 0x0D, 0xF0, 0x76,
        0x1E, 0x8D, 0xCD, 0x3D, 0x88, 0xE5, 0x4C, 0x2A,
        0x76, 0xD4, 0x57, 0xED
};
#define A2_len sizeof(A2)
static uint8_t C2[] = {
        0x13, 0xB4, 0xC7, 0x2B, 0x38, 0x9D, 0xC5, 0x01,
        0x8E, 0x72, 0xA1, 0x71, 0xDD, 0x85, 0xA5, 0xD3,
	0x75, 0x22, 0x74, 0xD3, 0xA0, 0x19, 0xFB, 0xCA,
        0xED, 0x09, 0xA4, 0x25, 0xCD, 0x9B, 0x2E, 0x1C,
	0x9B, 0x72, 0xEE, 0xE7, 0xC9, 0xDE, 0x7D, 0x52,
        0xB3, 0xF3
};
static uint8_t T2[] = {
        0xD6, 0xA5, 0x28, 0x4F, 0x4A, 0x6D, 0x3F, 0xE2,
        0x2A, 0x5D, 0x6C, 0x2B, 0x96, 0x04, 0x94, 0xC3
};

/*
 * http://csrc.nist.gov/groups/STM/cavp/gcmtestvectors.zip
 *    gcmEncryptExtIV128.rsp
 *
 * [Keylen = 128]
 * [IVlen = 96]
 * [PTlen = 128]
 * [AADlen = 128]
 * [Taglen = 128]
 * Count = 0
 * K:   c939cc13397c1d37de6ae0e1cb7c423c
 * IV:  b3d8cc017cbb89b39e0f67e2
 * P:   c3b3c41f113a31b73d9a5cd432103069
 * AAD: 24825602bd12a984e0092d3e448eda5f
 * C:   93fe7d9e9bfd10348a5606e5cafa7354
 * AT:  0032a1dc85f1c9786925a2e71d8272dd
 */
static uint8_t K3[] = {
        0xc9, 0x39, 0xcc, 0x13, 0x39, 0x7c, 0x1d, 0x37,
        0xde, 0x6a, 0xe0, 0xe1, 0xcb, 0x7c, 0x42, 0x3c
};
static uint8_t IV3[] = {
        0xb3, 0xd8, 0xcc, 0x01, 0x7c, 0xbb, 0x89, 0xb3,
        0x9e, 0x0f, 0x67, 0xe2
};
static uint8_t P3[] = {
        0xc3, 0xb3, 0xc4, 0x1f, 0x11, 0x3a, 0x31, 0xb7,
        0x3d, 0x9a, 0x5c, 0xd4, 0x32, 0x10, 0x30, 0x69
};
static uint8_t A3[] = {
        0x24, 0x82, 0x56, 0x02, 0xbd, 0x12, 0xa9, 0x84,
        0xe0, 0x09, 0x2d, 0x3e, 0x44, 0x8e, 0xda, 0x5f
};
#define A3_len sizeof(A3)
static uint8_t C3[] = {
        0x93, 0xfe, 0x7d, 0x9e, 0x9b, 0xfd, 0x10, 0x34,
        0x8a, 0x56, 0x06, 0xe5, 0xca, 0xfa, 0x73, 0x54
};
static uint8_t T3[] = {
        0x00, 0x32, 0xa1, 0xdc, 0x85, 0xf1, 0xc9, 0x78,
        0x69, 0x25, 0xa2, 0xe7, 0x1d, 0x82, 0x72, 0xdd
};

/*
 * http://csrc.nist.gov/groups/STM/cavp/gcmtestvectors.zip
 *    gcmEncryptExtIV128.rsp
 *
 * [Keylen = 128]
 * [IVlen = 96]
 * [PTlen = 256]
 * [AADlen = 128]
 * [Taglen = 128]
 * Count = 0
 * K = 298efa1ccf29cf62ae6824bfc19557fc
 * IV = 6f58a93fe1d207fae4ed2f6d
 * P = cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac63872daf16b93901
 * AAD = 021fafd238463973ffe80256e5b1c6b1
 * C = dfce4e9cd291103d7fe4e63351d9e79d3dfd391e3267104658212da96521b7db
 * T = 542465ef599316f73a7a560509a2d9f2
 */
static uint8_t K4[] = {
        0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62,
        0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95, 0x57, 0xfc
};
static uint8_t IV4[] = {
        0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa,
        0xe4, 0xed, 0x2f, 0x6d
};
static uint8_t P4[] = {
        0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad,
        0x91, 0x9b, 0x13, 0x95, 0xf5, 0xd6, 0x38, 0x01,
        0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac,
        0x63, 0x87, 0x2d, 0xaf, 0x16, 0xb9, 0x39, 0x01
};
static uint8_t A4[] = {
        0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73,
        0xff, 0xe8, 0x02, 0x56, 0xe5, 0xb1, 0xc6, 0xb1
};
#define A4_len sizeof(A4)
static uint8_t C4[] = {
        0xdf, 0xce, 0x4e, 0x9c, 0xd2, 0x91, 0x10, 0x3d,
        0x7f, 0xe4, 0xe6, 0x33, 0x51, 0xd9, 0xe7, 0x9d,
        0x3d, 0xfd, 0x39, 0x1e, 0x32, 0x67, 0x10, 0x46,
        0x58, 0x21, 0x2d, 0xa9, 0x65, 0x21, 0xb7, 0xdb
};
static uint8_t T4[] = {
        0x54, 0x24, 0x65, 0xef, 0x59, 0x93, 0x16, 0xf7,
        0x3a, 0x7a, 0x56, 0x05, 0x09, 0xa2, 0xd9, 0xf2
};

/*
 * http://csrc.nist.gov/groups/STM/cavp/gcmtestvectors.zip
 *    gcmEncryptExtIV128.rsp
 *
 * [Keylen = 128]
 * [IVlen = 96]
 * [PTlen = 256]
 * [AADlen = 128]
 * [Taglen = 128]
 * Count = 0
 * K = 298efa1ccf29cf62ae6824bfc19557fc
 * IV = 6f58a93fe1d207fae4ed2f6d
 * P = cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac63872daf16b93901
 * AAD = 021fafd238463973ffe80256e5b1c6b1
 * C = dfce4e9cd291103d7fe4e63351d9e79d3dfd391e3267104658212da96521b7db
 * T = 542465ef599316f73a7a560509a2d9f2
 */
static uint8_t K5[] = {
        0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62,
        0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95, 0x57, 0xfc
};
static uint8_t IV5[] = {
        0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa,
        0xe4, 0xed, 0x2f, 0x6d
};
static uint8_t P5[] = {
        0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad,
        0x91, 0x9b, 0x13, 0x95, 0xf5, 0xd6, 0x38, 0x01,
        0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac,
        0x63, 0x87, 0x2d, 0xaf, 0x16, 0xb9, 0x39, 0x01
};
static uint8_t A5[] = {
        0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73,
        0xff, 0xe8, 0x02, 0x56, 0xe5, 0xb1, 0xc6, 0xb1
};
#define A5_len sizeof(A5)
static uint8_t C5[] = {
        0xdf, 0xce, 0x4e, 0x9c, 0xd2, 0x91, 0x10, 0x3d,
        0x7f, 0xe4, 0xe6, 0x33, 0x51, 0xd9, 0xe7, 0x9d,
        0x3d, 0xfd, 0x39, 0x1e, 0x32, 0x67, 0x10, 0x46,
        0x58, 0x21, 0x2d, 0xa9, 0x65, 0x21, 0xb7, 0xdb
};
static uint8_t T5[] = {
        0x54, 0x24, 0x65, 0xef, 0x59, 0x93, 0x16, 0xf7,
        0x3a, 0x7a, 0x56, 0x05, 0x09, 0xa2, 0xd9, 0xf2
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/
 *    proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 2
 * K:  00000000000000000000000000000000
 * P:  00000000000000000000000000000000
 * IV: 000000000000000000000000
 * C:  0388dace60b6a392f328c2b971b2fe78
 * T:  ab6e47d42cec13bdf53a67b21257bddf
 * H:  66e94bd4ef8a2c3b884cfa59ca342b2e
 */
static uint8_t K6[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t P6[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t IV6[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};
static uint8_t A6[] = {0};
#define A6_len 0
static uint8_t C6[] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
};
static uint8_t T6[] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/
 *    documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 3
 * K:  feffe9928665731c6d6a8f9467308308
 * P:  d9313225f88406e5a55909c5aff5269a
 *     86a7a9531534f7da2e4c303d8a318a72
 *     1c3c0c95956809532fcf0e2449a6b525
 *     b16aedf5aa0de657ba637b391aafd255
 * IV: cafebabefacedbaddecaf888
 * H:  b83b533708bf535d0aa6e52980d53b78
 * C:  42831ec2217774244b7221b784d0d49c
 *     e3aa212f2c02a4e035c17e2329aca12e
 *     21d514b25466931c7d8f6a5aac84aa05
 *     1ba30b396a0aac973d58e091473f5985
 * T:  4d5c2af327cd64a62cf35abd2ba6fab4
 */
static uint8_t K7[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static uint8_t P7[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};
static uint8_t IV7[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
};
static uint8_t A7[] = {0};
#define A7_len 0
static uint8_t C7[] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
        0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
        0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
        0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
        0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85
};
static uint8_t T7[] = {
        0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
        0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/
 *    documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 4
 * K:  feffe9928665731c6d6a8f9467308308
 * P:  d9313225f88406e5a55909c5aff5269a
 *     86a7a9531534f7da2e4c303d8a318a72
 *     1c3c0c95956809532fcf0e2449a6b525
 *     b16aedf5aa0de657ba637b39
 * A:  feedfacedeadbeeffeedfacedeadbeef
 *     abaddad2
 * IV: cafebabefacedbaddecaf888
 * H:  b83b533708bf535d0aa6e52980d53b78
 * C:  42831ec2217774244b7221b784d0d49c
 *     e3aa212f2c02a4e035c17e2329aca12e
 *     21d514b25466931c7d8f6a5aac84aa05
 *     1ba30b396a0aac973d58e091
 * T:  5bc94fbc3221a5db94fae95ae7121a47
 */
static uint8_t K8[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static uint8_t P8[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
};
static uint8_t A8[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
};
#define A8_len sizeof(A8)
static uint8_t IV8[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
};
static uint8_t C8[] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
        0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
        0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
        0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
        0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85
};
static uint8_t T8[] = {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
        0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/
 *    documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 14
 * K:  00000000000000000000000000000000
 *     00000000000000000000000000000000
 * P:  00000000000000000000000000000000
 * A:
 * IV: 000000000000000000000000
 * H:  dc95c078a2408989ad48a21492842087
 * C:  cea7403d4d606b6e074ec5d3baf39d18
 * T:  d0d1c8a799996bf0265b98b5d48ab919
 */
static uint8_t K9[] = {
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};
static uint8_t P9[] =  {
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};
static uint8_t A9[] = {0};
#define A9_len 0
static uint8_t IV9[] = {
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
};
static uint8_t C9[] = {
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
};
static uint8_t T9[] = {
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/
 *    proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 15
 * K:  feffe9928665731c6d6a8f9467308308
 *     feffe9928665731c6d6a8f9467308308
 * P:  d9313225f88406e5a55909c5aff5269a
 *     86a7a9531534f7da2e4c303d8a318a72
 *     1c3c0c95956809532fcf0e2449a6b525
 *     b16aedf5aa0de657ba637b391aafd255
 * A:
 * IV: cafebabefacedbaddecaf888
 * H:  acbef20579b4b8ebce889bac8732dad7
 * C:  522dc1f099567d07f47f37a32a84427d
 *     643a8cdcbfe5c0c97598a2bd2555d1aa
 *     8cb08e48590dbb3da7b08b1056828838
 *     c5f61e6393ba7a0abcc9f662898015ad
 * T:  b094dac5d93471bdec1a502270e3cc6c
 */
static uint8_t K10[] =  {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static uint8_t P10[] =  {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};
static uint8_t A10[] =  {0};
#define A10_len 0
static uint8_t IV10[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
};
static uint8_t C10[] = {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad
};
static uint8_t T10[] = {
        0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
        0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/
 *    proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 16
 * K:  feffe9928665731c6d6a8f9467308308
 *     feffe9928665731c6d6a8f9467308308
 * P:  d9313225f88406e5a55909c5aff5269a
 *     86a7a9531534f7da2e4c303d8a318a72
 *     1c3c0c95956809532fcf0e2449a6b525
 *     b16aedf5aa0de657ba637b39
 * A:  feedfacedeadbeeffeedfacedeadbeef
 *     abaddad2
 * IV: cafebabefacedbaddecaf888
 * H:  acbef20579b4b8ebce889bac8732dad7
 * C:  522dc1f099567d07f47f37a32a84427d
 *     643a8cdcbfe5c0c97598a2bd2555d1aa
 *     8cb08e48590dbb3da7b08b1056828838
 *     c5f61e6393ba7a0abcc9f662
 * T:  76fc6ece0f4e1768cddf8853bb2d551b
 */
static uint8_t K11[] =  {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static uint8_t P11[] =  {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
};
static uint8_t A11[] =  {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
};
#define A11_len sizeof(A11)
static uint8_t IV11[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
};
static uint8_t C11[] =  {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
};
static uint8_t T11[] = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/
 *    proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 18 -- Not supported IV length greater than 12 bytes
 * K:  feffe9928665731c6d6a8f9467308308
 *     feffe9928665731c6d6a8f9467308308
 * P:  d9313225f88406e5a55909c5aff5269a
 *     86a7a9531534f7da2e4c303d8a318a72
 *     1c3c0c95956809532fcf0e2449a6b525
 *     b16aedf5aa0de657ba637b39
 * A:  feedfacedeadbeeffeedfacedeadbeef
 *     abaddad2
 * IV: 9313225df88406e555909c5aff5269aa
 *     6a7a9538534f7da1e4c303d2a318a728
 *     c3c0c95156809539fcf0e2429a6b5254
 *     16aedbf5a0de6a57a637b39b
 * H:  acbef20579b4b8ebce889bac8732dad7
 * C:  5a8def2f0c9e53f1f75d7853659e2a20
 *     eeb2b22aafde6419a058ab4f6f746bf4
 *     0fc0c3b780f244452da3ebf1c5d82cde
 *     a2418997200ef82e44ae7e3f
 * T:  a44a8266ee1c8eb0c8b5d4cf5ae9f19a
 */

/*
 * https://tools.ietf.org/html/draft-mcgrew-gcm-test-01
 * case #7
 */
/********************************************************
           key = feffe9928665731c6d6a8f9467308308
                 feffe9928665731c
                 (24 octets)
           spi = 0000a5f8
           seq = 0000000a
                 (4 octets)
         nonce = cafebabefacedbaddecaf888
     plaintext = 45000028a4ad4000400678800a01038f
                 0a010612802306b8cb712602dd6bb03e
                 501016d075680001
                 (40 octets)
           aad = 0000a5f80000000a
                 (8 octets)
     ctext+tag = a5b1f8066029aea40e598b8122de0242
                 0938b3ab33f828e687b8858b5bfbdbd0
                 315b27452144cc7795457b9652037f53
                 18027b5b4cd7a636
                 (56 octets)
********************************************************/
static uint8_t K13[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
};
static uint8_t IV13[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
};
static uint8_t A13[] = {
        0x00, 0x00, 0xa5, 0xf8, 0x00, 0x00, 0x00, 0x0a,
};
#define A13_len sizeof(A13)
static uint8_t P13[] = {
        0x45, 0x00, 0x00, 0x28, 0xa4, 0xad, 0x40, 0x00,
        0x40, 0x06, 0x78, 0x80, 0x0a, 0x01, 0x03, 0x8f,
        0x0a, 0x01, 0x06, 0x12, 0x80, 0x23, 0x06, 0xb8,
        0xcb, 0x71, 0x26, 0x02, 0xdd, 0x6b, 0xb0, 0x3e,
        0x50, 0x10, 0x16, 0xd0, 0x75, 0x68, 0x00, 0x01,
};
static uint8_t T13[] = {
        0x95, 0x45, 0x7b, 0x96, 0x52, 0x03, 0x7f, 0x53,
        0x18, 0x02, 0x7b, 0x5b, 0x4c, 0xd7, 0xa6, 0x36,
};
static uint8_t C13[] = {
        0xa5, 0xb1, 0xf8, 0x06, 0x60, 0x29, 0xae, 0xa4,
        0x0e, 0x59, 0x8b, 0x81, 0x22, 0xde, 0x02, 0x42,
        0x09, 0x38, 0xb3, 0xab, 0x33, 0xf8, 0x28, 0xe6,
        0x87, 0xb8, 0x85, 0x8b, 0x5b, 0xfb, 0xdb, 0xd0,
        0x31, 0x5b, 0x27, 0x45, 0x21, 0x44, 0xcc, 0x77,
};

/*
 * Test Case 14 -- GHASH output Auth Tag length of 4 bytes
 */
#define K14     K11
#define P14     P11
#define A14     A11
#define A14_len sizeof(A14)
#define IV14    IV11
#define C14     C11
static uint8_t T14[] = {
        0x76, 0xfc, 0x6e, 0xce
};

/*
 * Test Case 15 -- GHASH output Auth Tag length of 8 bytes
 */
#define K15     K11
#define P15     P11
#define A15     A11
#define A15_len sizeof(A15)
#define IV15    IV11
#define C15     C11
static uint8_t  T15[] = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68
};

/*
 * Test Case 16 -- GHASH output Auth Tag length of 14 bytes
 */
#define K16     K11
#define P16     P11
#define A16     A11
#define A16_len sizeof(A16)
#define IV16    IV11
#define C16     C11
static uint8_t  T16[] = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d
};

/*
 * Test Case 17 -- GHASH output Auth Tag length of 15 bytes
 */
#define K17     K11
#define P17     P11
#define A17     A11
#define A17_len sizeof(A17)
#define IV17    IV11
#define C17     C11
static uint8_t  T17[] = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55
};

/*
 * Test Case 18 -- No plaintext
 */
static uint8_t K18[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static uint8_t IV18[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
};
static uint8_t A18[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

#define P18 NULL
#define C18 NULL
#define P18_len 0
#define A18_len sizeof(A18)

static uint8_t T18[] = {
        0x8D, 0xF7, 0xD8, 0xED, 0xB9, 0x91, 0x65, 0xFA,
        0xAD, 0x1B, 0x03, 0x8C, 0x53, 0xB3, 0x20, 0xE8
};

/*
 * Test Case 19 -- No AAD
 */
static uint8_t P19[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static uint8_t C19[] = {
        0x93, 0x6D, 0xA5, 0xCD, 0x62, 0x1E, 0xF1, 0x53,
        0x43, 0xDB, 0x6B, 0x81, 0x3A, 0xAE, 0x7E, 0x07
};

#define K19 K18
#define IV19 IV18
#define P19_len sizeof(P19)
#define A19 NULL
#define A19_len 0

static uint8_t T19[] = {
        0xFE, 0x8E, 0xC5, 0x55, 0x5F, 0x36, 0x08, 0xF7,
        0x0E, 0xBC, 0x7F, 0xCE, 0xE9, 0x59, 0x2E, 0x9B
};

/*
 * Test Case 20 -- No plaintext, no AAD
 */
#define K20 K18
#define IV20 IV18
#define P20 NULL
#define C20 NULL
#define P20_len 0
#define A20 NULL
#define A20_len 0

static uint8_t T20[] = {
        0x43, 0x5B, 0x9B, 0xA1, 0x2D, 0x75, 0xA4, 0xBE,
        0x8A, 0x97, 0x7E, 0xA3, 0xCD, 0x01, 0x18, 0x90
};

/*
 * Test Case 21 -- Variable tag size (1 byte)
 */

#define K21 K1
#define IV21 IV1
#define P21 P1
#define C21 C1
#define A21 A1
#define A21_len A1_len

static uint8_t T21[] = {
        0x4F
};

/*
 * Test Case 22 -- No plaintext
 */
static uint8_t K22[] = {
        0x76, 0x80, 0xc5, 0xd3, 0xca, 0x61, 0x54, 0x75,
        0x8e, 0x51, 0x0f, 0x4d, 0x25, 0xb9, 0x88, 0x20
};

static uint8_t IV22[] = {
        0xf8, 0xf1, 0x05, 0xf9, 0xc3, 0xdf, 0x49, 0x65,
        0x78, 0x03, 0x21, 0xf8
};

static uint8_t A22[] = {
        0xc9, 0x4c, 0x41, 0x01, 0x94, 0xc7, 0x65, 0xe3,
        0xdc, 0xc7, 0x96, 0x43, 0x79, 0x75, 0x8e, 0xd3
};

#define A22_len sizeof(A22)
#define P22 NULL
#define C22 NULL
#define P22_len 0

static uint8_t T22[] = {
        0x94, 0xdc, 0xa8, 0xed, 0xfc, 0xf9, 0x0b, 0xb7,
        0x4b, 0x15, 0x3c, 0x8d, 0x48, 0xa1, 0x79, 0x30
};

/* GHASH vectors */
static uint8_t K23[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t P23[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static uint8_t T23[] = {
        0x9E, 0xE5, 0xA5, 0x1F, 0xBE, 0x28, 0xA1, 0x15,
        0x3E, 0xF1, 0x96, 0xF5, 0x0B, 0xBF, 0x03, 0xCA
};

static uint8_t K24[] = {
        0xA1, 0xF6, 0x25, 0x8C, 0x87, 0x7D, 0x5F, 0xCD,
        0x89, 0x64, 0x48, 0x45, 0x38, 0xBF, 0xC9, 0x2C
};

static uint8_t P24[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

static uint8_t T24[] = {
        0xB5, 0x40, 0xDA, 0x44, 0xA3, 0x8C, 0x9C, 0x2B,
        0x95, 0x8E, 0x4B, 0x0B
};

static uint8_t K25[] = {
        0xA1, 0xF6, 0x25, 0x8C, 0x87, 0x7D, 0x5F, 0xCD,
        0x89, 0x64, 0x48, 0x45, 0x38, 0xBF, 0xC9, 0x2C
};

static uint8_t P25[] = {
        0x05
};

static uint8_t T25[] = {
        0xE6, 0xCE, 0x47, 0xB5, 0xFB, 0xF2, 0xEF, 0x37,
        0x51, 0xF1, 0x57, 0x53, 0xAD, 0x56, 0x4F, 0xED
};

/* GCM vectors with IV different than 12 bytes */

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/
 *    proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * Test Case 17  -- Not supported IV length less than 12 bytes
 * K:  feffe9928665731c6d6a8f9467308308
 *     feffe9928665731c6d6a8f9467308308
 * P:  d9313225f88406e5a55909c5aff5269a
 *     86a7a9531534f7da2e4c303d8a318a72
 *     1c3c0c95956809532fcf0e2449a6b525
 *     b16aedf5aa0de657ba637b39
 * A:  feedfacedeadbeeffeedfacedeadbeef
 *     abaddad2
 * IV: cafebabefacedbad
 * H:  acbef20579b4b8ebce889bac8732dad7
 * C:  c3762df1ca787d32ae47c13bf19844cb
 *     af1ae14d0b976afac52ff7d79bba9de0
 *     feb582d33934a4f0954cc2363bc73f78
 *     62ac430e64abe499f47c9b1f
 * T:  3a337dbf46a792c45e454913fe2ea8f2
 */
static uint8_t K12[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static uint8_t P12[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
};
static uint8_t A12[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
};
static uint8_t IV12[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad
};
static uint8_t C12[] =  {
        0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32,
        0xae, 0x47, 0xc1, 0x3b, 0xf1, 0x98, 0x44, 0xcb,
        0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa,
        0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba, 0x9d, 0xe0,
        0xfe, 0xb5, 0x82, 0xd3, 0x39, 0x34, 0xa4, 0xf0,
        0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78,
        0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99,
        0xf4, 0x7c, 0x9b, 0x1f
};
static uint8_t T12[] =  {
        0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4,
        0x5e, 0x45, 0x49, 0x13, 0xfe, 0x2e, 0xa8, 0xf2
};
#define A12_len sizeof(A12)

static uint8_t K26[] = {
        0x83, 0xf9, 0xd9, 0x7d, 0x4a, 0xb7, 0x59, 0xfd,
        0xdc, 0xc3, 0xef, 0x54, 0xa0, 0xe2, 0xa8, 0xec
};
static uint8_t P26[] = {
        0x77, 0xe6, 0x32, 0x9c, 0xf9, 0x42, 0x4f, 0x71,
        0xc8, 0x08, 0xdf, 0x91, 0x70, 0xbf, 0xd2, 0x98
};
static uint8_t A26[] = {
        0x6d, 0xd4, 0x9e, 0xae, 0xb4, 0x10, 0x3d, 0xac,
        0x8f, 0x97, 0xe3, 0x23, 0x49, 0x46, 0xdd, 0x2d
};
static uint8_t IV26[] = {
        0xcf
};
static uint8_t C26[] =  {
        0x50, 0xde, 0x86, 0xa7, 0xa9, 0x2a, 0x8a, 0x5e,
        0xa3, 0x3d, 0xb5, 0x69, 0x6b, 0x96, 0xcd, 0x77
};
static uint8_t T26[] =  {
        0xaa, 0x18, 0x1e, 0x84, 0xbc, 0x8b, 0x4b, 0xf5,
        0xa6, 0x89, 0x27, 0xc4, 0x09, 0xd4, 0x22, 0xcb
};
#define A26_len sizeof(A26)

static uint8_t K27[] = {
        0x8b, 0x1c, 0x63, 0xbc, 0xcb, 0x55, 0x79, 0xe5,
        0x88, 0x7f, 0x5b, 0xf7, 0xb2, 0xbd, 0x0c, 0xbc,
        0xff, 0x13, 0x6d, 0x40, 0xd7, 0xb6, 0x1a, 0xb2
};
static uint8_t P27[] = {
        0x22, 0x4f, 0x5f, 0x2a, 0x23, 0x7b, 0x30, 0x7c,
        0x78, 0x42, 0xde, 0x75, 0xd9, 0xd1, 0xbb, 0x65
};
static uint8_t A27[] = {
        0x8f, 0xbe, 0x5a, 0x21, 0xa6, 0x5b, 0xdd, 0xd0,
        0x33, 0x16, 0x04, 0xc9, 0x17, 0x83, 0x9c, 0xf7
};
static uint8_t IV27[] = {
        0xca
};
static uint8_t C27[] =  {
        0x83, 0x49, 0xe3, 0xa4, 0x8f, 0x5d, 0x89, 0xd9,
        0x42, 0xc2, 0x4d, 0x80, 0xae, 0xfb, 0x1c, 0x5f
};
static uint8_t T27[] =  {
        0x3d, 0x49, 0xe3, 0xd4, 0x3f, 0x9a, 0x4a, 0x96,
        0x4c, 0x6d, 0x84, 0x4d, 0x60, 0xb4, 0xef, 0x1e
};
#define A27_len sizeof(A27)

static uint8_t K28[] = {
        0x0e, 0x00, 0xc7, 0x65, 0x61, 0xd2, 0xbd, 0x9b,
        0x40, 0xc3, 0xc1, 0x54, 0x27, 0xe2, 0xb0, 0x8f
};
static uint8_t P28[] = {
        0xfe, 0xf0, 0x3c, 0x2d, 0x7f, 0xb1, 0x5b, 0xf0,
        0xd2, 0xdf, 0x18, 0x00, 0x7d, 0x99, 0xf9, 0x67,
        0xc8, 0x78, 0xad, 0x59, 0x35, 0x90, 0x34, 0xf7,
        0xbb, 0x2c, 0x19, 0xaf, 0x12, 0x06, 0x85, 0xd7,
        0x8e, 0x32, 0xf6, 0xb8, 0xb8, 0x3b, 0x03, 0x20,
        0x19, 0x95, 0x6c, 0xa9, 0xc0, 0x19, 0x57, 0x21,
        0x47, 0x6b, 0x85
};
static uint8_t A28[] = {
        0xd8, 0xf1, 0x16, 0x3d, 0x8c, 0x84, 0x02, 0x92,
        0xa2, 0xb2, 0xda, 0xcf, 0x4a, 0xc7, 0xc3, 0x6a,
        0xff, 0x87, 0x33, 0xf1, 0x8f, 0xab, 0xb4, 0xfa,
        0x55, 0x94, 0x54, 0x41, 0x25, 0xe0, 0x3d, 0x1e,
        0x6e, 0x5d, 0x6d, 0x0f, 0xd6, 0x16, 0x56, 0xc8,
        0xd8, 0xf3, 0x27, 0xc9, 0x28, 0x39, 0xae, 0x55,
        0x39, 0xbb, 0x46, 0x9c, 0x92, 0x57, 0xf1, 0x09,
        0xeb, 0xff, 0x85, 0xaa, 0xd7, 0xbd, 0x22, 0x0f,
        0xda, 0xa9, 0x5c, 0x02, 0x2d, 0xbd, 0x0c, 0x7b,
        0xb2, 0xd8, 0x78, 0xad, 0x50, 0x41, 0x22, 0xc9,
        0x43, 0x04, 0x5d, 0x3c, 0x5e, 0xba, 0x8f, 0x1f,
        0x56, 0xc0
};
static uint8_t IV28[] = {
        0x49, 0x2c, 0xad, 0xac, 0xcd, 0x3c, 0xa3, 0xfb,
        0xc9, 0xcf, 0x9f, 0x06, 0xeb, 0x33, 0x25, 0xc4,
        0xe1, 0x59, 0x85, 0x0b, 0x0d, 0xbe, 0x98, 0x19,
        0x9b, 0x89, 0xb7, 0xaf, 0x52, 0x88, 0x06, 0x61,
        0x0b, 0x6f, 0x63, 0x99, 0x8e, 0x1e, 0xae, 0x80,
        0xc3, 0x48, 0xe7, 0x4c, 0xbb, 0x92, 0x1d, 0x83,
        0x26, 0x63, 0x16, 0x31, 0xfc, 0x6a, 0x5d, 0x30,
        0x4f, 0x39, 0x16, 0x6d, 0xaf, 0x7e, 0xa1, 0x5f,
        0xa1, 0x97, 0x7f, 0x10, 0x18, 0x19, 0xad, 0xb5,
        0x10, 0xb5, 0x0f, 0xe9, 0x93, 0x2e, 0x12, 0xc5,
        0xa8, 0x5a, 0xa3, 0xfd, 0x1e, 0x73, 0xd8, 0xd7,
        0x60, 0xaf, 0x21, 0x8b, 0xe8, 0x29, 0x90, 0x3a,
        0x77, 0xc6, 0x33, 0x59, 0xd7, 0x5e, 0xdd, 0x91,
        0xb4, 0xf6, 0xed, 0x54, 0x65, 0xa7, 0x26, 0x62,
        0xf5, 0x05, 0x59, 0x99, 0xe0, 0x59, 0xe7, 0x65,
        0x4a, 0x8e, 0xdc, 0x92, 0x1a, 0xa0, 0xd4, 0x96
};
static uint8_t C28[] =  {
        0x4f, 0x6c, 0xf4, 0x71, 0xbe, 0x7c, 0xbd, 0x25,
        0x75, 0xcd, 0x5a, 0x17, 0x47, 0xae, 0xa8, 0xfe,
        0x9d, 0xea, 0x83, 0xe5, 0x19, 0x36, 0xbe, 0xac,
        0x3e, 0x68, 0xf6, 0x62, 0x06, 0x92, 0x20, 0x60,
        0xc6, 0x97, 0xff, 0xa7, 0xaf, 0x80, 0xad, 0x6b,
        0xb6, 0x8f, 0x2c, 0xf4, 0xfc, 0x97, 0x41, 0x6e,
        0xe5, 0x2a, 0xbe
};
static uint8_t T28[] =  {
        0xe2, 0x0b, 0x66, 0x55
};
#define A28_len sizeof(A28)

static const struct gcm_ctr_vector gcm_vectors[] = {
	/*
         * field order {K, Klen, IV, IVlen, A, Alen, P, Plen, C, T, Tlen};
         * original vector does not have a valid sub hash key
         */
	vector(1),
	vector(2),
	vector(3),
	vector(4),
	vector(5),
	vector(6),
	vector(7),
	vector(8),
	vector(9),
	vector(10),
	vector(11),
	vector(12),
        vector(13),
        vector(14),
        vector(15),
        vector(16),
        vector(17),
        extra_vector(18),
        extra_vector(19),
        extra_vector(20),
        vector(21),
        extra_vector(22),
	vector(26),
	vector(27),
	vector(28)
};

static const struct gcm_ctr_vector ghash_vectors[] = {
        ghash_vector(23),
        ghash_vector(24),
        ghash_vector(25)
};

typedef void (*gcm_enc_dec_fn_t)(const struct gcm_key_data *,
                                 struct gcm_context_data *,
                                 uint8_t *, const uint8_t *, uint64_t,
                                 const uint8_t *, const uint64_t,
                                 const uint8_t *, uint64_t,
                                 uint8_t *, uint64_t);

static IMB_MGR *p_gcm_mgr = NULL;

static int check_data(const uint8_t *test, const uint8_t *expected,
                      uint64_t len, const char *data_name)
{
	int mismatch;
	int is_error = 0;

	mismatch = memcmp(test, expected, len);
	if (mismatch) {
                uint64_t a;

		is_error = 1;
		printf("  expected results don't match %s \t\t", data_name);
                for (a = 0; a < len; a++) {
                        if (test[a] != expected[a]) {
                                printf(" '%x' != '%x' at %llx of %llx\n",
                                       test[a], expected[a],
                                       (unsigned long long) a,
                                       (unsigned long long) len);
                                break;
                        }
                }
	}
	return is_error;
}

/*****************************************************************************
 * RAW API
 *****************************************************************************/
static void
aes_gcm_enc_128(const struct gcm_key_data *key,
                struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len,
                const uint8_t *iv, const uint64_t iv_len,
                const uint8_t *aad, uint64_t aad_len,
                uint8_t *auth_tag, uint64_t auth_tag_len)
{
        if (iv_len == 12) {
                IMB_AES128_GCM_ENC(p_gcm_mgr, key, ctx, out, in, len, iv,
                                   aad, aad_len, auth_tag, auth_tag_len);
        } else {
                IMB_AES128_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                           aad, aad_len);
                IMB_AES128_GCM_ENC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
                IMB_AES128_GCM_ENC_FINALIZE(p_gcm_mgr, key, ctx,
                                            auth_tag, auth_tag_len);
        }
}

static void
aes_gcm_dec_128(const struct gcm_key_data *key,
                struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len,
                const uint8_t *iv, const uint64_t iv_len,
                const uint8_t *aad, uint64_t aad_len,
                uint8_t *auth_tag, uint64_t auth_tag_len)
{
        if (iv_len == 12) {
                IMB_AES128_GCM_DEC(p_gcm_mgr, key, ctx, out, in, len, iv,
                                   aad, aad_len, auth_tag, auth_tag_len);
        } else {
                IMB_AES128_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                           aad, aad_len);
                IMB_AES128_GCM_DEC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
                IMB_AES128_GCM_DEC_FINALIZE(p_gcm_mgr, key, ctx,
                                            auth_tag, auth_tag_len);
        }
}

static void
aes_gcm_enc_192(const struct gcm_key_data *key,
                struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len,
                const uint8_t *iv, const uint64_t iv_len,
                const uint8_t *aad, uint64_t aad_len,
                uint8_t *auth_tag, uint64_t auth_tag_len)
{
        if (iv_len == 12) {
                IMB_AES192_GCM_ENC(p_gcm_mgr, key, ctx, out, in, len, iv,
                                   aad, aad_len, auth_tag, auth_tag_len);
        } else {
                IMB_AES192_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                           aad, aad_len);
                IMB_AES192_GCM_ENC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
                IMB_AES192_GCM_ENC_FINALIZE(p_gcm_mgr, key, ctx,
                                            auth_tag, auth_tag_len);
        }
}

static void
aes_gcm_dec_192(const struct gcm_key_data *key,
                struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len,
                const uint8_t *iv, const uint64_t iv_len,
                const uint8_t *aad, uint64_t aad_len,
                uint8_t *auth_tag, uint64_t auth_tag_len)
{
        if (iv_len == 12) {
                IMB_AES192_GCM_DEC(p_gcm_mgr, key, ctx, out, in, len, iv,
                                   aad, aad_len, auth_tag, auth_tag_len);
        } else {
                IMB_AES192_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                           aad, aad_len);
                IMB_AES192_GCM_DEC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
                IMB_AES192_GCM_DEC_FINALIZE(p_gcm_mgr, key, ctx,
                                            auth_tag, auth_tag_len);
        }
}

static void
aes_gcm_enc_256(const struct gcm_key_data *key,
                struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len,
                const uint8_t *iv, const uint64_t iv_len,
                const uint8_t *aad, uint64_t aad_len,
                uint8_t *auth_tag, uint64_t auth_tag_len)
{
        if (iv_len == 12) {
                IMB_AES256_GCM_ENC(p_gcm_mgr, key, ctx, out, in, len, iv,
                                   aad, aad_len, auth_tag, auth_tag_len);
        } else {
                IMB_AES256_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                           aad, aad_len);
                IMB_AES256_GCM_ENC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
                IMB_AES256_GCM_ENC_FINALIZE(p_gcm_mgr, key, ctx,
                                            auth_tag, auth_tag_len);
        }
}

static void
aes_gcm_dec_256(const struct gcm_key_data *key,
                struct gcm_context_data *ctx,
                uint8_t *out, const uint8_t *in, uint64_t len,
                const uint8_t *iv, const uint64_t iv_len,
                const uint8_t *aad, uint64_t aad_len,
                uint8_t *auth_tag, uint64_t auth_tag_len)
{
        if (iv_len == 12) {
                IMB_AES256_GCM_DEC(p_gcm_mgr, key, ctx, out, in, len, iv,
                                   aad, aad_len, auth_tag, auth_tag_len);
        } else {
                IMB_AES256_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                           aad, aad_len);
                IMB_AES256_GCM_DEC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
                IMB_AES256_GCM_DEC_FINALIZE(p_gcm_mgr, key, ctx,
                                            auth_tag, auth_tag_len);
        }
}

/*****************************************************************************
 * RAW SGL API
 *****************************************************************************/
static void
sgl_aes_gcm_enc_128(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        IMB_AES128_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                   aad, aad_len);
        IMB_AES128_GCM_ENC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
        IMB_AES128_GCM_ENC_FINALIZE(p_gcm_mgr, key, ctx,
                                    auth_tag, auth_tag_len);
}

static void
sgl_aes_gcm_dec_128(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        IMB_AES128_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                   aad, aad_len);
        IMB_AES128_GCM_DEC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
        IMB_AES128_GCM_DEC_FINALIZE(p_gcm_mgr, key, ctx,
                                    auth_tag, auth_tag_len);
}

static void
sgl_aes_gcm_enc_192(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        IMB_AES192_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                   aad, aad_len);
        IMB_AES192_GCM_ENC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
        IMB_AES192_GCM_ENC_FINALIZE(p_gcm_mgr, key, ctx,
                                    auth_tag, auth_tag_len);
}

static void
sgl_aes_gcm_dec_192(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        IMB_AES192_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                   aad, aad_len);
        IMB_AES192_GCM_DEC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
        IMB_AES192_GCM_DEC_FINALIZE(p_gcm_mgr, key, ctx,
                                    auth_tag, auth_tag_len);
}

static void
sgl_aes_gcm_enc_256(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        IMB_AES256_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                   aad, aad_len);
        IMB_AES256_GCM_ENC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
        IMB_AES256_GCM_ENC_FINALIZE(p_gcm_mgr, key, ctx,
                                    auth_tag, auth_tag_len);
}

static void
sgl_aes_gcm_dec_256(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        IMB_AES256_GCM_INIT_VAR_IV(p_gcm_mgr, key, ctx, iv, iv_len,
                                   aad, aad_len);
        IMB_AES256_GCM_DEC_UPDATE(p_gcm_mgr, key, ctx, out, in, len);
        IMB_AES256_GCM_DEC_FINALIZE(p_gcm_mgr, key, ctx,
                                    auth_tag, auth_tag_len);
}

/*****************************************************************************
 * job API
 *****************************************************************************/
static void
aes_gcm_job(IMB_MGR *mb_mgr,
            JOB_CHAIN_ORDER order,
            const struct gcm_key_data *key,
            uint64_t key_len,
            uint8_t *out, const uint8_t *in, uint64_t len,
            const uint8_t *iv, const uint64_t iv_len, const uint8_t *aad,
            uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        IMB_JOB *job;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        if (!job) {
                fprintf(stderr, "failed to get job\n");
                return;
        }

        job->cipher_mode                      = IMB_CIPHER_GCM;
        job->hash_alg                         = IMB_AUTH_AES_GMAC;
        job->chain_order                      = order;
        job->enc_keys             = key;
        job->dec_keys             = key;
        job->key_len_in_bytes             = key_len;
        job->src                              = in;
        job->dst                              = out;
        job->msg_len_to_cipher_in_bytes       = len;
        job->cipher_start_src_offset_in_bytes = UINT64_C(0);
        job->iv                               = iv;
        job->iv_len_in_bytes                  = iv_len;
        job->u.GCM.aad                        = aad;
        job->u.GCM.aad_len_in_bytes           = aad_len;
        job->auth_tag_output                  = auth_tag;
        job->auth_tag_output_len_in_bytes     = auth_tag_len;
        job->cipher_direction                 =
                (order == IMB_ORDER_CIPHER_HASH) ? IMB_DIR_ENCRYPT :
                                                   IMB_DIR_DECRYPT;

        job = IMB_SUBMIT_JOB(mb_mgr);
        while (job) {
                if (job->status != STS_COMPLETED)
                        fprintf(stderr, "failed job, status:%d\n", job->status);
                job = IMB_GET_COMPLETED_JOB(mb_mgr);
        }
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                if (job->status != STS_COMPLETED)
                        fprintf(stderr, "failed job, status:%d\n", job->status);
        }
}

static void
job_aes_gcm_enc_128(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        (void) ctx; /* unused */
        aes_gcm_job(p_gcm_mgr, IMB_ORDER_CIPHER_HASH, key,
                    IMB_KEY_AES_128_BYTES,
                    out, in, len,
                    iv, iv_len, aad, aad_len,
                    auth_tag, auth_tag_len);
}

static void
job_aes_gcm_dec_128(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        (void) ctx; /* unused */
        aes_gcm_job(p_gcm_mgr, IMB_ORDER_HASH_CIPHER, key,
                    IMB_KEY_AES_128_BYTES,
                    out, in, len,
                    iv, iv_len, aad, aad_len,
                    auth_tag, auth_tag_len);
}

static void
job_aes_gcm_enc_192(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        (void) ctx; /* unused */
        aes_gcm_job(p_gcm_mgr, IMB_ORDER_CIPHER_HASH, key,
                    IMB_KEY_AES_192_BYTES,
                    out, in, len,
                    iv, iv_len, aad, aad_len,
                    auth_tag, auth_tag_len);
}

static void
job_aes_gcm_dec_192(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        (void) ctx; /* unused */
        aes_gcm_job(p_gcm_mgr, IMB_ORDER_HASH_CIPHER, key,
                    IMB_KEY_AES_192_BYTES,
                    out, in, len,
                    iv, iv_len, aad, aad_len,
                    auth_tag, auth_tag_len);
}

static void
job_aes_gcm_enc_256(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        (void) ctx; /* unused */
        aes_gcm_job(p_gcm_mgr, IMB_ORDER_CIPHER_HASH, key,
                    IMB_KEY_AES_256_BYTES,
                    out, in, len,
                    iv, iv_len, aad, aad_len,
                    auth_tag, auth_tag_len);
}

static void
job_aes_gcm_dec_256(const struct gcm_key_data *key,
                    struct gcm_context_data *ctx,
                    uint8_t *out, const uint8_t *in, uint64_t len,
                    const uint8_t *iv, const uint64_t iv_len,
                    const uint8_t *aad, uint64_t aad_len,
                    uint8_t *auth_tag, uint64_t auth_tag_len)
{
        (void) ctx; /* unused */
        aes_gcm_job(p_gcm_mgr, IMB_ORDER_HASH_CIPHER, key,
                    IMB_KEY_AES_256_BYTES,
                    out, in, len,
                    iv, iv_len, aad, aad_len,
                    auth_tag, auth_tag_len);
}

/*****************************************************************************/

static int
test_gcm_vectors(struct gcm_ctr_vector const *vector,
                 gcm_enc_dec_fn_t encfn,
                 gcm_enc_dec_fn_t decfn)
{
	struct gcm_key_data gdata_key;
	struct gcm_context_data gdata_ctx;
	int is_error = 0;
	/* Temporary array for the calculated vectors */
	uint8_t *ct_test = NULL;
	uint8_t *pt_test = NULL;
	uint8_t *T_test = NULL;
	uint8_t *T2_test = NULL;
        const uint8_t *iv = vector->IV;
        uint64_t iv_len = vector->IVlen;

#ifdef DEBUG
        printf("Testing GCM128 std vectors\n");
#endif
        if (vector->Plen != 0) {
	        /* Allocate space for the calculated ciphertext */
		ct_test = malloc(vector->Plen);
		if (ct_test == NULL) {
			fprintf(stderr, "Can't allocate ciphertext memory\n");
			is_error = 1;
		        goto test_gcm_vectors_exit;
		}
	        /* Allocate space for the calculated plaintext */
		pt_test = malloc(vector->Plen);
		if (pt_test == NULL) {
			fprintf(stderr, "Can't allocate plaintext memory\n");
			is_error = 1;
		        goto test_gcm_vectors_exit;
		}
	}

	T_test = malloc(vector->Tlen);
	if (T_test == NULL) {
		fprintf(stderr, "Can't allocate tag memory\n");
		is_error = 1;
                goto test_gcm_vectors_exit;
	}
	T2_test = malloc(vector->Tlen);
	if (T2_test == NULL) {
		fprintf(stderr, "Can't allocate tag(2) memory\n");
		is_error = 1;
                goto test_gcm_vectors_exit;
	}
	/* This is only required once for a given key */
        switch (vector->Klen) {
        case BITS_128:
                IMB_AES128_GCM_PRE(p_gcm_mgr, vector->K, &gdata_key);
                break;
        case BITS_192:
                IMB_AES192_GCM_PRE(p_gcm_mgr, vector->K, &gdata_key);
                break;
        case BITS_256:
        default:
                IMB_AES256_GCM_PRE(p_gcm_mgr, vector->K, &gdata_key);
                break;
        }

	/*
         * Encrypt
         */
	encfn(&gdata_key, &gdata_ctx,
              ct_test, vector->P, vector->Plen,
              iv, iv_len, vector->A,
              vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->C, vector->Plen,
                               "encrypted cypher text (C)");
	is_error |= check_data(T_test, vector->T, vector->Tlen, "tag (T)");

	/* test of in-place encrypt */
	memcpy(pt_test, vector->P, vector->Plen);
	encfn(&gdata_key, &gdata_ctx, pt_test, pt_test, vector->Plen,
              iv, iv_len, vector->A, vector->Alen, T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->C, vector->Plen,
                               "encrypted cypher text(in-place)");
	memset(ct_test, 0, vector->Plen);
	memset(T_test, 0, vector->Tlen);

	/*
         * Decrypt
         */
	decfn(&gdata_key, &gdata_ctx, pt_test, vector->C, vector->Plen,
              iv, iv_len, vector->A, vector->Alen,
              T_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->P, vector->Plen,
                               "decrypted plain text (P)");
	/*
         * GCM decryption outputs a 16 byte tag value
         * that must be verified against the expected tag value
         */
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T)");

	/* test in in-place decrypt */
	memcpy(ct_test, vector->C, vector->Plen);
	decfn(&gdata_key, &gdata_ctx, ct_test, ct_test, vector->Plen,
              iv, iv_len, vector->A, vector->Alen,
              T_test, vector->Tlen);
	is_error |= check_data(ct_test, vector->P, vector->Plen,
                               "plain text (P) - in-place");
	is_error |= check_data(T_test, vector->T, vector->Tlen,
                               "decrypted tag (T) - in-place");
	/* enc -> dec */
	encfn(&gdata_key, &gdata_ctx, ct_test, vector->P, vector->Plen,
              iv, iv_len, vector->A, vector->Alen,
              T_test, vector->Tlen);
	memset(pt_test, 0, vector->Plen);

	decfn(&gdata_key, &gdata_ctx, pt_test, ct_test, vector->Plen,
              iv, iv_len, vector->A, vector->Alen,
              T2_test, vector->Tlen);
	is_error |= check_data(pt_test, vector->P, vector->Plen,
                               "self decrypted plain text (P)");
	is_error |= check_data(T_test, T2_test, vector->Tlen,
                               "self decrypted tag (T)");

	memset(pt_test, 0, vector->Plen);

 test_gcm_vectors_exit:
	if (NULL != ct_test)
		free(ct_test);
	if (NULL != pt_test)
		free(pt_test);
	if (NULL != T_test)
		free(T_test);
	if (NULL != T2_test)
		free(T2_test);

	return is_error;
}

static int test_gcm_std_vectors(void)
{
	int const vectors_cnt = sizeof(gcm_vectors) / sizeof(gcm_vectors[0]);
	int vect;
	int is_error = 0;

	printf("AES-GCM standard test vectors:\n");
	for (vect = 0; vect < vectors_cnt; vect++) {
#ifdef DEBUG
		printf("Standard vector %d/%d  Keylen:%d IVlen:%d PTLen:%d "
                       "AADlen:%d Tlen:%d\n",
                       vect + 1, vectors_cnt,
                       (int) gcm_vectors[vect].Klen,
                       (int) gcm_vectors[vect].IVlen,
                       (int) gcm_vectors[vect].Plen,
                       (int) gcm_vectors[vect].Alen,
                       (int) gcm_vectors[vect].Tlen);
#else
		printf(".");
#endif
                switch (gcm_vectors[vect].Klen) {
                case BITS_128:
			is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     aes_gcm_enc_128,
                                                     aes_gcm_dec_128);
			is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     sgl_aes_gcm_enc_128,
                                                     sgl_aes_gcm_dec_128);
			is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     job_aes_gcm_enc_128,
                                                     job_aes_gcm_dec_128);
                        break;
                case BITS_192:
                        is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     aes_gcm_enc_192,
                                                     aes_gcm_dec_192);
                        is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     sgl_aes_gcm_enc_192,
                                                     sgl_aes_gcm_dec_192);
			is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     job_aes_gcm_enc_192,
                                                     job_aes_gcm_dec_192);
                        break;
                case BITS_256:
			is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     aes_gcm_enc_256,
                                                     aes_gcm_dec_256);
			is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     sgl_aes_gcm_enc_256,
                                                     sgl_aes_gcm_dec_256);
			is_error |= test_gcm_vectors(&gcm_vectors[vect],
                                                     job_aes_gcm_enc_256,
                                                     job_aes_gcm_dec_256);
                        break;
                default:
                        is_error = -1;
                        break;
		}
		if (0 != is_error)
			return is_error;
	}
	printf("\n");
	return is_error;
}

static int test_ghash(void)
{
	int const vectors_cnt = sizeof(ghash_vectors) /
                                sizeof(ghash_vectors[0]);
	int vect;
	int is_error = 0;

	uint8_t T_test[16];

	printf("GHASH test vectors:\n");
	for (vect = 0; vect < vectors_cnt; vect++) {
	        struct gcm_key_data gdata_key = {0};
                struct gcm_ctr_vector const *vector = &ghash_vectors[vect];

                switch (vector->Klen) {
                case BITS_128:
                        IMB_AES128_GCM_PRE(p_gcm_mgr, vector->K, &gdata_key);
                        break;
                case BITS_192:
                        IMB_AES192_GCM_PRE(p_gcm_mgr, vector->K, &gdata_key);
                        break;
                case BITS_256:
                default:
                        IMB_AES256_GCM_PRE(p_gcm_mgr, vector->K, &gdata_key);
                        break;
                }
                IMB_GHASH(p_gcm_mgr, &gdata_key, vector->P, vector->Plen,
                          T_test, vector->Tlen);

	        is_error |= check_data(T_test, vector->T, vector->Tlen,
                                       "generated tag (T)");
        }

	return is_error;
}

int gcm_test(IMB_MGR *p_mgr)
{
	int errors = 0;

        p_gcm_mgr = p_mgr;

	errors = test_gcm_std_vectors();

        errors += test_ghash();

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

	return errors;
}
