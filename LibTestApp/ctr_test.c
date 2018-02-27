/*****************************************************************************
 Copyright (c) 2017-2018, Intel Corporation

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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <mb_mgr.h>
#include <aux_funcs.h>

#include "gcm_ctr_vectors_test.h"


/*
 * Test Vector from
 * https://tools.ietf.org/html/rfc3686
 *
 */
/*
   Test Vector #1: Encrypting 16 octets using AES-CTR with 128-bit key
   AES Key          : AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E
   AES-CTR IV       : 00 00 00 00 00 00 00 00
   Nonce            : 00 00 00 30
   Plaintext String : 'Single block msg'
   Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
   Counter Block (1): 00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01
   Key Stream    (1): B7 60 33 28 DB C2 93 1B 41 0E 16 C8 06 7E 62 DF
   Ciphertext       : E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8
*/
static uint8_t K1_CTR[] = {
        0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
        0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E,
};
static uint8_t IV1_CTR[] = {
        0x00, 0x00, 0x00, 0x30,	/* nonce */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static uint8_t P1_CTR[] = {
        0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
        0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67,
};
static uint8_t C1_CTR[] = {
        0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
        0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8,
};
static uint8_t T1_CTR[] = { 0 };
static uint8_t A1_CTR[] = { 0 };
#define A1_CTR_len 0

/*
   Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key
   AES Key          : 7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63
   AES-CTR IV       : C0 54 3B 59 DA 48 D9 0B
   Nonce            : 00 6C B6 DB
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
   Counter Block (1): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01
   Key Stream    (1): 51 05 A3 05 12 8F 74 DE 71 04 4B E5 82 D7 DD 87
   Counter Block (2): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 02
   Key Stream    (2): FB 3F 0C EF 52 CF 41 DF E4 FF 2A C4 8D 5C A0 37
   Ciphertext       : 51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88
                    : EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28
*/
static uint8_t K2_CTR[] = {
        0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
        0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63,
};
static uint8_t IV2_CTR[] = {
        0x00, 0x6C, 0xB6, 0xDB,	/* nonce */
        0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B,
};
static uint8_t P2_CTR[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static uint8_t C2_CTR[] = {
        0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
        0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
        0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
        0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28,
};
static uint8_t T2_CTR[] = { 0 };
static uint8_t A2_CTR[] = { 0 };
#define A2_CTR_len 0

/*
   Test Vector #3: Encrypting 36 octets using AES-CTR with 128-bit key
   AES Key          : 76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC
   AES-CTR IV       : 27 77 7F 3F  4A 17 86 F0
   Nonce            : 00 E0 01 7B
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                    : 20 21 22 23
   Counter Block (1): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 01
   Key Stream    (1): C1 CE 4A AB 9B 2A FB DE C7 4F 58 E2 E3 D6 7C D8
   Counter Block (2): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 02
   Key Stream    (2): 55 51 B6 38 CA 78 6E 21 CD 83 46 F1 B2 EE 0E 4C
   Counter Block (3): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 03
   Key Stream    (3): 05 93 25 0C 17 55 36 00 A6 3D FE CF 56 23 87 E9
   Ciphertext       : C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7
                    : 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53
                    : 25 B2 07 2F
*/
static uint8_t K3_CTR[] = {
        0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8,
        0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC,
};
static uint8_t IV3_CTR[] = {
        0x00, 0xE0, 0x01, 0x7B,	/* nonce */
        0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0,
};
static uint8_t P3_CTR[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23,
};
static uint8_t C3_CTR[] = {
        0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9,
        0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
        0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36,
        0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
        0x25, 0xB2, 0x07, 0x2F,
};
static uint8_t T3_CTR[] = { 0 };
static uint8_t A3_CTR[] = { 0 };
#define A3_CTR_len 0

/*
   Test Vector #4: Encrypting 16 octets using AES-CTR with 192-bit key
   AES Key          : 16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED
                    : 86 3D 06 CC FD B7 85 15
   AES-CTR IV       : 36 73 3C 14 7D 6D 93 CB
   Nonce            : 00 00 00 48
   Plaintext String : 'Single block msg'
   Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
   Counter Block (1): 00 00 00 48 36 73 3C 14 7D 6D 93 CB 00 00 00 01
   Key Stream    (1): 18 3C 56 28 8E 3C E9 AA 22 16 56 CB 23 A6 9A 4F
   Ciphertext       : 4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28
*/
static uint8_t K4_CTR[] = {
        0x16, 0xAF, 0x5B, 0x14, 0x5F, 0xC9, 0xF5, 0x79,
        0xC1, 0x75, 0xF9, 0x3E, 0x3B, 0xFB, 0x0E, 0xED,
        0x86, 0x3D, 0x06, 0xCC, 0xFD, 0xB7, 0x85, 0x15,
};
static uint8_t IV4_CTR[] = {
        0x00, 0x00, 0x00, 0x48,	/* nonce */
        0x36, 0x73, 0x3C, 0x14, 0x7D, 0x6D, 0x93, 0xCB,
};
static uint8_t P4_CTR[] = {
        0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
        0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67,
};
static uint8_t C4_CTR[] = {
        0x4B, 0x55, 0x38, 0x4F, 0xE2, 0x59, 0xC9, 0xC8,
        0x4E, 0x79, 0x35, 0xA0, 0x03, 0xCB, 0xE9, 0x28,
};
static uint8_t T4_CTR[] = { 0 };
static uint8_t A4_CTR[] = { 0 };
#define A4_CTR_len 0

/*
   Test Vector #5: Encrypting 32 octets using AES-CTR with 192-bit key
   AES Key          : 7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C
                    : 67 8C 3D B8 E6 F6 A9 1A
   AES-CTR IV       : 02 0C 6E AD C2 CB 50 0D
   Nonce            : 00 96 B0 3B
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
   Counter Block (1): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 01
   Key Stream    (1): 45 33 41 FF 64 9E 25 35 76 D6 A0 F1 7D 3C C3 90
   Counter Block (2): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 02
   Key Stream    (2): 94 81 62 0F 4E C1 B1 8B E4 06 FA E4 5E E9 E5 1F
   Ciphertext       : 45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F
                    : 84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00
*/
static uint8_t K5_CTR[] = {
        0x7C, 0x5C, 0xB2, 0x40, 0x1B, 0x3D, 0xC3, 0x3C,
        0x19, 0xE7, 0x34, 0x08, 0x19, 0xE0, 0xF6, 0x9C,
        0x67, 0x8C, 0x3D, 0xB8, 0xE6, 0xF6, 0xA9, 0x1A,
};
static uint8_t IV5_CTR[] = {
        0x00, 0x96, 0xB0, 0x3B,	/* nonce */
        0x02, 0x0C, 0x6E, 0xAD, 0xC2, 0xCB, 0x50, 0x0D,
};
static uint8_t P5_CTR[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static uint8_t C5_CTR[] = {
        0x45, 0x32, 0x43, 0xFC, 0x60, 0x9B, 0x23, 0x32,
        0x7E, 0xDF, 0xAA, 0xFA, 0x71, 0x31, 0xCD, 0x9F,
        0x84, 0x90, 0x70, 0x1C, 0x5A, 0xD4, 0xA7, 0x9C,
        0xFC, 0x1F, 0xE0, 0xFF, 0x42, 0xF4, 0xFB, 0x00,
};
static uint8_t T5_CTR[] = { 0 };
static uint8_t A5_CTR[] = { 0 };
#define A5_CTR_len 0

/*
   Test Vector #6: Encrypting 36 octets using AES-CTR with 192-bit key
   AES Key          : 02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B
                    : F5 9B 60 A7 86 D3 E0 FE
   AES-CTR IV       : 5C BD 60 27 8D CC 09 12
   Nonce            : 00 07 BD FD
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                    : 20 21 22 23
   Counter Block (1): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 01
   Key Stream    (1): 96 88 3D C6 5A 59 74 28 5C 02 77 DA D1 FA E9 57
   Counter Block (2): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 02
   Key Stream    (2): C2 99 AE 86 D2 84 73 9F 5D 2F D2 0A 7A 32 3F 97
   Counter Block (3): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 03
   Key Stream    (3): 8B CF 2B 16 39 99 B2 26 15 B4 9C D4 FE 57 39 98
   Ciphertext       : 96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58
                    : D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88
                    : AB EE 09 35
*/
static uint8_t K6_CTR[] = {
        0x02, 0xBF, 0x39, 0x1E, 0xE8, 0xEC, 0xB1, 0x59,
        0xB9, 0x59, 0x61, 0x7B, 0x09, 0x65, 0x27, 0x9B,
        0xF5, 0x9B, 0x60, 0xA7, 0x86, 0xD3, 0xE0, 0xFE,
};
static uint8_t IV6_CTR[] = {
        0x00, 0x07, 0xBD, 0xFD,	/* nonce */
        0x5C, 0xBD, 0x60, 0x27, 0x8D, 0xCC, 0x09, 0x12,
};
static uint8_t P6_CTR[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23,
};
static uint8_t C6_CTR[] = {
        0x96, 0x89, 0x3F, 0xC5, 0x5E, 0x5C, 0x72, 0x2F,
        0x54, 0x0B, 0x7D, 0xD1, 0xDD, 0xF7, 0xE7, 0x58,
        0xD2, 0x88, 0xBC, 0x95, 0xC6, 0x91, 0x65, 0x88,
        0x45, 0x36, 0xC8, 0x11, 0x66, 0x2F, 0x21, 0x88,
        0xAB, 0xEE, 0x09, 0x35,
};
static uint8_t T6_CTR[] = { 0 };
static uint8_t A6_CTR[] = { 0 };
#define A6_CTR_len 0

/*
   Test Vector #7: Encrypting 16 octets using AES-CTR with 256-bit key
   AES Key          : 77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C
                    : 6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04
   AES-CTR IV       : DB 56 72 C9 7A A8 F0 B2
   Nonce            : 00 00 00 60
   Plaintext String : 'Single block msg'
   Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
   Counter Block (1): 00 00 00 60 DB 56 72 C9 7A A8 F0 B2 00 00 00 01
   Key Stream    (1): 47 33 BE 7A D3 E7 6E A5 3A 67 00 B7 51 8E 93 A7
   Ciphertext       : 14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0
*/
static uint8_t K7_CTR[] = {
        0x77, 0x6B, 0xEF, 0xF2, 0x85, 0x1D, 0xB0, 0x6F,
        0x4C, 0x8A, 0x05, 0x42, 0xC8, 0x69, 0x6F, 0x6C,
        0x6A, 0x81, 0xAF, 0x1E, 0xEC, 0x96, 0xB4, 0xD3,
        0x7F, 0xC1, 0xD6, 0x89, 0xE6, 0xC1, 0xC1, 0x04,
};
static uint8_t IV7_CTR[] = {
        0x00, 0x00, 0x00, 0x60,	/* nonce */
        0xDB, 0x56, 0x72, 0xC9, 0x7A, 0xA8, 0xF0, 0xB2,
};
static uint8_t P7_CTR[] = {
        0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
        0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67,
};
static uint8_t C7_CTR[] = {
        0x14, 0x5A, 0xD0, 0x1D, 0xBF, 0x82, 0x4E, 0xC7,
        0x56, 0x08, 0x63, 0xDC, 0x71, 0xE3, 0xE0, 0xC0,
};
static uint8_t T7_CTR[] = { 0 };
static uint8_t A7_CTR[] = { 0 };
#define A7_CTR_len 0

/*
   Test Vector #8: Encrypting 32 octets using AES-CTR with 256-bit key
   AES Key          : F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86
                    : C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84
   AES-CTR IV       : C1 58 5E F1 5A 43 D8 75
   Nonce            : 00 FA AC 24
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
   Counter block (1): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 01
   Key stream    (1): F0 5F 21 18 3C 91 67 2B 41 E7 0A 00 8C 43 BC A6
   Counter block (2): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 02
   Key stream    (2): A8 21 79 43 9B 96 8B 7D 4D 29 99 06 8F 59 B1 03
   Ciphertext       : F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9
                    : B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C
*/
static uint8_t K8_CTR[] = {
        0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB,
        0x07, 0x96, 0x36, 0x58, 0x79, 0xEF, 0xF8, 0x86,
        0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A, 0x99, 0x74,
        0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84,
};
static uint8_t IV8_CTR[] = {
        0x00, 0xFA, 0xAC, 0x24,	/* nonce */
        0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75,
};
static uint8_t P8_CTR[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static uint8_t C8_CTR[] = {
        0xF0, 0x5E, 0x23, 0x1B, 0x38, 0x94, 0x61, 0x2C,
        0x49, 0xEE, 0x00, 0x0B, 0x80, 0x4E, 0xB2, 0xA9,
        0xB8, 0x30, 0x6B, 0x50, 0x8F, 0x83, 0x9D, 0x6A,
        0x55, 0x30, 0x83, 0x1D, 0x93, 0x44, 0xAF, 0x1C,
};
static uint8_t T8_CTR[] = { 0 };
static uint8_t A8_CTR[] = { 0 };
#define A8_CTR_len 0

/*
   Test Vector #9: Encrypting 36 octets using AES-CTR with 256-bit key
   AES Key          : FF 7A 61 7C E6 91 48 E4 F1 72 6E 2F 43 58 1D E2
                    : AA 62 D9 F8 05 53 2E DF F1 EE D6 87 FB 54 15 3D
   AES-CTR IV       : 51 A5 1D 70 A1 C1 11 48
   Nonce            : 00 1C C5 B7
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                    : 20 21 22 23
   Counter block (1): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 01
   Key stream    (1): EB 6D 50 81 19 0E BD F0 C6 7C 9E 4D 26 C7 41 A5
   Counter block (2): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 02
   Key stream    (2): A4 16 CD 95 71 7C EB 10 EC 95 DA AE 9F CB 19 00
   Counter block (3): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 03
   Key stream    (3): 3E E1 C4 9B C6 B9 CA 21 3F 6E E2 71 D0 A9 33 39
   Ciphertext       : EB 6C 52 82 1D 0B BB F7 CE 75 94 46 2A CA 4F AA
                    : B4 07 DF 86 65 69 FD 07 F4 8C C0 B5 83 D6 07 1F
                    : 1E C0 E6 B8
*/
static uint8_t K9_CTR[] = {
        0xFF, 0x7A, 0x61, 0x7C, 0xE6, 0x91, 0x48, 0xE4,
        0xF1, 0x72, 0x6E, 0x2F, 0x43, 0x58, 0x1D, 0xE2,
        0xAA, 0x62, 0xD9, 0xF8, 0x05, 0x53, 0x2E, 0xDF,
        0xF1, 0xEE, 0xD6, 0x87, 0xFB, 0x54, 0x15, 0x3D,
};
static uint8_t IV9_CTR[] = {
        0x00, 0x1C, 0xC5, 0xB7,	/* nonce */
        0x51, 0xA5, 0x1D, 0x70, 0xA1, 0xC1, 0x11, 0x48,
};
static uint8_t P9_CTR[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23,
};
static uint8_t C9_CTR[] = {
        0xEB, 0x6C, 0x52, 0x82, 0x1D, 0x0B, 0xBB, 0xF7,
        0xCE, 0x75, 0x94, 0x46, 0x2A, 0xCA, 0x4F, 0xAA,
        0xB4, 0x07, 0xDF, 0x86, 0x65, 0x69, 0xFD, 0x07,
        0xF4, 0x8C, 0xC0, 0xB5, 0x83, 0xD6, 0x07, 0x1F,
        0x1E, 0xC0, 0xE6, 0xB8,
};
static uint8_t T9_CTR[] = { 0 };
static uint8_t A9_CTR[] = { 0 };
#define A9_CTR_len 0

static const struct gcm_ctr_vector ctr_vectors[] = {
	/*
         * field order {K, Klen, IV, IVlen, A, Alen, P, Plen, C, T, Tlen};
         * original vector does not have a valid sub hash key
         */
	vector(1_CTR),
	vector(2_CTR),
	vector(3_CTR),
	vector(4_CTR),
	vector(5_CTR),
	vector(6_CTR),
	vector(7_CTR),
	vector(8_CTR),
	vector(9_CTR),
};

#ifdef _WIN32
#define snprintf _snprintf
#endif

static void
hexdump(FILE *fp,
        const char *msg,
        const void *p,
        size_t len)
{
        unsigned int i, out, ofs;
        const unsigned char *data = p;

        fprintf(fp, "%s\n", msg);

        ofs = 0;
        while (ofs < len) {
                char line[120];

                out = snprintf(line, sizeof(line), "%08x:", ofs);
                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        out += snprintf(line + out, sizeof(line) - out,
                                        " %02x", (data[ofs + i] & 0xff));
                for (; i <= 16; i++)
                        out += snprintf(line + out, sizeof(line) - out, " | ");
                for (i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];

                        if ((c < ' ') || (c > '~'))
                                c = '.';
                        out += snprintf(line + out,
                                        sizeof(line) - out, "%c", c);
                }
                fprintf(fp, "%s\n", line);
        }
}


static int
test_ctr(struct MB_MGR *mb_mgr,
         const void *expkey,
         unsigned key_len,
         const void *iv,
         unsigned iv_len,
         const uint8_t *in_text,
         const uint8_t *out_text,
         unsigned text_len,
         int dir,
         int order)
{
        struct JOB_AES_HMAC *job;
        uint8_t padding[16];
        uint8_t *target = malloc(text_len + (sizeof(padding) * 2));
        int ret = -1;

        if (target == NULL) {
		fprintf(stderr, "Can't allocate buffer memory\n");
		goto end;
        }

        memset(target, -1, text_len + (sizeof(padding) * 2));
        memset(padding, -1, sizeof(padding));

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = dir;
        job->chain_order = order;
        job->dst = target + 16;
        job->src = in_text;
        job->cipher_mode = CNTR;
        job->aes_enc_key_expanded = expkey;
        job->aes_dec_key_expanded = expkey;
        job->aes_key_len_in_bytes = key_len;
        job->iv = iv;
        job->iv_len_in_bytes = iv_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = text_len;

        job->hash_alg = NULL_HASH;
        job->hashed_auth_key_xor_ipad = NULL;
        job->hashed_auth_key_xor_opad = NULL;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = 0;
        job->auth_tag_output = NULL;
        job->auth_tag_output_len_in_bytes = 0;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job) {
                printf("%d Unexpected return from submit_job\n", __LINE__);
                goto end;
        }
        job = IMB_FLUSH_JOB(mb_mgr);
        if (!job) {
                printf("%d Unexpected null return from flush_job\n", __LINE__);
                goto end;
        }
        if (job->status != STS_COMPLETED) {
                printf("%d Error status:%d", __LINE__, job->status);
                goto end;
        }
        if (memcmp(out_text, target + 16, text_len)) {
                printf("mismatched\n");
                hexdump(stderr, "Target", target, text_len + 32);
                goto end;
        }
        if (memcmp(padding, target, sizeof(padding))) {
                printf("overwrite head\n");
                hexdump(stderr, "Target", target, text_len + 32);
                goto end;
        }
        if (memcmp(padding, target + sizeof(padding) + text_len,
                   sizeof(padding))) {
                printf("overwrite tail\n");
                hexdump(stderr, "Target", target, text_len + 32);
                goto end;
        }
        ret = 0;
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;
 end:
        if (target != NULL)
                free(target);
        return ret;
}

static int
test_ctr_std_vectors(struct MB_MGR *mb_mgr)
{
	int const vectors_cnt = sizeof(ctr_vectors) / sizeof(ctr_vectors[0]);
	int vect;
	int errors = 0;
        DECLARE_ALIGNED(uint32_t expkey[4*15], 16);
        DECLARE_ALIGNED(uint32_t dust[4*15], 16);

	printf("AES-CTR standard test vectors:\n");
	for (vect = 0; vect < vectors_cnt; vect++) {
#ifdef DEBUG
		printf("Standard vector %d/%d  Keylen:%d IVlen:%d PTLen:%d "
                       "AADlen:%d Tlen:%d\n",
                       vect, vectors_cnt - 1,
                       (int) ctr_vectors[vect].Klen,
                       (int) ctr_vectors[vect].IVlen,
                       (int) ctr_vectors[vect].Plen,
                       (int) ctr_vectors[vect].Alen,
                       (int) ctr_vectors[vect].Tlen);
#else
		printf(".");
#endif


                switch (ctr_vectors[vect].Klen) {
                case BITS_128:
                        IMB_AES_KEYEXP_128(mb_mgr, ctr_vectors[vect].K,
                                           expkey, dust);
                        break;
                case BITS_192:
                        IMB_AES_KEYEXP_192(mb_mgr, ctr_vectors[vect].K,
                                           expkey, dust);
                        break;
                case BITS_256:
                        IMB_AES_KEYEXP_256(mb_mgr, ctr_vectors[vect].K,
                                           expkey, dust);
                        break;
                default:
                        return -1;
                }

                if (test_ctr(mb_mgr,
                             expkey, ctr_vectors[vect].Klen,
                             ctr_vectors[vect].IV,
                             (unsigned) ctr_vectors[vect].IVlen,
                             ctr_vectors[vect].P, ctr_vectors[vect].C,
                             (unsigned) ctr_vectors[vect].Plen,
                             ENCRYPT, CIPHER_HASH)) {
                        printf("error #%d encrypt\n", vect + 1);
                        errors++;
                }

                if (test_ctr(mb_mgr,
                             expkey, ctr_vectors[vect].Klen,
                             ctr_vectors[vect].IV,
                             (unsigned) ctr_vectors[vect].IVlen,
                             ctr_vectors[vect].C, ctr_vectors[vect].P,
                             (unsigned) ctr_vectors[vect].Plen,
                             DECRYPT, HASH_CIPHER)) {
                        printf("error #%d decrypt\n", vect + 1);
                        errors++;
                }

                if (ctr_vectors[vect].IVlen == 12) {
                        /* IV in the table didn't
                         * include block counter (12 bytes).
                         * Let's encrypt & decrypt the same but
                         * with 16 byte IV that includes block counter.
                         */
                        const unsigned new_iv_len = 16;
                        const unsigned orig_iv_len = 12;
                        uint8_t local_iv[16];

                        memcpy(local_iv, ctr_vectors[vect].IV, orig_iv_len);
                        /* 32-bit 0x01000000 in LE */
                        local_iv[12] = 0x00;
                        local_iv[13] = 0x00;
                        local_iv[14] = 0x00;
                        local_iv[15] = 0x01;

                        if (test_ctr(mb_mgr,
                                     expkey, ctr_vectors[vect].Klen,
                                     local_iv, new_iv_len,
                                     ctr_vectors[vect].P, ctr_vectors[vect].C,
                                     (unsigned) ctr_vectors[vect].Plen,
                                     ENCRYPT, CIPHER_HASH)) {
                                printf("error #%d encrypt\n", vect + 1);
                                errors++;
                        }

                        if (test_ctr(mb_mgr,
                                     expkey, ctr_vectors[vect].Klen,
                                     local_iv, new_iv_len,
                                     ctr_vectors[vect].C, ctr_vectors[vect].P,
                                     (unsigned) ctr_vectors[vect].Plen,
                                     DECRYPT, HASH_CIPHER)) {
                                printf("error #%d decrypt\n", vect + 1);
                                errors++;
                        }
                }
	}
	printf("\n");
	return errors;
}

int
ctr_test(const enum arch_type arch,
         struct MB_MGR *mb_mgr)
{
        int errors;

        (void) arch; /* unused */

        errors = test_ctr_std_vectors(mb_mgr);

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

	return errors;
}
