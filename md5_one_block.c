/*
 * Copyright (c) 2012-2016, Intel Corporation
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
#include "types.h"

void md5_one_block_sse(const UINT8 *data, UINT32 digest[4]);

#ifdef LINUX
#define ROTATE(a,n) ((a << n) ^ (a >> (32-n)))
#else
#include <intrin.h>
#define ROTATE(a,n) _rotl(a,n)
#endif

#define H0 0x67452301
#define H1 0xefcdab89
#define H2 0x98badcfe
#define H3 0x10325476

#define	F1(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	F2(b,c,d)	((((b) ^ (c)) & (d)) ^ (c))
#define	F3(b,c,d)	((b) ^ (c) ^ (d))
#define	F4(b,c,d)	(((~(d)) | (b)) ^ (c))

#define STEP1(a,b,c,d,k,w,r)                    \
        a += w + k + F1(b,c,d);                 \
        a = ROTATE(a, r);                       \
        a += b;
#define STEP2(a,b,c,d,k,w,r)                    \
        a += w + k + F2(b,c,d);                 \
        a = ROTATE(a, r);                       \
        a += b;
#define STEP3(a,b,c,d,k,w,r)                    \
        a += w + k + F3(b,c,d);                 \
        a = ROTATE(a, r);                       \
        a += b;
#define STEP4(a,b,c,d,k,w,r)                    \
        a += w + k + F4(b,c,d);                 \
        a = ROTATE(a, r);                       \
        a += b;


void
md5_one_block_sse(const UINT8 *data, UINT32 digest[4])
{
        UINT32 a,b,c,d;
        UINT32 w00, w01, w02, w03, w04, w05, w06, w07,
                w08, w09, w10, w11, w12, w13, w14, w15;
        const UINT32 *data32 = (const UINT32*)data;

        a = H0;
        b = H1;
        c = H2;
        d = H3;

        w00 = data32[0];
        w01 = data32[1];

        STEP1(a,b,c,d,0xd76aa478,w00, 7);
        w02 = data32[2];
        STEP1(d,a,b,c,0xe8c7b756,w01,12);
        w03 = data32[3];
        STEP1(c,d,a,b,0x242070db,w02,17);
        w04 = data32[4];
        STEP1(b,c,d,a,0xc1bdceee,w03,22);
        w05 = data32[5];
        STEP1(a,b,c,d,0xf57c0faf,w04, 7);
        w06 = data32[6];
        STEP1(d,a,b,c,0x4787c62a,w05,12);
        w07 = data32[7];
        STEP1(c,d,a,b,0xa8304613,w06,17);
        w08 = data32[8];
        STEP1(b,c,d,a,0xfd469501,w07,22);
        w09 = data32[9];
        STEP1(a,b,c,d,0x698098d8,w08, 7);
        w10 = data32[10];
        STEP1(d,a,b,c,0x8b44f7af,w09,12);
        w11 = data32[11];
        STEP1(c,d,a,b,0xffff5bb1,w10,17);
        w12 = data32[12];
        STEP1(b,c,d,a,0x895cd7be,w11,22);
        w13 = data32[13];
        STEP1(a,b,c,d,0x6b901122,w12, 7);
        w14 = data32[14];
        STEP1(d,a,b,c,0xfd987193,w13,12);
        w15 = data32[15];
        STEP1(c,d,a,b,0xa679438e,w14,17);
        STEP1(b,c,d,a,0x49b40821,w15,22);
        STEP2(a,b,c,d,0xf61e2562,w01, 5);
        STEP2(d,a,b,c,0xc040b340,w06, 9);
        STEP2(c,d,a,b,0x265e5a51,w11,14);
        STEP2(b,c,d,a,0xe9b6c7aa,w00,20);
        STEP2(a,b,c,d,0xd62f105d,w05, 5);
        STEP2(d,a,b,c,0x02441453,w10, 9);
        STEP2(c,d,a,b,0xd8a1e681,w15,14);
        STEP2(b,c,d,a,0xe7d3fbc8,w04,20);
        STEP2(a,b,c,d,0x21e1cde6,w09, 5);
        STEP2(d,a,b,c,0xc33707d6,w14, 9);
        STEP2(c,d,a,b,0xf4d50d87,w03,14);
        STEP2(b,c,d,a,0x455a14ed,w08,20);
        STEP2(a,b,c,d,0xa9e3e905,w13, 5);
        STEP2(d,a,b,c,0xfcefa3f8,w02, 9);
        STEP2(c,d,a,b,0x676f02d9,w07,14);
        STEP2(b,c,d,a,0x8d2a4c8a,w12,20);
        STEP3(a,b,c,d,0xfffa3942,w05, 4);
        STEP3(d,a,b,c,0x8771f681,w08,11);
        STEP3(c,d,a,b,0x6d9d6122,w11,16);
        STEP3(b,c,d,a,0xfde5380c,w14,23);
        STEP3(a,b,c,d,0xa4beea44,w01, 4);
        STEP3(d,a,b,c,0x4bdecfa9,w04,11);
        STEP3(c,d,a,b,0xf6bb4b60,w07,16);
        STEP3(b,c,d,a,0xbebfbc70,w10,23);
        STEP3(a,b,c,d,0x289b7ec6,w13, 4);
        STEP3(d,a,b,c,0xeaa127fa,w00,11);
        STEP3(c,d,a,b,0xd4ef3085,w03,16);
        STEP3(b,c,d,a,0x04881d05,w06,23);
        STEP3(a,b,c,d,0xd9d4d039,w09, 4);
        STEP3(d,a,b,c,0xe6db99e5,w12,11);
        STEP3(c,d,a,b,0x1fa27cf8,w15,16);
        STEP3(b,c,d,a,0xc4ac5665,w02,23);
        STEP4(a,b,c,d,0xf4292244,w00, 6);
        STEP4(d,a,b,c,0x432aff97,w07,10);
        STEP4(c,d,a,b,0xab9423a7,w14,15);
        STEP4(b,c,d,a,0xfc93a039,w05,21);
        STEP4(a,b,c,d,0x655b59c3,w12, 6);
        STEP4(d,a,b,c,0x8f0ccc92,w03,10);
        STEP4(c,d,a,b,0xffeff47d,w10,15);
        STEP4(b,c,d,a,0x85845dd1,w01,21);
        STEP4(a,b,c,d,0x6fa87e4f,w08, 6);
        STEP4(d,a,b,c,0xfe2ce6e0,w15,10);
        STEP4(c,d,a,b,0xa3014314,w06,15);
        STEP4(b,c,d,a,0x4e0811a1,w13,21);
        STEP4(a,b,c,d,0xf7537e82,w04, 6);
        STEP4(d,a,b,c,0xbd3af235,w11,10);
        STEP4(c,d,a,b,0x2ad7d2bb,w02,15);
        STEP4(b,c,d,a,0xeb86d391,w09,21);

        digest[0] = a + H0;
        digest[1] = b + H1;
        digest[2] = c + H2;
        digest[3] = d + H3;
}
