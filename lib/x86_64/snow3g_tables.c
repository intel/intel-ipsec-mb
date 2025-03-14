/*******************************************************************************
  Copyright (c) 2009-2024, Intel Corporation

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
*******************************************************************************/

#include "snow3g_tables.h"

/*--------------------------------------------------------------------
 *
 * An implementation of SNOW 3G, the core algorithm for the
 * 3GPP Confidentiality and Integrity algorithms.
 *
 *--------------------------------------------------------------------*/

IMB_DLL_LOCAL
DECLARE_ALIGNED(const int snow3g_table_A_mul[256], 32) = {
        0x00000000, 0xe19fcf13, 0x6b973726, 0x8a08f835, 0xd6876e4c, 0x3718a15f, 0xbd10596a,
        0x5c8f9679, 0x05a7dc98, 0xe438138b, 0x6e30ebbe, 0x8faf24ad, 0xd320b2d4, 0x32bf7dc7,
        0xb8b785f2, 0x59284ae1, 0x0ae71199, 0xeb78de8a, 0x617026bf, 0x80efe9ac, 0xdc607fd5,
        0x3dffb0c6, 0xb7f748f3, 0x566887e0, 0x0f40cd01, 0xeedf0212, 0x64d7fa27, 0x85483534,
        0xd9c7a34d, 0x38586c5e, 0xb250946b, 0x53cf5b78, 0x1467229b, 0xf5f8ed88, 0x7ff015bd,
        0x9e6fdaae, 0xc2e04cd7, 0x237f83c4, 0xa9777bf1, 0x48e8b4e2, 0x11c0fe03, 0xf05f3110,
        0x7a57c925, 0x9bc80636, 0xc747904f, 0x26d85f5c, 0xacd0a769, 0x4d4f687a, 0x1e803302,
        0xff1ffc11, 0x75170424, 0x9488cb37, 0xc8075d4e, 0x2998925d, 0xa3906a68, 0x420fa57b,
        0x1b27ef9a, 0xfab82089, 0x70b0d8bc, 0x912f17af, 0xcda081d6, 0x2c3f4ec5, 0xa637b6f0,
        0x47a879e3, 0x28ce449f, 0xc9518b8c, 0x435973b9, 0xa2c6bcaa, 0xfe492ad3, 0x1fd6e5c0,
        0x95de1df5, 0x7441d2e6, 0x2d699807, 0xccf65714, 0x46feaf21, 0xa7616032, 0xfbeef64b,
        0x1a713958, 0x9079c16d, 0x71e60e7e, 0x22295506, 0xc3b69a15, 0x49be6220, 0xa821ad33,
        0xf4ae3b4a, 0x1531f459, 0x9f390c6c, 0x7ea6c37f, 0x278e899e, 0xc611468d, 0x4c19beb8,
        0xad8671ab, 0xf109e7d2, 0x109628c1, 0x9a9ed0f4, 0x7b011fe7, 0x3ca96604, 0xdd36a917,
        0x573e5122, 0xb6a19e31, 0xea2e0848, 0x0bb1c75b, 0x81b93f6e, 0x6026f07d, 0x390eba9c,
        0xd891758f, 0x52998dba, 0xb30642a9, 0xef89d4d0, 0x0e161bc3, 0x841ee3f6, 0x65812ce5,
        0x364e779d, 0xd7d1b88e, 0x5dd940bb, 0xbc468fa8, 0xe0c919d1, 0x0156d6c2, 0x8b5e2ef7,
        0x6ac1e1e4, 0x33e9ab05, 0xd2766416, 0x587e9c23, 0xb9e15330, 0xe56ec549, 0x04f10a5a,
        0x8ef9f26f, 0x6f663d7c, 0x50358897, 0xb1aa4784, 0x3ba2bfb1, 0xda3d70a2, 0x86b2e6db,
        0x672d29c8, 0xed25d1fd, 0x0cba1eee, 0x5592540f, 0xb40d9b1c, 0x3e056329, 0xdf9aac3a,
        0x83153a43, 0x628af550, 0xe8820d65, 0x091dc276, 0x5ad2990e, 0xbb4d561d, 0x3145ae28,
        0xd0da613b, 0x8c55f742, 0x6dca3851, 0xe7c2c064, 0x065d0f77, 0x5f754596, 0xbeea8a85,
        0x34e272b0, 0xd57dbda3, 0x89f22bda, 0x686de4c9, 0xe2651cfc, 0x03fad3ef, 0x4452aa0c,
        0xa5cd651f, 0x2fc59d2a, 0xce5a5239, 0x92d5c440, 0x734a0b53, 0xf942f366, 0x18dd3c75,
        0x41f57694, 0xa06ab987, 0x2a6241b2, 0xcbfd8ea1, 0x977218d8, 0x76edd7cb, 0xfce52ffe,
        0x1d7ae0ed, 0x4eb5bb95, 0xaf2a7486, 0x25228cb3, 0xc4bd43a0, 0x9832d5d9, 0x79ad1aca,
        0xf3a5e2ff, 0x123a2dec, 0x4b12670d, 0xaa8da81e, 0x2085502b, 0xc11a9f38, 0x9d950941,
        0x7c0ac652, 0xf6023e67, 0x179df174, 0x78fbcc08, 0x9964031b, 0x136cfb2e, 0xf2f3343d,
        0xae7ca244, 0x4fe36d57, 0xc5eb9562, 0x24745a71, 0x7d5c1090, 0x9cc3df83, 0x16cb27b6,
        0xf754e8a5, 0xabdb7edc, 0x4a44b1cf, 0xc04c49fa, 0x21d386e9, 0x721cdd91, 0x93831282,
        0x198beab7, 0xf81425a4, 0xa49bb3dd, 0x45047cce, 0xcf0c84fb, 0x2e934be8, 0x77bb0109,
        0x9624ce1a, 0x1c2c362f, 0xfdb3f93c, 0xa13c6f45, 0x40a3a056, 0xcaab5863, 0x2b349770,
        0x6c9cee93, 0x8d032180, 0x070bd9b5, 0xe69416a6, 0xba1b80df, 0x5b844fcc, 0xd18cb7f9,
        0x301378ea, 0x693b320b, 0x88a4fd18, 0x02ac052d, 0xe333ca3e, 0xbfbc5c47, 0x5e239354,
        0xd42b6b61, 0x35b4a472, 0x667bff0a, 0x87e43019, 0x0decc82c, 0xec73073f, 0xb0fc9146,
        0x51635e55, 0xdb6ba660, 0x3af46973, 0x63dc2392, 0x8243ec81, 0x084b14b4, 0xe9d4dba7,
        0xb55b4dde, 0x54c482cd, 0xdecc7af8, 0x3f53b5eb
};

IMB_DLL_LOCAL
DECLARE_ALIGNED(const int snow3g_table_A_div[256], 32) = {
        0x00000000, 0x180f40cd, 0x301e8033, 0x2811c0fe, 0x603ca966, 0x7833e9ab, 0x50222955,
        0x482d6998, 0xc078fbcc, 0xd877bb01, 0xf0667bff, 0xe8693b32, 0xa04452aa, 0xb84b1267,
        0x905ad299, 0x88559254, 0x29f05f31, 0x31ff1ffc, 0x19eedf02, 0x01e19fcf, 0x49ccf657,
        0x51c3b69a, 0x79d27664, 0x61dd36a9, 0xe988a4fd, 0xf187e430, 0xd99624ce, 0xc1996403,
        0x89b40d9b, 0x91bb4d56, 0xb9aa8da8, 0xa1a5cd65, 0x5249be62, 0x4a46feaf, 0x62573e51,
        0x7a587e9c, 0x32751704, 0x2a7a57c9, 0x026b9737, 0x1a64d7fa, 0x923145ae, 0x8a3e0563,
        0xa22fc59d, 0xba208550, 0xf20decc8, 0xea02ac05, 0xc2136cfb, 0xda1c2c36, 0x7bb9e153,
        0x63b6a19e, 0x4ba76160, 0x53a821ad, 0x1b854835, 0x038a08f8, 0x2b9bc806, 0x339488cb,
        0xbbc11a9f, 0xa3ce5a52, 0x8bdf9aac, 0x93d0da61, 0xdbfdb3f9, 0xc3f2f334, 0xebe333ca,
        0xf3ec7307, 0xa492d5c4, 0xbc9d9509, 0x948c55f7, 0x8c83153a, 0xc4ae7ca2, 0xdca13c6f,
        0xf4b0fc91, 0xecbfbc5c, 0x64ea2e08, 0x7ce56ec5, 0x54f4ae3b, 0x4cfbeef6, 0x04d6876e,
        0x1cd9c7a3, 0x34c8075d, 0x2cc74790, 0x8d628af5, 0x956dca38, 0xbd7c0ac6, 0xa5734a0b,
        0xed5e2393, 0xf551635e, 0xdd40a3a0, 0xc54fe36d, 0x4d1a7139, 0x551531f4, 0x7d04f10a,
        0x650bb1c7, 0x2d26d85f, 0x35299892, 0x1d38586c, 0x053718a1, 0xf6db6ba6, 0xeed42b6b,
        0xc6c5eb95, 0xdecaab58, 0x96e7c2c0, 0x8ee8820d, 0xa6f942f3, 0xbef6023e, 0x36a3906a,
        0x2eacd0a7, 0x06bd1059, 0x1eb25094, 0x569f390c, 0x4e9079c1, 0x6681b93f, 0x7e8ef9f2,
        0xdf2b3497, 0xc724745a, 0xef35b4a4, 0xf73af469, 0xbf179df1, 0xa718dd3c, 0x8f091dc2,
        0x97065d0f, 0x1f53cf5b, 0x075c8f96, 0x2f4d4f68, 0x37420fa5, 0x7f6f663d, 0x676026f0,
        0x4f71e60e, 0x577ea6c3, 0xe18d0321, 0xf98243ec, 0xd1938312, 0xc99cc3df, 0x81b1aa47,
        0x99beea8a, 0xb1af2a74, 0xa9a06ab9, 0x21f5f8ed, 0x39fab820, 0x11eb78de, 0x09e43813,
        0x41c9518b, 0x59c61146, 0x71d7d1b8, 0x69d89175, 0xc87d5c10, 0xd0721cdd, 0xf863dc23,
        0xe06c9cee, 0xa841f576, 0xb04eb5bb, 0x985f7545, 0x80503588, 0x0805a7dc, 0x100ae711,
        0x381b27ef, 0x20146722, 0x68390eba, 0x70364e77, 0x58278e89, 0x4028ce44, 0xb3c4bd43,
        0xabcbfd8e, 0x83da3d70, 0x9bd57dbd, 0xd3f81425, 0xcbf754e8, 0xe3e69416, 0xfbe9d4db,
        0x73bc468f, 0x6bb30642, 0x43a2c6bc, 0x5bad8671, 0x1380efe9, 0x0b8faf24, 0x239e6fda,
        0x3b912f17, 0x9a34e272, 0x823ba2bf, 0xaa2a6241, 0xb225228c, 0xfa084b14, 0xe2070bd9,
        0xca16cb27, 0xd2198bea, 0x5a4c19be, 0x42435973, 0x6a52998d, 0x725dd940, 0x3a70b0d8,
        0x227ff015, 0x0a6e30eb, 0x12617026, 0x451fd6e5, 0x5d109628, 0x750156d6, 0x6d0e161b,
        0x25237f83, 0x3d2c3f4e, 0x153dffb0, 0x0d32bf7d, 0x85672d29, 0x9d686de4, 0xb579ad1a,
        0xad76edd7, 0xe55b844f, 0xfd54c482, 0xd545047c, 0xcd4a44b1, 0x6cef89d4, 0x74e0c919,
        0x5cf109e7, 0x44fe492a, 0x0cd320b2, 0x14dc607f, 0x3ccda081, 0x24c2e04c, 0xac977218,
        0xb49832d5, 0x9c89f22b, 0x8486b2e6, 0xccabdb7e, 0xd4a49bb3, 0xfcb55b4d, 0xe4ba1b80,
        0x17566887, 0x0f59284a, 0x2748e8b4, 0x3f47a879, 0x776ac1e1, 0x6f65812c, 0x477441d2,
        0x5f7b011f, 0xd72e934b, 0xcf21d386, 0xe7301378, 0xff3f53b5, 0xb7123a2d, 0xaf1d7ae0,
        0x870cba1e, 0x9f03fad3, 0x3ea637b6, 0x26a9777b, 0x0eb8b785, 0x16b7f748, 0x5e9a9ed0,
        0x4695de1d, 0x6e841ee3, 0x768b5e2e, 0xfedecc7a, 0xe6d18cb7, 0xcec04c49, 0xd6cf0c84,
        0x9ee2651c, 0x86ed25d1, 0xaefce52f, 0xb6f3a5e2
};

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte0_low[16], 16) = { 0x00, 0x13, 0x26, 0x35, 0x4C, 0x5F,
                                                                 0x6A, 0x79, 0x98, 0x8B, 0xBE, 0xAD,
                                                                 0xD4, 0xC7, 0xF2, 0xE1 };
IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte1_low[16], 16) = { 0x00, 0xCF, 0x37, 0xF8, 0x6E, 0xA1,
                                                                 0x59, 0x96, 0xDC, 0x13, 0xEB, 0x24,
                                                                 0xB2, 0x7D, 0x85, 0x4A };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte2_low[16], 16) = { 0x00, 0x9F, 0x97, 0x08, 0x87, 0x18,
                                                                 0x10, 0x8F, 0xA7, 0x38, 0x30, 0xAF,
                                                                 0x20, 0xBF, 0xB7, 0x28 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte3_low[16], 16) = { 0x00, 0xE1, 0x6B, 0x8A, 0xD6, 0x37,
                                                                 0xBD, 0x5C, 0x05, 0xE4, 0x6E, 0x8F,
                                                                 0xD3, 0x32, 0xB8, 0x59 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte0_hi[16], 16) = { 0x00, 0x99, 0x9B, 0x02, 0x9F, 0x06,
                                                                0x04, 0x9D, 0x97, 0x0E, 0x0C, 0x95,
                                                                0x08, 0x91, 0x93, 0x0A };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte1_hi[16], 16) = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                                                0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
                                                                0xCC, 0xDD, 0xEE, 0xFF };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte2_hi[16], 16) = { 0x00, 0xE7, 0x67, 0x80, 0xCE, 0x29,
                                                                0xA9, 0x4E, 0x35, 0xD2, 0x52, 0xB5,
                                                                0xFB, 0x1C, 0x9C, 0x7B };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_MULa_byte3_hi[16], 16) = { 0x00, 0x0A, 0x14, 0x1E, 0x28, 0x22,
                                                                0x3C, 0x36, 0x50, 0x5A, 0x44, 0x4E,
                                                                0x78, 0x72, 0x6C, 0x66 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte0_low[16], 16) = { 0x00, 0xCD, 0x33, 0xFE, 0x66, 0xAB,
                                                                 0x55, 0x98, 0xCC, 0x01, 0xFF, 0x32,
                                                                 0xAA, 0x67, 0x99, 0x54 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte1_low[16], 16) = { 0x00, 0x40, 0x80, 0xC0, 0xA9, 0xE9,
                                                                 0x29, 0x69, 0xFB, 0xBB, 0x7B, 0x3B,
                                                                 0x52, 0x12, 0xD2, 0x92 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte2_low[16], 16) = { 0x00, 0x0F, 0x1E, 0x11, 0x3C, 0x33,
                                                                 0x22, 0x2D, 0x78, 0x77, 0x66, 0x69,
                                                                 0x44, 0x4B, 0x5A, 0x55 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte3_low[16], 16) = { 0x00, 0x18, 0x30, 0x28, 0x60, 0x78,
                                                                 0x50, 0x48, 0xC0, 0xD8, 0xF0, 0xE8,
                                                                 0xA0, 0xB8, 0x90, 0x88 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte0_hi[16], 16) = { 0x00, 0x31, 0x62, 0x53, 0xC4, 0xF5,
                                                                0xA6, 0x97, 0x21, 0x10, 0x43, 0x72,
                                                                0xE5, 0xD4, 0x87, 0xB6 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte1_hi[16], 16) = { 0x00, 0x5F, 0xBE, 0xE1, 0xD5, 0x8A,
                                                                0x6B, 0x34, 0x03, 0x5C, 0xBD, 0xE2,
                                                                0xD6, 0x89, 0x68, 0x37 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte2_hi[16], 16) = { 0x00, 0xF0, 0x49, 0xB9, 0x92, 0x62,
                                                                0xDB, 0x2B, 0x8D, 0x7D, 0xC4, 0x34,
                                                                0x1F, 0xEF, 0x56, 0xA6 };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_DIVa_byte3_hi[16], 16) = { 0x00, 0x29, 0x52, 0x7B, 0xA4, 0x8D,
                                                                0xF6, 0xDF, 0xE1, 0xC8, 0xB3, 0x9A,
                                                                0x45, 0x6C, 0x17, 0x3E };

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint8_t snow3g_invSR_SQ[256], 64) = {
        0xC2, 0xA6, 0x8F, 0x0A, 0x0D, 0xBE, 0xA7, 0x08, 0x1D, 0x99, 0x45, 0x59, 0x13, 0xD2, 0x11,
        0x9F, 0xAE, 0xE6, 0xD4, 0xA4, 0x92, 0x8D, 0x58, 0xC1, 0xD0, 0x97, 0xC8, 0x84, 0x9D, 0x4F,
        0xBC, 0x3B, 0x2D, 0xEB, 0x27, 0x53, 0x72, 0x4E, 0xE3, 0xEE, 0xDA, 0x7F, 0xAA, 0x4D, 0x5C,
        0x2F, 0x44, 0xDB, 0x3E, 0x3A, 0x67, 0xC5, 0xC3, 0x6A, 0x16, 0x4C, 0x38, 0xCC, 0xD7, 0xDD,
        0x70, 0x62, 0xF2, 0x19, 0x10, 0x09, 0x98, 0x4B, 0x61, 0xC9, 0x86, 0x03, 0xA8, 0x6B, 0x5A,
        0x33, 0x6E, 0x54, 0x5D, 0x8C, 0x41, 0x1A, 0xF7, 0xF6, 0x82, 0xC6, 0xF8, 0x80, 0xC0, 0xC7,
        0xFE, 0xB3, 0x65, 0x2C, 0x7B, 0xBA, 0xB4, 0xFC, 0x2A, 0x22, 0x0C, 0x73, 0xF5, 0x5F, 0x64,
        0x68, 0x2E, 0x94, 0xB2, 0x24, 0x35, 0x14, 0x78, 0xFB, 0xBF, 0x48, 0xDE, 0xED, 0x43, 0x07,
        0xB6, 0x32, 0xE4, 0xBD, 0x74, 0x7D, 0x57, 0x46, 0x3C, 0x37, 0xC4, 0xB7, 0x51, 0x8A, 0xF3,
        0x55, 0x6C, 0xCF, 0x79, 0xAB, 0x77, 0xA3, 0xE1, 0x93, 0xD5, 0x6D, 0x81, 0x5B, 0x2B, 0x9A,
        0x7E, 0x8B, 0x04, 0xB5, 0x85, 0xD3, 0x91, 0xA1, 0x47, 0x52, 0xA5, 0xEC, 0xD6, 0xBB, 0x20,
        0x87, 0x26, 0xF0, 0xAF, 0x4A, 0x89, 0xF4, 0xCE, 0x25, 0xCB, 0x50, 0x00, 0x3F, 0xD9, 0x42,
        0x90, 0x21, 0x3D, 0xA9, 0xE7, 0x29, 0x01, 0xF1, 0x36, 0x5E, 0xFA, 0xCD, 0xE5, 0x31, 0x1B,
        0x05, 0xFD, 0x9E, 0xA0, 0x76, 0x30, 0xB1, 0x75, 0xB0, 0x9B, 0x56, 0xEA, 0x1C, 0xEF, 0x06,
        0x69, 0x7A, 0x95, 0x88, 0x15, 0xFF, 0xCA, 0xAC, 0x0E, 0x23, 0xD8, 0x0F, 0x28, 0x0B, 0x18,
        0xF9, 0x63, 0x1E, 0x83, 0x66, 0x39, 0x9C, 0xE2, 0x49, 0x1F, 0xE8, 0xD1, 0x34, 0x7C, 0xA2,
        0xB9, 0xE0, 0x02, 0x12, 0xE9, 0xDF, 0xAD, 0x71, 0x96, 0x8E, 0x6F, 0xB8, 0x40, 0x60, 0x17,
        0xDC
};

IMB_DLL_LOCAL
DECLARE_ALIGNED(const uint64_t snow3g_table_S2[256], 32) = {
        0x4a6f25254a6f2525ULL, 0x486c2424486c2424ULL, 0xe6957373e6957373ULL, 0xcea96767cea96767ULL,
        0xc710d7d7c710d7d7ULL, 0x359baeae359baeaeULL, 0xb8e45c5cb8e45c5cULL, 0x6050303060503030ULL,
        0x2185a4a42185a4a4ULL, 0xb55beeeeb55beeeeULL, 0xdcb26e6edcb26e6eULL, 0xff34cbcbff34cbcbULL,
        0xfa877d7dfa877d7dULL, 0x03b6b5b503b6b5b5ULL, 0x6def82826def8282ULL, 0xdf04dbdbdf04dbdbULL,
        0xa145e4e4a145e4e4ULL, 0x75fb8e8e75fb8e8eULL, 0x90d8484890d84848ULL, 0x92db494992db4949ULL,
        0x9ed14f4f9ed14f4fULL, 0xbae75d5dbae75d5dULL, 0xd4be6a6ad4be6a6aULL, 0xf0887878f0887878ULL,
        0xe0907070e0907070ULL, 0x79f1888879f18888ULL, 0xb951e8e8b951e8e8ULL, 0xbee15f5fbee15f5fULL,
        0xbce25e5ebce25e5eULL, 0x61e5848461e58484ULL, 0xcaaf6565caaf6565ULL, 0xad4fe2e2ad4fe2e2ULL,
        0xd901d8d8d901d8d8ULL, 0xbb52e9e9bb52e9e9ULL, 0xf13dccccf13dccccULL, 0xb35eededb35eededULL,
        0x80c0404080c04040ULL, 0x5e712f2f5e712f2fULL, 0x2233111122331111ULL, 0x5078282850782828ULL,
        0xaef95757aef95757ULL, 0xcd1fd2d2cd1fd2d2ULL, 0x319dacac319dacacULL, 0xaf4ce3e3af4ce3e3ULL,
        0x94de4a4a94de4a4aULL, 0x2a3f15152a3f1515ULL, 0x362d1b1b362d1b1bULL, 0x1ba2b9b91ba2b9b9ULL,
        0x0dbfb2b20dbfb2b2ULL, 0x69e9808069e98080ULL, 0x63e6858563e68585ULL, 0x2583a6a62583a6a6ULL,
        0x5c722e2e5c722e2eULL, 0x0406020204060202ULL, 0x8ec947478ec94747ULL, 0x527b2929527b2929ULL,
        0x0e0907070e090707ULL, 0x96dd4b4b96dd4b4bULL, 0x1c120e0e1c120e0eULL, 0xeb2ac1c1eb2ac1c1ULL,
        0xa2f35151a2f35151ULL, 0x3d97aaaa3d97aaaaULL, 0x7bf289897bf28989ULL, 0xc115d4d4c115d4d4ULL,
        0xfd37cacafd37cacaULL, 0x0203010102030101ULL, 0x8cca46468cca4646ULL, 0x0fbcb3b30fbcb3b3ULL,
        0xb758efefb758efefULL, 0xd30eddddd30eddddULL, 0x88cc444488cc4444ULL, 0xf68d7b7bf68d7b7bULL,
        0xed2fc2c2ed2fc2c2ULL, 0xfe817f7ffe817f7fULL, 0x15abbebe15abbebeULL, 0xef2cc3c3ef2cc3c3ULL,
        0x57c89f9f57c89f9fULL, 0x4060202040602020ULL, 0x98d44c4c98d44c4cULL, 0xc8ac6464c8ac6464ULL,
        0x6fec83836fec8383ULL, 0x2d8fa2a22d8fa2a2ULL, 0xd0b86868d0b86868ULL, 0x84c6424284c64242ULL,
        0x2635131326351313ULL, 0x01b5b4b401b5b4b4ULL, 0x82c3414182c34141ULL, 0xf33ecdcdf33ecdcdULL,
        0x1da7baba1da7babaULL, 0xe523c6c6e523c6c6ULL, 0x1fa4bbbb1fa4bbbbULL, 0xdab76d6ddab76d6dULL,
        0x9ad74d4d9ad74d4dULL, 0xe2937171e2937171ULL, 0x4263212142632121ULL, 0x8175f4f48175f4f4ULL,
        0x73fe8d8d73fe8d8dULL, 0x09b9b0b009b9b0b0ULL, 0xa346e5e5a346e5e5ULL, 0x4fdc93934fdc9393ULL,
        0x956bfefe956bfefeULL, 0x77f88f8f77f88f8fULL, 0xa543e6e6a543e6e6ULL, 0xf738cfcff738cfcfULL,
        0x86c5434386c54343ULL, 0x8acf45458acf4545ULL, 0x6253313162533131ULL, 0x4466222244662222ULL,
        0x6e5937376e593737ULL, 0x6c5a36366c5a3636ULL, 0x45d3969645d39696ULL, 0x9d67fafa9d67fafaULL,
        0x11adbcbc11adbcbcULL, 0x1e110f0f1e110f0fULL, 0x1018080810180808ULL, 0xa4f65252a4f65252ULL,
        0x3a271d1d3a271d1dULL, 0xaaff5555aaff5555ULL, 0x342e1a1a342e1a1aULL, 0xe326c5c5e326c5c5ULL,
        0x9cd24e4e9cd24e4eULL, 0x4665232346652323ULL, 0xd2bb6969d2bb6969ULL, 0xf48e7a7af48e7a7aULL,
        0x4ddf92924ddf9292ULL, 0x9768ffff9768ffffULL, 0xb6ed5b5bb6ed5b5bULL, 0xb4ee5a5ab4ee5a5aULL,
        0xbf54ebebbf54ebebULL, 0x5dc79a9a5dc79a9aULL, 0x38241c1c38241c1cULL, 0x3b92a9a93b92a9a9ULL,
        0xcb1ad1d1cb1ad1d1ULL, 0xfc827e7efc827e7eULL, 0x1a170d0d1a170d0dULL, 0x916dfcfc916dfcfcULL,
        0xa0f05050a0f05050ULL, 0x7df78a8a7df78a8aULL, 0x05b3b6b605b3b6b6ULL, 0xc4a66262c4a66262ULL,
        0x8376f5f58376f5f5ULL, 0x141e0a0a141e0a0aULL, 0x9961f8f89961f8f8ULL, 0xd10ddcdcd10ddcdcULL,
        0x0605030306050303ULL, 0x78443c3c78443c3cULL, 0x18140c0c18140c0cULL, 0x724b3939724b3939ULL,
        0x8b7af1f18b7af1f1ULL, 0x19a1b8b819a1b8b8ULL, 0x8f7cf3f38f7cf3f3ULL, 0x7a473d3d7a473d3dULL,
        0x8d7ff2f28d7ff2f2ULL, 0xc316d5d5c316d5d5ULL, 0x47d0979747d09797ULL, 0xccaa6666ccaa6666ULL,
        0x6bea81816bea8181ULL, 0x6456323264563232ULL, 0x2989a0a02989a0a0ULL, 0x0000000000000000ULL,
        0x0c0a06060c0a0606ULL, 0xf53bcecef53bceceULL, 0x8573f6f68573f6f6ULL, 0xbd57eaeabd57eaeaULL,
        0x07b0b7b707b0b7b7ULL, 0x2e3917172e391717ULL, 0x8770f7f78770f7f7ULL, 0x71fd8c8c71fd8c8cULL,
        0xf28b7979f28b7979ULL, 0xc513d6d6c513d6d6ULL, 0x2780a7a72780a7a7ULL, 0x17a8bfbf17a8bfbfULL,
        0x7ff48b8b7ff48b8bULL, 0x7e413f3f7e413f3fULL, 0x3e211f1f3e211f1fULL, 0xa6f55353a6f55353ULL,
        0xc6a56363c6a56363ULL, 0xea9f7575ea9f7575ULL, 0x6a5f35356a5f3535ULL, 0x58742c2c58742c2cULL,
        0xc0a06060c0a06060ULL, 0x936efdfd936efdfdULL, 0x4e6927274e692727ULL, 0xcf1cd3d3cf1cd3d3ULL,
        0x41d5949441d59494ULL, 0x2386a5a52386a5a5ULL, 0xf8847c7cf8847c7cULL, 0x2b8aa1a12b8aa1a1ULL,
        0x0a0f05050a0f0505ULL, 0xb0e85858b0e85858ULL, 0x5a772d2d5a772d2dULL, 0x13aebdbd13aebdbdULL,
        0xdb02d9d9db02d9d9ULL, 0xe720c7c7e720c7c7ULL, 0x3798afaf3798afafULL, 0xd6bd6b6bd6bd6b6bULL,
        0xa8fc5454a8fc5454ULL, 0x161d0b0b161d0b0bULL, 0xa949e0e0a949e0e0ULL, 0x7048383870483838ULL,
        0x080c0404080c0404ULL, 0xf931c8c8f931c8c8ULL, 0x53ce9d9d53ce9d9dULL, 0xa740e7e7a740e7e7ULL,
        0x283c1414283c1414ULL, 0x0bbab1b10bbab1b1ULL, 0x67e0878767e08787ULL, 0x51cd9c9c51cd9c9cULL,
        0xd708dfdfd708dfdfULL, 0xdeb16f6fdeb16f6fULL, 0x9b62f9f99b62f9f9ULL, 0xdd07dadadd07dadaULL,
        0x547e2a2a547e2a2aULL, 0xe125c4c4e125c4c4ULL, 0xb2eb5959b2eb5959ULL, 0x2c3a16162c3a1616ULL,
        0xe89c7474e89c7474ULL, 0x4bda91914bda9191ULL, 0x3f94abab3f94ababULL, 0x4c6a26264c6a2626ULL,
        0xc2a36161c2a36161ULL, 0xec9a7676ec9a7676ULL, 0x685c3434685c3434ULL, 0x567d2b2b567d2b2bULL,
        0x339eadad339eadadULL, 0x5bc299995bc29999ULL, 0x9f64fbfb9f64fbfbULL, 0xe4967272e4967272ULL,
        0xb15dececb15dececULL, 0x6655333366553333ULL, 0x2436121224361212ULL, 0xd50bdeded50bdedeULL,
        0x59c1989859c19898ULL, 0x764d3b3b764d3b3bULL, 0xe929c0c0e929c0c0ULL, 0x5fc49b9b5fc49b9bULL,
        0x7c423e3e7c423e3eULL, 0x3028181830281818ULL, 0x2030101020301010ULL, 0x744e3a3a744e3a3aULL,
        0xacfa5656acfa5656ULL, 0xab4ae1e1ab4ae1e1ULL, 0xee997777ee997777ULL, 0xfb32c9c9fb32c9c9ULL,
        0x3c221e1e3c221e1eULL, 0x55cb9e9e55cb9e9eULL, 0x43d6959543d69595ULL, 0x2f8ca3a32f8ca3a3ULL,
        0x49d9909049d99090ULL, 0x322b1919322b1919ULL, 0x3991a8a83991a8a8ULL, 0xd8b46c6cd8b46c6cULL,
        0x121b0909121b0909ULL, 0xc919d0d0c919d0d0ULL, 0x8979f0f08979f0f0ULL, 0x65e3868665e38686ULL
};
