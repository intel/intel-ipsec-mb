/*****************************************************************************
 Copyright (c) 2019-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "kat_common_aead.h"
#include "utils.h"

int
pon_test(struct IMB_MGR *mb_mgr);

/* === vector 1 */

static const uint8_t KEY1_PON[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };

static const uint8_t IV1_PON[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };

static const uint8_t IN1_PON[] = {
        0x00, 0x20, 0x27, 0x11, 0x00, 0x00, 0x21, 0x23, /* XGEM header */
        0x01, 0x02, 0x03, 0x04,                         /* Ethernet frame */
        0xcd, 0xfb, 0x3c, 0xb6                          /* CRC value */
};

static const uint8_t OUT1_PON[] = {
        0x00, 0x20, 0x27, 0x11, 0x00, 0x00, 0x21, 0x23, /* XGEM header */
        0xC7, 0x62, 0x82, 0xCA,                         /* Ethernet frame */
        0x3E, 0x92, 0xC8, 0x5A                          /* CRC value */
};
#define BIPOUT1_PON  0xA24CD0F9
#define OFFSET1_PON  8
#define LENBIP1_PON  sizeof(IN1_PON)
#define LENCIPH1_PON (LENBIP1_PON - OFFSET1_PON)

/* === vector 2 */

static const uint8_t IN2_PON[] = {
        0x00, 0x40, 0x27, 0x11, 0x00, 0x00, 0x29, 0x3C, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* Ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x00, 0x14, 0xa9, 0x04  /* CRC value */
};

static const uint8_t OUT2_PON[] = {
        0x00, 0x40, 0x27, 0x11, 0x00, 0x00, 0x29, 0x3C, /* XGEM header */
        0xC7, 0x62, 0x82, 0xCA, 0xF6, 0x6F, 0xF5, 0xED,
        0xB7, 0x90, 0x1E, 0x02, 0xEA, 0x38, 0xA1, 0x78
};

#define KEY2_PON     KEY1_PON
#define IV2_PON      IV1_PON
#define BIPOUT2_PON  0x70C6E56C
#define OFFSET2_PON  8
#define LENBIP2_PON  sizeof(IN2_PON)
#define LENCIPH2_PON (LENBIP2_PON - OFFSET2_PON)

/* === vector 3 */

static const uint8_t IN3_PON[] = {
        0x01, 0x00, 0x27, 0x11, 0x00, 0x00, 0x33, 0x0B, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* Ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x81, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x6A, 0xB0,
        0x7E, 0x00, 0x00, 0x04, 0x06, 0x83, 0xBD, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8, 0x01, 0x01,
        0x04, 0xD2, 0x16, 0x2E, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x90, 0x50, 0x10, 0x20,
        0x00, 0xA6, 0x33, 0x00, 0x00, 0x30, 0x31, 0x53, 0xc1, 0xe6, 0x0c /* CRC value */
};

static const uint8_t OUT3_PON[] = {
        0x01, 0x00, 0x27, 0x11, 0x00, 0x00, 0x33, 0x0B, /* XGEM header */
        0xC7, 0x62, 0x82, 0xCA, 0xF6, 0x6F, 0xF5, 0xED, 0xB7, 0x90, 0x1E, 0x02, 0x6B,
        0x2C, 0x08, 0x7D, 0x3C, 0x90, 0xE8, 0x2C, 0x44, 0x30, 0x03, 0x29, 0x5F, 0x88,
        0xA9, 0xD6, 0x1E, 0xF9, 0xD1, 0xF1, 0xD6, 0x16, 0x8C, 0x72, 0xA4, 0xCD, 0xD2,
        0x8F, 0x63, 0x26, 0xC9, 0x66, 0xB0, 0x65, 0x24, 0x9B, 0x60, 0x5B, 0x18, 0x60,
        0xBD, 0xD5, 0x06, 0x13, 0x40, 0xC9, 0x60, 0x64, 0x36, 0x5F, 0x86, 0x8C
};
#define KEY3_PON     KEY1_PON
#define IV3_PON      IV1_PON
#define BIPOUT3_PON  0xFBADE0DF
#define OFFSET3_PON  8
#define LENBIP3_PON  sizeof(IN3_PON)
#define LENCIPH3_PON (LENBIP3_PON - OFFSET3_PON)

/* === vector 4 */

static const uint8_t IN4_PON[] = {
        0x01, 0x10, 0x27, 0x11, 0x00, 0x00, 0x3C, 0x18, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* Ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x81, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x6A, 0x70, 0x63, 0x00, 0x00, 0x04, 0x06, 0xC3, 0xD8, 0xC0, 0xA8,
        0x00, 0x01, 0xC0, 0xA8, 0x01, 0x01, 0x04, 0xD2, 0x16, 0x2E, 0x12, 0x34,
        0x56, 0x78, 0x12, 0x34, 0x56, 0x90, 0x50, 0x10, 0x20, 0x00, 0xA6, 0x33,
        0x00, 0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x49, 0x0d, 0x52, 0xab /* CRC value */
};

static const uint8_t OUT4_PON[] = {
        0x01, 0x10, 0x27, 0x11, 0x00, 0x00, 0x3C, 0x18, /* XGEM header */
        0xC7, 0x62, 0x82, 0xCA, 0xF6, 0x6F, 0xF5, 0xED, /* Ethernet frame */
        0xB7, 0x90, 0x1E, 0x02, 0x6B, 0x2C, 0x08, 0x7D, 0x3C, 0x90, 0xE8, 0x2C, 0x44, 0x30, 0xC3,
        0x34, 0x5F, 0x88, 0xA9, 0xD6, 0x5E, 0x9C, 0xD1, 0xF1, 0xD6, 0x16, 0x8C, 0x72, 0xA4, 0xCD,
        0xD2, 0x8F, 0x63, 0x26, 0xC9, 0x66, 0xB0, 0x65, 0x24, 0x9B, 0x60, 0x5B, 0x18, 0x60, 0xBD,
        0xD5, 0x06, 0x13, 0x40, 0xC9, 0x60, 0x64, 0x57, 0xAD, 0x54, 0xB5, 0xD9, 0xEA, 0x01, 0xB2
};
#define KEY4_PON     KEY1_PON
#define IV4_PON      IV1_PON
#define BIPOUT4_PON  0x7EB18D27
#define OFFSET4_PON  8
#define LENBIP4_PON  sizeof(IN4_PON)
#define LENCIPH4_PON (LENBIP4_PON - OFFSET4_PON)

/* Vectors with no encryption */
static const uint8_t IN5_PON[] = {
        0x00, 0x20, 0x27, 0x11, 0x00, 0x00, 0x21, 0x23, /* XGEM header */
        0x01, 0x02, 0x03, 0x04,                         /* Ethernet frame */
        0xCD, 0xFB, 0x3C, 0xB6                          /* CRC value */
};

static const uint8_t OUT5_PON[] = {
        0x00, 0x20, 0x27, 0x11, 0x00, 0x00, 0x21, 0x23, /* XGEM header */
        0x01, 0x02, 0x03, 0x04,                         /* Ethernet frame */
        0xCD, 0xFB, 0x3C, 0xB6                          /* CRC value */
};
#define BIPOUT5_PON  0x8039D9CC
#define OFFSET5_PON  8
#define LENBIP5_PON  sizeof(IN5_PON)
#define LENCIPH5_PON (LENBIP5_PON - OFFSET5_PON)

static const uint8_t IN6_PON[] = {
        0x00, 0x40, 0x27, 0x11, 0x00, 0x00, 0x29, 0x3C, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* Ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x00, 0x14, 0xa9, 0x04  /* CRC value */
};

static const uint8_t OUT6_PON[] = {
        0x00, 0x40, 0x27, 0x11, 0x00, 0x00, 0x29, 0x3C, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* Ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x00, 0x14, 0xa9, 0x04
};

#define BIPOUT6_PON  0x2DA45105
#define OFFSET6_PON  8
#define LENBIP6_PON  sizeof(IN6_PON)
#define LENCIPH6_PON (LENBIP6_PON - OFFSET6_PON)

static const uint8_t IN7_PON[] = {
        0x01, 0x00, 0x27, 0x11, 0x00, 0x00, 0x33, 0x0B, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x81, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x6a, 0xb0,
        0x7e, 0x00, 0x00, 0x04, 0x06, 0x83, 0xbd, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x01, 0x01,
        0x04, 0xd2, 0x16, 0x2e, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x90, 0x50, 0x10, 0x20,
        0x00, 0xa6, 0x33, 0x00, 0x00, 0x30, 0x31, 0x53, 0xC1, 0xE6, 0x0C /* CRC value */
};

static const uint8_t OUT7_PON[] = {
        0x01, 0x00, 0x27, 0x11, 0x00, 0x00, 0x33, 0x0B, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x81, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x6a,
        0xb0, 0x7e, 0x00, 0x00, 0x04, 0x06, 0x83, 0xbd, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
        0x01, 0x01, 0x04, 0xd2, 0x16, 0x2e, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x90,
        0x50, 0x10, 0x20, 0x00, 0xa6, 0x33, 0x00, 0x00, 0x30, 0x31, 0x53, 0xC1, 0xE6, 0x0C
};
#define BIPOUT7_PON  0xABC2D56A
#define OFFSET7_PON  8
#define LENBIP7_PON  sizeof(IN7_PON)
#define LENCIPH7_PON (LENBIP7_PON - OFFSET7_PON)

static const uint8_t IN8_PON[] = {
        0x01, 0x10, 0x27, 0x11, 0x00, 0x00, 0x3C, 0x18, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* Ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x81, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x6A, 0x70, 0x63, 0x00, 0x00, 0x04, 0x06, 0xC3, 0xD8, 0xC0, 0xA8,
        0x00, 0x01, 0xC0, 0xA8, 0x01, 0x01, 0x04, 0xD2, 0x16, 0x2E, 0x12, 0x34,
        0x56, 0x78, 0x12, 0x34, 0x56, 0x90, 0x50, 0x10, 0x20, 0x00, 0xA6, 0x33,
        0x00, 0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x49, 0x0D, 0x52, 0xAB /* CRC value */
};

static const uint8_t OUT8_PON[] = {
        0x01, 0x10, 0x27, 0x11, 0x00, 0x00, 0x3C, 0x18, /* XGEM header */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01, /* Ethernet frame */
        0x01, 0x01, 0x01, 0x01, 0x81, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x6A, 0x70, 0x63, 0x00, 0x00, 0x04, 0x06, 0xC3, 0xD8, 0xC0, 0xA8,
        0x00, 0x01, 0xC0, 0xA8, 0x01, 0x01, 0x04, 0xD2, 0x16, 0x2E, 0x12, 0x34,
        0x56, 0x78, 0x12, 0x34, 0x56, 0x90, 0x50, 0x10, 0x20, 0x00, 0xA6, 0x33,
        0x00, 0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x49, 0x0D, 0x52, 0xAB /* CRC value */
};
#define BIPOUT8_PON  0x378D5F02
#define OFFSET8_PON  8
#define LENBIP8_PON  sizeof(IN8_PON)
#define LENCIPH8_PON (LENBIP8_PON - OFFSET8_PON)

/* Vectors with encryption and with padding */
/* === vector 9 */
static const uint8_t IN9_PON[] = {
        0x00, 0x39, 0x03, 0xfd, 0x00, 0x00, 0xb3, 0x6a, /* XGEM header */
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* Ethernet frame */
        0x10, 0x11, 0x8c, 0xd0, 0x9a, 0x8b,             /* CRC value */
        0x55, 0x55                                      /* XGEM padding */
};

static const uint8_t OUT9_PON[] = {
        0x00, 0x39, 0x03, 0xfd, 0x00, 0x00, 0xb3, 0x6a, /* XGEM header */
        0x73, 0xe0, 0x5d, 0x5d, 0x32, 0x9c, 0x3b, 0xfa, /* Ethernet frame */
        0x6b, 0x66, 0xf6, 0x8e, 0x5b, 0xd5,             /* CRC value */
        0xab, 0xcd                                      /* XGEM padding */
};

#define KEY9_PON KEY1_PON

static const uint8_t IV9_PON[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
#define BIPOUT9_PON  0x738bf671
#define OFFSET9_PON  8
#define LENBIP9_PON  sizeof(IN9_PON)
#define LENCIPH9_PON (LENBIP9_PON - OFFSET9_PON)

/* === vector 10 */

/* This is fragmented frame (1 bytes payload + padding)
 * - computed CRC will not match value in the message
 * - on encrypt CRC should not be written into the message
 */
static const uint8_t IN10_PON[] = {
        0x00, 0x05, 0x03, 0xfd, 0x00, 0x00, 0xb9, 0xb4, /* XGEM header */
        0x08,                                           /* Ethernet frame */
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55        /* XGEM padding */
};

static const uint8_t OUT10_PON[] = {
        0x00, 0x05, 0x03, 0xfd, 0x00, 0x00, 0xb9, 0xb4, /* XGEM header */
        0x73,                                           /* Ethernet frame */
        0xbc, 0x02, 0x03, 0x6b, 0xc4, 0x60, 0xa0        /* XGEM padding */
};

#define KEY10_PON     KEY1_PON
#define IV10_PON      IV9_PON
#define BIPOUT10_PON  0xead87d18
#define OFFSET10_PON  8
#define LENBIP10_PON  sizeof(IN10_PON)
#define LENCIPH10_PON (LENBIP10_PON - OFFSET10_PON)

/* Vectors with no encryption and with padding */
/* === vector 11 */
static const uint8_t IN11_PON[] = {
        0x00, 0x39, 0x03, 0xfd, 0x00, 0x00, 0xb3, 0x6a, /* XGEM header */
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* Ethernet frame */
        0x10, 0x11, 0x8c, 0xd0, 0x9a, 0x8b,             /* CRC value */
        0x55, 0x55                                      /* XGEM padding */
};

static const uint8_t OUT11_PON[] = {
        0x00, 0x39, 0x03, 0xfd, 0x00, 0x00, 0xb3, 0x6a, /* XGEM header */
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* Ethernet frame */
        0x10, 0x11, 0x8c, 0xd0, 0x9a, 0x8b,             /* CRC value */
        0x55, 0x55                                      /* XGEM padding */
};

#define KEY11_PON     KEY1_PON
#define BIPOUT11_PON  0x166da78e
#define OFFSET11_PON  8
#define LENBIP11_PON  sizeof(IN11_PON)
#define LENCIPH11_PON (LENBIP11_PON - OFFSET11_PON)

/* === vector 12 */

/* This is fragmented frame (1 bytes payload + padding)
 * - computed CRC will not match value in the message
 * - on encrypt CRC should not be written into the message
 */
static const uint8_t IN12_PON[] = {
        0x00, 0x05, 0x03, 0xfd, 0x00, 0x00, 0xb9, 0xb4, /* XGEM header */
        0x08,                                           /* Ethernet frame */
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55        /* XGEM padding */
};

static const uint8_t OUT12_PON[] = {
        0x00, 0x05, 0x03, 0xfd, 0x00, 0x00, 0xb9, 0xb4, /* XGEM header */
        0x08,                                           /* Ethernet frame */
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55        /* XGEM padding */
};

#define KEY12_PON     KEY1_PON
#define BIPOUT12_PON  0x49ba055d
#define OFFSET12_PON  8
#define LENBIP12_PON  sizeof(IN12_PON)
#define LENCIPH12_PON (LENBIP12_PON - OFFSET12_PON)

/* === vector 13 */

/* This is fragmented frame (4 bytes payload + padding)
 * - computed CRC will not match value in the message
 * - on encrypt CRC should not be written into the message
 */
static const uint8_t IN13_PON[] = {
        0x00, 0x11, 0x03, 0xfd, 0x00, 0x00, 0xbf, 0xff, /* XGEM header */
        0x08, 0x09, 0x0a, 0x0b,                         /* Ethernet frame */
        0x55, 0x55, 0x55, 0x55                          /* XGEM padding */
};

static const uint8_t OUT13_PON[] = {
        0x00, 0x11, 0x03, 0xfd, 0x00, 0x00, 0xbf, 0xff, /* XGEM header */
        0x73, 0xe0, 0x5d, 0x5d,                         /* Ethernet frame */
        0x6b, 0xc4, 0x60, 0xa0                          /* XGEM padding */
};

#define KEY13_PON     KEY1_PON
#define IV13_PON      IV9_PON
#define BIPOUT13_PON  0xff813518
#define OFFSET13_PON  8
#define LENBIP13_PON  sizeof(IN13_PON)
#define LENCIPH13_PON (LENBIP13_PON - OFFSET13_PON)

#define ponvector(tname)                                                                           \
        { KEY##tname,    IV##tname,     IN##tname,      OUT##tname,                                \
          BIPOUT##tname, LENBIP##tname, LENCIPH##tname, OFFSET##tname }

#define pon_no_ctr_vector(tname)                                                                   \
        { NULL,          NULL,          IN##tname,      OUT##tname,                                \
          BIPOUT##tname, LENBIP##tname, LENCIPH##tname, OFFSET##tname }

static const struct pon_test_vector {
        const uint8_t *key;
        const uint8_t *iv;
        const uint8_t *in;
        const uint8_t *out;
        const uint32_t bip_out;
        size_t length_to_bip;
        size_t length_to_cipher;
        size_t offset_to_crc_cipher;
} pon_vectors[] = {
        ponvector(1_PON),         ponvector(2_PON),          ponvector(3_PON),
        ponvector(4_PON),         pon_no_ctr_vector(5_PON),  pon_no_ctr_vector(6_PON),
        pon_no_ctr_vector(7_PON), pon_no_ctr_vector(8_PON),  ponvector(9_PON),
        ponvector(10_PON),        pon_no_ctr_vector(11_PON), pon_no_ctr_vector(12_PON),
        ponvector(13_PON),
};

struct pon_job_ctx {
        const void *expkey;
        const void *iv;
        const uint8_t *in_text;
        const uint8_t *out_text;
        size_t len_to_cipher;
        size_t len_to_bip;
        size_t offset_to_cipher_crc;
        uint32_t bip_out;
        int dir;
        int order;
        uint8_t *target;
        uint64_t tag_output;
};

static int
pon_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, void *ctx_in)
{
        if (ctx_in == NULL)
                return -1;

        struct pon_job_ctx *ctx = ctx_in;
        const uint16_t pli =
                ((((uint16_t) ctx->in_text[0]) << 8) | ((uint16_t) ctx->in_text[1])) >> 2;

        (void) mb_mgr;

        ctx->target = malloc(ctx->len_to_bip);
        if (ctx->target == NULL)
                return -1;

        if (ctx->dir == IMB_DIR_ENCRYPT) {
                memcpy(ctx->target, ctx->in_text, ctx->len_to_bip);
                ctx->target[7] ^= 0xff;
                if (pli > 4) {
                        uint8_t *p_crc = &ctx->target[8 + pli - 4];

                        p_crc[0] ^= 0xff;
                        p_crc[1] ^= 0xff;
                        p_crc[2] ^= 0xff;
                        p_crc[3] ^= 0xff;
                }
        } else {
                memcpy(ctx->target, ctx->out_text, ctx->len_to_bip);
        }

        job->cipher_direction = ctx->dir;
        job->chain_order = ctx->order;
        job->dst = ctx->target + ctx->offset_to_cipher_crc;
        job->src = ctx->target;
        job->cipher_mode = IMB_CIPHER_PON_AES_CNTR;
        job->cipher_start_src_offset_in_bytes = (uint64_t) ctx->offset_to_cipher_crc;

        if (ctx->iv != NULL) {
                job->enc_keys = ctx->expkey;
                job->dec_keys = ctx->expkey;
                job->key_len_in_bytes = IMB_KEY_128_BYTES;
                job->iv = ctx->iv;
                job->iv_len_in_bytes = 16;
                job->msg_len_to_cipher_in_bytes = (uint64_t) ctx->len_to_cipher;
        } else {
                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->key_len_in_bytes = 0;
                job->iv = NULL;
                job->iv_len_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = 0;
        }

        job->hash_alg = IMB_AUTH_PON_CRC_BIP;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = (uint64_t) ctx->len_to_bip;
        job->auth_tag_output = (uint8_t *) &ctx->tag_output;
        job->auth_tag_output_len_in_bytes = (uint64_t) sizeof(ctx->tag_output);
        return 0;
}

static void
pon_job_cleanup(struct IMB_JOB *job, void *ctx_in)
{
        (void) job;
        if (ctx_in != NULL) {
                struct pon_job_ctx *ctx = ctx_in;

                free(ctx->target);
                ctx->target = NULL;
        }
}

static int
pon_job_validate(struct IMB_JOB *job, const void *ctx_in)
{
        if (ctx_in == NULL)
                return -1;

        const struct pon_job_ctx *ctx = ctx_in;
        const uint32_t bip_output = (uint32_t) ctx->tag_output;
        const uint32_t crc_output = (uint32_t) (ctx->tag_output >> 32);

        (void) job;

#ifdef DEBUG
        if (!quiet_mode) {
                printf("CRC received 0x%08x\n", crc_output);
                printf("BIP received 0x%08x\n", bip_output);
        }
#endif

        if (ctx->dir == IMB_DIR_DECRYPT) {
                const uint16_t pli =
                        ((((uint16_t) ctx->in_text[0]) << 8) | ((uint16_t) ctx->in_text[1])) >> 2;

                if (pli > 4) {
                        /* The CRC sits at an arbitrary offset in the message.
                         * x86 loads it misaligned without trouble, but a
                         * misaligned uint32_t dereference is undefined
                         * behaviour in C and is reported by UBSan, so use
                         * memcpy() to express the same load. */
                        uint32_t crc_in_msg;

                        memcpy(&crc_in_msg, &ctx->in_text[8 + pli - 4], sizeof(crc_in_msg));
                        if (crc_in_msg != crc_output) {
                                printf("CRC mismatch on decrypt! "
                                       "expected 0x%08x, received 0x%08x\n",
                                       crc_in_msg, crc_output);
                                return -1;
                        }
                }
        }

        if (bip_output != ctx->bip_out) {
                printf("BIP mismatch! expected 0x%08x, received 0x%08x\n", ctx->bip_out,
                       bip_output);
                return -1;
        }

        if (ctx->dir == IMB_DIR_ENCRYPT) {
                if (memcmp(ctx->out_text, ctx->target, ctx->len_to_bip)) {
                        printf("output mismatch\n");
                        hexdump(stderr, "Target", ctx->target, ctx->len_to_bip);
                        return -1;
                }
        } else {
                if (memcmp(ctx->in_text, ctx->target, ctx->len_to_bip - 4)) {
                        printf("output mismatch\n");
                        hexdump(stderr, "Target", ctx->target, ctx->len_to_bip);
                        return -1;
                }
        }

        return 0;
}

static int
test_pon(struct IMB_MGR *mb_mgr, const void *expkey, const void *iv, const uint8_t *in_text,
         const uint8_t *out_text, const size_t len_to_cipher, const size_t len_to_bip,
         const size_t offset_to_cipher_crc, const uint32_t bip_out, const int dir, const int order)
{
        struct pon_job_ctx ctx = {
                .expkey = expkey,
                .iv = iv,
                .in_text = in_text,
                .out_text = out_text,
                .len_to_cipher = len_to_cipher,
                .len_to_bip = len_to_bip,
                .offset_to_cipher_crc = offset_to_cipher_crc,
                .bip_out = bip_out,
                .dir = dir,
                .order = order,
                .target = NULL,
                .tag_output = 0,
        };

        const struct kat_custom_job_ops ops = {
                .prepare = pon_job_prepare,
                .cleanup = pon_job_cleanup,
                .validate = pon_job_validate,
                .ctx = &ctx,
        };

        if (kat_aead_test_custom_submit_flush(mb_mgr, &ops, 1) < 0)
                return -1;

        return 0;
}

static int
test_pon_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx)
{
        const int vectors_cnt = sizeof(pon_vectors) / sizeof(pon_vectors[0]);
        int vect;
        int errors = 0;
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        printf("PON (AES128-CTR/CRC/BIP) test vectors:\n");

        for (vect = 0; vect < vectors_cnt; vect++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Vector %d/%d CIPHLen:%d BIPLen:%d\n", vect + 1, vectors_cnt,
                               (int) pon_vectors[vect].length_to_cipher,
                               (int) pon_vectors[vect].length_to_bip);
#else
                        printf(".");
#endif
                }

                if (pon_vectors[vect].key != NULL)
                        IMB_AES_KEYEXP_128(mb_mgr, pon_vectors[vect].key, expkey, dust);

                if (test_pon(mb_mgr, expkey, pon_vectors[vect].iv, pon_vectors[vect].in,
                             pon_vectors[vect].out, pon_vectors[vect].length_to_cipher,
                             pon_vectors[vect].length_to_bip,
                             pon_vectors[vect].offset_to_crc_cipher, pon_vectors[vect].bip_out,
                             IMB_DIR_ENCRYPT, IMB_ORDER_HASH_CIPHER)) {
                        printf("error #%d encrypt\n", vect + 1);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);

                if (test_pon(mb_mgr, expkey, pon_vectors[vect].iv, pon_vectors[vect].in,
                             pon_vectors[vect].out, pon_vectors[vect].length_to_cipher,
                             pon_vectors[vect].length_to_bip,
                             pon_vectors[vect].offset_to_crc_cipher, pon_vectors[vect].bip_out,
                             IMB_DIR_DECRYPT, IMB_ORDER_CIPHER_HASH)) {
                        printf("error #%d decrypt\n", vect + 1);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);
        }
        if (!quiet_mode)
                printf("\n");
        return errors;
}

int
pon_test(struct IMB_MGR *mb_mgr)
{
        int errors;
        struct test_suite_context ctx;

        test_suite_start(&ctx, "PON-128-BIP-CRC32");
        test_pon_std_vectors(mb_mgr, &ctx);
        errors = test_suite_end(&ctx);

        return errors;
}
