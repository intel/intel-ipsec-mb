/*******************************************************************************
  Copyright (c) 2019-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <string.h>

#include "intel-ipsec-mb.h"
#include "include/wireless_common.h"

int
snow3g_f8_iv_gen(const uint32_t count, const uint8_t bearer, const uint8_t dir, void *iv_ptr)
{
        uint32_t *iv32 = (uint32_t *) iv_ptr;

        if (iv_ptr == NULL)
                return -1;

        /* Bearer must contain 5 bits only */
        if (bearer >= (1 << 5))
                return -1;

        /* Direction must contain 1 bit only */
        if (dir > 1)
                return -1;
        /**
         * Parameters are passed in Little Endian format
         * and reversed to generate the IV in Big Endian format
         */
        /* IV[3] = BEARER || DIRECTION || 0s */
        iv32[3] = bswap4((bearer << 27) | (dir << 26));

        /* IV[2] = COUNT */
        iv32[2] = bswap4(count);

        /* IV[1] = BEARER || DIRECTION || 0s */
        iv32[1] = iv32[3];

        /* IV[0] = COUNT */
        iv32[0] = iv32[2];

        return 0;
}

int
snow3g_f9_iv_gen(const uint32_t count, const uint32_t fresh, const uint8_t dir, void *iv_ptr)
{
        uint32_t *iv32 = (uint32_t *) iv_ptr;

        if (iv_ptr == NULL)
                return -1;

        /* Direction must contain 1 bit only */
        if (dir > 1)
                return -1;
        /**
         * Parameters are passed in Little Endian format
         * and reversed to generate the IV in Big Endian format
         */
        /* IV[3] = FRESH ^ (DIRECTION[0] << 17) */
        const uint32_t dir_b15 = dir ? (1UL << 15) : 0;

        /* IV[2] = DIRECTION[0] ^ COUNT[0-31] */
        const uint32_t dir_b31 = dir ? (1UL << 31) : 0;

        iv32[3] = bswap4(fresh ^ dir_b15);

        iv32[2] = bswap4(count ^ dir_b31);

        /* IV[1] = FRESH */
        iv32[1] = bswap4(fresh);

        /* IV[0] = COUNT */
        iv32[0] = bswap4(count);

        return 0;
}
