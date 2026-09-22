/*******************************************************************************
  Copyright (c) 2019-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <string.h>

#include "intel-ipsec-mb.h"
#include "include/wireless_common.h"

int
kasumi_f8_iv_gen(const uint32_t count, const uint8_t bearer, const uint8_t dir, void *iv_ptr)
{
        uint8_t *iv = (uint8_t *) iv_ptr;
        uint32_t *iv32 = (uint32_t *) iv_ptr;

        if (iv_ptr == NULL)
                return -1;

        /* Bearer must contain 5 bits only */
        if (bearer >= (1 << 5))
                return -1;

        /* Direction must contain 1 bit only */
        if (dir > 1)
                return -1;

        /* IV[0-3] = COUNT */
        iv32[0] = bswap4(count);

        /* IV[4] = BEARER || DIRECTION || 0s */
        iv[4] = (bearer << 3) + (dir << 2);

        /* IV[5-7] = Os */
        memset(&iv[5], 0, 3);

        return 0;
}

int
kasumi_f9_iv_gen(const uint32_t count, const uint32_t fresh, void *iv_ptr)
{
        uint32_t *iv32 = (uint32_t *) iv_ptr;

        if (iv_ptr == NULL)
                return -1;

        /* IV[0-3] = COUNT */
        iv32[0] = bswap4(count);

        /* IV[4-7] = FRESH */
        iv32[1] = bswap4(fresh);

        return 0;
}
