/*****************************************************************************
 Copyright (c) 2020-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "intel-ipsec-mb.h"
#include "gcm_ctr_vectors_test.h"
#include "utils.h"

#define MAX_RAND 1024
#define PATTERN  0x66

int
clear_mem_test(struct IMB_MGR *mb_mgr);

/* validate expected bytes */
static int
validate_bytes_zero(const uint8_t *ptr, const int mem_size)
{
        int i;
        const uint8_t *p = ptr;

        for (i = 0; i < mem_size; i++) {

                if (*p != 0) {
                        printf("Byte mismatch -- found 0x%x!\n"
                               "Byte Offset = %u\n",
                               *p, (unsigned) (p - ptr));
                        return 1;
                }
                p++;
        }

        return 0;
}

/* print bytes */
static void
print_bytes(uint8_t *ptr, int size)
{
        int i;

        for (i = 0; i < size; i++)
                printf("0x%x, ", *(ptr + i));

        printf("\n");
}

int
clear_mem_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        (void) mb_mgr;

        int i, errors;
        uint8_t *buf, padding[16];
        unsigned seed = 7890;

        printf("Clear memory API test:\n");

        memset(padding, 0xff, sizeof(padding));
        srand(seed);

        test_suite_start(&ctx, "CLEAR-MEM");
        for (i = 0; i < 100; i++) {
                const unsigned r = (rand() % MAX_RAND) + sizeof(padding) * 2 + 1;
                const int sz = r - (sizeof(padding) * 2);
                uint8_t *clear_zn;

                /* allocate buffer of random size */
                buf = malloc(r);
                if (buf == NULL) {
                        printf("Failed to allocate buffer memory!\n");
                        test_suite_update(&ctx, 0, 1);
                        break;
                }

                /* set whole buffer to 1's */
                memset(buf, 0xff, r);

                /* set zone to be cleared - after 16 bytes of padding */
                clear_zn = buf + sizeof(padding);

                /* set pattern to clear in clear zone */
                memset(clear_zn, PATTERN, sz);

                /* clear memory */
                imb_clear_mem(clear_zn, sz);

                /* validate memory cleared and head/tail not overwritten */
                if (validate_bytes_zero(clear_zn, sz)) {
                        printf("Found non-zero bytes in clear zone!\n");
                        print_bytes(clear_zn, sz);
                        test_suite_update(&ctx, 0, 1);
                } else
                        test_suite_update(&ctx, 1, 0);

                /* validate head */
                if (memcmp(buf, padding, sizeof(padding)) != 0) {
                        printf("Found mismatch in head!\n");
                        print_bytes(padding, sizeof(padding));
                        test_suite_update(&ctx, 0, 1);
                } else
                        test_suite_update(&ctx, 1, 0);

                /* validate tail */
                if (memcmp(buf + sizeof(padding) + sz, padding, sizeof(padding)) != 0) {
                        printf("Found mismatch in tail!\n");
                        print_bytes(buf + sizeof(padding) + sz, sizeof(padding));
                        test_suite_update(&ctx, 0, 1);
                } else
                        test_suite_update(&ctx, 1, 0);

                free(buf);

                if (!quiet_mode)
                        printf(".");
        }
        if (!quiet_mode)
                printf("\n");

        errors = test_suite_end(&ctx);

        return errors;
}
