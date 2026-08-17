/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef MAC_TEST_H
#define MAC_TEST_H

#include <stdint.h>
#include <stddef.h>

struct mac_test {
        size_t keySize; /* bits */
        size_t tagSize; /* bits */
        size_t tcId;
        const char *key;
        const char *msg;
        const char *tag;
        int resultValid;
        size_t msgSize; /* bits */
        const char *iv;
        size_t ivSize; /* bits */
};

#endif /* MAC_TEST_H */
