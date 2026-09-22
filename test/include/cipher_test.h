/*******************************************************************************
  Copyright (c) 2023-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef CIPHER_TEST_H
#define CIPHER_TEST_H

#include <stdint.h>
#include <stddef.h>

struct cipher_test {
        size_t ivSize;  /* bits */
        size_t keySize; /* bits */
        size_t tcId;
        const char *key;
        const char *iv;
        const char *msg;
        const char *ct;
        int resultValid;
        size_t msgSize; /* bits */
};

#endif /* CIPHER_TEST_H */
