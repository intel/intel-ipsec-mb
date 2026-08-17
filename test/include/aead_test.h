/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef AEAD_TEST_H
#define AEAD_TEST_H

#include <stdint.h>
#include <stddef.h>

struct aead_test {
        size_t ivSize;  /* bits */
        size_t keySize; /* bits */
        size_t tagSize; /* bits */
        size_t tcId;
        const char *key;
        const char *iv;
        const char *aad;
        const char *msg;
        const char *ct;
        const char *tag;
        int resultValid;
        size_t aadSize; /* bits */
        size_t msgSize; /* bits */
};

#endif /* AEAD_TEST_H */
