/*****************************************************************************
 Copyright (c) 2017-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef GCM_CTR_VECTORS_TEST_H_
#define GCM_CTR_VECTORS_TEST_H_

#include <stdint.h>

enum arch_type { ARCH_SSE = 0, ARCH_AVX2, ARCH_AVX512, ARCH_NUMOF };

#define KBITS(K) (sizeof(K))

/* struct to hold pointers to the key, plaintext and ciphertext vectors */
struct gcm_ctr_vector {
        const uint8_t *K;        /* AES Key */
        IMB_KEY_SIZE_BYTES Klen; /* length of key in bits */
        const uint8_t *IV;       /* initial value used by GCM */
        uint64_t IVlen;          /* length of IV in bytes */
        const uint8_t *A;        /* additional authenticated data */
        uint64_t Alen;           /* length of AAD in bytes */
        const uint8_t *P;        /* Plain text */
        uint64_t Plen;           /* length of our plaintext */
        /* outputs of encryption */
        const uint8_t *C; /* same length as PT */
        const uint8_t *T; /* Authentication tag */
        uint8_t Tlen;     /* AT length can be 0 to 128bits */
};

#define vector(N)                                                                                  \
        { K##N, (KBITS(K##N)), IV##N, sizeof(IV##N), A##N,        A##N##_len,                      \
          P##N, sizeof(P##N),  C##N,  T##N,          sizeof(T##N) }

#define extra_vector(N)                                                                            \
        { K##N, (KBITS(K##N)), IV##N, sizeof(IV##N), A##N,        A##N##_len,                      \
          P##N, P##N##_len,    C##N,  T##N,          sizeof(T##N) }
#define ghash_vector(N)                                                                            \
        { K##N, (KBITS(K##N)), NULL, 0, NULL, 0, P##N, sizeof(P##N), NULL, T##N, sizeof(T##N) }
struct MB_MGR;

extern int
gcm_test(IMB_MGR *p_mgr);

#endif /* GCM_CTR_VECTORS_TEST_H_ */
