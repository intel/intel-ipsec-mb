/*****************************************************************************
 Copyright (c) 2024-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef MP_ALLOC_H
#define MP_ALLOC_H

#include <stdlib.h>

/*
 * =============================================================================
 * =============================================================================
 * Basic shared memory allocator
 */

struct allocator {
        void *ptr;
        size_t offset;
        size_t size;
};

/**
 * @brief Simple memory allocator initialization
 *
 * @param a pointer to allocator instance structure
 * @param ptr pointer to memory chunk base pointer
 * @param size memory chunk size in bytes
 */
void
mp_init(struct allocator *a, void *ptr, const size_t size);

/**
 * @brief Simple memory allocator from the shared memory pool
 *
 * @param a pointer to allocator instance structure
 * @param length data size to allocate in bytes
 * @param alignment 0 or any power of 2 to align memory allocation to
 *
 * @return Pointer to allocated memory
 * @retval NULL allocation error
 */
void *
mp_alloc(struct allocator *a, const size_t length, const size_t alignment);

#endif /* MP_ALLOC_H */
