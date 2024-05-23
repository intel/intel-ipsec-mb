/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

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
