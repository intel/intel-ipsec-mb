/*****************************************************************************
 Copyright (c) 2024-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include "mp_alloc.h"

void
mp_init(struct allocator *a, void *ptr, const size_t size)
{
        a->ptr = ptr;
        a->size = size;
        a->offset = 0;
}

void *
mp_alloc(struct allocator *a, const size_t length, const size_t alignment)
{
        if (a->ptr == NULL)
                return NULL;

        if ((a->offset + length) > a->size)
                return NULL;

        if (alignment > 1) {
                const size_t align_mask = alignment - 1;

                a->offset = (a->offset + align_mask) & (~align_mask);
        }

        void *ptr = ((char *) a->ptr + a->offset);

        a->offset += length;

        return ptr;
}
