/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef IMB_CT_H
#define IMB_CT_H

#include <stddef.h>

#ifdef IMB_CONSTANT_TIME_VALIDATION

#include <valgrind/memcheck.h>

/**
 * @brief Marks a memory region as secret or public
 *
 * Valgrind's memcheck tool will then flag any control-flow branch or
 * memory index that depends on those bytes as an error.
 *
 * @param ptr start of the region, may be NULL
 * @param len size of the region in bytes, may be 0
 * @param is_secret region is secret if non-zero and public if zero
 */
static inline void
imb_ct_secret(const void *ptr, const size_t len, const int is_secret)
{
        if (ptr != NULL && len != 0) {
                if (is_secret)
                        VALGRIND_MAKE_MEM_UNDEFINED(ptr, len);
                else
                        VALGRIND_MAKE_MEM_DEFINED(ptr, len);
        }
}

#endif /* IMB_CONSTANT_TIME_VALIDATION */

#endif /* IMB_CT_H */
