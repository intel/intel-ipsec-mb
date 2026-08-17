/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef GUARD_MEM_H
#define GUARD_MEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

/** Opaque handle for a guard-page allocation */
struct guard_page {
        void *ptr;   /**< pointer to start of unmapped page */
        size_t size; /**< allocation size (one page) */
};

/**
 * @brief Allocate a single page with no access permissions (guard page).
 *
 * Any read or write to the returned pointer triggers a fault.
 *
 * @param [in/out] gp guard page structure to initialize
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 failure
 */
int
guard_page_alloc(struct guard_page *gp);

/**
 * @brief Free a guard page allocation.
 *
 * @param [in] gp guard page structure to free
 */
void
guard_page_free(struct guard_page *gp);

/**
 * @brief Usable memory region adjacent to a guard page.
 *
 * Used for both overrun and underrun detection depending on the layout.
 */
struct guard_mem {
        void *base;   /**< base of allocation */
        size_t total; /**< total allocation size */
        void *usable; /**< pointer to usable region */
        size_t size;  /**< usable size in bytes */
};

/**
 * @brief Allocate RW region with guard pages on both sides.
 *
 * Layout: [ Guard page (PROT_NONE) ][ RW page(s) ][ Guard page (PROT_NONE) ]
 *
 * A single allocation handles both overrun and underrun detection.
 * Callers can place data at the end of the usable RW region to detect
 * overruns, or at the start of the usable RW region to detect underruns.
 *
 * @param [in/out] gm           guard memory structure to initialize
 * @param [in]     usable_bytes bytes of usable memory needed
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 allocation failed
 */
int
guard_mem_alloc(struct guard_mem *gm, const size_t usable_bytes);

/**
 * @brief Free a guard memory allocation.
 *
 * @param [in] gm guard memory structure to free
 */
void
guard_mem_free(struct guard_mem *gm);

#endif /* GUARD_MEM_H */
