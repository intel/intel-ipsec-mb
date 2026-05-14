/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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

#include <string.h>

#include "guard_mem.h"

/**
 * @brief Detects page size in bytes
 *
 * @param [in/out] p_page_bytes pointer at which page size in bytes is stored
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 input error
 * @retval -2 sysconf() failed
 */
static int
get_page_size(size_t *p_page_bytes)
{
        if (p_page_bytes == NULL)
                return -1;
#ifdef _WIN32
        SYSTEM_INFO si;

        GetSystemInfo(&si);
        const size_t page_bytes = (size_t) si.dwPageSize;
#else
        const long ret = sysconf(_SC_PAGESIZE);

        if (ret < 0)
                return -2; /* sysconf error */

        const size_t page_bytes = (size_t) ret;
#endif
        *p_page_bytes = page_bytes;
        return 0;
}

void
guard_page_free(struct guard_page *gp)
{
        if (gp == NULL || gp->ptr == NULL)
                return;
#ifdef _WIN32
        VirtualFree(gp->ptr, 0, MEM_RELEASE);
#else
        munmap(gp->ptr, gp->size);
#endif
        memset(gp, 0, sizeof(*gp));
}

/* ========================================================================== */
/* Guard page allocator                                                       */
/* ========================================================================== */

int
guard_page_alloc(struct guard_page *gp)
{
        if (gp == NULL)
                return -1;

        memset(gp, 0, sizeof(*gp));

        size_t page_bytes = 0;
        const int ret = get_page_size(&page_bytes);

        if (ret != 0 || page_bytes == 0)
                return -1;
#ifdef _WIN32
        gp->ptr = VirtualAlloc(NULL, page_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        if (gp->ptr == NULL)
                return -1;
#else
        gp->ptr = mmap(NULL, page_bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (gp->ptr == MAP_FAILED) {
                gp->ptr = NULL;
                return -1;
        }
#endif
        gp->size = page_bytes;
        return 0;
}

/* ========================================================================== */
/* Guard memory allocator                                                     */
/* ========================================================================== */

int
guard_mem_alloc(struct guard_mem *gm, const size_t usable_bytes)
{
        if (gm == NULL)
                return -1;

        memset(gm, 0, sizeof(*gm));

        size_t page_bytes = 0;
        const int ret = get_page_size(&page_bytes);

        if (ret != 0 || page_bytes == 0)
                return -1;

        const size_t usable_bytes_aligned = (usable_bytes + page_bytes - 1) & ~(page_bytes - 1);
        const size_t total_bytes_aligned = page_bytes + usable_bytes_aligned + page_bytes;

#ifdef _WIN32
        gm->base =
                VirtualAlloc(NULL, total_bytes_aligned, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (gm->base == NULL)
                return -1;

        DWORD old_protect;

        /* guard page before */
        if (!VirtualProtect(gm->base, page_bytes, PAGE_NOACCESS, &old_protect)) {
                VirtualFree(gm->base, 0, MEM_RELEASE);
                return -1;
        }
        /* guard page after */
        if (!VirtualProtect((uint8_t *) gm->base + page_bytes + usable_bytes_aligned, page_bytes,
                            PAGE_NOACCESS, &old_protect)) {
                VirtualFree(gm->base, 0, MEM_RELEASE);
                return -1;
        }
#else
        gm->base = mmap(NULL, total_bytes_aligned, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (gm->base == MAP_FAILED) {
                gm->base = NULL;
                return -1;
        }
        /* guard page before */
        if (mprotect(gm->base, page_bytes, PROT_NONE) != 0) {
                munmap(gm->base, total_bytes_aligned);
                gm->base = NULL;
                return -1;
        }
        /* guard page after */
        if (mprotect((uint8_t *) gm->base + page_bytes + usable_bytes_aligned, page_bytes,
                     PROT_NONE) != 0) {
                munmap(gm->base, total_bytes_aligned);
                gm->base = NULL;
                return -1;
        }
#endif

        gm->total = total_bytes_aligned;
        gm->size = usable_bytes_aligned;
        gm->usable = (uint8_t *) gm->base + page_bytes;
        return 0;
}

void
guard_mem_free(struct guard_mem *gm)
{
        if (gm == NULL || gm->base == NULL)
                return;
#ifdef _WIN32
        VirtualFree(gm->base, 0, MEM_RELEASE);
#else
        munmap(gm->base, gm->total);
#endif
        memset(gm, 0, sizeof(*gm));
}
