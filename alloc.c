/*******************************************************************************
  Copyright (c) 2018, Intel Corporation

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
*******************************************************************************/

#include <stdint.h>
#ifdef LINUX
#include <stdlib.h> /* posix_memalign() and free() */
#else
#include <malloc.h> /* _aligned_malloc() and aligned_free() */
#endif
#include "mb_mgr.h"
#include "os.h"

/**
 * @brief Allocates memory for multi-buffer manager instance
 *
 * For binary compatibility between library versions
 * it is recommended to use this API.
 *
 * @param flags multi-buffer manager flags
 *     IMB_FLAG_SHANI_OFF - disable use (and detection) of SHA extenstions,
 *                          currently SHANI is only available for SSE
 *
 * @return Pointer to allocated memory for MB_MGR structure
 * @retval NULL on allocation error
 */
MB_MGR *alloc_mb_mgr(uint64_t flags)
{
        const size_t alignment = 64;
        const size_t size = sizeof(MB_MGR);
        MB_MGR *ptr = NULL;

#ifdef LINUX
        if (posix_memalign((void **)&ptr, alignment, size))
                return NULL;
#else
        ptr = _aligned_malloc(size, alignment);
#endif
        if (ptr != NULL)
                ptr->flags = flags; /* save the flags for future use in init */

        IMB_ASSERT(ptr != NULL);
        return ptr;
}

/**
 * @brief Frees memory allocated previously by alloc_mb_mgr()
 *
 * @param ptr a pointer to allocated MB_MGR structure
 *
 */
void free_mb_mgr(MB_MGR *ptr)
{
        IMB_ASSERT(ptr != NULL);
#ifdef LINUX
        free(ptr);
#else
        _aligned_free(ptr);
#endif
}
