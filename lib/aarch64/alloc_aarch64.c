/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/
#include <stdint.h>

#include <stdlib.h> /* posix_memalign() and free() */

#include <string.h>
#include "intel-ipsec-mb.h"
#include "cpu_feature.h"
#include "error.h"

static void *
alloc_aligned_mem(const size_t size)
{
        void *ptr;

        const size_t alignment = 64;
        if (posix_memalign((void **)&ptr, alignment, size))
                return NULL;

        IMB_ASSERT(ptr != NULL);

        memset(ptr, 0, size);

        return ptr;
}

static void
free_mem(void *ptr)
{
        free(ptr);
}

/**
 * @brief Allocates memory for multi-buffer manager instance
 *
 * For binary compatibility between library versions
 * it is recommended to use this API.
 *
 * @return Pointer to allocated memory for MB_MGR structure
 * @retval NULL on allocation error
 */
IMB_MGR *alloc_mb_mgr(uint64_t flags)
{
        IMB_MGR *ptr = NULL;

        ptr = alloc_aligned_mem(sizeof(IMB_MGR));
        IMB_ASSERT(ptr != NULL);
        if (ptr != NULL) {
                imb_set_errno(ptr, 0);
                ptr->flags = flags; /* save the flags for future use in init */
                ptr->features = cpu_feature_adjust(flags, cpu_feature_detect());
        } else {
                imb_set_errno(ptr, ENOMEM);
                return NULL;
        }

        return ptr;
}

/**
 * @brief Frees memory allocated previously by alloc_mb_mgr()
 *
 * @param ptr a pointer to allocated MB_MGR structure
 *
 */
void free_mb_mgr(IMB_MGR *ptr)
{
        IMB_ASSERT(ptr != NULL);

        /* Free IMB_MGR */
        free_mem(ptr);
}
