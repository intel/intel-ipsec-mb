/*******************************************************************************
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
