/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

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

#ifndef IMB_ARCH_X86_64_H
#define IMB_ARCH_X86_64_H

#include "intel-ipsec-mb.h"

IMB_DLL_LOCAL void *
poly1305_mac_scalar(IMB_JOB *job);
IMB_DLL_LOCAL void
poly1305_aead_update_scalar(const void *msg, const uint64_t msg_len, void *hash, const void *key);
IMB_DLL_LOCAL void
poly1305_aead_complete_scalar(const void *hash, const void *key, void *tag);

/**
 * @brief Runs self test on selected CAVP algorithms
 *
 * @param p_mgr initialized MB manager structure
 *
 * @return Self test status
 * @retval 0 self test failed
 * @retval 1 self test passed
 */
IMB_DLL_LOCAL int
self_test(IMB_MGR *p_mgr);

/**
 * @brief Atomic 64-bit counter increment
 *
 * This implements counter post increment.
 *
 * @param counter pointer to a 64-bit counter
 *
 * @return Counter value prior to increment
 */
IMB_DLL_LOCAL uint64_t
atomic_uint64_inc(uint64_t *counter);

#endif /* IMB_ARCH_X86_64_H */
