/*******************************************************************************
  Copyright (c) 2025, Intel Corporation

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

#ifndef IMB_SHA3_H
#define IMB_SHA3_H

#include <stdint.h>
#include <intel-ipsec-mb.h>

/**
 * Keccak sponge context for incremental (init / update / final) hashing.
 * Allows absorbing data in multiple pieces without allocating a
 * contiguous buffer.  Total size is 224 bytes — safe to use on the stack.
 */
typedef struct {
        uint8_t state[200];      /**< Keccak state (1600 bits) */
        uint64_t rateInBytes;    /**< Absorb rate in bytes (== block size) */
        uint64_t blockPos;       /**< Bytes absorbed into the current block */
        uint8_t delimitedSuffix; /**< Domain byte: 0x06 SHA3-*, 0x1F SHAKE* */
        uint8_t _pad[7];         /**< Alignment padding — do not use */
} sha3_ctx_t;

/**
 * Initialise a SHA3 context.
 * @param ctx             Context to initialise.
 * @param rateInBytes     Absorb rate: IMB_SHA3_{224,256,384,512}_BLOCK_SIZE.
 * @param delimitedSuffix Domain suffix byte (0x06 for SHA3-*, 0x1F for SHAKE*).
 */
IMB_DLL_LOCAL void
sha3_ctx_init(sha3_ctx_t *ctx, const uint64_t rateInBytes, const uint8_t delimitedSuffix);

/** Absorb additional input into an initialised context. Safe to call with len == 0. */
IMB_DLL_LOCAL void
sha3_ctx_update(sha3_ctx_t *ctx, const uint8_t *input, const uint64_t len);

/** Finalise and squeeze @a outputLen bytes.  Do not use the context afterwards. */
IMB_DLL_LOCAL void
sha3_ctx_final(sha3_ctx_t *ctx, uint8_t *output, const uint64_t outputLen);

/**
 * Function to compute SHAKE128 on the input message with any output length.
 */
IMB_DLL_LOCAL
void
shake128(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output,
         const uint64_t outputByteLen);

/**
 * Function to compute SHAKE256 on the input message with any output length.
 */
IMB_DLL_LOCAL
void
shake256(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output,
         const uint64_t outputByteLen);

/**
 * Function to compute SHA3-224 on the input message. The output length is
 * fixed to 28 bytes.
 */
IMB_DLL_LOCAL
void
sha3_224(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);

/**
 * Function to compute SHA3-256 on the input message. The output length is
 * fixed to 32 bytes.
 */
IMB_DLL_LOCAL
void
sha3_256(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);

/**
 * Function to compute SHA3-384 on the input message. The output length is
 * fixed to 48 bytes.
 */
IMB_DLL_LOCAL
void
sha3_384(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);

/**
 * Function to compute SHA3-512 on the input message. The output length is
 * fixed to 64 bytes.
 */
IMB_DLL_LOCAL
void
sha3_512(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);

#endif /* IMB_SHA3_H */
