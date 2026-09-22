/*******************************************************************************
  Copyright (c) 2025-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef IMB_SHA3_H
#define IMB_SHA3_H

#include <stdint.h>
#include <intel-ipsec-mb.h>
#include "internal/sha3.h" /* for KECCAK1600_CTX */

/**
 * Keccak sponge context for incremental (init / update / final) hashing.
 * Wraps KECCAK1600_CTX to use the optimised OpenSSL SHA3/SHAKE back-end
 * (SHA3_absorb / SHA3_squeeze from keccak1600-x86_64) instead of the
 * portable reference permutation.
 */
typedef struct {
        KECCAK1600_CTX kctx; /**< OpenSSL Keccak context (state + buffer + vtable) */
} sha3_ctx_t;

/**
 * Initialise a SHA3 context.
 * @param ctx             Context to initialise.
 * @param rateInBytes     Absorb rate: IMB_SHA3_{224,256,384,512}_BLOCK_SIZE
 *                        (144/136/104/72 bytes) or 168/136 for SHAKE-128/256.
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
