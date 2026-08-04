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

/*
 * SHA3 / SHAKE implementation for the job/burst API baseline (non-AVX-512/AVX10
 * architectures).
 *
 * Instead of the portable reference Keccak-f[1600] permutation this module
 * delegates to the OpenSSL SHA3/SHAKE back-end in lib/openssl/crypto/sha/:
 *
 *   SHA3_absorb / SHA3_squeeze  - from keccak1600-x86_64.S (optimised asm)
 *   ossl_sha3_*                 - buffering and padding glue in sha3_ossl.c
 *
 * sha3_ctx_t wraps KECCAK1600_CTX (defined in internal/sha3.h) so the same
 * vtable-driven absorb/final/squeeze code is reused throughout.
 */

#include <intel-ipsec-mb.h>
#include <stdint.h>
#include <sha3.h>
#include "include/clear_regs_mem.h"

/* Method table shared by all SHA3 / SHAKE contexts in this module. */
static const PROV_SHA3_METHOD sha3_ossl_meth = {
        ossl_sha3_absorb_default,
        ossl_sha3_final_default,
        ossl_shake_squeeze_default,
};

/* ------------------------------------------------------------------ */
/* One-shot SHA3 / SHAKE functions                                     */
/* ------------------------------------------------------------------ */

void
shake128(const uint8_t *input, uint64_t inputByteLen, uint8_t *output, uint64_t outputByteLen)
{
        KECCAK1600_CTX ctx;

        ossl_sha3_init(&ctx, 0x1f, 128);
        ctx.meth = sha3_ossl_meth;
        ossl_sha3_absorb(&ctx, input, (size_t) inputByteLen);
        ossl_sha3_squeeze(&ctx, output, (size_t) outputByteLen);
#ifdef SAFE_DATA
        imb_clear_mem(&ctx, sizeof(ctx));
#endif
}

void
shake256(const uint8_t *input, uint64_t inputByteLen, uint8_t *output, uint64_t outputByteLen)
{
        KECCAK1600_CTX ctx;

        ossl_sha3_init(&ctx, 0x1f, 256);
        ctx.meth = sha3_ossl_meth;
        ossl_sha3_absorb(&ctx, input, (size_t) inputByteLen);
        ossl_sha3_squeeze(&ctx, output, (size_t) outputByteLen);
#ifdef SAFE_DATA
        imb_clear_mem(&ctx, sizeof(ctx));
#endif
}

void
sha3_224(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        KECCAK1600_CTX ctx;

        ossl_sha3_init(&ctx, 0x06, 224);
        ctx.meth = sha3_ossl_meth;
        ossl_sha3_absorb(&ctx, input, (size_t) inputByteLen);
        ossl_sha3_final(&ctx, output, IMB_SHA3_224_DIGEST_SIZE_IN_BYTES);
#ifdef SAFE_DATA
        imb_clear_mem(&ctx, sizeof(ctx));
#endif
}

void
sha3_256(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        KECCAK1600_CTX ctx;

        ossl_sha3_init(&ctx, 0x06, 256);
        ctx.meth = sha3_ossl_meth;
        ossl_sha3_absorb(&ctx, input, (size_t) inputByteLen);
        ossl_sha3_final(&ctx, output, IMB_SHA3_256_DIGEST_SIZE_IN_BYTES);
#ifdef SAFE_DATA
        imb_clear_mem(&ctx, sizeof(ctx));
#endif
}

void
sha3_384(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        KECCAK1600_CTX ctx;

        ossl_sha3_init(&ctx, 0x06, 384);
        ctx.meth = sha3_ossl_meth;
        ossl_sha3_absorb(&ctx, input, (size_t) inputByteLen);
        ossl_sha3_final(&ctx, output, IMB_SHA3_384_DIGEST_SIZE_IN_BYTES);
#ifdef SAFE_DATA
        imb_clear_mem(&ctx, sizeof(ctx));
#endif
}

void
sha3_512(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        KECCAK1600_CTX ctx;

        ossl_sha3_init(&ctx, 0x06, 512);
        ctx.meth = sha3_ossl_meth;
        ossl_sha3_absorb(&ctx, input, (size_t) inputByteLen);
        ossl_sha3_final(&ctx, output, IMB_SHA3_512_DIGEST_SIZE_IN_BYTES);
#ifdef SAFE_DATA
        imb_clear_mem(&ctx, sizeof(ctx));
#endif
}

/* ------------------------------------------------------------------ */
/* Incremental (init / update / final) context API                    */
/* ------------------------------------------------------------------ */

void
sha3_ctx_init(sha3_ctx_t *ctx, uint64_t rateInBytes, uint8_t delimitedSuffix)
{
        /*
         * Derive bitlen from the absorb rate so ossl_sha3_init sets the
         * correct block_size:
         *   SHA3_BLOCKSIZE(bitlen) = (1600 - 2*bitlen) / 8 = rateInBytes
         *   => bitlen = (1600 - rateInBytes*8) / 2
         */
        const size_t bitlen = (KECCAK1600_WIDTH - (size_t) rateInBytes * 8) / 2;

        ossl_sha3_init(&ctx->kctx, delimitedSuffix, bitlen);
        ctx->kctx.meth = sha3_ossl_meth;
}

void
sha3_ctx_update(sha3_ctx_t *ctx, const uint8_t *input, uint64_t len)
{
        ossl_sha3_absorb(&ctx->kctx, input, (size_t) len);
}

void
sha3_ctx_final(sha3_ctx_t *ctx, uint8_t *output, uint64_t outputLen)
{
        /*
         * SHA3 (pad 0x06): single-shot finalise - applies padding, absorbs
         * last block, squeezes a fixed-length digest.
         * SHAKE (pad 0x1f): XOF squeeze - same first call but supports
         * arbitrary output lengths via ossl_shake_squeeze_default.
         */
        if (ctx->kctx.pad == 0x06) {
                ossl_sha3_final(&ctx->kctx, output, (size_t) outputLen);
        } else {
                ossl_sha3_squeeze(&ctx->kctx, output, (size_t) outputLen);
        }
#ifdef SAFE_DATA
        imb_clear_mem(&ctx->kctx, sizeof(ctx->kctx));
#endif
}
