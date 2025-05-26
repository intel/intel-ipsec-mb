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
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <stdint.h>
#include <sha3.h>

/**
 * Function to compute the Keccak[r, c] sponge function over a given input.
 * @param  rate            The value of the rate r.
 * @param  capacity        The value of the capacity c.
 * @param  input           Pointer to the input message.
 * @param  inputByteLen    The number of input bytes provided in the input
 * message.
 * @param  delimitedSuffix Bits that will be automatically appended to the end
 *                         of the input message, as in domain separation.
 *                         This is a byte containing from 0 to 7 bits
 *                         These <i>n</i> bits must be in the least significant
 * bit positions and must be delimited with a bit 1 at position <i>n</i>
 *                         (counting from 0=LSB to 7=MSB) and followed by bits 0
 *                         from position <i>n</i>+1 to position 7.
 *                         Some examples:
 *                             - If no bits are to be appended, then @a
 * delimitedSuffix must be 0x01.
 *                             - If the 2-bit sequence 0,1 is to be appended (as
 * for SHA3-*), @a delimitedSuffix must be 0x06.
 *                             - If the 4-bit sequence 1,1,1,1 is to be appended
 * (as for SHAKE*), @a delimitedSuffix must be 0x1F.
 *                             - If the 7-bit sequence 1,1,0,1,0,0,0 is to be
 * absorbed, @a delimitedSuffix must be 0x8B.
 * @param  output          Pointer to the buffer where to store the output.
 * @param  outputByteLen   The number of output bytes desired.
 * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this
 * implementation.
 */
void
Keccak(const uint32_t rate, const uint32_t capacity, const uint8_t *input, uint64_t inputByteLen,
       const uint8_t delimitedSuffix, uint8_t *output, uint64_t outputByteLen);

void
shake128(const uint8_t *input, uint64_t inputByteLen, uint8_t *output, uint64_t outputByteLen)
{
        Keccak(1344, 256, input, inputByteLen, 0x1F, output, outputByteLen);
}

void
shake256(const uint8_t *input, uint64_t inputByteLen, uint8_t *output, uint64_t outputByteLen)
{
        Keccak(1088, 512, input, inputByteLen, 0x1F, output, outputByteLen);
}

void
sha3_224(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        Keccak(1152, 448, input, inputByteLen, 0x06, output, 28);
}

void
sha3_256(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        Keccak(1088, 512, input, inputByteLen, 0x06, output, 32);
}

void
sha3_384(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        Keccak(832, 768, input, inputByteLen, 0x06, output, 48);
}

void
sha3_512(const uint8_t *input, uint64_t inputByteLen, uint8_t *output)
{
        Keccak(576, 1024, input, inputByteLen, 0x06, output, 64);
}

/*
================================================================
Technicalities
================================================================
*/

typedef uint64_t tKeccakLane;

/*
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
*/

static inline uint64_t
ROL64(uint64_t a, uint32_t offset)
{
        return (a << offset) ^ (a >> (64 - offset));
}

static inline uint32_t
i(uint32_t x, uint32_t y)
{
        return x + 5 * y;
}

static inline uint64_t
readLane(void *state, uint32_t x, uint32_t y)
{
        return ((uint64_t *) state)[i(x, y)];
}

static inline void
writeLane(void *state, uint32_t x, uint32_t y, uint64_t lane)
{
        ((uint64_t *) state)[i(x, y)] = lane;
}

static inline void
XORLane(void *state, uint32_t x, uint32_t y, uint64_t lane)
{
        ((uint64_t *) state)[i(x, y)] ^= lane;
}

/**
 * Function that computes the linear feedback shift register (LFSR) used to
 * define the round constants (see [Keccak Reference, Section 1.2]).
 */
static int
lfsr86540(uint8_t *LFSR)
{
        int result = ((*LFSR) & 0x01) != 0;
        if (((*LFSR) & 0x80) != 0)
                /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
                (*LFSR) = ((*LFSR) << 1) ^ 0x71;
        else
                (*LFSR) <<= 1;
        return result;
}

/**
 * Function that computes the Keccak-f[1600] permutation on the given state.
 */
static void
KeccakF1600_StatePermute(void *state)
{
        unsigned int round, x, y, j, t;
        uint8_t LFSRstate = 0x01;

        for (round = 0; round < 24; round++) {
                { /* === θ step (see [Keccak Reference, Section 2.3.2]) === */
                        tKeccakLane C[5], D;

                        /* Compute the parity of the columns */
                        for (x = 0; x < 5; x++)
                                C[x] = readLane(state, x, 0) ^ readLane(state, x, 1) ^
                                       readLane(state, x, 2) ^ readLane(state, x, 3) ^
                                       readLane(state, x, 4);
                        for (x = 0; x < 5; x++) {
                                /* Compute the θ effect for a given column */
                                D = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
                                /* Add the θ effect to the whole column */
                                for (y = 0; y < 5; y++)
                                        XORLane(state, x, y, D);
                        }
                }

                { /* === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4])
                     === */
                        tKeccakLane current, temp;
                        /* Start at coordinates (1 0) */
                        x = 1;
                        y = 0;
                        current = readLane(state, x, y);
                        /* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
                        for (t = 0; t < 24; t++) {
                                /* Compute the rotation constant r = (t+1)(t+2)/2 */
                                unsigned int r = ((t + 1) * (t + 2) / 2) % 64;
                                /* Compute ((0 1)(2 3)) * (x y) */
                                unsigned int Y = (2 * x + 3 * y) % 5;
                                x = y;
                                y = Y;
                                /* Swap current and state(x,y), and rotate */
                                temp = readLane(state, x, y);
                                writeLane(state, x, y, ROL64(current, r));
                                current = temp;
                        }
                }

                { /* === χ step (see [Keccak Reference, Section 2.3.1]) === */
                        tKeccakLane temp[5];
                        for (y = 0; y < 5; y++) {
                                /* Take a copy of the plane */
                                for (x = 0; x < 5; x++)
                                        temp[x] = readLane(state, x, y);
                                /* Compute χ on the plane */
                                for (x = 0; x < 5; x++)
                                        writeLane(state, x, y,
                                                  temp[x] ^ ((~temp[(x + 1) % 5]) &
                                                             temp[(x + 2) % 5]));
                        }
                }

                { /* === ι step (see [Keccak Reference, Section 2.3.5]) === */
                        for (j = 0; j < 7; j++) {
                                unsigned int bitPosition = (1 << j) - 1; /* 2^j-1 */
                                if (lfsr86540(&LFSRstate))
                                        XORLane(state, 0, 0, (tKeccakLane) 1 << bitPosition);
                        }
                }
        }
}

/*
================================================================
A readable and compact implementation of the Keccak sponge functions
that use the Keccak-f[1600] permutation.
================================================================
*/

#include <string.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))

void
Keccak(const uint32_t rate, const uint32_t capacity, const uint8_t *input, uint64_t inputByteLen,
       const uint8_t delimitedSuffix, uint8_t *output, uint64_t outputByteLen)
{
        uint8_t state[200];
        const uint64_t rateInBytes = rate / 8;
        uint64_t blockSize = 0;

        if (((rate + capacity) != 1600) || ((rate % 8) != 0))
                return;

        /* === Initialize the state === */
        memset(state, 0, sizeof(state));

        /* === Absorb all the input blocks === */
        while (inputByteLen > 0) {
                blockSize = MIN(inputByteLen, rateInBytes);
                for (uint32_t i = 0; i < blockSize; i++)
                        state[i] ^= input[i];
                input += blockSize;
                inputByteLen -= blockSize;

                if (blockSize == rateInBytes) {
                        KeccakF1600_StatePermute(state);
                        blockSize = 0;
                }
        }

        /* === Do the padding and switch to the squeezing phase === */
        /* Absorb the last few bits and add the first bit of padding (which coincides
         * with the delimiter in delimitedSuffix) */
        state[blockSize] ^= delimitedSuffix;
        /* If the first bit of padding is at position rate-1, we need a whole new
         * block for the second bit of padding */
        if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
                KeccakF1600_StatePermute(state);
        /* Add the second bit of padding */
        state[rateInBytes - 1] ^= 0x80;
        /* Switch to the squeezing phase */
        KeccakF1600_StatePermute(state);

        /* === Squeeze out all the output blocks === */
        while (outputByteLen > 0) {
                blockSize = MIN(outputByteLen, rateInBytes);
                memcpy(output, state, blockSize);
                output += blockSize;
                outputByteLen -= blockSize;

                if (outputByteLen > 0)
                        KeccakF1600_StatePermute(state);
        }
}
