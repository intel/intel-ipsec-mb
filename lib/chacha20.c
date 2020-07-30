/*******************************************************************************
  Copyright (c) 2020, Intel Corporation

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

/* basic Chacha20 implementation */
#include <string.h>
#include <inttypes.h>

#include "intel-ipsec-mb.h"
#include "include/chacha20.h"

#include "clear_regs_mem.h"

#define CLEAR_MEM clear_mem
#define CLEAR_VAR clear_var

#define ROT_L(a, N) ((uint32_t) a << N | (uint32_t) a >> (32 - N))

static uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

static inline void
quarter_round(uint32_t vec[4])
{
        uint32_t *a = &vec[0];
        uint32_t *b = &vec[1];
        uint32_t *c = &vec[2];
        uint32_t *d = &vec[3];

        *a += *b;
        *d ^= *a;
        *d = ROT_L(*d, 16);

        *c += *d;
        *b ^= *c;
        *b = ROT_L(*b, 12);

        *a += *b;
        *d ^= *a;
        *d = ROT_L(*d, 8);

        *c += *d;
        *b ^= *c;
        *b = ROT_L(*b, 7);
}

static inline void
column_round(uint32_t vec[16], uint32_t cols[4][4])
{
        unsigned int i, j;

        for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                        cols[i][j] = vec[j*4 + i];

        for (i = 0; i < 4; i++)
                quarter_round(cols[i]);

        for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                        vec[i*4 + j] = cols[j][i];
}

static inline void
diagonal_round(uint32_t vec[16], uint32_t diags[4][4])
{
        unsigned int i;

        diags[0][0] = vec[0]; diags[0][1] =  vec[5];
        diags[0][2] = vec[10]; diags[0][3] = vec[15];
        diags[1][0] = vec[1]; diags[1][1] =  vec[6];
        diags[1][2] = vec[11]; diags[1][3] = vec[12];
        diags[2][0] = vec[2]; diags[2][1] =  vec[7];
        diags[2][2] = vec[8]; diags[2][3] = vec[13];
        diags[3][0] = vec[3]; diags[3][1] =  vec[4];
        diags[3][2] = vec[9]; diags[3][3] = vec[14];

        for (i = 0; i < 4; i++)
                quarter_round(diags[i]);

        vec[0] = diags[0][0]; vec[1] = diags[1][0];
        vec[2] = diags[2][0]; vec[3] = diags[3][0];
        vec[4] = diags[3][1]; vec[5] = diags[0][1];
        vec[6] = diags[1][1]; vec[7] = diags[2][1];
        vec[8] = diags[2][2]; vec[9] = diags[3][2];
        vec[10] = diags[0][2]; vec[11] = diags[1][2];
        vec[12] = diags[1][3]; vec[13] = diags[2][3];
        vec[14] = diags[3][3]; vec[15] = diags[0][3];
}

static inline void
full_20_rounds(uint32_t vec[16])
{
        unsigned int i;
        uint32_t temp_mem[4][4];

        /* Perform 20 rounds (interleaving column and diagonal rounds) */
        for (i = 0; i < 10; i++) {
                column_round(vec, temp_mem);
                diagonal_round(vec, temp_mem);
        }
#ifdef SAFE_DATA
        CLEAR_MEM(temp_mem, sizeof(temp_mem));
#endif
}

static inline void
chacha_block(uint32_t chacha_state[16])
{
        uint32_t temp_vec[16];
        unsigned int i;

        memcpy(temp_vec, chacha_state, 64);

        full_20_rounds(temp_vec);

        for (i = 0; i < 16; i++)
                chacha_state[i] += temp_vec[i];
#ifdef SAFE_DATA
        CLEAR_MEM(temp_vec, sizeof(temp_vec));
#endif
}

static inline void
prepare_chacha_state(const uint8_t key[32], const uint8_t nonce[12],
                     const uint32_t block_count, uint32_t chacha_state[16])
{
        /* Construct chacha state from key, nonce and block count */
        memcpy(&chacha_state[0], constants, 4*4);
        memcpy(&chacha_state[4], key, 8*4);
        chacha_state[12] = block_count;
        memcpy(&chacha_state[13], nonce, 3*4);
};

IMB_DLL_LOCAL
void
chacha20_enc_dec_basic(const void *input, void *output, const uint64_t len,
                       const void *ks, const void *iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) ||
            (ks == NULL) || (iv == NULL) || (len == 0))
                return;
#endif

        uint64_t i, j;
        uint32_t chacha_state[16];
        uint8_t *keystr;
        const uint8_t *key = (const uint8_t *) ks;
        const uint8_t *iv8 = (const uint8_t *) iv;
        uint32_t block_ctr = 1;
        const uint8_t *nonce = &iv8[0];
        const uint8_t *in = (const uint8_t *) input;
        uint8_t *out = (uint8_t *) output;

        for (i = 0; i < len; i+= 64) {
                prepare_chacha_state(key, nonce, block_ctr, chacha_state);
                chacha_block(chacha_state);
                keystr = (uint8_t *) chacha_state;
                block_ctr++;
                if ((i + 64) > len) {
                        for (j = 0; j < (len % 64); j++)
                                out[i+j] = in[i+j] ^ keystr[j];
                        break;
                }
                for (j = 0; j < 64; j++)
                        out[i+j] = in[i+j] ^ keystr[j];
        }
#ifdef SAFE_DATA
        CLEAR_MEM(chacha_state, sizeof(chacha_state));
#endif
}
