/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "ml_dsa_poly.h"

IMB_DLL_LOCAL ML_DSA_POLY_NTT_MULT_FN ml_dsa_poly_add_avx2;
IMB_DLL_LOCAL ML_DSA_POLY_NTT_MULT_FN ml_dsa_poly_sub_avx2;
IMB_DLL_LOCAL ML_DSA_POLY_CHKNORM_FN ml_dsa_poly_chknorm_avx2;
IMB_DLL_LOCAL ML_DSA_POLY_CHKNORM_FN ml_dsa_poly_chknorm_signed_avx2;
IMB_DLL_LOCAL ML_DSA_POLY_COUNT_FN ml_dsa_poly_count_ones_avx2;

static inline void
ml_dsa_poly_high_bits_32_base(const POLY *in, POLY *out)
{
        poly_high_bits(in, ML_DSA_GAMMA2_Q_MINUS1_DIV32, out);
}

static inline void
ml_dsa_poly_high_bits_88_base(const POLY *in, POLY *out)
{
        poly_high_bits(in, ML_DSA_GAMMA2_Q_MINUS1_DIV88, out);
}

static inline void
ml_dsa_poly_low_bits_32_base(const POLY *in, POLY *out)
{
        poly_low_bits(in, ML_DSA_GAMMA2_Q_MINUS1_DIV32, out);
}

static inline void
ml_dsa_poly_low_bits_88_base(const POLY *in, POLY *out)
{
        poly_low_bits(in, ML_DSA_GAMMA2_Q_MINUS1_DIV88, out);
}

static inline void
ml_dsa_poly_decompose_base(const POLY *in, uint32_t gamma2, POLY *high, POLY *low)
{
        for (unsigned i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++) {
                uint32_t r1;
                int32_t r0;

                ossl_ml_dsa_key_compress_decompose(in->coeff[i], gamma2, &r1, &r0);
                high->coeff[i] = r1;
                low->coeff[i] = (uint32_t) r0;
        }
}

static inline void
ml_dsa_poly_decompose_32_base(const POLY *in, POLY *high, POLY *low)
{
        ml_dsa_poly_decompose_base(in, ML_DSA_GAMMA2_Q_MINUS1_DIV32, high, low);
}

static inline void
ml_dsa_poly_decompose_88_base(const POLY *in, POLY *high, POLY *low)
{
        ml_dsa_poly_decompose_base(in, ML_DSA_GAMMA2_Q_MINUS1_DIV88, high, low);
}

static inline void
ml_dsa_poly_make_hint_32_base(const POLY *ct0, const POLY *cs2, const POLY *w, POLY *out)
{
        poly_make_hint(ct0, cs2, w, ML_DSA_GAMMA2_Q_MINUS1_DIV32, out);
}

static inline void
ml_dsa_poly_make_hint_88_base(const POLY *ct0, const POLY *cs2, const POLY *w, POLY *out)
{
        poly_make_hint(ct0, cs2, w, ML_DSA_GAMMA2_Q_MINUS1_DIV88, out);
}

static uint32_t
ml_dsa_poly_chknorm_base(const POLY *p, uint32_t bound)
{
        uint32_t bad = 0;

        for (unsigned i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
                bad |= constant_time_ge(abs_mod_prime(p->coeff[i]), bound);
        return bad & 1;
}

static uint32_t
ml_dsa_poly_chknorm_signed_base(const POLY *p, uint32_t bound)
{
        uint32_t bad = 0;

        for (unsigned i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
                bad |= constant_time_ge(abs_signed(p->coeff[i]), bound);
        return bad & 1;
}

static uint32_t
ml_dsa_poly_count_ones_base(const POLY *p)
{
        uint32_t count = 0;

        for (unsigned i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
                count += p->coeff[i];
        return count;
}

static void
ml_dsa_poly_pack_w1_4_base(const POLY *p, uint8_t *out)
{
        for (unsigned i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i += 2)
                *out++ = (uint8_t) (p->coeff[i] | (p->coeff[i + 1] << 4));
}

static void
ml_dsa_poly_pack_z_20_base(const POLY *p, uint8_t *out)
{
        for (unsigned i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i += 2) {
                const uint64_t a = mod_sub(ML_DSA_GAMMA1_TWO_POWER_19, p->coeff[i]);
                const uint64_t b = mod_sub(ML_DSA_GAMMA1_TWO_POWER_19, p->coeff[i + 1]);
                const uint64_t packed = a | (b << 20);

                for (unsigned j = 0; j < 5; j++)
                        *out++ = (uint8_t) (packed >> (8 * j));
        }
}

void
ossl_ml_dsa_poly_init_base(IMB_ML_DSA *self)
{
        if (self->alg == IMB_ML_DSA_44) {
                self->poly_high_bits = ml_dsa_poly_high_bits_88_base;
                self->poly_low_bits = ml_dsa_poly_low_bits_88_base;
                self->poly_decompose = ml_dsa_poly_decompose_88_base;
                self->poly_make_hint = ml_dsa_poly_make_hint_88_base;
        } else {
                self->poly_high_bits = ml_dsa_poly_high_bits_32_base;
                self->poly_low_bits = ml_dsa_poly_low_bits_32_base;
                self->poly_decompose = ml_dsa_poly_decompose_32_base;
                self->poly_make_hint = ml_dsa_poly_make_hint_32_base;
        }
        self->poly_chknorm = ml_dsa_poly_chknorm_base;
        self->poly_chknorm_signed = ml_dsa_poly_chknorm_signed_base;
        self->poly_count_ones = ml_dsa_poly_count_ones_base;
        self->poly_pack_w1_4 = ml_dsa_poly_pack_w1_4_base;
        self->poly_pack_z_20 = ml_dsa_poly_pack_z_20_base;
        self->poly_add = poly_add;
        self->poly_sub = poly_sub;
}

void
ossl_ml_dsa_poly_init_avx2(IMB_ML_DSA *self)
{
        ossl_ml_dsa_poly_init_base(self);
        self->poly_chknorm = ml_dsa_poly_chknorm_avx2;
        self->poly_chknorm_signed = ml_dsa_poly_chknorm_signed_avx2;
        self->poly_count_ones = ml_dsa_poly_count_ones_avx2;
        self->poly_add = ml_dsa_poly_add_avx2;
        self->poly_sub = ml_dsa_poly_sub_avx2;
}
