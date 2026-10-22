/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ml_dsa_local.h"
#include "ml_dsa_vector.h"
#include "ml_dsa_matrix.h"

/*
 * Matrix multiply of a k*l matrix of polynomials by a 1 * l vector of
 * polynomials to produce a 1 * k vector of polynomial results.
 * i.e. t = a * s
 * Each row is computed with a fused NTT-domain dot product.
 *
 * @param a A k * l matrix of polynomials in NTT form
 * @param s A 1 * l vector of polynomials in NTT form
 * @param t 1 * k vector of polynomial results in NTT form
 */
void
ossl_ml_dsa_matrix_mult_vector(const IMB_ML_DSA *self, const MATRIX *a, const VECTOR *s, VECTOR *t)
{
        for (size_t i = 0; i < a->k; i++)
                self->poly_ntt_dot(a->m_poly + i * a->l, s->poly, a->l, t->poly + i);
}
