/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Shared compile-time constants for the x4-SHAKE ML-DSA sampling paths.
 *
 * Included by both ml_dsa_sample_hw_x86_64.h (AVX-512VL) and
 * ml_dsa_sample_hw_x86_64_avx2.h (AVX2) so that neither header depends on
 * the other being included first.
 */

#ifndef ML_DSA_SAMPLE_X4_DEFS_H
# define ML_DSA_SAMPLE_X4_DEFS_H

# define ML_DSA_SHAKE_X4_BATCH_SIZE          4
# define ML_DSA_SHAKE_X4_DONE_MASK           ((1 << ML_DSA_SHAKE_X4_BATCH_SIZE) - 1)

# define ML_DSA_EXPAND_MASK_BYTES_PER_COEFF  32
# define ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_19 20
# define ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_17 18
# define ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_19                                  \
        (ML_DSA_EXPAND_MASK_BYTES_PER_COEFF * ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_19)
# define ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_17                                  \
        (ML_DSA_EXPAND_MASK_BYTES_PER_COEFF * ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_17)
# define ML_DSA_EXPAND_MASK_BUF_SIZE(gamma1)                                    \
        ((gamma1) == ML_DSA_GAMMA1_TWO_POWER_19                                 \
                ? ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_19                         \
                : ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_17)

#endif /* ML_DSA_SAMPLE_X4_DEFS_H */
