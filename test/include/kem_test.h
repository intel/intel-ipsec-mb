/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef KEM_TEST_H
#define KEM_TEST_H

#include <stddef.h>

/*
 * Generic KEM (key-encapsulation mechanism) test vector, covering the four
 * Wycheproof ML-KEM JSON vector schema families (mlkem_test_schema.json,
 * mlkem_encaps_test_schema.json, mlkem_keygen_seed_test_schema.json,
 * mlkem_semi_expanded_decaps_test_schema.json):
 *
 *   - combined keygen-from-seed + decap ("MLKEMTest"):  seed?, ek?, c, K,
 *     result, flags
 *   - encapsulation ("MLKEMEncapsTest"): ek, m, c, K, result, flags
 *   - keygen-from-seed ("MLKEMKeyGen"): seed, ek, dk, result
 *   - semi-expanded decapsulation ("MLKEMSemiExpandedDecapsTest"): dk, ek
 *     (context, unused), c, K?, result, flags
 *
 * Every field that is not present in a given schema/test entry is optional;
 * the corresponding hasXxx flag indicates whether the field was present in
 * that particular test's JSON object. Since this shape covers whatever
 * subset of (seed, ek, dk, m, c, K) a given ML-KEM test vector schema
 * provides, this struct is not ML-KEM-specific and may be reused by future
 * KEM test modules.
 */
struct kem_test {
        size_t tcId;
        const char *comment;

        int hasSeed;
        const char *seed; /* KeyGen seed: FIPS 203 "d" || "z" (64 bytes) */
        size_t seedLen;

        int hasEk;
        const char *ek; /* Encapsulation (public) key */
        size_t ekLen;

        int hasDk;
        const char *dk; /* Decapsulation (private) key */
        size_t dkLen;

        int hasM;
        const char *m; /* Encapsulation randomness (32 bytes) */
        size_t mLen;

        int hasC;
        const char *c; /* Ciphertext */
        size_t cLen;

        int hasK;
        const char *K; /* Shared secret */
        size_t KLen;

        int resultValid;
};

#endif /* KEM_TEST_H */
