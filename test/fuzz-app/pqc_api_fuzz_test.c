/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Fuzz application for the post-quantum cryptography (PQC) direct API:
 * ML-DSA (FIPS 204) and ML-KEM (FIPS 203).
 *
 * The PQC API differs from the rest of the direct API in that it is stateful
 * (an opaque context caches a decoded key) and that most of its entry points
 * parse externally supplied, structured byte strings (encoded keys,
 * ciphertexts and signatures). Those decoders are the interesting fuzz
 * target, so the harness:
 *  - generates one known good key pair (and one valid signature / ciphertext)
 *    per parameter set from a fixed seed, once, and caches it. This is what
 *    lets the fuzzer reach the code past the initial format checks without
 *    paying for a key generation on every iteration,
 *  - feeds the API either raw fuzz input or a bit-corrupted copy of that
 *    known good material,
 *  - sizes every input and output buffer to exactly the length passed to the
 *    library, so that ASAN traps any access beyond it,
 *  - fuzzes the parameter set selectors, the buffer lengths and the optional
 *    parameter structures alongside the payloads.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <intel-ipsec-mb.h>
#include "utils.h"
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int
LLVMFuzzerInitialize(int *, char ***);

static struct fuzz_args fargs = { 0 };

/**
 * @brief libFuzzer initialization hook. Extracts the application specific
 *        arguments introduced by "--" and hides them from libFuzzer.
 *
 * @param [in,out] argc  Argument count, truncated at the "--" argument
 * @param [in,out] argv  Argument vector
 *
 * @return 0 always
 */
int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
        fuzz_args_init(&fargs);
        return parse_args(argc, argv, &fargs);
}

/* ========================================================================== */
/* Fuzz input reader                                                          */
/* ========================================================================== */

/* Largest encoded object sizes across all ML-DSA and ML-KEM parameter sets */
#define MAX_PUBKEY_BYTES  IMB_ML_DSA_87_PUBKEY_BYTES
#define MAX_PRIVKEY_BYTES IMB_ML_DSA_87_PRIVKEY_BYTES
#define MAX_SIG_BYTES     IMB_ML_DSA_87_SIG_BYTES
#define MAX_CT_BYTES      IMB_ML_KEM_1024_CIPHERTEXT_BYTES

/* Upper bound on any buffer the harness is allowed to allocate */
#define MAX_ALLOC_BYTES (MAX_SIG_BYTES + 1024)

struct fuzz_reader {
        const uint8_t *data;
        size_t size;
        size_t pos;
};

/**
 * @brief Consume one byte of fuzz input.
 *
 * @param [in,out] f  Fuzz input reader
 *
 * @return Next input byte, or 0 once the input is exhausted
 */
static uint8_t
fz_u8(struct fuzz_reader *f)
{
        if (f == NULL)
                return 0;
        if (f->pos >= f->size)
                return 0;
        return f->data[f->pos++];
}

/**
 * @brief Consume four bytes of fuzz input, most significant byte first.
 *
 * @param [in,out] f  Fuzz input reader
 *
 * @return Next 32-bit value, zero padded once the input is exhausted
 */
static uint32_t
fz_u32(struct fuzz_reader *f)
{
        if (f == NULL)
                return 0;

        uint32_t v = 0;

        for (unsigned i = 0; i < 4; i++)
                v = (v << 8) | (uint32_t) fz_u8(f);

        return v;
}

/**
 * @brief Copy \a n bytes of fuzz input into \a dst, zero padding the
 *        remainder once the input is exhausted.
 *
 * @param [in,out] f    Fuzz input reader
 * @param [out]    dst  Destination buffer of \a n bytes
 * @param [in]     n    Number of bytes to write
 */
static void
fz_bytes(struct fuzz_reader *f, void *dst, const size_t n)
{
        if (dst == NULL || n == 0 || f == NULL)
                return;

        const size_t avail = (f->pos < f->size) ? (f->size - f->pos) : 0;
        const size_t cp = (avail < n) ? avail : n;

        if (cp > 0)
                memcpy(dst, &f->data[f->pos], cp);
        if (cp < n)
                memset((uint8_t *) dst + cp, 0, n - cp);
        f->pos += cp;
}

/**
 * @brief Allocate a zeroed buffer of exactly \a size bytes.
 *
 * Buffers are never over-allocated, so that the ASAN redzone sits directly
 * behind the length the library is given and any access past it is trapped.
 *
 * @param [in] size  Buffer size in bytes (0 allocates a single byte)
 *
 * @return Pointer to the new buffer, or NULL on allocation failure
 */
static void *
calloc_exact(const size_t size)
{
        const size_t alloc_size = (size == 0) ? 1 : size;
        void *p = malloc(alloc_size);

        if (p != NULL)
                memset(p, 0, alloc_size);

        return p;
}

/**
 * @brief Pick a buffer length to hand to the API: the correct one in roughly
 *        three out of four cases, otherwise zero, off by one or arbitrary,
 *        to exercise the length validation.
 *
 * @param [in,out] f      Fuzz input reader
 * @param [in]     exact  Length the API expects
 *
 * @return Length to pass to the API
 */
static size_t
pick_len(struct fuzz_reader *f, const size_t exact)
{
        const uint8_t sel = fz_u8(f);

        switch (sel & 0x0f) {
        case 0:
                return 0;
        case 1:
                return (exact > 0) ? (exact - 1) : 0;
        case 2:
                return exact + 1;
        case 3:
                return (size_t) (fz_u32(f) % (MAX_ALLOC_BYTES + 1));
        default:
                /* correct length for the remaining ~75% of the cases */
                return exact;
        }
}

/**
 * @brief Build a key, ciphertext or signature shaped input of \a len bytes.
 *
 * The content is either taken straight from the fuzz input or is a copy of
 * known good material with up to four fuzz driven bytes corrupted. The latter
 * stays close enough to well formed to drive the decoders past their initial
 * format checks.
 *
 * @param [in,out] f         Fuzz input reader
 * @param [in]     len       Length of the buffer to build
 * @param [in]     good      Known good material, or NULL if unavailable
 * @param [in]     good_len  Size of \a good in bytes
 *
 * @return Buffer of exactly \a len bytes, or NULL on allocation failure
 */
static uint8_t *
make_input(struct fuzz_reader *f, const size_t len, const void *good, const size_t good_len)
{
        uint8_t *buf = calloc_exact(len);

        if (buf == NULL || len == 0)
                return buf;

        const uint8_t mode = fz_u8(f);

        if (good == NULL || good_len == 0 || (mode & 1) == 0) {
                fz_bytes(f, buf, len);
                return buf;
        }

        const size_t cp = (good_len < len) ? good_len : len;

        memcpy(buf, good, cp);
        if (cp < len)
                fz_bytes(f, buf + cp, len - cp);

        /* corrupt 1 to 4 bytes (the mask may be zero, leaving it intact) */
        const unsigned n_corrupt = ((mode >> 1) & 3) + 1;

        for (unsigned i = 0; i < n_corrupt; i++) {
                const size_t off = (size_t) (fz_u32(f) % len);

                buf[off] ^= fz_u8(f);
        }

        return buf;
}

/* ========================================================================== */
/* Parameter set helpers                                                      */
/* ========================================================================== */

/**
 * @brief Encoded ML-DSA public key size for \a alg.
 *
 * @param [in] alg  ML-DSA parameter set
 *
 * @return Size in bytes, or 0 for an unknown parameter set
 */
static size_t
ml_dsa_pk_bytes(const IMB_ML_DSA_ALG alg)
{
        switch (alg) {
        case IMB_ML_DSA_44:
                return IMB_ML_DSA_44_PUBKEY_BYTES;
        case IMB_ML_DSA_65:
                return IMB_ML_DSA_65_PUBKEY_BYTES;
        case IMB_ML_DSA_87:
                return IMB_ML_DSA_87_PUBKEY_BYTES;
        default:
                return 0;
        }
}

/**
 * @brief Encoded ML-DSA private key size for \a alg.
 *
 * @param [in] alg  ML-DSA parameter set
 *
 * @return Size in bytes, or 0 for an unknown parameter set
 */
static size_t
ml_dsa_sk_bytes(const IMB_ML_DSA_ALG alg)
{
        switch (alg) {
        case IMB_ML_DSA_44:
                return IMB_ML_DSA_44_PRIVKEY_BYTES;
        case IMB_ML_DSA_65:
                return IMB_ML_DSA_65_PRIVKEY_BYTES;
        case IMB_ML_DSA_87:
                return IMB_ML_DSA_87_PRIVKEY_BYTES;
        default:
                return 0;
        }
}

/**
 * @brief Encoded ML-DSA signature size for \a alg.
 *
 * @param [in] alg  ML-DSA parameter set
 *
 * @return Size in bytes, or 0 for an unknown parameter set
 */
static size_t
ml_dsa_sig_bytes(const IMB_ML_DSA_ALG alg)
{
        switch (alg) {
        case IMB_ML_DSA_44:
                return IMB_ML_DSA_44_SIG_BYTES;
        case IMB_ML_DSA_65:
                return IMB_ML_DSA_65_SIG_BYTES;
        case IMB_ML_DSA_87:
                return IMB_ML_DSA_87_SIG_BYTES;
        default:
                return 0;
        }
}

/**
 * @brief Encoded ML-KEM encapsulation (public) key size for \a alg.
 *
 * @param [in] alg  ML-KEM parameter set
 *
 * @return Size in bytes, or 0 for an unknown parameter set
 */
static size_t
ml_kem_ek_bytes(const IMB_ML_KEM_ALG alg)
{
        switch (alg) {
        case IMB_ML_KEM_512:
                return IMB_ML_KEM_512_PUBKEY_BYTES;
        case IMB_ML_KEM_768:
                return IMB_ML_KEM_768_PUBKEY_BYTES;
        case IMB_ML_KEM_1024:
                return IMB_ML_KEM_1024_PUBKEY_BYTES;
        default:
                return 0;
        }
}

/**
 * @brief Encoded ML-KEM decapsulation (private) key size for \a alg.
 *
 * @param [in] alg  ML-KEM parameter set
 *
 * @return Size in bytes, or 0 for an unknown parameter set
 */
static size_t
ml_kem_dk_bytes(const IMB_ML_KEM_ALG alg)
{
        switch (alg) {
        case IMB_ML_KEM_512:
                return IMB_ML_KEM_512_PRIVKEY_BYTES;
        case IMB_ML_KEM_768:
                return IMB_ML_KEM_768_PRIVKEY_BYTES;
        case IMB_ML_KEM_1024:
                return IMB_ML_KEM_1024_PRIVKEY_BYTES;
        default:
                return 0;
        }
}

/**
 * @brief Encoded ML-KEM ciphertext size for \a alg.
 *
 * @param [in] alg  ML-KEM parameter set
 *
 * @return Size in bytes, or 0 for an unknown parameter set
 */
static size_t
ml_kem_ct_bytes(const IMB_ML_KEM_ALG alg)
{
        switch (alg) {
        case IMB_ML_KEM_512:
                return IMB_ML_KEM_512_CIPHERTEXT_BYTES;
        case IMB_ML_KEM_768:
                return IMB_ML_KEM_768_CIPHERTEXT_BYTES;
        case IMB_ML_KEM_1024:
                return IMB_ML_KEM_1024_CIPHERTEXT_BYTES;
        default:
                return 0;
        }
}

/**
 * @brief Pick an ML-DSA parameter set: a valid one in 15 out of 16 cases,
 *        otherwise an out of range selector, to exercise the parameter set
 *        validation.
 *
 * @param [in,out] f  Fuzz input reader
 *
 * @return Parameter set selector to pass to imb_ml_dsa_new()
 */
static IMB_ML_DSA_ALG
pick_ml_dsa_alg(struct fuzz_reader *f)
{
        const uint8_t sel = fz_u8(f);

        if ((sel & 0x0f) == 0x0f)
                return (IMB_ML_DSA_ALG) fz_u32(f);

        return (IMB_ML_DSA_ALG) (IMB_ML_DSA_44 + (sel % 3));
}

/**
 * @brief Pick an ML-KEM parameter set: a valid one in 15 out of 16 cases,
 *        otherwise an out of range selector, to exercise the parameter set
 *        validation.
 *
 * @param [in,out] f  Fuzz input reader
 *
 * @return Parameter set selector to pass to imb_ml_kem_new()
 */
static IMB_ML_KEM_ALG
pick_ml_kem_alg(struct fuzz_reader *f)
{
        const uint8_t sel = fz_u8(f);

        if ((sel & 0x0f) == 0x0f)
                return (IMB_ML_KEM_ALG) fz_u32(f);

        return (IMB_ML_KEM_ALG) (IMB_ML_KEM_512 + (sel % 3));
}

/* ========================================================================== */
/* Known good key material, generated once per parameter set                   */
/* ========================================================================== */

enum cache_state { CACHE_EMPTY = 0, CACHE_READY, CACHE_FAILED };

struct ml_dsa_cache {
        enum cache_state state;
        IMB_ML_DSA *ctx; /* context with the cached key pair bound */
        uint8_t pk[MAX_PUBKEY_BYTES];
        uint8_t sk[MAX_PRIVKEY_BYTES];
        uint8_t sig[MAX_SIG_BYTES]; /* valid signature over cached_msg */
        size_t sig_len;
};

struct ml_kem_cache {
        enum cache_state state;
        IMB_ML_KEM *ctx; /* context with the cached key pair bound */
        uint8_t ek[MAX_PUBKEY_BYTES];
        uint8_t dk[MAX_PRIVKEY_BYTES];
        uint8_t ct[MAX_CT_BYTES]; /* valid ciphertext for the cached key */
};

static struct ml_dsa_cache dsa_cache[3];
static struct ml_kem_cache kem_cache[3];

/* Message the cached ML-DSA signature is computed over */
static const uint8_t cached_msg[] = "intel-ipsec-mb PQC fuzz message";

/**
 * @brief Fill \a seed with fixed, non-secret bytes. Keeps the cached key
 *        material identical from run to run, so that findings reproduce.
 *
 * @param [out] seed  Seed buffer
 * @param [in]  len   Size of \a seed in bytes
 */
static void
fill_fixed_seed(void *seed, const size_t len)
{
        uint8_t *p = (uint8_t *) seed;

        for (size_t i = 0; i < len; i++)
                p[i] = (uint8_t) (i * 7 + 1);
}

/**
 * @brief Return the cached ML-DSA material for \a alg, generating it on first
 *        use: a key pair from a fixed seed, a context with that key bound and
 *        a valid deterministic signature over \a cached_msg.
 *
 * Caching keeps key generation off the fuzzing hot path and gives the harness
 * known good material to corrupt and feed back to the API.
 *
 * @param [in] p_mgr  Initialized IMB_MGR
 * @param [in] alg    ML-DSA parameter set
 *
 * @return Cache entry, or NULL for an invalid parameter set or on failure
 */
static struct ml_dsa_cache *
get_ml_dsa_cache(IMB_MGR *p_mgr, const IMB_ML_DSA_ALG alg)
{
        if (alg < IMB_ML_DSA_44 || alg > IMB_ML_DSA_87)
                return NULL;

        struct ml_dsa_cache *c = &dsa_cache[alg - IMB_ML_DSA_44];

        if (c->state == CACHE_READY)
                return c;
        if (c->state == CACHE_FAILED)
                return NULL;

        c->state = CACHE_FAILED;

        IMB_ML_DSA *ctx = NULL;

        if (imb_ml_dsa_new(p_mgr, alg, &ctx) != 0)
                return NULL;

        uint8_t xi[IMB_ML_DSA_KEYGEN_SEED_BYTES];
        IMB_ML_DSA_KEYGEN_PARAMS kg_params;

        fill_fixed_seed(xi, sizeof(xi));
        IMB_ML_DSA_KEYGEN_PARAMS_INIT(&kg_params);
        kg_params.xi_32 = xi;
        kg_params.xi_len = sizeof(xi);

        if (imb_ml_dsa_keypair(ctx, c->pk, ml_dsa_pk_bytes(alg), c->sk, ml_dsa_sk_bytes(alg),
                               &kg_params) != 0) {
                imb_ml_dsa_free(ctx);
                return NULL;
        }

        /* deterministic signing, so that the cached signature is reproducible */
        uint8_t rnd[IMB_ML_DSA_SIGN_RND_BYTES];
        IMB_ML_DSA_SIGN_PARAMS sign_params;

        memset(rnd, 0, sizeof(rnd));
        IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);
        sign_params.rnd_32 = rnd;
        sign_params.rnd_len = sizeof(rnd);

        c->sig_len = ml_dsa_sig_bytes(alg);
        if (imb_ml_dsa_sign(ctx, c->sig, &c->sig_len, cached_msg, sizeof(cached_msg),
                            &sign_params) != 0) {
                imb_ml_dsa_free(ctx);
                return NULL;
        }

        c->ctx = ctx;
        c->state = CACHE_READY;
        return c;
}

/**
 * @brief Return the cached ML-KEM material for \a alg, generating it on first
 *        use: a key pair from a fixed seed, a context with that key bound and
 *        a valid deterministic ciphertext.
 *
 * Caching keeps key generation off the fuzzing hot path and gives the harness
 * known good material to corrupt and feed back to the API.
 *
 * @param [in] p_mgr  Initialized IMB_MGR
 * @param [in] alg    ML-KEM parameter set
 *
 * @return Cache entry, or NULL for an invalid parameter set or on failure
 */
static struct ml_kem_cache *
get_ml_kem_cache(IMB_MGR *p_mgr, const IMB_ML_KEM_ALG alg)
{
        if (alg < IMB_ML_KEM_512 || alg > IMB_ML_KEM_1024)
                return NULL;

        struct ml_kem_cache *c = &kem_cache[alg - IMB_ML_KEM_512];

        if (c->state == CACHE_READY)
                return c;
        if (c->state == CACHE_FAILED)
                return NULL;

        c->state = CACHE_FAILED;

        IMB_ML_KEM *ctx = NULL;

        if (imb_ml_kem_new(p_mgr, alg, &ctx) != 0)
                return NULL;

        uint8_t seed[IMB_ML_KEM_KEYGEN_SEED_BYTES];
        IMB_ML_KEM_KEYGEN_PARAMS kg_params;

        fill_fixed_seed(seed, sizeof(seed));
        IMB_ML_KEM_KEYGEN_PARAMS_INIT(&kg_params);
        kg_params.seed_d_z = seed;
        kg_params.seed_d_z_len = sizeof(seed);

        if (imb_ml_kem_keypair(ctx, c->ek, ml_kem_ek_bytes(alg), c->dk, ml_kem_dk_bytes(alg),
                               &kg_params) != 0) {
                imb_ml_kem_free(ctx);
                return NULL;
        }

        /* deterministic encapsulation, so that the cached ciphertext is reproducible */
        uint8_t m[IMB_ML_KEM_ENCAP_SEED_BYTES];
        uint8_t ss[IMB_ML_KEM_SHARED_SECRET_BYTES];
        IMB_ML_KEM_ENCAP_PARAMS encap_params;

        fill_fixed_seed(m, sizeof(m));
        IMB_ML_KEM_ENCAP_PARAMS_INIT(&encap_params);
        encap_params.m_32 = m;
        encap_params.m_len = sizeof(m);

        if (imb_ml_kem_encap(ctx, c->ct, ml_kem_ct_bytes(alg), ss, sizeof(ss), &encap_params) !=
            0) {
                imb_ml_kem_free(ctx);
                return NULL;
        }

        c->ctx = ctx;
        c->state = CACHE_READY;
        return c;
}

/* ========================================================================== */
/* ML-DSA tests                                                               */
/* ========================================================================== */

/**
 * @brief Fuzz imb_ml_dsa_new() and imb_ml_dsa_free() with valid and out of
 *        range parameter set selectors, and check that freeing a NULL context
 *        is tolerated.
 */
static int
test_ml_dsa_new_free(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_DSA_ALG alg = pick_ml_dsa_alg(f);
        IMB_ML_DSA *ctx = NULL;

        (void) imb_ml_dsa_new(p_mgr, alg, &ctx);
        imb_ml_dsa_free(ctx);

        /* freeing a NULL context must be tolerated */
        imb_ml_dsa_free(NULL);
        return 0;
}

/**
 * @brief Fuzz imb_ml_dsa_keypair() with fuzzed output buffer capacities and
 *        either default (fresh random) generation or a fuzzed
 *        IMB_ML_DSA_KEYGEN_PARAMS (seed, seed length, struct size).
 *        Optionally signs afterwards to exercise the freshly bound key.
 */
static int
test_ml_dsa_keypair(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_DSA_ALG alg = pick_ml_dsa_alg(f);
        IMB_ML_DSA *ctx = NULL;

        if (imb_ml_dsa_new(p_mgr, alg, &ctx) != 0)
                return 0;

        const uint8_t opts = fz_u8(f);
        const size_t pk_len = pick_len(f, ml_dsa_pk_bytes(alg));
        const size_t sk_len = pick_len(f, ml_dsa_sk_bytes(alg));
        uint8_t *pk = calloc_exact(pk_len);
        uint8_t *sk = calloc_exact(sk_len);

        if (pk == NULL || sk == NULL)
                goto exit;

        if ((opts & 0x03) == 0) {
                /* default (fresh random) key generation */
                (void) imb_ml_dsa_keypair(ctx, pk, pk_len, sk, sk_len, NULL);
        } else {
                uint8_t xi[IMB_ML_DSA_KEYGEN_SEED_BYTES];
                IMB_ML_DSA_KEYGEN_PARAMS params;

                fz_bytes(f, xi, sizeof(xi));
                IMB_ML_DSA_KEYGEN_PARAMS_INIT(&params);
                if (opts & 0x04) {
                        params.xi_32 = xi;
                        params.xi_len = pick_len(f, sizeof(xi));
                }
                if (opts & 0x08)
                        params.size = (size_t) fz_u32(f);

                (void) imb_ml_dsa_keypair(ctx, pk, pk_len, sk, sk_len, &params);
        }

        /*
         * If key generation succeeded the context now holds a key - exercise
         * a signature with it to catch inconsistent context state.
         */
        if (opts & 0x10) {
                uint8_t *sig = calloc_exact(ml_dsa_sig_bytes(alg));
                size_t sig_len = ml_dsa_sig_bytes(alg);

                if (sig != NULL)
                        (void) imb_ml_dsa_sign(ctx, sig, &sig_len, cached_msg, sizeof(cached_msg),
                                               NULL);
                free(sig);
        }

exit:
        free(pk);
        free(sk);
        imb_ml_dsa_free(ctx);
        return 0;
}

/**
 * @brief Fuzz imb_ml_dsa_set_privkey() and imb_ml_dsa_set_pubkey() with fuzzed
 *        key lengths and either random bytes or a corrupted copy of a valid
 *        key. On a successful bind, a sign or verify is driven with the new
 *        key to catch inconsistent context state.
 */
static int
test_ml_dsa_set_key(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_DSA_ALG alg = pick_ml_dsa_alg(f);
        struct ml_dsa_cache *c = get_ml_dsa_cache(p_mgr, alg);
        IMB_ML_DSA *ctx = NULL;

        if (imb_ml_dsa_new(p_mgr, alg, &ctx) != 0)
                return 0;

        const uint8_t opts = fz_u8(f);
        const bool priv = ((opts & 1) != 0);
        const size_t exact = priv ? ml_dsa_sk_bytes(alg) : ml_dsa_pk_bytes(alg);
        const size_t key_len = pick_len(f, exact);
        const void *good = NULL;
        size_t good_len = 0;

        if (c != NULL) {
                good = priv ? (const void *) c->sk : (const void *) c->pk;
                good_len = exact;
        }

        uint8_t *key = make_input(f, key_len, good, good_len);

        if (key == NULL)
                goto exit;

        const int ret = priv ? imb_ml_dsa_set_privkey(ctx, key, key_len)
                             : imb_ml_dsa_set_pubkey(ctx, key, key_len);

        /* on a successfully bound key, drive an operation with it */
        if (ret == 0) {
                const size_t sig_len_exact = ml_dsa_sig_bytes(alg);

                if (priv) {
                        uint8_t *sig = calloc_exact(sig_len_exact);
                        size_t sig_len = sig_len_exact;

                        if (sig != NULL)
                                (void) imb_ml_dsa_sign(ctx, sig, &sig_len, cached_msg,
                                                       sizeof(cached_msg), NULL);
                        free(sig);
                } else if (c != NULL) {
                        (void) imb_ml_dsa_verify(ctx, cached_msg, sizeof(cached_msg), c->sig,
                                                 c->sig_len, NULL);
                }
        }

        free(key);
exit:
        imb_ml_dsa_free(ctx);
        return 0;
}

/**
 * @brief Build an optional ML-DSA context string, deliberately allowing
 *        lengths above IMB_ML_DSA_MAX_CTX_BYTES.
 *
 * @param [in,out] f        Fuzz input reader
 * @param [in]     opts     Fuzz driven option bits
 * @param [out]    ctx_len  Receives the context string length in bytes
 *
 * @return Buffer of exactly \a *ctx_len bytes, NULL when no context string is
 *         requested or on allocation failure
 */
static uint8_t *
make_ml_dsa_ctx_string(struct fuzz_reader *f, const uint8_t opts, size_t *ctx_len)
{
        *ctx_len = 0;

        if ((opts & 0x03) == 0)
                return NULL;

        /* deliberately allow lengths above IMB_ML_DSA_MAX_CTX_BYTES */
        *ctx_len = (size_t) (fz_u32(f) % (IMB_ML_DSA_MAX_CTX_BYTES + 16));

        uint8_t *ctx_str = calloc_exact(*ctx_len);

        if (ctx_str == NULL) {
                *ctx_len = 0;
                return NULL;
        }
        fz_bytes(f, ctx_str, *ctx_len);
        return ctx_str;
}

/**
 * @brief Fuzz imb_ml_dsa_sign() against a cached valid private key, with a
 *        fuzzed message and signature buffer capacity and either default
 *        parameters or a fuzzed IMB_ML_DSA_SIGN_PARAMS (context string,
 *        randomizer, struct size, reserved field, pre-computed mu path).
 */
static int
test_ml_dsa_sign(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_DSA_ALG alg = pick_ml_dsa_alg(f);
        struct ml_dsa_cache *c = get_ml_dsa_cache(p_mgr, alg);

        if (c == NULL)
                return 0;

        const uint8_t opts = fz_u8(f);
        const int msg_is_mu = ((opts & 0x03) == 0x03);
        const size_t msg_len =
                msg_is_mu ? pick_len(f, IMB_ML_DSA_MU_BYTES) : (size_t) (fz_u32(f) % 1024);
        uint8_t *msg = calloc_exact(msg_len);
        const size_t sig_cap = pick_len(f, ml_dsa_sig_bytes(alg));
        uint8_t *sig = calloc_exact(sig_cap);
        size_t sig_len = sig_cap;

        if (msg == NULL || sig == NULL)
                goto exit;

        fz_bytes(f, msg, msg_len);

        if (opts & 0x80) {
                /* default parameters: no context string, hedged signing */
                (void) imb_ml_dsa_sign(c->ctx, sig, &sig_len, msg, msg_len, NULL);
                goto exit;
        }

        uint8_t rnd[IMB_ML_DSA_SIGN_RND_BYTES];
        size_t ctx_len = 0;
        uint8_t *ctx_str = make_ml_dsa_ctx_string(f, opts, &ctx_len);
        IMB_ML_DSA_SIGN_PARAMS params;

        IMB_ML_DSA_SIGN_PARAMS_INIT(&params);
        params.msg_is_mu = msg_is_mu;
        params.ctx = ctx_str;
        params.ctx_len = ctx_len;

        if (opts & 0x04) {
                fz_bytes(f, rnd, sizeof(rnd));
                params.rnd_32 = rnd;
                params.rnd_len = pick_len(f, sizeof(rnd));
        }
        if (opts & 0x08)
                params.size = (size_t) fz_u32(f);
        if (opts & 0x10)
                fz_bytes(f, params.reserved, sizeof(params.reserved));
        if (opts & 0x20) {
                /* context length not matching the context string buffer */
                params.ctx_len = (size_t) (fz_u32(f) % (IMB_ML_DSA_MAX_CTX_BYTES + 1));
                params.ctx = NULL;
        }

        (void) imb_ml_dsa_sign(c->ctx, sig, &sig_len, msg, msg_len, &params);

        free(ctx_str);
exit:
        free(msg);
        free(sig);
        return 0;
}

/**
 * @brief Fuzz imb_ml_dsa_verify() against a cached valid key with a corrupted
 *        copy of a valid signature, over either the signed message or a fuzzed
 *        one, and with default or fuzzed IMB_ML_DSA_VERIFY_PARAMS.
 */
static int
test_ml_dsa_verify(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_DSA_ALG alg = pick_ml_dsa_alg(f);
        struct ml_dsa_cache *c = get_ml_dsa_cache(p_mgr, alg);

        if (c == NULL)
                return 0;

        const uint8_t opts = fz_u8(f);
        const int msg_is_mu = ((opts & 0x03) == 0x03);
        const size_t sig_len = pick_len(f, c->sig_len);
        uint8_t *sig = make_input(f, sig_len, c->sig, c->sig_len);
        const uint8_t *msg = cached_msg;
        size_t msg_len = sizeof(cached_msg);
        uint8_t *fuzz_msg = NULL;

        if (sig == NULL)
                return 0;

        /* half of the time verify against a fuzz supplied message instead */
        if (opts & 0x40) {
                msg_len =
                        msg_is_mu ? pick_len(f, IMB_ML_DSA_MU_BYTES) : (size_t) (fz_u32(f) % 1024);
                fuzz_msg = calloc_exact(msg_len);
                if (fuzz_msg == NULL)
                        goto exit;
                fz_bytes(f, fuzz_msg, msg_len);
                msg = fuzz_msg;
        }

        if (opts & 0x80) {
                (void) imb_ml_dsa_verify(c->ctx, msg, msg_len, sig, sig_len, NULL);
                goto exit;
        }

        size_t ctx_len = 0;
        uint8_t *ctx_str = make_ml_dsa_ctx_string(f, opts, &ctx_len);
        IMB_ML_DSA_VERIFY_PARAMS params;

        IMB_ML_DSA_VERIFY_PARAMS_INIT(&params);
        params.msg_is_mu = msg_is_mu;
        params.ctx = ctx_str;
        params.ctx_len = ctx_len;

        if (opts & 0x08)
                params.size = (size_t) fz_u32(f);
        if (opts & 0x10)
                fz_bytes(f, params.reserved, sizeof(params.reserved));

        (void) imb_ml_dsa_verify(c->ctx, msg, msg_len, sig, sig_len, &params);

        free(ctx_str);
exit:
        free(fuzz_msg);
        free(sig);
        return 0;
}

/**
 * @brief Fuzz imb_ml_dsa_pubkey_validate() and imb_ml_dsa_privkey_validate()
 *        with fuzzed key lengths and either random bytes or a corrupted copy
 *        of a valid key.
 */
static int
test_ml_dsa_key_validate(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_DSA_ALG alg = pick_ml_dsa_alg(f);
        struct ml_dsa_cache *c = get_ml_dsa_cache(p_mgr, alg);
        IMB_ML_DSA *ctx = NULL;

        if (imb_ml_dsa_new(p_mgr, alg, &ctx) != 0)
                return 0;

        const bool priv = ((fz_u8(f) & 1) != 0);
        const size_t exact = priv ? ml_dsa_sk_bytes(alg) : ml_dsa_pk_bytes(alg);
        const size_t key_len = pick_len(f, exact);
        const void *good = NULL;

        if (c != NULL)
                good = priv ? (const void *) c->sk : (const void *) c->pk;

        uint8_t *key = make_input(f, key_len, good, (good != NULL) ? exact : 0);

        if (key != NULL) {
                if (priv)
                        (void) imb_ml_dsa_privkey_validate(ctx, key, key_len);
                else
                        (void) imb_ml_dsa_pubkey_validate(ctx, key, key_len);
        }

        free(key);
        imb_ml_dsa_free(ctx);
        return 0;
}

/**
 * @brief Fuzz imb_ml_dsa_pubkey_from_privkey() with a random or corrupted
 *        private key and fuzzed input and output buffer lengths.
 */
static int
test_ml_dsa_pubkey_from_privkey(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_DSA_ALG alg = pick_ml_dsa_alg(f);
        struct ml_dsa_cache *c = get_ml_dsa_cache(p_mgr, alg);
        IMB_ML_DSA *ctx = NULL;

        if (imb_ml_dsa_new(p_mgr, alg, &ctx) != 0)
                return 0;

        const size_t sk_len = pick_len(f, ml_dsa_sk_bytes(alg));
        const size_t pk_len = pick_len(f, ml_dsa_pk_bytes(alg));
        uint8_t *sk = make_input(f, sk_len, (c != NULL) ? c->sk : NULL,
                                 (c != NULL) ? ml_dsa_sk_bytes(alg) : 0);
        uint8_t *pk = calloc_exact(pk_len);

        if (sk != NULL && pk != NULL)
                (void) imb_ml_dsa_pubkey_from_privkey(ctx, sk, sk_len, pk, pk_len);

        free(sk);
        free(pk);
        imb_ml_dsa_free(ctx);
        return 0;
}

/* ========================================================================== */
/* ML-KEM tests                                                               */
/* ========================================================================== */

/**
 * @brief Fuzz imb_ml_kem_new() and imb_ml_kem_free() with valid and out of
 *        range parameter set selectors, and check that freeing a NULL context
 *        is tolerated.
 */
static int
test_ml_kem_new_free(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_KEM_ALG alg = pick_ml_kem_alg(f);
        IMB_ML_KEM *ctx = NULL;

        (void) imb_ml_kem_new(p_mgr, alg, &ctx);
        imb_ml_kem_free(ctx);

        /* freeing a NULL context must be tolerated */
        imb_ml_kem_free(NULL);
        return 0;
}

/**
 * @brief Fuzz imb_ml_kem_keypair() with fuzzed output buffer capacities and
 *        either default (fresh random) generation or a fuzzed
 *        IMB_ML_KEM_KEYGEN_PARAMS (seed, seed length, struct size).
 *        Optionally encapsulates and decapsulates with the freshly bound key.
 */
static int
test_ml_kem_keypair(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_KEM_ALG alg = pick_ml_kem_alg(f);
        IMB_ML_KEM *ctx = NULL;

        if (imb_ml_kem_new(p_mgr, alg, &ctx) != 0)
                return 0;

        const uint8_t opts = fz_u8(f);
        const size_t ek_len = pick_len(f, ml_kem_ek_bytes(alg));
        const size_t dk_len = pick_len(f, ml_kem_dk_bytes(alg));
        uint8_t *ek = calloc_exact(ek_len);
        uint8_t *dk = calloc_exact(dk_len);

        if (ek == NULL || dk == NULL)
                goto exit;

        if ((opts & 0x03) == 0) {
                (void) imb_ml_kem_keypair(ctx, ek, ek_len, dk, dk_len, NULL);
        } else {
                uint8_t seed[IMB_ML_KEM_KEYGEN_SEED_BYTES];
                IMB_ML_KEM_KEYGEN_PARAMS params;

                fz_bytes(f, seed, sizeof(seed));
                IMB_ML_KEM_KEYGEN_PARAMS_INIT(&params);
                if (opts & 0x04) {
                        params.seed_d_z = seed;
                        params.seed_d_z_len = pick_len(f, sizeof(seed));
                }
                if (opts & 0x08)
                        params.size = (size_t) fz_u32(f);

                (void) imb_ml_kem_keypair(ctx, ek, ek_len, dk, dk_len, &params);
        }

        /* exercise the freshly bound key, if any */
        if (opts & 0x10) {
                uint8_t *ct = calloc_exact(ml_kem_ct_bytes(alg));
                uint8_t ss[IMB_ML_KEM_SHARED_SECRET_BYTES];

                if (ct != NULL) {
                        (void) imb_ml_kem_encap(ctx, ct, ml_kem_ct_bytes(alg), ss, sizeof(ss),
                                                NULL);
                        (void) imb_ml_kem_decap(ctx, ss, sizeof(ss), ct, ml_kem_ct_bytes(alg),
                                                NULL);
                }
                free(ct);
        }

exit:
        free(ek);
        free(dk);
        imb_ml_kem_free(ctx);
        return 0;
}

/**
 * @brief Fuzz imb_ml_kem_set_privkey() and imb_ml_kem_set_pubkey() with fuzzed
 *        key lengths and either random bytes or a corrupted copy of a valid
 *        key. On a successful bind, an encapsulation (plus a decapsulation for
 *        a private key) is driven with the new key.
 */
static int
test_ml_kem_set_key(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_KEM_ALG alg = pick_ml_kem_alg(f);
        struct ml_kem_cache *c = get_ml_kem_cache(p_mgr, alg);
        IMB_ML_KEM *ctx = NULL;

        if (imb_ml_kem_new(p_mgr, alg, &ctx) != 0)
                return 0;

        const uint8_t opts = fz_u8(f);
        const bool priv = ((opts & 1) != 0);
        const size_t exact = priv ? ml_kem_dk_bytes(alg) : ml_kem_ek_bytes(alg);
        const size_t key_len = pick_len(f, exact);
        const void *good = NULL;

        if (c != NULL)
                good = priv ? (const void *) c->dk : (const void *) c->ek;

        uint8_t *key = make_input(f, key_len, good, (good != NULL) ? exact : 0);

        if (key == NULL)
                goto exit;

        const int ret = priv ? imb_ml_kem_set_privkey(ctx, key, key_len)
                             : imb_ml_kem_set_pubkey(ctx, key, key_len);

        /* on a successfully bound key, drive an operation with it */
        if (ret == 0) {
                const size_t ct_len = ml_kem_ct_bytes(alg);
                uint8_t *ct = calloc_exact(ct_len);
                uint8_t ss[IMB_ML_KEM_SHARED_SECRET_BYTES];

                if (ct != NULL) {
                        (void) imb_ml_kem_encap(ctx, ct, ct_len, ss, sizeof(ss), NULL);
                        if (priv)
                                (void) imb_ml_kem_decap(ctx, ss, sizeof(ss), ct, ct_len, NULL);
                }
                free(ct);
        }

        free(key);
exit:
        imb_ml_kem_free(ctx);
        return 0;
}

/**
 * @brief Fuzz imb_ml_kem_encap() against a cached valid key, with fuzzed
 *        ciphertext and shared secret buffer capacities and either default
 *        parameters or a fuzzed IMB_ML_KEM_ENCAP_PARAMS (randomness,
 *        randomness length, struct size).
 */
static int
test_ml_kem_encap(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_KEM_ALG alg = pick_ml_kem_alg(f);
        struct ml_kem_cache *c = get_ml_kem_cache(p_mgr, alg);

        if (c == NULL)
                return 0;

        const uint8_t opts = fz_u8(f);
        const size_t ct_len = pick_len(f, ml_kem_ct_bytes(alg));
        const size_t ss_len = pick_len(f, IMB_ML_KEM_SHARED_SECRET_BYTES);
        uint8_t *ct = calloc_exact(ct_len);
        uint8_t *ss = calloc_exact(ss_len);

        if (ct == NULL || ss == NULL)
                goto exit;

        if ((opts & 0x03) == 0) {
                (void) imb_ml_kem_encap(c->ctx, ct, ct_len, ss, ss_len, NULL);
        } else {
                uint8_t m[IMB_ML_KEM_ENCAP_SEED_BYTES];
                IMB_ML_KEM_ENCAP_PARAMS params;

                fz_bytes(f, m, sizeof(m));
                IMB_ML_KEM_ENCAP_PARAMS_INIT(&params);
                if (opts & 0x04) {
                        params.m_32 = m;
                        params.m_len = pick_len(f, sizeof(m));
                }
                if (opts & 0x08)
                        params.size = (size_t) fz_u32(f);

                (void) imb_ml_kem_encap(c->ctx, ct, ct_len, ss, ss_len, &params);
        }

exit:
        free(ct);
        free(ss);
        return 0;
}

/**
 * @brief Fuzz imb_ml_kem_decap() against a cached valid private key with a
 *        corrupted copy of a valid ciphertext and fuzzed ciphertext and shared
 *        secret lengths. Note that the FIPS 203 implicit rejection mechanism
 *        makes a correctly sized but invalid ciphertext succeed.
 */
static int
test_ml_kem_decap(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_KEM_ALG alg = pick_ml_kem_alg(f);
        struct ml_kem_cache *c = get_ml_kem_cache(p_mgr, alg);

        if (c == NULL)
                return 0;

        const size_t exact_ct = ml_kem_ct_bytes(alg);
        const size_t ct_len = pick_len(f, exact_ct);
        const size_t ss_len = pick_len(f, IMB_ML_KEM_SHARED_SECRET_BYTES);
        uint8_t *ct = make_input(f, ct_len, c->ct, exact_ct);
        uint8_t *ss = calloc_exact(ss_len);

        if (ct != NULL && ss != NULL)
                (void) imb_ml_kem_decap(c->ctx, ss, ss_len, ct, ct_len, NULL);

        free(ct);
        free(ss);
        return 0;
}

/**
 * @brief Fuzz imb_ml_kem_pubkey_validate() and imb_ml_kem_privkey_validate()
 *        with fuzzed key lengths and either random bytes or a corrupted copy
 *        of a valid key.
 */
static int
test_ml_kem_key_validate(IMB_MGR *p_mgr, struct fuzz_reader *f)
{
        const IMB_ML_KEM_ALG alg = pick_ml_kem_alg(f);
        struct ml_kem_cache *c = get_ml_kem_cache(p_mgr, alg);
        IMB_ML_KEM *ctx = NULL;

        if (imb_ml_kem_new(p_mgr, alg, &ctx) != 0)
                return 0;

        const bool priv = ((fz_u8(f) & 1) != 0);
        const size_t exact = priv ? ml_kem_dk_bytes(alg) : ml_kem_ek_bytes(alg);
        const size_t key_len = pick_len(f, exact);
        const void *good = NULL;

        if (c != NULL)
                good = priv ? (const void *) c->dk : (const void *) c->ek;

        uint8_t *key = make_input(f, key_len, good, (good != NULL) ? exact : 0);

        if (key != NULL) {
                if (priv)
                        (void) imb_ml_kem_privkey_validate(ctx, key, key_len);
                else
                        (void) imb_ml_kem_pubkey_validate(ctx, key, key_len);
        }

        free(key);
        imb_ml_kem_free(ctx);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

/** Table of PQC API tests, indexed by the leading bytes of the fuzz input */
const struct {
        int (*func)(IMB_MGR *mb_mgr, struct fuzz_reader *f);
        const char *func_name;
} pqc_apis[] = {
        { test_ml_dsa_new_free, "test_ml_dsa_new_free" },
        { test_ml_dsa_keypair, "test_ml_dsa_keypair" },
        { test_ml_dsa_set_key, "test_ml_dsa_set_key" },
        { test_ml_dsa_sign, "test_ml_dsa_sign" },
        { test_ml_dsa_verify, "test_ml_dsa_verify" },
        { test_ml_dsa_key_validate, "test_ml_dsa_key_validate" },
        { test_ml_dsa_pubkey_from_privkey, "test_ml_dsa_pubkey_from_privkey" },

        { test_ml_kem_new_free, "test_ml_kem_new_free" },
        { test_ml_kem_keypair, "test_ml_kem_keypair" },
        { test_ml_kem_set_key, "test_ml_kem_set_key" },
        { test_ml_kem_encap, "test_ml_kem_encap" },
        { test_ml_kem_decap, "test_ml_kem_decap" },
        { test_ml_kem_key_validate, "test_ml_kem_key_validate" },
};

/**
 * @brief libFuzzer entry point. The leading 4 bytes of the input select the
 *        API test to run, the remainder is the input that test consumes.
 *
 * @param [in] data      Fuzz input
 * @param [in] dataSize  Size of \a data in bytes
 *
 * @return 0 on success, -1 when the input is too short or setup failed
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize)
{
        static IMB_MGR *p_mgr = NULL;
        unsigned selector = 0;

        /* the leading bytes of the input select the API to exercise */
        if (dataSize < sizeof(selector))
                return -1;

        memcpy(&selector, data, sizeof(selector));

        /* allocate multi-buffer manager */
        if (allocate_init_mb_mgr(&p_mgr, &fargs) != 0)
                return -1;

        struct fuzz_reader reader = { data + sizeof(selector), dataSize - sizeof(selector), 0 };
        const unsigned idx = selector % (unsigned) DIM(pqc_apis);

        /**
         * @note There is no call to free_mb_mgr() to recycle the same instance across
         *       multiple iterations. Sanitizers do not consider it as a memory leak.
         */
        return pqc_apis[idx].func(p_mgr, &reader);
}
