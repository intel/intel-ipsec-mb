/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/**
 * imb-speed-pqc: OpenSSL-speed-style throughput / latency benchmark for
 * post-quantum algorithms exposed by intel-ipsec-mb.
 *
 * Usage: imb-speed-pqc [options] [algorithm ...]
 *
 * Algorithm names (e.g. "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512",
 * "ML-KEM-768", "ML-KEM-1024") are passed as positional arguments, mirroring
 * "openssl speed".  One or more names may be given at a time; with no
 * algorithm arguments all known algorithms are benchmarked.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#define strcasecmp _stricmp
#endif

#include <intel-ipsec-mb.h>

#define WARMUP_SECONDS  0.5
#define DEFAULT_SECONDS 10.0
#define MSG_LEN         32
#define MAX_OPS         8  /* max operations per algorithm (keygen/sign/verify/...) */
#define MAX_RESULTS     64 /* max algorithms per run */

/* ML-DSA ops[] indices */
#define ML_DSA_OP_KEYGEN 0
#define ML_DSA_OP_SIGN   1
#define ML_DSA_OP_VERIFY 2

/* ML-KEM ops[] indices */
#define ML_KEM_OP_KEYPAIR 0
#define ML_KEM_OP_ENCAPS  1
#define ML_KEM_OP_DECAPS  2

/* Deterministic PRNG seed used to diversify benchmark inputs. */
static const uint64_t prng_init = 0x123456789ABCDEF0ULL;

/**
 * @brief Benchmark result for a single algorithm (one entry per algorithm × operation).
 */
struct pqc_result {
        const char *algo; /**< algorithm name string */
        unsigned num_ops; /**< number of timed operations in ops[] */
        struct {
                const char *name; /**< operation name (e.g. "keygen", "sign") */
                uint64_t iter;    /**< number of iterations completed */
                double secs;      /**< elapsed wall-clock seconds */
        } ops[MAX_OPS];
        int valid; /**< non-zero if measurement succeeded */
};

/**
 * @brief Algorithm dispatch entry. Each supported algorithm registers a name
 *        and a measure function. New families (SLH-DSA, ...) add entries here.
 */
struct algo_entry {
        const char *name; /**< algorithm name string (e.g. "ML-DSA-44") */
        /* Returns 0 on success, -1 on failure. Populates *res. */
        int (*measure)(struct IMB_MGR *mgr, double seconds,
                       struct pqc_result *res); /**< measurement function */
};

/**
 * @brief Return current wall-clock time in seconds.
 */
static double
now_sec(void)
{
#ifdef _WIN32
        static LARGE_INTEGER freq;
        LARGE_INTEGER cnt;

        if (freq.QuadPart == 0)
                QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&cnt);
        return (double) cnt.QuadPart / (double) freq.QuadPart;
#else
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (double) ts.tv_sec + (double) ts.tv_nsec * 1e-9;
#endif
}

/**
 * @brief Fast deterministic PRNG (splitmix64); not cryptographic - only used to
 *        diversify benchmark inputs without OS randomness overhead.
 */
static uint64_t
splitmix64(uint64_t *state)
{
        uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);

        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
}

static void
fill_random_buf(uint64_t *prng, uint8_t *buf, size_t n)
{
        for (size_t i = 0; i < n; i += 8) {
                const uint64_t r = splitmix64(prng);
                const size_t k = (n - i < 8) ? (n - i) : 8;

                memcpy(buf + i, &r, k);
        }
}

typedef int (*bench_fn)(void *ctx);

/**
 * Run fn(ctx) repeatedly for the requested wall-clock window after a warm-up.
 * Returns elapsed seconds and iteration count, or -1.0 on fn() failure.
 */
static double
bench(bench_fn fn, void *ctx, const char *algo, const char *op, const double seconds,
      uint64_t *iter_out)
{
        const double warm = seconds < WARMUP_SECONDS ? seconds : WARMUP_SECONDS;
        double t0, elapsed;
        uint64_t iter = 0;

        *iter_out = 0;
        fprintf(stderr, "Running %s %s for %gs...\n", algo, op, seconds);
        fflush(stderr);

        t0 = now_sec();
        while (now_sec() - t0 < warm) {
                if (fn(ctx) != 0)
                        return -1.0;
        }

        t0 = now_sec();
        do {
                if (fn(ctx) != 0)
                        return -1.0;
                iter++;
                elapsed = now_sec() - t0;
        } while (elapsed < seconds);

        *iter_out = iter;
        return elapsed;
}

/* ML-DSA benchmark */

/* Fixed test message ("Intel ipsec-mb ML-DSA perf msg!\n"). */
static const uint8_t test_msg[MSG_LEN] = { 0x49, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x69, 0x70,
                                           0x73, 0x65, 0x63, 0x2d, 0x6d, 0x62, 0x20, 0x4d,
                                           0x4c, 0x2d, 0x44, 0x53, 0x41, 0x20, 0x70, 0x65,
                                           0x72, 0x66, 0x20, 0x6d, 0x73, 0x67, 0x21, 0x0a };

/**
 * @brief ML-DSA parameter set sizes and algorithm identifier.
 */
struct ml_dsa_variant {
        IMB_ML_DSA_ALG alg;   /**< library algorithm identifier */
        const char *name;     /**< human-readable parameter set name (e.g. "ML-DSA-44") */
        size_t pubkey_bytes;  /**< public key size in bytes */
        size_t privkey_bytes; /**< private key size in bytes */
        size_t sig_bytes;     /**< maximum signature size in bytes */
};

static const struct ml_dsa_variant ml_dsa_variants[] = {
        { IMB_ML_DSA_44, "ML-DSA-44", IMB_ML_DSA_44_PUBKEY_BYTES, IMB_ML_DSA_44_PRIVKEY_BYTES,
          IMB_ML_DSA_44_SIG_BYTES },
        { IMB_ML_DSA_65, "ML-DSA-65", IMB_ML_DSA_65_PUBKEY_BYTES, IMB_ML_DSA_65_PRIVKEY_BYTES,
          IMB_ML_DSA_65_SIG_BYTES },
        { IMB_ML_DSA_87, "ML-DSA-87", IMB_ML_DSA_87_PUBKEY_BYTES, IMB_ML_DSA_87_PRIVKEY_BYTES,
          IMB_ML_DSA_87_SIG_BYTES },
};

/**
 * @brief Per-call ML-DSA benchmark context (buffers, handle, PRNG state).
 */
struct ml_dsa_ctx {
        IMB_ML_DSA *handle;   /**< opaque library handle holding the active key pair */
        uint8_t *pk;          /**< public key buffer */
        uint8_t *sk;          /**< private key buffer */
        uint8_t *sig;         /**< signature output buffer */
        size_t sig_cap;       /**< capacity of the sig buffer in bytes */
        size_t sig_len;       /**< length of last produced signature in bytes */
        uint64_t prng;        /**< splitmix64 PRNG state for deterministic randomisation */
        uint8_t seed_buf[32]; /**< keygen seed (xi), refreshed per call */
        uint8_t rnd[32];      /**< per-signature randomizer, refreshed per call */
};

static int
ml_dsa_op_keygen(void *arg)
{
        struct ml_dsa_ctx *c = (struct ml_dsa_ctx *) arg;
        IMB_ML_DSA_KEYGEN_PARAMS params = { 0 };

        fill_random_buf(&c->prng, c->seed_buf, sizeof(c->seed_buf));
        params.xi_32 = c->seed_buf;
        /* Also binds the freshly generated key to c->handle. */
        return imb_ml_dsa_keypair(c->handle, c->pk, c->sk, &params);
}

static int
ml_dsa_op_sign(void *arg)
{
        struct ml_dsa_ctx *c = (struct ml_dsa_ctx *) arg;
        IMB_ML_DSA_SIGN_PARAMS params = { 0 };
        size_t sig_len = c->sig_cap;
        int ret;

        fill_random_buf(&c->prng, c->rnd, sizeof(c->rnd));
        params.ctx = NULL;
        params.ctx_len = 0;
        params.rnd_32 = c->rnd;
        /* Signs against the key bound to c->handle by ml_dsa_op_keygen(). */
        ret = imb_ml_dsa_sign(c->handle, c->sig, &sig_len, test_msg, MSG_LEN, &params);
        c->sig_len = sig_len;
        return ret;
}

static int
ml_dsa_op_verify(void *arg)
{
        struct ml_dsa_ctx *c = (struct ml_dsa_ctx *) arg;
        IMB_ML_DSA_VERIFY_PARAMS params = { 0 };

        params.ctx = NULL;
        params.ctx_len = 0;
        /* Verifies against the key bound to c->handle by ml_dsa_op_keygen(). */
        return imb_ml_dsa_verify(c->handle, test_msg, MSG_LEN, c->sig, c->sig_len, &params);
}

static int
measure_ml_dsa(struct IMB_MGR *mgr, const struct ml_dsa_variant *v, const double seconds,
               struct pqc_result *res)
{
        struct ml_dsa_ctx ctx;
        int ret = -1;

        memset(res, 0, sizeof(*res));
        memset(&ctx, 0, sizeof(ctx));
        res->algo = v->name;
        res->num_ops = 3;
        res->ops[ML_DSA_OP_KEYGEN].name = "keygen";
        res->ops[ML_DSA_OP_SIGN].name = "sign";
        res->ops[ML_DSA_OP_VERIFY].name = "verify";

        if (imb_ml_dsa_new(mgr, v->alg, &ctx.handle) != 0) {
                fprintf(stderr, "%s: imb_ml_dsa_new failed (errno %d: %s)\n", v->name,
                        imb_get_errno(mgr), imb_get_strerror(imb_get_errno(mgr)));
                return -1;
        }

        ctx.pk = malloc(v->pubkey_bytes);
        ctx.sk = malloc(v->privkey_bytes);
        ctx.sig = malloc(v->sig_bytes);
        ctx.sig_cap = v->sig_bytes;
        ctx.prng = prng_init;

        if (ctx.pk == NULL || ctx.sk == NULL || ctx.sig == NULL) {
                fprintf(stderr, "%s: out of memory\n", v->name);
                goto cleanup;
        }

        /* Functional self-check before measuring. */
        if (ml_dsa_op_keygen(&ctx) != 0 || ml_dsa_op_sign(&ctx) != 0 ||
            ml_dsa_op_verify(&ctx) != 0) {
                fprintf(stderr, "%s: functional self-check failed\n", v->name);
                goto cleanup;
        }

        res->ops[ML_DSA_OP_KEYGEN].secs = bench(ml_dsa_op_keygen, &ctx, v->name, "keygen", seconds,
                                                &res->ops[ML_DSA_OP_KEYGEN].iter);

        /* Produce one valid signature before benchmarking verify. */
        if (ml_dsa_op_sign(&ctx) != 0) {
                fprintf(stderr, "%s: signing failed\n", v->name);
                goto cleanup;
        }

        res->ops[ML_DSA_OP_SIGN].secs = bench(ml_dsa_op_sign, &ctx, v->name, "sign", seconds,
                                              &res->ops[ML_DSA_OP_SIGN].iter);
        res->ops[ML_DSA_OP_VERIFY].secs = bench(ml_dsa_op_verify, &ctx, v->name, "verify", seconds,
                                                &res->ops[ML_DSA_OP_VERIFY].iter);

        if (res->ops[ML_DSA_OP_KEYGEN].secs < 0.0 || res->ops[ML_DSA_OP_SIGN].secs < 0.0 ||
            res->ops[ML_DSA_OP_VERIFY].secs < 0.0) {
                fprintf(stderr, "%s: benchmark run failed\n", v->name);
                goto cleanup;
        }

        res->valid = 1;
        ret = 0;
cleanup:
        free(ctx.pk);
        free(ctx.sk);
        free(ctx.sig);
        imb_ml_dsa_free(ctx.handle);
        return ret;
}

/* One measure wrapper per variant, matching the algo_entry signature. */
static int
measure_ml_dsa_44(struct IMB_MGR *mgr, double seconds, struct pqc_result *res)
{
        return measure_ml_dsa(mgr, &ml_dsa_variants[0], seconds, res);
}

static int
measure_ml_dsa_65(struct IMB_MGR *mgr, double seconds, struct pqc_result *res)
{
        return measure_ml_dsa(mgr, &ml_dsa_variants[1], seconds, res);
}

static int
measure_ml_dsa_87(struct IMB_MGR *mgr, double seconds, struct pqc_result *res)
{
        return measure_ml_dsa(mgr, &ml_dsa_variants[2], seconds, res);
}

/* ML-KEM benchmark */
/**
 * @brief ML-KEM parameter set sizes and algorithm identifier.
 */
struct ml_kem_variant {
        IMB_ML_KEM_ALG alg;   /**< library algorithm identifier */
        const char *name;     /**< human-readable parameter set name (e.g. "ML-KEM-512") */
        size_t pubkey_bytes;  /**< encapsulation key (ek) size in bytes */
        size_t privkey_bytes; /**< decapsulation key (dk) size in bytes */
        size_t ct_bytes;      /**< ciphertext size in bytes */
};

static const struct ml_kem_variant ml_kem_variants[] = {
        { IMB_ML_KEM_512, "ML-KEM-512", IMB_ML_KEM_512_PUBKEY_BYTES, IMB_ML_KEM_512_PRIVKEY_BYTES,
          IMB_ML_KEM_512_CIPHERTEXT_BYTES },
        { IMB_ML_KEM_768, "ML-KEM-768", IMB_ML_KEM_768_PUBKEY_BYTES, IMB_ML_KEM_768_PRIVKEY_BYTES,
          IMB_ML_KEM_768_CIPHERTEXT_BYTES },
        { IMB_ML_KEM_1024, "ML-KEM-1024", IMB_ML_KEM_1024_PUBKEY_BYTES,
          IMB_ML_KEM_1024_PRIVKEY_BYTES, IMB_ML_KEM_1024_CIPHERTEXT_BYTES },
};

/**
 * @brief Per-call ML-KEM benchmark context (buffers, handle, PRNG state).
 */
struct ml_kem_ctx {
        IMB_ML_KEM *handle; /**< opaque library handle holding the active key pair */
        uint8_t *ek;        /**< encapsulation key buffer */
        uint8_t *dk;        /**< decapsulation key buffer */
        uint8_t *ct;        /**< ciphertext buffer */
        size_t ct_len;      /**< ciphertext length in bytes */
        uint8_t ss_encap[IMB_ML_KEM_SHARED_SECRET_BYTES]; /**< shared secret produced by encaps */
        uint8_t ss_decap[IMB_ML_KEM_SHARED_SECRET_BYTES]; /**< shared secret produced by decaps */
        uint64_t prng;        /**< splitmix64 PRNG state for deterministic randomisation */
        uint8_t seed_buf[64]; /**< keypair seed: FIPS 203 "d" || "z", refreshed per call */
        uint8_t m_buf[32];    /**< encaps randomizer: FIPS 203 "m", refreshed per call */
};

static int
ml_kem_op_keygen(void *arg)
{
        struct ml_kem_ctx *c = (struct ml_kem_ctx *) arg;
        IMB_ML_KEM_KEYGEN_PARAMS params;

        fill_random_buf(&c->prng, c->seed_buf, sizeof(c->seed_buf));
        params.seed_d_z = c->seed_buf;
        /* Also binds the freshly generated key to c->handle. */
        return imb_ml_kem_keypair(c->handle, c->ek, c->dk, &params);
}

static int
ml_kem_op_encap(void *arg)
{
        struct ml_kem_ctx *c = (struct ml_kem_ctx *) arg;
        IMB_ML_KEM_ENCAP_PARAMS params;

        fill_random_buf(&c->prng, c->m_buf, sizeof(c->m_buf));
        params.m_32 = c->m_buf;
        /* Encapsulates against the key bound to c->handle by ml_kem_op_keygen(). */
        return imb_ml_kem_encap(c->handle, c->ct, c->ss_encap, &params);
}

static int
ml_kem_op_decap(void *arg)
{
        struct ml_kem_ctx *c = (struct ml_kem_ctx *) arg;

        /* Decapsulates against the key bound to c->handle by ml_kem_op_keygen(). */
        return imb_ml_kem_decap(c->handle, c->ss_decap, c->ct, c->ct_len, NULL);
}

static int
measure_ml_kem(struct IMB_MGR *mgr, const struct ml_kem_variant *v, const double seconds,
               struct pqc_result *res)
{
        struct ml_kem_ctx ctx;
        int ret = -1;

        memset(res, 0, sizeof(*res));
        memset(&ctx, 0, sizeof(ctx));
        res->algo = v->name;
        res->num_ops = 3;
        res->ops[ML_KEM_OP_KEYPAIR].name = "keypair";
        res->ops[ML_KEM_OP_ENCAPS].name = "encaps";
        res->ops[ML_KEM_OP_DECAPS].name = "decaps";

        if (imb_ml_kem_new(mgr, v->alg, &ctx.handle) != 0) {
                fprintf(stderr, "%s: imb_ml_kem_new failed (errno %d: %s)\n", v->name,
                        imb_get_errno(mgr), imb_get_strerror(imb_get_errno(mgr)));
                return -1;
        }

        ctx.ek = malloc(v->pubkey_bytes);
        ctx.dk = malloc(v->privkey_bytes);
        ctx.ct = malloc(v->ct_bytes);
        ctx.ct_len = v->ct_bytes;
        ctx.prng = prng_init;

        if (ctx.ek == NULL || ctx.dk == NULL || ctx.ct == NULL) {
                fprintf(stderr, "%s: out of memory\n", v->name);
                goto cleanup;
        }

        /* Functional self-check before measuring: keypair, encaps, decaps, and
         * confirm the shared secrets agree. */
        if (ml_kem_op_keygen(&ctx) != 0 || ml_kem_op_encap(&ctx) != 0 ||
            ml_kem_op_decap(&ctx) != 0 ||
            memcmp(ctx.ss_encap, ctx.ss_decap, IMB_ML_KEM_SHARED_SECRET_BYTES) != 0) {
                fprintf(stderr, "%s: functional self-check failed\n", v->name);
                goto cleanup;
        }

        res->ops[ML_KEM_OP_KEYPAIR].secs = bench(ml_kem_op_keygen, &ctx, v->name, "keypair",
                                                 seconds, &res->ops[ML_KEM_OP_KEYPAIR].iter);

        /* Produce one valid ciphertext before benchmarking decaps. */
        if (ml_kem_op_encap(&ctx) != 0) {
                fprintf(stderr, "%s: encapsulation failed\n", v->name);
                goto cleanup;
        }

        res->ops[ML_KEM_OP_ENCAPS].secs = bench(ml_kem_op_encap, &ctx, v->name, "encaps", seconds,
                                                &res->ops[ML_KEM_OP_ENCAPS].iter);
        res->ops[ML_KEM_OP_DECAPS].secs = bench(ml_kem_op_decap, &ctx, v->name, "decaps", seconds,
                                                &res->ops[ML_KEM_OP_DECAPS].iter);

        if (res->ops[ML_KEM_OP_KEYPAIR].secs < 0.0 || res->ops[ML_KEM_OP_ENCAPS].secs < 0.0 ||
            res->ops[ML_KEM_OP_DECAPS].secs < 0.0) {
                fprintf(stderr, "%s: benchmark run failed\n", v->name);
                goto cleanup;
        }

        res->valid = 1;
        ret = 0;
cleanup:
        free(ctx.ek);
        free(ctx.dk);
        free(ctx.ct);
        imb_ml_kem_free(ctx.handle);
        return ret;
}

/* One measure wrapper per variant, matching the algo_entry signature. */
static int
measure_ml_kem_512(struct IMB_MGR *mgr, double seconds, struct pqc_result *res)
{
        return measure_ml_kem(mgr, &ml_kem_variants[0], seconds, res);
}

static int
measure_ml_kem_768(struct IMB_MGR *mgr, double seconds, struct pqc_result *res)
{
        return measure_ml_kem(mgr, &ml_kem_variants[1], seconds, res);
}

static int
measure_ml_kem_1024(struct IMB_MGR *mgr, double seconds, struct pqc_result *res)
{
        return measure_ml_kem(mgr, &ml_kem_variants[2], seconds, res);
}

/* Algorithm registry - add new families here as they are implemented. */

static const struct algo_entry known_algos[] = {
        { "ML-DSA-44", measure_ml_dsa_44 },   { "ML-DSA-65", measure_ml_dsa_65 },
        { "ML-DSA-87", measure_ml_dsa_87 },   { "ML-KEM-512", measure_ml_kem_512 },
        { "ML-KEM-768", measure_ml_kem_768 }, { "ML-KEM-1024", measure_ml_kem_1024 },
};

#define NUM_KNOWN_ALGOS (sizeof(known_algos) / sizeof(known_algos[0]))

static const struct algo_entry *
lookup_algo(const char *name)
{
        for (size_t i = 0; i < NUM_KNOWN_ALGOS; i++)
                if (strcasecmp(known_algos[i].name, name) == 0)
                        return &known_algos[i];
        return NULL;
}

/* Output */
static double
ops_per_sec(const uint64_t iter, const double secs)
{
        return (secs > 0.0) ? (double) iter / secs : 0.0;
}

static double
us_per_op(const uint64_t iter, const double secs)
{
        return (iter != 0) ? (secs * 1e6) / (double) iter : 0.0;
}

static void
print_run_info(const char *requested_arch, const char *selected_arch)
{
        fprintf(stderr,
                "Library version: %s\n"
                "Requested architecture: %s\n"
                "Selected architecture: %s\n\n",
                imb_get_version_str(), requested_arch, selected_arch);
}

/**
 * Two results belong to the same table block if they report the same set of
 * operations (e.g. ML-DSA's keygen/sign/verify vs. ML-KEM's
 * keygen/encap/decap): mixing those under one header would mislabel columns.
 */
static int
same_op_names(const struct pqc_result *a, const struct pqc_result *b)
{
        if (a->num_ops != b->num_ops)
                return 0;
        for (unsigned j = 0; j < a->num_ops; j++)
                if (strcmp(a->ops[j].name, b->ops[j].name) != 0)
                        return 0;
        return 1;
}

static void
print_table(const struct pqc_result *results, int n, const double seconds)
{
        unsigned char printed[MAX_RESULTS] = { 0 };
        int any = 0;

        for (int i = 0; i < n; i++)
                if (results[i].valid)
                        any = 1;
        if (!any)
                return;

        printf("\nPQC speed -- %s\n", imb_get_version_str());
        printf("window %g s/op\n", seconds);

        /* Emit one throughput/latency block per distinct operation set, in
         * order of first appearance, so mixed selections (e.g. ML-DSA-44
         * ML-KEM-512) each get correctly labelled columns. */
        for (int i = 0; i < n; i++) {
                const struct pqc_result *head = &results[i];

                if (!head->valid || printed[i])
                        continue;

                printf("\n%-12s", "algorithm");
                for (unsigned j = 0; j < head->num_ops; j++)
                        printf(" %14s/s", head->ops[j].name);
                printf("\n");

                for (int k = i; k < n; k++) {
                        const struct pqc_result *r = &results[k];

                        if (!r->valid || !same_op_names(r, head))
                                continue;
                        printf("%-12s", r->algo);
                        for (unsigned j = 0; j < r->num_ops; j++)
                                printf(" %15.1f", ops_per_sec(r->ops[j].iter, r->ops[j].secs));
                        printf("\n");
                }

                printf("\n%-12s", "latency");
                for (unsigned j = 0; j < head->num_ops; j++)
                        printf(" %12s(us)", head->ops[j].name);
                printf("\n");

                for (int k = i; k < n; k++) {
                        const struct pqc_result *r = &results[k];

                        if (!r->valid || !same_op_names(r, head))
                                continue;
                        printf("%-12s", r->algo);
                        for (unsigned j = 0; j < r->num_ops; j++)
                                printf(" %15.2f", us_per_op(r->ops[j].iter, r->ops[j].secs));
                        printf("\n");
                        printed[k] = 1;
                }
        }
        printf("\n");
}

static void
print_csv(const struct pqc_result *results, int n)
{
        printf("algorithm,operation,iterations,seconds,ops_per_sec,us_per_op\n");
        for (int i = 0; i < n; i++) {
                const struct pqc_result *r = &results[i];

                if (!r->valid)
                        continue;
                for (unsigned j = 0; j < r->num_ops; j++) {
                        printf("%s,%s,%llu,%.6f,%.3f,%.3f\n", r->algo, r->ops[j].name,
                               (unsigned long long) r->ops[j].iter, r->ops[j].secs,
                               ops_per_sec(r->ops[j].iter, r->ops[j].secs),
                               us_per_op(r->ops[j].iter, r->ops[j].secs));
                }
        }
}

/* CLI */

/**
 * --arch selects which init_mb_mgr_<arch>() is used to set up the IMB_MGR.
 * "AUTO" (the default) mirrors init_mb_mgr_auto(): the best ISA supported by
 * the running CPU is picked automatically.
 */
struct arch_entry {
        const char *name;           /**< architecture name string (e.g. "AVX512") */
        void (*init)(IMB_MGR *mgr); /**< function to initialise the IMB_MGR for this architecture */
};

static void
init_arch_auto(IMB_MGR *mgr)
{
        init_mb_mgr_auto(mgr, NULL);
}

static const struct arch_entry known_archs[] = {
        { "AUTO", init_arch_auto },     { "SSE", init_mb_mgr_sse },
        { "AVX2", init_mb_mgr_avx2 },   { "AVX512", init_mb_mgr_avx512 },
        { "AVX10", init_mb_mgr_avx10 },
};

#define NUM_KNOWN_ARCHS (sizeof(known_archs) / sizeof(known_archs[0]))

static const struct arch_entry *
lookup_arch(const char *name)
{
        for (size_t i = 0; i < NUM_KNOWN_ARCHS; i++)
                if (strcasecmp(known_archs[i].name, name) == 0)
                        return &known_archs[i];
        return NULL;
}

static void
usage(const char *prog)
{
        printf("Usage: %s [options] [algorithm ...]\n"
               "  --seconds, -s <float>  measurement window per operation "
               "(default: %g)\n"
               "  --arch, -a <arch>      architecture to initialize the "
               "IMB_MGR with (default: AUTO)\n"
               "  --csv, -c              emit results as CSV\n"
               "  --help, -h             show this help and exit\n"
               "\n"
               "Architectures (default: AUTO):\n",
               prog, DEFAULT_SECONDS);
        for (size_t i = 0; i < NUM_KNOWN_ARCHS; i++)
                printf("  %s\n", known_archs[i].name);
        printf("\nAlgorithms (default: all):\n");
        for (size_t i = 0; i < NUM_KNOWN_ALGOS; i++)
                printf("  %s\n", known_algos[i].name);
}

int
main(int argc, char **argv)
{
        struct pqc_result results[MAX_RESULTS];
        int num_results = 0;
        double seconds = DEFAULT_SECONDS;
        int csv = 0;
        int failures = 0;
        /* Algo names selected from the command line (positional args). */
        const char *selected[MAX_RESULTS];
        int num_selected = 0;
        const char *arch_name = "AUTO";
        const struct arch_entry *arch;
        const char *selected_arch = NULL;
        size_t i;
        IMB_MGR *mgr;

        for (i = 1; i < (size_t) argc; i++) {
                const char *a = argv[i];

                if ((strcmp(a, "--seconds") == 0 || strcmp(a, "-s") == 0) &&
                    i + 1 < (size_t) argc) {
                        seconds = strtod(argv[++i], NULL);
                } else if ((strcmp(a, "--arch") == 0 || strcmp(a, "-a") == 0) &&
                           i + 1 < (size_t) argc) {
                        arch_name = argv[++i];
                } else if (strcmp(a, "--csv") == 0 || strcmp(a, "-c") == 0) {
                        csv = 1;
                } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
                        usage(argv[0]);
                        return EXIT_SUCCESS;
                } else if (a[0] == '-') {
                        fprintf(stderr, "Unknown option: %s\n", a);
                        usage(argv[0]);
                        return EXIT_FAILURE;
                } else {
                        if (num_selected < MAX_RESULTS)
                                selected[num_selected++] = a;
                }
        }

        if (seconds <= 0.0) {
                fprintf(stderr, "--seconds must be a positive value\n");
                return EXIT_FAILURE;
        }

        arch = lookup_arch(arch_name);
        if (arch == NULL) {
                fprintf(stderr, "Unknown architecture: '%s'\n", arch_name);
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        /* Validate any explicitly named algorithms before starting. */
        for (i = 0; i < (size_t) num_selected; i++) {
                if (lookup_algo(selected[i]) == NULL) {
                        fprintf(stderr, "Unknown algorithm: '%s'\n", selected[i]);
                        usage(argv[0]);
                        return EXIT_FAILURE;
                }
        }

        mgr = alloc_mb_mgr(0);
        if (mgr == NULL) {
                fprintf(stderr, "Could not allocate IMB_MGR\n");
                return EXIT_FAILURE;
        }
        arch->init(mgr);
        if (imb_get_errno(mgr) != 0) {
                fprintf(stderr, "init_mb_mgr_%s failed (errno %d: %s)\n", arch_name,
                        imb_get_errno(mgr), imb_get_strerror(imb_get_errno(mgr)));
                free_mb_mgr(mgr);
                return EXIT_FAILURE;
        }

        if (imb_get_arch_type_string(mgr, &selected_arch, NULL) != 0 || selected_arch == NULL)
                selected_arch = "UNKNOWN";

        print_run_info(arch_name, selected_arch);

        if (num_selected == 0) {
                /* No explicit selection - run all known algorithms. */
                for (i = 0; i < NUM_KNOWN_ALGOS && num_results < MAX_RESULTS; i++) {
                        if (known_algos[i].measure(mgr, seconds, &results[num_results]) != 0)
                                failures++;
                        num_results++;
                }
        } else {
                for (i = 0; i < (size_t) num_selected && num_results < MAX_RESULTS; i++) {
                        const struct algo_entry *e = lookup_algo(selected[i]);

                        if (e->measure(mgr, seconds, &results[num_results]) != 0)
                                failures++;
                        num_results++;
                }
        }

        if (csv)
                print_csv(results, num_results);
        else
                print_table(results, num_results, seconds);

        free_mb_mgr(mgr);
        return (failures != 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
