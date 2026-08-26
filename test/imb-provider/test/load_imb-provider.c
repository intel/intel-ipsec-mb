/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static OSSL_PROVIDER *
load_imb_provider(OSSL_LIB_CTX *libctx)
{
        char *path;
        char *env_path = getenv("IMB_PROVIDER_PATH");

        if (env_path != NULL) {
                path = realpath(env_path, NULL);
        } else {
                path = realpath("../", NULL);
        }

        if (path == NULL) {
                fprintf(stderr, "Failed to resolve absolute path for provider location\n");
                return NULL;
        }

        if (OSSL_PROVIDER_set_default_search_path(libctx, path) != 1) {
                fprintf(stderr, "Failed to set default search path for imb-provider\n");
                free(path);
                return NULL;
        }
        OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "imb-provider");
        if (provider == NULL) {
                fprintf(stderr, "Failed to load imb-provider\n");
        }
        free(path);
        return provider;
}

/* Test that the imb-provider can be successfully loaded with valid configuration */
void
test_load_provider_success()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_load_provider_success passed\n");
}

/* Test that attempting to load a nonexistent provider fails gracefully */
void
test_load_provider_failure()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "nonexistent-provider");
        if (provider != NULL) {
                fprintf(stderr, "Unexpectedly loaded nonexistent provider\n");
                OSSL_PROVIDER_unload(provider);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_load_provider_failure passed\n");
}

/* Test that fetching algorithms with invalid provider properties fails */
void
test_provider_fetch_with_invalid_params()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, "SHA256", "provider=invalid-provider");
        if (md != NULL) {
                fprintf(stderr, "Unexpectedly fetched SHA256 with invalid provider\n");
                EVP_MD_free(md);
                OSSL_PROVIDER_unload(provider);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);

        printf("test_provider_fetch_with_invalid_params passed\n");
}

/* Test that the provider can be unloaded and reloaded successfully */
void
test_provider_reload()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);

        provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to reload provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);

        printf("test_provider_reload passed\n");
}

/* Test that the provider's self-test functionality works correctly */
void
test_provider_self_test()
{
        OSSL_PROVIDER *prov = NULL;

        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        prov = load_imb_provider(libctx);
        if (prov == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        if (!OSSL_PROVIDER_self_test(prov)) {
                fprintf(stderr, "Provider self-test failed\n");
                OSSL_PROVIDER_unload(prov);
                OSSL_LIB_CTX_free(libctx);
        }
}

/* Test that we can query and fetch algorithms from the provider */
void
test_provider_query_operation()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, "SHA256", "provider=imb-provider");
        if (md == NULL) {
                fprintf(stderr, "Failed to fetch SHA256 from provider\n");
                OSSL_PROVIDER_unload(provider);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD_free(md);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_query_operation passed\n");
}

/* Test that querying for invalid algorithms from the provider fails */
void
test_provider_invalid_query()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, "INVALID_QUERY", "provider=imb-provider");
        if (md != NULL) {
                fprintf(stderr, "Unexpectedly fetched INVALID_QUERY from provider\n");
                EVP_MD_free(md);
                OSSL_PROVIDER_unload(provider);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_invalid_query passed\n");
}

/* Test that we can retrieve provider parameters and status */
void
test_provider_params()
{
        OSSL_PROVIDER *prov = NULL;
        OSSL_PARAM params[2];
        unsigned int status = 0;

        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        prov = load_imb_provider(libctx);
        if (prov == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        params[0] = OSSL_PARAM_construct_uint(OSSL_PROV_PARAM_STATUS, &status);
        params[1] = OSSL_PARAM_construct_end();

        if (!OSSL_PROVIDER_get_params(prov, params)) {
                fprintf(stderr, "Failed to get provider parameters\n");
                goto err;
        }

        if (status != 1) {
                fprintf(stderr, "Provider status is not OK\n");
                goto err;
        }

err:
        OSSL_PROVIDER_unload(prov);
        OSSL_LIB_CTX_free(libctx);
}

/* Test that multiple instances of the provider can be loaded simultaneously */
void
test_provider_load_multiple()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider1 = load_imb_provider(libctx);
        if (provider1 == NULL) {
                fprintf(stderr, "Failed to load first instance of provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider2 = load_imb_provider(libctx);
        if (provider2 == NULL) {
                fprintf(stderr, "Failed to load second instance of provider\n");
                OSSL_PROVIDER_unload(provider1);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider1);
        OSSL_PROVIDER_unload(provider2);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_load_multiple passed\n");
}

/* Test that unloading a NULL provider pointer behaves correctly */
void
test_provider_unload_without_load()
{
        OSSL_PROVIDER *provider = NULL;
        int unload_result = OSSL_PROVIDER_unload(provider);
        if (unload_result != 0) {
                fprintf(stderr, "Unexpected behavior when unloading a NULL provider\n");
                exit(EXIT_FAILURE);
        }

        printf("test_provider_unload_without_load passed\n");
}

/* Test that fetching algorithms with NULL context fails */
void
test_provider_fetch_with_null_context()
{
        EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", "provider=imb-provider");
        if (md != NULL) {
                fprintf(stderr, "Unexpectedly fetched SHA256 with NULL context\n");
                EVP_MD_free(md);
                exit(EXIT_FAILURE);
        }

        printf("test_provider_fetch_with_null_context passed\n");
}

/* Test that loading a provider with an invalid search path fails */
void
test_provider_invalid_path()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        if (OSSL_PROVIDER_set_default_search_path(libctx, "/invalid/path") != 1) {
                fprintf(stderr, "Failed to set invalid search path as expected\n");
        }

        OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "imb-provider");
        if (provider != NULL) {
                fprintf(stderr, "Unexpectedly succeeded in loading provider from invalid path\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_invalid_path passed\n");
}

/* Test that querying algorithms after unloading the provider fails */
void
test_provider_query_after_unload()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);

        EVP_MD *md = EVP_MD_fetch(libctx, "SHA256", "provider=imb-provider");
        if (md != NULL) {
                fprintf(stderr, "Unexpectedly fetched SHA256 after provider unload\n");
                EVP_MD_free(md);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_query_after_unload passed\n");
}

/* Test that the provider can be unloaded successfully */
void
test_provider_unload()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        int unload_result = OSSL_PROVIDER_unload(provider);
        if (unload_result != 1) {
                fprintf(stderr, "Failed to unload provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_unload passed\n");
}

/* Test that loading a provider with NULL context fails */
void
test_provider_load_with_null_context()
{
        OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "imb-provider");
        if (provider != NULL) {
                fprintf(stderr, "Unexpectedly loaded provider with NULL context\n");
                OSSL_PROVIDER_unload(provider);
                exit(EXIT_FAILURE);
        }

        printf("test_provider_load_with_null_context passed\n");
}

/* Test that unloading the same provider multiple times behaves correctly */
void
test_provider_unload_multiple_times()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);
        int unload_result = OSSL_PROVIDER_unload(provider);
        if (unload_result != 0) {
                fprintf(stderr, "Unexpected behavior when unloading provider multiple times\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_unload_multiple_times passed\n");
}

/* Test that loading a provider with an invalid name fails */
void
test_provider_load_with_invalid_name()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, "invalid-provider-name");
        if (provider != NULL) {
                fprintf(stderr, "Unexpectedly loaded provider with invalid name\n");
                OSSL_PROVIDER_unload(provider);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_load_with_invalid_name passed\n");
}

/* Test that querying algorithms with an empty name fails */
void
test_provider_query_with_empty_name()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, "", "provider=imb-provider");
        if (md != NULL) {
                fprintf(stderr, "Unexpectedly fetched digest with empty name\n");
                EVP_MD_free(md);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_query_with_empty_name passed\n");
}

/* Test that querying algorithms with a NULL name fails */
void
test_provider_query_with_null_name()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, NULL, "provider=imb-provider");
        if (md != NULL) {
                fprintf(stderr, "Unexpectedly fetched digest with NULL name\n");
                EVP_MD_free(md);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_query_with_null_name passed\n");
}

/* Test that setting the provider search path to NULL works correctly */
void
test_provider_set_search_path_to_null()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        if (OSSL_PROVIDER_set_default_search_path(libctx, NULL) != 1) {
                fprintf(stderr, "Failed to set search path to NULL as expected\n");
        }

        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_set_search_path_to_null passed\n");
}

/* Test that fetching algorithms with empty properties works */
void
test_provider_fetch_with_empty_properties()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, "SHA256", "");
        if (md == NULL) {
                fprintf(stderr, "Failed to fetch SHA256 with empty properties\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD_free(md);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_fetch_with_empty_properties passed\n");
}

/* Test that the provider can be loaded after resetting the library context */
void
test_provider_load_after_context_reset()
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);

        libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context after reset\n");
                exit(EXIT_FAILURE);
        }

        provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider after context reset\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_load_after_context_reset passed\n");
}

/* Test that specific hash algorithms can be fetched from the provider */
void
test_provider_fetch_hash(const char *hash_name)
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, hash_name, "provider=imb-provider");
        if (md == NULL) {
                fprintf(stderr, "Failed to fetch %s from provider\n", hash_name);
                OSSL_PROVIDER_unload(provider);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD_free(md);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_fetch_%s passed\n", hash_name);
}

/* Test that supported hash algorithms can be fetched from the provider */
void
test_provider_fetch_all_hashes()
{
        const char *hashes[] = {
                /* SHA-1 / SHA-2 */
                "SHA1",
                "SHA224",
                "SHA256",
                "SHA384",
                "SHA512",
                /* SHA-3 */
                "SHA3-224",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512",
                /* SHAKE (default output length) */
                "SHAKE-128",
                "SHAKE-256",
        };
        for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
                test_provider_fetch_hash(hashes[i]);
        }
}

/*
 * Test that SHAKE-128 and SHAKE-256 accept a caller-supplied XOFLEN.
 * Exercises the SETTABLE_CTX_PARAMS dispatch path and
 * prov_shake_set_ctx_params().  The provider's update/final path requires an
 * async job context, so we only verify fetch -> init -> set_params here.
 */
void
test_provider_shake_xoflen(const char *shake_name, size_t xoflen)
{
        int ok = 0;

        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_MD *md = EVP_MD_fetch(libctx, shake_name, "provider=imb-provider");
        if (md == NULL) {
                fprintf(stderr, "Failed to fetch %s from provider\n", shake_name);
                goto err;
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx == NULL) {
                fprintf(stderr, "Failed to create EVP_MD_CTX\n");
                goto err_md;
        }

        if (!EVP_DigestInit_ex(ctx, md, NULL)) {
                fprintf(stderr, "%s: DigestInit failed\n", shake_name);
                goto err_ctx;
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_MD_CTX_set_params(ctx, params)) {
                fprintf(stderr, "%s: set XOFLEN=%zu failed\n", shake_name, xoflen);
                goto err_ctx;
        }

        ok = 1;
        printf("test_provider_%s_xoflen_%zu passed\n", shake_name, xoflen);

err_ctx:
        EVP_MD_CTX_free(ctx);
err_md:
        EVP_MD_free(md);
err:
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        if (!ok)
                exit(EXIT_FAILURE);
}

void
test_provider_fetch_all_shake_xoflen()
{
        /* Default (fits in auths[]) */
        test_provider_shake_xoflen("SHAKE-128", 32);
        test_provider_shake_xoflen("SHAKE-256", 64);
        /* Non-default lengths that fit in auths[] */
        test_provider_shake_xoflen("SHAKE-128", 16);
        test_provider_shake_xoflen("SHAKE-256", 48);
        /* Lengths that exceed auths[] and require heap allocation */
        test_provider_shake_xoflen("SHAKE-128", 128);
        test_provider_shake_xoflen("SHAKE-256", 256);
}

void
test_provider_fetch_cipher(const char *cipher_name)
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        OSSL_PROVIDER *provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_CIPHER *cipher = EVP_CIPHER_fetch(libctx, cipher_name, "provider=imb-provider");
        if (cipher == NULL) {
                fprintf(stderr, "Failed to fetch %s from provider\n", cipher_name);
                OSSL_PROVIDER_unload(provider);
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_fetch_%s passed\n", cipher_name);
}

/* Test that supported cipher algorithms can be fetched from the provider */
void
test_provider_fetch_all_ciphers()
{
        const char *ciphers[] = { "AES-128-GCM", "AES-192-GCM", "AES-256-GCM" };
        for (size_t i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); i++) {
                test_provider_fetch_cipher(ciphers[i]);
        }
}

/* Number of operations run against a single cached key */
#define PQC_OPS 4

/*
 * Test one ML-KEM parameter set following the provider's caching model:
 * generate the key once, call EVP_PKEY_encapsulate_init()/decapsulate_init()
 * once each, then run several encapsulations/decapsulations that all reuse the
 * key cached in the operation context.
 */
void
test_provider_ml_kem(const char *name)
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *provider;
        EVP_PKEY_CTX *genctx = NULL, *encctx = NULL, *decctx = NULL;
        EVP_PKEY *pkey = NULL;
        unsigned char *ct = NULL, *ss_enc = NULL, *ss_dec = NULL;
        size_t ct_len = 0, ss_len = 0, ss_dec_len = 0;
        int i;

        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        /* Key generation - done exactly once */
        genctx = EVP_PKEY_CTX_new_from_name(libctx, name, "provider=imb-provider");
        if (genctx == NULL || EVP_PKEY_keygen_init(genctx) <= 0 ||
            EVP_PKEY_keygen(genctx, &pkey) <= 0) {
                fprintf(stderr, "%s: key generation failed\n", name);
                goto err;
        }

        /* Encapsulation context - initialized once, used PQC_OPS times */
        encctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=imb-provider");
        if (encctx == NULL || EVP_PKEY_encapsulate_init(encctx, NULL) <= 0) {
                fprintf(stderr, "%s: encapsulate init failed\n", name);
                goto err;
        }
        if (EVP_PKEY_encapsulate(encctx, NULL, &ct_len, NULL, &ss_len) <= 0) {
                fprintf(stderr, "%s: encapsulate size query failed\n", name);
                goto err;
        }

        /* Decapsulation context - initialized once, used PQC_OPS times */
        decctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=imb-provider");
        if (decctx == NULL || EVP_PKEY_decapsulate_init(decctx, NULL) <= 0) {
                fprintf(stderr, "%s: decapsulate init failed\n", name);
                goto err;
        }

        ct = OPENSSL_malloc(ct_len);
        ss_enc = OPENSSL_malloc(ss_len);
        ss_dec = OPENSSL_malloc(ss_len);
        if (ct == NULL || ss_enc == NULL || ss_dec == NULL) {
                fprintf(stderr, "%s: allocation failed\n", name);
                goto err;
        }

        for (i = 0; i < PQC_OPS; i++) {
                size_t this_ct_len = ct_len, this_ss_len = ss_len;

                if (EVP_PKEY_encapsulate(encctx, ct, &this_ct_len, ss_enc, &this_ss_len) <= 0) {
                        fprintf(stderr, "%s: encapsulate %d failed\n", name, i);
                        goto err;
                }
                if (this_ct_len != ct_len || this_ss_len != ss_len) {
                        fprintf(stderr, "%s: unexpected encapsulate output sizes\n", name);
                        goto err;
                }

                ss_dec_len = ss_len;
                if (EVP_PKEY_decapsulate(decctx, ss_dec, &ss_dec_len, ct, ct_len) <= 0) {
                        fprintf(stderr, "%s: decapsulate %d failed\n", name, i);
                        goto err;
                }
                if (ss_dec_len != ss_len || memcmp(ss_enc, ss_dec, ss_len) != 0) {
                        fprintf(stderr, "%s: shared secret mismatch on iteration %d\n", name, i);
                        goto err;
                }
        }

        OPENSSL_free(ct);
        OPENSSL_free(ss_enc);
        OPENSSL_free(ss_dec);
        EVP_PKEY_CTX_free(decctx);
        EVP_PKEY_CTX_free(encctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_%s passed\n", name);
        return;

err:
        ERR_print_errors_fp(stderr);
        OPENSSL_free(ct);
        OPENSSL_free(ss_enc);
        OPENSSL_free(ss_dec);
        EVP_PKEY_CTX_free(decctx);
        EVP_PKEY_CTX_free(encctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        exit(EXIT_FAILURE);
}

/* Test that all supported ML-KEM parameter sets encapsulate and decapsulate */
void
test_provider_all_ml_kem()
{
        const char *names[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
                test_provider_ml_kem(names[i]);
        }
}

/*
 * Test one ML-DSA parameter set: generate the key once, call
 * EVP_PKEY_sign_init()/verify_init() once each, then sign and verify several
 * times reusing the key cached in the operation context.
 */
void
test_provider_ml_dsa(const char *name)
{
        static const unsigned char msg[] = "imb-provider ML-DSA test message";
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *provider;
        EVP_PKEY_CTX *genctx = NULL, *signctx = NULL, *verifyctx = NULL;
        EVP_PKEY *pkey = NULL;
        unsigned char *sig = NULL;
        size_t sig_len = 0;
        int i;

        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        /* Key generation - done exactly once */
        genctx = EVP_PKEY_CTX_new_from_name(libctx, name, "provider=imb-provider");
        if (genctx == NULL || EVP_PKEY_keygen_init(genctx) <= 0 ||
            EVP_PKEY_keygen(genctx, &pkey) <= 0) {
                fprintf(stderr, "%s: key generation failed\n", name);
                goto err;
        }

        /* Signing context - initialized once, used PQC_OPS times */
        signctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=imb-provider");
        if (signctx == NULL || EVP_PKEY_sign_init(signctx) <= 0) {
                fprintf(stderr, "%s: sign init failed\n", name);
                goto err;
        }
        if (EVP_PKEY_sign(signctx, NULL, &sig_len, msg, sizeof(msg) - 1) <= 0) {
                fprintf(stderr, "%s: signature size query failed\n", name);
                goto err;
        }

        /* Verification context - initialized once, used PQC_OPS times */
        verifyctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=imb-provider");
        if (verifyctx == NULL || EVP_PKEY_verify_init(verifyctx) <= 0) {
                fprintf(stderr, "%s: verify init failed\n", name);
                goto err;
        }

        sig = OPENSSL_malloc(sig_len);
        if (sig == NULL) {
                fprintf(stderr, "%s: allocation failed\n", name);
                goto err;
        }

        for (i = 0; i < PQC_OPS; i++) {
                size_t this_sig_len = sig_len;

                if (EVP_PKEY_sign(signctx, sig, &this_sig_len, msg, sizeof(msg) - 1) <= 0) {
                        fprintf(stderr, "%s: sign %d failed\n", name, i);
                        goto err;
                }
                if (this_sig_len != sig_len) {
                        fprintf(stderr, "%s: unexpected signature length\n", name);
                        goto err;
                }
                if (EVP_PKEY_verify(verifyctx, sig, this_sig_len, msg, sizeof(msg) - 1) != 1) {
                        fprintf(stderr, "%s: verify %d failed\n", name, i);
                        goto err;
                }

                /* A corrupted signature must not verify */
                sig[0] ^= 0x01;
                if (EVP_PKEY_verify(verifyctx, sig, this_sig_len, msg, sizeof(msg) - 1) == 1) {
                        fprintf(stderr, "%s: corrupted signature verified on iteration %d\n", name,
                                i);
                        goto err;
                }
                ERR_clear_error();
                sig[0] ^= 0x01;
        }

        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(verifyctx);
        EVP_PKEY_CTX_free(signctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_%s passed\n", name);
        return;

err:
        ERR_print_errors_fp(stderr);
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(verifyctx);
        EVP_PKEY_CTX_free(signctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        exit(EXIT_FAILURE);
}

/* Test that all supported ML-DSA parameter sets sign and verify */
void
test_provider_all_ml_dsa()
{
        const char *names[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
                test_provider_ml_dsa(names[i]);
        }
}

/* Build an EVP_PKEY from a single raw key component */
static EVP_PKEY *
pqc_key_fromdata(OSSL_LIB_CTX *libctx, const char *name, const char *param_name,
                 const unsigned char *buf, size_t buf_len, int selection)
{
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, name, "provider=imb-provider");
        EVP_PKEY *pkey = NULL;
        OSSL_PARAM params[2];

        if (ctx == NULL)
                return NULL;

        params[0] = OSSL_PARAM_construct_octet_string(param_name, (void *) buf, buf_len);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
            EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                return NULL;
        }
        EVP_PKEY_CTX_free(ctx);
        return pkey;
}

/*
 * Export the raw key components of a generated ML-KEM key, re-import them into
 * separate encapsulation-only and decapsulation-only keys, and check that the
 * two halves still agree on the shared secret. This exercises the import path,
 * where key material is decoded and cached exactly once.
 */
void
test_provider_ml_kem_import(const char *name)
{
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *provider;
        EVP_PKEY_CTX *genctx = NULL, *encctx = NULL, *decctx = NULL;
        EVP_PKEY *pkey = NULL, *enckey = NULL, *deckey = NULL;
        unsigned char *pub = NULL, *priv = NULL, *ct = NULL, *ss_enc = NULL, *ss_dec = NULL;
        size_t pub_len = 0, priv_len = 0, ct_len = 0, ss_len = 0, ss_dec_len = 0;

        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        genctx = EVP_PKEY_CTX_new_from_name(libctx, name, "provider=imb-provider");
        if (genctx == NULL || EVP_PKEY_keygen_init(genctx) <= 0 ||
            EVP_PKEY_keygen(genctx, &pkey) <= 0) {
                fprintf(stderr, "%s: key generation failed\n", name);
                goto err;
        }

        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) !=
                    1 ||
            EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &priv_len) !=
                    1) {
                fprintf(stderr, "%s: raw key size query failed\n", name);
                goto err;
        }
        pub = OPENSSL_malloc(pub_len);
        priv = OPENSSL_malloc(priv_len);
        if (pub == NULL || priv == NULL) {
                fprintf(stderr, "%s: allocation failed\n", name);
                goto err;
        }
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len,
                                            &pub_len) != 1 ||
            EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len,
                                            &priv_len) != 1) {
                fprintf(stderr, "%s: raw key export failed\n", name);
                goto err;
        }

        enckey = pqc_key_fromdata(libctx, name, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len,
                                  EVP_PKEY_PUBLIC_KEY);
        deckey = pqc_key_fromdata(libctx, name, OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len,
                                  EVP_PKEY_KEYPAIR);
        if (enckey == NULL || deckey == NULL) {
                fprintf(stderr, "%s: raw key import failed\n", name);
                goto err;
        }

        /* The decapsulation key embeds the encapsulation key - they must match */
        if (EVP_PKEY_eq(enckey, deckey) != 1) {
                fprintf(stderr, "%s: imported public and private keys do not match\n", name);
                goto err;
        }

        encctx = EVP_PKEY_CTX_new_from_pkey(libctx, enckey, "provider=imb-provider");
        decctx = EVP_PKEY_CTX_new_from_pkey(libctx, deckey, "provider=imb-provider");
        if (encctx == NULL || decctx == NULL || EVP_PKEY_encapsulate_init(encctx, NULL) <= 0 ||
            EVP_PKEY_decapsulate_init(decctx, NULL) <= 0) {
                fprintf(stderr, "%s: import operation init failed\n", name);
                goto err;
        }

        if (EVP_PKEY_encapsulate(encctx, NULL, &ct_len, NULL, &ss_len) <= 0) {
                fprintf(stderr, "%s: encapsulate size query failed\n", name);
                goto err;
        }
        ct = OPENSSL_malloc(ct_len);
        ss_enc = OPENSSL_malloc(ss_len);
        ss_dec = OPENSSL_malloc(ss_len);
        if (ct == NULL || ss_enc == NULL || ss_dec == NULL) {
                fprintf(stderr, "%s: allocation failed\n", name);
                goto err;
        }

        ss_dec_len = ss_len;
        if (EVP_PKEY_encapsulate(encctx, ct, &ct_len, ss_enc, &ss_len) <= 0 ||
            EVP_PKEY_decapsulate(decctx, ss_dec, &ss_dec_len, ct, ct_len) <= 0) {
                fprintf(stderr, "%s: imported key encap/decap failed\n", name);
                goto err;
        }
        if (ss_dec_len != ss_len || memcmp(ss_enc, ss_dec, ss_len) != 0) {
                fprintf(stderr, "%s: imported key shared secret mismatch\n", name);
                goto err;
        }

        OPENSSL_free(pub);
        OPENSSL_free(priv);
        OPENSSL_free(ct);
        OPENSSL_free(ss_enc);
        OPENSSL_free(ss_dec);
        EVP_PKEY_CTX_free(decctx);
        EVP_PKEY_CTX_free(encctx);
        EVP_PKEY_free(deckey);
        EVP_PKEY_free(enckey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_%s_import passed\n", name);
        return;

err:
        ERR_print_errors_fp(stderr);
        OPENSSL_free(pub);
        OPENSSL_free(priv);
        OPENSSL_free(ct);
        OPENSSL_free(ss_enc);
        OPENSSL_free(ss_dec);
        EVP_PKEY_CTX_free(decctx);
        EVP_PKEY_CTX_free(encctx);
        EVP_PKEY_free(deckey);
        EVP_PKEY_free(enckey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        exit(EXIT_FAILURE);
}

/*
 * Sign with a generated ML-DSA key, then verify with a public key re-imported
 * from the exported raw encoding.
 */
void
test_provider_ml_dsa_import(const char *name)
{
        static const unsigned char msg[] = "imb-provider ML-DSA import test message";
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *provider;
        EVP_PKEY_CTX *genctx = NULL, *signctx = NULL, *verifyctx = NULL;
        EVP_PKEY *pkey = NULL, *pubkey = NULL;
        unsigned char *pub = NULL, *sig = NULL;
        size_t pub_len = 0, sig_len = 0;

        if (libctx == NULL) {
                fprintf(stderr, "Failed to create library context\n");
                exit(EXIT_FAILURE);
        }

        provider = load_imb_provider(libctx);
        if (provider == NULL) {
                fprintf(stderr, "Failed to load provider\n");
                OSSL_LIB_CTX_free(libctx);
                exit(EXIT_FAILURE);
        }

        genctx = EVP_PKEY_CTX_new_from_name(libctx, name, "provider=imb-provider");
        if (genctx == NULL || EVP_PKEY_keygen_init(genctx) <= 0 ||
            EVP_PKEY_keygen(genctx, &pkey) <= 0) {
                fprintf(stderr, "%s: key generation failed\n", name);
                goto err;
        }

        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) !=
            1) {
                fprintf(stderr, "%s: raw public key size query failed\n", name);
                goto err;
        }
        pub = OPENSSL_malloc(pub_len);
        if (pub == NULL) {
                fprintf(stderr, "%s: allocation failed\n", name);
                goto err;
        }
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len,
                                            &pub_len) != 1) {
                fprintf(stderr, "%s: raw public key export failed\n", name);
                goto err;
        }

        pubkey = pqc_key_fromdata(libctx, name, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len,
                                  EVP_PKEY_PUBLIC_KEY);
        if (pubkey == NULL) {
                fprintf(stderr, "%s: raw public key import failed\n", name);
                goto err;
        }

        signctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=imb-provider");
        verifyctx = EVP_PKEY_CTX_new_from_pkey(libctx, pubkey, "provider=imb-provider");
        if (signctx == NULL || verifyctx == NULL || EVP_PKEY_sign_init(signctx) <= 0 ||
            EVP_PKEY_verify_init(verifyctx) <= 0) {
                fprintf(stderr, "%s: import operation init failed\n", name);
                goto err;
        }

        if (EVP_PKEY_sign(signctx, NULL, &sig_len, msg, sizeof(msg) - 1) <= 0) {
                fprintf(stderr, "%s: signature size query failed\n", name);
                goto err;
        }
        sig = OPENSSL_malloc(sig_len);
        if (sig == NULL) {
                fprintf(stderr, "%s: allocation failed\n", name);
                goto err;
        }
        if (EVP_PKEY_sign(signctx, sig, &sig_len, msg, sizeof(msg) - 1) <= 0) {
                fprintf(stderr, "%s: sign failed\n", name);
                goto err;
        }
        if (EVP_PKEY_verify(verifyctx, sig, sig_len, msg, sizeof(msg) - 1) != 1) {
                fprintf(stderr, "%s: verify with imported public key failed\n", name);
                goto err;
        }

        OPENSSL_free(pub);
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(verifyctx);
        EVP_PKEY_CTX_free(signctx);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        printf("test_provider_%s_import passed\n", name);
        return;

err:
        ERR_print_errors_fp(stderr);
        OPENSSL_free(pub);
        OPENSSL_free(sig);
        EVP_PKEY_CTX_free(verifyctx);
        EVP_PKEY_CTX_free(signctx);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(genctx);
        OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(libctx);
        exit(EXIT_FAILURE);
}

/* Test raw key import/export round-trips for all PQC parameter sets */
void
test_provider_all_pqc_import()
{
        const char *dsa_names[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
        const char *kem_names[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
        size_t i;

        for (i = 0; i < sizeof(dsa_names) / sizeof(dsa_names[0]); i++)
                test_provider_ml_dsa_import(dsa_names[i]);
        for (i = 0; i < sizeof(kem_names) / sizeof(kem_names[0]); i++)
                test_provider_ml_kem_import(kem_names[i]);
}

int
main()
{
        test_load_provider_success();
        test_load_provider_failure();

        test_provider_set_search_path_to_null();
        test_provider_invalid_path();

        test_provider_reload();
        test_provider_unload();
        test_provider_load_multiple();
        test_provider_unload_without_load();
        test_provider_load_with_null_context();
        test_provider_unload_multiple_times();
        test_provider_load_with_invalid_name();
        test_provider_load_after_context_reset();

        test_provider_query_operation();
        test_provider_query_with_empty_name();
        test_provider_query_with_null_name();
        test_provider_query_after_unload();
        test_provider_invalid_query();

        test_provider_fetch_with_invalid_params();
        test_provider_fetch_with_null_context();
        test_provider_fetch_with_empty_properties();
        test_provider_params();

        test_provider_fetch_all_hashes();
        test_provider_fetch_all_ciphers();
        test_provider_fetch_all_shake_xoflen();

        test_provider_all_ml_dsa();
        test_provider_all_ml_kem();
        test_provider_all_pqc_import();

        test_provider_self_test();

        printf("All tests passed\n");
        return 0;
}