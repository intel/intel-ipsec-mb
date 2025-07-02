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

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
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
        const char *hashes[] = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
        for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
                test_provider_fetch_hash(hashes[i]);
        }
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

        test_provider_self_test();

        printf("All tests passed\n");
        return 0;
}