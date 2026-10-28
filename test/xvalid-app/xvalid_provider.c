/**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "xvalid_provider.h"

/*
 * The public provider API is intentionally backend-neutral. Selection and
 * private backend-specific initialization are handled below this layer.
 */
int
xval_prov_init(struct xval_prov *provider, const struct xval_prov_params *params)
{
        (void) params;

        if (provider == NULL) {
                fprintf(stderr, "Invalid provider init arguments\n");
                return -1;
        }

        memset(provider, 0, sizeof(*provider));
        provider->name = NULL;
        return 0;
}

/* Check whether a provider supports the selected algorithm/parameter combination. */
int
xval_prov_supports_params(const struct xval_prov *provider, const void *params)
{
        if ((provider == NULL) || (provider->supports_params == NULL))
                return 0;

        return provider->supports_params(provider, params);
}

/* Verify that both providers accept the same parameter set for a mixed-provider validation. */
int
xval_prov_common_supports_params(const struct xval_prov *enc_provider,
                                 const struct xval_prov *dec_provider, const void *params)
{
        return xval_prov_supports_params(enc_provider, params) &&
               xval_prov_supports_params(dec_provider, params);
}

/* Dispatch a cipher operation through the selected provider. */
int
xval_prov_cipher_crypt(const struct xval_prov *provider, const void *params,
                       const struct xvalid_cipher_request *request)
{
        if ((provider == NULL) || (provider->cipher_crypt == NULL))
                return -1;

        return provider->cipher_crypt(provider, params, request);
}

/* Dispatch a hash operation through the selected provider. */
int
xval_prov_hash_compute(const struct xval_prov *provider, const void *params,
                       const struct xvalid_hash_request *request)
{
        if ((provider == NULL) || (provider->hash_compute == NULL))
                return -1;

        return provider->hash_compute(provider, params, request);
}

/* Dispatch an AEAD operation through the selected provider. */
int
xval_prov_aead_crypt(const struct xval_prov *provider, const void *params,
                     const struct xvalid_aead_request *request)
{
        if ((provider == NULL) || (provider->aead_crypt == NULL))
                return -1;

        return provider->aead_crypt(provider, params, request);
}

/* Release provider resources and clear the provider state. */
void
xval_prov_free(struct xval_prov *provider)
{
        if (provider == NULL)
                return;

        if (provider->free != NULL)
                provider->free(provider);

        provider->name = NULL;
        provider->supports_params = NULL;
        provider->cipher_crypt = NULL;
        provider->hash_compute = NULL;
        provider->aead_crypt = NULL;
        provider->free = NULL;
        provider->ctx = NULL;
}
