/**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

/*
 * Provider interface for xvalid cross-validation test backends.
 *
 * Every backend used by xvalid must implement the same lifecycle and capability
 * contract described here. The app treats a provider as a pluggable crypto
 * backend whose supported feature set is negotiated at runtime, independent of
 * the specific library or implementation underneath it.
 *

 * Provider lifecycle:
 *  - allocate an initialized provider instance
 *  - query support for cipher/hash/AEAD capability groups and parameter sets
 *  - invoke the provider dispatch entry points for cryptographic operations
 *  - release provider resources via xval_prov_free()
 */

#ifndef XVAL_PROV_H
#define XVAL_PROV_H

#include <stddef.h>
#include <stdint.h>

/*
 * Backend target names are resolved privately inside the provider layer. The
 * xvalid application only supplies the generic validation inputs it needs
 * (for example enc/dec + arch) and should not depend on backend-specific
 * names or implementation identifiers.
 */

enum xvalid_cipher_direction {
        XVALID_CIPHER_DIR_ENCRYPT = 0,
        XVALID_CIPHER_DIR_DECRYPT = 1,
};

/*
 * Common request payload for block cipher operations executed through a backend.
 *
 * All pointers point to caller-owned memory whose lifetime covers the call. The
 * implementation must not retain them after returning. On in-place transforms,
 * src and dst may alias only when the provider explicitly supports that mode;
 * otherwise the caller must provide separate source and destination buffers.
 */
struct xvalid_cipher_request {
        const uint8_t *src;
        uint8_t *dst;
        uint32_t msg_len;
        const uint8_t *key;
        uint32_t key_len;
        const uint8_t *iv;
        uint32_t iv_len;
        enum xvalid_cipher_direction dir;
};

/*
 * Common request payload for hash or MAC operations.
 *
 * The payload, authentication key, and IV memory are read-only for the duration
 * of the call. The digest output buffer is caller-owned and must be written in
 * full for the requested digest length. No provider-owned storage may be
 * referenced after the call returns.
 */
struct xvalid_hash_request {
        const uint8_t *msg;
        uint32_t msg_len;
        const uint8_t *auth_key;
        uint32_t auth_key_len;
        const uint8_t *auth_iv;
        uint32_t auth_iv_len;
        uint8_t *digest;
        uint32_t digest_len;
};

/*
 * Common request payload for AEAD operations.
 *
 * The source, destination, AAD, key, IV, and tag buffers are all caller-owned
 * and remain valid for the duration of the call. For encrypt operations, tag is
 * an output buffer that the provider fills with the authentication tag. For
 * decrypt operations, tag is the caller-provided expected tag input; the
 * provider must validate the computed tag against it and return an error on any
 * mismatch without modifying the caller's tag buffer.
 */
struct xvalid_aead_request {
        const uint8_t *src;
        uint8_t *dst;
        uint32_t msg_len;
        const uint8_t *aad;
        uint32_t aad_len;
        const uint8_t *key;
        uint32_t key_len;
        const uint8_t *iv;
        uint32_t iv_len;
        uint8_t *tag;
        uint32_t tag_len;
        enum xvalid_cipher_direction dir;
};

struct xval_prov;

/*
 * Runtime instance of a provider.
 *
 * The public interface is intentionally backend-neutral: a provider owns its
 * private context behind this pointer and is free to interpret it however it
 * needs. The xvalid harness only relies on the request/response contracts
 * above and the function pointers below.
 */
struct xval_prov {
        const char *name;
        int (*supports_params)(const struct xval_prov *provider, const void *params);
        int (*cipher_crypt)(const struct xval_prov *provider, const void *params,
                            const struct xvalid_cipher_request *request);
        int (*hash_compute)(const struct xval_prov *provider, const void *params,
                            const struct xvalid_hash_request *request);
        int (*aead_crypt)(const struct xval_prov *provider, const void *params,
                          const struct xvalid_aead_request *request);
        void (*free)(struct xval_prov *provider);
        void *ctx;
};

/*
 * Generic initialization parameters for a provider implementation.
 *
 * Provider-specific configuration stays provider-specific; the shared API only
 * exposes generic runtime flags. Backends that need extra setup should define
 * their own private parameter structs and initialize them through their own
 * implementation entry points.
 */
struct xval_prov_params {
        uint64_t flags;
};

/*
 * Initialize a provider instance using the implementation selected internally by
 * the provider registry. The app does not choose backend names; it supplies the
 * validation inputs and the provider layer resolves the concrete backend and
 * architecture combination that matches the requested workload.
 *
 * @param provider Pointer to the provider instance to populate.
 * @param params Generic initialization parameters for the provider.
 *
 * @return 0 on success, negative value on failure.
 */
int
xval_prov_init(struct xval_prov *provider, const struct xval_prov_params *params);

/*
 * Query whether the provider supports the specific parameter set used by xvalid.
 */
int
xval_prov_supports_params(const struct xval_prov *provider, const void *params);

/*
 * Check the common support between two providers for a concrete parameter set.
 */
int
xval_prov_common_supports_params(const struct xval_prov *enc_provider,
                                 const struct xval_prov *dec_provider, const void *params);

/*
 * Dispatch a cipher operation to the provider.
 */
int
xval_prov_cipher_crypt(const struct xval_prov *provider, const void *params,
                       const struct xvalid_cipher_request *request);

/*
 * Dispatch a hash/MAC operation to the provider.
 */
int
xval_prov_hash_compute(const struct xval_prov *provider, const void *params,
                       const struct xvalid_hash_request *request);

/*
 * Dispatch an AEAD operation to the provider.
 */
int
xval_prov_aead_crypt(const struct xval_prov *provider, const void *params,
                     const struct xvalid_aead_request *request);

/*
 * Release all resources owned by a provider instance.
 */
void
xval_prov_free(struct xval_prov *provider);

#endif /* XVAL_PROV_H */
