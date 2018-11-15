/*******************************************************************************
  Copyright (c) 2018, Intel Corporation

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

#include "intel-ipsec-mb.h"

#ifndef NO_GCM

#ifndef _GCM_H_
#define _GCM_H_

/*
 * AVX512 GCM API
 * - intentionally this is not exposed in intel-ipsec-mb.h
 * - available through IMB_GCM_xxx() macros from intel-ipsec-mb.h
 */
IMB_DLL_EXPORT void
aes_gcm_enc_128_avx512(const struct gcm_key_data *key_data,
                       struct gcm_context_data *context_data,
                       uint8_t *out, uint8_t const *in, uint64_t len,
                       const uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len,
                       uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_avx512(const struct gcm_key_data *key_data,
                       struct gcm_context_data *context_data,
                       uint8_t *out, uint8_t const *in, uint64_t len,
                       const uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len,
                       uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_avx512(const struct gcm_key_data *key_data,
                       struct gcm_context_data *context_data,
                       uint8_t *out, uint8_t const *in, uint64_t len,
                       const uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len,
                       uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_avx512(const struct gcm_key_data *key_data,
                       struct gcm_context_data *context_data,
                       uint8_t *out, uint8_t const *in, uint64_t len,
                       const uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len,
                       uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_avx512(const struct gcm_key_data *key_data,
                       struct gcm_context_data *context_data,
                       uint8_t *out, uint8_t const *in, uint64_t len,
                       const uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len,
                       uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_avx512(const struct gcm_key_data *key_data,
                       struct gcm_context_data *context_data,
                       uint8_t *out, uint8_t const *in, uint64_t len,
                       const uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len,
                       uint8_t *auth_tag, uint64_t auth_tag_len);

IMB_DLL_EXPORT void
aes_gcm_init_128_avx512(const struct gcm_key_data *key_data,
                        struct gcm_context_data *context_data,
                        const uint8_t *iv, uint8_t const *aad,
                        uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_192_avx512(const struct gcm_key_data *key_data,
                        struct gcm_context_data *context_data,
                        const uint8_t *iv, uint8_t const *aad,
                        uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_256_avx512(const struct gcm_key_data *key_data,
                        struct gcm_context_data *context_data,
                        const uint8_t *iv, uint8_t const *aad,
                        uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_update_avx512(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              uint8_t *out, const uint8_t *in,
                              uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_update_avx512(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              uint8_t *out, const uint8_t *in,
                              uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_update_avx512(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              uint8_t *out, const uint8_t *in,
                              uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_update_avx512(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              uint8_t *out, const uint8_t *in,
                              uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_update_avx512(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              uint8_t *out, const uint8_t *in,
                              uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_update_avx512(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              uint8_t *out, const uint8_t *in,
                              uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_finalize_avx512(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_finalize_avx512(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_finalize_avx512(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_finalize_avx512(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_finalize_avx512(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_finalize_avx512(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_precomp_128_avx512(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_precomp_192_avx512(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_precomp_256_avx512(struct gcm_key_data *key_data);

IMB_DLL_EXPORT void
aes_gcm_pre_128_avx512(const void *key, struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_pre_192_avx512(const void *key, struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_pre_256_avx512(const void *key, struct gcm_key_data *key_data);

/*
 * AESNI emulation GCM API (based on SSE acrhitecture)
 * - intentionally this is not exposed in intel-ipsec-mb.h
 * - available through IMB_GCM_xxx() macros from intel-ipsec-mb.h
 */
IMB_DLL_EXPORT void
aes_gcm_enc_128_sse_no_aesni(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *out, uint8_t const *in, uint64_t len,
                             const uint8_t *iv, uint8_t const *aad,
                             uint64_t aad_len, uint8_t *auth_tag,
                             uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_sse_no_aesni(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *out, uint8_t const *in, uint64_t len,
                             const uint8_t *iv, uint8_t const *aad,
                             uint64_t aad_len, uint8_t *auth_tag,
                             uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_sse_no_aesni(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *out, uint8_t const *in, uint64_t len,
                             const uint8_t *iv,
                             uint8_t const *aad, uint64_t aad_len,
                             uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_sse_no_aesni(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *out, uint8_t const *in, uint64_t len,
                             const uint8_t *iv, uint8_t const *aad,
                             uint64_t aad_len, uint8_t *auth_tag,
                             uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_sse_no_aesni(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *out, uint8_t const *in, uint64_t len,
                             const uint8_t *iv, uint8_t const *aad,
                             uint64_t aad_len, uint8_t *auth_tag,
                             uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_sse_no_aesni(const struct gcm_key_data *key_data,
                             struct gcm_context_data *context_data,
                             uint8_t *out, uint8_t const *in, uint64_t len,
                             const uint8_t *iv, uint8_t const *aad,
                             uint64_t aad_len, uint8_t *auth_tag,
                             uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_init_128_sse_no_aesni(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              const uint8_t *iv, uint8_t const *aad,
                              uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_192_sse_no_aesni(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              const uint8_t *iv, uint8_t const *aad,
                              uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_init_256_sse_no_aesni(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data,
                              const uint8_t *iv, uint8_t const *aad,
                              uint64_t aad_len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_update_sse_no_aesni(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data,
                                    uint8_t *out, const uint8_t *in,
                                    uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_update_sse_no_aesni(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data,
                                    uint8_t *out, const uint8_t *in,
                                    uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_update_sse_no_aesni(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data,
                                    uint8_t *out, const uint8_t *in,
                                    uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_update_sse_no_aesni(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data,
                                    uint8_t *out, const uint8_t *in,
                                    uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_update_sse_no_aesni(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data,
                                    uint8_t *out, const uint8_t *in,
                                    uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_update_sse_no_aesni(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data,
                                    uint8_t *out, const uint8_t *in,
                                    uint64_t len);
IMB_DLL_EXPORT void
aes_gcm_enc_128_finalize_sse_no_aesni(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data,
                                      uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_192_finalize_sse_no_aesni(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data,
                                      uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_enc_256_finalize_sse_no_aesni(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data,
                                      uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_128_finalize_sse_no_aesni(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data,
                                      uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_192_finalize_sse_no_aesni(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data,
                                      uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_dec_256_finalize_sse_no_aesni(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data,
                                      uint8_t *auth_tag, uint64_t auth_tag_len);
IMB_DLL_EXPORT void
aes_gcm_precomp_128_sse_no_aesni(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_precomp_192_sse_no_aesni(struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_precomp_256_sse_no_aesni(struct gcm_key_data *key_data);

IMB_DLL_EXPORT void
aes_gcm_pre_128_sse_no_aesni(const void *key, struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_pre_192_sse_no_aesni(const void *key, struct gcm_key_data *key_data);
IMB_DLL_EXPORT void
aes_gcm_pre_256_sse_no_aesni(const void *key, struct gcm_key_data *key_data);

#endif /* _GCM_H_ */
#endif /* NO_GCM */
