/**********************************************************************
  Copyright(c) 2022-2024, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <malloc.h>
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
/* ========================================================================== */

static void
fill_data(void *d, const size_t d_size, const void *s, const size_t s_size)
{
        if (d == NULL || d_size == 0)
                return;

        memset(d, 0, d_size);

        if (s == NULL || s_size == 0)
                return;

        const size_t m_size = (s_size > d_size) ? d_size : s_size;
        memcpy(d, s, m_size);
}

/* ========================================================================== */
/* ========================================================================== */

static snow3g_key_schedule_t *snow3g_exp_key = NULL;
static uint8_t *snow3g_iv = NULL;
static uint32_t *snow3g_digest = NULL;

static void
snow3g_end(void)
{
        if (snow3g_digest != NULL)
                free(snow3g_digest);
        if (snow3g_exp_key != NULL)
                free(snow3g_exp_key);
        if (snow3g_iv != NULL)
                free(snow3g_iv);
        snow3g_exp_key = NULL;
        snow3g_iv = NULL;
        snow3g_digest = NULL;
}

static int
snow3g_start(void)
{
        snow3g_exp_key = (snow3g_key_schedule_t *) malloc(sizeof(snow3g_key_schedule_t));
        snow3g_iv = (uint8_t *) malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
        snow3g_digest = (uint32_t *) malloc(IMB_SNOW3G_DIGEST_LEN);
        if (snow3g_iv == NULL || snow3g_exp_key == NULL || snow3g_digest) {
                snow3g_end();
                return -1;
        }
        return 0;
}

static int
test_snow3g_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < sizeof(snow3g_key_schedule_t))
                return -1;

        if (snow3g_start())
                return -1;

        IMB_SNOW3G_INIT_KEY_SCHED(p_mgr, buff, snow3g_exp_key);

        snow3g_end();
        return 0;
}

static int
test_snow3g_f8_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        struct {
                uint32_t count;
                uint8_t bearer;
                uint8_t dir;
        } params;

        fill_data(&params, sizeof(params), buff, dataSize);

        void *iv = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);

        if (iv == NULL)
                return -1;
        snow3g_f8_iv_gen(params.count, params.bearer, params.dir, iv);
        free(iv);
        return 0;
}

static int
test_snow3g_f9_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        struct {
                uint32_t count;
                uint32_t fresh;
                uint8_t dir;
        } params;

        fill_data(&params, sizeof(params), buff, dataSize);

        void *iv = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);

        if (iv == NULL)
                return -1;
        snow3g_f9_iv_gen(params.count, params.fresh, params.dir, iv);
        free(iv);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static struct gcm_key_data *gcm_key = NULL;
static struct gcm_context_data *gcm_ctx = NULL;
static uint8_t *gcm_iv = NULL;
static uint8_t *gcm_aad = NULL;
static uint64_t gcm_aad_len;
static uint8_t *gcm_auth_tag = NULL;
static uint64_t gcm_tag_len;

static void
gcm_end(void)
{
        if (gcm_key != NULL)
                free(gcm_key);
        if (gcm_ctx != NULL)
                free(gcm_ctx);
        if (gcm_iv != NULL)
                free(gcm_iv);
        if (gcm_aad != NULL)
                free(gcm_aad);
        if (gcm_auth_tag != NULL)
                free(gcm_auth_tag);
        gcm_key = NULL;
        gcm_ctx = NULL;
        gcm_iv = NULL;
        gcm_aad = NULL;
        gcm_aad_len = 0;
        gcm_auth_tag = NULL;
        gcm_tag_len = 0;
}

static int
gcm_start(const size_t dataSize, const uint8_t *data)
{
        gcm_key = (struct gcm_key_data *) memalign(16, sizeof(struct gcm_key_data));
        gcm_ctx = (struct gcm_context_data *) memalign(16, sizeof(struct gcm_context_data));
        gcm_iv = (uint8_t *) malloc(IMB_GCM_IV_DATA_LEN);
        gcm_aad_len = dataSize;
        gcm_aad = (uint8_t *) malloc(gcm_aad_len);
        gcm_tag_len = dataSize;
        gcm_auth_tag = (uint8_t *) malloc(gcm_tag_len);
        if (gcm_key == NULL || gcm_ctx == NULL || gcm_iv == NULL || gcm_aad == NULL ||
            gcm_auth_tag == NULL) {
                gcm_end();
                return -1;
        }
        fill_data(gcm_key, sizeof(struct gcm_key_data), data, dataSize);
        fill_data(gcm_ctx, sizeof(struct gcm_context_data), data, dataSize);
        fill_data(gcm_iv, IMB_GCM_IV_DATA_LEN, data, dataSize);
        fill_data(gcm_aad, gcm_aad_len, data, dataSize);
        fill_data(gcm_auth_tag, gcm_tag_len, data, dataSize);
        return 0;
}

static int
test_aes_gcm_precomp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        if (dataSize >= IMB_KEY_256_BYTES)
                IMB_AES256_GCM_PRECOMP(p_mgr, gcm_key);
        else if (dataSize >= IMB_KEY_192_BYTES)
                IMB_AES192_GCM_PRECOMP(p_mgr, gcm_key);
        else
                IMB_AES128_GCM_PRECOMP(p_mgr, gcm_key);

        gcm_end();
        return 0;
}

static int
test_aes128_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_init_var_iv(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, gcm_key, gcm_ctx, buff, dataSize, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

static int
test_aes_gcm_pre(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KEY_128_BYTES)
                return -1;

        if (gcm_start(dataSize, buff) != 0)
                return -1;

        if (dataSize >= IMB_KEY_256_BYTES)
                IMB_AES256_GCM_PRE(p_mgr, buff, gcm_key);
        else if (dataSize >= IMB_KEY_192_BYTES)
                IMB_AES192_GCM_PRE(p_mgr, buff, gcm_key);
        else
                IMB_AES128_GCM_PRE(p_mgr, buff, gcm_key);

        gcm_end();
        return 0;
}

static int
test_aes128_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes128_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES192_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES192_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_ENC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_DEC(p_mgr, gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                           gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes128_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES128_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES128_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes128_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES128_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES128_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES128_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        uint64_t len = dataSize;

        IMB_AES192_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES192_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES192_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES192_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES192_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES192_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_enc_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES256_GCM_ENC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES256_GCM_ENC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gcm_dec_sgl(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_AES256_GCM_INIT(p_mgr, gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        IMB_AES256_GCM_DEC_UPDATE(p_mgr, gcm_key, gcm_ctx, out, in, len);
        IMB_AES256_GCM_DEC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_aes128_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        /* use GCM AAD field as GMAC IV */
        IMB_AES128_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
        IMB_AES128_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
        IMB_AES128_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes192_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        /* use GCM AAD field as GMAC IV */
        IMB_AES192_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
        IMB_AES192_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
        IMB_AES192_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

static int
test_aes256_gmac(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        /* use GCM AAD field as GMAC IV */
        IMB_AES256_GMAC_INIT(p_mgr, gcm_key, gcm_ctx, gcm_aad, gcm_aad_len);
        IMB_AES256_GMAC_UPDATE(p_mgr, gcm_key, gcm_ctx, buff, dataSize);
        IMB_AES256_GMAC_FINALIZE(p_mgr, gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_ghash_pre(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        /* GHASH key size */
        if (dataSize < 16)
                return -1;

        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_GHASH_PRE(p_mgr, buff, gcm_key);

        gcm_end();
        return 0;
}

static int
test_ghash(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (gcm_start(dataSize, buff) != 0)
                return -1;

        IMB_GHASH(p_mgr, gcm_key, buff, dataSize, gcm_auth_tag, gcm_tag_len);

        gcm_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_zuc_eea3_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        struct {
                uint32_t count;
                uint8_t bearer;
                uint8_t dir;
        } params;

        fill_data(&params, sizeof(params), buff, dataSize);

        void *iv = malloc(IMB_ZUC_IV_LEN_IN_BYTES);

        if (iv == NULL)
                return -1;
        zuc_eea3_iv_gen(params.count, params.bearer, params.dir, iv);
        free(iv);
        return 0;
}

static int
test_zuc_eia3_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        struct {
                uint32_t count;
                uint8_t bearer;
                uint8_t dir;
        } params;

        fill_data(&params, sizeof(params), buff, dataSize);

        void *iv = malloc(IMB_ZUC_IV_LEN_IN_BYTES);

        if (iv == NULL)
                return -1;
        zuc_eia3_iv_gen(params.count, params.bearer, params.dir, iv);
        free(iv);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint8_t *ccp_key = NULL;
static struct chacha20_poly1305_context_data *ccp_ctx = NULL;
static uint8_t *ccp_iv = NULL;
static uint8_t *ccp_aad = NULL;
static uint64_t ccp_aad_len;
static uint8_t *ccp_auth_tag = NULL;
static uint64_t ccp_tag_len;

static void
ccp_end(void)
{
        if (ccp_key != NULL)
                free(ccp_key);
        if (ccp_ctx != NULL)
                free(ccp_ctx);
        if (ccp_iv != NULL)
                free(ccp_iv);
        if (ccp_aad != NULL)
                free(ccp_aad);
        if (ccp_auth_tag != NULL)
                free(ccp_auth_tag);
        ccp_key = NULL;
        ccp_ctx = NULL;
        ccp_iv = NULL;
        ccp_aad = NULL;
        ccp_aad_len = 0;
        ccp_auth_tag = NULL;
        ccp_tag_len = 0;
}

static int
ccp_start(const size_t dataSize, const uint8_t *data)
{
        ccp_key = (uint8_t *) malloc(IMB_CHACHA20_POLY1305_KEY_SIZE);
        ccp_ctx = (struct chacha20_poly1305_context_data *) memalign(
                16, sizeof(struct chacha20_poly1305_context_data));
        ccp_iv = (uint8_t *) malloc(IMB_CHACHA20_POLY1305_IV_SIZE);
        ccp_aad_len = dataSize;
        ccp_aad = (uint8_t *) malloc(ccp_aad_len);
        ccp_tag_len = dataSize;
        ccp_auth_tag = (uint8_t *) malloc(ccp_tag_len);
        if (ccp_key == NULL || ccp_ctx == NULL || ccp_iv == NULL || ccp_aad == NULL ||
            ccp_auth_tag == NULL) {
                ccp_end();
                return -1;
        }
        fill_data(ccp_key, IMB_CHACHA20_POLY1305_KEY_SIZE, data, dataSize);
        fill_data(ccp_ctx, sizeof(struct chacha20_poly1305_context_data), data, dataSize);
        fill_data(ccp_iv, IMB_CHACHA20_POLY1305_IV_SIZE, data, dataSize);
        fill_data(ccp_aad, ccp_aad_len, data, dataSize);
        fill_data(ccp_auth_tag, ccp_tag_len, data, dataSize);
        return 0;
}

static int
test_chacha_poly_enc(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (ccp_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_CHACHA20_POLY1305_INIT(p_mgr, ccp_key, ccp_ctx, ccp_iv, ccp_aad, ccp_aad_len);
        IMB_CHACHA20_POLY1305_ENC_UPDATE(p_mgr, ccp_key, ccp_ctx, out, in, len);
        IMB_CHACHA20_POLY1305_ENC_FINALIZE(p_mgr, ccp_ctx, ccp_auth_tag, ccp_tag_len);

        ccp_end();
        return 0;
}

static int
test_chacha_poly_dec(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (ccp_start(dataSize, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = dataSize;

        IMB_CHACHA20_POLY1305_INIT(p_mgr, ccp_key, ccp_ctx, ccp_iv, ccp_aad, ccp_aad_len);
        IMB_CHACHA20_POLY1305_DEC_UPDATE(p_mgr, ccp_key, ccp_ctx, out, in, len);
        IMB_CHACHA20_POLY1305_DEC_FINALIZE(p_mgr, ccp_ctx, ccp_auth_tag, ccp_tag_len);

        ccp_end();
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static uint64_t *kasumi_iv = NULL;
static kasumi_key_sched_t *kasumi_key = NULL;
static uint32_t *kasumi_tag = NULL;

static void
kasumi_end(void)
{
        if (kasumi_key != NULL)
                free(kasumi_key);
        if (kasumi_iv != NULL)
                free(kasumi_iv);
        if (kasumi_tag != NULL)
                free(kasumi_tag);
        kasumi_key = NULL;
        kasumi_iv = NULL;
        kasumi_tag = NULL;
}

static int
kasumi_start(const size_t dataSize, const uint8_t *data)
{
        kasumi_key = (kasumi_key_sched_t *) malloc(sizeof(kasumi_key_sched_t));
        kasumi_iv = (uint64_t *) malloc(IMB_KASUMI_IV_SIZE);
        kasumi_tag = (uint32_t *) malloc(IMB_KASUMI_DIGEST_SIZE);

        if (kasumi_key == NULL || kasumi_iv == NULL || kasumi_tag == NULL) {
                kasumi_end();
                return -1;
        }
        fill_data(kasumi_key, sizeof(kasumi_key_sched_t), data, dataSize);
        fill_data(kasumi_iv, IMB_KASUMI_IV_SIZE, data, dataSize);
        fill_data(kasumi_tag, IMB_KASUMI_DIGEST_SIZE, data, dataSize);
        return 0;
}

static int
test_kasumi_f8_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_KEY_SIZE)
                return -1;

        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        IMB_KASUMI_INIT_F8_KEY_SCHED(p_mgr, buff, kasumi_key);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f8_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        struct {
                uint32_t count;
                uint8_t bearer;
                uint8_t dir;
        } params;

        fill_data(&params, sizeof(params), buff, dataSize);

        void *iv = malloc(IMB_KASUMI_IV_SIZE);

        if (iv == NULL)
                return -1;
        kasumi_f8_iv_gen(params.count, params.bearer, params.dir, iv);
        free(iv);
        return 0;
}

static int
test_kasumi_f9_init_key_sched(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KASUMI_KEY_SIZE)
                return -1;

        if (kasumi_start(dataSize, buff) != 0)
                return -1;

        IMB_KASUMI_INIT_F9_KEY_SCHED(p_mgr, buff, kasumi_key);
        kasumi_end();
        return 0;
}

static int
test_kasumi_f9_iv_gen(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        struct {
                uint32_t count;
                uint32_t fresh;
        } params;

        fill_data(&params, sizeof(params), buff, dataSize);

        void *iv = malloc(IMB_KASUMI_IV_SIZE);

        if (iv == NULL)
                return -1;
        kasumi_f9_iv_gen(params.count, params.fresh, iv);
        free(iv);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_clear_mem(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        imb_clear_mem(buff, dataSize);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static void
test_aes_exp_free(void **ekey, void **dkey)
{
        void *e = *ekey;
        void *d = *dkey;

        if (e != NULL)
                free(e);
        if (d != NULL)
                free(d);
        *ekey = NULL;
        *dkey = NULL;
}

static int
test_aes_exp_alloc(const unsigned rounds, void **ekey, void **dkey)
{
        void *e = malloc(rounds * 16);
        void *d = malloc(rounds * 16);

        *ekey = e;
        *dkey = d;

        if (e == NULL || d == NULL) {
                test_aes_exp_free(ekey, dkey);
                return -1;
        }

        return 0;
}

static int
test_imb_aes_keyexp_128(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KEY_128_BYTES)
                return -1;

        void *ekey, *dkey;

        if (test_aes_exp_alloc(11, &ekey, &dkey) != 0)
                return -1;

        IMB_AES_KEYEXP_128(p_mgr, buff, ekey, dkey);
        test_aes_exp_free(&ekey, &dkey);
        return 0;
}

static int
test_imb_aes_keyexp_192(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KEY_192_BYTES)
                return -1;

        void *ekey, *dkey;

        if (test_aes_exp_alloc(13, &ekey, &dkey) != 0)
                return -1;

        IMB_AES_KEYEXP_192(p_mgr, buff, ekey, dkey);
        test_aes_exp_free(&ekey, &dkey);
        return 0;
}

static int
test_imb_aes_keyexp_256(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        if (dataSize < IMB_KEY_256_BYTES)
                return -1;

        void *ekey, *dkey;

        if (test_aes_exp_alloc(15, &ekey, &dkey) != 0)
                return -1;

        IMB_AES_KEYEXP_256(p_mgr, buff, ekey, dkey);
        test_aes_exp_free(&ekey, &dkey);
        return 0;
}

static int
test_imb_aes_subkey_cmac128(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        void *skey1, *skey2, *ekey, *dkey;

        if (test_aes_exp_alloc(1, &skey1, &skey2) != 0)
                return -1;

        if (test_aes_exp_alloc(11, &ekey, &dkey) != 0) {
                test_aes_exp_free(&skey1, &skey2);
                return -1;
        }

        const size_t sz_ekey = 11 * 16;

        memset(ekey, 0, sz_ekey);
        memcpy(ekey, buff, (dataSize > sz_ekey) ? sz_ekey : dataSize);

        IMB_AES_CMAC_SUBKEY_GEN_128(p_mgr, ekey, skey1, skey2);

        test_aes_exp_free(&skey1, &skey2);
        test_aes_exp_free(&ekey, &dkey);
        return 0;
}

static int
test_imb_aes_subkey_cmac256(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        void *skey1, *skey2, *ekey, *dkey;

        if (test_aes_exp_alloc(1, &skey1, &skey2) != 0)
                return -1;

        if (test_aes_exp_alloc(15, &ekey, &dkey) != 0) {
                test_aes_exp_free(&skey1, &skey2);
                return -1;
        }

        const size_t sz_ekey = 15 * 16;

        memset(ekey, 0, sz_ekey);
        memcpy(ekey, buff, (dataSize > sz_ekey) ? sz_ekey : dataSize);

        IMB_AES_CMAC_SUBKEY_GEN_256(p_mgr, ekey, skey1, skey2);

        test_aes_exp_free(&skey1, &skey2);
        test_aes_exp_free(&ekey, &dkey);
        return 0;
}

static int
test_imb_aes_keyexp_xcbc128(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        void *key2, *key3, *key, *key_dust;
        void *expkey, *expkey_dust;

        if (test_aes_exp_alloc(1, &key2, &key3) != 0)
                return -1;

        if (test_aes_exp_alloc(1, &key, &key_dust) != 0) {
                test_aes_exp_free(&key2, &key3);
                return -1;
        }

        if (test_aes_exp_alloc(11, &expkey, &expkey_dust) != 0) {
                test_aes_exp_free(&key2, &key3);
                test_aes_exp_free(&key, &key_dust);
                return -1;
        }

        memset(key, 0, 16);
        memcpy(key, buff, (dataSize > 16) ? 16 : dataSize);

        IMB_AES_XCBC_KEYEXP(p_mgr, key, expkey, key2, key3);

        test_aes_exp_free(&key2, &key3);
        test_aes_exp_free(&key, &key_dust);
        test_aes_exp_free(&expkey, &expkey_dust);
        return 0;
}

static int
test_imb_des_keyexp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        void *key = malloc(sizeof(uint64_t));

        if (key == NULL)
                return -1;

        void *expkey = malloc(IMB_DES_KEY_SCHED_SIZE);

        if (expkey == NULL) {
                free(key);
                return -1;
        }

        memset(key, 0, sizeof(uint64_t));
        memcpy(key, buff, (dataSize > sizeof(uint64_t)) ? sizeof(uint64_t) : dataSize);

        IMB_DES_KEYSCHED(p_mgr, expkey, key);

        free(key);
        free(expkey);
        return 0;
}

static int
test_imb_sm4_keyexp(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        void *key = malloc(IMB_KEY_128_BYTES);
        if (key == NULL)
                return -1;

        fill_data(key, IMB_KEY_128_BYTES, buff, dataSize);

        void *ekey, *dkey;

        if (test_aes_exp_alloc((IMB_SM4_KEY_SCHEDULE_ROUNDS * 4) / 16, &ekey, &dkey) != 0) {
                free(key);
                return -1;
        }

        IMB_SM4_KEYEXP(p_mgr, key, ekey, dkey);
        test_aes_exp_free(&ekey, &dkey);
        free(key);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_sha1(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t tag_sz = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
        void *tag = malloc(tag_sz);

        if (tag == NULL)
                return -1;

        IMB_SHA1(p_mgr, buff, dataSize, tag);

        free(tag);
        return 0;
}

static int
test_imb_sha224(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t tag_sz = IMB_SHA224_DIGEST_SIZE_IN_BYTES;
        void *tag = malloc(tag_sz);

        if (tag == NULL)
                return -1;

        IMB_SHA224(p_mgr, buff, dataSize, tag);

        free(tag);
        return 0;
}

static int
test_imb_sha256(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t tag_sz = IMB_SHA256_DIGEST_SIZE_IN_BYTES;
        void *tag = malloc(tag_sz);

        if (tag == NULL)
                return -1;

        IMB_SHA256(p_mgr, buff, dataSize, tag);

        free(tag);
        return 0;
}

static int
test_imb_sha384(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t tag_sz = IMB_SHA384_DIGEST_SIZE_IN_BYTES;
        void *tag = malloc(tag_sz);

        if (tag == NULL)
                return -1;

        IMB_SHA384(p_mgr, buff, dataSize, tag);

        free(tag);
        return 0;
}

static int
test_imb_sha512(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t tag_sz = IMB_SHA512_DIGEST_SIZE_IN_BYTES;
        void *tag = malloc(tag_sz);

        if (tag == NULL)
                return -1;

        IMB_SHA512(p_mgr, buff, dataSize, tag);

        free(tag);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_hec32(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t xgem_sz = 4;
        void *xgem = malloc(xgem_sz);

        if (xgem == NULL)
                return -1;

        fill_data(xgem, xgem_sz, buff, dataSize);

        IMB_HEC_32(p_mgr, xgem);

        free(xgem);
        return 0;
}

static int
test_imb_hec64(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t xgem_sz = 8;
        void *xgem = malloc(xgem_sz);

        if (xgem == NULL)
                return -1;

        fill_data(xgem, xgem_sz, buff, dataSize);

        IMB_HEC_64(p_mgr, xgem);

        free(xgem);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct test_hash_one_block {
        void *tag;
        void *block;
};

static void
test_hash_one_block_free(struct test_hash_one_block *ts)
{
        if (ts->tag != NULL)
                free(ts->tag);
        if (ts->block != NULL)
                free(ts->block);
        memset(ts, 0, sizeof(*ts));
}

static int
test_hash_one_block_alloc(struct test_hash_one_block *ts, const size_t tag_size,
                          const size_t block_size)
{
        ts->tag = malloc(tag_size);
        ts->block = malloc(block_size);
        if (ts->tag == NULL || ts->block == NULL) {
                test_hash_one_block_free(ts);
                return -1;
        }
        return 0;
}

static int
test_imb_sha1_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_hash_one_block ts;

        if (test_hash_one_block_alloc(&ts, IMB_SHA1_DIGEST_SIZE_IN_BYTES, IMB_SHA1_BLOCK_SIZE) != 0)
                return -1;

        fill_data(ts.block, IMB_SHA1_BLOCK_SIZE, buff, dataSize);

        IMB_SHA1_ONE_BLOCK(p_mgr, ts.block, ts.tag);

        test_hash_one_block_free(&ts);
        return 0;
}

static int
test_imb_sha224_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_hash_one_block ts;

        if (test_hash_one_block_alloc(&ts, IMB_SHA256_DIGEST_SIZE_IN_BYTES,
                                      IMB_SHA_224_BLOCK_SIZE) != 0)
                return -1;

        fill_data(ts.block, IMB_SHA_224_BLOCK_SIZE, buff, dataSize);

        IMB_SHA224_ONE_BLOCK(p_mgr, ts.block, ts.tag);

        test_hash_one_block_free(&ts);
        return 0;
}

static int
test_imb_sha256_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_hash_one_block ts;

        if (test_hash_one_block_alloc(&ts, IMB_SHA256_DIGEST_SIZE_IN_BYTES,
                                      IMB_SHA_256_BLOCK_SIZE) != 0)
                return -1;

        fill_data(ts.block, IMB_SHA_256_BLOCK_SIZE, buff, dataSize);

        IMB_SHA256_ONE_BLOCK(p_mgr, ts.block, ts.tag);

        test_hash_one_block_free(&ts);
        return 0;
}

static int
test_imb_sha384_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_hash_one_block ts;

        if (test_hash_one_block_alloc(&ts, IMB_SHA512_DIGEST_SIZE_IN_BYTES,
                                      IMB_SHA_384_BLOCK_SIZE) != 0)
                return -1;

        fill_data(ts.block, IMB_SHA_384_BLOCK_SIZE, buff, dataSize);

        IMB_SHA384_ONE_BLOCK(p_mgr, ts.block, ts.tag);

        test_hash_one_block_free(&ts);
        return 0;
}

static int
test_imb_sha512_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_hash_one_block ts;

        if (test_hash_one_block_alloc(&ts, IMB_SHA512_DIGEST_SIZE_IN_BYTES,
                                      IMB_SHA_512_BLOCK_SIZE) != 0)
                return -1;

        fill_data(ts.block, IMB_SHA_512_BLOCK_SIZE, buff, dataSize);

        IMB_SHA512_ONE_BLOCK(p_mgr, ts.block, ts.tag);

        test_hash_one_block_free(&ts);
        return 0;
}

static int
test_imb_md5_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_hash_one_block ts;

        if (test_hash_one_block_alloc(&ts, IMB_MD5_DIGEST_SIZE_IN_BYTES, IMB_MD5_BLOCK_SIZE) != 0)
                return -1;

        fill_data(ts.block, IMB_MD5_BLOCK_SIZE, buff, dataSize);

        IMB_MD5_ONE_BLOCK(p_mgr, ts.block, ts.tag);

        test_hash_one_block_free(&ts);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_hmac_ipad_opad(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const struct {
                IMB_HASH_ALG hash;
                size_t digest_size;
        } htab[] = {
                { IMB_AUTH_HMAC_SHA_1, IMB_SHA1_DIGEST_SIZE_IN_BYTES },
                { IMB_AUTH_HMAC_SHA_224, IMB_SHA256_DIGEST_SIZE_IN_BYTES },
                { IMB_AUTH_HMAC_SHA_256, IMB_SHA256_DIGEST_SIZE_IN_BYTES },
                { IMB_AUTH_HMAC_SHA_384, IMB_SHA512_DIGEST_SIZE_IN_BYTES },
                { IMB_AUTH_HMAC_SHA_512, IMB_SHA512_DIGEST_SIZE_IN_BYTES },
                { IMB_AUTH_MD5, IMB_MD5_DIGEST_SIZE_IN_BYTES },
                { IMB_AUTH_GHASH, 1 }, /* invalid */
        };
        const size_t index = dataSize > 0 ? (buff[0] % IMB_DIM(htab)) : 0;

        void *opad = malloc(htab[index].digest_size);

        if (opad == NULL)
                return -1;

        void *ipad = malloc(htab[index].digest_size);

        if (ipad == NULL) {
                free(opad);
                return -1;
        }

        imb_hmac_ipad_opad(p_mgr, htab[index].hash, buff, dataSize, ipad, opad);

        free(opad);
        free(ipad);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct test_cfb_one_block {
        void *iv;
        void *expkey;
};

static void
test_cfb_one_block_free(struct test_cfb_one_block *ts)
{
        if (ts->iv != NULL)
                free(ts->iv);
        if (ts->expkey != NULL)
                free(ts->expkey);
        memset(ts, 0, sizeof(*ts));
}

static int
test_cfb_one_block_alloc(struct test_cfb_one_block *ts, const size_t rounds, const int is_aes)
{
        if (is_aes) {
                /* AES */
                ts->iv = malloc(16);
                ts->expkey = malloc(rounds * 16);
        } else {
                /* DES */
                ts->iv = malloc(8);
                ts->expkey = malloc(IMB_DES_KEY_SCHED_SIZE);
        }
        if (ts->iv == NULL || ts->expkey == NULL) {
                test_cfb_one_block_free(ts);
                return -1;
        }
        return 0;
}

static int
test_imb_cfb128_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_cfb_one_block ts;
        const size_t aes_rounds = 11;

        if (test_cfb_one_block_alloc(&ts, aes_rounds, 1 /* AES */) != 0)
                return -1;

        fill_data(ts.iv, 16, buff, dataSize);
        fill_data(ts.expkey, aes_rounds * 16, buff, dataSize);

        IMB_AES128_CFB_ONE(p_mgr, buff, buff, ts.iv, ts.expkey, dataSize);

        test_cfb_one_block_free(&ts);
        return 0;
}

static int
test_imb_cfb256_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        struct test_cfb_one_block ts;
        const size_t aes_rounds = 15;

        if (test_cfb_one_block_alloc(&ts, aes_rounds, 1 /* AES */) != 0)
                return -1;

        fill_data(ts.iv, 16, buff, dataSize);
        fill_data(ts.expkey, aes_rounds * 16, buff, dataSize);

        IMB_AES256_CFB_ONE(p_mgr, buff, buff, ts.iv, ts.expkey, dataSize);

        test_cfb_one_block_free(&ts);
        return 0;
}

static int
test_imb_des_cfb_one_block(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        struct test_cfb_one_block ts;

        if (test_cfb_one_block_alloc(&ts, 0, 0 /* DES */) != 0)
                return -1;

        fill_data(ts.iv, 8, buff, dataSize);
        fill_data(ts.expkey, IMB_DES_KEY_SCHED_SIZE, buff, dataSize);

        des_cfb_one(buff, buff, ts.iv, ts.expkey, dataSize);

        test_cfb_one_block_free(&ts);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_set_session(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        IMB_JOB *job = malloc(sizeof(*job));

        if (job == NULL)
                return -1;
        fill_data(job, sizeof(*job), buff, dataSize);

        imb_set_session(p_mgr, job);
        free(job);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_self_test_cb_fn(void *cb_arg, const IMB_SELF_TEST_CALLBACK_DATA *data)
{
        (void) cb_arg;
        (void) data;
        return 0;
}

static int
test_imb_self_test_set_cb(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        const size_t cb_arg_size = 8;
        void *cb_arg = malloc(cb_arg_size);

        if (cb_arg == NULL)
                return -1;

        fill_data(cb_arg, cb_arg_size, buff, dataSize);

        imb_self_test_set_cb(p_mgr, test_imb_self_test_cb_fn, cb_arg);
        imb_self_test_set_cb(p_mgr, NULL, NULL);

        free(cb_arg);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_self_test_get_cb(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) buff;
        (void) dataSize;

        imb_self_test_cb_t *cb_fn = malloc(sizeof(*cb_fn));

        if (cb_fn == NULL)
                return -1;

        void **cb_arg = malloc(sizeof(*cb_arg));

        if (cb_arg == NULL) {
                free(cb_fn);
                return -1;
        }

        (void) imb_self_test_get_cb(p_mgr, cb_fn, cb_arg);

        free(cb_fn);
        free(cb_arg);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

static int
test_imb_get_strerror(IMB_MGR *p_mgr, uint8_t *buff, size_t dataSize)
{
        (void) p_mgr;

        int *errnum = malloc(sizeof(*errnum));

        if (errnum == NULL)
                return -1;
        fill_data(errnum, sizeof(*errnum), buff, dataSize);

        imb_get_strerror(*errnum);

        free(errnum);
        return 0;
}

/* ========================================================================== */
/* ========================================================================== */

struct {
        int (*func)(IMB_MGR *mb_mgr, uint8_t *buff, size_t dataSize);
        const char *func_name;
} direct_apis[] = {
        { test_imb_aes_keyexp_128, "test_imb_aes_keyexp_128" },
        { test_imb_aes_keyexp_192, "test_imb_aes_keyexp_192" },
        { test_imb_aes_keyexp_256, "test_imb_aes_keyexp_256" },
        { test_imb_aes_subkey_cmac128, "test_imb_aes_subkey_cmac128" },
        { test_imb_aes_subkey_cmac256, "test_imb_aes_subkey_cmac256" },
        { test_imb_aes_keyexp_xcbc128, "test_imb_aes_keyexp_xcbc128" },
        { test_imb_des_keyexp, "test_imb_des_keyexp" },
        { test_imb_sm4_keyexp, "test_imb_sm4_keyexp" },

        { test_imb_sha1, "test_imb_sha1" },
        { test_imb_sha224, "test_imb_sha224" },
        { test_imb_sha256, "test_imb_sha256" },
        { test_imb_sha384, "test_imb_sha384" },
        { test_imb_sha512, "test_imb_sha512" },

        { test_imb_sha1_one_block, "test_imb_sha1_one_block" },
        { test_imb_sha224_one_block, "test_imb_sha224_one_block" },
        { test_imb_sha256_one_block, "test_imb_sha256_one_block" },
        { test_imb_sha384_one_block, "test_imb_sha384_one_block" },
        { test_imb_sha512_one_block, "test_imb_sha512_one_block" },
        { test_imb_md5_one_block, "test_imb_md5_one_block" },

        { test_imb_hmac_ipad_opad, "test_imb_hmac_ipad_opad" },

        { test_imb_cfb128_one_block, "test_imb_cfb128_one_block" },
        { test_imb_cfb256_one_block, "test_imb_cfb256_one_block" },
        { test_imb_des_cfb_one_block, "test_imb_des_cfb_one_block" },

        { test_snow3g_init_key_sched, "test_snow3g_init_key_sched" },
        { test_snow3g_f8_iv_gen, "test_snow3g_f8_iv_gen" },
        { test_snow3g_f9_iv_gen, "test_snow3g_f9_iv_gen" },

        { test_aes_gcm_pre, "test_aes_gcm_pre" },
        { test_aes_gcm_precomp, "test_aes_gcm_precomp" },
        { test_aes128_gcm_enc_sgl, "test_aes128_gcm_enc_sgl" },
        { test_aes128_gcm_dec_sgl, "test_aes128_gcm_dec_sgl" },
        { test_aes192_gcm_enc_sgl, "test_aes192_gcm_enc_sgl" },
        { test_aes192_gcm_dec_sgl, "test_aes192_gcm_dec_sgl" },
        { test_aes256_gcm_enc_sgl, "test_aes256_gcm_enc_sgl" },
        { test_aes256_gcm_dec_sgl, "test_aes256_gcm_dec_sgl" },
        { test_aes128_gcm_enc, "test_aes128_gcm_enc" },
        { test_aes128_gcm_dec, "test_aes128_gcm_dec" },
        { test_aes192_gcm_enc, "test_aes192_gcm_enc" },
        { test_aes192_gcm_dec, "test_aes192_gcm_dec" },
        { test_aes256_gcm_enc, "test_aes256_gcm_enc" },
        { test_aes256_gcm_dec, "test_aes256_gcm_dec" },
        { test_aes128_gcm_init_var_iv, "test_aes128_gcm_init_var_iv" },
        { test_aes192_gcm_init_var_iv, "test_aes192_gcm_init_var_iv" },
        { test_aes256_gcm_init_var_iv, "test_aes256_gcm_init_var_iv" },

        { test_aes128_gmac, "test_aes128_gmac" },
        { test_aes192_gmac, "test_aes192_gmac" },
        { test_aes256_gmac, "test_aes256_gmac" },

        { test_ghash, "test_ghash" },
        { test_ghash_pre, "test_ghash_pre" },

        { test_zuc_eea3_iv_gen, "test_zuc_eea3_iv_gen" },
        { test_zuc_eia3_iv_gen, "test_zuc_eia3_iv_gen" },

        { test_chacha_poly_enc, "test_chacha_poly_enc" },
        { test_chacha_poly_dec, "test_chacha_poly_dec" },

        { test_kasumi_f8_init_key_sched, "test_kasumi_f8_init_key_sched" },
        { test_kasumi_f8_iv_gen, "test_kasumi_f8_iv_gen" },
        { test_kasumi_f9_init_key_sched, "test_kasumi_f9_init_key_sched" },
        { test_kasumi_f9_iv_gen, "test_kasumi_f9_iv_gen" },

        { test_imb_clear_mem, "test_imb_clear_mem" },

        { test_imb_set_session, "test_imb_set_session" },
        { test_imb_self_test_set_cb, "test_imb_self_test_set_cb" },
        { test_imb_self_test_get_cb, "test_imb_self_test_get_cb" },
        { test_imb_get_strerror, "test_imb_get_strerror" },

        { test_imb_hec32, "test_imb_hec32" },
        { test_imb_hec64, "test_imb_hec64" },
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataSize)
{
        static IMB_MGR *p_mgr = NULL;

        if (dataSize < sizeof(int))
                return -1;

        const size_t newDataSize = dataSize - sizeof(int);
        uint8_t *buff = malloc(newDataSize);

        if (buff == NULL)
                return -1;

        memcpy(buff, &data[sizeof(int)], newDataSize);

        /* allocate multi-buffer manager */
        if (allocate_init_mb_mgr(&p_mgr, &fargs) != 0) {
                free(buff);
                return -1;
        }

        const int idx = ((const int *) data)[0] % DIM(direct_apis);
        const int ret = direct_apis[idx].func(p_mgr, buff, newDataSize);

        /**
         * @note There is no call to free_mb_mgr() to recycle the same instance across
         *       multiple iterations. Sanitizers do not consider it as a memory leak.
         */
        free(buff);
        return ret;
}
