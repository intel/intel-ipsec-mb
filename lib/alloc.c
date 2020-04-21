/*******************************************************************************
  Copyright (c) 2018-2020, Intel Corporation

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

#include <stdint.h>
#ifdef LINUX
#include <stdlib.h> /* posix_memalign() and free() */
#else
#include <malloc.h> /* _aligned_malloc() and aligned_free() */
#endif
#include <string.h>
#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"
#include "cpu_feature.h"

static void *
alloc_aligned_mem(const size_t size)
{
        void *ptr;

        const size_t alignment = 64;
#ifdef LINUX
        if (posix_memalign((void **)&ptr, alignment, size))
                return NULL;
#else
        ptr = _aligned_malloc(size, alignment);
#endif

        IMB_ASSERT(ptr != NULL);

        memset(ptr, 0, size);

        return ptr;
}

static void
free_mem(void *ptr)
{
#ifdef LINUX
        free(ptr);
#else
        _aligned_free(ptr);
#endif
}

/**
 * @brief Allocates memory for multi-buffer manager instance
 *
 * For binary compatibility between library versions
 * it is recommended to use this API.
 *
 * @param flags multi-buffer manager flags
 *     IMB_FLAG_SHANI_OFF - disable use (and detection) of SHA extenstions,
 *                          currently SHANI is only available for SSE
 *
 * @return Pointer to allocated memory for MB_MGR structure
 * @retval NULL on allocation error
 */
IMB_MGR *alloc_mb_mgr(uint64_t flags)
{
        IMB_MGR *ptr = NULL;

        ptr = alloc_aligned_mem(sizeof(IMB_MGR));
        IMB_ASSERT(ptr != NULL);
        if (ptr != NULL) {
                ptr->flags = flags; /* save the flags for future use in init */
                ptr->features = cpu_feature_adjust(flags, cpu_feature_detect());
        } else
                return NULL;


        /* Allocate memory for OOO */
        ptr->aes128_ooo = alloc_aligned_mem(sizeof(MB_MGR_AES_OOO));
        if (ptr->aes128_ooo == NULL)
                goto exit_fail;
        ptr->aes192_ooo = alloc_aligned_mem(sizeof(MB_MGR_AES_OOO));
        if (ptr->aes192_ooo == NULL)
                goto exit_fail;
        ptr->aes256_ooo = alloc_aligned_mem(sizeof(MB_MGR_AES_OOO));
        if (ptr->aes256_ooo == NULL)
                goto exit_fail;
        ptr->docsis128_sec_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_DOCSIS_AES_OOO));
        if (ptr->docsis128_sec_ooo == NULL)
                goto exit_fail;
        ptr->docsis128_crc32_sec_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_DOCSIS_AES_OOO));
        if (ptr->docsis128_crc32_sec_ooo == NULL)
                goto exit_fail;
        ptr->docsis256_sec_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_DOCSIS_AES_OOO));
        if (ptr->docsis256_sec_ooo == NULL)
                goto exit_fail;
        ptr->docsis256_crc32_sec_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_DOCSIS_AES_OOO));
        if (ptr->docsis256_crc32_sec_ooo == NULL)
                goto exit_fail;
        ptr->des_enc_ooo = alloc_aligned_mem(sizeof(MB_MGR_DES_OOO));
        if (ptr->des_enc_ooo == NULL)
                goto exit_fail;
        ptr->des_dec_ooo = alloc_aligned_mem(sizeof(MB_MGR_DES_OOO));
        if (ptr->des_dec_ooo == NULL)
                goto exit_fail;
        ptr->des3_enc_ooo = alloc_aligned_mem(sizeof(MB_MGR_DES_OOO));
        if (ptr->des3_enc_ooo == NULL)
                goto exit_fail;
        ptr->des3_dec_ooo = alloc_aligned_mem(sizeof(MB_MGR_DES_OOO));
        if (ptr->des3_dec_ooo == NULL)
                goto exit_fail;
        ptr->docsis_des_enc_ooo = alloc_aligned_mem(sizeof(MB_MGR_DES_OOO));
        if (ptr->docsis_des_enc_ooo == NULL)
                goto exit_fail;
        ptr->docsis_des_dec_ooo = alloc_aligned_mem(sizeof(MB_MGR_DES_OOO));
        if (ptr->docsis_des_dec_ooo == NULL)
                goto exit_fail;
        ptr->zuc_eea3_ooo = alloc_aligned_mem(sizeof(MB_MGR_ZUC_OOO));
        if (ptr->zuc_eea3_ooo == NULL)
                goto exit_fail;

        ptr->hmac_sha_1_ooo = alloc_aligned_mem(sizeof(MB_MGR_HMAC_SHA_1_OOO));
        if (ptr->hmac_sha_1_ooo == NULL)
                goto exit_fail;
        ptr->hmac_sha_224_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_HMAC_SHA_256_OOO));
        if (ptr->hmac_sha_224_ooo == NULL)
                goto exit_fail;
        ptr->hmac_sha_256_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_HMAC_SHA_256_OOO));
        if (ptr->hmac_sha_256_ooo == NULL)
                goto exit_fail;
        ptr->hmac_sha_384_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_HMAC_SHA_512_OOO));
        if (ptr->hmac_sha_384_ooo == NULL)
                goto exit_fail;
        ptr->hmac_sha_512_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_HMAC_SHA_512_OOO));
        if (ptr->hmac_sha_512_ooo == NULL)
                goto exit_fail;
        ptr->hmac_md5_ooo =
                alloc_aligned_mem(sizeof(MB_MGR_HMAC_MD5_OOO));
        if (ptr->hmac_md5_ooo == NULL)
                goto exit_fail;
        ptr->aes_xcbc_ooo = alloc_aligned_mem(sizeof(MB_MGR_AES_XCBC_OOO));
        if (ptr->aes_xcbc_ooo == NULL)
                goto exit_fail;
        ptr->aes_ccm_ooo = alloc_aligned_mem(sizeof(MB_MGR_CCM_OOO));
        if (ptr->aes_ccm_ooo == NULL)
                goto exit_fail;
        ptr->aes_cmac_ooo = alloc_aligned_mem(sizeof(MB_MGR_CMAC_OOO));
        if (ptr->aes_cmac_ooo == NULL)
                goto exit_fail;
        ptr->zuc_eia3_ooo = alloc_aligned_mem(sizeof(MB_MGR_ZUC_OOO));
        if (ptr->zuc_eia3_ooo == NULL)
                goto exit_fail;

        return ptr;

exit_fail:
        free_mem(ptr->aes128_ooo);
        free_mem(ptr->aes192_ooo);
        free_mem(ptr->aes256_ooo);
        free_mem(ptr->docsis128_sec_ooo);
        free_mem(ptr->docsis128_crc32_sec_ooo);
        free_mem(ptr->docsis256_sec_ooo);
        free_mem(ptr->docsis256_crc32_sec_ooo);
        free_mem(ptr->des_enc_ooo);
        free_mem(ptr->des_dec_ooo);
        free_mem(ptr->des3_enc_ooo);
        free_mem(ptr->des3_dec_ooo);
        free_mem(ptr->docsis_des_enc_ooo);
        free_mem(ptr->docsis_des_dec_ooo);
        free_mem(ptr->zuc_eea3_ooo);

        free_mem(ptr->hmac_sha_1_ooo);
        free_mem(ptr->hmac_sha_224_ooo);
        free_mem(ptr->hmac_sha_256_ooo);
        free_mem(ptr->hmac_sha_384_ooo);
        free_mem(ptr->hmac_sha_512_ooo);
        free_mem(ptr->hmac_md5_ooo);
        free_mem(ptr->aes_xcbc_ooo);
        free_mem(ptr->aes_ccm_ooo);
        free_mem(ptr->aes_cmac_ooo);
        free_mem(ptr->zuc_eia3_ooo);
        free(ptr);

        return NULL;
}

/**
 * @brief Frees memory allocated previously by alloc_mb_mgr()
 *
 * @param ptr a pointer to allocated MB_MGR structure
 *
 */
void free_mb_mgr(IMB_MGR *ptr)
{
        IMB_ASSERT(ptr != NULL);

        /* Free memory for OOO */
        if (ptr != NULL) {
                free_mem(ptr->aes128_ooo);
                free_mem(ptr->aes192_ooo);
                free_mem(ptr->aes256_ooo);
                free_mem(ptr->docsis128_sec_ooo);
                free_mem(ptr->docsis128_crc32_sec_ooo);
                free_mem(ptr->docsis256_sec_ooo);
                free_mem(ptr->docsis256_crc32_sec_ooo);
                free_mem(ptr->des_enc_ooo);
                free_mem(ptr->des_dec_ooo);
                free_mem(ptr->des3_enc_ooo);
                free_mem(ptr->des3_dec_ooo);
                free_mem(ptr->docsis_des_enc_ooo);
                free_mem(ptr->docsis_des_dec_ooo);
                free_mem(ptr->zuc_eea3_ooo);

                free_mem(ptr->hmac_sha_1_ooo);
                free_mem(ptr->hmac_sha_224_ooo);
                free_mem(ptr->hmac_sha_256_ooo);
                free_mem(ptr->hmac_sha_384_ooo);
                free_mem(ptr->hmac_sha_512_ooo);
                free_mem(ptr->hmac_md5_ooo);
                free_mem(ptr->aes_xcbc_ooo);
                free_mem(ptr->aes_ccm_ooo);
                free_mem(ptr->aes_cmac_ooo);
                free_mem(ptr->zuc_eia3_ooo);
        }

        /* Free IMB_MGR */
        free_mem(ptr);
}
