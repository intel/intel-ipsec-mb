/*****************************************************************************
 Copyright (c) 2023-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "include/error.h"
#include "include/memcpy.h"
#include "include/mb_mgr.h" /* CALL_SM3(), CALL_SM3_ONE_BLOCK() */
#include "include/sha3.h"   /* sha3_224/256/384/512 */

IMB_DLL_EXPORT
void
imb_hmac_ipad_opad(IMB_MGR *mb_mgr, const IMB_HASH_ALG sha_type, const void *pkey,
                   const size_t key_len, void *ipad_hash, void *opad_hash)
{
#ifdef SAFE_PARAM
        if (mb_mgr == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
        if (pkey == NULL) {
                imb_set_errno(mb_mgr, IMB_ERR_NULL_KEY);
                return;
        }
        imb_set_errno(mb_mgr, 0);
#endif
        uint32_t i = 0;
        size_t local_key_len = 0;

        switch (sha_type) {
        case IMB_AUTH_HMAC_SHA_1:
                local_key_len =
                        (key_len <= IMB_SHA1_BLOCK_SIZE) ? key_len : IMB_SHA1_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA_224:
                local_key_len = (key_len <= IMB_SHA_224_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA224_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA_256:
                local_key_len = (key_len <= IMB_SHA_256_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA256_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA_384:
                local_key_len = (key_len <= IMB_SHA_384_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA384_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA_512:
                local_key_len = (key_len <= IMB_SHA_512_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA512_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_MD5:
                if (key_len <= IMB_MD5_BLOCK_SIZE)
                        local_key_len = key_len;
                else {
                        /**
                         * Key lengths longer than MD5 block
                         * size not supported
                         */
                        imb_set_errno(NULL, IMB_ERR_KEY_LEN);
                        return;
                }
                break;
        case IMB_AUTH_HMAC_SM3:
                local_key_len = (key_len <= IMB_SM3_BLOCK_SIZE) ? key_len : IMB_SM3_DIGEST_SIZE;
                break;
        case IMB_AUTH_HMAC_SHA3_224:
                local_key_len = (key_len <= IMB_SHA3_224_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA3_224_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA3_256:
                local_key_len = (key_len <= IMB_SHA3_256_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA3_256_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA3_384:
                local_key_len = (key_len <= IMB_SHA3_384_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA3_384_DIGEST_SIZE_IN_BYTES;
                break;
        case IMB_AUTH_HMAC_SHA3_512:
                local_key_len = (key_len <= IMB_SHA3_512_BLOCK_SIZE)
                                        ? key_len
                                        : IMB_SHA3_512_DIGEST_SIZE_IN_BYTES;
                break;
        default:
                imb_set_errno(NULL, IMB_ERR_HASH_ALGO);
                return;
        }
        uint8_t key[IMB_SHA3_MAX_BLOCK_SIZE]; /* large enough for all variants */
        uint8_t buf[IMB_SHA3_MAX_BLOCK_SIZE];

        /* prepare the key */
        if (local_key_len == key_len) {
                safe_memcpy(key, pkey, key_len);
        } else
                switch (sha_type) {
                case IMB_AUTH_HMAC_SHA_1:
                        IMB_SHA1(mb_mgr, pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SHA_224:
                        IMB_SHA224(mb_mgr, pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SHA_256:
                        IMB_SHA256(mb_mgr, pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SHA_384:
                        IMB_SHA384(mb_mgr, pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SM3:
                        CALL_SM3(mb_mgr, pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SHA3_224:
                        sha3_224(pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SHA3_256:
                        sha3_256(pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SHA3_384:
                        sha3_384(pkey, key_len, key);
                        break;
                case IMB_AUTH_HMAC_SHA3_512:
                        sha3_512(pkey, key_len, key);
                        break;
                default: /* For SHA-512 */
                        IMB_SHA512(mb_mgr, pkey, key_len, key);
                }

        /* compute ipad hash */
        if (ipad_hash != NULL) {
                memset(buf, 0x36, sizeof(buf));
                for (i = 0; i < local_key_len; i++)
                        buf[i] ^= key[i];
                switch (sha_type) {
                case IMB_AUTH_HMAC_SHA_1:
                        IMB_SHA1_ONE_BLOCK(mb_mgr, buf, ipad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_224:
                        IMB_SHA224_ONE_BLOCK(mb_mgr, buf, ipad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_256:
                        IMB_SHA256_ONE_BLOCK(mb_mgr, buf, ipad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_384:
                        IMB_SHA384_ONE_BLOCK(mb_mgr, buf, ipad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_512:
                        IMB_SHA512_ONE_BLOCK(mb_mgr, buf, ipad_hash);
                        break;
                case IMB_AUTH_HMAC_SM3:
                        CALL_SM3_ONE_BLOCK(mb_mgr, buf, ipad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA3_224:
                        memcpy(ipad_hash, buf, IMB_SHA3_224_BLOCK_SIZE);
                        break;
                case IMB_AUTH_HMAC_SHA3_256:
                        memcpy(ipad_hash, buf, IMB_SHA3_256_BLOCK_SIZE);
                        break;
                case IMB_AUTH_HMAC_SHA3_384:
                        memcpy(ipad_hash, buf, IMB_SHA3_384_BLOCK_SIZE);
                        break;
                case IMB_AUTH_HMAC_SHA3_512:
                        memcpy(ipad_hash, buf, IMB_SHA3_512_BLOCK_SIZE);
                        break;
                default: /* For MD5 */
                        IMB_MD5_ONE_BLOCK(mb_mgr, buf, ipad_hash);
                }
        }

        /* compute opad hash */
        if (opad_hash != NULL) {
                memset(buf, 0x5c, sizeof(buf));
                for (i = 0; i < local_key_len; i++)
                        buf[i] ^= key[i];
                switch (sha_type) {
                case IMB_AUTH_HMAC_SHA_1:
                        IMB_SHA1_ONE_BLOCK(mb_mgr, buf, opad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_224:
                        IMB_SHA224_ONE_BLOCK(mb_mgr, buf, opad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_256:
                        IMB_SHA256_ONE_BLOCK(mb_mgr, buf, opad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_384:
                        IMB_SHA384_ONE_BLOCK(mb_mgr, buf, opad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA_512:
                        IMB_SHA512_ONE_BLOCK(mb_mgr, buf, opad_hash);
                        break;
                case IMB_AUTH_HMAC_SM3:
                        CALL_SM3_ONE_BLOCK(mb_mgr, buf, opad_hash);
                        break;
                case IMB_AUTH_HMAC_SHA3_224:
                        memcpy(opad_hash, buf, IMB_SHA3_224_BLOCK_SIZE);
                        break;
                case IMB_AUTH_HMAC_SHA3_256:
                        memcpy(opad_hash, buf, IMB_SHA3_256_BLOCK_SIZE);
                        break;
                case IMB_AUTH_HMAC_SHA3_384:
                        memcpy(opad_hash, buf, IMB_SHA3_384_BLOCK_SIZE);
                        break;
                case IMB_AUTH_HMAC_SHA3_512:
                        memcpy(opad_hash, buf, IMB_SHA3_512_BLOCK_SIZE);
                        break;
                default: /* For MD5 */
                        IMB_MD5_ONE_BLOCK(mb_mgr, buf, opad_hash);
                }
        }

#ifdef SAFE_DATA
        imb_clear_mem(key, sizeof(key));
        imb_clear_mem(buf, sizeof(buf));
#endif
}
