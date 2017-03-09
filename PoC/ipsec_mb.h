/*
 * Copyright (c) 2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Author: Shuzo Ichiyoshi
 */

#ifndef _IPSEC_MB_H_
#define _IPSEC_MB_H_

#include <ipsec_mb_types.h>
#include <ipsec_mb_debug.h>

/******************************************************************************
 * Arch values
 ******************************************************************************/
enum cpuid_bits {
        CPUID_AESNI = 0,	/* MUST */
        CPUID_PCLMULQDQ,	/* MUST */
        CPUID_AVX,		/* with AVX */
        CPUID_AVX2,		/* with AVX2 */
        CPUID_AVX512F,		/* with AVX512F */
        CPUID_SHANI,		/* with SHANI */

        CPUID_NUMOF,
};

/******************************************************************************
 * Cipher Key and Authentication key
 ******************************************************************************/
struct aes_exp_key {
        UINT128 expanded_keys[AES_RAOUNDS_MAX + 1];
};

struct hmac_exp_key {
        UINT8 ipad[MAX_HASH_BLOCK_SIZE];
        UINT8 opad[MAX_HASH_BLOCK_SIZE];
};

struct gmac_exp_key {
        UINT128 shifted_hkey[8];
        UINT128 shifted_hkey_k[8];
};

struct xcbc_exp_key {
        struct aes_exp_key k1;
        UINT128 k2;
        UINT128 k3;
};

union auth_exp_key {
        struct hmac_exp_key hmac;
        struct gmac_exp_key gmac;
        struct xcbc_exp_key xcbc;
};

/*
 * counter block used in CTR,GCM
 */
union AES_IV {
        BE128 iv128[1];
        UINT8 iv8[16];
        struct {
                union {
                        UINT8 salt[4];
                        BE32 salt32;
                };
                union {
                        UINT8 iv[8];
                        BE64 iv64;
                };
                union {
                        UINT8 ctr[4];
                        BE32 ctr32;
                };
        } __packed;
};


/******************************************************************************
 * Job context
 ******************************************************************************/
enum JOB_STS {
        STS_BEING_PROCESSED = 0,
        STS_COMPLETED_AES   = 1,
        STS_COMPLETED_HMAC  = 2,
        STS_COMPLETED       = 3, // COMPLETED_AES | COMPLETED_HMAC
        STS_INVALID_ARGS    = 4,
        STS_INTERNAL_ERROR  = 8,
        STS_AUTH_FAILED     = 16,
};

enum JOB_CIPHER_MODE {
        CBC = 1,
        CNTR,
        NULL_CIPHER,
        DOCSIS_SEC_BPI,
        GCM,

        CIPHER_MODE_NUMOF,
};

enum AES_KEY_SIZE_BYTES {
        AES_128_BYTES = AES128_KEY_SIZE,
        AES_192_BYTES = AES192_KEY_SIZE,
        AES_256_BYTES = AES256_KEY_SIZE,
};

enum JOB_CIPHER_DIRECTION {
        ENCRYPT = 1,
        DECRYPT,
};

enum JOB_HASH_ALG {
        SHA1 = 1,
        SHA_224,
        SHA_256,
        SHA_384,
        SHA_512,
        AES_XCBC,
        MD5,
        NULL_HASH,
        GMAC_AES,	/* with GCM only */

        HASH_ALG_NUMOF,
};

enum JOB_CHAIN_ORDER {
        CIPHER_HASH = 1,
        HASH_CIPHER,
};

/******************************************************************************
 * Job context
 ******************************************************************************/
union MB_MGR_JOB_STATE {
        struct MB_MGR_HMAC_SHA1_OOO   sha1_ooo;
        struct MB_MGR_HMAC_SHA256_OOO sha256_ooo;
        struct MB_MGR_HMAC_SHA512_OOO sha512_ooo;
        struct MB_MGR_HMAC_MD5_OOO    md5_ooo;
        struct MB_MGR_AES_XCBC_OOO    xcbc_ooo;
        struct MB_MGR_AES_OOO         aes_ooo;
};

enum JOB_TASK {
        JOB_TASK_INVALID = 0,

        JOB_TASK_AES128_CBC,
        JOB_TASK_AES192_CBC,
        JOB_TASK_AES256_CBC,
        JOB_TASK_AES128_CTR,
        JOB_TASK_AES192_CTR,
        JOB_TASK_AES256_CTR,
        JOB_TASK_AES128_GCM,
        JOB_TASK_AES192_GCM,
        JOB_TASK_AES256_GCM,
        JOB_TASK_DOCSIS,
        JOB_TASK_NULL_CIPHER,
        JOB_TASK_SHA1,
        JOB_TASK_SHA224,
        JOB_TASK_SHA256,
        JOB_TASK_SHA384,
        JOB_TASK_SHA512,
        JOB_TASK_MD5,
        JOB_TASK_XCBC,
        JOB_TASK_NULL_HASH,

        JOB_TASK_NUMOF,
};

enum JOB_STATE {
        JOB_STATE_INVALID = 0,	/* for state less job */

        JOB_STATE_MD5,
        JOB_STATE_SHA224,
        JOB_STATE_DOCSIS,

        JOB_STATE_AES128,
        JOB_STATE_AES192,
        JOB_STATE_AES256,
        JOB_STATE_SHA1,
        JOB_STATE_SHA256,
        JOB_STATE_SHA384,
        JOB_STATE_SHA512,
        JOB_STATE_XCBC,

        JOB_STATE_NUMOF,
};

struct JOB_TASK_INFO {
        enum JOB_STATE state_id;
        const char *name;
        void (*state_initializer)(union MB_MGR_JOB_STATE *state);
        struct {
                struct JOB_AES_HMAC * (*submit)(union MB_MGR_JOB_STATE *,
                                                struct JOB_AES_HMAC *);
                struct JOB_AES_HMAC * (*flush)(union MB_MGR_JOB_STATE *);
        } dir_func[2];	/* CIPHER_DIRECTION - 1 */
};

const struct JOB_TASK_INFO job_task_info[JOB_TASK_NUMOF];

/*
 *
 */
struct JOB_AES_HMAC {
        const struct aes_exp_key *aes_enc_key_expanded;
        const struct aes_exp_key *aes_dec_key_expanded;
        UINT64 aes_key_len_in_bytes;
        const void *src;
        void       *dst;
        UINT64 cipher_start_src_offset_in_bytes;
        UINT64 msg_len_to_cipher_in_bytes;

        UINT64 hash_start_src_offset_in_bytes;
        UINT64 msg_len_to_hash_in_bytes;
        const void *iv;
        UINT64 iv_len_in_bytes;
        void *auth_tag_output;
        UINT64 auth_tag_output_len_in_bytes;

        union {
                struct {
                        const UINT8 *ipad_key;
                        const UINT8 *opad_key;
                } hmac;
                struct {
                        const struct aes_exp_key *k1_exp;
                        const UINT128 *k2;
                        const UINT128 *k3;
                } xcbc;
                struct {
                        struct gmac_exp_key *key;
                } gmac;
        };

        enum JOB_STS status;
        enum JOB_CIPHER_MODE cipher_mode;
        enum JOB_CIPHER_DIRECTION cipher_direction;
        enum JOB_HASH_ALG hash_alg;
        enum JOB_CHAIN_ORDER chain_order;	/* not used */

        void *user_data;
        void *user_data2;

        /**********************************************************************
         * Extended Area
         **********************************************************************/
        enum JOB_TASK stage_task[2];
        int current_stage;	/* 1 -> 0 */
        unsigned seq_num;	/* job ID (for debug) */

        /*
         * GCM: used cipher area + AAD
         */
        UINT64 aad_len_in_bytes;
        const void *aad;

        void *chk_tag_p;
        DECLARE_ALIGNED(UINT128 ext_data[2], 16);/* CTR block and AAD used */

        UINT8 verify_tag[32];		/* verifying used */
        UINT8 auth_tag_backup[32];	/* IPsec ESN decrypt used */
} __attribute__((aligned(32)));


/******************************************************************************
 * Multi Buffer Manager
 ******************************************************************************/

#define MAX_JOBS 128

struct MB_MGR {
        DECLARE_ALIGNED(union MB_MGR_JOB_STATE states[JOB_STATE_NUMOF], 32);

        /* FIFO */
        DECLARE_ALIGNED(struct JOB_AES_HMAC jobs[MAX_JOBS], 32);
        unsigned next;
        unsigned depth;
};

/******************************************************************************
 * Private Functions
 ******************************************************************************/
__forceinline struct JOB_AES_HMAC *
_ipsec_mb_submit_new_job(struct MB_MGR *mgr,
                         struct JOB_AES_HMAC *job)
{
        TRACE("start job:%u\n", job->seq_num);

        while (job->current_stage >= 0) {
                union MB_MGR_JOB_STATE *state;
                const struct JOB_TASK_INFO *tinfo
                        = &job_task_info[job->stage_task[job->current_stage]];

                TRACE("job:%u current:%d\n", job->seq_num, job->current_stage);

                state = &mgr->states[tinfo->state_id];
                job = tinfo->dir_func[job->cipher_direction - 1].submit(state, job);
                if (!job)
                        break;

                job->current_stage -= 1;
        }

        if (job) {
                TRACE("finish job:%u\n", job->seq_num);
                (void) job;
        }
        return job;
}

__forceinline void
_ipsec_mb_do_complete_job(struct MB_MGR *mgr,
                          struct JOB_AES_HMAC *job)
{
        TRACE("start job:%u\n", job->seq_num);
        while (job->current_stage >= 0) {
                struct JOB_AES_HMAC *next;
                union MB_MGR_JOB_STATE *state;
                const struct JOB_TASK_INFO *tinfo
                        = &job_task_info[job->stage_task[job->current_stage]];

                state = &mgr->states[tinfo->state_id];
                next = tinfo->dir_func[job->cipher_direction - 1].flush(state);

                TRACE("next:%u current:%d\n",
                      next->seq_num, next->current_stage);

                while (next) {
                        next->current_stage -= 1;
                        if (next->current_stage < 0)
                                break;

                        tinfo = &job_task_info[next->stage_task[next->current_stage]];
                        state = &mgr->states[tinfo->state_id];
                        next = tinfo->dir_func[next->cipher_direction - 1].submit(state, next);
                }
        }
}

/*
 * get head of FIFO job (earliest job)
 */
__forceinline struct JOB_AES_HMAC *
_ipsec_mb_head_job(struct MB_MGR *mgr)
{
        if (mgr->depth) {
                unsigned head = mgr->next - mgr->depth;

                head &= (ARRAYOF(mgr->jobs) - 1);
                return &mgr->jobs[head];
        }
        return NULL;
}

extern int _ipsec_mb_setup_job(struct JOB_AES_HMAC *job);

/******************************************************************************
 * API
 ******************************************************************************/
extern unsigned ipsec_mb_cpuid_get(void);
extern int ipsec_mb_cpuid_set(unsigned flags);
extern int ipsec_mb_init_mgr(struct MB_MGR *mgr);

/*
 * Get next Job
 */
__forceinline struct JOB_AES_HMAC *
ipsec_mb_get_next_job(struct MB_MGR *mgr)
{
        return &mgr->jobs[mgr->next];
}

/*
 * Submit Job
 * return completed or rejected Job
 */
__forceinline struct JOB_AES_HMAC *
ipsec_mb_submit_job(struct MB_MGR *mgr,
                    struct JOB_AES_HMAC *job)
{
        if (job != ipsec_mb_get_next_job(mgr)) {
                TRACE("invalid job:%p\n", job);
                job->status = STS_INVALID_ARGS;
                return job;
        }

        TRACE("start job:%u\n", job->seq_num);
        if (!_ipsec_mb_setup_job(job)) {

                mgr->next += 1;
                mgr->next &= (ARRAYOF(mgr->jobs) - 1);
                mgr->depth += 1;

                job = _ipsec_mb_submit_new_job(mgr, job);
                if (job) {
                        if (_ipsec_mb_head_job(mgr) == job) {
                                mgr->depth -= 1;
                                TRACE("finish job:%u\n", job->seq_num);
                        } else {
                                job = NULL;
                        }
                }
                if (mgr->depth == ARRAYOF(mgr->jobs)) {
                        job = _ipsec_mb_head_job(mgr);

                        _ipsec_mb_do_complete_job(mgr, job);
                        mgr->depth -= 1;
                        TRACE("finish job:%u\n", job->seq_num);
                }
        }
        return job;
}

/*
 * Get Completed Job
 */
__forceinline struct JOB_AES_HMAC *
ipsec_mb_get_completed_job(struct MB_MGR *mgr)
{
        struct JOB_AES_HMAC *job;

        TRACE("statrt next:%u depth:%u\n", mgr->next, mgr->depth);
        job = _ipsec_mb_head_job(mgr);
        if (job) {
                if (job->current_stage < 0) {
                        mgr->depth -= 1;
                        TRACE("finish job:%u\n", job->seq_num);
                } else {
                        job = NULL;
                }
        }
        return job;
}

/*
 * Flush Job
 */
__forceinline struct JOB_AES_HMAC *
ipsec_mb_flush_job(struct MB_MGR *mgr)
{
        struct JOB_AES_HMAC *job;

        TRACE("statrt next:%u depth:%u\n", mgr->next, mgr->depth);
        job = _ipsec_mb_head_job(mgr);
        if (job) {
                _ipsec_mb_do_complete_job(mgr, job);
                mgr->depth -= 1;
                TRACE("finish job:%u\n", job->seq_num);
        }
        return job;
}

/*
 *
 */
__forceinline unsigned
ipsec_mb_queue_size(const struct MB_MGR *mgr)
{
        return mgr->depth;
}

#endif /* !_IPSEC_MB_H_ */
