/*
 * Copyright (c) 2012-2017, Intel Corporation
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

#ifndef _MB_MGR_H_
#define _MB_MGR_H_

#include "types.h"
#include "constants.h"
#include "job_aes_hmac.h"
#include "asm_types.h"

#define MAX_JOBS 128

////////////////////////////////////////////////////////////////////////
// AES out-of-order scheduler fields
typedef struct MB_MGR_AES_OOO {
        AES_ARGS_x8 args;
        DECLARE_ALIGNED(UINT16 lens[8], 16);
        UINT64 unused_lanes; // each nibble is index (0...7) of unused lanes
        // nibble 8 is set to F as a flag
        JOB_AES_HMAC *job_in_lane[8];
} MB_MGR_AES_OOO;

////////////////////////////////////////////////////////////////////////
// AES XCBC out-of-order scheduler fields

typedef struct XCBC_LANE_DATA {
        DECLARE_ALIGNED(UINT8 final_block[2*16], 32);
        JOB_AES_HMAC *job_in_lane;
        UINT64 final_done;
} XCBC_LANE_DATA;

typedef struct {
        AES_XCBC_ARGS_x8 args;
        DECLARE_ALIGNED(UINT16 lens[8], 16);
        UINT64 unused_lanes; // each byte is index (0...3) of unused lanes
        // byte 4 is set to FF as a flag
        XCBC_LANE_DATA ldata[8];
} MB_MGR_AES_XCBC_OOO;


////////////////////////////////////////////////////////////////////////
// SHA-HMAC out-of-order scheduler fields

// used for SHA1 and SHA256
typedef struct HMAC_SHA1_LANE_DATA {
        DECLARE_ALIGNED(UINT8 extra_block[2 * SHA1_BLOCK_SIZE+8], 32); // allows ymm aligned access
        JOB_AES_HMAC *job_in_lane;
        UINT8 outer_block[64];
        UINT32 outer_done;
        UINT32 extra_blocks; // num extra blocks (1 or 2)
        UINT32 size_offset;  // offset in extra_block to start of size field
        UINT32 start_offset; // offset to start of data
} HMAC_SHA1_LANE_DATA;

// used for SHA512
typedef struct HMAC_SHA512_LANE_DATA {
        DECLARE_ALIGNED(UINT8 extra_block[2 * SHA_512_BLOCK_SIZE + 16], 32);
        UINT8 outer_block[SHA_512_BLOCK_SIZE];
        JOB_AES_HMAC *job_in_lane;
        UINT32 outer_done;
        UINT32 extra_blocks; // num extra blocks (1 or 2)
        UINT32 size_offset;  // offset in extra_block to start of size field
        UINT32 start_offset; // offset to start of data
} HMAC_SHA512_LANE_DATA;


// unused_lanes contains a list of unused lanes stored as bytes or as
// nibbles depending on the arch. The end of list is either FF or F.

typedef struct MB_MGR_HMAC_SHA_1_OOO {
        SHA1_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[16], 32);
        UINT64 unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_SHA1_LANES];
        UINT32 num_lanes_inuse;
} MB_MGR_HMAC_SHA_1_OOO;

typedef struct MB_MGR_HMAC_SHA_256_OOO {
        SHA256_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[16], 16);
        UINT64 unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_SHA256_LANES];
        UINT32 num_lanes_inuse;
} MB_MGR_HMAC_SHA_256_OOO;

typedef struct MB_MGR_HMAC_SHA_512_OOO {
        SHA512_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[8], 16);
        UINT64 unused_lanes;
        HMAC_SHA512_LANE_DATA ldata[AVX512_NUM_SHA512_LANES];
} MB_MGR_HMAC_SHA_512_OOO;


////////////////////////////////////////////////////////////////////////
// MD5-HMAC out-of-order scheduler fields

typedef struct MB_MGR_HMAC_MD5_OOO {
        MD5_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[AVX512_NUM_MD5_LANES], 16);
        // In the avx2 case, all 16 nibbles of unused lanes are used. In that
        // case num_lanes_inuse is used to detect the end of the list
        UINT64 unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_MD5_LANES];
        UINT32 num_lanes_inuse;
} MB_MGR_HMAC_MD5_OOO;

////////////////////////////////////////////////////////////////////////
union MB_MGR_JOB_STATE {
        MB_MGR_HMAC_SHA_1_OOO   hmac_sha_1_ooo;
        MB_MGR_HMAC_SHA_256_OOO hmac_sha_224_ooo;
        MB_MGR_HMAC_SHA_256_OOO hmac_sha_256_ooo;
        MB_MGR_HMAC_SHA_512_OOO hmac_sha_384_ooo;
        MB_MGR_HMAC_SHA_512_OOO hmac_sha_512_ooo;
        MB_MGR_HMAC_MD5_OOO     hmac_md5_ooo;
        MB_MGR_AES_XCBC_OOO     aes_xcbc_ooo;
        MB_MGR_AES_OOO          aes128_ooo;
        MB_MGR_AES_OOO          aes192_ooo;
        MB_MGR_AES_OOO          aes256_ooo;
        MB_MGR_AES_OOO          docsis_sec_ooo;
};

enum JOB_STATE {
        JOB_STATE_AES128 = 0,
        JOB_STATE_AES192,
        JOB_STATE_AES256,
        JOB_STATE_DOCSIS,

        JOB_STATE_SHA1,
        JOB_STATE_SHA224,
        JOB_STATE_SHA256,
        JOB_STATE_SHA384,
        JOB_STATE_SHA512,
        JOB_STATE_XCBC,
        JOB_STATE_MD5,

        JOB_STATE_NUMOF,
};

struct job_task_handler {
        struct {
                struct JOB_AES_HMAC * (*submit)(union MB_MGR_JOB_STATE *,
                                                struct JOB_AES_HMAC *);
                struct JOB_AES_HMAC * (*flush)(union MB_MGR_JOB_STATE *);
        } direction[2];	/* CIPHER_DIRECTION - 1 */
        const char *name;
        enum JOB_STATE state_id;
        int _pad;
};

////////////////////////////////////////////////////////////////////////
// TOP LEVEL (MB_MGR) Data structure fields

typedef struct MB_MGR {
        DECLARE_ALIGNED(union MB_MGR_JOB_STATE states[JOB_STATE_NUMOF], 32);
        DECLARE_ALIGNED(struct JOB_AES_HMAC jobs[MAX_JOBS], 32);

#ifndef LINUX
        DECLARE_ALIGNED(UINT128 vec_regs[10], 16);
        void (*save_vec_regs)(UINT128 *);
        void (*restore_vec_regs)(UINT128 *);
#endif
        // in-order scheduler fields
        const struct job_task_handler *handler;
        unsigned next;
        unsigned depth;
} MB_MGR;

#ifndef LINUX
# include "save_xmms.h"
# define SAVE_VEC_REGS(m)	(m)->save_vec_regs((m)->vec_regs)
# define RESTORE_VEC_REGS(m)	(m)->restore_vec_regs((m)->vec_regs)
#else
# define SAVE_VEC_REGS(m)
# define RESTORE_VEC_REGS(m)
#endif

enum SHA_EXTENSION_USAGE {
        SHA_EXT_NOT_PRESENT = 0, /* don't detect and don't use SHA extensions */
        SHA_EXT_PRESENT,  /* don't detect and use SHA extensions */
        SHA_EXT_DETECT,   /* default - detect and use SHA extensions if present */
};


/******************************************************************************
 * API
 ******************************************************************************/
typedef void (*init_mb_mgr_t)(MB_MGR *);
typedef JOB_AES_HMAC *(*get_next_job_t)(MB_MGR *);
typedef JOB_AES_HMAC *(*submit_job_t)(MB_MGR *);
typedef JOB_AES_HMAC *(*get_completed_job_t)(MB_MGR *);
typedef JOB_AES_HMAC *(*flush_job_t)(MB_MGR *);
typedef unsigned (*queue_size_t)(MB_MGR *);

/*
 * Get next Job
 */
__forceinline struct JOB_AES_HMAC *
ipsec_mb_get_next_job(struct MB_MGR *mgr)
{
        return &mgr->jobs[mgr->next];
}

/*
 * Submit Job (New API)
 * return completed or rejected Job
 * Note: enable_tag_cmp is FALSE, if non-linux
 */
extern struct JOB_AES_HMAC *ipsec_mb_submit_job_NAPI(struct MB_MGR *mgr,
                                                     int enable_tag_cmp,
                                                     BE32 *esn_high_p);

__forceinline struct JOB_AES_HMAC *
ipsec_mb_submit_job(struct MB_MGR *mgr)
{
        return ipsec_mb_submit_job_NAPI(mgr, 0, NULL);
}

/*
 * Get Completed Job
 */
extern struct JOB_AES_HMAC *ipsec_mb_get_completed_job(struct MB_MGR *mgr);

/*
 * Flush Job
 */
extern struct JOB_AES_HMAC *ipsec_mb_flush_job(struct MB_MGR *mgr);

/*
 *
 */
__forceinline unsigned
ipsec_mb_queue_size(const struct MB_MGR *mgr)
{
        return mgr->depth;
}

extern enum SHA_EXTENSION_USAGE sse_sha_ext_usage;

/* legacy API */
extern void init_mb_mgr_sse(struct MB_MGR *mgr);
extern void init_mb_mgr_avx(struct MB_MGR *mgr);
extern void init_mb_mgr_avx2(struct MB_MGR *mgr);
extern void init_mb_mgr_avx512(struct MB_MGR *mgr);

#define get_next_job_sse	ipsec_mb_get_next_job
#define get_next_job_avx	ipsec_mb_get_next_job
#define get_next_job_avx2	ipsec_mb_get_next_job
#define get_next_job_avx512	ipsec_mb_get_next_job

#define submit_job_sse		ipsec_mb_submit_job
#define submit_job_avx		ipsec_mb_submit_job
#define submit_job_avx2		ipsec_mb_submit_job
#define submit_job_avx512	ipsec_mb_submit_job

#define get_completed_job_sse	ipsec_mb_get_completed_job
#define get_completed_job_avx	ipsec_mb_get_completed_job
#define get_completed_job_avx2	ipsec_mb_get_completed_job
#define get_completed_job_avx512	ipsec_mb_get_completed_job

#define flush_job_sse		ipsec_mb_flush_job
#define flush_job_avx		ipsec_mb_flush_job
#define flush_job_avx2		ipsec_mb_flush_job
#define flush_job_avx512	ipsec_mb_flush_job

#define queue_size_sse		ipsec_mb_queue_size
#define queue_size_avx		ipsec_mb_queue_size
#define queue_size_avx2		ipsec_mb_queue_size
#define queue_size_avx512	ipsec_mb_queue_size


/* private use (don't call) */
extern void _init_mb_mgr_sse(struct MB_MGR *mgr, enum SHA_EXTENSION_USAGE);
extern void _init_mb_mgr_avx(struct MB_MGR *mgr);
extern void _init_mb_mgr_avx2(struct MB_MGR *mgr);
extern void _init_mb_mgr_avx512(struct MB_MGR *mgr);

#endif /* !_MB_MGR_H_ */
