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


#include "types.h"
#include "constants.h"
#include "job_aes_hmac.h"
#include "asm_types.h"

#define MAX_JOBS 128


////////////////////////////////////////////////////////////////////////
// AES out-of-order scheduler fields
typedef struct {
        AES_ARGS_x8 args;
        DECLARE_ALIGNED(UINT16 lens[8], 16);
        UINT64 unused_lanes; // each nibble is index (0...7) of unused lanes
        // nibble 8 is set to F as a flag
        JOB_AES_HMAC *job_in_lane[8];
} MB_MGR_AES_OOO;

////////////////////////////////////////////////////////////////////////
// AES XCBC out-of-order scheduler fields

typedef struct {
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
typedef struct {
        DECLARE_ALIGNED(UINT8 extra_block[2 * SHA1_BLOCK_SIZE+8], 32); // allows ymm aligned access
        JOB_AES_HMAC *job_in_lane;
        UINT8 outer_block[64];
        UINT32 outer_done;
        UINT32 extra_blocks; // num extra blocks (1 or 2)
        UINT32 size_offset;  // offset in extra_block to start of size field
        UINT32 start_offset; // offset to start of data
} HMAC_SHA1_LANE_DATA;

// used for SHA512
typedef struct {
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

typedef struct {
        SHA1_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[16], 32);
        UINT64 unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_SHA1_LANES];
        UINT32 num_lanes_inuse;
} MB_MGR_HMAC_SHA_1_OOO;

typedef struct {
        SHA256_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[16], 16);
        UINT64 unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_SHA256_LANES];
        UINT32 num_lanes_inuse;
} MB_MGR_HMAC_SHA_256_OOO;

typedef struct {
        SHA512_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[8], 16);
        UINT64 unused_lanes;
        HMAC_SHA512_LANE_DATA ldata[AVX512_NUM_SHA512_LANES];
} MB_MGR_HMAC_SHA_512_OOO;


////////////////////////////////////////////////////////////////////////
// MD5-HMAC out-of-order scheduler fields

typedef struct {
        MD5_ARGS args;
        DECLARE_ALIGNED(UINT16 lens[AVX512_NUM_MD5_LANES], 16);
        // In the avx2 case, all 16 nibbles of unused lanes are used. In that
        // case num_lanes_inuse is used to detect the end of the list
        UINT64 unused_lanes;
        HMAC_SHA1_LANE_DATA ldata[AVX512_NUM_MD5_LANES];
        UINT32 num_lanes_inuse;
} MB_MGR_HMAC_MD5_OOO;

////////////////////////////////////////////////////////////////////////
// API definitions
struct MB_MGR;
typedef void (*init_mb_mgr_t)(struct MB_MGR *);
typedef JOB_AES_HMAC* (*get_next_job_t)(struct MB_MGR *);
typedef JOB_AES_HMAC* (*submit_job_t)(struct MB_MGR *);
typedef JOB_AES_HMAC* (*get_completed_job_t)(struct MB_MGR *);
typedef JOB_AES_HMAC* (*flush_job_t)(struct MB_MGR *);
typedef UINT32 (*queue_size_t)(struct MB_MGR *);
typedef void (*keyexp_t)(const void *, void *, void *);

////////////////////////////////////////////////////////////////////////
// TOP LEVEL (MB_MGR) Data structure fields

typedef struct MB_MGR {
        MB_MGR_AES_OOO aes128_ooo;
        MB_MGR_AES_OOO aes192_ooo;
        MB_MGR_AES_OOO aes256_ooo;
        MB_MGR_AES_OOO docsis_sec_ooo;

        MB_MGR_HMAC_SHA_1_OOO        hmac_sha_1_ooo;
        MB_MGR_HMAC_SHA_256_OOO      hmac_sha_224_ooo;
        MB_MGR_HMAC_SHA_256_OOO      hmac_sha_256_ooo;
        MB_MGR_HMAC_SHA_512_OOO      hmac_sha_384_ooo;
        MB_MGR_HMAC_SHA_512_OOO      hmac_sha_512_ooo;
        MB_MGR_HMAC_MD5_OOO          hmac_md5_ooo;
        MB_MGR_AES_XCBC_OOO          aes_xcbc_ooo;

        // in-order scheduler fields
        int              earliest_job; // byte offset, -1 if none
        int              next_job;     // byte offset
        JOB_AES_HMAC     jobs[MAX_JOBS];

        /* arch handlers */
        get_next_job_t          get_next_job;
        submit_job_t            submit_job;
        submit_job_t            submit_job_nocheck;
        get_completed_job_t     get_completed_job;
        flush_job_t             flush_job;
        queue_size_t            queue_size;
        keyexp_t                keyexp_128;
        keyexp_t                keyexp_192;
        keyexp_t                keyexp_256;
} MB_MGR;



// get_next_job returns a job object. This must be filled in and returned
// via submit_job before get_next_job is called again.
// After submit_job is called, one should call get_completed_job() at least
// once (and preferably until it returns NULL).
// get_completed_job and flush_job returns a job object. This job object ceases
// to be usable at the next call to get_next_job
void init_mb_mgr_avx(MB_MGR *state);
//JOB_AES_HMAC* get_next_job_avx(MB_MGR *state);
JOB_AES_HMAC* submit_job_avx(MB_MGR *state);
JOB_AES_HMAC* submit_job_nocheck_avx(MB_MGR *state);
//JOB_AES_HMAC* get_completed_job_avx(MB_MGR *state);
JOB_AES_HMAC* flush_job_avx(MB_MGR *state);
UINT32 queue_size_avx(MB_MGR *state);

void init_mb_mgr_avx2(MB_MGR *state);
//JOB_AES_HMAC* get_next_job_avx(MB_MGR *state);
JOB_AES_HMAC* submit_job_avx2(MB_MGR *state);
JOB_AES_HMAC* submit_job_nocheck_avx2(MB_MGR *state);
//JOB_AES_HMAC* get_completed_job_avx(MB_MGR *state);
JOB_AES_HMAC* flush_job_avx2(MB_MGR *state);
UINT32 queue_size_avx2(MB_MGR *state);

void init_mb_mgr_avx512(MB_MGR *state);
//JOB_AES_HMAC* get_next_job_avx(MB_MGR *state);
JOB_AES_HMAC* submit_job_avx512(MB_MGR *state);
JOB_AES_HMAC* submit_job_nocheck_avx512(MB_MGR *state);
//JOB_AES_HMAC* get_completed_job_avx(MB_MGR *state);
JOB_AES_HMAC* flush_job_avx512(MB_MGR *state);
UINT32 queue_size_avx512(MB_MGR *state);


void init_mb_mgr_sse(MB_MGR *state);
//JOB_AES_HMAC* get_next_job_sse(MB_MGR *state);
JOB_AES_HMAC* submit_job_sse(MB_MGR *state);
JOB_AES_HMAC* submit_job_nocheck_sse(MB_MGR *state);
//JOB_AES_HMAC* get_completed_job_sse(MB_MGR *state);
JOB_AES_HMAC* flush_job_sse(MB_MGR *state);
UINT32 queue_size_sse(MB_MGR *state);

enum SHA_EXTENSION_USAGE {
        SHA_EXT_NOT_PRESENT = 0, /* don't detect and don't use SHA extensions */
        SHA_EXT_PRESENT,  /* don't detect and use SHA extensions */
        SHA_EXT_DETECT,   /* default - detect and use SHA extensions if present */
};

extern enum SHA_EXTENSION_USAGE sse_sha_ext_usage;

#define get_completed_job_avx  get_completed_job_sse
#define get_next_job_avx       get_next_job_sse

#define get_completed_job_avx2 get_completed_job_sse
#define get_next_job_avx2      get_next_job_sse

#define get_completed_job_avx512 get_completed_job_sse
#define get_next_job_avx512      get_next_job_sse

// JOBS() and ADV_JOBS() also used in mb_mgr_code.h
// index in JOBS array using byte offset rather than object index
__forceinline
JOB_AES_HMAC *JOBS(MB_MGR *state, const int offset)
{
        char *cp = (char *)state->jobs;

        return (JOB_AES_HMAC *)(cp + offset);
}

__forceinline
void ADV_JOBS(int *ptr)
{
        *ptr += sizeof(JOB_AES_HMAC);
        if (*ptr >= (int) (MAX_JOBS * sizeof(JOB_AES_HMAC)))
                *ptr = 0;
}

__forceinline
JOB_AES_HMAC *
get_completed_job_sse(MB_MGR *state)
{
        JOB_AES_HMAC* job;

        if (state->earliest_job < 0)
                return NULL;

        job = JOBS(state, state->earliest_job);
        if (job->status < STS_COMPLETED)
                return NULL;

        ADV_JOBS(&state->earliest_job);

        if (state->earliest_job == state->next_job)
                state->earliest_job = -1;

        return job;
}

__forceinline
JOB_AES_HMAC *
get_next_job_sse(MB_MGR *state)
{
        return JOBS(state, state->next_job);
}

/*
 * Wrapper macros to call arch API's set up
 * at init phase of multi-buffer manager.
 *
 * For example, after calling init_mb_mgr_sse(&mgr)
 * The 'mgr' structure be set up so that:
 *   mgr.get_next_job will point to get_next_job_sse(),
 *   mgr.submit_job will point to submit_job_sse(),
 *   mgr.submit_job_nocheck will point to submit_job_nocheck_sse(),
 *   mgr.get_completed_job will point to get_completed_job_sse(),
 *   mgr.flush_job will point to flush_job_sse(),
 *   mgr.queue_size will point to queue_size_sse()
 *   mgr.keyexp_128 will point to aes_keyexp_128_sse()
 *   mgr.keyexp_192 will point to aes_keyexp_192_sse()
 *   mgr.keyexp_256 will point to aes_keyexp_256_sse()
 *
 * Direct use of arch API's may result in better performance.
 * Using below indirect interface may produce slightly worse performance but
 * it can simplify application implementation.
 * LibTestApp provides example of using the indirect interface.
 */
#define IMB_GET_NEXT_JOB(_mgr)       (_mgr)->get_next_job((_mgr))
#define IMB_SUBMIT_JOB(_mgr)         (_mgr)->submit_job((_mgr))
#define IMB_SUBMIT_JOB_NOCHECK(_mgr) (_mgr)->submit_job_nocheck((_mgr))
#define IMB_GET_COMPLETED_JOB(_mgr)  (_mgr)->get_completed_job((_mgr))
#define IMB_FLUSH_JOB(_mgr)          (_mgr)->flush_job((_mgr))
#define IMB_QUEUE_SIZE(_mgr)         (_mgr)->queue_size((_mgr))
#define IMB_AES_KEYEXP_128(_mgr, _raw, _enc, _dec) \
        (_mgr)->keyexp_128((_raw), (_enc), (_dec))
#define IMB_AES_KEYEXP_192(_mgr, _raw, _enc, _dec) \
        (_mgr)->keyexp_192((_raw), (_enc), (_dec))
#define IMB_AES_KEYEXP_256(_mgr, _raw, _enc, _dec) \
        (_mgr)->keyexp_256((_raw), (_enc), (_dec))
