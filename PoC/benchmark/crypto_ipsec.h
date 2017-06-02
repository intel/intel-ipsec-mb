/*
 * Copyright (c) 2017 Deadcafe Beef(deadcafe.beef@gmail.com)
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

#ifndef _CRYPTO_ATTR_H_
#define	_CRYPTO_ATTR_H_

#include <sys/queue.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <ipsec_mb.h>
#include <ipsec_mb_api.h>

struct crypto_attr_s {
        enum JOB_CIPHER_MODE cipher_mode;
        enum JOB_HASH_ALG hash_alg;
        enum AES_KEY_SIZE_BYTES cipher_key_len;
        uint16_t auth_key_len;
        uint16_t block_size;	/* in ESP frame */
        uint16_t iv_len;	/* in ESP frame */
        uint16_t tag_len;
        union auth_exp_key *auth_key;
        struct aes_exp_key *enc_key;
        struct aes_exp_key *dec_key;
};

struct esp_hd_s {
        uint32_t spi;
        uint32_t seq;
} __attribute__((packed));


struct xorshift_s {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
};

static inline UINT32
BSWAP32(UINT32 x)
{
        asm volatile ("bswap %[x]" : [x] "+r" (x));
        return x;
}

static inline void
xorshift_init(struct xorshift_s *seed)
{
    seed->x = 123456789;
    seed->y = 362436069;
    seed->z = 521288629;
    seed->w = 88675123;
}

static inline uint32_t
xorshift(struct xorshift_s *seed)
{
    uint32_t t;

    t = seed->x ^ (seed->x << 11);
    seed->x = seed->y;
    seed->y = seed->z;
    seed->z = seed->w;

    return seed->w = (seed->w ^ (seed->w >> 19)) ^ (t ^ (t >> 8));
}


extern const struct crypto_attr_s crypto_attr[];
extern enum cipher_mode_e cipher_mode(const char *name);
extern enum auth_alg_e auth_alg(const char *name);

static inline int
offset(const void *p0,
       const void *p1)
{
        return (const char *) p0 - (const char *) p1;
}

static inline void
print_error(int line,
            const char *msg,
            int status,
            const struct crypto_attr_s *attr)
{
        assert(attr);

        fprintf(stderr,
                "%d:%s status:%d "
                "%d-%d\n",
                line, msg, status,
                attr->cipher_mode,
                attr->hash_alg);
}

static inline void
flush_job(struct MB_MGR *mb_mgr)
{
        struct JOB_AES_HMAC *job;

        //        fprintf(stderr, "do flush\n");
        while ((job = ipsec_mb_flush_job(mb_mgr)) != NULL) {
                job->user_data = NULL;

                if (job->status != STS_COMPLETED) {
                        const struct crypto_attr_s *attr = job->user_data2;

                        print_error(__LINE__, "job error", job->status, attr);

                        if (job->status & STS_AUTH_FAILED) {
                                hexdump(stderr, "org", job->chk_tag_p, job->auth_tag_output_len_in_bytes);
                                hexdump(stderr, "verify", job->verify_tag, job->auth_tag_output_len_in_bytes);
                        }
                }
        }
        //        fprintf(stderr, "flushed\n");
}

static inline void
submit_job(struct MB_MGR *mb_mgr,
           struct JOB_AES_HMAC *job)
{
        //        fprintf(stderr, "do submit\n");

        job = ipsec_mb_submit_job(mb_mgr, job);
        while (job) {

                job->user_data = NULL;
                if (job->status != STS_COMPLETED) {
                        const struct crypto_attr_s *attr = job->user_data2;

                        print_error(__LINE__, "job error", job->status, attr);

                        if (job->status & STS_AUTH_FAILED) {
                                hexdump(stderr, "org", job->chk_tag_p, job->auth_tag_output_len_in_bytes);
                                hexdump(stderr, "verify", job->verify_tag, job->auth_tag_output_len_in_bytes);
                        }
                }

                //                fprintf(stderr, "completed\n");
                job = ipsec_mb_get_completed_job(mb_mgr);
        }

        //        fprintf(stderr, "submited\n");
}


extern unsigned arrayof_crypto_attr(void);

extern void init_key(void);

#endif	/* !_CRYPTO_ATTR_H_ */
