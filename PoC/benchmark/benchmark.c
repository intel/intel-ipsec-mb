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

#include <sys/queue.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <stddef.h>

#include "crypto_ipsec.h"

struct esp_frame_s {
        SLIST_ENTRY(esp_frame_s) node;
        const struct crypto_attr_s *attr;
        unsigned payload_len;
        unsigned max_size;

        struct esp_hd_s esp;
        union {
                struct {
                        uint8_t iv[8];
                        uint8_t payload[0];
                } ctr;

                struct {
                        uint8_t iv[16];
                        uint8_t payload[0];
                } cbc;

                struct {
                        uint8_t payload[0];
                } null;
        };
} __attribute__((packed));

SLIST_HEAD(esp_list_s, esp_frame_s);

/* iv:16 tag:32 block:16 */
#define DEADSPACE	(offsetof(struct esp_frame_s, esp) + 32 + 16 + 16)

#define IS_ENABLED(flags, algo)		(flags & (1u << algo))

#define SALT	BSWAP32(0xcafebabe)

/****************************************************************************
 *
 ****************************************************************************/
static int
init_esp(struct esp_list_s *head,
         unsigned num,
         unsigned size)
{
        unsigned alloc_size = size + DEADSPACE;

        SLIST_INIT(head);

        if (alloc_size < 4096)
                alloc_size = 4096;

        for (uint32_t seq = 1; seq <= num; seq++) {
                struct esp_frame_s *frame;

                if ((frame = aligned_alloc(4096, alloc_size)) == NULL)
                        return -1;
                frame->max_size = size;
                frame->esp.spi = BSWAP32(0x0000a5f8);
                frame->esp.seq = BSWAP32(0x0000000a);

                uint8_t iv[8] = {
                        0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
                };
                memcpy(frame->ctr.iv, iv, sizeof(iv));
                uint8_t txt[] = {
                        0x45, 0x00, 0x00, 0x3e, 0x69, 0x8f, 0x00, 0x00,
                        0x80, 0x11, 0x4d, 0xcc, 0xc0, 0xa8, 0x01, 0x02,
                        0xc0, 0xa8, 0x01, 0x01, 0x0a, 0x98, 0x00, 0x35,
                        0x00, 0x2a, 0x23, 0x43, 0xb2, 0xd0, 0x01, 0x00,
                        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x03, 0x73, 0x69, 0x70, 0x09, 0x63, 0x79, 0x62,
                        0x65, 0x72, 0x63, 0x69, 0x74, 0x79, 0x02, 0x64,
                        0x6b, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
                };

                memcpy(frame->ctr.payload, txt, sizeof(txt));
                SLIST_INSERT_HEAD(head, frame, node);
        }
        return 0;
}

static void
init_dump(const struct MB_MGR *mb_mgr)
{
        (void) mb_mgr;
#if 0
#if 1
        hexdump(stderr, "AES128",
                &mb_mgr->aes128_ooo,
                sizeof(mb_mgr->aes128_ooo));
        hexdump(stderr, "AES192",
                &mb_mgr->aes192_ooo,
                sizeof(mb_mgr->aes192_ooo));
        hexdump(stderr, "AES256",
                &mb_mgr->aes256_ooo,
                sizeof(mb_mgr->aes256_ooo));

        hexdump(stderr, "SHA1",
                &mb_mgr->hmac_sha_1_ooo,
                sizeof(mb_mgr->hmac_sha_1_ooo));
        hexdump(stderr, "SHA224",
                &mb_mgr->hmac_sha_224_ooo,
                sizeof(mb_mgr->hmac_sha_224_ooo));
        hexdump(stderr, "SHA256",
                &mb_mgr->hmac_sha_256_ooo,
                sizeof(mb_mgr->hmac_sha_256_ooo));
        hexdump(stderr, "SHA384",
                &mb_mgr->hmac_sha_384_ooo,
                sizeof(mb_mgr->hmac_sha_384_ooo));
        hexdump(stderr, "SHA512",
                &mb_mgr->hmac_sha_512_ooo,
                sizeof(mb_mgr->hmac_sha_512_ooo));
        hexdump(stderr, "MD5",
                &mb_mgr->hmac_md5_ooo,
                sizeof(mb_mgr->hmac_md5_ooo));
        hexdump(stderr, "AES-XCBC",
                &mb_mgr->aes_xcbc_ooo,
                sizeof(mb_mgr->aes_xcbc_ooo));

#else
        /* SAH-1 */
        hexdump(stderr, "SHA-1 lane data extra_block",
                mb_mgr->hmac_sha_1_ooo.ldata[0].extra_block,
                sizeof(mb_mgr->hmac_sha_1_ooo.ldata[0].extra_block));
        hexdump(stderr, "SHA-1 lane data outer_block",
                mb_mgr->hmac_sha_1_ooo.ldata[0].outer_block,
                sizeof(mb_mgr->hmac_sha_1_ooo.ldata[0].outer_block));
        fprintf(stderr,
                "outer_done:0x%04x extra_blocks:0x%04x size_offset:0x%04x start_offset:0x%04x\n",
                mb_mgr->hmac_sha_1_ooo.ldata[0].outer_done,
                mb_mgr->hmac_sha_1_ooo.ldata[0].extra_blocks,
                mb_mgr->hmac_sha_1_ooo.ldata[0].size_offset,
                mb_mgr->hmac_sha_1_ooo.ldata[0].start_offset);
        fprintf(stderr,
                "unused_lanes:0x%08llx\n\n",
                (unsigned long long) mb_mgr->hmac_sha_1_ooo.unused_lanes);

        /* SHA-224 */
                hexdump(stderr, "SHA-224 lane data extra_block",
                mb_mgr->hmac_sha_224_ooo.ldata[0].extra_block,
                sizeof(mb_mgr->hmac_sha_224_ooo.ldata[0].extra_block));
        hexdump(stderr, "SHA-224 lane data outer_block",
                mb_mgr->hmac_sha_224_ooo.ldata[0].outer_block,
                sizeof(mb_mgr->hmac_sha_224_ooo.ldata[0].outer_block));
        fprintf(stderr,
                "outer_done:0x%04x extra_blocks:0x%04x size_offset:0x%04x start_offset:0x%04x\n",
                mb_mgr->hmac_sha_224_ooo.ldata[0].outer_done,
                mb_mgr->hmac_sha_224_ooo.ldata[0].extra_blocks,
                mb_mgr->hmac_sha_224_ooo.ldata[0].size_offset,
                mb_mgr->hmac_sha_224_ooo.ldata[0].start_offset);
        fprintf(stderr,
                "unused_lanes:0x%08llx\n\n",
                (unsigned long long) mb_mgr->hmac_sha_224_ooo.unused_lanes);

        /* SHA-256 */
        hexdump(stderr, "SHA-256 lane data extra_block",
                mb_mgr->hmac_sha_256_ooo.ldata[0].extra_block,
                sizeof(mb_mgr->hmac_sha_256_ooo.ldata[0].extra_block));
        hexdump(stderr, "SHA-256 lane data outer_block",
                mb_mgr->hmac_sha_256_ooo.ldata[0].outer_block,
                sizeof(mb_mgr->hmac_sha_256_ooo.ldata[0].outer_block));
        fprintf(stderr,
                "outer_done:0x%04x extra_blocks:0x%04x size_offset:0x%04x start_offset:0x%04x\n",
                mb_mgr->hmac_sha_256_ooo.ldata[0].outer_done,
                mb_mgr->hmac_sha_256_ooo.ldata[0].extra_blocks,
                mb_mgr->hmac_sha_256_ooo.ldata[0].size_offset,
                mb_mgr->hmac_sha_256_ooo.ldata[0].start_offset);
        fprintf(stderr,
                "unused_lanes:0x%08llx\n\n",
                (unsigned long long) mb_mgr->hmac_sha_256_ooo.unused_lanes);

        /* SHA-384 */
        hexdump(stderr, "SHA-384 lane data extra_block",
                mb_mgr->hmac_sha_384_ooo.ldata[0].extra_block,
                sizeof(mb_mgr->hmac_sha_384_ooo.ldata[0].extra_block));
        hexdump(stderr, "SHA-384 lane data outer_block",
                mb_mgr->hmac_sha_384_ooo.ldata[0].outer_block,
                sizeof(mb_mgr->hmac_sha_384_ooo.ldata[0].outer_block));
        fprintf(stderr,
                "outer_done:0x%04x extra_blocks:0x%04x size_offset:0x%04x start_offset:0x%04x\n",
                mb_mgr->hmac_sha_384_ooo.ldata[0].outer_done,
                mb_mgr->hmac_sha_384_ooo.ldata[0].extra_blocks,
                mb_mgr->hmac_sha_384_ooo.ldata[0].size_offset,
                mb_mgr->hmac_sha_384_ooo.ldata[0].start_offset);
        fprintf(stderr,
                "unused_lanes:0x%08llx\n\n",
                (unsigned long long) mb_mgr->hmac_sha_384_ooo.unused_lanes);

        /* SHA-512 */
        hexdump(stderr, "SHA-512 lane data extra_block",
                mb_mgr->hmac_sha_512_ooo.ldata[0].extra_block,
                sizeof(mb_mgr->hmac_sha_512_ooo.ldata[0].extra_block));
        hexdump(stderr, "SHA-512 lane data outer_block",
                mb_mgr->hmac_sha_512_ooo.ldata[0].outer_block,
                sizeof(mb_mgr->hmac_sha_512_ooo.ldata[0].outer_block));
        fprintf(stderr,
                "outer_done:0x%04x extra_blocks:0x%04x size_offset:0x%04x start_offset:0x%04x\n",
                mb_mgr->hmac_sha_512_ooo.ldata[0].outer_done,
                mb_mgr->hmac_sha_512_ooo.ldata[0].extra_blocks,
                mb_mgr->hmac_sha_512_ooo.ldata[0].size_offset,
                mb_mgr->hmac_sha_512_ooo.ldata[0].start_offset);
        fprintf(stderr,
                "unused_lanes:0x%08llx\n\n",
                (unsigned long long) mb_mgr->hmac_sha_512_ooo.unused_lanes);

#endif
        exit(0);
#endif
}

static inline void
xxx_exec(struct MB_MGR *mb_mgr,
         enum JOB_CIPHER_DIRECTION dir,
         struct esp_frame_s *frame,
         uint16_t payload_len,
         const struct crypto_attr_s *attr)
{
        struct JOB_AES_HMAC *job;
        union AES_IV *iv;
        struct aad {
                BE32 spi;
                BE32 seq;
        };
        struct aad *aad;
        struct esp_hd_s *esp = &frame->esp;
        uint8_t *p = (uint8_t *) (esp + 1);

        job = ipsec_mb_get_next_job(mb_mgr);
        iv = (union AES_IV *) (&job->ext_data[0]);
        aad = (struct aad *) (&job->ext_data[1]);
        job->user_data = frame;
        job->user_data2 = (void *) ((uintptr_t) attr);

        memcpy(aad, esp, sizeof(*aad));
        if (attr->iv_len == 8) {
                iv->salt32 = SALT;
                memcpy(iv->iv, p, 8);
                iv->ctr32 = BSWAP32(1);
        } else {
                memcpy(iv, p, 16);
        }
        p += attr->iv_len;

        job->src = esp;
        job->dst = p;

        job->cipher_start_src_offset_in_bytes = sizeof(*esp) + attr->iv_len;
        job->msg_len_to_cipher_in_bytes = payload_len;
        job->auth_tag_output = (p + payload_len);
        job->auth_tag_output_len_in_bytes = attr->tag_len;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = payload_len + sizeof(*esp) + attr->iv_len;

        job->cipher_mode = attr->cipher_mode;
        job->hash_alg = attr->hash_alg;
        job->aes_key_len_in_bytes = attr->cipher_key_len;
        job->auth_tag_output_len_in_bytes = attr->tag_len;
        job->aes_enc_key_expanded = attr->enc_key;
        job->aes_dec_key_expanded = attr->dec_key;
        job->iv = iv;
        job->iv_len_in_bytes = sizeof(*iv);
        job->aad = aad;
        job->aad_len_in_bytes = 8;
        job->cipher_direction = dir;

        if (dir == ENCRYPT)
                job->chain_order = CIPHER_HASH;
        else
                job->chain_order = HASH_CIPHER;

        switch (attr->hash_alg) {
        case SHA1:
        case SHA_224:
        case SHA_256:
        case SHA_384:
        case SHA_512:
        case MD5:
                job->hmac.ipad_key = attr->auth_key->hmac.ipad;
                job->hmac.opad_key = attr->auth_key->hmac.opad;
                break;

        case AES_XCBC:
                job->xcbc.k1_exp = &attr->auth_key->xcbc.k1;
                job->xcbc.k2     = &attr->auth_key->xcbc.k2;
                job->xcbc.k3     = &attr->auth_key->xcbc.k3;
                break;

        case GMAC_AES:
                job->gmac.key = &attr->auth_key->gmac;
                break;

        default:
                break;
        }

        submit_job(mb_mgr, job);
}

static uint64_t
bench_mb(struct MB_MGR *mb_mgr,
         struct esp_list_s *esp_list,
         uint16_t payload_len,
         const struct crypto_attr_s *attr)
{
        enum JOB_CIPHER_DIRECTION dir;
        uint64_t start_tsc, end_tsc;

        start_tsc = rdtsc();
        for (dir = ENCRYPT; dir <= DECRYPT; dir++) {
                struct esp_frame_s *next = SLIST_FIRST(esp_list);

                flush_job(mb_mgr);

                while (next) {
                        struct esp_frame_s *frame = next;

                        next = SLIST_NEXT(frame ,node);
                        if (next)
                                prefetch0(next);

                        xxx_exec(mb_mgr,
                                 dir,
                                 frame,
                                 payload_len,
                                 attr);
                }
        }

        flush_job(mb_mgr);

        end_tsc = rdtsc();
        return end_tsc - start_tsc;
}

/******************************************************************************
 *
 ******************************************************************************/

static const char *cipher_mode_name[] = {
        [CBC]            = "CBC",
        [CNTR]           = "CTR",
        [NULL_CIPHER]    = "NULL",
        [GCM]            = "GCM",
        [DOCSIS_SEC_BPI] = "DOCSIS",
};

static const char *hash_alg_name[] = {
        [SHA1]        = "SHA1",
        [SHA_224]     = "SHA224",
        [SHA_256]     = "SHA256",
        [SHA_384]     = "SHA384",
        [SHA_512]     = "SHA512",
        [AES_XCBC]    = "XCBC",
        [NULL_HASH]   = "NULL",
        [GMAC_AES]    = "GMAC128",
        [MD5]         = "MD5",
};

static int
key_len_bit(unsigned len)
{
        const unsigned klen_bit[] = { 0, 128, 192, 256 };

        for (unsigned i = 0; i < ARRAYOF(klen_bit); i++) {
                if (klen_bit[i] == len)
                        return (int) i;
        }
        return -1;
}

#if 0
static inline uint64_t
random_bench(unsigned cpuid_flags,
             struct MB_MGR *mb_mgr,
             unsigned max_size,
             struct esp_list_s *esp_list,
             struct xorshift_s *seed,
             uint64_t cipher_flags,
             uint64_t auth_flags)
{
        const unsigned nb_attr = arrayof_crypto_attr();
        struct esp_frame_s *frame, *next;
        uint64_t start_tsc, tsc;
        unsigned packets = 0;
        unsigned bytes = 0;
        unsigned payload_len;
        const struct crypto_attr_s *attr;

        start_tsc = rdtsc();
        /* encryption */
        SLIST_FOREACH (frame, esp_list, node) {
                next = SLIST_NEXT(frame ,node);
                if (next)
                        prefetch0(next);

                do {
                        attr = &crypto_attr[xorshift(seed) % nb_attr];
                } while (!IS_ENABLED(cipher_flags, attr->cipher_mode) ||
                         !IS_ENABLED(auth_flags, attr->hash_alg));

                if (max_size > 16) {
                        do {
                                payload_len = xorshift(seed) & (frame->max_size - 1);
                                payload_len &= ~(attr->block_size - 1);
                        } while (payload_len < 16);
                } else {
                        payload_len = 16;
                }

                xxx_exec(mb_mgr,
                         sess_list,
                         ENCRYPT,
                         frame,
                         payload_len,
                         attr);

                packets++;
                bytes += payload_len;
        }

        /* decryption */
        SLIST_FOREACH (frame, esp_list, node) {
                next = SLIST_NEXT(frame ,node);
                if (next)
                        prefetch0(next);

                attr = frame->attr;
                payload_len = frame->payload_len;

                xxx_exec(mb_mgr,
                         sess_list,
                         DECRYPT,
                         frame,
                         payload_len,
                         attr);

                bytes += payload_len;
                packets++;
        }

        flush_job(mb_mgr);

        tsc = rdtsc() - start_tsc;
        fprintf(stdout,
                "%x\trandom av \t%u %6"PRIu64" %.2f\n",
                cpuid_flags,
                bytes / packets,
                tsc / packets,
                (double) tsc / (double) (bytes * packets));
        return 0;
}
#endif

static int
benchmark(unsigned cpuid_flags,
          struct esp_list_s *esp_list,
          const unsigned num,
          const unsigned size,
          unsigned cipher_flags,
          unsigned auth_flags,
          unsigned klen_flags)
{
        struct xorshift_s seed;
        DECLARE_ALIGNED(struct MB_MGR mb_mgr, 32);

        memset(&mb_mgr, 0x55, sizeof(mb_mgr));

        if (ipsec_mb_cpuid_set(cpuid_flags)) {
                fprintf(stderr, "failed CPUID set:0x%0x\n", cpuid_flags);
                return -1;
        }
        cpuid_flags = ipsec_mb_cpuid_get();
        ipsec_mb_init_mgr(&mb_mgr);

        init_dump(&mb_mgr);

        xorshift_init(&seed);
        init_key();

        fprintf(stdout, "arch\tcipher-auth\tbytes   cpp   cpB\n");
        for (unsigned i = 0; i < arrayof_crypto_attr(); i++) {

                if (!IS_ENABLED(cipher_flags, crypto_attr[i].cipher_mode)) {
                        continue;
                }

                if (!IS_ENABLED(auth_flags, crypto_attr[i].hash_alg)) {
                        continue;
                }

                if (key_len_bit(crypto_attr[i].cipher_key_len << 3) >= 0) {
                        if (!IS_ENABLED(klen_flags,
                                        key_len_bit(crypto_attr[i].cipher_key_len << 3))) {
                                continue;
                        }
                }

                for (unsigned len = 16; len <= size; len <<= 1) {
                        uint64_t tsc = 0;

                        tsc = bench_mb(&mb_mgr,
                                       esp_list,
                                       len,
                                       &crypto_attr[i]);

                        fprintf(stdout,
                                "0x%0x\t%s%d-%s\t%4u %6"PRIu64" %.2f\n",
                                cpuid_flags,
                                cipher_mode_name[crypto_attr[i].cipher_mode],
                                crypto_attr[i].cipher_key_len << 3,
                                hash_alg_name[crypto_attr[i].hash_alg],
                                len, tsc / (num * 2),
                                (double) tsc / (double) (len * num * 2.0));
                }
        }
#if 0
        random_bench(cpuid_flags,
                     &mb_mgr,
                     size,
                     esp_list,
                     sess_list,
                     &seed,
                     cipher_flags,
                     auth_flags);
#endif
        return 0;
}

#define PRN_JOB(job)                                                    \
        do {                                                            \
                if (job) {                                              \
                        uintptr_t id = (uintptr_t) (job->user_data);    \
                        job->user_data = NULL;                          \
                        fprintf(stderr, "%s:%d Job:%p id:%u status:0x%x\n", \
                                __func__, __LINE__, job, (unsigned) id, job->status); \
                } else {                                                \
                        fprintf(stderr, "%s:%d Job:%p\n",               \
                                __func__, __LINE__, job);               \
                }                                                       \
        } while(0)



static void
usage(const char *prog)
{
        fprintf(stderr,
                "%s [-i CPUID] [-n NUM] [-s SIZE] [-c CIPHER_NAME] [-k KEY_LEN] [-a AUTH_NAME]\n"
                "\t-i:\tCPUID: enabled CPUID. default AUTO\n"
                "\t-n:\tNUM: number of packets(8196)\n"
                "\t-s:\tSIZE: size of packet(2048)\n"
                "\t-c:\tignored cipher algorithm\n"
                "\t-k:\tignored cipher key length\n"
                "\t-a:\tignored authentication algorithm\n",
                prog);

        fprintf(stderr,
                "CPUID:\tAESNI(must) PCLMULQDQ(must) AVX AVX2 AVX512F SHANI\n");
        fprintf(stderr,
                "CIPHER_NAME:\n"
                "\tCBC CTR GCM NULL\n");

        fprintf(stderr,
                "KE_LEN:\n"
                "\t0 128 192 256\n");

        fprintf(stderr,
                "AUTH_NAME:\n"
                "\tHMAC_SHA1 HMAC_SHA256 HMAC_SHA384 HMAC_SHA512\n"
                "\tAES_XCBC NULL\n");

        exit(0);
}

static unsigned
cipher_method_id(const char *name)
{
        for (unsigned i = 0; i < ARRAYOF(cipher_mode_name); i++) {
                if (!cipher_mode_name[i])
                        continue;
                if (!strcmp(name, cipher_mode_name[i]))
                        return i;
        }
        return 0;
}

static unsigned
hash_alg_id(const char *name)
{
        for (unsigned i = 0; i < ARRAYOF(hash_alg_name); i++) {
                if (!hash_alg_name[i])
                        continue;
                if (!strcmp(name, hash_alg_name[i]))
                        return i;
        }
        return 0;
}

extern int gcm_test(void);


static unsigned
get_cpuid(const char *s)
{
        const char *cpuid_name[] = {
                [CPUID_AESNI]     = "AESNI",
                [CPUID_PCLMULQDQ] = "PCLMULQDQ",
                [CPUID_AVX]       = "AVX",
                [CPUID_AVX2]      = "AVX2",
                [CPUID_AVX512F]    = "AVX512F",
                [CPUID_SHANI]     = "SHANI",
        };

        for (unsigned i = 0; i < ARRAYOF(cpuid_name); i++) {
                if (!cpuid_name[i])
                        continue;
                if (!strcmp(s, cpuid_name[i]))
                        return (1u << i);
        }
        fprintf(stderr, "unknown CPUID: %s ... ignored\n", s);
        return 0;
}

/*
 *
 */
int
main(int argc,
     char **argv)
{
        int opt;
        unsigned nb_packet = 1024 * 8;
        unsigned sz_packet = 2048;
        struct esp_list_s esp_list;
        unsigned cpuid_flags = 0;
        unsigned cipher_flags = -1;
        unsigned auth_flags = -1;
        unsigned klen_flags = -1;

#if 0
        if (gcm_test()) {
                fprintf(stderr, "failed GCM test\n");
                return 0;
        }
#endif
        while ((opt = getopt(argc, argv, "i:n:s:c:a:k:")) != -1) {
                switch (opt) {
                case 'i':
                        cpuid_flags |= get_cpuid(optarg);
                        break;
                case 'n':
                        nb_packet = atoi(optarg);
                        break;
                case 's':
                        sz_packet = atoi(optarg);
                        break;
                case 'c':
                        cipher_flags &= ~(1u << cipher_method_id(optarg));
                        break;
                case 'a':
                        auth_flags &= ~(1u << hash_alg_id(optarg));
                        break;
                case'k':
                        {
                                int id = key_len_bit(atoi(optarg));

                                if (id < 0) {
                                        usage(argv[0]);
                                        return -1;
                                }
                                klen_flags &= ~(1u << id);
                        }
                        break;
                default:
                        usage(argv[0]);
                        return -1;
                }
        }

        if (!nb_packet || sz_packet < 16 ||
            !cipher_flags || !auth_flags || __builtin_popcount(sz_packet) != 1) {
                fprintf(stderr, "invalid args\n");
                return -1;
        }

        if (init_esp(&esp_list, nb_packet, sz_packet)) {
                fprintf(stderr, "failed to initialize ESP\n");
                return -1;
        }

        if (benchmark(cpuid_flags,
                      &esp_list,
                      nb_packet,
                      sz_packet,
                      cipher_flags,
                      auth_flags,
                      klen_flags))
                fprintf(stderr, "failed to exec bench\n");
        return 0;
}
