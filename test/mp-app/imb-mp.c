/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

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
*****************************************************************************/

#include <stdlib.h>
#include <stdio.h>

#include <intel-ipsec-mb.h>

#ifdef LINUX
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

int is_secondary = 0;

/*
 * =============================================================================
 * =============================================================================
 * Shared memory create and destroy
 */

#define SHM_SIZE (2ULL * 1024ULL * 1024ULL)
#define SHM_NAME "mp-app-shared-memory"

void *mmap_ptr = NULL;
void *alloc_ptr = NULL;
size_t alloc_offset = 0;

int shm_fd;

static int
shm_destroy(void)
{
        int ret = 0;

        if (alloc_ptr != NULL)
                if (munmap(alloc_ptr, SHM_SIZE) != 0)
                        ret = -1;
        alloc_ptr = NULL;

        if (shm_fd == -1)
                if (close(shm_fd) != 0)
                        ret = -1;
        shm_fd = -1;

        if (!is_secondary) {
                if (shm_unlink(SHM_NAME) != 0)
                        ret = -1;
        }

        return ret;
}

static int
shm_create(void)
{
        /* create the shared memory object */
        if (is_secondary)
                shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);
        else
                shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
        if (shm_fd == -1)
                return -1;

        /* configure the size of the shared memory object */
        if (!is_secondary) {
                if (ftruncate(shm_fd, SHM_SIZE) != 0) {
                        (void) shm_destroy();
                        return -1;
                }
        }

        /*
         * memory map the shared memory object
         * - secondary process maps shared memory into the same region as the primary process
         */
        if (is_secondary)
                alloc_ptr = mmap(mmap_ptr, SHM_SIZE, PROT_WRITE, MAP_SHARED, shm_fd, 0);
        else
                alloc_ptr = mmap(0, SHM_SIZE, PROT_WRITE, MAP_SHARED, shm_fd, 0);

        if (alloc_ptr == MAP_FAILED) {
                (void) shm_destroy();
                return -1;
        }

        mmap_ptr = alloc_ptr;
        return 0;
}

/*
 * =============================================================================
 * =============================================================================
 * Shared memory allocator
 */

/**
 * @brief Simple memory allocator from the shared memory pool
 *
 * @param length data size to allocate in bytes
 * @param alignment 0 or any power of 2 to align memory allocation to
 *
 * @return Pointer to allocated memory
 * @retval NULL allocation error
 */
static void *
mp_alloc(const size_t length, const size_t alignment)
{
        if (alloc_ptr == NULL)
                return NULL;

        if ((alloc_offset + length) > SHM_SIZE)
                return NULL;

        if (alignment > 1) {
                const size_t align_mask = alignment - 1;

                alloc_offset = (alloc_offset + align_mask) & (~align_mask);
        }

        void *ptr = ((char *) alloc_ptr + alloc_offset);

        alloc_offset += length;

        return ptr;
}

/*
 * =============================================================================
 * =============================================================================
 * Primary and secondary processes
 */

/*
 * Process data
 * - primary process allocates and initializes them
 * - secondary process only picks them up
 * All shared memory allocations will have the same virtual address
 * in primary and secondary processes.
 */
const size_t buffer_size = 17 * 16;

static unsigned jobs_sent = 0;
static unsigned jobs_received = 0;

static void *p_mgr;
static void *exp_enc_key;
static void *exp_dec_key;
static void *aes_key;
static void *iv;
static void *buffer_table_in[15];
static void *buffer_table_out[15];
static IMB_MGR *mb_mgr;

static int
submit_aes_cbc_enc_jobs(IMB_MGR *p_mgr, void **in, void **out, const size_t n, const int do_flush)
{
        for (size_t i = 0; i < n; i++) {
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                memset(job, 0, sizeof(*job));

                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = in[i];
                job->dst = out[i];
                job->cipher_mode = IMB_CIPHER_CBC;
                job->enc_keys = exp_enc_key;
                job->dec_keys = NULL;
                job->key_len_in_bytes = IMB_KEY_128_BYTES;

                job->iv = iv;
                job->iv_len_in_bytes = 16;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = buffer_size;
                job->hash_alg = IMB_AUTH_NULL;

                IMB_JOB *job_ret = IMB_SUBMIT_JOB(p_mgr);

                if (imb_get_errno(p_mgr) == 0)
                        jobs_sent++;
                else
                        return -1;

                if (job_ret != NULL)
                        jobs_received++;
        }

        if (!do_flush)
                return 0;

        while (IMB_FLUSH_JOB(p_mgr) != NULL) {
                const int err = imb_get_errno(p_mgr);

                if (err != 0) {
                        fprintf(stderr, "!Flush error: %s!\n", imb_get_strerror(err));
                        return -1;
                } else
                        jobs_received++;
        }

        return 0;
}

static int
init_imb_and_buffers(void)
{
        if (!is_secondary) {
                /*
                 * Primary process does all memory allocations in shared memory and
                 * stores pointers in data section that secondary process will inherit
                 */
                size_t i;

                p_mgr = mp_alloc(imb_get_mb_mgr_size(), 64);
                exp_enc_key = mp_alloc(11 * 16, 16);
                exp_dec_key = mp_alloc(11 * 16, 16);
                aes_key = mp_alloc(16, 0);
                iv = mp_alloc(16, 0);

                for (i = 0; i < IMB_DIM(buffer_table_in); i++) {
                        buffer_table_in[i] = mp_alloc(buffer_size, 4);
                        if (buffer_table_in[i] == NULL)
                                break;
                        memset(buffer_table_in[i], ~i, buffer_size);

                        buffer_table_out[i] = mp_alloc(buffer_size, 4);
                        if (buffer_table_out[i] == NULL)
                                break;
                        memset(buffer_table_out[i], 0, buffer_size);
                }

                if (p_mgr == NULL || exp_enc_key == NULL || exp_dec_key == NULL ||
                    aes_key == NULL || iv == NULL || i < IMB_DIM(buffer_table_in))
                        return -1;

                /*
                 * Set up multi-buffer manager in the shared memory
                 * - imb_set_pointers_mb_mgr() call with reset parameter is required
                 *     Normally, alloc_mb_mgr() clears memory and sets selected feature flags.
                 * - it is followed with init_mb_mgr_auto() call
                 */
                mb_mgr = imb_set_pointers_mb_mgr(p_mgr, 0, 1);
                if (mb_mgr == NULL)
                        return -1;

                IMB_ARCH arch;

                init_mb_mgr_auto(mb_mgr, &arch);

                if (imb_get_errno(mb_mgr) != 0)
                        return -1;

        } else {
                /*
                 * Secondary process picks allocations done by primary process and
                 * resets functions pointers in the manager
                 */
                mb_mgr = imb_set_pointers_mb_mgr(p_mgr, 0, 0);
        }

        if (mb_mgr == NULL)
                return -1;

        if (!is_secondary) {
                /* Create key schedule and set IV */
                memset(aes_key, 0xaa, 16);
                IMB_AES_KEYEXP_128(mb_mgr, aes_key, exp_enc_key, exp_dec_key);

                memset(iv, 0x55, 16);

                /*
                 * Use temporary manager to get reference answers
                 */
                IMB_MGR *tmp_mgr = alloc_mb_mgr(0);

                if (tmp_mgr == NULL)
                        return -1;

                IMB_ARCH arch;

                init_mb_mgr_auto(tmp_mgr, &arch);

                if (imb_get_errno(tmp_mgr) != 0) {
                        free_mb_mgr(tmp_mgr);
                        return -1;
                }

                jobs_sent = 0;
                jobs_received = 0;

                if (submit_aes_cbc_enc_jobs(tmp_mgr, buffer_table_in, buffer_table_out,
                                            IMB_DIM(buffer_table_in), 1) != 0) {
                        free_mb_mgr(tmp_mgr);
                        return -1;
                }

                if (jobs_sent != IMB_DIM(buffer_table_in)) {
                        free_mb_mgr(tmp_mgr);
                        return -1;
                }

                jobs_sent = 0;
                jobs_received = 0;

                free_mb_mgr(tmp_mgr);
        }

        return 0;
}

static int
mp_secondary(void)
{
        is_secondary = 1;

        if (jobs_sent == 0)
                return -1;

        if (shm_create() != 0)
                return -1;

        if (init_imb_and_buffers() != 0) {
                (void) shm_destroy();
                return -1;
        }

        unsigned jobs_received_now = 0;

        while (IMB_FLUSH_JOB(mb_mgr) != NULL) {
                const int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        fprintf(stderr, "SECONDARY: flush error: %s!\n", imb_get_strerror(err));
                        (void) shm_destroy();
                        return -1;
                } else {
                        jobs_received_now++;
                        jobs_received++;
                }
        }

        fprintf(stdout, "SECONDARY: received %u (total %u) AES-128-CBC encrypt jobs\n",
                jobs_received_now, (unsigned) jobs_received);

        if (jobs_sent != jobs_received) {
                fprintf(stderr, "SECONDARY: expected %u jobs, received %u\n", (unsigned) jobs_sent,
                        (unsigned) jobs_received);
                (void) shm_destroy();
                return -1;
        }

        if (shm_destroy() != 0)
                return -1;
        return 0;
}

static int
mp_primary(void)
{
        is_secondary = 0;

        if (shm_create() != 0)
                return -1;

        if (init_imb_and_buffers() != 0) {
                (void) shm_destroy();
                return -1;
        }

        jobs_sent = 0;
        jobs_received = 0;
        if (submit_aes_cbc_enc_jobs(mb_mgr, buffer_table_in, buffer_table_in,
                                    IMB_DIM(buffer_table_in), 0) != 0) {
                (void) shm_destroy();
                return -1;
        }

        fprintf(stdout, "PRIMARY: sent %u AES-128-CBC encrypt jobs\n", (unsigned) jobs_sent);
        fprintf(stdout, "PRIMARY: received %u AES-128-CBC encrypt jobs\n",
                (unsigned) jobs_received);

        if (jobs_sent != IMB_DIM(buffer_table_in)) {
                (void) shm_destroy();
                return -1;
        }

        /*
         * - fork now
         * - let the child perform the flush operation
         * - wait for child to complete
         */
        pid_t pid = fork();

        if (pid < 0) {
                fprintf(stderr, "PRIMARY: Fork failed\n");
                return -1;
        }

        if (pid == 0) {
                /* child process - secondary process */
                const int status = mp_secondary();

                (void) shm_destroy();
                fflush(stderr);
                fflush(stdout);
                exit((status != 0) ? EXIT_FAILURE : EXIT_SUCCESS);
        } else {
                /* parent waits for the child to finish */
                int wstatus = 0;

                wait(&wstatus);

                const int err = (!WIFEXITED(wstatus)) || (WEXITSTATUS(wstatus) != EXIT_SUCCESS);

                if (err != 0) {
                        fprintf(stderr, "PRIMARY: secondary process failed\n");
                        fprintf(stdout, "MULTI-PROCESS TEST: FAILED\n");
                        (void) shm_destroy();
                        return -1;
                } else {
                        /*
                         * Child process exited normally - let's check the answers
                         */
                        unsigned mismatch = 0;

                        for (size_t i = 0; i < IMB_DIM(buffer_table_in); i++)
                                if (memcmp(buffer_table_in[i], buffer_table_out[i], buffer_size) !=
                                    0)
                                        mismatch++;

                        fprintf(stdout, "MULTI-PROCESS TEST: %s\n",
                                mismatch ? "FAILED " : "PASSED");
                }
        }

        if (shm_destroy() != 0)
                return -1;

        return 0;
}

#else /* LINUX */

static int
mp_primary(void)
{
        fprintf(stdout, "MULTI-PROCESS TEST: NOT RUN\n");
        return 0;
}

#endif /* !LINUX */

int
main(int argc, char **argv)
{
        (void) argc;
        (void) argv;

        if (mp_primary() != 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
