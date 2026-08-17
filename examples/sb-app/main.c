/**********************************************************************
  Copyright(c) 2025 Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#define BUF_SIZE       16384
#define TOTAL_NUM_JOBS 10000UL

static void
fill_buffer(void *buf)
{
        /* Fill buffer with random data */
        for (size_t i = 0; i < BUF_SIZE; i++)
                ((unsigned char *) buf)[i] = (unsigned char) rand();
}

int
main(int argc, char **argv)
{
        if (argc != 2) {
                printf("Usage: %s <sha_type>\n", argv[0]);
                printf("sha_type: SHA1, SHA224, SHA256, SHA384, SHA512\n");
                return EXIT_FAILURE;
        }

        IMB_MGR *mb_mgr = NULL;
        int exit_status = EXIT_FAILURE;
        const char *sha_type = argv[1];

        /* Allocate buffers */
        void *src_buf = malloc(BUF_SIZE);
        uint8_t digest[IMB_SHA512_DIGEST_SIZE_IN_BYTES];

        unsigned n_jobs_left = TOTAL_NUM_JOBS;

        if (src_buf == NULL) {
                printf("Could not allocate memory for source buffer\n");
                goto exit;
        }

        /* IMB API: Allocate MB_MGR */
        mb_mgr = alloc_mb_mgr(0);

        if (mb_mgr == NULL) {
                printf("Could not allocate memory for IMB_MGR\n");
                goto exit;
        }

        fill_buffer(src_buf);

        /* IMB API: Initialize MB_MGR, detecting best implementation to use */
        init_mb_mgr_auto(mb_mgr, NULL);

        printf("Computing %s on %u bytes buffer %lu times\n", sha_type, BUF_SIZE, TOTAL_NUM_JOBS);
        while (n_jobs_left != 0) {
                if (strcasecmp(sha_type, "SHA1") == 0) {
                        IMB_SHA1(mb_mgr, src_buf, BUF_SIZE, digest);
                } else if (strcasecmp(sha_type, "SHA224") == 0) {
                        IMB_SHA224(mb_mgr, src_buf, BUF_SIZE, digest);
                } else if (strcasecmp(sha_type, "SHA256") == 0) {
                        IMB_SHA256(mb_mgr, src_buf, BUF_SIZE, digest);
                } else if (strcasecmp(sha_type, "SHA384") == 0) {
                        IMB_SHA384(mb_mgr, src_buf, BUF_SIZE, digest);
                } else if (strcasecmp(sha_type, "SHA512") == 0) {
                        IMB_SHA512(mb_mgr, src_buf, BUF_SIZE, digest);
                } else {
                        printf("Unsupported SHA type: %s\n", sha_type);
                        goto exit;
                }

                /* IMB API: Get error number set (0 = all correct) */
                const int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        printf("Error authenticating msg %d : '%s'\n", err, imb_get_strerror(err));
                        goto exit;
                } else {
                        n_jobs_left--;
                }
        }

        exit_status = EXIT_SUCCESS;

        printf("Authentication successful\n");
exit:
        free(src_buf);
        free_mb_mgr(mb_mgr);

        return exit_status;
}