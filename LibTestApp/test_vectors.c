/*
 * Test Vectors
 *   by deadcafe.beef
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "handler.h"

int Verbose = 0;

static void
usage(const char *prog)
{
        fprintf(stderr,
                "%s [-v] [-0] [-1] [-2] [-3] [-h] [-g] [-c] [-e] [-b]\n"
                "\t-v:\tverbose (disable)\n"
                "\t-0:\tSSE\n"
                "\t-1:\tAVX\n"
                "\t-2:\tAVX2\n"
                "\t-3:\tAVX512 (disable)\n"
                "\t-h:\tHMAC\n"
                "\t-g:\tGCM\n"
                "\t-c:\tCTR\n"
                "\t-e:\tECB (disable)\n"
                "\t-b:\tBenchmark (disable)\n",

                prog);
        exit(0);
}


enum target_e {
        ECB = 0,
        CTR,
        GCM,
        HMAC,
        BENCHMARK,

        NB_TARGETS,
};

/*
 *
 */
int
main(int argc,
     char **argv)
{
        int opt;
        unsigned flags = 0;
        unsigned targets = 0;
        enum capability_e cap;

        while ((opt = getopt(argc, argv, "0123cghevb")) != -1) {
                switch (opt) {
                case '0':
                        flags |= (1u << SSE);
                        break;
                case '1':
                        flags |= (1u << AVX);
                        break;
                case '2':
                        flags |= (1u << AVX2);
                        break;
                case '3':
                        flags |= (1u << AVX512);
                        break;
                case 'v':
                        Verbose = 1;
                        break;
                case 'c':
                        targets |= (1u << CTR);
                        break;
                case 'g':
                        targets |= (1u << GCM);
                        break;
                case 'h':
                        targets |= (1u << HMAC);
                        break;
                case 'e':
                        targets |= (1u << ECB);
                        break;
                case 'b':
                        targets |= (1u << BENCHMARK);
                        break;
                default:
                        usage(argv[0]);
                        return -1;
                }
        }

        if (!flags)
                flags = (1u << SSE) | (1u << AVX) | (1u << AVX2);

        if (!targets)
                targets = (1u << CTR) | (1u << GCM) | (1u << HMAC);

        for (cap = SSE; cap < NB_CAPS; cap++) {
                if (flags & (1u << cap)) {
                        const char *capname = get_cap_name(cap);

                        fprintf(stderr, "Testing %s\n", capname);

                        if (targets & (1u << CTR)) {
                                if (!ctr_test(cap)) {
                                        fprintf(stderr,
                                                "CTR %s interface passes\n",
                                                capname);
                                }
                        }

                        if (targets & (1u << GCM)) {
                                if (!gcm_test(cap)) {
                                        fprintf(stderr,
                                                "GCM %s interface passes\n",
                                                capname);
                                }
                        }

                        if (targets & (1u << HMAC)) {
                                if (!hmac_test(cap)) {
                                        fprintf(stderr,
                                                "HMAC %s interface passes\n",
                                                capname);
                                }
                        }

                        if (targets & (1u << ECB)) {
                                if (!ecb_test(cap)) {
                                        fprintf(stderr,
                                                "ECB %s interface passes\n",
                                                capname);
                                }
                        }

                        if (targets & (1u << BENCHMARK)) {
                                if (benchmark(cap))
                                        fprintf(stderr, "failed to exec bench\n");
                        }
                }
        }

        return 0;
}
