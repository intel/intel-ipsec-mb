/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "mac_test.h"
#include "cipher_test.h"

int
json_parser_test(struct IMB_MGR *mb_mgr);

/* Write content to a temp file; returns 0 on success, -1 on failure */
static int
write_tmp_file(const char *path, const char *content)
{
        FILE *f = fopen(path, "w");

        if (f == NULL)
                return -1;
        if (content != NULL && content[0] != '\0')
                fputs(content, f);
        fclose(f);
        return 0;
}

/* Remove a temp file, printing a warning if it cannot be deleted */
static void
remove_tmp_file(const char *path)
{
        if (remove(path) != 0)
                fprintf(stderr, "WARNING: failed to remove temp file '%s'\n", path);
}

int
json_parser_test(struct IMB_MGR *mb_mgr)
{
        (void) mb_mgr;

        int errors = 0;
        char path[64];
        struct mac_test *mac_v = NULL;
        struct cipher_test *cipher_v = NULL;
        struct test_json_alloc_ctx *ctx = NULL;
        int ret;

        if (!quiet_mode)
                printf("JSON Parser test:\n");

        /* ------------------------------------------------------------------ */
        /* P1 – valid MAC single vector                                        */
        /* ------------------------------------------------------------------ */
        strcpy(path, "imb_json_test_1.json");
        ret = write_tmp_file(path, "{\n"
                                   "  \"testGroups\": [\n"
                                   "    {\n"
                                   "      \"tests\": [\n"
                                   "        {\n"
                                   "          \"tcId\": 1,\n"
                                   "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                   "          \"keySize\": 128,\n"
                                   "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                   "          \"msgSize\": 128,\n"
                                   "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                   "          \"tagSize\": 128,\n"
                                   "          \"result\": \"valid\"\n"
                                   "        }\n"
                                   "      ]\n"
                                   "    }\n"
                                   "  ]\n"
                                   "}\n");
        if (ret != 0) {
                fprintf(stderr, "FAIL: P1 – could not write temp file\n");
                errors++;
                goto p1_done;
        }
        ret = json_load_mac_test(path, &mac_v, &ctx);
        if (ret != 0) {
                fprintf(stderr, "FAIL: P1 – json_load_mac_test returned %d\n", ret);
                errors++;
                goto p1_cleanup;
        }
        if (mac_v[1].msg != NULL) {
                fprintf(stderr, "FAIL: P1 – expected sentinel at index 1\n");
                errors++;
        } else if (mac_v[0].tcId != 1 || mac_v[0].keySize != 128 || mac_v[0].msgSize != 128 ||
                   mac_v[0].tagSize != 128 || mac_v[0].resultValid != 1 || mac_v[0].key == NULL ||
                   (unsigned char) mac_v[0].key[0] != 0x2b || mac_v[0].msg == NULL ||
                   (unsigned char) mac_v[0].msg[0] != 0x6b || mac_v[0].tag == NULL ||
                   (unsigned char) mac_v[0].tag[0] != 0x07) {
                fprintf(stderr, "FAIL: P1 – unexpected field values\n");
                errors++;
        } else {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("PASS: P1 - valid MAC single vector\n");
#else
                        printf(".");
#endif
                }
        }
p1_cleanup:
        json_free_test_ctx(ctx);
        ctx = NULL;
        mac_v = NULL;
p1_done:
        remove_tmp_file(path);

        /* ------------------------------------------------------------------ */
        /* P2 – valid MAC with "invalid" result                                */
        /* ------------------------------------------------------------------ */
        strcpy(path, "imb_json_test_2.json");
        ret = write_tmp_file(path, "{\n"
                                   "  \"testGroups\": [\n"
                                   "    {\n"
                                   "      \"tests\": [\n"
                                   "        {\n"
                                   "          \"tcId\": 2,\n"
                                   "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                   "          \"keySize\": 128,\n"
                                   "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                   "          \"msgSize\": 128,\n"
                                   "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                   "          \"tagSize\": 128,\n"
                                   "          \"result\": \"invalid\"\n"
                                   "        }\n"
                                   "      ]\n"
                                   "    }\n"
                                   "  ]\n"
                                   "}\n");
        if (ret != 0) {
                fprintf(stderr, "FAIL: P2 – could not write temp file\n");
                errors++;
                goto p2_done;
        }
        ret = json_load_mac_test(path, &mac_v, &ctx);
        if (ret != 0) {
                fprintf(stderr, "FAIL: P2 – json_load_mac_test returned %d\n", ret);
                errors++;
                goto p2_cleanup;
        }
        if (mac_v[0].resultValid != 0) {
                fprintf(stderr, "FAIL: P2 – expected resultValid == 0, got %d\n",
                        mac_v[0].resultValid);
                errors++;
        } else {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("PASS: P2 - valid MAC with invalid result\n");
#else
                        printf(".");
#endif
                }
        }
p2_cleanup:
        json_free_test_ctx(ctx);
        ctx = NULL;
        mac_v = NULL;
p2_done:
        remove_tmp_file(path);

        /* ------------------------------------------------------------------ */
        /* P3 – fields at testGroup level (inherited)                          */
        /* ------------------------------------------------------------------ */
        strcpy(path, "imb_json_test_3.json");
        ret = write_tmp_file(path, "{\n"
                                   "  \"testGroups\": [\n"
                                   "    {\n"
                                   "      \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                   "      \"keySize\": 128,\n"
                                   "      \"tests\": [\n"
                                   "        {\n"
                                   "          \"tcId\": 1,\n"
                                   "          \"msg\": \"\",\n"
                                   "          \"msgSize\": 0,\n"
                                   "          \"tag\": \"bb1d6929e95937287fa37d129b756746\",\n"
                                   "          \"tagSize\": 128,\n"
                                   "          \"result\": \"valid\"\n"
                                   "        }\n"
                                   "      ]\n"
                                   "    }\n"
                                   "  ]\n"
                                   "}\n");
        if (ret != 0) {
                fprintf(stderr, "FAIL: P3 – could not write temp file\n");
                errors++;
                goto p3_done;
        }
        ret = json_load_mac_test(path, &mac_v, &ctx);
        if (ret != 0) {
                fprintf(stderr, "FAIL: P3 – json_load_mac_test returned %d\n", ret);
                errors++;
                goto p3_cleanup;
        }
        if (mac_v[1].msg != NULL) {
                fprintf(stderr, "FAIL: P3 – expected sentinel at index 1\n");
                errors++;
        } else if (mac_v[0].keySize != 128 || mac_v[0].key == NULL ||
                   (unsigned char) mac_v[0].key[0] != 0x2b) {
                fprintf(stderr, "FAIL: P3 – unexpected field values\n");
                errors++;
        } else {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("PASS: P3 - fields at testGroup level (inherited)\n");
#else
                        printf(".");
#endif
                }
        }
p3_cleanup:
        json_free_test_ctx(ctx);
        ctx = NULL;
        mac_v = NULL;
p3_done:
        remove_tmp_file(path);

        /* ------------------------------------------------------------------ */
        /* P4 – valid MAC multiple testGroups                                  */
        /* ------------------------------------------------------------------ */
        strcpy(path, "imb_json_test_4.json");
        ret = write_tmp_file(path, "{\n"
                                   "  \"testGroups\": [\n"
                                   "    {\n"
                                   "      \"tests\": [\n"
                                   "        {\n"
                                   "          \"tcId\": 1,\n"
                                   "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                   "          \"keySize\": 128,\n"
                                   "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                   "          \"msgSize\": 128,\n"
                                   "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                   "          \"tagSize\": 128,\n"
                                   "          \"result\": \"valid\"\n"
                                   "        }\n"
                                   "      ]\n"
                                   "    },\n"
                                   "    {\n"
                                   "      \"tests\": [\n"
                                   "        {\n"
                                   "          \"tcId\": 2,\n"
                                   "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                   "          \"keySize\": 128,\n"
                                   "          \"msg\": \"ae2d8a571e03ac9c9eb76fac45af8e51\",\n"
                                   "          \"msgSize\": 128,\n"
                                   "          \"tag\": \"7649abac8119b246cee98e9b12e9197d\",\n"
                                   "          \"tagSize\": 128,\n"
                                   "          \"result\": \"valid\"\n"
                                   "        }\n"
                                   "      ]\n"
                                   "    }\n"
                                   "  ]\n"
                                   "}\n");
        if (ret != 0) {
                fprintf(stderr, "FAIL: P4 – could not write temp file\n");
                errors++;
                goto p4_done;
        }
        ret = json_load_mac_test(path, &mac_v, &ctx);
        if (ret != 0) {
                fprintf(stderr, "FAIL: P4 – json_load_mac_test returned %d\n", ret);
                errors++;
                goto p4_cleanup;
        }
        if (mac_v[2].msg != NULL) {
                fprintf(stderr, "FAIL: P4 – expected sentinel at index 2\n");
                errors++;
        } else if (mac_v[0].msg == NULL || mac_v[1].msg == NULL) {
                fprintf(stderr, "FAIL: P4 – expected 2 vectors\n");
                errors++;
        } else {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("PASS: P4 - valid MAC multiple testGroups\n");
#else
                        printf(".");
#endif
                }
        }
p4_cleanup:
        json_free_test_ctx(ctx);
        ctx = NULL;
        mac_v = NULL;
p4_done:
        remove_tmp_file(path);

        /* ------------------------------------------------------------------ */
        /* P5 – valid cipher single vector                                     */
        /* ------------------------------------------------------------------ */
        strcpy(path, "imb_json_test_5.json");
        ret = write_tmp_file(path, "{\n"
                                   "  \"testGroups\": [\n"
                                   "    {\n"
                                   "      \"tests\": [\n"
                                   "        {\n"
                                   "          \"tcId\": 1,\n"
                                   "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                   "          \"keySize\": 128,\n"
                                   "          \"iv\": \"000102030405060708090a0b0c0d0e0f\",\n"
                                   "          \"ivSize\": 128,\n"
                                   "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                   "          \"msgSize\": 128,\n"
                                   "          \"ct\": \"7649abac8119b246cee98e9b12e9197d\",\n"
                                   "          \"result\": \"valid\"\n"
                                   "        }\n"
                                   "      ]\n"
                                   "    }\n"
                                   "  ]\n"
                                   "}\n");
        if (ret != 0) {
                fprintf(stderr, "FAIL: P5 – could not write temp file\n");
                errors++;
                goto p5_done;
        }
        ret = json_load_cipher_test(path, &cipher_v, &ctx);
        if (ret != 0) {
                fprintf(stderr, "FAIL: P5 – json_load_cipher_test returned %d\n", ret);
                errors++;
                goto p5_cleanup;
        }
        if (cipher_v[1].msg != NULL) {
                fprintf(stderr, "FAIL: P5 – expected sentinel at index 1\n");
                errors++;
        } else if (cipher_v[0].keySize != 128 || cipher_v[0].ivSize != 128 ||
                   cipher_v[0].msgSize != 128 || cipher_v[0].resultValid != 1 ||
                   cipher_v[0].key == NULL || (unsigned char) cipher_v[0].key[0] != 0x2b ||
                   cipher_v[0].iv == NULL || (unsigned char) cipher_v[0].iv[0] != 0x00 ||
                   cipher_v[0].msg == NULL || (unsigned char) cipher_v[0].msg[0] != 0x6b ||
                   cipher_v[0].ct == NULL || (unsigned char) cipher_v[0].ct[0] != 0x76) {
                fprintf(stderr, "FAIL: P5 – unexpected field values\n");
                errors++;
        } else {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("PASS: P5 - valid cipher single vector\n");
#else
                        printf(".");
#endif
                }
        }
p5_cleanup:
        json_free_test_ctx(ctx);
        ctx = NULL;
        cipher_v = NULL;
p5_done:
        remove_tmp_file(path);

        /* ------------------------------------------------------------------ */
        /* P6 – sizes derived from hex when size fields absent                 */
        /* ------------------------------------------------------------------ */
        strcpy(path, "imb_json_test_6.json");
        ret = write_tmp_file(path, "{\n"
                                   "  \"testGroups\": [\n"
                                   "    {\n"
                                   "      \"tests\": [\n"
                                   "        {\n"
                                   "          \"tcId\": 1,\n"
                                   "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                   "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                   "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                   "          \"result\": \"valid\"\n"
                                   "        }\n"
                                   "      ]\n"
                                   "    }\n"
                                   "  ]\n"
                                   "}\n");
        if (ret != 0) {
                fprintf(stderr, "FAIL: P6 – could not write temp file\n");
                errors++;
                goto p6_done;
        }
        ret = json_load_mac_test(path, &mac_v, &ctx);
        if (ret != 0) {
                fprintf(stderr, "FAIL: P6 – json_load_mac_test returned %d\n", ret);
                errors++;
                goto p6_cleanup;
        }
        if (mac_v[0].keySize != 128 || mac_v[0].msgSize != 128 || mac_v[0].tagSize != 128) {
                fprintf(stderr, "FAIL: P6 – derived sizes wrong: key=%zu msg=%zu tag=%zu\n",
                        mac_v[0].keySize, mac_v[0].msgSize, mac_v[0].tagSize);
                errors++;
        } else {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("PASS: P6 - sizes derived from hex when size fields absent\n");
#else
                        printf(".");
#endif
                }
        }
p6_cleanup:
        json_free_test_ctx(ctx);
        ctx = NULL;
        mac_v = NULL;
p6_done:
        remove_tmp_file(path);

        /* ================================================================== */
        /* Negative tests – parser must return -1                             */
        /* ================================================================== */

        /* N1 – empty file */
        strcpy(path, "imb_json_test_n1.json");
        if (write_tmp_file(path, "") != 0) {
                fprintf(stderr, "FAIL: N1 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N1 – expected -1 for empty file, got %d\n", ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N1 - empty file\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N2 – empty JSON object {} */
        strcpy(path, "imb_json_test_n2.json");
        if (write_tmp_file(path, "{}") != 0) {
                fprintf(stderr, "FAIL: N2 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N2 – expected -1 for empty object, got %d\n", ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N2 - empty JSON object\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N3 – root is array [] */
        strcpy(path, "imb_json_test_n3.json");
        if (write_tmp_file(path, "[]") != 0) {
                fprintf(stderr, "FAIL: N3 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N3 – expected -1 for root array, got %d\n", ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N3 - root is array\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N4 – testGroups not array */
        strcpy(path, "imb_json_test_n4.json");
        if (write_tmp_file(path, "{\"testGroups\": \"bad\"}") != 0) {
                fprintf(stderr, "FAIL: N4 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N4 – expected -1 for testGroups not array, got %d\n",
                                ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N4 - testGroups not array\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N5 – tests not array */
        strcpy(path, "imb_json_test_n5.json");
        if (write_tmp_file(path, "{\"testGroups\": [{\"tests\": \"bad\"}]}") != 0) {
                fprintf(stderr, "FAIL: N5 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N5 – expected -1 for tests not array, got %d\n",
                                ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N5 - tests not array\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N6 – missing result field */
        strcpy(path, "imb_json_test_n6.json");
        if (write_tmp_file(path, "{\n"
                                 "  \"testGroups\": [\n"
                                 "    {\n"
                                 "      \"tests\": [\n"
                                 "        {\n"
                                 "          \"tcId\": 1,\n"
                                 "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                 "          \"keySize\": 128,\n"
                                 "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                 "          \"msgSize\": 128,\n"
                                 "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                 "          \"tagSize\": 128\n"
                                 "        }\n"
                                 "      ]\n"
                                 "    }\n"
                                 "  ]\n"
                                 "}\n") != 0) {
                fprintf(stderr, "FAIL: N6 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N6 – expected -1 for missing result field, got %d\n",
                                ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N6 - missing result field\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N7 – invalid result value */
        strcpy(path, "imb_json_test_n7.json");
        if (write_tmp_file(path, "{\n"
                                 "  \"testGroups\": [\n"
                                 "    {\n"
                                 "      \"tests\": [\n"
                                 "        {\n"
                                 "          \"tcId\": 1,\n"
                                 "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                 "          \"keySize\": 128,\n"
                                 "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                 "          \"msgSize\": 128,\n"
                                 "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                 "          \"tagSize\": 128,\n"
                                 "          \"result\": \"maybe\"\n"
                                 "        }\n"
                                 "      ]\n"
                                 "    }\n"
                                 "  ]\n"
                                 "}\n") != 0) {
                fprintf(stderr, "FAIL: N7 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N7 – expected -1 for invalid result value, got %d\n",
                                ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N7 - invalid result value\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N8 – invalid hex chars */
        strcpy(path, "imb_json_test_n8.json");
        if (write_tmp_file(path, "{\n"
                                 "  \"testGroups\": [\n"
                                 "    {\n"
                                 "      \"tests\": [\n"
                                 "        {\n"
                                 "          \"tcId\": 1,\n"
                                 "          \"key\": \"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\",\n"
                                 "          \"keySize\": 128,\n"
                                 "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                 "          \"msgSize\": 128,\n"
                                 "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                 "          \"tagSize\": 128,\n"
                                 "          \"result\": \"valid\"\n"
                                 "        }\n"
                                 "      ]\n"
                                 "    }\n"
                                 "  ]\n"
                                 "}\n") != 0) {
                fprintf(stderr, "FAIL: N8 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N8 – expected -1 for invalid hex chars, got %d\n",
                                ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N8 - invalid hex chars\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N9 – truncated JSON */
        strcpy(path, "imb_json_test_n9.json");
        if (write_tmp_file(path, "{\"testGroups\": [") != 0) {
                fprintf(stderr, "FAIL: N9 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N9 – expected -1 for truncated JSON, got %d\n", ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N9 - truncated JSON\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N10 – negative keySize */
        strcpy(path, "imb_json_test_n10.json");
        if (write_tmp_file(path, "{\n"
                                 "  \"testGroups\": [\n"
                                 "    {\n"
                                 "      \"tests\": [\n"
                                 "        {\n"
                                 "          \"tcId\": 1,\n"
                                 "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                 "          \"keySize\": -1,\n"
                                 "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                 "          \"msgSize\": 128,\n"
                                 "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                 "          \"tagSize\": 128,\n"
                                 "          \"result\": \"valid\"\n"
                                 "        }\n"
                                 "      ]\n"
                                 "    }\n"
                                 "  ]\n"
                                 "}\n") != 0) {
                fprintf(stderr, "FAIL: N10 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N10 – expected -1 for negative keySize, got %d\n",
                                ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N10 - negative keySize\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        /* N11 – keySize overflow */
        strcpy(path, "imb_json_test_n11.json");
        if (write_tmp_file(path, "{\n"
                                 "  \"testGroups\": [\n"
                                 "    {\n"
                                 "      \"tests\": [\n"
                                 "        {\n"
                                 "          \"tcId\": 1,\n"
                                 "          \"key\": \"2b7e151628aed2a6abf7158809cf4f3c\",\n"
                                 "          \"keySize\": 99999999999999999999,\n"
                                 "          \"msg\": \"6bc1bee22e409f96e93d7e117393172a\",\n"
                                 "          \"msgSize\": 128,\n"
                                 "          \"tag\": \"070a16b46b4d4144f79bdd9dd04a287c\",\n"
                                 "          \"tagSize\": 128,\n"
                                 "          \"result\": \"valid\"\n"
                                 "        }\n"
                                 "      ]\n"
                                 "    }\n"
                                 "  ]\n"
                                 "}\n") != 0) {
                fprintf(stderr, "FAIL: N11 - could not create temp file\n");
                errors++;
        } else {
                int saved_stderr = suppress_stderr();
                ret = json_load_mac_test(path, &mac_v, &ctx);
                restore_stderr(saved_stderr);
                if (ret != -1) {
                        fprintf(stderr, "FAIL: N11 – expected -1 for keySize overflow, got %d\n",
                                ret);
                        errors++;
                        json_free_test_ctx(ctx);
                        ctx = NULL;
                } else {
                        if (!quiet_mode) {
#ifdef DEBUG
                                printf("PASS: N11 - keySize overflow\n");
#else
                                printf(".");
#endif
                        }
                }
                remove_tmp_file(path);
        }

        if (!quiet_mode) {
                printf("\n");
                if (errors)
                        printf("JSON Parser test: %d error(s)\n", errors);
        }
        return errors;
}
