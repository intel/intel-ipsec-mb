#
# Copyright (c) 2017-2020, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

TEST_APP = ipsec_MB_testapp
XVALID_APP = ipsec_xvalid_test
INSTNAME = intel-ipsec-mb

!if !defined(PREFIX)
PREFIX = C:\Program Files
!endif

!if exist("$(PREFIX)\$(INSTNAME)\libIPSec_MB.lib")
IPSECLIB = "$(PREFIX)\$(INSTNAME)\libIPSec_MB.lib"
INCDIR = -I"$(PREFIX)\$(INSTNAME)"
!else
!if !defined(LIB_DIR)
LIB_DIR = ..
!endif
IPSECLIB = "$(LIB_DIR)\libIPSec_MB.lib"
INCDIR = -I..\ -I..\include
!endif

!ifdef DEBUG
DCFLAGS = /Od /DDEBUG /Z7
DLFLAGS = /debug
!else
DCFLAGS = /O2 /Oi
DLFLAGS =
!endif

CC = cl
# _CRT_SECURE_NO_WARNINGS disables warning C4996 about unsecure snprintf() being used
CFLAGS = /nologo /DNO_COMPAT_IMB_API_053 /D_CRT_SECURE_NO_WARNINGS $(DCFLAGS) /Y- /W3 /WX- /Gm- /fp:precise /EHsc $(EXTRA_CFLAGS) $(INCDIR)

LNK = link
TEST_LFLAGS = /out:$(TEST_APP).exe $(DLFLAGS)
XVALID_LFLAGS = /out:$(XVALID_APP).exe $(DLFLAGS)

AS = nasm
AFLAGS = -fwin64 -Xvc -DWIN_ABI

TEST_OBJS = main.obj gcm_test.obj ctr_test.obj customop_test.obj des_test.obj ccm_test.obj cmac_test.obj hmac_sha1_test.obj hmac_sha256_sha512_test.obj utils.obj hmac_md5_test.obj aes_test.obj sha_test.obj chained_test.obj api_test.obj pon_test.obj ecb_test.obj zuc_test.obj kasumi_test.obj snow3g_test.obj direct_api_test.obj clear_mem_test.obj

XVALID_OBJS = ipsec_xvalid.obj misc.obj

all: $(TEST_APP).exe $(XVALID_APP).exe

$(TEST_APP).exe: $(TEST_OBJS) $(IPSECLIB)
        $(LNK) $(TEST_LFLAGS) $(TEST_OBJS) $(IPSECLIB)

$(XVALID_APP).exe: $(XVALID_OBJS) $(IPSECLIB)
        $(LNK) $(XVALID_LFLAGS) $(XVALID_OBJS) $(IPSECLIB)

misc.obj: misc.asm
        $(AS) -o $@ $(AFLAGS) misc.asm

main.obj: main.c do_test.h
        $(CC) /c $(CFLAGS) main.c

gcm_test.obj: gcm_test.c gcm_ctr_vectors_test.h
        $(CC) /c $(CFLAGS) gcm_test.c

ctr_test.obj: ctr_test.c gcm_ctr_vectors_test.h
        $(CC) /c $(CFLAGS) ctr_test.c

pon_test.obj: pon_test.c gcm_ctr_vectors_test.h
        $(CC) /c $(CFLAGS) pon_test.c

customop_test.obj: customop_test.c customop_test.h
        $(CC) /c $(CFLAGS) customop_test.c

des_test.obj: des_test.c gcm_ctr_vectors_test.h
        $(CC) /c $(CFLAGS) des_test.c

ccm_test.obj: ccm_test.c gcm_ctr_vectors_test.h utils.h
        $(CC) /c $(CFLAGS) ccm_test.c

cmac_test.obj: cmac_test.c utils.h
        $(CC) /c $(CFLAGS) cmac_test.c

hmac_sha1_test.obj: hmac_sha1_test.c utils.h
        $(CC) /c $(CFLAGS) hmac_sha1_test.c

hmac_sha256_sha512_test.obj: hmac_sha256_sha512_test.c utils.h
        $(CC) /c $(CFLAGS) hmac_sha256_sha512_test.c

hmac_md5_test.obj: hmac_md5_test.c utils.h
        $(CC) /c $(CFLAGS) hmac_md5_test.c

aes_test.obj: aes_test.c utils.h
        $(CC) /c $(CFLAGS) aes_test.c

ecb_test.obj: ecb_test.c utils.h
        $(CC) /c $(CFLAGS) ecb_test.c

utils.obj: utils.c
        $(CC) /c $(CFLAGS) utils.c

sha_test.obj: sha_test.c utils.h
        $(CC) /c $(CFLAGS) sha_test.c

chained_test.obj: chained_test.c utils.h
        $(CC) /c $(CFLAGS) chained_test.c

api_test.obj: api_test.c gcm_ctr_vectors_test.h
        $(CC) /c $(CFLAGS) api_test.c

zuc_test.obj: zuc_test.c zuc_test_vectors.h
        $(CC) /c $(CFLAGS) zuc_test.c

kasumi_test.obj: kasumi_test.c kasumi_test_vectors.h
        $(CC) /c $(CFLAGS) kasumi_test.c

snow3g_test.obj: snow3g_test.c snow3g_test_vectors.h
        $(CC) /c $(CFLAGS) snow3g_test.c

direct_api_test.obj: direct_api_test.c
        $(CC) /c $(CFLAGS) direct_api_test.c

ipsec_xvalid.obj: ipsec_xvalid.c misc.h
        $(CC) /c $(CFLAGS) ipsec_xvalid.c

clear_mem_test.obj: clear_mem_test.c gcm_ctr_vectors_test.h
        $(CC) /c $(CFLAGS) clear_mem_test.c

clean:
        del /q $(TEST_OBJS) $(TEST_APP).* $(XVALID_OBJS) $(XVALID_APP).*
