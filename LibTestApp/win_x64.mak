#
# Copyright (c) 2017-2019, Intel Corporation
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

APP = ipsec_MB_testapp
INSTNAME = intel-ipsec-mb

!if !defined(PREFIX)
PREFIX = C:\Program Files
!endif

!if exist("$(PREFIX)\$(INSTNAME)\libIPSec_MB.lib")
IPSECLIB = "$(PREFIX)\$(INSTNAME)\libIPSec_MB.lib"
INCDIR = -I"$(PREFIX)\$(INSTNAME)"
!else
IPSECLIB = ..\libIPSec_MB.lib
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
CFLAGS = /nologo /D_CRT_SECURE_NO_WARNINGS $(DCFLAGS) /Y- /W3 /WX- /Gm- /fp:precise /EHsc $(INCDIR)

LNK = link
LFLAGS = /out:$(APP).exe $(DLFLAGS)

OBJS = main.obj gcm_test.obj ctr_test.obj customop_test.obj des_test.obj ccm_test.obj cmac_test.obj hmac_sha1_test.obj hmac_sha256_sha512_test.obj utils.obj hmac_md5_test.obj aes_test.obj sha_test.obj chained_test.obj api_test.obj

all: $(APP).exe

$(APP).exe: $(OBJS) $(IPSECLIB)
        $(LNK) $(LFLAGS) $(OBJS) $(IPSECLIB)

main.obj: main.c do_test.h
	$(CC) /c $(CFLAGS) main.c

gcm_test.obj: gcm_test.c gcm_ctr_vectors_test.h
	$(CC) /c $(CFLAGS) gcm_test.c

ctr_test.obj: ctr_test.c gcm_ctr_vectors_test.h
	$(CC) /c $(CFLAGS) ctr_test.c

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

hmac_aes_test.obj: aes_test.c utils.h
	$(CC) /c $(CFLAGS) aes_test.c

utils.obj: utils.c
	$(CC) /c $(CFLAGS) utils.c

sha_test.obj: sha_test.c utils.h
	$(CC) /c $(CFLAGS) sha_test.c

chained_test.obj: chained_test.c utils.h
	$(CC) /c $(CFLAGS) chained_test.c

api_test.obj: api_test.c gcm_ctr_vectors_test.h
	$(CC) /c $(CFLAGS) api_test.c

clean:
	del /q $(OBJS) $(APP).*
