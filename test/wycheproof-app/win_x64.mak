#
# Copyright (c) 2022, Intel Corporation
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

APP = imb-wycheproof

include ..\common\win_x64_common.mk

OBJS = aes_gcm_test.json.obj aes_ccm_test.json.obj \
	chacha20_poly1305_test.json.obj \
	aes_cmac_test.json.obj gmac_test.json.obj \
	hmac_sha1_test.json.obj hmac_sha224_test.json.obj \
	hmac_sha256_test.json.obj hmac_sha384_test.json.obj \
	hmac_sha512_test.json.obj wycheproof.obj
LFLAGS = /out:$(APP).exe $(DLFLAGS)

all: $(APP).exe

$(APP).exe: $(OBJS) $(IPSECLIB)
        $(LNK) $(LFLAGS) $(OBJS) $(IPSECLIB)

tests.dep: $(OBJS)
        @type *.obj.dep > $@ 2> nul

.c.obj:
	$(CC) /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

clean:
        del /q $(OBJS) tests.dep *.obj.dep $(APP).exe

!if exist(tests.dep)
!include tests.dep
!endif
