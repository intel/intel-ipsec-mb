#
# Copyright (c) 2023, Intel Corporation
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

APP = imb-kat

include ..\common\win_x64_common.mk

TEST_OBJS = utils.obj main.obj gcm_test.obj ctr_test.obj customop_test.obj des_test.obj ccm_test.obj cmac_test.obj hmac_sha1_test.obj hmac_sha256_sha512_test.obj hmac_md5_test.obj aes_test.obj sha_test.obj chained_test.obj api_test.obj pon_test.obj ecb_test.obj zuc_test.obj kasumi_test.obj snow3g_test.obj direct_api_test.obj clear_mem_test.obj hec_test.obj xcbc_test.obj aes_cbcs_test.obj crc_test.obj chacha_test.obj poly1305_test.obj chacha20_poly1305_test.obj null_test.obj snow_v_test.obj direct_api_param_test.obj quic_ecb_test.obj hmac_sha1.json.obj hmac_sha224.json.obj hmac_sha256.json.obj hmac_sha384.json.obj hmac_sha512.json.obj hmac_md5.json.obj gmac_test.obj gmac_test.json.obj ghash_test.obj ghash_test.json.obj poly1305_test.json.obj cmac_test.json.obj xcbc_test.json.obj sha_test.json.obj aes_cfb_test.obj aes_cfb_test.json.obj aes_cbcs_test.json.obj aes_cbc_test.obj aes_cbc_test.json.obj ecb_test.json.obj ctr_test.json.obj chacha_test.json.obj des_test.json.obj gcm_test.json.obj quic_chacha20_test.obj chacha20_poly1305_test.json.c
TEST_LFLAGS = /out:$(APP).exe $(DLFLAGS)

all: $(APP).exe tests.dep

$(APP).exe: $(TEST_OBJS) $(IPSECLIB)
        $(LNK) $(TEST_LFLAGS) $(TEST_OBJS) $(IPSECLIB)

tests.dep: $(TEST_OBJS)
        @type *.obj.dep > $@ 2> nul

.c.obj:
	$(CC) /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{..\common\}.c.obj:
	$(CC) /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

clean:
        del /q $(TEST_OBJS) tests.dep *.obj.dep $(APP).*

!if exist(tests.dep)
!include tests.dep
!endif
