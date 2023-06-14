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

APP := imb-kat

# include common options
include ../common/common.mk

# imb-kat modules
SOURCES := main.c gcm_test.c ctr_test.c customop_test.c des_test.c ccm_test.c \
	cmac_test.c hmac_sha1_test.c hmac_sha256_sha512_test.c \
	hmac_md5_test.c aes_test.c sha_test.c chained_test.c api_test.c pon_test.c \
	ecb_test.c zuc_test.c kasumi_test.c snow3g_test.c direct_api_test.c clear_mem_test.c \
	hec_test.c xcbc_test.c aes_cbcs_test.c crc_test.c chacha_test.c poly1305_test.c \
	chacha20_poly1305_test.c null_test.c snow_v_test.c direct_api_param_test.c quic_ecb_test.c \
	hmac_sha1.json.c hmac_sha224.json.c hmac_sha256.json.c hmac_sha384.json.c hmac_sha512.json.c \
	hmac_md5.json.c gmac_test.json.c ghash_test.c ghash_test.json.c poly1305_test.json.c \
	cmac_test.json.c xcbc_test.json.c sha_test.json.c aes_cbcs_test.json.c gmac_test.c
OBJECTS := $(SOURCES:%.c=%.o) utils.o

# targets come here
all: $(APP)

$(APP): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

utils.o: ../common/utils.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	-rm -f $(OBJECTS) $(APP) $(DEP_FILES)

# if target not clean then make dependencies
ifneq ($(MAKECMDGOALS),clean)
-include $(wildcard *.d)
endif

