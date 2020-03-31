#
# Copyright (c) 2012-2020, Intel Corporation
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

TEST_APP := ipsec_MB_testapp
XVALID_APP := ipsec_xvalid_test
INSTPATH ?= /usr/include/intel-ipsec-mb.h
LIB_DIR ?= ..

USE_YASM ?= n
YASM ?= yasm
NASM ?= nasm

CFLAGS = -g -DLINUX -D_GNU_SOURCE -DNO_COMPAT_IMB_API_053 \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
	-fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv

YASM_FLAGS := -f x64 -f elf64 -X gnu -g dwarf2 -DLINUX -D__linux__
NASM_FLAGS := -felf64 -Xgnu -gdwarf -DLINUX -D__linux__

LDFLAGS = -fPIE -z noexecstack -z relro -z now
LDLIBS = -lIPSec_MB

ifeq ("$(shell test -r $(INSTPATH) && echo -n yes)","yes")
# library installed
CFLAGS +=
else
# library not installed
CFLAGS +=  -I../include -I../
LDFLAGS += -L$(LIB_DIR)
endif

ifeq ($(DEBUG),y)
CFLAGS += -O0 -DDEBUG
LDFLAGS += -g
else
CFLAGS += -O3
endif

SOURCES := main.c gcm_test.c ctr_test.c customop_test.c des_test.c ccm_test.c \
	cmac_test.c utils.c hmac_sha1_test.c hmac_sha256_sha512_test.c \
	hmac_md5_test.c aes_test.c sha_test.c chained_test.c api_test.c pon_test.c \
	ecb_test.c zuc_test.c kasumi_test.c snow3g_test.c direct_api_test.c clear_mem_test.c

%.o:%.asm
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -MD $(@:.o=.d) -MT $@ -o $@ $(NASM_FLAGS) $<
endif

ASM_OBJECTS := misc.o

OBJECTS := $(SOURCES:%.c=%.o)

XVALID_SOURCES := ipsec_xvalid.c
XVALID_OBJECTS := $(XVALID_SOURCES:%.c=%.o) $(ASM_OBJECTS)

all: $(TEST_APP) $(XVALID_APP)

$(TEST_APP): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(XVALID_APP): $(XVALID_OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

main.o: main.c do_test.h
gcm_test.o: gcm_test.c gcm_ctr_vectors_test.h
ctr_test.o: ctr_test.c gcm_ctr_vectors_test.h
pon_test.o: pon_test.c gcm_ctr_vectors_test.h
des_test.o: des_test.c
ccm_test.o: ccm_test.c utils.h
cmac_test.o: cmac_test.c utils.h
hmac_sha1_test.o: hmac_sha1_test.c utils.h
hmac_md5_test.o: hmac_md5_test.c utils.h
hmac_sha256_sha512_test.o: hmac_sha256_sha512_test.c utils.h
aes_test.o: aes_test.c gcm_ctr_vectors_test.h utils.h
ecb_test.o: ecb_test.c gcm_ctr_vectors_test.h utils.h
customop_test.o: customop_test.c customop_test.h
utils.o: utils.c utils.h
sha_test.o: sha_test.c utils.h
chained_test.o: chained_test.c utils.h
api_test.o: api_test.c gcm_ctr_vectors_test.h
zuc_test.o: zuc_test.c zuc_test_vectors.h
kasumi_test.o: kasumi_test.c kasumi_test_vectors.h
snow3g_test.o: snow3g_test.c snow3g_test_vectors.h
ipsec_xvalid.o: ipsec_xvalid.c misc.h
direct_api_test.o: direct_api_test.c
clear_mem_test.o: clear_mem_test.c

.PHONY: clean
clean:
	-rm -f $(OBJECTS) $(TEST_APP) $(XVALID_OBJECTS) $(XVALID_APP) $(ASM_OBJECTS)

SOURCES_STYLE := $(foreach infile,$(SOURCES) $(XVALID_SOURCES),-f $(infile))
CHECKPATCH?=checkpatch.pl
.PHONY: style
style:
	$(CHECKPATCH) --no-tree --no-signoff --emacs --no-color \
--ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,\
UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,\
AVOID_EXTERNS,COMPLEX_MACRO,USE_FUNC,CONSTANT_COMPARISON,MISSING_SPACE $(SOURCES_STYLE)
