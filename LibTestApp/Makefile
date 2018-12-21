#
# Copyright (c) 2012-2019, Intel Corporation
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

APP := ipsec_MB_testapp
INSTPATH ?= /usr/include/intel-ipsec-mb.h

CFLAGS = -g -DLINUX -D_GNU_SOURCE \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition

LDFLAGS = -fPIE -z noexecstack -z relro -z now
LDLIBS = -lIPSec_MB

ifeq ("$(shell test -r $(INSTPATH) && echo -n yes)","yes")
# library installed
CFLAGS +=
else
# library not installed
CFLAGS +=  -I../include -I../
LDFLAGS += -L../
endif

ifeq ($(DEBUG),y)
CFLAGS += -O0 -DDEBUG
LDFLAGS += -g
else
CFLAGS += -O3
endif

SOURCES := main.c gcm_test.c ctr_test.c customop_test.c des_test.c ccm_test.c \
	cmac_test.c utils.c hmac_sha1_test.c hmac_sha256_sha512_test.c \
	hmac_md5_test.c aes_test.c sha_test.c api_test.c
OBJECTS := $(SOURCES:%.c=%.o)

all: $(APP)

$(APP): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

main.o: main.c do_test.h
gcm_test.o: gcm_test.c gcm_ctr_vectors_test.h
ctr_test.o: ctr_test.c gcm_ctr_vectors_test.h
des_test.o: des_test.c
ccm_test.o: ccm_test.c utils.h
cmac_test.o: cmac_test.c utils.h
hmac_sha1_test.o: hmac_sha1_test.c utils.h
hmac_md5_test.o: hmac_md5_test.c utils.h
hmac_sha256_sha512_test.o: hmac_sha256_sha512_test.c utils.h
aes_test.o: aes_test.c gcm_ctr_vectors_test.h utils.h
customop_test.o: customop_test.c customop_test.h
utils.o: utils.c utils.h
sha_test.o: sha_test.c utils.h
api_test.o: api_test.c gcm_ctr_vectors_test.h

.PHONY: clean
clean:
	-rm -f $(OBJECTS) $(APP)

SOURCES_STYLE := $(foreach infile,$(SOURCES),-f $(infile))
CHECKPATCH?=checkpatch.pl
.PHONY: style
style:
	$(CHECKPATCH) --no-tree --no-signoff --emacs --no-color \
--ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,\
UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,\
AVOID_EXTERNS,COMPLEX_MACRO,USE_FUNC,CONSTANT_COMPARISON,MISSING_SPACE $(SOURCES_STYLE)
