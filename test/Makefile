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
LIB_DIR ?= ../lib

USE_YASM ?= n
YASM ?= yasm
NASM ?= nasm

CFLAGS = -MMD -DLINUX -D_GNU_SOURCE -DNO_COMPAT_IMB_API_053 \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
	-fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv

# if "-z ibt" is supported then assume "-z shstk, -z cet-report=error, -fcf-protection" are also supported
CC_HAS_CET = $(shell $(CC) --target-help 2> /dev/null | grep -m1 -e "-z ibt" | wc -l)

ifeq ($(CC_HAS_CET),1)
CFLAGS += -fcf-protection
endif

YASM_FLAGS := -f x64 -f elf64 -X gnu -g dwarf2 -DLINUX -D__linux__
NASM_FLAGS := -felf64 -Xgnu -gdwarf -DLINUX -D__linux__

LDFLAGS = -fPIE -z noexecstack -z relro -z now
ifeq ($(CC_HAS_CET),1)
LDFLAGS += -Wl,-z,ibt -Wl,-z,shstk -Wl,-z,cet-report=error
endif
LDLIBS = -lIPSec_MB

ifeq ("$(shell test -r $(INSTPATH) && echo -n yes)","yes")
# library installed
CFLAGS +=
else
# library not installed
CFLAGS +=  -I../lib/include -I../lib
LDFLAGS += -L$(LIB_DIR)
endif

DEBUG_OPT ?= -O0
ifeq ($(DEBUG),y)
CFLAGS += $(DEBUG_OPT) -DDEBUG -g
LDFLAGS += -g
else
CFLAGS += -O3
endif

# ipsec_MB_testapp modules
SOURCES := main.c gcm_test.c ctr_test.c customop_test.c des_test.c ccm_test.c \
	cmac_test.c utils.c hmac_sha1_test.c hmac_sha256_sha512_test.c \
	hmac_md5_test.c aes_test.c sha_test.c chained_test.c api_test.c pon_test.c \
	ecb_test.c zuc_test.c kasumi_test.c snow3g_test.c direct_api_test.c clear_mem_test.c \
	hec_test.c xcbc_test.c aes_cbcs_test.c crc_test.c chacha_test.c poly1305_test.c \
	chacha20_poly1305_test.c null_test.c snow_v_test.c
OBJECTS := $(SOURCES:%.c=%.o)

# ipsec_xvalid_test modules
XVALID_ASM := misc.asm
XVALID_SOURCES := ipsec_xvalid.c utils.c
XVALID_OBJECTS := $(XVALID_SOURCES:%.c=%.o) $(XVALID_ASM:%.asm=%.o)

# list of present dependency files
DEP_FILES = $(wildcard ./*.d)

# rule for compiling assembly code with producing dependencies
%.o:%.asm
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -MD $(@:.o=.d) -MT $@ -o $@ $(NASM_FLAGS) $<
endif

# targets come here
all: $(TEST_APP) $(XVALID_APP)

$(TEST_APP): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(XVALID_APP): $(XVALID_OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

.PHONY: clean
clean:
	-rm -f $(OBJECTS) $(TEST_APP) $(DEP_FILES) $(XVALID_OBJECTS) $(XVALID_APP) $(ASM_OBJECTS)

# style check section
CHECKPATCH?=checkpatch.pl
CHECKPATCH_FLAGS = --no-tree --no-signoff --emacs --no-color --ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,AVOID_EXTERNS,COMPLEX_MACRO,USE_FUNC,CONSTANT_COMPARISON,MISSING_SPACE,NEW_TYPEDEFS

%.c_style_check : %.c
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

%.h_style_check : %.h
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

%.asm_style_check : %.asm
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

%.inc_style_check : %.inc
	$(CHECKPATCH) $(CHECKPATCH_FLAGS) -f $<

SOURCES_ALL := $(wildcard *.[ch]) $(wildcard *.asm) $(wildcard *.inc)
SOURCES_STYLE := $(foreach infile,$(SOURCES_ALL),$(infile)_style_check)

.PHONY: style
style: $(SOURCES_STYLE)

# if target not clean or rinse then make dependencies
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),style)
-include $(wildcard *.d)
endif
endif
