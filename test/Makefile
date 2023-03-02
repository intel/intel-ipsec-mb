#
# Copyright (c) 2012-2022, Intel Corporation
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

TEST_APP := test-app
XVALID_APP := xvalid-app
FUZZ_APP := fuzz-app
ACVP_APP := acvp-app
INSTPATH ?= /usr/include/intel-ipsec-mb.h
LIB_DIR ?= ../lib

MINGW ?= $(shell $(CC) -dM -E - < /dev/null | grep -i mingw | wc -l | sed 's/^ *//')

CFLAGS = -MMD -D_GNU_SOURCE -DNO_COMPAT_IMB_API_053 \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
	-fno-delete-null-pointer-checks -fwrapv -std=c99

# -fno-strict-overflow is not supported by clang
ifneq ($(CC),clang)
CFLAGS += -fno-strict-overflow
endif

# if "-z ibt" is supported then assume "-z shstk, -z cet-report=error" are also supported
# "-fcf-protection" needs to be checked separately
ifeq ($(MINGW),0)
CC_HAS_CET = $(and $(shell $(CC) --target-help 2> /dev/null | grep -m1 -e "-z ibt" | wc -l), \
	$(shell $(CC) --help=common 2> /dev/null | grep -m1 -e "-fcf-protection" | wc -l))
CET_LDFLAGS=-r -z ibt -z shstk
endif

ifeq ($(CC_HAS_CET),1)
CFLAGS += -fcf-protection=full
endif

ifeq ($(MINGW),0)
LDFLAGS = -fPIE -z noexecstack -z relro -z now
else
LDFLAGS = -fPIE
endif

ifeq ($(CC_HAS_CET),1)
LDFLAGS += -fcf-protection=full -Wl,-z,ibt -Wl,-z,shstk -Wl,-z,cet-report=error
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
ifeq ($(MINGW),0)
CFLAGS += -O3
else
CFLAGS += -O2
endif
endif

ifneq ($(PIN_CEC_ROOT),)
CFLAGS += -I$(PIN_CEC_ROOT)/include -DPIN_BASED_CEC
endif

# list of present dependency files
DEP_FILES = $(wildcard ./*.d)

# targets come here
all: $(TEST_APP) $(XVALID_APP) $(FUZZ_APP) $(DIRECT_FUZZ_APP) $(ACVP_APP)

.PHONY: $(TEST_APP) $(XVALID_APP) $(FUZZ_APP) $(ACVP_APP)

$(TEST_APP):
	$(MAKE) -C test-app

$(XVALID_APP):
	$(MAKE) -C xvalid-app

$(ACVP_APP):
	$(MAKE) -C acvp-app

.PHONY: clean
clean:
	$(MAKE) -C test-app clean
	$(MAKE) -C xvalid-app clean
	$(MAKE) -C fuzz-app clean
	$(MAKE) -C acvp-app clean

# style check section
CHECKPATCH?=checkpatch.pl
CHECKPATCH_FLAGS = --no-tree --no-signoff --emacs --no-color --max-line-length=100 --ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,AVOID_EXTERNS,COMPLEX_MACRO,USE_FUNC,CONSTANT_COMPARISON,MISSING_SPACE,NEW_TYPEDEFS

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

# cppcheck analysis check
CPPCHECK ?= cppcheck
CPPCHECK_OPTS ?= -I./ -I../lib
CPPCHECK_FLAGS ?= -j $(shell getconf _NPROCESSORS_ONLN)
CPPCHECK_FLAGS1 ?= --cppcheck-build-dir=.cppcheck $(CPPCHECK_FLAGS)
CPPCHECK_FLAGS2 ?= --cppcheck-build-dir=.bughunt $(CPPCHECK_FLAGS)
.PHONY: cppcheck
cppcheck:
	mkdir -p .cppcheck
	$(CPPCHECK) --force --enable=all $(CPPCHECK_FLAGS1) $(CPPCHECK_OPTS) ./

.PHONY: bughunt
bughunt:
	mkdir -p .bughunt
	$(CPPCHECK) --bug-hunting --inconclusive $(CPPCHECK_FLAGS2) $(CPPCHECK_OPTS) ./

# if target not clean or rinse then make dependencies
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),style)
-include $(wildcard *.d)
endif
endif
