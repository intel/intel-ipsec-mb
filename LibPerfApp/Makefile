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

EXE=ipsec_perf
INSTPATH ?= /usr/include/intel-ipsec-mb.h
LIB_DIR ?= ..

CFLAGS = -DLINUX -D_GNU_SOURCE -DNO_COMPAT_IMB_API_053 $(INCLUDES) \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
	-pthread -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv

LDFLAGS = -fPIE -z noexecstack -z relro -z now -pthread
LDLIBS = -lIPSec_MB

ifeq ("$(shell test -e $(INSTPATH) && echo -n yes)","yes")
# library installed
CFLAGS +=
else
# library not installed
CFLAGS +=  -I../include -I../
LDFLAGS += -L$(LIB_DIR)
endif

ifeq ($(DEBUG),y)
CFLAGS += -g -DDEBUG -O0
LDFLAGS += -g
else
CFLAGS += -O3 -fPIE -fstack-protector -D_FORTIFY_SOURCE=2
endif

SOURCES := ipsec_perf.c msr.c
OBJECTS := $(SOURCES:%.c=%.o)

CHECKPATCH ?= checkpatch.pl
CPPCHECK ?= cppcheck

.PHONY: all clean style cppcheck

all: $(EXE)

$(EXE): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

ipsec_perf.o: $(SOURCES)

.PHONY: clean
clean:
	-rm -f $(OBJECTS)
	-rm -f $(EXE)

SOURCES_STYLE := $(foreach infile,$(SOURCES),-f $(infile))
CHECKPATCH?=checkpatch.pl
.PHONY: style
style:
	$(CHECKPATCH) --no-tree --no-signoff --emacs --no-color \
--ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,\
UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,\
COMPLEX_MACRO,SPACING,STORAGE_CLASS $(SOURCES_STYLE)
