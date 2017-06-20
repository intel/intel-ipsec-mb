# Copyright (c) 2017, Intel Corporation
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
LIB_LOC?=..
LIB?=$(LIB_LOC)/libIPSec_MB.a
INCLUDE_DIRS := $(LIB_LOC) $(LIB_LOC)/include
INCLUDES := $(foreach i,$(INCLUDE_DIRS),-I$i)

CFLAGS := -DLINUX $(INCLUDES) \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition
LDFLAGS := -g

ifeq ($(DEBUG),y)
CFLAGS += -g -DDEBUG -O0
else
CFLAGS += -O2 -fPIE -fstack-protector -D_FORTIFY_SOURCE=2
endif

ifeq ($(USE_ARCH_HANDLER),y)
CFLAGS += -DUSE_ARCH_HANDLER
endif

SOURCES := ipsec_perf.c
OBJECTS := $(SOURCES:%.c=%.o)

CHECKPATCH ?= checkpatch.pl
CPPCHECK ?= cppcheck

.PHONY: all clean style cppcheck

all: $(EXE)

$(EXE): $(OBJECTS) $(LIB)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	-rm -f $(OBJECTS)
	-rm -f $(EXE)

style:
	$(CHECKPATCH) --no-tree --no-signoff --emacs \
		--ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING \
		--ignore UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE \
		--ignore GLOBAL_INITIALISERS \
		-f ipsec_perf.c

cppcheck:
	$(CPPCHECK) \
		--enable=warning,portability,performance,missingInclude \
		--std=c99 --template=gcc \
		ipsec_perf.c
