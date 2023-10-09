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

APP := imb-burst
INSTPATH ?= /usr/include/intel-ipsec-mb.h
LIB_DIR ?= ../../lib

CFLAGS = -D_GNU_SOURCE -DNO_COMPAT_IMB_API_053 $(INCLUDES) \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
	-pthread -fno-delete-null-pointer-checks -fwrapv -std=c99

MINGW ?= $(shell $(CC) -dM -E - < /dev/null | grep -i mingw | wc -l | sed 's/^ *//')

# -fno-strict-overflow is not supported by clang
ifneq ($(CC),clang)
CFLAGS += -fno-strict-overflow
endif

LDLIBS = -lIPSec_MB
ifeq ($(MINGW),0)
LDFLAGS = -fPIE -z noexecstack -z relro -z now -pthread
else
LDFLAGS = -fPIE
endif

# imb-burst modules
SOURCES := main.c
OBJECTS := $(SOURCES:%.c=%.o)

ifeq ($(DEBUG),y)
CFLAGS += -O0 -DDEBUG -g
LDFLAGS += -g
else
ifeq ($(MINGW),0)
CFLAGS += -O3
else
CFLAGS += -O2
endif
endif

ifeq ("$(shell test -e $(INSTPATH) && echo -n yes)","yes")
# library installed
CFLAGS +=
else
# library not installed
CFLAGS += -I$(LIB_DIR)
LDFLAGS += -L$(LIB_DIR)
endif

# targets come here
all: $(APP)

$(APP): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

.PHONY: clean
clean:
	-rm -f $(DEP_FILES) $(OBJECTS) $(APP)

# if target not clean then make dependencies
ifneq ($(MAKECMDGOALS),clean)
-include $(wildcard *.d)
endif
