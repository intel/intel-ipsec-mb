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

INSTPATH ?= /usr/include/intel-ipsec-mb.h
LIB_DIR ?= ../../lib

NASM ?= nasm

MINGW ?= $(shell $(CC) -dM -E - < /dev/null | grep -i mingw | wc -l | sed 's/^ *//')

CFLAGS = -MMD -D_GNU_SOURCE \
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
endif

ifeq ($(CC_HAS_CET),1)
CFLAGS += -fcf-protection=full
endif

ifeq ($(MINGW),0)
CFLAGS += -DLINUX
NASM_FLAGS := -Werror -felf64 -Xgnu -gdwarf -DLINUX -D__linux__
else
NASM_FLAGS := -Werror -fwin64 -Xvc -gcv8 -DWIN_ABI
endif

ifeq ($(MINGW),0)
LDFLAGS = -fPIE -z noexecstack -z relro -z now
else
LDFLAGS = -fPIE
endif

ifeq ($(CC_HAS_CET),1)
LDFLAGS += -Wl,-z,ibt -Wl,-z,shstk -Wl,-z,cet-report=error
endif
LDLIBS = -lIPSec_MB

ifeq ("$(shell test -r $(INSTPATH) && echo -n yes)","yes")
# library installed
$(info INFO: Using system installed library version.)
CFLAGS += -I../include/
else
# library not installed
CFLAGS += -I../../lib -I../include/
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

