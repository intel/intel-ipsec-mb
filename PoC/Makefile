#
# Copyright (c) 2017, Deadcafe.beef
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

IPSEC_MB_DIR ?= ..
OBJ_DIR = $(IPSEC_MB_DIR)/obj

LIB := libIPSec_MB_PoC.a
ORG_LIB := $(IPSEC_MB_DIR)/libIPSec_MB.a

WARN_CFLAGS = \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition

CFLAGS  = -g $(WARN_CFLAGS) -std=gnu11 -m64 -fPIE -pipe 

#OPTFLAGS = -O2 -funroll-loops -fno-builtin -march=native -finline-functions -fpredictive-commoning -ftree-loop-distribute-patterns -ftree-partial-pre -ftree-vectorize -funswitch-loops

OPTFLAGS = -O3 -march=native

# -ftree-vectorize

#CFLAGS += -mavx
#CFLAGS += -mavx2
#-mtune=core2 -mavx

CFLAGS += $(OPTFLAGS)
CPPFLAGS = -c -I. -D_GNU_SOURCE -DLINUX -DDEBUG
#-DDEBUG

LIBS =
LDFLAGS = -g

#CFLAGS += -funroll-loops -frerun-loop-opt
#CFLAGS += -fforce-addr

SRCS	=	\
	ipsec_mb_arch.c \
	ipsec_mb_job.c

ASM_OBJS =

OBJS = ${SRCS:.c=.o}
DEPENDS = .depend


.SUFFIXES:      .o .c
.PHONY: all clean depend

all	:	depend $(LIB)

.c.o	:
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

$(TARGET):	$(OBJS) $(ASM_OBJS)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

$(LIB):	$(OBJS)
	cp $(ORG_LIB) $@
	ar -rcs $@ $^

$(OBJS)	:	Makefile

clean:
	rm -f $(LIB) $(OBJS) $(TARGET) $(DEPENDS) *~

depend:	$(SRCS) Makefile
	-@ $(CC) $(CPPFLAGS) -MM -MG $(SRCS) > $(DEPENDS)

-include $(DEPENDS)
