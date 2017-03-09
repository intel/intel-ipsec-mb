#
# Copyright (c) 2017 Deadcafe Beef(deadcafe.beef@gmail.com)
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

IPSEC_MB_DIR := ../../PoC

MYLIB := $(IPSEC_MB_DIR)/libIPSec_MB_PoC.a

NASM := nasm
NASM_INCLUDES := $(foreach i,$(ASM_INCLUDE_DIRS),-I$i/)
NASM_FLAGS := -felf64 -Xgnu -gdwarf -DLINUX -D__linux__

CFLAGS := -g -O3 -pipe -std=gnu11
WCFLAGS := \
	-Werror -Wextra -Wall -Wbad-function-cast -Wcast-align -Wcast-qual \
	-Wmissing-declarations -Wmissing-include-dirs -Wmissing-prototypes \
	-Wnested-externs -Wpointer-arith -Wredundant-decls

#-Wpadded -Wpacked

CPPFLAGS := -DLINUX -I$(IPSEC_MB_DIR) -DDEBUG
LDFLAGS := -g
LIBS :=
APP := benchmark

SRCS := \
	benchmark.c \
	crypto_ipsec.c \
	gcm_test.c

OBJS = ${SRCS:.c=.o}
DEPENDS = .depend

.SUFFIXES:	.o .c
.PHONY:	all clean depend



all: depend $(APP)

.c.o	:	Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) $(WCFLAGS) -c $<

$(APP): $(OBJS) $(MYLIB)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJS):	Makefile

clean:
	-@ rm -f $(APP) $(OBJS) $(DEPENDS) core core.*

depend: $(SRCS) Makefile
	-@ $(CC) $(CPPFLAGS) -MM -MG $(SRCS) > $(DEPENDS)

-include $(DEPENDS)
