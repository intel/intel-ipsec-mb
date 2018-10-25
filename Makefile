#
# Copyright (c) 2012-2018, Intel Corporation
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

LIB = libIPSec_MB
SHARED ?= y
IMB_HDR = intel-ipsec-mb.h

# Detect library version
IMB_VERSION = $(shell grep -e "IMB_VERSION_STR" $(IMB_HDR) | cut -d'"' -f2)
ifeq ($(IMB_VERSION),)
$(error "Failed to detect library version!")
endif

VERSION = $(shell echo $(IMB_VERSION) | cut -d. -f1-2)
SO_VERSION = $(shell echo $(VERSION) | cut -d. -f1)

PREFIX ?= /usr
LIB_INSTALL_DIR ?= $(PREFIX)/lib
HDR_DIR ?= $(PREFIX)/include
MAN_DIR ?= $(PREFIX)/man/man7
MAN1 = libipsec-mb.7
MAN2 = libipsec-mb-dev.7
NOLDCONFIG ?= n

USE_YASM ?= n
YASM ?= yasm
NASM ?= nasm

OBJ_DIR = obj

INCLUDE_DIRS := include . no-aesni
INCLUDES := $(foreach i,$(INCLUDE_DIRS),-I $i)

CC ?= gcc

CFLAGS := -DLINUX $(EXTRA_CFLAGS) $(INCLUDES) \
	-W -Wall -Wextra -Wmissing-declarations -Wpointer-arith \
	-Wcast-qual -Wundef -Wwrite-strings  \
	-Wformat -Wformat-security \
	-Wunreachable-code -Wmissing-noreturn -Wsign-compare -Wno-endif-labels \
	-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition

ifeq ($(DEBUG),y)
CFLAGS += -g -O0 -DDEBUG
LDFLAGS += -g
else
CFLAGS += -O3 -fstack-protector -D_FORTIFY_SOURCE=2
endif

# so or static build
ifeq ($(SHARED),y)
CFLAGS += -fPIC
LIBNAME = $(LIB).so.$(VERSION)
LIBPERM = 0755
LDFLAGS += -z noexecstack -z relro -z now
else
CFLAGS += -fPIE
LIBNAME = $(LIB).a
LIBPERM = 0644
LDFLAGS += -g
endif

ASM_INCLUDE_DIRS := include . avx avx2 avx512 sse

YASM_INCLUDES := $(foreach i,$(ASM_INCLUDE_DIRS),-I $i)
YASM_FLAGS := -f x64 -f elf64 -X gnu -g dwarf2 -DLINUX -D__linux__ $(YASM_INCLUDES)

NASM_INCLUDES := $(foreach i,$(ASM_INCLUDE_DIRS),-I$i/)
NASM_FLAGS := -felf64 -Xgnu -gdwarf -DLINUX -D__linux__ $(NASM_INCLUDES)

lib_objs := \
	aes128_cbc_dec_by4_sse.o \
	aes128_cbc_dec_by4_sse_no_aesni.o \
	aes128_cbc_dec_by8_avx.o \
	aes128_cntr_by4_sse.o \
	aes128_cntr_by4_sse_no_aesni.o \
	aes128_cntr_by8_avx.o \
	aes128_ecbenc_x3.o \
	aes192_cbc_dec_by4_sse.o \
	aes192_cbc_dec_by4_sse_no_aesni.o \
	aes192_cbc_dec_by8_avx.o \
	aes192_cntr_by4_sse.o \
	aes192_cntr_by4_sse_no_aesni.o \
	aes192_cntr_by8_avx.o \
	aes256_cbc_dec_by4_sse.o \
	aes256_cbc_dec_by4_sse_no_aesni.o \
	aes256_cbc_dec_by8_avx.o \
	aes256_cntr_by4_sse.o \
	aes256_cntr_by4_sse_no_aesni.o \
	aes256_cntr_by8_avx.o \
	aes_cfb_128_sse.o \
	aes_cfb_128_avx.o \
	aes128_cbc_mac_x4.o \
	aes128_cbc_mac_x4_no_aesni.o \
	aes128_cbc_mac_x8.o \
	aes_cbc_enc_128_x4.o \
	aes_cbc_enc_128_x4_no_aesni.o \
	aes_cbc_enc_128_x8.o \
	aes_cbc_enc_192_x4.o \
	aes_cbc_enc_192_x4_no_aesni.o \
	aes_cbc_enc_192_x8.o \
	aes_cbc_enc_256_x4.o \
	aes_cbc_enc_256_x4_no_aesni.o \
	aes_cbc_enc_256_x8.o \
	aes_keyexp_128.o \
	aes_keyexp_192.o \
	aes_keyexp_256.o \
	aes_xcbc_mac_128_x4.o \
	aes_xcbc_mac_128_x4_no_aesni.o \
	aes_xcbc_mac_128_x8.o \
	aes_cmac_subkey_gen.o \
	mb_mgr_aes192_flush_avx.o \
	mb_mgr_aes192_flush_sse.o \
	mb_mgr_aes192_flush_sse_no_aesni.o \
	mb_mgr_aes192_submit_avx.o \
	mb_mgr_aes192_submit_sse.o \
	mb_mgr_aes192_submit_sse_no_aesni.o \
	mb_mgr_aes256_flush_avx.o \
	mb_mgr_aes256_flush_sse.o \
	mb_mgr_aes256_flush_sse_no_aesni.o \
	mb_mgr_aes256_submit_avx.o \
	mb_mgr_aes256_submit_sse.o \
	mb_mgr_aes256_submit_sse_no_aesni.o \
	mb_mgr_aes_flush_avx.o \
	mb_mgr_aes_flush_sse.o \
	mb_mgr_aes_flush_sse_no_aesni.o \
	mb_mgr_aes_submit_avx.o \
	mb_mgr_aes_submit_sse.o \
	mb_mgr_aes_submit_sse_no_aesni.o \
	mb_mgr_aes_cmac_submit_flush_sse.o \
	mb_mgr_aes_cmac_submit_flush_sse_no_aesni.o \
	mb_mgr_aes_cmac_submit_flush_avx.o\
	mb_mgr_aes_xcbc_flush_avx.o \
	mb_mgr_aes_xcbc_flush_sse.o \
	mb_mgr_aes_xcbc_flush_sse_no_aesni.o \
	mb_mgr_aes_xcbc_submit_avx.o \
	mb_mgr_aes_xcbc_submit_sse.o \
	mb_mgr_aes_xcbc_submit_sse_no_aesni.o \
	mb_mgr_hmac_flush_avx.o \
	mb_mgr_hmac_flush_avx2.o \
	mb_mgr_hmac_flush_sse.o \
	mb_mgr_hmac_flush_ni_sse.o \
	mb_mgr_hmac_flush_avx512.o \
	mb_mgr_hmac_md5_flush_avx.o \
	mb_mgr_hmac_md5_flush_avx2.o \
	mb_mgr_hmac_md5_flush_sse.o \
	mb_mgr_hmac_md5_submit_avx.o \
	mb_mgr_hmac_md5_submit_avx2.o \
	mb_mgr_hmac_md5_submit_sse.o \
	mb_mgr_hmac_sha_224_flush_avx.o \
	mb_mgr_hmac_sha_224_flush_avx2.o \
	mb_mgr_hmac_sha_224_flush_avx512.o \
	mb_mgr_hmac_sha_224_flush_sse.o \
	mb_mgr_hmac_sha_224_flush_ni_sse.o \
	mb_mgr_hmac_sha_224_submit_avx.o \
	mb_mgr_hmac_sha_224_submit_avx2.o \
	mb_mgr_hmac_sha_224_submit_avx512.o \
	mb_mgr_hmac_sha_224_submit_sse.o \
	mb_mgr_hmac_sha_224_submit_ni_sse.o \
	mb_mgr_hmac_sha_256_flush_avx.o \
	mb_mgr_hmac_sha_256_flush_avx2.o \
	mb_mgr_hmac_sha_256_flush_sse.o \
	mb_mgr_hmac_sha_256_flush_ni_sse.o \
	mb_mgr_hmac_sha_256_flush_avx512.o \
	mb_mgr_hmac_sha_256_submit_avx.o \
	mb_mgr_hmac_sha_256_submit_avx2.o \
	mb_mgr_hmac_sha_256_submit_sse.o \
	mb_mgr_hmac_sha_256_submit_ni_sse.o \
	mb_mgr_hmac_sha_256_submit_avx512.o \
	mb_mgr_hmac_sha_384_flush_avx.o \
	mb_mgr_hmac_sha_384_flush_avx2.o \
	mb_mgr_hmac_sha_384_flush_avx512.o \
	mb_mgr_hmac_sha_384_flush_sse.o \
	mb_mgr_hmac_sha_384_submit_avx.o \
	mb_mgr_hmac_sha_384_submit_avx2.o \
	mb_mgr_hmac_sha_384_submit_avx512.o \
	mb_mgr_hmac_sha_384_submit_sse.o \
	mb_mgr_hmac_sha_512_flush_avx.o \
	mb_mgr_hmac_sha_512_flush_avx2.o \
	mb_mgr_hmac_sha_512_flush_avx512.o \
	mb_mgr_hmac_sha_512_flush_sse.o \
	mb_mgr_hmac_sha_512_submit_avx.o \
	mb_mgr_hmac_sha_512_submit_avx2.o \
	mb_mgr_hmac_sha_512_submit_avx512.o \
	mb_mgr_hmac_sha_512_submit_sse.o \
	mb_mgr_hmac_submit_avx.o \
	mb_mgr_hmac_submit_avx2.o \
	mb_mgr_hmac_submit_sse.o \
	mb_mgr_hmac_submit_ni_sse.o \
	mb_mgr_hmac_submit_avx512.o \
	mb_mgr_des_avx512.o \
	md5_x4x2_avx.o \
	md5_x4x2_sse.o \
	md5_x8x2_avx2.o \
	save_xmms.o \
	sha1_mult_avx.o \
	sha1_mult_sse.o \
	sha1_ni_x2_sse.o \
	sha1_one_block_avx.o \
	sha1_one_block_sse.o \
	sha1_x8_avx2.o \
	sha1_x16_avx512.o \
	sha224_one_block_avx.o \
	sha224_one_block_sse.o \
	sha256_oct_avx2.o \
	sha256_one_block_avx.o \
	sha256_one_block_sse.o \
	sha256_ni_x2_sse.o \
	sha256_x16_avx512.o \
	sha384_one_block_avx.o \
	sha384_one_block_sse.o \
	sha512_one_block_avx.o \
	sha512_one_block_sse.o \
	sha512_x2_avx.o \
	sha512_x2_sse.o \
	sha512_x4_avx2.o \
	sha512_x8_avx512.o \
	sha_256_mult_avx.o \
	sha_256_mult_sse.o \
	aes_xcbc_expand_key.o \
	alloc.o \
	mb_mgr_avx.o \
	mb_mgr_avx2.o \
	mb_mgr_avx512.o \
	mb_mgr_sse.o \
	mb_mgr_sse_no_aesni.o \
	md5_one_block.o \
	sha_one_block.o \
	des_key.o \
	des_basic.o \
	des_x16_avx512.o \
	const.o \
	version.o

gcm_objs := gcm128_sse.o gcm192_sse.o gcm256_sse.o \
	gcm128_avx_gen2.o gcm192_avx_gen2.o gcm256_avx_gen2.o \
	gcm128_avx_gen4.o gcm192_avx_gen4.o gcm256_avx_gen4.o

ifeq ($(NO_GCM), y)
obj2_files := $(lib_objs:%=$(OBJ_DIR)/%)
CFLAGS += -DNO_GCM
else
obj2_files := $(lib_objs:%=$(OBJ_DIR)/%) $(gcm_objs:%=$(OBJ_DIR)/%)
endif

all: $(LIBNAME)

$(LIBNAME): $(obj2_files)
ifeq ($(SHARED),y)
	$(CC) -shared -Wl,-soname,$(LIB).so.$(SO_VERSION) -o $(LIBNAME) $^ -lc
	ln -f -s $(LIBNAME) $(LIB).so.$(SO_VERSION)
	ln -f -s $(LIB).so.$(SO_VERSION) $(LIB).so
else
	$(AR) -qcs $@ $^
endif

.PHONY: install
install: $(LIBNAME)
	install -d $(HDR_DIR)
	install -m 0644 $(IMB_HDR) $(HDR_DIR)
	install -d $(LIB_INSTALL_DIR)
	install -s -m $(LIBPERM) $(LIBNAME) $(LIB_INSTALL_DIR)
	install -d $(MAN_DIR)
	install -m 0444 $(MAN1) $(MAN_DIR)
	install -m 0444 $(MAN2) $(MAN_DIR)
ifeq ($(SHARED),y)
	cd $(LIB_INSTALL_DIR); \
		ln -f -s $(LIB).so.$(VERSION) $(LIB).so.$(SO_VERSION); \
		ln -f -s $(LIB).so.$(SO_VERSION) $(LIB).so
ifneq ($(NOLDCONFIG),y)
	ldconfig
endif
endif

.PHONY: uninstall
uninstall: $(LIBNAME)
	-rm -f $(HDR_DIR)/$(IMB_HDR)
	-rm -f $(LIB_INSTALL_DIR)/$(LIBNAME)
	-rm -f $(MAN_DIR)/$(MAN1)
	-rm -f $(MAN_DIR)/$(MAN2)
ifeq ($(SHARED),y)
	-rm -f $(LIB_INSTALL_DIR)/$(LIB).so.$(SO_VERSION)
	-rm -f $(LIB_INSTALL_DIR)/$(LIB).so
endif


$(obj2_files): | $(OBJ_DIR)

$(OBJ_DIR)/%.o:%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o:%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif

$(OBJ_DIR)/%.o:sse/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o:sse/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif

$(OBJ_DIR)/%.o:avx/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o:avx/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif

$(OBJ_DIR)/%.o:avx2/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o:avx2/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif

$(OBJ_DIR)/%.o:avx512/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o:avx512/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif

$(OBJ_DIR)/%.o:include/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif

$(OBJ_DIR)/%.o:no-aesni/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o:no-aesni/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

.PHONY: TAGS
TAGS:
	find ./ -name '*.[ch]' | etags -
	find ./ -name '*.asm'  | etags -a -
	find ./ -name '*.inc'  | etags -a -

.PHONY: clean
clean:
	rm -Rf $(obj2_files)
	rm -f $(LIB).a $(LIB).so*

SOURCES_DIRS := . sse avx avx2 avx512 include
SOURCES := $(foreach dir,$(SOURCES_DIRS),$(wildcard $(dir)/*.[ch]) $(wildcard $(dir)/*.asm) $(wildcard $(dir)/*.inc))
SOURCES_STYLE := $(foreach infile,$(SOURCES),-f $(infile))
CHECKPATCH?=checkpatch.pl
# SPACING - produces false positives with tyepdefs and *
# CONSTANT_COMPARISON - forbids defensive programming technique
# USE_FUNC - produces false positives for Windows target
# INITIALISED_STATIC, LEADING_SPACE, SPLIT_STRING, CODE_INDENT,
# PREFER_ALIGNED, UNSPECIFIED_INT, ARRAY_SIZE, GLOBAL_INITIALISERS,
# NEW_TYPEDEFS, AVOID_EXTERNS, COMPLEX_MACRO, BLOCK_COMMENT_STYLE
# - found obsolete in this project
.PHONY: style
style:
	$(CHECKPATCH) --no-tree --no-signoff --emacs --no-color \
--ignore CODE_INDENT,INITIALISED_STATIC,LEADING_SPACE,SPLIT_STRING,\
UNSPECIFIED_INT,ARRAY_SIZE,BLOCK_COMMENT_STYLE,GLOBAL_INITIALISERS,\
NEW_TYPEDEFS,AVOID_EXTERNS,COMPLEX_MACRO,PREFER_ALIGNED,USE_FUNC,\
CONSTANT_COMPARISON,SPACING $(SOURCES_STYLE)
