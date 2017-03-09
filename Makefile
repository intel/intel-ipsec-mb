#
# Copyright (c) 2012-2017, Intel Corporation
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
LIB=libIPSec_MB.a

USE_YASM ?= n
YASM ?= yasm
NASM ?= nasm

OBJ_DIR = obj

INCLUDE_DIRS := include .
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
else
CFLAGS += -O3 -fPIE -fstack-protector -D_FORTIFY_SOURCE=2
endif

ASM_INCLUDE_DIRS := include . avx avx2 avx512 sse

YASM_INCLUDES := $(foreach i,$(ASM_INCLUDE_DIRS),-I $i)
YASM_FLAGS := -f x64 -f elf64 -X gnu -g dwarf2 -DLINUX -D__linux__ $(YASM_INCLUDES)

NASM_INCLUDES := $(foreach i,$(ASM_INCLUDE_DIRS),-I$i/)
NASM_FLAGS := -felf64 -Xgnu -gdwarf -DLINUX -D__linux__ $(NASM_INCLUDES)

LDFLAGS += -g

lib_objs := \
	aes128_cbc_dec_by4_sse.o \
	aes128_cbc_dec_by8_avx.o \
	aes128_cntr_by4_sse.o \
	aes128_cntr_by8_avx.o \
	aes128_ecbenc_x3.o \
	aes192_cbc_dec_by4_sse.o \
	aes192_cbc_dec_by8_avx.o \
	aes192_cntr_by4_sse.o \
	aes192_cntr_by8_avx.o \
	aes256_cbc_dec_by4_sse.o \
	aes256_cbc_dec_by8_avx.o \
	aes256_cntr_by4_sse.o \
	aes256_cntr_by8_avx.o \
	aes_cfb_128_sse.o \
	aes_cfb_128_avx.o \
	aes_cbc_enc_128_x4.o \
	aes_cbc_enc_128_x8.o \
	aes_cbc_enc_192_x4.o \
	aes_cbc_enc_192_x8.o \
	aes_cbc_enc_256_x4.o \
	aes_cbc_enc_256_x8.o \
	aes_keyexp_128.o \
	aes_keyexp_192.o \
	aes_keyexp_256.o \
	aes_xcbc_mac_128_x4.o \
	aes_xcbc_mac_128_x8.o \
	mb_mgr_aes192_flush_avx.o \
	mb_mgr_aes192_flush_sse.o \
	mb_mgr_aes192_submit_avx.o \
	mb_mgr_aes192_submit_sse.o \
	mb_mgr_aes256_flush_avx.o \
	mb_mgr_aes256_flush_sse.o \
	mb_mgr_aes256_submit_avx.o \
	mb_mgr_aes256_submit_sse.o \
	mb_mgr_aes_flush_avx.o \
	mb_mgr_aes_flush_sse.o \
	mb_mgr_aes_submit_avx.o \
	mb_mgr_aes_submit_sse.o \
	mb_mgr_aes_xcbc_flush_avx.o \
	mb_mgr_aes_xcbc_flush_sse.o \
	mb_mgr_aes_xcbc_submit_avx.o \
	mb_mgr_aes_xcbc_submit_sse.o \
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
	mb_mgr_hmac_sha_384_flush_sse.o \
	mb_mgr_hmac_sha_384_submit_avx.o \
	mb_mgr_hmac_sha_384_submit_avx2.o \
	mb_mgr_hmac_sha_384_submit_sse.o \
	mb_mgr_hmac_sha_512_flush_avx.o \
	mb_mgr_hmac_sha_512_flush_avx2.o \
	mb_mgr_hmac_sha_512_flush_sse.o \
	mb_mgr_hmac_sha_512_submit_avx.o \
	mb_mgr_hmac_sha_512_submit_avx2.o \
	mb_mgr_hmac_sha_512_submit_sse.o \
	mb_mgr_hmac_submit_avx.o \
	mb_mgr_hmac_submit_avx2.o \
	mb_mgr_hmac_submit_sse.o \
	mb_mgr_hmac_submit_ni_sse.o \
	mb_mgr_hmac_submit_avx512.o \
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
	\
	aes_xcbc_expand_key.o \
	mb_mgr_avx.o \
	mb_mgr_avx2.o \
	mb_mgr_avx512.o \
	mb_mgr_sse.o \
	md5_one_block.o

gcm_objs := gcm128_sse.o gcm192_sse.o gcm256_sse.o \
	gcm128_avx_gen2.o gcm192_avx_gen2.o gcm256_avx_gen2.o \
	gcm128_avx_gen4.o gcm192_avx_gen4.o gcm256_avx_gen4.o

ifeq ($(NO_GCM), y)
obj2_files := $(lib_objs:%=$(OBJ_DIR)/%)
else
obj2_files := $(lib_objs:%=$(OBJ_DIR)/%) $(gcm_objs:%=$(OBJ_DIR)/%)
endif

all: $(LIB)

$(LIB): $(obj2_files)
	ar -qcs $@ $^

$(obj2_files): | $(OBJ_DIR)

$(OBJ_DIR)/%.o:%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:sse/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:sse/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:avx/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:avx/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:avx2/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:avx2/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:avx512/%.c
	@ echo "Making object file $@ "
	$(CC) -c $(CFLAGS) $< -o $@
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:avx512/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif
	@ echo "--------------------------------------------------------------"

$(OBJ_DIR)/%.o:include/%.asm
	@ echo "Making object file $@ "
ifeq ($(USE_YASM),y)
	$(YASM) $(YASM_FLAGS) $< -o $@
else
	$(NASM) -o $@ $(NASM_FLAGS) $<
endif
	@ echo "--------------------------------------------------------------"

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
	rm -Rf $(LIB)

