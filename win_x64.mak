#
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
#

LIBNAME = libIPSec_MB.lib
OBJ_DIR = obj

!ifdef DEBUG
DCFLAGS = /Od /DDEBUG /Zi /Yd
DAFLAGS =
!else
DCFLAGS = /O2 /Oi
DAFLAGS = -g
!endif

CC = cl
CFLAGS = $(EXTRA_CFLAGS) $(DCFLAGS)  /I. /Iinclude \
	/nologo /Y- /W3 /WX- /Gm- /Gy /fp:precise /EHsc

LIB_TOOL = lib
LIBFLAGS = /nologo /machine:X64 /nodefaultlib

AS = nasm
AFLAGS = $(DAFLAGS) -fwin64 -Xvc -DWIN_ABI -Iinclude/ -I./ -Iavx/ -Iavx2/ -Iavx512/ -Isse/

lib_objs = \
	$(OBJ_DIR)\aes128_cbc_dec_by4_sse.obj \
	$(OBJ_DIR)\aes128_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes128_cntr_by4_sse.obj \
	$(OBJ_DIR)\aes128_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes128_ecbenc_x3.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by4_sse.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes192_cntr_by4_sse.obj \
	$(OBJ_DIR)\aes192_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by4_sse.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes256_cntr_by4_sse.obj \
	$(OBJ_DIR)\aes256_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes_cfb_128_sse.obj \
	$(OBJ_DIR)\aes_cfb_128_avx.obj \
	$(OBJ_DIR)\aes_cbc_enc_128_x4.obj \
	$(OBJ_DIR)\aes_cbc_enc_128_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_192_x4.obj \
	$(OBJ_DIR)\aes_cbc_enc_192_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_256_x4.obj \
	$(OBJ_DIR)\aes_cbc_enc_256_x8.obj \
	$(OBJ_DIR)\aes_keyexp_128.obj \
	$(OBJ_DIR)\aes_keyexp_192.obj \
	$(OBJ_DIR)\aes_keyexp_256.obj \
	$(OBJ_DIR)\aes_xcbc_mac_128_x4.obj \
	$(OBJ_DIR)\aes_xcbc_mac_128_x8.obj \
	$(OBJ_DIR)\mb_mgr_aes192_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes192_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_avx512.obj \
	$(OBJ_DIR)\md5_x4x2_avx.obj \
	$(OBJ_DIR)\md5_x4x2_sse.obj \
	$(OBJ_DIR)\md5_x8x2_avx2.obj \
	$(OBJ_DIR)\save_xmms.obj \
	$(OBJ_DIR)\sha1_mult_avx.obj \
	$(OBJ_DIR)\sha1_mult_sse.obj \
	$(OBJ_DIR)\sha1_ni_x2_sse.obj \
	$(OBJ_DIR)\sha1_one_block_avx.obj \
	$(OBJ_DIR)\sha1_one_block_sse.obj \
	$(OBJ_DIR)\sha1_x8_avx2.obj \
	$(OBJ_DIR)\sha1_x16_avx512.obj \
	$(OBJ_DIR)\sha224_one_block_avx.obj \
	$(OBJ_DIR)\sha224_one_block_sse.obj \
	$(OBJ_DIR)\sha256_oct_avx2.obj \
	$(OBJ_DIR)\sha256_one_block_avx.obj \
	$(OBJ_DIR)\sha256_one_block_sse.obj \
	$(OBJ_DIR)\sha256_ni_x2_sse.obj \
	$(OBJ_DIR)\sha384_one_block_avx.obj \
	$(OBJ_DIR)\sha384_one_block_sse.obj \
	$(OBJ_DIR)\sha512_one_block_avx.obj \
	$(OBJ_DIR)\sha512_one_block_sse.obj \
	$(OBJ_DIR)\sha512_x2_avx.obj \
	$(OBJ_DIR)\sha512_x2_sse.obj \
	$(OBJ_DIR)\sha512_x4_avx2.obj \
	$(OBJ_DIR)\sha_256_mult_avx.obj \
	$(OBJ_DIR)\sha_256_mult_sse.obj \
	$(OBJ_DIR)\aes_xcbc_expand_key.obj \
	$(OBJ_DIR)\mb_mgr_avx.obj \
	$(OBJ_DIR)\mb_mgr_avx2.obj \
	$(OBJ_DIR)\mb_mgr_avx512.obj \
	$(OBJ_DIR)\mb_mgr_sse.obj \
	$(OBJ_DIR)\md5_one_block.obj

gcm_objs = \
        $(OBJ_DIR)\gcm128_sse.obj \
	$(OBJ_DIR)\gcm128_avx_gen2.obj \
	$(OBJ_DIR)\gcm128_avx_gen4.obj \
        $(OBJ_DIR)\gcm256_sse.obj \
	$(OBJ_DIR)\gcm256_avx_gen2.obj \
	$(OBJ_DIR)\gcm256_avx_gen4.obj

!ifdef NO_GCM
all_objs = $(lib_objs)
!else
all_objs = $(lib_objs) $(gcm_objs)
!endif

all: $(LIBNAME)

$(LIBNAME): $(all_objs)
	$(LIB_TOOL) $(LIBFLAGS) /out:$@ $(all_objs)

{.\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<

{.\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{sse\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<

{sse\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{avx\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<

{avx\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{avx2\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<

{avx2\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{avx512\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<

{avx512\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{include\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

clean:
	del /q $(all_objs)
	del /q $(LIBNAME)

