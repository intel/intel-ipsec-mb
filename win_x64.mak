#
# Copyright (c) 2017-2019, Intel Corporation
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

# Available build options:
# DEBUG=y   	- this option will produce library fit for debugging
# DEBUG=n   	- this option will produce library not fit for debugging (default)
# SHARED=y  	- this option will produce shared library (DLL) (default)
# SHARED=n  	- this option will produce static library (lib)
# SAFE_DATA=y   - this option will clear memory and registers containing
# 		  sensitive information (e.g. keys, IVs)
# SAFE_PARAM=y  - this option will add extra input parameter checks
# GCM_BIG_DATA=y
#           - Better performing VAES GCM on big buffers using more ghash keys (~5% up).
#             This option results in a much bigger gcm_key structure (>2K)

!if !defined(SHARED)
SHARED = y
!endif

# Available installation options:
# PREFIX=<path> - path to install the library (c:\program files\ is default)

!if !defined(PREFIX)
PREFIX = c:\Program Files
!endif
INSTDIR = $(PREFIX)\intel-ipsec-mb

LIBBASE = libIPSec_MB
!if "$(SHARED)" == "y"
LIBNAME = $(LIBBASE).dll
!else
LIBNAME = $(LIBBASE).lib
!endif
OBJ_DIR = obj

!ifdef DEBUG
OPT = /Od
DCFLAGS = /DDEBUG /Z7
DAFLAGS = -gcv8
DLFLAGS = /DEBUG
!else
OPT = /O2 /Oi
DCFLAGS =
DAFLAGS =
DLFLAGS = /RELEASE
!endif

!if "$(SAFE_DATA)" == "y"
DCFLAGS = $(DCFLAGS) /DSAFE_DATA
DAFLAGS = $(DAFLAGS) -DSAFE_DATA
!endif

!if "$(SAFE_PARAM)" == "y"
DCFLAGS = $(DCFLAGS) /DSAFE_PARAM
DAFLAGS = $(DAFLAGS) -DSAFE_PARAM
!endif

!if "$(GCM_BIG_DATA)" == "y"
GCM_AFLAGS = -DGCM_BIG_DATA
GCM_CFLAGS = /DGCM_BIG_DATA
!else
GCM_AFLAGS =
GCM_CFLAGS =
!endif

CC = cl
CFLAGS_ALL = $(EXTRA_CFLAGS) $(GCM_CFLAGS) /I. /Iinclude /Ino-aesni \
	/nologo /Y- /W3 /WX- /Gm- /fp:precise /EHsc

CFLAGS = $(CFLAGS_ALL) $(OPT) $(DCFLAGS)
CFLAGS_NO_SIMD = $(CFLAGS_ALL) /Od $(DCFLAGS)

LIB_TOOL = lib
LIBFLAGS = /nologo /machine:X64 /nodefaultlib

LINK_TOOL = link
LINKFLAGS = $(DLFLAGS) /nologo /machine:X64

AS = nasm
AFLAGS = $(DAFLAGS) $(GCM_AFLAGS) -fwin64 -Xvc -DWIN_ABI -Iinclude/ \
       -I./ -Iavx/ -Iavx2/ -Iavx512/ -Isse/

# warning messages

SAFE_PARAM_MSG1=SAFE_PARAM option not set.
SAFE_PARAM_MSG2=Input parameters will not be checked.
SAFE_DATA_MSG1=SAFE_DATA option not set.
SAFE_DATA_MSG2=Stack and registers containing sensitive information, \
		such keys or IV will not be cleared \
		at the end of function calls.

lib_objs1 = \
	$(OBJ_DIR)\aes128_cbc_dec_by4_sse.obj \
        $(OBJ_DIR)\aes128_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes_ecb_by4_sse.obj \
	$(OBJ_DIR)\aes_ecb_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes_ecb_by4_avx.obj \
	$(OBJ_DIR)\pon_sse.obj \
	$(OBJ_DIR)\pon_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cntr_by4_sse.obj \
        $(OBJ_DIR)\aes128_cntr_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\pon_avx.obj \
	$(OBJ_DIR)\aes128_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by4_sse.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by8_avx.obj \
	$(OBJ_DIR)\aes128_ecbenc_x3.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by4_sse.obj \
        $(OBJ_DIR)\aes192_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes192_cntr_by4_sse.obj \
        $(OBJ_DIR)\aes192_cntr_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes192_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by4_sse.obj \
        $(OBJ_DIR)\aes256_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes256_cntr_by4_sse.obj \
        $(OBJ_DIR)\aes256_cntr_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes_cfb_128_sse.obj \
        $(OBJ_DIR)\aes_cfb_128_sse_no_aesni.obj \
	$(OBJ_DIR)\aes_cfb_128_avx.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x4.obj \
        $(OBJ_DIR)\aes128_cbc_mac_x4_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_128_x4.obj \
        $(OBJ_DIR)\aes_cbc_enc_128_x4_no_aesni.obj \
	$(OBJ_DIR)\aes_cbc_enc_128_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_192_x4.obj \
        $(OBJ_DIR)\aes_cbc_enc_192_x4_no_aesni.obj \
	$(OBJ_DIR)\aes_cbc_enc_192_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_256_x4.obj \
        $(OBJ_DIR)\aes_cbc_enc_256_x4_no_aesni.obj \
	$(OBJ_DIR)\aes_cbc_enc_256_x8.obj \
	$(OBJ_DIR)\aes_keyexp_128.obj \
	$(OBJ_DIR)\aes_keyexp_192.obj \
	$(OBJ_DIR)\aes_keyexp_256.obj \
	$(OBJ_DIR)\aes_cmac_subkey_gen.obj \
	$(OBJ_DIR)\aes_xcbc_mac_128_x4.obj \
        $(OBJ_DIR)\aes_xcbc_mac_128_x4_no_aesni.obj \
	$(OBJ_DIR)\aes_xcbc_mac_128_x8.obj \
	$(OBJ_DIR)\md5_x4x2_avx.obj \
	$(OBJ_DIR)\md5_x4x2_sse.obj \
	$(OBJ_DIR)\md5_x8x2_avx2.obj \
	$(OBJ_DIR)\save_xmms.obj \
	$(OBJ_DIR)\clear_regs_mem_fns.obj \
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
	$(OBJ_DIR)\sha256_x16_avx512.obj \
	$(OBJ_DIR)\sha384_one_block_avx.obj \
	$(OBJ_DIR)\sha384_one_block_sse.obj \
	$(OBJ_DIR)\sha512_one_block_avx.obj \
	$(OBJ_DIR)\sha512_one_block_sse.obj \
	$(OBJ_DIR)\sha512_x2_avx.obj \
	$(OBJ_DIR)\sha512_x2_sse.obj \
	$(OBJ_DIR)\sha512_x4_avx2.obj \
	$(OBJ_DIR)\sha512_x8_avx512.obj \
	$(OBJ_DIR)\sha_256_mult_avx.obj \
	$(OBJ_DIR)\sha_256_mult_sse.obj \
	$(OBJ_DIR)\kasumi_avx.obj \
	$(OBJ_DIR)\kasumi_iv.obj \
	$(OBJ_DIR)\kasumi_sse.obj \
	$(OBJ_DIR)\zuc_common.obj \
	$(OBJ_DIR)\zuc_sse_top.obj \
	$(OBJ_DIR)\zuc_avx_top.obj \
	$(OBJ_DIR)\zuc_sse.obj \
	$(OBJ_DIR)\zuc_avx.obj \
	$(OBJ_DIR)\zuc_iv.obj \
	$(OBJ_DIR)\snow3g_sse.obj \
	$(OBJ_DIR)\snow3g_sse_no_aesni.obj \
	$(OBJ_DIR)\snow3g_avx.obj \
	$(OBJ_DIR)\snow3g_avx2.obj \
	$(OBJ_DIR)\snow3g_tables.obj \
        $(OBJ_DIR)\snow3g_iv.obj \
	$(OBJ_DIR)\aes_xcbc_expand_key.obj \
	$(OBJ_DIR)\md5_one_block.obj \
	$(OBJ_DIR)\sha_one_block.obj \
	$(OBJ_DIR)\des_key.obj \
	$(OBJ_DIR)\des_basic.obj \
	$(OBJ_DIR)\des_x16_avx512.obj \
	$(OBJ_DIR)\cntr_vaes_avx512.obj \
        $(OBJ_DIR)\aes_cbc_dec_vaes_avx512.obj \
        $(OBJ_DIR)\aes_cbc_enc_vaes_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes_submit_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes_flush_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes192_submit_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes192_flush_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes256_submit_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes256_flush_avx512.obj \
        $(OBJ_DIR)\const.obj \
	$(OBJ_DIR)\wireless_common.obj

lib_objs2 = \
	$(OBJ_DIR)\mb_mgr_aes192_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_flush_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes192_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes192_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_submit_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes192_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_flush_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes256_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_submit_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes256_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_flush_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_submit_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_sse_no_aesni.obj \
        $(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_ccm_auth_submit_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_ccm_auth_submit_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_ccm_auth_submit_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_flush_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes_xcbc_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_xcbc_submit_sse.obj \
        $(OBJ_DIR)\mb_mgr_aes_xcbc_submit_sse_no_aesni.obj \
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
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_224_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_256_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_384_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha_512_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_avx.obj \
	$(OBJ_DIR)\mb_mgr_avx2.obj \
	$(OBJ_DIR)\mb_mgr_avx512.obj \
	$(OBJ_DIR)\mb_mgr_des_avx512.obj \
	$(OBJ_DIR)\mb_mgr_sse.obj \
	$(OBJ_DIR)\mb_mgr_sse_no_aesni.obj \
	$(OBJ_DIR)\alloc.obj \
	$(OBJ_DIR)\version.obj \
	$(OBJ_DIR)\cpu_feature.obj \
        $(OBJ_DIR)\aesni_emu.obj

gcm_objs = \
	$(OBJ_DIR)\gcm.obj \
        $(OBJ_DIR)\gcm128_sse.obj \
	$(OBJ_DIR)\gcm128_avx_gen2.obj \
	$(OBJ_DIR)\gcm128_avx_gen4.obj \
	$(OBJ_DIR)\gcm128_avx512.obj \
	$(OBJ_DIR)\gcm128_vaes_avx512.obj \
        $(OBJ_DIR)\gcm192_sse.obj \
	$(OBJ_DIR)\gcm192_avx_gen2.obj \
	$(OBJ_DIR)\gcm192_avx_gen4.obj \
	$(OBJ_DIR)\gcm192_avx512.obj \
	$(OBJ_DIR)\gcm192_vaes_avx512.obj \
        $(OBJ_DIR)\gcm256_sse.obj \
	$(OBJ_DIR)\gcm256_avx_gen2.obj \
	$(OBJ_DIR)\gcm256_avx_gen4.obj \
	$(OBJ_DIR)\gcm256_avx512.obj \
	$(OBJ_DIR)\gcm256_vaes_avx512.obj \
        $(OBJ_DIR)\gcm128_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm192_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm256_sse_no_aesni.obj

!ifdef NO_GCM
all_objs = $(lib_objs1) $(lib_objs2)
CFLAGS = $(CFLAGS) -DNO_GCM
!else
all_objs = $(lib_objs1) $(lib_objs2) $(gcm_objs)
!endif

all: $(LIBNAME)

$(LIBNAME): $(all_objs)
!if "$(SHARED)" == "y"
	$(LINK_TOOL) $(LINKFLAGS) /DLL /DEF:libIPSec_MB.def /OUT:$@  $(all_objs)
!else
	$(LIB_TOOL) $(LIBFLAGS) /out:$@ $(all_objs)
!endif
!if "$(SAFE_PARAM)" != "y"
	@echo NOTE:  $(SAFE_PARAM_MSG1) $(SAFE_PARAM_MSG2)
!endif
!if "$(SAFE_DATA)" != "y"
	@echo NOTE:  $(SAFE_DATA_MSG1) $(SAFE_DATA_MSG2)
!endif

$(all_objs): $(OBJ_DIR)

{.\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<

{.\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{sse\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<

{sse\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{avx\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<

{avx\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{avx2\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<

{avx2\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{avx512\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<

{avx512\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{no-aesni\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS_NO_SIMD) $<

{no-aesni\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

{include\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -o $@ $(AFLAGS) $<

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

help:
!message * Available build options:
!message * DEBUG=n (default)
!message *           - this option will produce library not fit for debugging
!message * SHARED=y (default)
!message *           - this option will produce shared library
!message * DEBUG=y   - this option will produce library fit for debugging
!message * SHARED=n  - this option will produce static library
!message * SAFE_DATA=n (default)
!message *           - Sensitive data not cleared from registers and memory
!message *             at operation end
!message * SAFE_DATA=y
!message *           - Sensitive data cleared from registers and memory
!message *             at operation end
!message * SAFE_PARAM=n (default)
!message *           - API input parameters not checked
!message * SAFE_PARAM=y
!message *           - API input parameters checked
!message * GCM_BIG_DATA=n (default)"
!message *   Smaller GCM key structure with good performance level (VAES)
!message *   for packet processing applications (buffers size < 2K).
!message *   8 ghash keys used on SSE, AVX, AVX2 and AVX512.
!message *   48 ghash keys used on AVX512 with VAES and VPCLMULQDQ.
!message * GCM_BIG_DATA=y
!message *   Better performing VAES GCM on big buffers using more ghash keys.
!message *   This option results in a much bigger gcm_key structure (>2K).
!message *   It only takes effect on platforms with VAES and VPCLMULQDQ.

clean:
	-del /q $(lib_objs1)
	-del /q $(lib_objs2)
	-del /q $(gcm_objs)
	-del /q $(LIBNAME).*

install:
        -md "$(INSTDIR)"
        -copy /Y /V /A $(LIBBASE).def "$(INSTDIR)"
        -copy /Y /V /B $(LIBBASE).exp "$(INSTDIR)"
        -copy /Y /V /B $(LIBBASE).lib "$(INSTDIR)"
        -copy /Y /V /A intel-ipsec-mb.h "$(INSTDIR)"
!if "$(SHARED)" == "y"
        -copy /Y /V /B $(LIBBASE).dll "$(INSTDIR)"
        -copy /Y /V /B $(LIBBASE).dll "%windir%\system32"
!endif

uninstall:
!if "$(SHARED)" == "y"
        -del /Q "%windir%\system32\$(LIBBASE).dll"
        -del /Q "$(INSTDIR)\$(LIBBASE).dll"
!endif
        -del /Q "$(INSTDIR)\$(LIBBASE).def"
        -del /Q "$(INSTDIR)\$(LIBBASE).exp"
        -del /Q "$(INSTDIR)\$(LIBBASE).lib"
        -del /Q "$(INSTDIR)\intel-ipsec-mb.h"
        -rd "$(INSTDIR)"
