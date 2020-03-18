#
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
#

# Available build options:
# DEBUG=y   	- this option will produce library fit for debugging
# DEBUG=n   	- this option will produce library not fit for debugging (default)
# SHARED=y  	- this option will produce shared library (DLL) (default)
# SHARED=n  	- this option will produce static library (lib)
# SAFE_DATA=y   - this option will clear memory and registers containing
# 		  sensitive information (e.g. keys, IVs)
# SAFE_PARAM=y  - this option will add extra input parameter checks
# SAFE_LOOKUP=y - this option will perform constant-time lookups depending on
# 		  sensitive data (default)

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
!if !defined(OBJ_DIR)
OBJ_DIR = obj
!endif
!if !defined(LIB_DIR)
LIB_DIR = .\
!endif

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

!if "$(SAFE_LOOKUP)" != "n"
DCFLAGS = $(DCFLAGS) /DSAFE_LOOKUP
DAFLAGS = $(DAFLAGS) -DSAFE_LOOKUP
!endif

CC = cl
CFLAGS_ALL = $(EXTRA_CFLAGS) /I. /Iinclude /Ino-aesni \
	/nologo /Y- /W3 /WX- /Gm- /fp:precise /EHsc

CFLAGS = $(CFLAGS_ALL) $(OPT) $(DCFLAGS)
CFLAGS_NO_SIMD = $(CFLAGS_ALL) /Od $(DCFLAGS)

LIB_TOOL = lib
LIBFLAGS = /nologo /machine:X64 /nodefaultlib

LINK_TOOL = link
LINKFLAGS = $(DLFLAGS) /nologo /machine:X64

AS = nasm
AFLAGS = $(DAFLAGS) -fwin64 -Xvc -DWIN_ABI -Iinclude/ \
       -I./ -Iavx/ -Iavx2/ -Iavx512/ -Isse/

# warning messages

SAFE_PARAM_MSG1=SAFE_PARAM option not set.
SAFE_PARAM_MSG2=Input parameters will not be checked.
SAFE_DATA_MSG1=SAFE_DATA option not set.
SAFE_DATA_MSG2=Stack and registers containing sensitive information, \
		such keys or IV will not be cleared \
		at the end of function calls.
SAFE_LOOKUP_MSG1=SAFE_LOOKUP option not set.
SAFE_LOOKUP_MSG2=Lookups which depend on sensitive information \
		are not guaranteed to be done in constant time.

lib_objs1 = \
	$(OBJ_DIR)\aes128_cbc_dec_by4_sse.obj \
        $(OBJ_DIR)\aes128_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbc_dec_by8_sse.obj \
	$(OBJ_DIR)\aes128_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes_ecb_by4_sse.obj \
	$(OBJ_DIR)\aes_ecb_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes_ecb_by4_avx.obj \
	$(OBJ_DIR)\pon_sse.obj \
	$(OBJ_DIR)\pon_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cntr_by8_sse.obj \
        $(OBJ_DIR)\aes128_cntr_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\pon_avx.obj \
	$(OBJ_DIR)\aes128_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by8_sse.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by8_avx.obj \
	$(OBJ_DIR)\aes128_ecbenc_x3.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by4_sse.obj \
        $(OBJ_DIR)\aes192_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by8_sse.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes192_cntr_by8_sse.obj \
        $(OBJ_DIR)\aes192_cntr_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes192_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by4_sse.obj \
        $(OBJ_DIR)\aes256_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by8_sse.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes256_cntr_by8_sse.obj \
        $(OBJ_DIR)\aes256_cntr_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes_cfb_sse.obj \
        $(OBJ_DIR)\aes_cfb_sse_no_aesni.obj \
	$(OBJ_DIR)\aes_cfb_avx.obj \
	$(OBJ_DIR)\aes_docsis_dec_avx512.obj \
	$(OBJ_DIR)\aes_docsis_enc_avx512.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x4.obj \
        $(OBJ_DIR)\aes128_cbc_mac_x4_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x8_sse.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_128_x4.obj \
        $(OBJ_DIR)\aes_cbc_enc_128_x4_no_aesni.obj \
	$(OBJ_DIR)\aes_cbc_enc_128_x8_sse.obj \
	$(OBJ_DIR)\aes_cbc_enc_128_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_192_x4.obj \
        $(OBJ_DIR)\aes_cbc_enc_192_x4_no_aesni.obj \
	$(OBJ_DIR)\aes_cbc_enc_192_x8_sse.obj \
	$(OBJ_DIR)\aes_cbc_enc_192_x8.obj \
	$(OBJ_DIR)\aes_cbc_enc_256_x4.obj \
        $(OBJ_DIR)\aes_cbc_enc_256_x4_no_aesni.obj \
	$(OBJ_DIR)\aes_cbc_enc_256_x8_sse.obj \
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
	$(OBJ_DIR)\zuc_sse_no_aesni_top.obj \
	$(OBJ_DIR)\zuc_avx_top.obj \
	$(OBJ_DIR)\zuc_avx2_top.obj \
	$(OBJ_DIR)\zuc_avx512_top.obj \
	$(OBJ_DIR)\zuc_sse.obj \
	$(OBJ_DIR)\zuc_sse_no_aesni.obj \
	$(OBJ_DIR)\zuc_avx.obj \
	$(OBJ_DIR)\zuc_avx2.obj \
	$(OBJ_DIR)\zuc_avx512.obj \
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
        $(OBJ_DIR)\cntr_ccm_vaes_avx512.obj \
        $(OBJ_DIR)\aes_cbc_dec_vaes_avx512.obj \
        $(OBJ_DIR)\aes_cbc_enc_vaes_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes_submit_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes_flush_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes192_submit_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes192_flush_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes256_submit_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes256_flush_avx512.obj \
        $(OBJ_DIR)\const.obj \
	$(OBJ_DIR)\wireless_common.obj \
	$(OBJ_DIR)\constant_lookup.obj \
	$(OBJ_DIR)\ethernet_fcs_sse.obj \
	$(OBJ_DIR)\ethernet_fcs_avx.obj \
        $(OBJ_DIR)\ethernet_fcs_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_vaes_avx512.obj \
        $(OBJ_DIR)\mb_mgr_aes_ccm_auth_submit_flush_vaes_avx512.obj

lib_objs2 = \
	$(OBJ_DIR)\mb_mgr_aes192_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes192_flush_sse_x8.obj \
        $(OBJ_DIR)\mb_mgr_aes192_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes192_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes192_submit_sse_x8.obj \
        $(OBJ_DIR)\mb_mgr_aes192_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_flush_sse_x8.obj \
        $(OBJ_DIR)\mb_mgr_aes256_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_submit_sse_x8.obj \
        $(OBJ_DIR)\mb_mgr_aes256_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_flush_sse_x8.obj \
        $(OBJ_DIR)\mb_mgr_aes_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_submit_sse_x8.obj \
        $(OBJ_DIR)\mb_mgr_aes_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_sse_x8.obj \
        $(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_sse_no_aesni.obj \
        $(OBJ_DIR)\mb_mgr_aes_cmac_submit_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes_ccm_auth_submit_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes_ccm_auth_submit_flush_sse_x8.obj \
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
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_gfni_avx512.obj \
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

all_objs = $(lib_objs1) $(lib_objs2) $(gcm_objs)

all: $(LIB_DIR)\$(LIBNAME)

$(LIB_DIR)\$(LIBNAME): $(all_objs)
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

!if "$(SAFE_LOOKUP)" == "n"
	@echo NOTE:  $(SAFE_LOOKUP_MSG1) $(SAFE_LOOKUP_MSG2)
!endif

$(all_objs): $(OBJ_DIR) $(LIB_DIR)

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

$(LIB_DIR):
	mkdir $(LIB_DIR)

help:
	@echo "Available build options:"
	@echo "DEBUG=n (default)"
	@echo "          - this option will produce library not fit for debugging"
	@echo "SHARED=y (default)"
	@echo "          - this option will produce shared library"
	@echo "DEBUG=y   - this option will produce library fit for debugging"
	@echo "SHARED=n  - this option will produce static library"
	@echo "OBJ_DIR=obj (default)"
	@echo "          - this option can be used to change build directory"
	@echo "LIB_DIR=. (default)"
	@echo "          - this option can be used to change the library directory"
	@echo "SAFE_DATA=n (default)"
	@echo "          - Sensitive data not cleared from registers and memory"
	@echo "            at operation end"
	@echo "SAFE_DATA=y"
	@echo "          - Sensitive data cleared from registers and memory"
	@echo "            at operation end"
	@echo "SAFE_PARAM=n (default)"
	@echo "          - API input parameters not checked"
	@echo "SAFE_PARAM=y"
	@echo "          - API input parameters checked"
	@echo "SAFE_LOOKUP=n"
	@echo "          - Lookups depending on sensitive data might not be constant time"
	@echo "SAFE_LOOKUP=y (default)"
	@echo "          - Lookups depending on sensitive data are constant time"

clean:
	-del /q $(lib_objs1)
	-del /q $(lib_objs2)
	-del /q $(gcm_objs)
	-del /q $(LIB_DIR)\$(LIBBASE).dll $(LIB_DIR)\$(LIBBASE).lib $(LIB_DIR)\$(LIBBASE).exp

install:
        -md "$(INSTDIR)"
        -copy /Y /V /A $(LIBBASE).def "$(INSTDIR)"
        -copy /Y /V /B $(LIBBASE).exp "$(INSTDIR)"
        -copy /Y /V /B $(LIBBASE).lib "$(INSTDIR)"
        -copy /Y /V /A intel-ipsec-mb.h "$(INSTDIR)"
!if "$(SHARED)" == "y"
        -copy /Y /V /B $(LIB_DIR)\$(LIBBASE).dll "$(INSTDIR)"
        -copy /Y /V /B $(LIB_DIR)\$(LIBBASE).dll "%windir%\system32"
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
