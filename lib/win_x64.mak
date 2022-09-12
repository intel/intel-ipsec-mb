#
# Copyright (c) 2017-2022, Intel Corporation
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
# DEBUG_OPT=<optim level> - this option will modify the optimization level
#                           when DEBUG is used
# AESNI_EMU=y   - this option will enable AESNI emulation support"
# AESNI_EMU=n   - this option will disable AESNI emulation support (default)"
# SHARED=y  	- this option will produce shared library (DLL) (default)
# SHARED=n  	- this option will produce static library (lib)
# SAFE_DATA=y   - this option will clear memory and registers containing
# 		  sensitive information (e.g. keys, IVs)
# SAFE_PARAM=y  - this option will add extra input parameter checks
# SAFE_LOOKUP=y - this option will perform constant-time lookups depending on
# 		  sensitive data (default)
# SAFE_OPTIONS=n - this will disable all safe options( by default all safe options are enabled )

!if !defined(SHARED)
SHARED = y
!endif
!if !defined(DEBUG_OPT)
DEBUG_OPT = /Od
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
OPT = $(DEBUG_OPT)
DCFLAGS = /DDEBUG
DAFLAGS = -gcv8
DLFLAGS = /DEBUG /INCREMENTAL:NO
!else
OPT = /O2 /Oi
DCFLAGS =
DAFLAGS =
DLFLAGS = /RELEASE /DEBUG /OPT:REF /OPT:ICF /INCREMENTAL:NO
!endif

!if "$(SAFE_OPTIONS)" == "n"
SAFE_DATA = n
SAFE_PARAM = n
SAFE_LOOKUP = n
!endif

!if "$(SAFE_DATA)" != "n"
DCFLAGS = $(DCFLAGS) /DSAFE_DATA
DAFLAGS = $(DAFLAGS) -DSAFE_DATA
!endif

!if "$(SAFE_PARAM)" != "n"
DCFLAGS = $(DCFLAGS) /DSAFE_PARAM
DAFLAGS = $(DAFLAGS) -DSAFE_PARAM
!endif

!if "$(SAFE_LOOKUP)" != "n"
DCFLAGS = $(DCFLAGS) /DSAFE_LOOKUP
DAFLAGS = $(DAFLAGS) -DSAFE_LOOKUP
!endif

!if "$(AESNI_EMU)" == "y"
DCFLAGS = $(DCFLAGS) /DAESNI_EMU
DAFLAGS = $(DAFLAGS) -DAESNI_EMU
!endif

CC = cl

CFLAGS_ALL = $(EXTRA_CFLAGS) /DNO_COMPAT_IMB_API_053 /I. /Iinclude /Ino-aesni \
	/nologo /Y- /W3 /WX- /Gm- /fp:precise /EHsc /Z7

CFLAGS = $(CFLAGS_ALL) $(OPT) $(DCFLAGS)
CFLAGS_NO_SIMD = $(CFLAGS_ALL) /Od $(DCFLAGS)

LIB_TOOL = lib
LIBFLAGS = /nologo /machine:X64 /nodefaultlib

LINK_TOOL = link
LINKFLAGS = $(DLFLAGS) /nologo /machine:X64

AS = nasm
AFLAGS = $(DAFLAGS) -Werror -fwin64 -Xvc -DWIN_ABI -I.

# dependency
!ifndef DEPTOOL
DEPTOOL = ..\mkdep.bat
!endif
DEPFLAGS=/I. /Iinclude /Ino-aesni
DEPALL=lib.dep

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
SAFE_OPTIONS_MSG1="SAFE_OPTIONS not set."
SAFE_OPTIONS_MSG2="All safe options enabled."

lib_objs1 = \
	$(OBJ_DIR)\aes128_cbc_dec_by4_sse.obj \
	$(OBJ_DIR)\aes128_cbc_dec_by8_sse.obj \
	$(OBJ_DIR)\aes128_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes128_ecb_by4_sse.obj \
	$(OBJ_DIR)\aes192_ecb_by4_sse.obj \
	$(OBJ_DIR)\aes256_ecb_by4_sse.obj \
	$(OBJ_DIR)\aes128_ecb_by8_sse.obj \
	$(OBJ_DIR)\aes192_ecb_by8_sse.obj \
	$(OBJ_DIR)\aes256_ecb_by8_sse.obj \
	$(OBJ_DIR)\aes128_ecb_by8_avx.obj \
	$(OBJ_DIR)\aes192_ecb_by8_avx.obj \
	$(OBJ_DIR)\aes256_ecb_by8_avx.obj \
	$(OBJ_DIR)\aes128_ecb_vaes_avx2.obj \
	$(OBJ_DIR)\aes192_ecb_vaes_avx2.obj \
	$(OBJ_DIR)\aes256_ecb_vaes_avx2.obj \
	$(OBJ_DIR)\aes_ecb_vaes_avx512.obj \
	$(OBJ_DIR)\pon_by8_sse.obj \
	$(OBJ_DIR)\aes128_cntr_by8_sse.obj \
	$(OBJ_DIR)\pon_by8_avx.obj \
	$(OBJ_DIR)\pon_vaes_avx512.obj \
	$(OBJ_DIR)\aes128_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by8_sse.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by8_avx.obj \
	$(OBJ_DIR)\aes128_ecbenc_x3.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by4_sse.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by8_sse.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes192_cntr_by8_sse.obj \
	$(OBJ_DIR)\aes192_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by4_sse.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by8_sse.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by8_avx.obj \
	$(OBJ_DIR)\aes256_cntr_by8_sse.obj \
	$(OBJ_DIR)\aes256_cntr_by8_avx.obj \
	$(OBJ_DIR)\aes256_cntr_ccm_by8_sse.obj \
	$(OBJ_DIR)\aes256_cntr_ccm_by8_avx.obj \
	$(OBJ_DIR)\aes_cfb_sse.obj \
	$(OBJ_DIR)\aes_cfb_avx.obj \
	$(OBJ_DIR)\aes_docsis_dec_avx512.obj \
	$(OBJ_DIR)\aes_docsis_enc_avx512.obj \
	$(OBJ_DIR)\aes_docsis_dec_vaes_avx512.obj \
	$(OBJ_DIR)\aes_docsis_enc_vaes_avx512.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x4_sse.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x8_sse.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x8_avx.obj \
	$(OBJ_DIR)\aes256_cbc_mac_x4_sse.obj \
	$(OBJ_DIR)\aes256_cbc_mac_x8_sse.obj \
	$(OBJ_DIR)\aes256_cbc_mac_x8_avx.obj \
	$(OBJ_DIR)\aes128_cbc_enc_x4_sse.obj \
	$(OBJ_DIR)\aes128_cbc_enc_x8_sse.obj \
	$(OBJ_DIR)\aes128_cbc_enc_x8_avx.obj \
	$(OBJ_DIR)\aes192_cbc_enc_x4_sse.obj \
	$(OBJ_DIR)\aes192_cbc_enc_x8_sse.obj \
	$(OBJ_DIR)\aes192_cbc_enc_x8_avx.obj \
	$(OBJ_DIR)\aes256_cbc_enc_x4_sse.obj \
	$(OBJ_DIR)\aes256_cbc_enc_x8_sse.obj \
	$(OBJ_DIR)\aes256_cbc_enc_x8_avx.obj \
	$(OBJ_DIR)\aes_keyexp_128.obj \
	$(OBJ_DIR)\aes_keyexp_192.obj \
	$(OBJ_DIR)\aes_keyexp_256.obj \
	$(OBJ_DIR)\aes_cmac_subkey_gen.obj \
	$(OBJ_DIR)\aes128_xcbc_mac_x4_sse.obj \
	$(OBJ_DIR)\aes128_xcbc_mac_x8_avx.obj \
	$(OBJ_DIR)\md5_x4x2_avx.obj \
	$(OBJ_DIR)\md5_x4x2_sse.obj \
	$(OBJ_DIR)\md5_x8x2_avx2.obj \
	$(OBJ_DIR)\save_xmms.obj \
	$(OBJ_DIR)\clear_regs_mem_fns.obj \
	$(OBJ_DIR)\sha1_x4_avx.obj \
	$(OBJ_DIR)\sha1_x4_sse.obj \
	$(OBJ_DIR)\sha1_ni_x2_sse.obj \
	$(OBJ_DIR)\sha1_ni_x1_sse.obj \
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
	$(OBJ_DIR)\sha256_ni_x1_sse.obj \
	$(OBJ_DIR)\sha256_x16_avx512.obj \
	$(OBJ_DIR)\sha384_one_block_avx.obj \
	$(OBJ_DIR)\sha384_one_block_sse.obj \
	$(OBJ_DIR)\sha512_one_block_avx.obj \
	$(OBJ_DIR)\sha512_one_block_sse.obj \
	$(OBJ_DIR)\sha512_x2_avx.obj \
	$(OBJ_DIR)\sha512_x2_sse.obj \
	$(OBJ_DIR)\sha512_x4_avx2.obj \
	$(OBJ_DIR)\sha512_x8_avx512.obj \
	$(OBJ_DIR)\sha256_mult_avx.obj \
	$(OBJ_DIR)\sha256_mult_sse.obj \
	$(OBJ_DIR)\kasumi_avx.obj \
	$(OBJ_DIR)\kasumi_iv.obj \
	$(OBJ_DIR)\kasumi_sse.obj \
	$(OBJ_DIR)\zuc_common.obj \
	$(OBJ_DIR)\zuc_top_sse.obj \
	$(OBJ_DIR)\zuc_top_avx.obj \
	$(OBJ_DIR)\zuc_top_avx2.obj \
	$(OBJ_DIR)\zuc_top_avx512.obj \
	$(OBJ_DIR)\zuc_x4_sse.obj \
	$(OBJ_DIR)\zuc_x4_gfni_sse.obj \
	$(OBJ_DIR)\zuc_x4_avx.obj \
	$(OBJ_DIR)\zuc_x8_avx2.obj \
	$(OBJ_DIR)\zuc_x16_avx512.obj \
	$(OBJ_DIR)\zuc_x16_vaes_avx512.obj \
	$(OBJ_DIR)\zuc_iv.obj \
	$(OBJ_DIR)\snow3g_sse.obj \
	$(OBJ_DIR)\snow3g_uea2_by4_sse.obj \
	$(OBJ_DIR)\snow3g_uia2_by4_sse.obj \
	$(OBJ_DIR)\snow3g_avx.obj \
	$(OBJ_DIR)\snow3g_avx2.obj \
	$(OBJ_DIR)\snow3g_avx512.obj \
	$(OBJ_DIR)\snow3g_uia2_by4_avx.obj \
	$(OBJ_DIR)\snow3g_tables.obj \
	$(OBJ_DIR)\snow3g_iv.obj \
	$(OBJ_DIR)\snow3g_uia2_by32_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_snow3g_uea2_submit_flush_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_snow3g_uia2_submit_flush_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_snow3g_uea2_submit_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_snow3g_uia2_submit_flush_x4_sse.obj \
	$(OBJ_DIR)\aes_xcbc_expand_key.obj \
	$(OBJ_DIR)\md5_one_block.obj \
	$(OBJ_DIR)\sha_sse.obj \
	$(OBJ_DIR)\sha_avx.obj \
	$(OBJ_DIR)\sha_mb_sse.obj \
	$(OBJ_DIR)\sha_ni_mb_sse.obj \
	$(OBJ_DIR)\sha_mb_avx.obj \
	$(OBJ_DIR)\sha_mb_avx2.obj \
	$(OBJ_DIR)\sha_mb_avx512.obj \
	$(OBJ_DIR)\des_key.obj \
	$(OBJ_DIR)\des_basic.obj \
	$(OBJ_DIR)\chacha20_sse.obj \
	$(OBJ_DIR)\chacha20_avx.obj \
	$(OBJ_DIR)\chacha20_avx2.obj \
	$(OBJ_DIR)\chacha20_avx512.obj \
	$(OBJ_DIR)\poly_avx512.obj \
	$(OBJ_DIR)\poly_fma_avx512.obj \
	$(OBJ_DIR)\des_x16_avx512.obj \
	$(OBJ_DIR)\aes_cntr_api_by16_vaes_avx512.obj \
	$(OBJ_DIR)\aes_cntr_bit_api_by16_vaes_avx512.obj \
	$(OBJ_DIR)\aes_cntr_ccm_api_by16_vaes_avx512.obj \
	$(OBJ_DIR)\aes_cntr_pon_api_by16_vaes_avx512.obj \
	$(OBJ_DIR)\aes_cbc_dec_by16_vaes_avx512.obj \
	$(OBJ_DIR)\aes_cbc_enc_vaes_avx512.obj \
	$(OBJ_DIR)\aes_cbcs_enc_vaes_avx512.obj \
	$(OBJ_DIR)\aes_cbcs_dec_by16_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_flush_avx512.obj \
	$(OBJ_DIR)\const.obj \
	$(OBJ_DIR)\wireless_common.obj \
	$(OBJ_DIR)\constant_lookup_fns.obj \
	$(OBJ_DIR)\crc32_refl_by8_sse.obj \
	$(OBJ_DIR)\crc32_refl_by8_avx.obj \
	$(OBJ_DIR)\ethernet_fcs_sse.obj \
	$(OBJ_DIR)\ethernet_fcs_avx.obj \
	$(OBJ_DIR)\ethernet_fcs_avx512.obj \
	$(OBJ_DIR)\crc16_x25_sse.obj \
	$(OBJ_DIR)\crc16_x25_avx.obj \
	$(OBJ_DIR)\crc16_x25_avx512.obj \
	$(OBJ_DIR)\crc32_by8_sse.obj \
	$(OBJ_DIR)\crc32_by8_avx.obj \
	$(OBJ_DIR)\crc32_sctp_sse.obj \
	$(OBJ_DIR)\crc32_sctp_avx.obj \
	$(OBJ_DIR)\crc32_sctp_avx512.obj \
	$(OBJ_DIR)\crc32_lte_sse.obj \
	$(OBJ_DIR)\crc32_lte_avx.obj \
	$(OBJ_DIR)\crc32_lte_avx512.obj \
	$(OBJ_DIR)\crc32_fp_sse.obj \
	$(OBJ_DIR)\crc32_fp_avx.obj \
	$(OBJ_DIR)\crc32_fp_avx512.obj \
	$(OBJ_DIR)\crc32_iuup_sse.obj \
	$(OBJ_DIR)\crc32_iuup_avx.obj \
	$(OBJ_DIR)\crc32_iuup_avx512.obj \
	$(OBJ_DIR)\crc32_wimax_sse.obj \
	$(OBJ_DIR)\crc32_wimax_avx.obj \
	$(OBJ_DIR)\crc32_wimax_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cmac_submit_flush_x16_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cmac_submit_flush_x16_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes128_ccm_auth_submit_flush_x16_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes256_ccm_auth_submit_flush_x16_vaes_avx512.obj \
	$(OBJ_DIR)\mb_mgr_aes128_xcbc_submit_flush_x16_vaes_avx512.obj \
	$(OBJ_DIR)\aes128_cbcs_1_9_enc_x4_sse.obj \
	$(OBJ_DIR)\aes128_cbcs_1_9_dec_by4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_flush_sse.obj \
	$(OBJ_DIR)\aes128_cbcs_1_9_enc_x8_avx.obj \
	$(OBJ_DIR)\aes128_cbcs_1_9_dec_by8_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_flush_avx.obj \
	$(OBJ_DIR)\error.obj \
	$(OBJ_DIR)\memcpy_sse.obj \
	$(OBJ_DIR)\memcpy_avx.obj \
	$(OBJ_DIR)\ooo_mgr_reset.obj \
	$(OBJ_DIR)\self_test.obj

lib_objs2 = \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_flush_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_submit_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_submit_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_flush_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_submit_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_submit_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_flush_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_submit_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_submit_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cmac_submit_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cmac_submit_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cmac_submit_flush_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cmac_submit_flush_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cmac_submit_flush_x8_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cmac_submit_flush_x8_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_ccm_auth_submit_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_ccm_auth_submit_flush_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_ccm_auth_submit_flush_x8_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes256_ccm_auth_submit_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_ccm_auth_submit_flush_x8_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes256_ccm_auth_submit_flush_x8_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_xcbc_flush_x8_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_xcbc_flush_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_aes128_xcbc_submit_x8_avx.obj \
	$(OBJ_DIR)\mb_mgr_aes128_xcbc_submit_x4_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_md5_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha224_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_flush_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha256_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha384_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha512_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_submit_avx.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_submit_avx2.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_submit_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_submit_ni_sse.obj \
	$(OBJ_DIR)\mb_mgr_hmac_sha1_submit_avx512.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_sse.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_gfni_sse.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_avx.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_avx2.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_avx512.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_gfni_avx512.obj \
	$(OBJ_DIR)\mb_mgr_avx.obj \
	$(OBJ_DIR)\mb_mgr_avx_t1.obj \
	$(OBJ_DIR)\mb_mgr_avx_t2.obj \
	$(OBJ_DIR)\mb_mgr_avx2.obj \
	$(OBJ_DIR)\mb_mgr_avx2_t1.obj \
	$(OBJ_DIR)\mb_mgr_avx2_t2.obj \
	$(OBJ_DIR)\mb_mgr_avx512.obj \
	$(OBJ_DIR)\mb_mgr_avx512_t1.obj \
	$(OBJ_DIR)\mb_mgr_avx512_t2.obj \
	$(OBJ_DIR)\mb_mgr_des_avx512.obj \
	$(OBJ_DIR)\mb_mgr_sse.obj \
	$(OBJ_DIR)\mb_mgr_sse_t1.obj \
	$(OBJ_DIR)\mb_mgr_sse_t2.obj \
	$(OBJ_DIR)\mb_mgr_sse_t3.obj \
	$(OBJ_DIR)\alloc.obj \
	$(OBJ_DIR)\version.obj \
	$(OBJ_DIR)\cpu_feature.obj \
	$(OBJ_DIR)\crc32_refl_const.obj \
	$(OBJ_DIR)\crc32_const.obj \
	$(OBJ_DIR)\crc32_refl_by16_vclmul_avx512.obj \
	$(OBJ_DIR)\crc32_by16_vclmul_avx512.obj \
	$(OBJ_DIR)\mb_mgr_auto.obj \
	$(OBJ_DIR)\poly1305.obj \
	$(OBJ_DIR)\chacha20_poly1305.obj \
	$(OBJ_DIR)\snow_v_sse.obj \
	$(OBJ_DIR)\snow_v_avx.obj

no_aesni_objs = \
	$(OBJ_DIR)\aesni_emu.obj \
	$(OBJ_DIR)\aes128_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes_cfb_sse_no_aesni.obj \
	$(OBJ_DIR)\pon_sse_no_aesni.obj \
	$(OBJ_DIR)\aes_ecb_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cntr_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cntr_ccm_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes192_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes192_cntr_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cbc_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cntr_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cntr_ccm_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbc_mac_x4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cbc_mac_x4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbc_enc_x4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes192_cbc_enc_x4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes256_cbc_enc_x4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_xcbc_mac_x4_sse_no_aesni.obj \
	$(OBJ_DIR)\ethernet_fcs_sse_no_aesni.obj \
	$(OBJ_DIR)\snow3g_sse_no_aesni.obj \
	$(OBJ_DIR)\snow3g_uia2_sse_no_aesni.obj \
	$(OBJ_DIR)\zuc_top_sse_no_aesni.obj \
	$(OBJ_DIR)\zuc_sse_no_aesni.obj \
	$(OBJ_DIR)\crc16_x25_sse_no_aesni.obj \
	$(OBJ_DIR)\crc32_refl_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\crc32_by8_sse_no_aesni.obj \
	$(OBJ_DIR)\crc32_sctp_sse_no_aesni.obj \
	$(OBJ_DIR)\crc32_lte_sse_no_aesni.obj \
	$(OBJ_DIR)\crc32_iuup_sse_no_aesni.obj \
	$(OBJ_DIR)\crc32_fp_sse_no_aesni.obj \
	$(OBJ_DIR)\crc32_wimax_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbcs_1_9_enc_x4_sse_no_aesni.obj \
	$(OBJ_DIR)\aes128_cbcs_1_9_dec_by4_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbcs_1_9_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes192_cbc_enc_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cbc_enc_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cbc_enc_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_cmac_submit_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_cmac_submit_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_ccm_auth_submit_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes256_ccm_auth_submit_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_xcbc_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_aes128_xcbc_submit_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_zuc_submit_flush_sse_no_aesni.obj \
	$(OBJ_DIR)\mb_mgr_sse_no_aesni.obj \
	$(OBJ_DIR)\snow_v_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm128_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm128_sgl_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm128_gmac_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm192_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm192_sgl_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm192_gmac_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm256_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm256_sgl_api_sse_no_aesni.obj \
	$(OBJ_DIR)\gcm256_gmac_api_sse_no_aesni.obj

gcm_objs = \
	$(OBJ_DIR)\gcm.obj \
	$(OBJ_DIR)\aes128_gcm_by8_avx.obj \
	$(OBJ_DIR)\aes128_gcm_by8_avx2.obj \
	$(OBJ_DIR)\aes128_gcm_by8_avx512.obj \
	$(OBJ_DIR)\aes128_gcm_by48_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes128_gcm_by48_sgl_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes128_gmac_by48_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes192_gcm_by8_avx.obj \
	$(OBJ_DIR)\aes192_gcm_by8_avx2.obj \
	$(OBJ_DIR)\aes192_gcm_by8_avx512.obj \
	$(OBJ_DIR)\aes192_gcm_by48_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes192_gcm_by48_sgl_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes192_gmac_by48_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes256_gcm_by8_avx.obj \
	$(OBJ_DIR)\aes256_gcm_by8_avx2.obj \
	$(OBJ_DIR)\aes256_gcm_by8_avx512.obj \
	$(OBJ_DIR)\aes256_gcm_by48_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes256_gcm_by48_sgl_api_vaes_avx512.obj \
	$(OBJ_DIR)\aes256_gmac_by48_api_vaes_avx512.obj \
	$(OBJ_DIR)\gcm128_api_by8_sse.obj \
	$(OBJ_DIR)\gcm128_sgl_api_by8_sse.obj \
	$(OBJ_DIR)\gcm128_gmac_api_by8_sse.obj \
	$(OBJ_DIR)\gcm192_api_by8_sse.obj \
	$(OBJ_DIR)\gcm192_sgl_api_by8_sse.obj \
	$(OBJ_DIR)\gcm192_gmac_api_by8_sse.obj \
	$(OBJ_DIR)\gcm256_api_by8_sse.obj \
	$(OBJ_DIR)\gcm256_sgl_api_by8_sse.obj \
	$(OBJ_DIR)\gcm256_gmac_api_by8_sse.obj

!if "$(AESNI_EMU)" == "y"
all_objs = $(lib_objs1) $(lib_objs2) $(gcm_objs) $(no_aesni_objs)
!else
all_objs = $(lib_objs1) $(lib_objs2) $(gcm_objs)
!endif

all: $(LIB_DIR)\$(LIBNAME) $(DEPALL)

$(LIB_DIR)\$(LIBNAME): $(all_objs) $(LIBBASE)_lnk.def
!if "$(SHARED)" == "y"
	$(LINK_TOOL) $(LINKFLAGS) /DLL /DEF:$(LIBBASE)_lnk.def /OUT:$@  $(all_objs)
!else
	$(LIB_TOOL) $(LIBFLAGS) /out:$@ $(all_objs)
!endif
!if "$(SAFE_PARAM)" == "n"
	@echo NOTE:  $(SAFE_PARAM_MSG1) $(SAFE_PARAM_MSG2)
!endif
!if "$(SAFE_DATA)" == "n"
	@echo NOTE:  $(SAFE_DATA_MSG1) $(SAFE_DATA_MSG2)
!endif

!if "$(SAFE_LOOKUP)" == "n"
	@echo NOTE:  $(SAFE_LOOKUP_MSG1) $(SAFE_LOOKUP_MSG2)
!endif

!if "$(SAFE_OPTIONS)" != "n"
	@echo NOTE:  $(SAFE_OPTIONS_MSG1) $(SAFE_OPTIONS_MSG2)
!endif

$(all_objs): $(OBJ_DIR) $(LIB_DIR)

$(LIBBASE)_lnk.def: $(LIBBASE).def
!if "$(AESNI_EMU)" == "y"
        copy /Y $(LIBBASE).def $(LIBBASE)_lnk.def
!else
	findstr /v _no_aesni $(LIBBASE).def > $(LIBBASE)_lnk.def
!endif

$(DEPALL): $(all_objs)
        @type $(OBJ_DIR)\*.dep > $@ 2> nul

{x86_64\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{x86_64\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{sse_t1\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{sse_t1\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{sse_t2\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{sse_t2\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{sse_t3\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{sse_t3\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{avx_t1\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{avx_t1\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{avx_t2\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{avx_t2\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{avx2_t1\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{avx2_t1\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{avx2_t2\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{avx2_t2\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{avx512_t1\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{avx512_t1\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{avx512_t2\}.c{$(OBJ_DIR)}.obj:
	$(CC) /arch:AVX /Fo$@ /c $(CFLAGS) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{avx512_t2\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

{no-aesni\}.c{$(OBJ_DIR)}.obj:
	$(CC) /Fo$@ /c $(CFLAGS_NO_SIMD) $<
        $(DEPTOOL) $< $@ "$(DEPFLAGS)" > $@.dep

{no-aesni\}.asm{$(OBJ_DIR)}.obj:
	$(AS) -MD $@.dep -o $@ $(AFLAGS) $<

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
	@echo "DEBUG_OPT=<optimization level>"
	@echo "		- this option will modify the optimization level when DEBUG is used"
	@echo "DEBUG=y   - this option will produce library fit for debugging"
	@echo "SHARED=n  - this option will produce static library"
	@echo "AESNI_EMU=y - AESNI emulation support enabled"
	@echo "AESNI_EMU=n - AESNI emulation support disabled (default)"
	@echo "OBJ_DIR=obj (default)"
	@echo "          - this option can be used to change build directory"
	@echo "LIB_DIR=. (default)"
	@echo "          - this option can be used to change the library directory"
	@echo "SAFE_DATA=n"
	@echo "          - Sensitive data not cleared from registers and memory"
	@echo "            at operation end"
	@echo "SAFE_DATA=y (default)"
	@echo "          - Sensitive data cleared from registers and memory"
	@echo "            at operation end"
	@echo "SAFE_PARAM=n"
	@echo "          - API input parameters not checked"
	@echo "SAFE_PARAM=y (default)"
	@echo "          - API input parameters checked"
	@echo "SAFE_LOOKUP=n"
	@echo "          - Lookups depending on sensitive data might not be constant time"
	@echo "SAFE_LOOKUP=y (default)"
	@echo "          - Lookups depending on sensitive data are constant time"
	@echo "SAFE_OPTIONS=n "
	@echo "          - Disable all safe options (enabled by default)"

clean:
	-del /q $(OBJ_DIR)\*.obj
	-del /q $(OBJ_DIR)\*.dep
	-del /q $(LIB_DIR)\*_lnk.def
	-del /q $(LIB_DIR)\$(LIBBASE).dll $(LIB_DIR)\$(LIBBASE).pdb $(LIB_DIR)\$(LIBBASE).lib $(LIB_DIR)\$(LIBBASE).exp $(DEPALL)

install:
	-md "$(INSTDIR)"
	-copy /Y /V /A $(LIBBASE).def "$(INSTDIR)"
	-copy /Y /V /B $(LIBBASE).exp "$(INSTDIR)"
	-copy /Y /V /B $(LIBBASE).lib "$(INSTDIR)"
	-copy /Y /V /A intel-ipsec-mb.h "$(INSTDIR)"
!if "$(SHARED)" == "y"
	-copy /Y /V /B $(LIB_DIR)\$(LIBBASE).pdb "$(INSTDIR)"
	-copy /Y /V /B $(LIB_DIR)\$(LIBBASE).dll "$(INSTDIR)"
	-copy /Y /V /B $(LIB_DIR)\$(LIBBASE).dll "%windir%\system32"
!endif

uninstall:
!if "$(SHARED)" == "y"
	-del /Q "%windir%\system32\$(LIBBASE).dll"
	-del /Q "$(INSTDIR)\$(LIBBASE).dll"
	-del /Q "$(INSTDIR)\$(LIBBASE).pdb"
!endif
	-del /Q "$(INSTDIR)\$(LIBBASE).def"
	-del /Q "$(INSTDIR)\$(LIBBASE).exp"
	-del /Q "$(INSTDIR)\$(LIBBASE).lib"
	-del /Q "$(INSTDIR)\intel-ipsec-mb.h"
	-rd "$(INSTDIR)"

!if exist($(DEPALL))
!include $(DEPALL)
!endif
