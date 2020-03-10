;;
;; Copyright (c) 2012-2020, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;

%include "include/datastruct.asm"
%include "constants.asm"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define MAX_AES_JOBS		128

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define AES_ARGS and AES Out of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; AES_ARGS
;;	name		size	  align
FIELD	_aesarg_in,	8*16,	  8	; array of 16 pointers to in text
FIELD	_aesarg_out,	8*16,	  8	; array of 16 pointers to out text
FIELD	_aesarg_keys,	8*16,	  8	; array of 16 pointers to keys
FIELD	_aesarg_IV,	16*16,	  64	; array of 16 128-bit IV's
FIELD	_aesarg_key_tab,16*16*15, 64	; array of 128-bit round keys
END_FIELDS
%assign _AES_ARGS_size	_FIELD_OFFSET
%assign _AES_ARGS_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_AES_OOO
;;	name		size	align
FIELD	_aes_args,	_AES_ARGS_size, _AES_ARGS_align
FIELD	_aes_lens,      16*2,	16
FIELD	_aes_unused_lanes, 8,	8
FIELD	_aes_job_in_lane, 16*8,	8
FIELD	_aes_lanes_in_use, 8,	8
END_FIELDS
%assign _MB_MGR_AES_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_AES_OOO_align	_STRUCT_ALIGN

_aes_args_in	equ	_aes_args + _aesarg_in
_aes_args_out	equ	_aes_args + _aesarg_out
_aes_args_keys	equ	_aes_args + _aesarg_keys
_aes_args_IV	equ	_aes_args + _aesarg_IV
_aes_args_key_tab       equ     _aes_args + _aesarg_key_tab

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Build on top of AES args and AES OOO - it needs to be compatible

START_FIELDS	; MB_MGR_DOCSIS_AES_OOO
;;	name                      size            align
FIELD	_docsis_aes_args,         _AES_ARGS_size, _AES_ARGS_align
FIELD	_docsis_aes_lens,         16*2,           16
FIELD	_docsis_aes_unused_lanes, 8,              8
FIELD	_docsis_aes_job_in_lane,  16*8,	          8
FIELD	_docsis_aes_lanes_in_use, 8,              8
FIELD	_docsis_crc_init,         16*16,	  64
FIELD	_docsis_crc_len,          16*2,           16
FIELD	_docsis_crc_done,         16*1,           16
END_FIELDS
%assign _MB_MGR_DOCSIS_AES_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_DOCSIS_AES_OOO_align	_STRUCT_ALIGN

_docsis_aes_args_in      equ   _docsis_aes_args + _aesarg_in
_docsis_aes_args_out     equ   _docsis_aes_args + _aesarg_out
_docsis_aes_args_keys    equ   _docsis_aes_args + _aesarg_keys
_docsis_aes_args_IV      equ   _docsis_aes_args + _aesarg_IV
_docsis_aes_args_key_tab equ   _docsis_aes_args + _aesarg_key_tab
_docsis_crc_args_init    equ   _docsis_aes_args + _docsis_crc_init
_docsis_crc_args_len     equ   _docsis_aes_args + _docsis_crc_len
_docsis_crc_args_done    equ   _docsis_aes_args + _docsis_crc_done

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define XCBC Out of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; AES_XCBC_ARGS_X8
;;	name			size	align
FIELD	_aesxcbcarg_in,		8*8,	8	; array of 8 pointers to in text
FIELD	_aesxcbcarg_keys,	8*8,	8	; array of 8 pointers to keys
FIELD	_aesxcbcarg_ICV,	16*8,	32	; array of 8 128-bit ICV's
END_FIELDS
%assign _AES_XCBC_ARGS_X8_size	_FIELD_OFFSET
%assign _AES_XCBC_ARGS_X8_align	_STRUCT_ALIGN

START_FIELDS	; XCBC_LANE_DATA
;;;	name		size	align
FIELD	_xcbc_final_block,	2*16,	32	; final block with padding
FIELD	_xcbc_job_in_lane,	8,	8	; pointer to job object
FIELD	_xcbc_final_done,	8,	8	; offset to start of data
END_FIELDS
%assign _XCBC_LANE_DATA_size	_FIELD_OFFSET
%assign	_XCBC_LANE_DATA_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_AES_XCBC_OOO
;;	name		size	align
FIELD	_aes_xcbc_args,	_AES_XCBC_ARGS_X8_size, _AES_XCBC_ARGS_X8_align
FIELD	_aes_xcbc_lens,		16,	16
FIELD	_aes_xcbc_unused_lanes, 8,	8
FIELD	_aes_xcbc_ldata, _XCBC_LANE_DATA_size*8, _XCBC_LANE_DATA_align
END_FIELDS
%assign _MB_MGR_AES_XCBC_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_AES_XCBC_OOO_align	_STRUCT_ALIGN

_aes_xcbc_args_in	equ	_aes_xcbc_args + _aesxcbcarg_in
_aes_xcbc_args_keys	equ	_aes_xcbc_args + _aesxcbcarg_keys
_aes_xcbc_args_ICV	equ	_aes_xcbc_args + _aesxcbcarg_ICV


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define CMAC Out of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_CMAC_OOO
;;	name		size	align
FIELD	_aes_cmac_args,	_AES_ARGS_size, _AES_ARGS_align
FIELD	_aes_cmac_lens, 16*2,	32
FIELD	_aes_cmac_init_done,    16*2,	32
FIELD	_aes_cmac_unused_lanes, 8,      8
FIELD	_aes_cmac_job_in_lane,  16*8,	8
FIELD   _aes_cmac_num_lanes_inuse, 8,   8
FIELD   _aes_cmac_scratch,  16*16,   32
END_FIELDS
%assign _MB_MGR_CMAC_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_CMAC_OOO_align	_STRUCT_ALIGN

_aes_cmac_args_in	equ	_aes_cmac_args + _aesarg_in
_aes_cmac_args_keys	equ	_aes_cmac_args + _aesarg_keys
_aes_cmac_args_IV	equ	_aes_cmac_args + _aesarg_IV
_aes_cmac_args_key_tab  equ     _aes_cmac_args + _aesarg_key_tab

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define CCM Out of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_CCM_OOO
;;	name		size	align
FIELD	_aes_ccm_args,	_AES_ARGS_size, _AES_ARGS_align
FIELD	_aes_ccm_lens, 16*2,	32
FIELD	_aes_ccm_init_done,    16*2,	32
FIELD	_aes_ccm_unused_lanes, 8,      8
FIELD	_aes_ccm_job_in_lane,  16*8,	8
FIELD   _aes_ccm_num_lanes_inuse, 8,   8
FIELD   _aes_ccm_init_blocks,  16*4*16,   64
END_FIELDS
%assign _MB_MGR_CCM_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_CCM_OOO_align	_STRUCT_ALIGN

_aes_ccm_args_in	equ	_aes_ccm_args + _aesarg_in
_aes_ccm_args_keys	equ	_aes_ccm_args + _aesarg_keys
_aes_ccm_args_IV	equ	_aes_ccm_args + _aesarg_IV
_aes_ccm_args_key_tab   equ     _aes_ccm_args + _aesarg_key_tab

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define DES Out of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; DES_ARGS_X16
;;	name		size	align
FIELD	_desarg_in,	16*8,	8	; array of 16 pointers to in text
FIELD	_desarg_out,	16*8,	8	; array of 16 pointers to out text
FIELD	_desarg_keys,	16*8,	8	; array of 16 pointers to keys
FIELD	_desarg_IV,	16*8,	32	; array of 16 64-bit IV's
FIELD	_desarg_plen,	16*4,	32	; array of 16 32-bit partial lens
FIELD	_desarg_blen,	16*4,	32	; array of 16 32-bit block lens
FIELD	_desarg_lin,	16*8,	8	; array of 16 pointers to last (block) in text
FIELD	_desarg_lout,	16*8,	8	; array of 16 pointers to last (block) out text
END_FIELDS
%assign _DES_ARGS_X16_size	_FIELD_OFFSET
%assign _DES_ARGS_X16_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_DES_OOO
;;	name		size	align
FIELD	_des_args,	_DES_ARGS_X16_size, _DES_ARGS_X16_align
FIELD	_des_lens,	16*2,	16
FIELD	_des_unused_lanes, 8,	8
FIELD	_des_job_in_lane, 16*8,	8
FIELD	_des_lanes_in_use, 8,	8
END_FIELDS
%assign _MB_MGR_DES_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_DES_OOO_align	_STRUCT_ALIGN

_des_args_in	equ	_des_args + _desarg_in
_des_args_out	equ	_des_args + _desarg_out
_des_args_keys	equ	_des_args + _desarg_keys
_des_args_IV	equ	_des_args + _desarg_IV
_des_args_PLen	equ	_des_args + _desarg_plen
_des_args_BLen	equ	_des_args + _desarg_blen
_des_args_LIn	equ	_des_args + _desarg_lin
_des_args_LOut	equ	_des_args + _desarg_lout

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define ZUC Out of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; ZUC_ARGS_X16
;;	name		size	align
FIELD	_zucarg_in,	16*8,	8	; array of 16 pointers to in text
FIELD	_zucarg_out,	16*8,	8	; array of 16 pointers to out text
FIELD	_zucarg_keys,	16*8,	8	; array of 16 pointers to keys
FIELD	_zucarg_IV,	16*8,	8	; array of 16 pointers to IVs
END_FIELDS
%assign _ZUC_ARGS_X16_size	_FIELD_OFFSET
%assign _ZUC_ARGS_X16_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_ZUC_OOO
;;	name		size	align
FIELD	_zuc_args,	_ZUC_ARGS_X16_size, _ZUC_ARGS_X16_align
FIELD	_zuc_lens,	16*2,	32
FIELD	_zuc_unused_lanes, 8,	8
FIELD	_zuc_job_in_lane, 16*8,	8
FIELD	_zuc_lanes_in_use, 8,	8
END_FIELDS
%assign _MB_MGR_ZUC_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_ZUC_OOO_align	_STRUCT_ALIGN

_zuc_args_in	equ	_zuc_args + _zucarg_in
_zuc_args_out	equ	_zuc_args + _zucarg_out
_zuc_args_keys	equ	_zuc_args + _zucarg_keys
_zuc_args_IV	equ	_zuc_args + _zucarg_IV

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define HMAC Out Of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; HMAC_SHA1_LANE_DATA
;;;	name		size	align
FIELD	_extra_block,	2*64+8,	32	; final block with padding
FIELD	_job_in_lane,	8,	8	; pointer to job object
FIELD	_outer_block,	64,	1	; block containing hash
FIELD	_outer_done,	4,	4	; boolean flag
FIELD	_extra_blocks,	4,	4	; num extra blocks (1 or 2)
FIELD	_size_offset,	4,	4	; offset in extra_block to start of size
FIELD	_start_offset,	4,	4	; offset to start of data
END_FIELDS

%assign _HMAC_SHA1_LANE_DATA_size	_FIELD_OFFSET
%assign	_HMAC_SHA1_LANE_DATA_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; SHA512_LANE_DATA
;;;	name		size	align
FIELD	_extra_block_sha512,	2* SHA512_BLK_SZ + 16,	32	; final block with padding, alignment 16 to read in XMM chunks
FIELD	_outer_block_sha512,	SHA512_BLK_SZ,	        1	; block containing hash
FIELD	_job_in_lane_sha512,	8,	                8	; pointer to job object
FIELD	_outer_done_sha512,	4,	                4	; boolean flag
FIELD	_extra_blocks_sha512,	4,	                4	; num extra blocks (1 or 2)
FIELD	_size_offset_sha512,	4,	                4	; offset in extra_block to start of size
FIELD	_start_offset_sha512,	4,	                4	; offset to start of data
END_FIELDS
%assign _SHA512_LANE_DATA_size	_FIELD_OFFSET
%assign	_SHA512_LANE_DATA_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; SHA1_ARGS
;;;	name		size	                align
FIELD	_digest,	SHA1_DIGEST_SIZE,	32	; transposed digest
FIELD	_data_ptr_sha1, PTR_SZ*MAX_SHA1_LANES,	8	; array of pointers to data
END_FIELDS
%assign _SHA1_ARGS_size		_FIELD_OFFSET
%assign _SHA1_ARGS_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_HMAC_SHA_1_OOO
;;;	name		size	align
FIELD	_args,		_SHA1_ARGS_size, _SHA1_ARGS_align
FIELD	_lens,		32,	32
FIELD	_unused_lanes,	8,	8
FIELD	_ldata,		_HMAC_SHA1_LANE_DATA_size*MAX_SHA1_LANES, _HMAC_SHA1_LANE_DATA_align
FIELD   _num_lanes_inuse_sha1, 4,     4
END_FIELDS
%assign _MB_MGR_HMAC_SHA_1_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_HMAC_SHA_1_OOO_align	_STRUCT_ALIGN

_args_digest	equ	_args + _digest
_args_data_ptr	equ	_args + _data_ptr_sha1

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; SHA256_ARGS
;;;	name		        size	                        align
FIELD	_digest_sha256,	        SHA256_DIGEST_SIZE,	        32	; transposed digest
FIELD	_data_ptr_sha256,	PTR_SZ*MAX_SHA256_LANES,	8	; array of pointers to data
END_FIELDS
%assign _SHA256_ARGS_size	_FIELD_OFFSET
%assign _SHA256_ARGS_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_HMAC_SHA_256_OOO
;;;	name		size	align
FIELD	_args_sha256,		 _SHA256_ARGS_size, _SHA256_ARGS_align
FIELD	_lens_sha256,		 16*2,	16
FIELD	_unused_lanes_sha256,	 8,	8
FIELD	_ldata_sha256,		 _HMAC_SHA1_LANE_DATA_size * MAX_SHA256_LANES, _HMAC_SHA1_LANE_DATA_align
FIELD   _num_lanes_inuse_sha256, 4,     4
END_FIELDS
%assign _MB_MGR_HMAC_SHA_256_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_HMAC_SHA_256_OOO_align	_STRUCT_ALIGN

_args_digest_sha256	equ	_args_sha256 + _digest_sha256
_args_data_ptr_sha256	equ	_args_sha256 + _data_ptr_sha256

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define HMAC SHA512 Out Of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; SHA512_ARGS
;;;	name		        size	                        align
FIELD	_digest_sha512,	        SHA512_DIGEST_SIZE,	        32      ; transposed digest. 2 lanes, 8 digest words, each 8 bytes long
FIELD	_data_ptr_sha512,	MAX_SHA512_LANES * PTR_SZ,	8	; array of pointers to data
END_FIELDS
%assign _SHA512_ARGS_size	_FIELD_OFFSET
%assign _SHA512_ARGS_align	_STRUCT_ALIGN


;; ---------------------------------------
START_FIELDS	; MB_MGR_HMAC_SHA512_OOO
;;;	name	         	size             	align
FIELD	_args_sha512,		_SHA512_ARGS_size,  _SHA512_ARGS_align
FIELD	_lens_sha512,		16,	16
FIELD	_unused_lanes_sha512,	8,	                8
FIELD	_ldata_sha512,		_SHA512_LANE_DATA_size * MAX_SHA512_LANES, _SHA512_LANE_DATA_align
END_FIELDS
%assign _MB_MGR_HMAC_SHA_512_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_HMAC_SHA_512_OOO_align	_STRUCT_ALIGN

_args_digest_sha512	equ	_args_sha512 + _digest_sha512
_args_data_ptr_sha512	equ	_args_sha512 + _data_ptr_sha512



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define HMAC MD5 Out Of Order Data Structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MD5_ARGS
;;;	name		size	                align
FIELD	_digest_md5,	MD5_DIGEST_SIZE,	32	; transposed digest
FIELD	_data_ptr_md5,	MAX_MD5_LANES*PTR_SZ,	8	; array of pointers to data
END_FIELDS
%assign _MD5_ARGS_size	_FIELD_OFFSET
%assign _MD5_ARGS_align	_STRUCT_ALIGN

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; MB_MGR_HMAC_MD5_OOO
;;;	name		size	align
FIELD	_args_md5,	_MD5_ARGS_size, _MD5_ARGS_align
FIELD	_lens_md5,	MAX_MD5_LANES*2,	16
FIELD	_unused_lanes_md5, 8,	8
FIELD	_ldata_md5,	_HMAC_SHA1_LANE_DATA_size * MAX_MD5_LANES, _HMAC_SHA1_LANE_DATA_align
FIELD   _num_lanes_inuse_md5, 4,     8
END_FIELDS
%assign _MB_MGR_HMAC_MD5_OOO_size	_FIELD_OFFSET
%assign _MB_MGR_HMAC_MD5_OOO_align	_STRUCT_ALIGN

_args_digest_md5	equ	_args_md5 + _digest_md5
_args_data_ptr_md5	equ	_args_md5 + _data_ptr_md5
