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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define STS_BEING_PROCESSED	0
%define STS_COMPLETED_AES	1
%define STS_COMPLETED_HMAC	2
%define STS_COMPLETED		3
%define STS_INVALID_ARGS	4

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Define IMB_JOB structure
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START_FIELDS	; HMAC Specific Fields
;;;	name				size	align
FIELD	__auth_key_xor_ipad,		8,	8	; pointer to ipad
FIELD	__auth_key_xor_opad,		8,	8	; pointer to opad
END_FIELDS

%assign _HMAC_spec_fields_size	_FIELD_OFFSET
%assign _HMAC_spec_fields_align	_STRUCT_ALIGN

START_FIELDS	; AES XCBC Specific Fields
;;;	name				size	align
FIELD	__k1_expanded,			8,	8	; ptr to exp k1 keys
FIELD	__k2,				8,	8	; ptr to k2
FIELD	__k3,				8,	8	; ptr to k3
END_FIELDS

%assign _AES_XCBC_spec_fields_size	_FIELD_OFFSET
%assign _AES_XCBC_spec_fields_align	_STRUCT_ALIGN

START_FIELDS	; CBCMAC Specific Fields
;;;	name				size	align
FIELD	__aad,				8,	8	; pointer to AAD
FIELD	__aad_len,			8,	8	; 64-bit AAD length
END_FIELDS

%assign _CBCMAC_spec_fields_size	_FIELD_OFFSET
%assign _CBCMAC_spec_fields_align	_STRUCT_ALIGN

START_FIELDS	; AES CMAC Specific Fields
;;;	name				size	align
FIELD	__key_expanded,			8,	8	; ptr to exp keys
FIELD	__skey1,			8,	8	; ptr to subkey 1
FIELD	__skey2,			8,	8	; ptr to subkey 2
END_FIELDS

%assign _AES_CMAC_spec_fields_size	_FIELD_OFFSET
%assign _AES_CMAC_spec_fields_align	_STRUCT_ALIGN

START_FIELDS	; GCM Specific Fields
;;;	name	ggn			size	align
FIELD	__gcm_aad,			8,	8	; pointer to AAD
FIELD	__gcm_aad_len,			8,	8	; 64-bit AAD length
END_FIELDS

%assign _GCM_spec_fields_size	_FIELD_OFFSET
%assign _GCM_spec_fields_align	_STRUCT_ALIGN

START_FIELDS	; ZUC-EIA3 Specific Fields
;;;	name				size	align
FIELD	__zuc_eia3_key,			8,	8	; pointer to key
FIELD	__zuc_eia3_iv,			8,	8	; pointer to IV
END_FIELDS

%assign _ZUC_EIA3_spec_fields_size	_FIELD_OFFSET
%assign _ZUC_EIA3_spec_fields_align	_STRUCT_ALIGN


START_FIELDS	; IMB_JOB
;;;	name				size	align
FIELD	_enc_keys,			8,	8	; pointer to enc keys
FIELD	_dec_keys,			8,	8	; pointer to dec keys
FIELD	_key_len_in_bytes,		8,	8
FIELD	_src,				8,	8	; pointer to src buffer
FIELD	_dst,				8,	8	; pointer to dst buffer
FIELD	_cipher_start_src_offset_in_bytes, \
					8,	8
FIELD	_msg_len_to_cipher,	        8,	8
FIELD	_hash_start_src_offset_in_bytes,8,	8
FIELD	_msg_len_to_hash,	        8,	8
FIELD	_iv,				8,	8	; pointer to IV
FIELD	_iv_len_in_bytes,		8,	8
FIELD	_auth_tag_output,		8,	8	; pointer to hash output
FIELD	_auth_tag_output_len_in_bytes,	8,	8

UNION	_u,	_HMAC_spec_fields_size,     _HMAC_spec_fields_align, \
		_AES_XCBC_spec_fields_size, _AES_XCBC_spec_fields_align, \
		_CBCMAC_spec_fields_size, _CBCMAC_spec_fields_align, \
                _AES_CMAC_spec_fields_size, _AES_CMAC_spec_fields_align, \
                _GCM_spec_fields_size, _GCM_spec_fields_align, \
                _ZUC_EIA3_spec_fields_size, _ZUC_EIA3_spec_fields_align

FIELD	_status,			4,	4	; JOB_STS
FIELD	_cipher_mode,			4,	4	; JOB_CIPHER_MODE
FIELD	_cipher_direction,		4,	4	; JOB_CIPHER_DIRECTION
FIELD	_hash_alg,			4,	4	; JOB_HASH_ALG
FIELD	_chain_order,			4,	4	; JOB_CHAIN_ORDER
FIELD	_user_data,			8,	8
FIELD	_user_data2,			8,	8
END_FIELDS

%assign _msg_len_to_cipher_in_bytes _msg_len_to_cipher
%assign _msg_len_to_cipher_in_bits  _msg_len_to_cipher
%assign _msg_len_to_hash_in_bytes   _msg_len_to_hash
%assign _msg_len_to_hash_in_bits    _msg_len_to_hash

%assign _IMB_JOB_size	_FIELD_OFFSET
%assign _IMB_JOB_align	_STRUCT_ALIGN

%assign _auth_key_xor_ipad              _u + __auth_key_xor_ipad
%assign _auth_key_xor_opad	        _u + __auth_key_xor_opad
%assign _k1_expanded		        _u + __k1_expanded
%assign _k2			        _u + __k2
%assign _k3			        _u + __k3
%assign _cbcmac_aad	                _u + __aad
%assign _cbcmac_aad_len	                _u + __aad_len
%assign _key_expanded		        _u + __key_expanded
%assign _skey1			        _u + __skey1
%assign _skey2			        _u + __skey2
%assign _gcm_aad	                _u + __gcm_aad
%assign _gcm_aad_len	                _u + __gcm_aad_len
%assign _zuc_eia3_key                   _u + __zuc_eia3_key
%assign _zuc_eia3_iv                    _u + __zuc_eia3_iv

