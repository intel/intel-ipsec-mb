;;
;; Copyright (c) 2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef GCM_CONTEXT_INC_INCLUDED
%define GCM_CONTEXT_INC_INCLUDED

;
; Authors:
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford

;;define the fields of gcm_context_data struct
;; struct gcm_context_data {
;;         // init, update and finalize context data
;;         uint8_t  aad_hash[IMB_GCM_BLOCK_LEN];
;;         uint64_t aad_length;
;;         uint64_t in_length;
;;         uint8_t  partial_block_enc_key[IMB_GCM_BLOCK_LEN];
;;         uint8_t  orig_IV[IMB_GCM_BLOCK_LEN];
;;         uint8_t  current_counter[IMB_GCM_BLOCK_LEN];
;;         uint64_t  partial_block_length;
;; };

%define AadHash         (16*0)    ; store current Hash of data which has been input
%define AadLen          (16*1)    ; store length of input data which will not be encrypted or decrypted
%define InLen           ((16*1)+8); store length of input data which will be encrypted or decrypted
%define PBlockEncKey    (16*2)    ; encryption key for the partial block at the end of the previous update
%define OrigIV          (16*3)    ; input IV
%define CurCount        (16*4)    ; Current counter for generation of encryption key
%define PBlockLen       (16*5)    ; length of partial block at the end of the previous update

%endif ; GCM_CONTEXT_INC_INCLUDED
