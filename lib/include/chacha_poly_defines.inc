;;
;; Copyright (c) 2021-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef CHACHA_POLY_DEFINES_INC_INCLUDED
%define CHACHA_POLY_DEFINES_INC_INCLUDED

;;define the fields of gcm_context_data struct
;; struct chacha20_poly1305_context_data {
;;        uint64_t hash[3];
;;        uint64_t aad_len;
;;        uint64_t hash_len;
;;        uint8_t last_ks[64];
;;        uint8_t poly_key[32];
;;        uint8_t poly_scratch[16];
;;        uint64_t last_block_count;
;;        uint64_t remain_ks_bytes;
;;        uint64_t remain_ct_bytes;
;;        uint8_t IV[12];
;; };

%define Hash            (0)       ; Intermediate computation of hash value (24 bytes)
%define AadLen          (8*3)     ; Total AAD length (8 bytes)
%define HashLen         (8*4)     ; Total length to digest (excluding AAD) (8 bytes)
%define LastKs          (8*5)     ; Last 64 bytes of KS
%define PolyKey         (8*13)    ; Poly Key (32 bytes)
%define PolyScratch     (8*17)    ; Scratchpad to compute Poly on 16 bytes
%define LastBlkCount    (8*19)    ; Last block count used in last segment (8 bytes)
; Amount of bytes still to use of keystream (8 bytes)
%define RemainKsBytes   (8*20)
; Amount of ciphertext bytes still to use of previous segment to authenticate (8 bytes)
%define RemainCtBytes   (8*21)
%define IV              (8*22)

%endif ; CHACHA_POLY_DEFINES_INC_INCLUDED
