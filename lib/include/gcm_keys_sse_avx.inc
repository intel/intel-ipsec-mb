;;
;; Copyright (c) 2019-2024, Intel Corporation
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

%ifndef GCM_KEYS_SSE_AVX_INCLUDED
%define GCM_KEYS_SSE_AVX_INCLUDED

;; Define the fields of gcm_key_data struct:
;; uint8_t expanded_keys[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
;; uint8_t shifted_hkey_8[GCM_ENC_KEY_LEN]; // HashKey^8 <<1 mod poly
;; uint8_t shifted_hkey_7[GCM_ENC_KEY_LEN]; // HashKey^7 <<1 mod poly
;; uint8_t shifted_hkey_6[GCM_ENC_KEY_LEN]; // HashKey^6 <<1 mod poly
;; uint8_t shifted_hkey_5[GCM_ENC_KEY_LEN]; // HashKey^5 <<1 mod poly
;; uint8_t shifted_hkey_4[GCM_ENC_KEY_LEN]; // HashKey^4 <<1 mod poly
;; uint8_t shifted_hkey_3[GCM_ENC_KEY_LEN]; // HashKey^3 <<1 mod poly
;; uint8_t shifted_hkey_2[GCM_ENC_KEY_LEN]; // HashKey^2 <<1 mod poly
;; uint8_t shifted_hkey_1[GCM_ENC_KEY_LEN]; // HashKey   <<1 mod poly
;; uint8_t shifted_hkey_1_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of HashKey <<1 mod poly (Karatsuba)
;; uint8_t shifted_hkey_2_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^2 <<1 mod poly (Karatsuba)
;; uint8_t shifted_hkey_3_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^3 <<1 mod poly (Karatsuba)
;; uint8_t shifted_hkey_4_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^4 <<1 mod poly (Karatsuba)
;; uint8_t shifted_hkey_5_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^5 <<1 mod poly (Karatsuba)
;; uint8_t shifted_hkey_6_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^6 <<1 mod poly (Karatsuba)
;; uint8_t shifted_hkey_7_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^7 <<1 mod poly (Karatsuba)
;; uint8_t shifted_hkey_8_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^8 <<1 mod poly (Karatsuba)

;;
;; Key structure holds up to 8 ghash keys
;;
%define HashKey_8   (16*15)   ; HashKey^8 <<1 mod poly
%define HashKey_7   (16*16)   ; HashKey^7 <<1 mod poly
%define HashKey_6   (16*17)   ; HashKey^6 <<1 mod poly
%define HashKey_5   (16*18)   ; HashKey^5 <<1 mod poly
%define HashKey_4   (16*19)   ; HashKey^4 <<1 mod poly
%define HashKey_3   (16*20)   ; HashKey^3 <<1 mod poly
%define HashKey_2   (16*21)   ; HashKey^2 <<1 mod poly
%define HashKey_1   (16*22)   ; HashKey <<1 mod poly
%define HashKey     (16*22)   ; HashKey <<1 mod poly
;; ghash keys for Karatsuba multiply
%define HashKey_k   (16*23)   ; XOR of High 64 bits and Low 64 bits of HashKey <<1 mod poly
%define HashKey_1_k (16*23)   ; XOR of High 64 bits and Low 64 bits of HashKey <<1 mod poly
%define HashKey_2_k (16*24)   ; XOR of High 64 bits and Low 64 bits of HashKey^2 <<1 mod poly
%define HashKey_3_k (16*25)   ; XOR of High 64 bits and Low 64 bits of HashKey^3 <<1 mod poly
%define HashKey_4_k (16*26)   ; XOR of High 64 bits and Low 64 bits of HashKey^4 <<1 mod poly
%define HashKey_5_k (16*27)   ; XOR of High 64 bits and Low 64 bits of HashKey^5 <<1 mod poly
%define HashKey_6_k (16*28)   ; XOR of High 64 bits and Low 64 bits of HashKey^6 <<1 mod poly
%define HashKey_7_k (16*29)   ; XOR of High 64 bits and Low 64 bits of HashKey^7 <<1 mod poly
%define HashKey_8_k (16*30)   ; XOR of High 64 bits and Low 64 bits of HashKey^8 <<1 mod poly

%endif ; GCM_KEYS_SSE_AVX_INCLUDED
