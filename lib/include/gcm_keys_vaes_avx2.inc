;;
;; Copyright (c) 2019-2023, Intel Corporation
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

%ifndef GCM_KEYS_AVX2_VAES_INCLUDED
%define GCM_KEYS_AVX2_VAES_INCLUDED

;; First 15 128-bit words are reserved for AES round keys
%define HashKey_16      (16*15)  ; HashKey^16 <<1 mod poly
%define HashKey_15      (16*16)  ; HashKey^15 <<1 mod poly
%define HashKey_14      (16*17)  ; HashKey^14 <<1 mod poly
%define HashKey_13      (16*18)  ; HashKey^13 <<1 mod poly
%define HashKey_12      (16*19)  ; HashKey^12 <<1 mod poly
%define HashKey_11      (16*20)  ; HashKey^11 <<1 mod poly
%define HashKey_10      (16*21)  ; HashKey^10 <<1 mod poly
%define HashKey_9       (16*22)  ; HashKey^9 <<1 mod poly
%define HashKey_8       (16*23)  ; HashKey^8 <<1 mod poly
%define HashKey_7       (16*24)  ; HashKey^7 <<1 mod poly
%define HashKey_6       (16*25)  ; HashKey^6 <<1 mod poly
%define HashKey_5       (16*26)  ; HashKey^5 <<1 mod poly
%define HashKey_4       (16*27)  ; HashKey^4 <<1 mod poly
%define HashKey_3       (16*28)  ; HashKey^3 <<1 mod poly
%define HashKey_2       (16*29)  ; HashKey^2 <<1 mod poly
%define HashKey_1       (16*30)  ; HashKey <<1 mod poly
%define HashKey         (16*30)  ; HashKey <<1 mod poly

%endif ; GCM_KEYS_AVX2_VAES_INCLUDED
