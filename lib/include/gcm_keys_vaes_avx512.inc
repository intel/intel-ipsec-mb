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

%ifndef GCM_KEYS_VAES_AVX512_INCLUDED
%define GCM_KEYS_VAES_AVX512_INCLUDED

;; First 15 128-bit words are reserved for AES round keys
%xdefine HKeyStart (16 * 15)

;;
;; Key structure holds up to 32 ghash keys
;;
%xdefine HashKey_32     ((16 * 0) + HKeyStart)  ; HashKey^32 <<1 mod poly
%xdefine HashKey_31     ((16 * 1) + HKeyStart)  ; HashKey^31 <<1 mod poly
%xdefine HashKey_30     ((16 * 2) + HKeyStart)  ; HashKey^30 <<1 mod poly
%xdefine HashKey_29     ((16 * 3) + HKeyStart)  ; HashKey^29 <<1 mod poly
%xdefine HashKey_28     ((16 * 4) + HKeyStart)  ; HashKey^28 <<1 mod poly
%xdefine HashKey_27     ((16 * 5) + HKeyStart)  ; HashKey^27 <<1 mod poly
%xdefine HashKey_26     ((16 * 6) + HKeyStart)  ; HashKey^26 <<1 mod poly
%xdefine HashKey_25     ((16 * 7) + HKeyStart)  ; HashKey^25 <<1 mod poly
%xdefine HashKey_24     ((16 * 8) + HKeyStart)  ; HashKey^24 <<1 mod poly
%xdefine HashKey_23     ((16 * 9) + HKeyStart)  ; HashKey^23 <<1 mod poly
%xdefine HashKey_22     ((16 * 10) + HKeyStart) ; HashKey^22 <<1 mod poly
%xdefine HashKey_21     ((16 * 11) + HKeyStart) ; HashKey^21 <<1 mod poly
%xdefine HashKey_20     ((16 * 12) + HKeyStart) ; HashKey^20 <<1 mod poly
%xdefine HashKey_19     ((16 * 13) + HKeyStart) ; HashKey^19 <<1 mod poly
%xdefine HashKey_18     ((16 * 14) + HKeyStart) ; HashKey^18 <<1 mod poly
%xdefine HashKey_17     ((16 * 15) + HKeyStart) ; HashKey^17 <<1 mod poly
%xdefine HashKey_16     ((16 * 16) + HKeyStart) ; HashKey^16 <<1 mod poly
%xdefine HashKey_15     ((16 * 17) + HKeyStart) ; HashKey^15 <<1 mod poly
%xdefine HashKey_14     ((16 * 18) + HKeyStart) ; HashKey^14 <<1 mod poly
%xdefine HashKey_13     ((16 * 19) + HKeyStart) ; HashKey^13 <<1 mod poly
%xdefine HashKey_12     ((16 * 20) + HKeyStart) ; HashKey^12 <<1 mod poly
%xdefine HashKey_11     ((16 * 21) + HKeyStart) ; HashKey^11 <<1 mod poly
%xdefine HashKey_10     ((16 * 22) + HKeyStart) ; HashKey^10 <<1 mod poly
%xdefine HashKey_9      ((16 * 23) + HKeyStart) ; HashKey^9 <<1 mod poly
%xdefine HashKey_8      ((16 * 24) + HKeyStart) ; HashKey^8 <<1 mod poly
%xdefine HashKey_7      ((16 * 25) + HKeyStart) ; HashKey^7 <<1 mod poly
%xdefine HashKey_6      ((16 * 26) + HKeyStart) ; HashKey^6 <<1 mod poly
%xdefine HashKey_5      ((16 * 27) + HKeyStart) ; HashKey^5 <<1 mod poly
%xdefine HashKey_4      ((16 * 28) + HKeyStart) ; HashKey^4 <<1 mod poly
%xdefine HashKey_3      ((16 * 29) + HKeyStart) ; HashKey^3 <<1 mod poly
%xdefine HashKey_2      ((16 * 30) + HKeyStart) ; HashKey^2 <<1 mod poly
%xdefine HashKey_1      ((16 * 31) + HKeyStart) ; HashKey <<1 mod poly

%xdefine HKeyGap (16 * 32)
;; (HashKey^n mode POLY) x POLY constants

%xdefine HashKeyK_32    (HashKey_32 + HKeyGap) ; (HashKey^32 <<1 mod poly) x POLY
%xdefine HashKeyK_31    (HashKey_31 + HKeyGap) ; (HashKey^31 <<1 mod poly) x POLY
%xdefine HashKeyK_30    (HashKey_30 + HKeyGap) ; (HashKey^30 <<1 mod poly) x POLY
%xdefine HashKeyK_29    (HashKey_29 + HKeyGap) ; (HashKey^29 <<1 mod poly) x POLY
%xdefine HashKeyK_28    (HashKey_28 + HKeyGap) ; (HashKey^28 <<1 mod poly) x POLY
%xdefine HashKeyK_27    (HashKey_27 + HKeyGap) ; (HashKey^27 <<1 mod poly) x POLY
%xdefine HashKeyK_26    (HashKey_26 + HKeyGap) ; (HashKey^26 <<1 mod poly) x POLY
%xdefine HashKeyK_25    (HashKey_25 + HKeyGap) ; (HashKey^25 <<1 mod poly) x POLY
%xdefine HashKeyK_24    (HashKey_24 + HKeyGap) ; (HashKey^24 <<1 mod poly) x POLY
%xdefine HashKeyK_23    (HashKey_23 + HKeyGap) ; (HashKey^23 <<1 mod poly) x POLY
%xdefine HashKeyK_22    (HashKey_22 + HKeyGap) ; (HashKey^22 <<1 mod poly) x POLY
%xdefine HashKeyK_21    (HashKey_21 + HKeyGap) ; (HashKey^21 <<1 mod poly) x POLY
%xdefine HashKeyK_20    (HashKey_20 + HKeyGap) ; (HashKey^20 <<1 mod poly) x POLY
%xdefine HashKeyK_19    (HashKey_19 + HKeyGap) ; (HashKey^19 <<1 mod poly) x POLY
%xdefine HashKeyK_18    (HashKey_18 + HKeyGap) ; (HashKey^18 <<1 mod poly) x POLY
%xdefine HashKeyK_17    (HashKey_17 + HKeyGap) ; (HashKey^17 <<1 mod poly) x POLY
%xdefine HashKeyK_16    (HashKey_16 + HKeyGap) ; (HashKey^16 <<1 mod poly) x POLY
%xdefine HashKeyK_15    (HashKey_15 + HKeyGap) ; (HashKey^15 <<1 mod poly) x POLY
%xdefine HashKeyK_14    (HashKey_14 + HKeyGap) ; (HashKey^14 <<1 mod poly) x POLY
%xdefine HashKeyK_13    (HashKey_13 + HKeyGap) ; (HashKey^13 <<1 mod poly) x POLY
%xdefine HashKeyK_12    (HashKey_12 + HKeyGap) ; (HashKey^12 <<1 mod poly) x POLY
%xdefine HashKeyK_11    (HashKey_11 + HKeyGap) ; (HashKey^11 <<1 mod poly) x POLY
%xdefine HashKeyK_10    (HashKey_10 + HKeyGap) ; (HashKey^10 <<1 mod poly) x POLY
%xdefine HashKeyK_9     (HashKey_9 + HKeyGap)  ; (HashKey^9 <<1 mod poly) x POLY
%xdefine HashKeyK_8     (HashKey_8 + HKeyGap)  ; (HashKey^8 <<1 mod poly) x POLY
%xdefine HashKeyK_7     (HashKey_7 + HKeyGap)  ; (HashKey^7 <<1 mod poly) x POLY
%xdefine HashKeyK_6     (HashKey_6 + HKeyGap)  ; (HashKey^6 <<1 mod poly) x POLY
%xdefine HashKeyK_5     (HashKey_5 + HKeyGap)  ; (HashKey^5 <<1 mod poly) x POLY
%xdefine HashKeyK_4     (HashKey_4 + HKeyGap)  ; (HashKey^4 <<1 mod poly) x POLY
%xdefine HashKeyK_3     (HashKey_3 + HKeyGap)  ; (HashKey^3 <<1 mod poly) x POLY
%xdefine HashKeyK_2     (HashKey_2 + HKeyGap)  ; (HashKey^2 <<1 mod poly) x POLY
%xdefine HashKeyK_1     (HashKey_1 + HKeyGap)  ; (HashKey <<1 mod poly) x POLY

%endif ; GCM_KEYS_VAES_AVX512_INCLUDED
