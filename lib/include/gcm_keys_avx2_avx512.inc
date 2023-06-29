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

%ifndef GCM_KEYS_AVX2_AVX512_INCLUDED
%define GCM_KEYS_AVX2_AVX512_INCLUDED

;; First 15 128-bit words are reserved for AES round keys
%xdefine HKeyStart (16 * 15)

%xdefine HashKey_8      ((16 * 0) + HKeyStart)  ; HashKey^8 << 1 mod poly
%xdefine HashKey_7      ((16 * 1) + HKeyStart)  ; HashKey^7 << 1 mod poly
%xdefine HashKey_6      ((16 * 2) + HKeyStart)  ; HashKey^6 << 1 mod poly
%xdefine HashKey_5      ((16 * 3) + HKeyStart)  ; HashKey^5 << 1 mod poly
%xdefine HashKey_4      ((16 * 4) + HKeyStart)  ; HashKey^4 << 1 mod poly
%xdefine HashKey_3      ((16 * 5) + HKeyStart)  ; HashKey^3 << 1 mod poly
%xdefine HashKey_2      ((16 * 6) + HKeyStart)  ; HashKey^2 << 1 mod poly
%xdefine HashKey_1      ((16 * 7) + HKeyStart)  ; HashKey << 1 mod poly
%xdefine HashKey        HashKey_1

%xdefine HKeyGap (16 * 8)
;; (HashKey^n << 1 mod POLY) x POLY constants

%xdefine HashKeyK_8     (HashKey_8 + HKeyGap)   ; (HashKey^8 << 1 mod poly) x POLY
%xdefine HashKeyK_7     (HashKey_7 + HKeyGap)   ; (HashKey^7 << 1 mod poly) x POLY
%xdefine HashKeyK_6     (HashKey_6 + HKeyGap)   ; (HashKey^6 << 1 mod poly) x POLY
%xdefine HashKeyK_5     (HashKey_5 + HKeyGap)   ; (HashKey^5 << 1 mod poly) x POLY
%xdefine HashKeyK_4     (HashKey_4 + HKeyGap)   ; (HashKey^4 << 1 mod poly) x POLY
%xdefine HashKeyK_3     (HashKey_3 + HKeyGap)   ; (HashKey^3 << 1 mod poly) x POLY
%xdefine HashKeyK_2     (HashKey_2 + HKeyGap)   ; (HashKey^2 << 1 mod poly) x POLY
%xdefine HashKeyK_1     (HashKey_1 + HKeyGap)   ; (HashKey << 1 mod poly) x POLY
%xdefine HashKeyK       HashKey_1

%endif ; GCM_KEYS_AVX2_AVX512_INCLUDED
