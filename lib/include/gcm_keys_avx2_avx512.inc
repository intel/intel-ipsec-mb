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

%ifndef GCM_KEYS_AVX2_AVX512_INCLUDED
%define GCM_KEYS_AVX2_AVX512_INCLUDED

;; First 15 128-bit words are reserved for AES round keys
%xdefine HKeyStart (16 * 15)

%xdefine HashKey_8      ((16 *  0) + HKeyStart) ; HashKey^8 << 1 mod poly
%xdefine HashKeyK_8     ((16 *  1) + HKeyStart) ; (HashKey^8 << 1 mod poly) x POLY
%xdefine HashKey_7      ((16 *  2) + HKeyStart) ; HashKey^7 << 1 mod poly
%xdefine HashKeyK_7     ((16 *  3) + HKeyStart) ; (HashKey^7 << 1 mod poly) x POLY
%xdefine HashKey_6      ((16 *  4) + HKeyStart) ; HashKey^6 << 1 mod poly
%xdefine HashKeyK_6     ((16 *  5) + HKeyStart) ; (HashKey^6 << 1 mod poly) x POLY
%xdefine HashKey_5      ((16 *  6) + HKeyStart) ; HashKey^5 << 1 mod poly
%xdefine HashKeyK_5     ((16 *  7) + HKeyStart) ; (HashKey^5 << 1 mod poly) x POLY
%xdefine HashKey_4      ((16 *  8) + HKeyStart) ; HashKey^4 << 1 mod poly
%xdefine HashKeyK_4     ((16 *  9) + HKeyStart) ; (HashKey^4 << 1 mod poly) x POLY
%xdefine HashKey_3      ((16 * 10) + HKeyStart) ; HashKey^3 << 1 mod poly
%xdefine HashKeyK_3     ((16 * 11) + HKeyStart) ; (HashKey^3 << 1 mod poly) x POLY
%xdefine HashKey_2      ((16 * 12) + HKeyStart) ; HashKey^2 << 1 mod poly
%xdefine HashKeyK_2     ((16 * 13) + HKeyStart) ; (HashKey^2 << 1 mod poly) x POLY
%xdefine HashKey_1      ((16 * 14) + HKeyStart) ; HashKey << 1 mod poly
%xdefine HashKeyK_1     ((16 * 15) + HKeyStart) ; (HashKey << 1 mod poly) x POLY

%endif ; GCM_KEYS_AVX2_AVX512_INCLUDED
