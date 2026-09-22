;;
;; Copyright (c) 2019-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
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
