;;
;; Copyright (c) 2026, Intel Corporation
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

%ifndef _POLYVAL_VCLMUL_AVX512_INC_
%define _POLYVAL_VCLMUL_AVX512_INC_

;;
;; Key structure holds up to 8 hash keys
;;
%xdefine HashKey_8      (16 * 0) ; HashKey^8
%xdefine HashKey_7      (16 * 1) ; HashKey^7
%xdefine HashKey_6      (16 * 2) ; HashKey^6
%xdefine HashKey_5      (16 * 3) ; HashKey^5
%xdefine HashKey_4      (16 * 4) ; HashKey^4
%xdefine HashKey_3      (16 * 5) ; HashKey^3
%xdefine HashKey_2      (16 * 6) ; HashKey^2
%xdefine HashKey_1      (16 * 7) ; HashKey

%xdefine HKeyGap (8 * 16)
;; (HashKey^n mod POLY) x POLY constants

%xdefine HashKeyK_8     (HashKey_8 + HKeyGap)  ; HashKey^8 x POLY
%xdefine HashKeyK_7     (HashKey_7 + HKeyGap)  ; HashKey^7 x POLY
%xdefine HashKeyK_6     (HashKey_6 + HKeyGap)  ; HashKey^6 x POLY
%xdefine HashKeyK_5     (HashKey_5 + HKeyGap)  ; HashKey^5 x POLY
%xdefine HashKeyK_4     (HashKey_4 + HKeyGap)  ; HashKey^4 x POLY
%xdefine HashKeyK_3     (HashKey_3 + HKeyGap)  ; HashKey^3 x POLY
%xdefine HashKeyK_2     (HashKey_2 + HKeyGap)  ; HashKey^2 x POLY
%xdefine HashKeyK_1     (HashKey_1 + HKeyGap)  ; HashKey x POLY

%xdefine HKeySize (2*8*16)

;;; ===========================================================================
;;; Horizontal XOR - 4 x 128bits xored together
%macro VHPXORI4x128 2
%define %%REG   %1      ; [in/out] ZMM with 4x128bits to xor; 128bit output
%define %%TMP   %2      ; [clobbered] ZMM temporary register
        vextracti64x4   YWORD(%%TMP), %%REG, 1
        vpxorq          YWORD(%%REG), YWORD(%%REG), YWORD(%%TMP)
        vextracti32x4   XWORD(%%TMP), YWORD(%%REG), 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro               ; VHPXORI4x128

;;; ===========================================================================
;;; Horizontal XOR - 2 x 128bits xored together
%macro VHPXORI2x128 2
%define %%REG   %1      ; [in/out] YMM with 2x128bits to xor; 128bit output
%define %%TMP   %2      ; [clobbered] YMM temporary register
        vextracti32x4   XWORD(%%TMP), YWORD(%%REG), 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro               ; VHPXORI2x128

;;; ===========================================================================
;;; Schoolbook multiply of 4 blocks (4 x 16 bytes) or 8 blocks (8 x 16 bytes)
;;; - always starts POLYVAL process and performs reduction at the end
;;; - LOAD TYPE options:
;;;   - hk_load (default): load hash keys and do horizontal XOR after reduction
;;;   - hk_broadcast: broadcast hash keys and NO horizontal XOR after reduction
%macro HASH_4_OR_8 14
%define %%LOADT %1      ; [in] hash key load type: hk_load (load) or hk_bcast (broadcast)
%define %%INPTR %2      ; [in] data input pointer
%define %%HKPTR %3      ; [in] hash key pointer
%define %%HASH  %4      ; [in/out] ZMM hash value in/out
%define %%NUM_BLOCKS %5 ; [in] numerical value: 4 or 8
%define %%ZTMP0 %6      ; [clobbered] temporary ZMM
%define %%ZTMP1 %7      ; [clobbered] temporary ZMM
%define %%ZTMP2 %8      ; [clobbered] temporary ZMM
%define %%ZTMP3 %9      ; [clobbered] temporary ZMM
%define %%ZTMP4 %10     ; [clobbered] temporary ZMM
%define %%ZTMP5 %11     ; [clobbered] temporary ZMM
%define %%ZTMP6 %12     ; [clobbered] temporary ZMM
%define %%GH    %13     ; [clobbered] temporary ZMM
%define %%GL    %14     ; [clobbered] temporary ZMM

        ;; in this use case, start-hash and reduction always take place
%assign hk_broadcast 0
%assign do_hxor 1

%ifidn %%LOADT, hk_bcast
%assign hk_broadcast 1
%assign do_hxor 0
%endif

        ;; hash blocks 0-3
        vmovdqu64       %%ZTMP5, [%%INPTR]
        vpxorq          %%ZTMP5, %%ZTMP5, %%HASH

%if hk_broadcast != 0
        vbroadcasti64x2 %%ZTMP4, [%%HKPTR]
        vbroadcasti64x2 %%ZTMP6, [%%HKPTR + HKeyGap]
%else
        vmovdqu64       %%ZTMP4, [%%HKPTR]
        vmovdqu64       %%ZTMP6, [%%HKPTR + HKeyGap]
%endif
        vpclmulqdq      %%ZTMP0, %%ZTMP5, %%ZTMP6, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%ZTMP1, %%ZTMP5, %%ZTMP6, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%ZTMP2, %%ZTMP5, %%ZTMP4, 0x01 ; THL = MH*HL
        vpclmulqdq      %%ZTMP3, %%ZTMP5, %%ZTMP4, 0x11 ; THH = MH*HH

        ;; update sums
        vpxorq          %%GL, %%ZTMP0, %%ZTMP2          ; GL = THL + TLL
        vpxorq          %%GH, %%ZTMP1, %%ZTMP3          ; GH = THH + TLH

%if %%NUM_BLOCKS == 8
        ;; hash blocks 4-7
        vmovdqu64       %%ZTMP5, [%%INPTR + 64]
%if hk_broadcast != 0
        vbroadcasti64x2 %%ZTMP4, [%%HKPTR + 64]
        vbroadcasti64x2 %%ZTMP6, [%%HKPTR + HKeyGap + 64]
%else
        vmovdqu64       %%ZTMP4, [%%HKPTR + 64]
        vmovdqu64       %%ZTMP6, [%%HKPTR + HKeyGap + 64]
%endif
        vpclmulqdq      %%ZTMP0, %%ZTMP5, %%ZTMP6, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%ZTMP1, %%ZTMP5, %%ZTMP6, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%ZTMP2, %%ZTMP5, %%ZTMP4, 0x01 ; THL = MH*HL
        vpclmulqdq      %%ZTMP3, %%ZTMP5, %%ZTMP4, 0x11 ; THH = MH*HH

        ;; update sums
        vpternlogq      %%GL, %%ZTMP2, %%ZTMP0, 0x96    ; GL += THL + TLL
        vpternlogq      %%GH, %%ZTMP3, %%ZTMP1, 0x96    ; GH += THH + TLH
%endif ;; 8 blocks

        ;; new reduction
        vpclmulqdq      %%HASH, %%GL, [rel polyval_poly_avx512], 0x10
        vpshufd         %%ZTMP0, %%GL, 01001110b
        vpternlogq      %%HASH, %%GH, %%ZTMP0, 0x96
%if do_hxor != 0
        VHPXORI4x128    %%HASH, %%ZTMP0
%endif

%endmacro

;;; ===========================================================================
;;; GH = (GH * HK) mod POLY using improved (KK-augmented) reduction.
;;; KK = pclmul(HK, POLY, 0x10) ^ pshufd(HK, 0b01001110) precomputed once per HK.
;;; Works for xmm/ymm/zmm operands (lane-parallel).
;;; Requires: extern polyval_poly_avx512 (defined in polyval_api_vclmul_avx512.asm)
%macro  HASH_MUL2  7
%define %%GH  %1        ;; [in/out] xmm with multiply operand(s) (128-bits)
%define %%HK  %2        ;; [in] xmm with hash key value(s) (128-bits)
%define %%KK  %3        ;; [in] xmm with hash key K value(s) (128-bits)
%define %%TLL %4        ;; [clobbered] xmm
%define %%TLH %5        ;; [clobbered] xmm
%define %%THL %6        ;; [clobbered] xmm
%define %%THH %7        ;; [clobbered] xmm

        vpclmulqdq      %%TLL, %%GH, %%KK, 0x00     ; TLL = GH_L * KK_L
        vpclmulqdq      %%TLH, %%GH, %%KK, 0x10     ; TLH = GH_L * KK_H
        vpclmulqdq      %%THL, %%GH, %%HK, 0x01     ; THL = GH_H * HK_L
        vpclmulqdq      %%THH, %%GH, %%HK, 0x11     ; THH = GH_H * HK_H

        vpxorq          %%TLL, %%TLL, %%THL
        vpxorq          %%THH, %%THH, %%TLH

        vpclmulqdq      %%GH, %%TLL, [rel polyval_poly_avx512], 0x10
        vpshufd         %%TLH, %%TLL, 01001110b
        vpternlogq      %%GH, %%THH, %%TLH, 0x96
%endmacro

%endif ;; _POLYVAL_VCLMUL_AVX512_INC_
