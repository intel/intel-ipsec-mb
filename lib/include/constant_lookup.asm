;;
;; Copyright (c) 2021, Intel Corporation
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

extern idx_rows_avx512
extern all_3fs
extern all_c0s
extern all_1s
extern all_2s
extern all_3s

%macro LOOKUP8_64_AVX512 26
%define %%INDICES       %1
%define %%RET_VALUES    %2
%define %%TABLE         %3
%define %%LOW_NIBBLE    %4
%define %%HIGH_NIBBLE   %5
%define %%ZTMP1         %6
%define %%ZTMP2         %7
%define %%ZTMP3         %8
%define %%ZTMP4         %9
%define %%ZTMP5         %10
%define %%ZTMP6         %11
%define %%ZTMP7         %12
%define %%ZTMP8         %13
%define %%ZTMP9         %14
%define %%ZTMP10        %15
%define %%ZTMP11        %16
%define %%ZTMP12        %17
%define %%ZTMP13        %18
%define %%ZTMP14        %19
%define %%ZTMP15        %20
%define %%ZTMP16        %21
%define %%ZTMP17        %22
%define %%ZTMP18        %23
%define %%ZTMP19        %24
%define %%ZTMP20        %25
%define %%ZTMP21        %26

        vmovdqa64       %%ZTMP1, [rel idx_rows_avx512 + (15 * 64)]
        vpsrlq          %%ZTMP2, %%ZTMP1, 4

        vpandq          %%HIGH_NIBBLE, %%ZTMP1, %%INDICES ;; top nibble part of the index
        vpandq          %%LOW_NIBBLE, %%ZTMP2, %%INDICES  ;; low nibble part of the index

        vpcmpb          k1,  %%HIGH_NIBBLE, [rel idx_rows_avx512 + (0 * 64)], 0
        vbroadcastf64x2 %%ZTMP1, [%%TABLE + (0 * 16)]
        vpcmpb          k2, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (1 * 64)], 0
        vbroadcastf64x2 %%ZTMP2, [%%TABLE + (1 * 16)]
        vpcmpb          k3, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (2 * 64)], 0
        vbroadcastf64x2 %%ZTMP3, [%%TABLE + (2 * 16)]
        vpcmpb          k4, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (3 * 64)], 0
        vbroadcastf64x2 %%ZTMP4, [%%TABLE + (3 * 16)]
        vpcmpb          k5, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (4 * 64)], 0
        vbroadcastf64x2 %%ZTMP5, [%%TABLE + (4 * 16)]
        vpcmpb          k6, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (5 * 64)], 0
        vbroadcastf64x2 %%ZTMP6, [%%TABLE + (5 * 16)]

        vpshufb         %%RET_VALUES{k1}{z},  %%ZTMP1, %%LOW_NIBBLE
        vpshufb         %%ZTMP7{k2}{z}, %%ZTMP2, %%LOW_NIBBLE
        vpshufb         %%ZTMP8{k3}{z}, %%ZTMP3, %%LOW_NIBBLE
        vpshufb         %%ZTMP9{k4}{z}, %%ZTMP4, %%LOW_NIBBLE
        vpshufb         %%ZTMP10{k5}{z}, %%ZTMP5, %%LOW_NIBBLE
        vpshufb         %%ZTMP11{k6}{z}, %%ZTMP6, %%LOW_NIBBLE

        vpcmpb          k1,  %%HIGH_NIBBLE, [rel idx_rows_avx512 + (6 * 64)], 0
        vbroadcastf64x2 %%ZTMP1, [%%TABLE + (6 * 16)]
        vpcmpb          k2, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (7 * 64)], 0
        vbroadcastf64x2 %%ZTMP2, [%%TABLE + (7 * 16)]
        vpcmpb          k3, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (8 * 64)], 0
        vbroadcastf64x2 %%ZTMP3, [%%TABLE + (8 * 16)]
        vpcmpb          k4, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (9 * 64)], 0
        vbroadcastf64x2 %%ZTMP4, [%%TABLE + (9 * 16)]
        vpcmpb          k5, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (10 * 64)], 0
        vbroadcastf64x2 %%ZTMP5, [%%TABLE + (10 * 16)]

        vpshufb         %%ZTMP12{k1}{z}, %%ZTMP1, %%LOW_NIBBLE
        vpshufb         %%ZTMP13{k2}{z}, %%ZTMP2, %%LOW_NIBBLE
        vpshufb         %%ZTMP14{k3}{z}, %%ZTMP3, %%LOW_NIBBLE
        vpshufb         %%ZTMP15{k4}{z}, %%ZTMP4, %%LOW_NIBBLE
        vpshufb         %%ZTMP16{k5}{z}, %%ZTMP5, %%LOW_NIBBLE

        vpcmpb          k1,  %%HIGH_NIBBLE, [rel idx_rows_avx512 + (11 * 64)], 0
        vbroadcastf64x2 zmm3, [%%TABLE + (11 * 16)]
        vpcmpb          k2, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (12 * 64)], 0
        vbroadcastf64x2 zmm4, [%%TABLE + (12 * 16)]
        vpcmpb          k3, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (13 * 64)], 0
        vbroadcastf64x2 zmm5, [%%TABLE + (13 * 16)]
        vpcmpb          k4, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (14 * 64)], 0
        vbroadcastf64x2 zmm6, [%%TABLE + (14 * 16)]
        vpcmpb          k5, %%HIGH_NIBBLE, [rel idx_rows_avx512 + (15 * 64)], 0
        vbroadcastf64x2 zmm7, [%%TABLE + (15 * 16)]

        vpshufb         %%ZTMP17{k1}{z}, %%ZTMP1, %%LOW_NIBBLE
        vpshufb         %%ZTMP18{k2}{z}, %%ZTMP2, %%LOW_NIBBLE
        vpshufb         %%ZTMP19{k3}{z}, %%ZTMP3, %%LOW_NIBBLE
        vpshufb         %%ZTMP20{k4}{z}, %%ZTMP4, %%LOW_NIBBLE
        vpshufb         %%ZTMP21{k5}{z}, %%ZTMP5, %%LOW_NIBBLE

        ; OR all registers
        vpternlogq      %%RET_VALUES, %%ZTMP7, %%ZTMP8, 0xFE
        vpternlogq      %%ZTMP9, %%ZTMP10, %%ZTMP11, 0xFE
        vpternlogq      %%ZTMP12, %%ZTMP13, %%ZTMP14, 0xFE
        vpternlogq      %%ZTMP15, %%ZTMP16, %%ZTMP17, 0xFE
        vpternlogq      %%ZTMP18, %%ZTMP19, %%ZTMP20, 0xFE

        vpternlogq      %%RET_VALUES, %%ZTMP9, %%ZTMP12, 0xFE
        vpternlogq      %%ZTMP15, %%ZTMP18, %%ZTMP21, 0xFE
        vporq           %%RET_VALUES, %%ZTMP15

%endmacro

%macro LOOKUP8_64_AVX512_VBMI 9
%define %%INDICES       %1
%define %%RET_VALUES    %2
%define %%TABLE         %3
%define %%LOW_BITS      %4
%define %%HIGH_BITS     %5
%define %%ZTMP1         %6
%define %%ZTMP2         %7
%define %%ZTMP3         %8
%define %%ZTMP4         %9

        vpandq          %%LOW_BITS, %%INDICES, [rel all_3fs] ; 6 LSB on each byte
        vpandq          %%HIGH_BITS, %%INDICES, [rel all_c0s] ; 2 MSB on each byte

        vmovdqu64       %%RET_VALUES, [%%TABLE]
        vmovdqu64       %%ZTMP1, [%%TABLE + 64]
        vmovdqu64       %%ZTMP2, [%%TABLE + 64*2]
        vmovdqu64       %%ZTMP3, [%%TABLE + 64*3]

        vpxorq          %%ZTMP4, %%ZTMP4
        vpcmpb          k1, %%HIGH_BITS, %%ZTMP4, 0
        vpcmpb          k2, %%HIGH_BITS, [rel all_1s], 0
        vpcmpb          k3, %%HIGH_BITS, [rel all_2s], 0
        vpcmpb          k4, %%HIGH_BITS, [rel all_3s], 0

        vpermb          %%RET_VALUES{k1}{z}, %%LOW_BITS, %%RET_VALUES
        vpermb          %%ZTMP1{k2}{z}, %%LOW_BITS, %%ZTMP1
        vpermb          %%ZTMP2{k3}{z}, %%LOW_BITS, %%ZTMP2
        vpermb          %%ZTMP3{k4}{z}, %%LOW_BITS, %%ZTMP3

        vpternlogq      %%ZTMP1, %%ZTMP2, %%ZTMP3, 0xFE
        vporq           %%RET_VALUES, %%ZTMP1
%endmacro
