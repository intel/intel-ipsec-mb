;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef crc32_refl_inc_included
%define crc32_refl_inc_included

struc CRC32_REFL_CONSTANTS
crc32_const_fold_16x128b:
                resq    2       ; fold by 16 x 128-bits
crc32_const_fold_8x128b:
                resq    2       ; fold by 8 x 128-bits
crc32_const_fold_7x128b:
                resq    2       ; fold by 7 x 128-bits
crc32_const_fold_6x128b:
                resq    2       ; fold by 6 x 128-bits
crc32_const_fold_5x128b:
                resq    2       ; fold by 5 x 128-bits
crc32_const_fold_4x128b:
                resq    2       ; fold by 4 x 128-bits
crc32_const_fold_3x128b:
                resq    2       ; fold by 3 x 128-bits
crc32_const_fold_2x128b:
                resq    2       ; fold by 2 x 128-bits
crc32_const_fold_1x128b:
                resq    2       ; fold by 1 x 128-bits
crc32_const_null_padding:
                resq    2
crc32_const_fold_128b_to_64b:
                resq    2       ; 128-bits to 64-bits fold
crc32_const_reduce_64b_to_32b:
                resq    2       ; barrett reduction 64-bits to 32-bits
endstruc

%endif ;; crc32_refl_inc_included
