;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef crc32_refl_const_inc_included
%define crc32_refl_const_inc_included

;; functions
extern crc32_refl_by8_sse
extern crc32_refl_by8_avx
extern crc32_refl_vclmul_avx2
extern crc32_refl_by16_vclmul_avx512

;; structures with constants
extern crc32_ethernet_fcs_const
extern crc16_x25_ccitt_const

%endif ;; crc32_refl_const_inc_included
