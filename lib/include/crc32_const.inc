;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef crc32_const_inc_included
%define crc32_const_inc_included

;; functions
extern crc32_by8_sse
extern crc32_by8_avx
extern crc32_vclmul_avx2
extern crc32_by16_vclmul_avx512

;; structures with constants
extern crc32_sctp_const
extern crc32_lte24_a_const
extern crc32_lte24_b_const
extern crc32_fp_data_crc16_const
extern crc32_fp_header_crc11_const
extern crc32_fp_header_crc7_const
extern crc32_iuup_data_crc10_const
extern crc32_iuup_header_crc6_const
extern crc32_wimax_ofdma_data_const
extern crc32_wimax_ofdma_hcs8_const

%endif ;; crc32_const_inc_included
