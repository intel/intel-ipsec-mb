;;
;; Copyright (c) 2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef GCM_DATA_AVX2_INC_INCLUDED
%define GCM_DATA_AVX2_INC_INCLUDED

;
; Authors:
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford

mksection .rodata
default rel

align 16
POLY:
        dq     0x0000000000000001, 0xC200000000000000

align 16
POLY2:
        dq     0x00000001C2000000, 0xC200000000000000

align 16
SHUF_MASK:
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607

;;; @note Order of these constants should not change.
;;; More specifically, ALL_F should follow SHIFT_MASK, and ZERO should follow ALL_F
align 16
SHIFT_MASK:
        dq     0x0706050403020100, 0x0f0e0d0c0b0a0908

ALL_F:
        dq     0xffffffffffffffff, 0xffffffffffffffff

ZERO:
        dq     0x0000000000000000, 0x0000000000000000

align 16
ONE:
        dq     0x0000000000000001, 0x0000000000000000

align 16
TWO:
        dq     0x0000000000000002, 0x0000000000000000

align 16
TWOONE:
        dq     0x0000000000000001, 0x0000000100000000

align 16
ONEf:
        dq     0x0000000000000000, 0x0100000000000000

align 16
TWOf:
        dq     0x0000000000000000, 0x0200000000000000

;; NIST SP 800-38-D, section 5.2.1.1: len(M) < 2^39 - 256 [bits]
align 8
gcm_max_len:
        dq      (((1<<39) - 256) / 8) - 1

%endif ; GCM_DATA_AVX2_INC_INCLUDED
