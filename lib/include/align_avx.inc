;;
;; Copyright (c) 2025-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%use smartalign
ALIGNMODE P6

;; Common macro to be used to align functions
%define align_function align 64

;; Common macro to be used to align loops
%define align_loop align 32

;; Common macro to be used to align labels
%define align_label align 4
