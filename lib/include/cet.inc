;;
;; Copyright (c) 2021-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef _CET_INC_
%define _CET_INC_

%macro endbranch64 0
        ;; generate enbranch64 opcode only for Linux/FreeBSD
%ifdef LINUX
        db 0xf3, 0x0f, 0x1e, 0xfa
%endif
%endmacro

%endif ; _CET_INC_
