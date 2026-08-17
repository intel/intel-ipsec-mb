;;
;; Copyright (c) 2017-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;
%ifndef OS_INC_FILE
%define OS_INC_FILE

%ifndef WIN_ABI
%ifidn __OUTPUT_FORMAT__, win64
%define WIN_ABI
%endif
%endif

%ifndef LINUX
%ifidn __OUTPUT_FORMAT__, elf64
%define LINUX
%endif
%endif

%ifdef LINUX
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : function or data
;;;  - scope : internal, private, default
%define MKGLOBAL(name,type,scope) global name %+ : %+ type scope
%endif                          ; LINUX

%ifdef WIN_ABI
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : function or data
;;;  - scope : internal, private, default (ignored in win64 coff format)
%define MKGLOBAL(name,type,scope) global name
%endif                          ; WIN_ABI

;;; macro to declare sections
;;; The main uses case is to declare read-only data sections on linux & windows
%macro mksection 1+
%ifidni %1,.rodata
        ;; read-only data section recognized
%ifdef LINUX
        section .rodata
%else ; WIN_ABI
        section .rdata
%endif
%elifidni %1,stack-noexec
        ;; noexec stack marker
%ifdef LINUX
        section .note.GNU-stack noalloc noexec nowrite progbits
%endif                          ; LINUX
%else
        ;; data, bss or code/text
        section %1
%endif
%endmacro

;; Macro to reserve stack space before function call,
;; based on number of arguments
%macro RESERVE_STACK_SPACE 1
%define %%N_ARGS        %1 ; [immediate] Number of arguments

%ifdef LINUX
%if %%N_ARGS > 6
        sub     rsp, 8*(%%N_ARGS - 6)
%endif
%else ; Windows
%if %%N_ARGS <= 4
        ; Reserve 32 bytes if number of arguments is <= 4
        sub     rsp, 8*4
%else
        sub     rsp, 8*%%N_ARGS
%endif
%endif ; LINUX
%endmacro

;; Macro to restore stack pointer after function call,
;; based on number of arguments
%macro RESTORE_STACK_SPACE 1
%define %%N_ARGS        %1 ; [immediate] Number of arguments

%ifdef LINUX
%if %%N_ARGS > 6
        add     rsp, 8*(%%N_ARGS - 6)
%endif
%else ; Windows
%if %%N_ARGS <= 4
        ; Reserve 32 bytes if number of arguments is <= 4
        add     rsp, 8*4
%else
        add     rsp, 8*%%N_ARGS
%endif
%endif ; LINUX
%endmacro

%endif                          ; OS_INC_FILE
