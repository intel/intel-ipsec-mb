;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2026, Intel Corporation All rights reserved.
;
;  SPDX-License-Identifier: BSD-3-Clause
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


%ifdef LINUX
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : function or data
;;;  - scope : internal, private, default
%define MKGLOBAL(name,type,scope) global name %+ : %+ type scope
%else
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : function or data
;;;  - scope : internal, private, default (ignored in win64 coff format)
%define MKGLOBAL(name,type,scope) global name
%endif

%ifdef WIN_ABI
%define arg1 rcx
%define arg2 rdx
%else
%define arg1 rdi
%define arg2 rsi
%endif

%define GP0 r8
%define GP1 r9
%define GP2 r10

;; macro to read TSC into GP register
%macro RDTSCP 1
%define %%TSC   %1      ; GP reg to store TSC value (cannot be rax, rdx or rcx)
        rdtscp
        shl     rdx, 32
        or      rax, rdx
        mov     %%TSC, rax
%endmacro

section .text

;; uint64_t measure_tsc(const uint64_t cycles);
MKGLOBAL(measure_tsc,function,)
align 16
measure_tsc:
        ;; store arg1 (clobbered in RDTSCP on Windows)
        mov     GP0, arg1

        ;; get start ts
        RDTSCP  GP1

        ;; loop with fixed_overhead number of cycles due to
        ;; 1-cycle latency dependency on all non-ancient CPUs
        mov     rax, GP0 ; arg1 (cycles)
fixed_loop:
        dec     eax
        dec     eax
        jg      fixed_loop

        ;; get end ts
        RDTSCP  rax

        sub     rax, GP1

        ret

;; void ssc_mark4(void)
MKGLOBAL(ssc_mark4,function,)
align 16
ssc_mark4:
        push rbx
        mov  ebx, 4
        db 0x64, 0x67, 0x90, 0x90, 0x90
        pop  rbx
        ret

;; void ssc_mark5(void)
MKGLOBAL(ssc_mark5,function,)
align 16
ssc_mark5:
        push rbx
        mov  ebx, 5
        db 0x64, 0x67, 0x90, 0x90, 0x90
        pop  rbx
        ret

;; void ssc_mark6(void)
MKGLOBAL(ssc_mark6,function,)
align 16
ssc_mark6:
        push rbx
        mov  ebx, 6
        db 0x64, 0x67, 0x90, 0x90, 0x90
        pop  rbx
        ret

;; void ssc_mark7(void)
MKGLOBAL(ssc_mark7,function,)
align 16
ssc_mark7:
        push rbx
        mov  ebx, 7
        db 0x64, 0x67, 0x90, 0x90, 0x90
        pop  rbx
        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
