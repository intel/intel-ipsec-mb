;;
;; Copyright (c) 2023-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; function to wrap cpuid opcode across OS versions
%include "include/os.inc"
%include "include/reg_sizes.inc"

%ifdef LINUX
%define arg1            rdi
%define arg2            rsi
%define arg3            rdx
%else
%define arg1            rcx
%define arg2            rdx
%define arg3            r8
%endif

mksection .text

;;
;; Wrapper for CPUID opcode
;;
;; Parameters:
;;    [in] leaf    - CPUID leaf number (EAX)
;;    [in] subleaf - CPUID sub-leaf number (ECX)
;;    [out] out    - registers structure to store results of CPUID into
;;
;; void mbcpuid(const unsigned leaf, const unsigned subleaf, struct cpuid_regs *out)

MKGLOBAL(mbcpuid,function,internal)
mbcpuid:
        push    rbx

        mov     r11, arg3       ;; arg3 will get overwritten with cpuid on sysv
        mov     eax, DWORD(arg1)
        mov     ecx, DWORD(arg2)

        cpuid

        mov     [r11 + 0*4], eax
        mov     [r11 + 1*4], ebx
        mov     [r11 + 2*4], ecx
        mov     [r11 + 3*4], edx

        pop     rbx
        ret

mksection stack-noexec
