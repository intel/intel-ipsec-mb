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
;; Post-increment atomic 64-bit increment
;;
;; Parameters:
;;    [in] counter - pointer to a 64-bit counter
;;
;; uint64_t atomic_uint64_inc(uint64_t *counter)

MKGLOBAL(atomic_uint64_inc,function,internal)
atomic_uint64_inc:
        mov             rax, [arg1]
atomic_uint64_loop:
        lea             r11, [rax + 1]
        lock cmpxchg    [arg1], r11             ;; compare counter against RAX, if not changed then store R11 in to counter
        jnz             atomic_uint64_loop      ;; if counter changed between load and cmpxchg then load counter into RAX & try again
        ret                                     ;; return current counter value through RAX

mksection stack-noexec
