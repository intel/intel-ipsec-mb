;;
;; Copyright (c) 2023-2024, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
