;;
;; Copyright (c) 2020-2024, Intel Corporation
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

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/crc32_const.inc"
%include "include/cet.inc"
%include "include/align_avx512.inc"

[bits 64]
default rel

%ifdef LINUX
%define arg1            rdi
%define arg2            rsi
%define arg3            rdx
%define arg4            rcx
%else
%define arg1            rcx
%define arg2            rdx
%define arg3            r8
%define arg4            r9
%endif

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(crc32_wimax_ofdma_data_avx512, function,)
crc32_wimax_ofdma_data_avx512:
        endbranch64
        lea             arg4, [rel crc32_wimax_ofdma_data_const]
        mov             arg3, arg2
        mov             arg2, arg1
        mov             DWORD(arg1), 0xffff_ffff

        call            crc32_by16_vclmul_avx512

        not             eax

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(crc8_wimax_ofdma_hcs_avx512, function,)
crc8_wimax_ofdma_hcs_avx512:
        endbranch64
        lea             arg4, [rel crc32_wimax_ofdma_hcs8_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_by16_vclmul_avx512

        shr             eax, 24          ; adjust for 8-bit poly

        ret

mksection stack-noexec
