;;
;; Copyright (c) 2020, Intel Corporation
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

%include "include/os.asm"

[bits 64]
default rel

section .data

;; Ethernet FCS CRC32 0x04c11db7
align 64
MKGLOBAL(crc32_ethernet_fcs_const,data,internal)
crc32_ethernet_fcs_const:
        dq 0x00000000ccaa009e
        dq 0x00000001751997d0
        dq 0x000000014a7fe880
        dq 0x00000001e88ef372
        dq 0x00000000ccaa009e
        dq 0x0000000163cd6124
        dq 0x00000001f7011640
        dq 0x00000001db710640
        dq 0x00000001d7cfc6ac
        dq 0x00000001ea89367e
        dq 0x000000018cb44e58
        dq 0x00000000df068dc2
        dq 0x00000000ae0b5394
        dq 0x00000001c7569e54
        dq 0x00000001c6e41596
        dq 0x0000000154442bd4
        dq 0x0000000174359406
        dq 0x000000003db1ecdc
        dq 0x000000015a546366
        dq 0x00000000f1da05aa

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
