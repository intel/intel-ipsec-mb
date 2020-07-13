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
;; http://www.ietf.org/rfc/rfc1952.txt
align 64
MKGLOBAL(crc32_ethernet_fcs_const,data,internal)
crc32_ethernet_fcs_const:
        dq 0x00000000e95c1271, 0x00000000ce3371cb   ; 2048-bits fold
        dq 0x00000000910eeec1, 0x0000000033fff533   ; 1024-bits fold
        dq 0x000000000cbec0ed, 0x0000000031f8303f   ; 896-bits fold
        dq 0x0000000057c54819, 0x00000000df068dc2   ; 768-bits fold
        dq 0x00000000ae0b5394, 0x000000001c279815   ; 640-bits fold
        dq 0x000000001d9513d7, 0x000000008f352d95   ; 512-bits fold
        dq 0x00000000af449247, 0x000000003db1ecdc   ; 384-bits fold
        dq 0x0000000081256527, 0x00000000f1da05aa   ; 256-bits fold
        dq 0x00000000ccaa009e, 0x00000000ae689191   ; 128-bits fold
        dq 0x0000000000000000, 0x0000000000000000   ; padding
	dq 0x00000000ccaa009e, 0x00000000b8bc6765   ; 128-bits to 64-bits fold
	dq 0x00000001f7011640, 0x00000001db710640   ; 64-bits to 32-bits reduction

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
