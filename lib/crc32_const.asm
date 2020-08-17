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

;; SCTP CRC32 https://www.ietf.org/rfc/rfc3309.txt
;; 0x1edc6f41 (Castagnoli93)
align 64
MKGLOBAL(crc32_sctp_const,data,internal)
crc32_sctp_const:
        dq 0x000000004ef6a711, 0x00000000fa374b2e   ; 2048-b fold
        dq 0x00000000e78dbf1d, 0x000000005a47b20d   ; 1024-b fold
        dq 0x0000000079d09793, 0x00000000da9c52d0   ; 896-b fold
        dq 0x00000000ac594d98, 0x000000007def8667   ; 768-b fold
        dq 0x0000000038f8236c, 0x000000009a6aeb31   ; 640-b fold
        dq 0x00000000aa97d41d, 0x00000000a6955f31   ; 512-b fold
        dq 0x00000000e6957b4d, 0x00000000aa5eec4a   ; 384-b fold
        dq 0x0000000059a3508a, 0x000000007bba6798   ; 256-b fold
        dq 0x0000000018571d18, 0x000000006503ea99   ; 128-b fold
        dq 0x0000000000000000, 0x0000000000000000   ; padding (zero)
        dq 0xd7a0166500000000, 0x3aab457600000000   ; 128->64 reduction
        dq 0x000000011f91caf6, 0x000000011edc6f41   ; 64->32 reduction

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
