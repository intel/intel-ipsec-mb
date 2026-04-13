;;
;; Copyright (c) 2025-2026, Intel Corporation
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
%include "include/cet.inc"
%include "include/clear_regs.inc"
%include "include/align_avx512.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%else ;; LINUX
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%endif

default rel

section .data

align 16
set_ai_bit:
dq      0x0000000000000001,0x0000000000000000

align 64
add_0_1_2_0:
dq      0x0000000000000000,0x0000000000000000
dq      0x0000000000000000,0x0100000000000000
dq      0x0000000000000000,0x0200000000000000
dq      0x0000000000000000,0x0000000000000000

extern byteswap_const

section .text

;;
;; Generates 16-byte H, Q, P keys using AES-256,
;; by encrypting the 16-byte internal state (from IV),
;; varying the last 4 bytes of the state with counter values
;; 0, 1 and 2.
;; The 3x16 bytes are output through argument 3.
;;
align_function
MKGLOBAL(generate_hqp_vaes_avx512,function,internal)
generate_hqp_vaes_avx512:

%define p_keys  arg1
%define iv      arg2
%define hqp     arg3

%define x_counter xmm0
%define z_counter zmm0

%define zkey0   zmm16
%define zkey1   zmm17
%define zkey2   zmm18
%define zkey3   zmm19
%define zkey4   zmm20
%define zkey5   zmm21
%define zkey6   zmm22
%define zkey7   zmm23
%define zkey8   zmm24
%define zkey9   zmm25
%define zkey10  zmm26
%define zkey11  zmm27
%define zkey12  zmm28
%define zkey13  zmm29
%define zkey14  zmm30

        endbranch64

        ;; Construct internal state from IV, where last 4 bytes are 0
        ;; by reading the first 12 bytes of IV
        vmovq   x_counter, [iv]
        vpinsrd x_counter, [iv + 8], 2
        ; For AES, this AI bit 0 of first byte needs to be set
        vporq   x_counter, [rel set_ai_bit]

        ; Counter for H, Q, P
        vshufi32x4 z_counter, z_counter, 0x00
        vpaddq  z_counter, z_counter, [rel add_0_1_2_0]

        ; Encrypt blocks with AES-256
        ; Load the keys
%assign i 0
%rep 15
        vbroadcasti32x4  zkey %+ i, [p_keys + i*16]
%assign i (i + 1)
%endrep

        vpxorq  z_counter, z_counter, zkey0

%assign i 1
%rep 13
        vaesenc z_counter, z_counter, zkey %+ i
%assign i (i + 1)
%endrep
        vaesenclast z_counter, z_counter, zkey14

        ; Write the 3x16 bytes out
        mov     rax, 0x3f
        kmovq   k1, rax
        vmovdqa64 [hqp]{k1}, z_counter

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif
        ret
