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
%include "include/reg_sizes.inc"
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

mksection .rodata

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

mksection .text

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

%define x_counter xmm16
%define y_counter ymm16
%define z_counter zmm16

%define zkey    zmm17

        ;; Construct internal state from IV, where last 4 bytes are 0
        ;; by reading the first 12 bytes of IV
        vmovq           x_counter, [iv]
        vpinsrd         x_counter, [iv + 8], 2
        ; For AES, this AI bit 0 of first byte needs to be set
        vporq           x_counter, [rel set_ai_bit]

        ; Counter for H, Q, P
        vshufi32x4      z_counter, z_counter, 0x00
        vpaddq          z_counter, z_counter, [rel add_0_1_2_0]

        ; Encrypt blocks with AES-256
        ; Load the keys
        vbroadcasti32x4 zkey, [p_keys + 0*16]
        vpxorq          z_counter, z_counter, zkey

%assign i 1
%rep 13
        vbroadcasti32x4 zkey, [p_keys + i*16]
        vaesenc         z_counter, z_counter, zkey
%assign i (i + 1)
%endrep
        vbroadcasti32x4 zkey, [p_keys + i*16]
        vaesenclast     z_counter, z_counter, zkey

        ; Write the 3x16 bytes out
        vmovdqu64       [hqp], y_counter
        vextracti32x4   [hqp + 32], z_counter, 2

%ifdef SAFE_DATA
        clear_zmms_avx512 xmm16, xmm17
%endif
        ret

mksection stack-noexec
