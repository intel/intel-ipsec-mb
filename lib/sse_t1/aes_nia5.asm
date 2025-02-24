;;
;; Copyright (c) 2025, Intel Corporation
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
%include "include/align_sse.inc"

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

align 16
add_1:
dq      0x0000000000000000,0x0100000000000000

align 16
add_2:
dq      0x0000000000000000,0x0200000000000000

extern byteswap_const

section .text

;;
;; Generates 16-byte H, Q, P keys using AES-256,
;; by encrypting the 16-byte internal state (from IV),
;; varying the last 4 bytes of the state with counter values
;; 0, 1 and 2.
;; The 3x16 bytes are output through argument 3.
;;
MKGLOBAL(generate_hqp_aes_sse,function,internal)
align_function
generate_hqp_aes_sse:
%define p_keys  arg1
%define iv      arg2
%define hqp     arg3

%define xcounter_h xmm0
%define xcounter_q xmm1
%define xcounter_p xmm2

%define xkeyA   xmm3
%define xkeyB   xmm4
%define xkeyC   xmm5

        endbranch64

        ;; Construct internal state from IV, where last 4 bytes are 0
        ;; by reading the first 12 bytes of IV
        movq    xcounter_h, [iv]
        pinsrd  xcounter_h, [iv + 8], 2
        ; For AES, this AI bit 0 of first byte needs to be set
        por     xcounter_h, [rel set_ai_bit]

        ; For Q, block counter value is 1
        movdqa  xcounter_q, xcounter_h
        paddd   xcounter_q, [rel add_1]
        ; For P, block counter value is 2
        movdqa  xcounter_p, xcounter_h
        paddd   xcounter_p, [rel add_2]

        ; Encrypt blocks with AES-256
        movdqa  xkeyA, [p_keys + 0*16]
        movdqa  xkeyB, [p_keys + 1*16]

        pxor    xcounter_h, xkeyA
        pxor    xcounter_q, xkeyA
        pxor    xcounter_p, xkeyA

        movdqa  xkeyC, [p_keys + 2*16]
        aesenc  xcounter_h, xkeyB                ; key 1
        aesenc  xcounter_q, xkeyB                ; key 1
        aesenc  xcounter_p, xkeyB                ; key 1

        movdqa  xkeyA, [p_keys + 3*16]
        aesenc  xcounter_h, xkeyC                ; key 2
        aesenc  xcounter_q, xkeyC                ; key 2
        aesenc  xcounter_p, xkeyC                ; key 2

        movdqa  xkeyB, [p_keys + 4*16]
        aesenc  xcounter_h, xkeyA                ; key 3
        aesenc  xcounter_q, xkeyA                ; key 3
        aesenc  xcounter_p, xkeyA                ; key 3

        movdqa  xkeyC, [p_keys + 5*16]
        aesenc  xcounter_h, xkeyB                ; key 4
        aesenc  xcounter_q, xkeyB                ; key 4
        aesenc  xcounter_p, xkeyB                ; key 4

        movdqa  xkeyA, [p_keys + 6*16]
        aesenc  xcounter_h, xkeyC                ; key 5
        aesenc  xcounter_q, xkeyC                ; key 5
        aesenc  xcounter_p, xkeyC                ; key 5

        movdqa  xkeyB, [p_keys + 7*16]
        aesenc  xcounter_h, xkeyA                ; key 6
        aesenc  xcounter_q, xkeyA                ; key 6
        aesenc  xcounter_p, xkeyA                ; key 6

        movdqa  xkeyC, [p_keys + 8*16]
        aesenc  xcounter_h, xkeyB                ; key 7
        aesenc  xcounter_q, xkeyB                ; key 7
        aesenc  xcounter_p, xkeyB                ; key 7

        movdqa  xkeyA, [p_keys + 9*16]
        aesenc  xcounter_h, xkeyC                ; key 8
        aesenc  xcounter_q, xkeyC                ; key 8
        aesenc  xcounter_p, xkeyC                ; key 8

        movdqa  xkeyB, [p_keys + 10*16]
        aesenc  xcounter_h, xkeyA                ; key 9
        aesenc  xcounter_q, xkeyA                ; key 9
        aesenc  xcounter_p, xkeyA                ; key 9

        movdqa  xkeyC, [p_keys + 11*16]
        aesenc  xcounter_h, xkeyB                ; key 10
        aesenc  xcounter_q, xkeyB                ; key 10
        aesenc  xcounter_p, xkeyB                ; key 10

        movdqa  xkeyA, [p_keys + 12*16]
        aesenc  xcounter_h, xkeyC                ; key 11
        aesenc  xcounter_q, xkeyC                ; key 11
        aesenc  xcounter_p, xkeyC                ; key 11

        movdqa  xkeyB, [p_keys + 13*16]
        aesenc  xcounter_h, xkeyA                ; key 12
        aesenc  xcounter_q, xkeyA                ; key 12
        aesenc  xcounter_p, xkeyA                ; key 12

        movdqa  xkeyC, [p_keys + 14*16]
        aesenc  xcounter_h, xkeyB                ; key 13
        aesenc  xcounter_q, xkeyB                ; key 13
        aesenc  xcounter_p, xkeyB                ; key 13

        aesenclast    xcounter_h, xkeyC        ; key 14
        aesenclast    xcounter_q, xkeyC        ; key 14
        aesenclast    xcounter_p, xkeyC        ; key 14

        ; Write the 3x16 bytes out
        movdqa  [hqp], xcounter_h
        movdqa  [hqp + 16], xcounter_q
        movdqa  [hqp + 16*2], xcounter_p

        ret
