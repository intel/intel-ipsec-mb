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

;; ===========================================================
;; NOTE about comment format:
;;
;;      xmm = a b c d
;;            ^     ^
;;            |     |
;;       MSB--+     +--LSB
;;
;;      a - most significant word in `xmm`
;;      d - least significant word in `xmm`
;; ===========================================================

%use smartalign

%include "include/os.inc"
%include "include/clear_regs.inc"

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rdx
%define arg4	rcx
%else
%define arg1	rcx
%define arg2	rdx
%define arg3	r8
%define arg4	r9
%endif

%define arg_hash        arg1
%define arg_msg         arg2
%define arg_num_blks    arg3

mksection .rodata
default rel

align 16
SHUFF_MASK:
	db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

mksection .text

;; ***************************************************************************
;; Create 4 x 32-bit new words of message schedule W[] using SM3-NI ISA
;; ***************************************************************************
%macro SM3MSG 7
%define %%W03_00        %1      ;; [in] XMM register with W[0..3]
%define %%W07_04        %2      ;; [in] XMM register with W[4..7]
%define %%W11_08        %3      ;; [in] XMM register with W[8..11]
%define %%W15_12        %4      ;; [in] XMM register with W[12..15]
%define %%W19_16        %5      ;; [out] XMM register with W[19..16]
%define %%T1            %6      ;; [clobbered] XMM register
%define %%T2            %7      ;; [clobbered] XMM register

%define %%T3 %%W19_16

        vpalignr        %%T3, %%W11_08, %%W07_04, 3*4   ;; xmm8 = W10 W9 W8 W7
	vpsrldq         %%T1, %%W15_12, 4               ;; xmm9 = 0 W15 W14 W13
	vsm3msg1        %%T3, %%T1, %%W03_00            ;; xmm8 = WTMP3 WTMP2 WTMP1 WTMP0
	vpalignr        %%T1, %%W07_04, %%W03_00, 3*4   ;; xmm9 = W6 W5 W4 W3
	vpalignr        %%T2, %%W15_12, %%W11_08, 2*4   ;; xmm1 = W13 W12 W11 W10
	vsm3msg2        %%T3, %%T1, %%T2                ;; xmm8 = W19 W18 W17 W16
%endmacro

;; ***************************************************************************
;; Performs 4 rounds of SM3 algorithm
;; - consumes 4 words of message schedule W[]
;; - updates SM3 state registers: ABEF and CDGH
;; ***************************************************************************
%macro SM3ROUNDS4 6
%define %%ABEF          %1      ;; [in/out] XMM register with ABEF registers
%define %%CDGH          %2      ;; [in/out] XMM register with CDGH registers
%define %%W03_00        %3      ;; [in] XMM register with W[8..11]
%define %%W07_04        %4      ;; [in] XMM register with W[12..15]
%define %%T1            %5      ;; [clobbered] XMM register
%define %%R             %6      ;; [in] round number

        vpunpcklqdq     %%T1, %%W03_00, %%W07_04        ;; T1 = W5 W4 W1 W0
	vsm3rnds2       %%CDGH, %%ABEF, %%T1, %%R       ;; CDGH = updated ABEF // 2 rounds
	vpunpckhqdq     %%T1, %%W03_00, %%W07_04        ;; T1 = W7 W6 W3 W2
	vsm3rnds2       %%ABEF, %%CDGH, %%T1, (%%R + 2) ;; ABEF = updated CDGH // 2 rounds
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sm3_update(uint32_t digest[8], const void *input, uint64_t num_blocks)
;; arg1 : [in/out] pointer to hash value
;; arg2 : [in] message pointer
;; arg3 : [in] number of blocks to process

align 32
MKGLOBAL(sm3_update_ni_x1,function,internal)
sm3_update_ni_x1:
        or              arg_num_blks, arg_num_blks
        je              done_hash

%ifidn __OUTPUT_FORMAT__, win64
        ;; xmm6:xmm12 need to be maintained for Windows
        sub             rsp, 7*16
        vmovdqu         [rsp + 0*16], xmm6
        vmovdqu         [rsp + 1*16], xmm7
        vmovdqu         [rsp + 2*16], xmm8
        vmovdqu         [rsp + 3*16], xmm9
        vmovdqu         [rsp + 4*16], xmm10
        vmovdqu         [rsp + 5*16], xmm11
        vmovdqu         [rsp + 6*16], xmm12
%endif

        ;; load current hash value and change word order
        vmovdqu         xmm6, [arg_hash]
        vmovdqu         xmm7, [arg_hash + 16]
        ;; xmm6 = D C B A, xmm7 = H G F E

        vpshufd         xmm0, xmm6, 0x1B        ;; xmm0 = A B C D
        vpshufd         xmm1, xmm7, 0x1B        ;; xmm1 = E F G H
        vpunpckhqdq     xmm6, xmm1, xmm0        ;; xmm6 = A B E F
        vpunpcklqdq     xmm7, xmm1, xmm0        ;; xmm7 = C D G H
        vpsrld          xmm2, xmm7, 9
        vpslld          xmm3, xmm7, 23
        vpxor           xmm1, xmm2, xmm3        ;; xmm1 = xmm2 ^ xmm3 = ROL32(CDGH, 23)
        vpsrld          xmm4, xmm7, 19
        vpslld          xmm5, xmm7, 13
        vpxor           xmm0, xmm4, xmm5        ;; xmm0 = xmm2 ^ xmm3 = ROL32(CDGH, 13)
        vpblendd        xmm7, xmm1, xmm0, 0x3   ;; xmm7 = ROL32(C, 23) ROL32(D, 23) ROL32(G, 13) ROL32(H, 13)

        vmovdqa         xmm12, [rel SHUFF_MASK]
align 32
block_loop:
        vmovdqa         xmm10, xmm6
        vmovdqa         xmm11, xmm7

        ;; prepare W[0..15] - read and shuffle the data
        vmovdqu         xmm2, [arg_msg + 0*16]
        vmovdqu         xmm3, [arg_msg + 1*16]
        vmovdqu         xmm4, [arg_msg + 2*16]
        vmovdqu         xmm5, [arg_msg + 3*16]
        vpshufb         xmm2, xmm2, xmm12                               ;; xmm2 = W03 W02 W01 W00
        vpshufb         xmm3, xmm3, xmm12                               ;; xmm3 = W07 W06 W05 W04
        vpshufb         xmm4, xmm4, xmm12                               ;; xmm4 = W11 W10 W09 W08
        vpshufb         xmm5, xmm5, xmm12                               ;; xmm5 = W15 W14 W13 W12

        SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W19 W18 W17 W16
        SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 0

        vmovdqa         xmm2, xmm8
        SM3MSG          xmm3, xmm4, xmm5, xmm2, xmm8, xmm9, xmm1        ;; xmm8 = W23 W22 W21 W20
        SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 4

        vmovdqa         xmm3, xmm8
        SM3MSG          xmm4, xmm5, xmm2, xmm3, xmm8, xmm9, xmm1        ;; xmm8 = W27 W26 W25 W24
        SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 8

        vmovdqa         xmm4, xmm8
        SM3MSG          xmm5, xmm2, xmm3, xmm4, xmm8, xmm9, xmm1        ;; xmm8 = W31 W30 W29 W28
        SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 12

        vmovdqa         xmm5, xmm8
        SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W35 W34 W33 W32
        SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 16

        vmovdqa         xmm2, xmm8
        SM3MSG          xmm3, xmm4, xmm5, xmm2, xmm8, xmm9, xmm1        ;; xmm8 = W39 W38 W37 W36
        SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 20

        vmovdqa         xmm3, xmm8
        SM3MSG          xmm4, xmm5, xmm2, xmm3, xmm8, xmm9, xmm1        ;; xmm8 = W43 W42 W41 W40
        SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 24

        vmovdqa         xmm4, xmm8
        SM3MSG          xmm5, xmm2, xmm3, xmm4, xmm8, xmm9, xmm1        ;; xmm8 = W47 W46 W45 W44
        SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 28

        vmovdqa         xmm5, xmm8
        SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W51 W50 W49 W48
        SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 32

        vmovdqa         xmm2, xmm8
        SM3MSG          xmm3, xmm4, xmm5, xmm2, xmm8, xmm9, xmm1        ;; xmm8 = W55 W54 W53 W52
        SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 36

        vmovdqa         xmm3, xmm8
        SM3MSG          xmm4, xmm5, xmm2, xmm3, xmm8, xmm9, xmm1        ;; xmm8 = W59 W58 W57 W56
        SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 40

        vmovdqa         xmm4, xmm8
        SM3MSG          xmm5, xmm2, xmm3, xmm4, xmm8, xmm9, xmm1        ;; xmm8 = W63 W62 W61 W60
        SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 44

        vmovdqa         xmm5, xmm8
        SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W67 W66 W65 W64
        SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 48

        vmovdqa         xmm2, xmm8
        SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 52

        SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 56

        SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 60

        ;; add feed-forward to the chaining value and move on to the next message block
        vpxor           xmm6, xmm6, xmm10
        vpxor           xmm7, xmm7, xmm11
        add             arg_msg, 64
        dec             arg_num_blks
        jnz             block_loop

        ;; change word order and store the hash value back in memory
        vpslld          xmm2, xmm7, 9
        vpsrld          xmm3, xmm7, 23
        vpxor           xmm1, xmm2, xmm3        ;; xmm1 = xmm2 ^ xmm3 = ROL32(CDGH, 9)
        vpslld          xmm4, xmm7, 19
        vpsrld          xmm5, xmm7, 13
        vpxor           xmm0, xmm4, xmm5        ;; xmm0 = xmm2 ^ xmm3 = ROL32(CDGH, 19)
        vpblendd        xmm7, xmm1, xmm0, 0x3   ;; xmm7 = ROL32(C, 9) ROL32(D, 9) ROL32(G, 19) ROL32(H, 19)
        vpshufd         xmm0, xmm6, 0x1B        ;; xmm0 = F E B A
        vpshufd         xmm1, xmm7, 0x1B        ;; xmm1 = H G D C

        vpunpcklqdq     xmm6, xmm0, xmm1        ;; xmm6 = D C B A
        vpunpckhqdq     xmm7, xmm0, xmm1        ;; xmm7 = H G F E

        vmovdqu         [arg_hash], xmm6
        vmovdqu         [arg_hash + 16], xmm7

%ifidn __OUTPUT_FORMAT__, win64
        ;; xmm6:xmm12 need to be maintained for Windows
        vmovdqu         xmm6, [rsp + 0*16]
        vmovdqu         xmm7, [rsp + 1*16]
        vmovdqu         xmm8, [rsp + 2*16]
        vmovdqu         xmm9, [rsp + 3*16]
        vmovdqu         xmm10, [rsp + 4*16]
        vmovdqu         xmm11, [rsp + 5*16]
        vmovdqu         xmm12, [rsp + 6*16]
        add             rsp, 7*16
%endif

done_hash:

	ret

mksection stack-noexec
