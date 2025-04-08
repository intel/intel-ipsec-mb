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

;; https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/align_sse.inc"

%ifdef LINUX

%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx

%define t1      rax
%define t2      r8
%define t3      r9
%define t4      r10
%define t5      r11
%define t6      arg4
%define t7      r12
%define t8      r13
%define t9      r14
%define t10     r15
%define t11     rbx
%define t12     rbp

%else

%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9

%define t1      rax
%define t2      rdi
%define t3      rsi
%define t4      r10
%define t5      r11
%define t6      arg4
%define t7      r12
%define t8      r13
%define t9      r14
%define t10     r15
%define t11     rbx
%define t12     rbp

%endif

%define A DWORD(t1)
%define B DWORD(t2)
%define C DWORD(t3)
%define D DWORD(t4)
%define E DWORD(t5)
%define F DWORD(t6)
%define G DWORD(t7)
%define H DWORD(t8)

;; SM3 stack frame
struc STACK
_W:             resd    68      ; expanded message W[]
_TT2:           resd    1
%ifidn __OUTPUT_FORMAT__, win64
_gpr_save:      resq    8       ; space for 8 GPR's
%else
_gpr_save:      resq    6       ; space for 6 GPR's
%endif
_rsp_save:      resq    1       ; space for rsp pointer
endstruc

mksection .rodata

align 16
K_const:
        dd 0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e,
        dd 0xe6228cbc, 0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39,
        dd 0x11465e73, 0x228cbce6, 0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879,
        dd 0xb14f50f3, 0x629ea1e7, 0xc53d43ce, 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
        dd 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5, 0x7a879d8a, 0xf50f3b14, 0xea1e7629,
        dd 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d, 0x879d8a7a, 0x0f3b14f5,
        dd 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43, 0x9d8a7a87,
        dd 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        dd 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762,
        dd 0x3d43cec5

align 16
SHUFF_MASK:
	db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

mksection .text

;; =============================================================================
;; FF0(x, y, z) = x ^ y ^ z
;; =============================================================================
%macro FF0 3
%define %%X  %1 ;; [in/out] 32-bit GPR
%define %%Y  %2 ;; [in] 32-bit GPR
%define %%Z  %3 ;; [in] 32-bit GPR

        xor     %%X, %%Y
        xor     %%X, %%Z
%endmacro

;; =============================================================================
;; GG0(x, y, z) = x ^ y ^ z
;; =============================================================================
%macro GG0 3
%define %%X  %1 ;; [in/out] 32-bit GPR
%define %%Y  %2 ;; [in] 32-bit GPR
%define %%Z  %3 ;; [in] 32-bit GPR

        xor     %%X, %%Y
        xor     %%X, %%Z
%endmacro

;; =============================================================================
;; FF1(x, y, z) = (x & y) | ((x | y) & z)
;; =============================================================================
%macro FF1 4
%define %%X  %1 ;; [in/out] 32-bit GPR
%define %%Y  %2 ;; [in] 32-bit GPR
%define %%Z  %3 ;; [in] 32-bit GPR
%define %%T  %4 ;; [clobbered] temporary GPR

        mov     %%T, %%X
        and     %%X, %%Y
        or      %%T, %%Y
        and     %%T, %%Z
        or      %%X, %%T
%endmacro

;; =============================================================================
;; GG1(x, y, z) = z ^ (x & (y ^ z))
;; =============================================================================
%macro GG1 4
%define %%X  %1 ;; [in/out] 32-bit GPR
%define %%Y  %2 ;; [in] 32-bit GPR
%define %%Z  %3 ;; [in] 32-bit GPR
%define %%T  %4 ;; [clobbered] temporary GPR

        mov     %%T, %%Z
        xor     %%T, %%Y
        and     %%X, %%T
        xor     %%X, %%Z
%endmacro

;; =============================================================================
;; P0(x) = x ^ ROL32(x, 9) ^ ROL32(x, 17)
;; =============================================================================
%macro P0 3
%define %%X  %1 ;; [in/out] 32-bit GPR
%define %%T1 %2 ;; [clobbered] temporary GPR
%define %%T2 %3 ;; [clobbered] temporary GPR

        mov     %%T1, %%X
        mov     %%T2, %%X
        rol     %%T1, 9
        rol     %%T2, 17
        xor     %%X, %%T1
        xor     %%X, %%T2
%endmacro

;; =============================================================================
;; P1(x) = x ^ ROL32(x, 15) ^ ROL32(x, 23)
;; =============================================================================
%macro P1 3
%define %%X  %1 ;; [in/out] 32-bit GPR
%define %%T1 %2 ;; [clobbered] temporary GPR
%define %%T2 %3 ;; [clobbered] temporary GPR

        mov     %%T1, %%X
        mov     %%T2, %%X
        rol     %%T1, 15
        rol     %%T2, 23
        xor     %%X, %%T1
        xor     %%X, %%T2
%endmacro

;; =============================================================================
;; Compress macro
;;    SS1 = ROL32((ROL32(A, 12) + E + K[i]), 7);
;;    SS2 = SS1 ^ ROL32(A, 12);
;;    TT1 = (i < 16) ? FF0(A, B, C) + D + SS2 + (W[i] ^ W[i + 4]) :
;;                     FF1(A, B, C) + D + SS2 + (W[i] ^ W[i + 4]);
;;    TT2 = (i < 16) ? GG0(E, F, G) + H + SS1 + W[i] :
;;                     GG1(E, F, G) + H + SS1 + W[i];
;;
;;    D = C;
;;    C = ROL32(B, 9);
;;    B = A;
;;    A = TT1;
;;    H = G;
;;    G = ROL32(F, 19);
;;    F = E;
;;    E = P0(TT2);
;;
;; Updates registers A, B, C, D, E, F, G and H
;; =============================================================================
%macro SM3_COMPRESS 5
%define %%IDX   %1 ;; [in] GPR with current index to W[]
%define %%I     %2 ;; [in] immediate value: 0 -> 0 <= index < 16, 1 -> 16 <= index < 64
%define %%T1    %3 ;; [clobbered] temporary 32-bit GPR
%define %%T2    %4 ;; [clobbered] temporary 32-bit GPR
%define %%T3    %5 ;; [clobbered] temporary 32-bit GPR

        ;; calculate SS1 and SS2
        mov     %%T1, A
        rol     %%T1, 12
        mov     %%T2, %%T1                      ;; T1 = T2 = ROL32(A, 12)

        add     %%T1, E
        lea     QWORD(%%T3), [rel K_const]
        add     %%T1, [QWORD(%%T3) + %%IDX*4]
        ;; T1 = ROL32(A, 12) + E + K[i]
        rol     %%T1, 7
        ;; T1 = SS1 = ROL32(ROL32(A, 12) + E + K[i], 7)
        xor     %%T2, %%T1
        ;; T2 = SS2 = SS1 ^ ROL32(A, 12)

        ;; calculate TT1 and TT2
        add     %%T1, [rsp + _W + %%IDX*4]      ;; SS1 += W[i]
        add     %%T1, H                         ;; SS1 += H
        mov     [rsp + _TT2], %%T1              ;; TT2 = H + SS1 + W[i]
        mov     %%T1, E
%if %%I == 0
        GG0     %%T1, F, G
%else
        GG1     %%T1, F, G, %%T3
%endif
        add     [rsp + _TT2], %%T1              ;; TT2 += GGx(E, F, G)

        add     %%T2, D                         ;; SS2 += D
        mov     %%T1, [rsp + _W + %%IDX*4]      ;; T1 = W[i]
        xor     %%T1, [rsp + _W + %%IDX*4 + 4*4];; T1 ^= W[i + 4]
        add     %%T2, %%T1                      ;; TT1 = D + SS2 + (W[i] ^ W[i + 4])
        mov     %%T1, A
%if %%I == 0
        FF0     %%T1, B, C
%else
        FF1     %%T1, B, C, %%T3
%endif
        add     %%T2, %%T1                      ;; TT1 += FFx(A, B, C)
        ;; T2 = TT1

        ;; update state registers
        mov     D, C                            ;; D = C
        mov     C, B
        rol     C, 9                            ;; C = ROL32(B, 9)
        mov     B, A                            ;; B = A
        mov     A, %%T2                         ;; A = TT1
        mov     H, G                            ;; H = G
        mov     G, F
        rol     G, 19                           ;; G = ROL32(F, 19)
        mov     F, E                            ;; F = E
        mov     E, [rsp + _TT2]
        P0      E, %%T1, %%T2                   ;; E = P0(TT2)
%endmacro

;; =============================================================================
;; Save registers on the stack and create stack frame
;; =============================================================================

%macro FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16
        mov     [rsp + _rsp_save], rax
        mov     [rsp + _gpr_save + 0*8], rbx
        mov     [rsp + _gpr_save + 1*8], rbp
        mov     [rsp + _gpr_save + 2*8], r12
        mov     [rsp + _gpr_save + 3*8], r13
        mov     [rsp + _gpr_save + 4*8], r14
        mov     [rsp + _gpr_save + 5*8], r15
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + _gpr_save + 6*8], rdi
        mov     [rsp + _gpr_save + 7*8], rsi
%endif
%endmacro

;; =============================================================================
;; Restore registers from the stack
;; =============================================================================

%macro FUNC_END 0
        mov     rbx, [rsp + _gpr_save + 0*8]
        mov     rbp, [rsp + _gpr_save + 1*8]
        mov     r12, [rsp + _gpr_save + 2*8]
        mov     r13, [rsp + _gpr_save + 3*8]
        mov     r14, [rsp + _gpr_save + 4*8]
        mov     r15, [rsp + _gpr_save + 5*8]
%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + _gpr_save + 6*8]
        mov     rsi, [rsp + _gpr_save + 7*8]
%endif
        mov     rsp, [rsp + _rsp_save]
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sm3_base_update(uint32_t digest[8], const void *input, uint64_t num_blocks)
MKGLOBAL(sm3_base_update,function,internal)
align_function
sm3_base_update:
        or      arg3, arg3
        jz      sm3_base_update_end

        FUNC_START

align_loop
sm3_base_loop:
        ;; W[0..15]: load and shuffle 16 bytes of message
        movdqu  xmm0, [arg2 + 0*16]
        movdqu  xmm1, [arg2 + 1*16]
        pshufb  xmm0, [rel SHUFF_MASK]
        pshufb  xmm1, [rel SHUFF_MASK]
        movdqu  [rsp + _W + 0*16], xmm0
        movdqu  [rsp + _W + 1*16], xmm1

        movdqu  xmm0, [arg2 + 2*16]
        movdqu  xmm1, [arg2 + 3*16]
        pshufb  xmm0, [rel SHUFF_MASK]
        pshufb  xmm1, [rel SHUFF_MASK]
        movdqu  [rsp + _W + 2*16], xmm0
        movdqu  [rsp + _W + 3*16], xmm1

        ;; W[16..67]: expand W[]
        lea     t9, [rsp + _W]
        mov     DWORD(t10), 16

align_loop
sm3_base_W_expand:
        ;; W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROL32(W[i - 3], 15)) ^
        ;;        ROL32(W[i - 13], 7) ^ W[i - 6]

        mov     DWORD(t1), [t9 + 13*4]  ;; W[i - 3]
        rol     DWORD(t1), 15
        xor     DWORD(t1), [t9 +  0*4]  ;; W[i - 16]
        xor     DWORD(t1), [t9 +  7*4]  ;; W[i - 9]
        ;; t1 = W[i - 16] ^ W[i - 9] ^ ROL32(W[i - 3], 15)
        P1      DWORD(t1), DWORD(t2), DWORD(t3)
        ;; t1 = P1(W[i - 16] ^ W[i - 9] ^ ROL32(W[i - 3], 15))
        xor     DWORD(t1), [t9 + 10*4]  ;; W[i - 6]
        mov     DWORD(t2), [t9 +  3*4]  ;; W[i - 13]
        rol     DWORD(t2), 7
        xor     DWORD(t1), DWORD(t2)
        mov     [rsp + _W + t10*4], DWORD(t1)
        add     t9, 4
        inc     t10
        cmp     DWORD(t10), 68
        jne     sm3_base_W_expand

        ;; read digest
        mov     A, [arg1 + 0*4]
        mov     B, [arg1 + 1*4]
        mov     C, [arg1 + 2*4]
        mov     D, [arg1 + 3*4]
        mov     E, [arg1 + 4*4]
        mov     F, [arg1 + 5*4]
        mov     G, [arg1 + 6*4]
        mov     H, [arg1 + 7*4]

        ;; compress
        xor     DWORD(t10), DWORD(t10)

align_loop
sm3_base_compress_0_15:
        SM3_COMPRESS t10, 0, DWORD(t9), DWORD(t11), DWORD(t12)
        inc     DWORD(t10)
        cmp     DWORD(t10), 16
        jne     sm3_base_compress_0_15

align_loop
sm3_base_compress_16_63:
        SM3_COMPRESS t10, 1, DWORD(t9), DWORD(t11), DWORD(t12)
        inc     DWORD(t10)
        cmp     DWORD(t10), 64
        jne     sm3_base_compress_16_63

        ;; update digest
        xor     [arg1 + 0*4], A
        xor     [arg1 + 1*4], B
        xor     [arg1 + 2*4], C
        xor     [arg1 + 3*4], D
        xor     [arg1 + 4*4], E
        xor     [arg1 + 5*4], F
        xor     [arg1 + 6*4], G
        xor     [arg1 + 7*4], H

        add     arg2, 64
        dec     arg3
        jnz     sm3_base_loop

%ifdef SAFE_DATA
        pxor    xmm0, xmm0
        pxor    xmm1, xmm1

        movdqu  [rsp + _W +  0*4], xmm0
        movdqu  [rsp + _W +  4*4], xmm0
        movdqu  [rsp + _W +  8*4], xmm0
        movdqu  [rsp + _W + 12*4], xmm0

        movdqu  [rsp + _W + 16*4], xmm0
        movdqu  [rsp + _W + 20*4], xmm0
        movdqu  [rsp + _W + 24*4], xmm0
        movdqu  [rsp + _W + 28*4], xmm0
%endif
        FUNC_END
align_label
sm3_base_update_end:
        ret

mksection stack-noexec
