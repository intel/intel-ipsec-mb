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
%include "imb_job.asm"
%include "include/memcpy.asm"

section .data
default rel

align 16
constants:
dd      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

align 16
add_1:
dd      0x00000001, 0x00000000, 0x00000000, 0x00000000

align 16
shuf_mask_rotl8:
db      3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14

align 16
shuf_mask_rotl16:
db      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13

%ifdef LINUX
%define arg1    rdi
%else
%define arg1    rcx
%endif

%define job     arg1

section .text

; VPROLD reg, imm, tmp
%macro VPROLD 3
%define %%reg %1
%define %%imm %2
%define %%tmp %3
%if %%imm == 8
        vpshufb %%reg, [rel shuf_mask_rotl8]
%elif %%imm == 16
        vpshufb %%reg, [rel shuf_mask_rotl16]
%else
        vpsrld  %%tmp, %%reg, (32-%%imm)
        vpslld  %%reg, %%imm
        vpor    %%reg, %%tmp
%endif
%endmacro

;;
;; Performs a quarter round on all 4 columns,
;; resulting in a full round
;;
%macro quarter_round 5
%define %%A    %1 ;; [in/out] XMM register containing value A of all 4 columns
%define %%B    %2 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C    %3 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D    %4 ;; [in/out] XMM register containing value D of all 4 columns
%define %%XTMP %5 ;; [clobbered] Temporary XMM register

        vpaddd  %%A, %%B
        vpxor   %%D, %%A
        VPROLD  %%D, 16, %%XTMP
        vpaddd  %%C, %%D
        vpxor   %%B, %%C
        VPROLD  %%B, 12, %%XTMP
        vpaddd  %%A, %%B
        vpxor   %%D, %%A
        VPROLD  %%D, 8, %%XTMP
        vpaddd  %%C, %%D
        vpxor   %%B, %%C
        VPROLD  %%B, 7, %%XTMP

%endmacro

;;
;; Rotates the registers to prepare the data
;; from column round to diagonal round
;;
%macro column_to_diag 3
%define %%B %1 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] XMM register containing value D of all 4 columns

        vpshufd %%B, %%B, 0x39 ; 0b00111001 ;; 0,3,2,1
        vpshufd %%C, %%C, 0x4E ; 0b01001110 ;; 1,0,3,2
        vpshufd %%D, %%D, 0x93 ; 0b10010011 ;; 2,1,0,3

%endmacro

;;
;; Rotates the registers to prepare the data
;; from diagonal round to column round
;;
%macro diag_to_column 3
%define %%B %1 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] XMM register containing value D of all 4 columns

        vpshufd %%B, %%B, 0x93 ; 0b10010011 ; 2,1,0,3
        vpshufd %%C, %%C, 0x4E ; 0b01001110 ; 1,0,3,2
        vpshufd %%D, %%D, 0x39 ; 0b00111001 ; 0,3,2,1

%endmacro

;;
;; Generates 64 bytes of keystream
;;
%macro generate_ks 9
%define %%STATE_IN_A    %1  ;; [in] XMM containing state A
%define %%STATE_IN_B    %2  ;; [in] XMM containing state B
%define %%STATE_IN_C    %3  ;; [in] XMM containing state C
%define %%STATE_IN_D    %4  ;; [in] XMM containing state D
%define %%A_KS0         %5  ;; [out] XMM to contain keystream 0-15 bytes
%define %%B_KS1         %6  ;; [out] XMM to contain keystream 0-15 bytes
%define %%C_KS2         %7  ;; [out] XMM to contain keystream 0-15 bytes
%define %%D_KS3         %8  ;; [out] XMM to contain keystream 0-15 bytes
%define %%XTMP          %9  ;; [clobbered] Temporary XMM register
        vmovdqa %%A_KS0, %%STATE_IN_A
        vmovdqa %%B_KS1, %%STATE_IN_B
        vmovdqa %%C_KS2, %%STATE_IN_C
        vmovdqa %%D_KS3, %%STATE_IN_D
%rep 10
        quarter_round %%A_KS0, %%B_KS1, %%C_KS2, %%D_KS3, %%XTMP
        column_to_diag %%B_KS1, %%C_KS2, %%D_KS3
        quarter_round %%A_KS0, %%B_KS1, %%C_KS2, %%D_KS3, %%XTMP
        diag_to_column %%B_KS1, %%C_KS2, %%D_KS3
%endrep

        vpaddd  %%A_KS0, %%STATE_IN_A
        vpaddd  %%B_KS1, %%STATE_IN_B
        vpaddd  %%C_KS2, %%STATE_IN_C
        vpaddd  %%D_KS3, %%STATE_IN_D
%endmacro

align 32
MKGLOBAL(submit_job_chacha20_enc_dec_avx,function,internal)
submit_job_chacha20_enc_dec_avx:

%define src     r8
%define dst     r9
%define len     r10
%define tmp     r11
%define tmp2    rax

        ; Prepare chacha state from IV, key
        mov     tmp, [job + _enc_keys]
        vmovdqu xmm1, [tmp]          ; Load key bytes 0-15
        vmovdqu xmm2, [tmp + 16]     ; Load key bytes 16-31
        mov     tmp, [job + _iv]
        ; Read nonce (12 bytes)
        vmovq   xmm3, [tmp]
        vpinsrd xmm3, [tmp + 8], 2
        vpslldq xmm3, 4
        vmovdqa xmm0, [rel constants]

        mov     len, [job + _msg_len_to_cipher_in_bytes]
        mov     src, [job + _src]
        add     src, [job + _cipher_start_src_offset_in_bytes]

        mov     dst, [job + _dst]
start_loop:
        cmp     len, 64
        jb      exit_loop

        ; Increment block counter and generate 64 bytes of keystream
        vpaddd  xmm3, [rel add_1]
        generate_ks xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm12

        ; Load plaintext
        vmovdqu  xmm8,  [src]
        vmovdqu  xmm9,  [src + 16]
        vmovdqu  xmm10, [src + 32]
        vmovdqu  xmm11, [src + 48]

        ; XOR KS with plaintext and store resulting ciphertext
        vpxor    xmm8,  xmm4
        vpxor    xmm9,  xmm5
        vpxor    xmm10, xmm6
        vpxor    xmm11, xmm7

        vmovdqu [dst], xmm8
        vmovdqu [dst + 16], xmm9
        vmovdqu [dst + 32], xmm10
        vmovdqu [dst + 48], xmm11

        ; Update pointers
        add     src, 64
        add     dst, 64

        sub     len, 64

        jmp     start_loop

exit_loop:

        ; Check if there are partial block (less than 64 bytes)
        or      len, len
        jz      no_partial_block

        ; Increment block counter and generate 64 bytes of keystream
        vpaddd   xmm3, [rel add_1]
        generate_ks xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm12

        cmp     len, 48
        jb      less_than_48

        ; Load plaintext
        vmovdqu  xmm8, [src]
        vmovdqu  xmm9, [src + 16]
        vmovdqu  xmm10, [src + 32]

        ; XOR KS with plaintext and store resulting ciphertext
        vpxor    xmm8, xmm4
        vpxor    xmm9, xmm5
        vpxor    xmm10, xmm6

        vmovdqu [dst], xmm8
        vmovdqu [dst + 16], xmm9
        vmovdqu [dst + 32], xmm10

        ; Store last KS in xmm4, for partial block
        vmovdqu  xmm4, xmm7

        sub     len, 48
        add     src, 48
        add     dst, 48

        jmp     check_partial
less_than_48:
        cmp     len, 32
        jb      less_than_32

        ; Load plaintext
        vmovdqu  xmm8, [src]
        vmovdqu  xmm9, [src + 16]

        ; XOR KS with plaintext and store resulting ciphertext
        vpxor    xmm8, xmm4
        vpxor    xmm9, xmm5

        vmovdqu [dst], xmm8
        vmovdqu [dst + 16], xmm9

        ; Store last KS in xmm4, for partial block
        vmovdqu  xmm4, xmm6

        sub     len, 32
        add     src, 32
        add     dst, 32

        jmp     check_partial

less_than_32:
        cmp     len, 16
        jb      check_partial

        ; Load plaintext
        vmovdqu  xmm8, [src]

        ; XOR KS with plaintext and store resulting ciphertext
        vpxor    xmm8, xmm4

        vmovdqu [dst], xmm8

        ; Store last KS in xmm4, for partial block
        vmovdqu  xmm4, xmm5

        sub     len, 16
        add     src, 16
        add     dst, 16

check_partial:
        or      len, len
        jz      no_partial_block

        ; Load plaintext
        simd_load_avx_15_1 xmm8, src, len

        ; XOR KS with plaintext and store resulting ciphertext
        vpxor    xmm8, xmm4

        simd_store_avx_15 dst, xmm8, len, tmp, tmp2

no_partial_block:

%ifdef SAFE_DATA
        clear_all_xmms_avx_asm
%endif
        mov     rax, job
        or      dword [rax + _status], STS_COMPLETED_AES

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
