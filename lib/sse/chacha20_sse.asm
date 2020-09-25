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
%include "include/clear_regs.asm"

section .data
default rel

align 16
constants:
dd      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

align 16
dword_1:
dd      0x00000001, 0x00000000, 0x00000000, 0x00000000

align 16
dword_2:
dd      0x00000002, 0x00000000, 0x00000000, 0x00000000

align 16
shuf_mask_rotl8:
db      3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14

align 16
shuf_mask_rotl16:
db      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13

align 16
poly_clamp_r:
dq      0x0ffffffc0fffffff, 0x0ffffffc0ffffffc

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%else
%define arg1    rcx
%define arg2    rdx
%endif

%define job     arg1

section .text

; PROLD reg, imm, tmp
%macro PROLD 3
%define %%reg %1
%define %%imm %2
%define %%tmp %3
%if %%imm == 8
        pshufb  %%reg, [rel shuf_mask_rotl8]
%elif %%imm == 16
        pshufb  %%reg, [rel shuf_mask_rotl16]
%else
        movdqa  %%tmp, %%reg
        psrld   %%tmp, (32-%%imm)
        pslld   %%reg, %%imm
        por     %%reg, %%tmp
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

        paddd   %%A, %%B
        pxor    %%D, %%A
        PROLD   %%D, 16, %%XTMP
        paddd   %%C, %%D
        pxor    %%B, %%C
        PROLD   %%B, 12, %%XTMP
        paddd   %%A, %%B
        pxor    %%D, %%A
        PROLD   %%D, 8, %%XTMP
        paddd   %%C, %%D
        pxor    %%B, %%C
        PROLD   %%B, 7, %%XTMP

%endmacro

%macro quarter_round_x2 9
%define %%A_L    %1 ;; [in/out] XMM register containing value A of all 4 columns
%define %%B_L    %2 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C_L    %3 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D_L    %4 ;; [in/out] XMM register containing value D of all 4 columns
%define %%A_H    %5 ;; [in/out] XMM register containing value A of all 4 columns
%define %%B_H    %6 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C_H    %7 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D_H    %8 ;; [in/out] XMM register containing value D of all 4 columns
%define %%XTMP   %9 ;; [clobbered] Temporary XMM register

        paddd   %%A_L, %%B_L
        paddd   %%A_H, %%B_H
        pxor    %%D_L, %%A_L
        pxor    %%D_H, %%A_H
        PROLD   %%D_L, 16, %%XTMP
        PROLD   %%D_H, 16, %%XTMP
        paddd   %%C_L, %%D_L
        paddd   %%C_H, %%D_H
        pxor    %%B_L, %%C_L
        pxor    %%B_H, %%C_H
        PROLD   %%B_L, 12, %%XTMP
        PROLD   %%B_H, 12, %%XTMP
        paddd   %%A_L, %%B_L
        paddd   %%A_H, %%B_H
        pxor    %%D_L, %%A_L
        pxor    %%D_H, %%A_H
        PROLD   %%D_L, 8, %%XTMP
        PROLD   %%D_H, 8, %%XTMP
        paddd   %%C_L, %%D_L
        paddd   %%C_H, %%D_H
        pxor    %%B_L, %%C_L
        pxor    %%B_H, %%C_H
        PROLD   %%B_L, 7, %%XTMP
        PROLD   %%B_H, 7, %%XTMP

%endmacro

;;
;; Rotates the registers to prepare the data
;; from column round to diagonal round
;;
%macro column_to_diag 3
%define %%B %1 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] XMM register containing value D of all 4 columns

        pshufd  %%B, %%B, 0x39 ; 0b00111001 ;; 0,3,2,1
        pshufd  %%C, %%C, 0x4E ; 0b01001110 ;; 1,0,3,2
        pshufd  %%D, %%D, 0x93 ; 0b10010011 ;; 2,1,0,3

%endmacro

;;
;; Rotates the registers to prepare the data
;; from diagonal round to column round
;;
%macro diag_to_column 3
%define %%B %1 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] XMM register containing value D of all 4 columns

        pshufd  %%B, %%B, 0x93 ; 0b10010011 ; 2,1,0,3
        pshufd  %%C, %%C, 0x4E ; 0b01001110 ; 1,0,3,2
        pshufd  %%D, %%D, 0x39 ; 0b00111001 ; 0,3,2,1

%endmacro

;;
;; Generates 64 or 128 bytes of keystream
;; States IN A-C are the same for first 64 and last 64 bytes
;; State IN D differ because of the different block count
;;
%macro generate_ks 9-14
%define %%STATE_IN_A      %1  ;; [in] XMM containing state A
%define %%STATE_IN_B      %2  ;; [in] XMM containing state B
%define %%STATE_IN_C      %3  ;; [in] XMM containing state C
%define %%STATE_IN_D_L    %4  ;; [in] XMM containing state D (low block count)
%define %%A_L_KS0         %5  ;; [out] XMM to contain keystream 0-15 bytes
%define %%B_L_KS1         %6  ;; [out] XMM to contain keystream 16-31 bytes
%define %%C_L_KS2         %7  ;; [out] XMM to contain keystream 32-47 bytes
%define %%D_L_KS3         %8  ;; [out] XMM to contain keystream 48-63 bytes
%define %%XTMP            %9  ;; [clobbered] Temporary XMM register
%define %%STATE_IN_D_H    %10  ;; [in] XMM containing state D (high block count)
%define %%A_H_KS4         %11  ;; [out] XMM to contain keystream 64-79 bytes
%define %%B_H_KS5         %12  ;; [out] XMM to contain keystream 80-95 bytes
%define %%C_H_KS6         %13  ;; [out] XMM to contain keystream 96-111 bytes
%define %%D_H_KS7         %14  ;; [out] XMM to contain keystream 112-127 bytes

        movdqa  %%A_L_KS0, %%STATE_IN_A
        movdqa  %%B_L_KS1, %%STATE_IN_B
        movdqa  %%C_L_KS2, %%STATE_IN_C
        movdqa  %%D_L_KS3, %%STATE_IN_D_L
%if %0 == 14
        movdqa  %%A_H_KS4, %%STATE_IN_A
        movdqa  %%B_H_KS5, %%STATE_IN_B
        movdqa  %%C_H_KS6, %%STATE_IN_C
        movdqa  %%D_H_KS7, %%STATE_IN_D_H
%endif
%rep 10
%if %0 == 14
        quarter_round_x2 %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3, \
                %%A_H_KS4, %%B_H_KS5, %%C_H_KS6, %%D_H_KS7, %%XTMP
        column_to_diag %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
        column_to_diag %%B_H_KS5, %%C_H_KS6, %%D_H_KS7
        quarter_round_x2 %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3, \
                %%A_H_KS4, %%B_H_KS5, %%C_H_KS6, %%D_H_KS7, %%XTMP
        diag_to_column %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
        diag_to_column %%B_H_KS5, %%C_H_KS6, %%D_H_KS7
%else
        quarter_round %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3, %%XTMP
        column_to_diag %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
        quarter_round %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3, %%XTMP
        diag_to_column %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
%endif
%endrep

        paddd   %%A_L_KS0, %%STATE_IN_A
        paddd   %%B_L_KS1, %%STATE_IN_B
        paddd   %%C_L_KS2, %%STATE_IN_C
        paddd   %%D_L_KS3, %%STATE_IN_D_L
%if %0 == 14
        paddd   %%A_H_KS4, %%STATE_IN_A
        paddd   %%B_H_KS5, %%STATE_IN_B
        paddd   %%C_H_KS6, %%STATE_IN_C
        paddd   %%D_H_KS7, %%STATE_IN_D_H
%endif
%endmacro

align 32
MKGLOBAL(submit_job_chacha20_enc_dec_sse,function,internal)
submit_job_chacha20_enc_dec_sse:

%define src     r8
%define dst     r9
%define len     r10
%define tmp     r11
%define tmp2    rax

        ; Prepare first 2 chacha states from IV, key
        mov     tmp, [job + _enc_keys]
        movdqu  xmm1, [tmp]          ; Load key bytes 0-15
        movdqu  xmm2, [tmp + 16]     ; Load key bytes 16-31
        mov     tmp, [job + _iv]
        ; Read nonce (12 bytes)
        movq    xmm3, [tmp]
        pinsrd  xmm3, [tmp + 8], 2
        pslldq  xmm3, 4
        movdqa  xmm0, [rel constants]

        movdqa  xmm8, xmm3

        por     xmm3, [rel dword_1]
        por     xmm8, [rel dword_2]

        mov     len, [job + _msg_len_to_cipher_in_bytes]
        mov     src, [job + _src]
        add     src, [job + _cipher_start_src_offset_in_bytes]

        mov     dst, [job + _dst]
start_loop:
        cmp     len, 128
        jb      exit_loop

        ; Generate 128 bytes of keystream
        generate_ks xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                    xmm13, xmm8, xmm9, xmm10, xmm11, xmm12

        ; Load plaintext, XOR with KS and store ciphertext
        movdqu  xmm14, [src]
        movdqu  xmm15, [src + 16]
        pxor    xmm14, xmm4
        pxor    xmm15, xmm5
        movdqu  [dst], xmm14
        movdqu  [dst + 16], xmm15

        movdqu  xmm14, [src + 16*2]
        movdqu  xmm15, [src + 16*3]
        pxor    xmm14, xmm6
        pxor    xmm15, xmm7
        movdqu  [dst + 16*2], xmm14
        movdqu  [dst + 16*3], xmm15

        movdqu  xmm14, [src + 16*4]
        movdqu  xmm15, [src + 16*5]
        pxor    xmm14, xmm9
        pxor    xmm15, xmm10
        movdqu  [dst + 16*4], xmm14
        movdqu  [dst + 16*5], xmm15

        movdqu  xmm14, [src + 16*6]
        movdqu  xmm15, [src + 16*7]
        pxor    xmm14, xmm11
        pxor    xmm15, xmm12
        movdqu  [dst + 16*6], xmm14
        movdqu  [dst + 16*7], xmm15

        ; Update pointers
        add     src, 128
        add     dst, 128

        sub     len, 128

        ; Increment block counters
        paddd   xmm3, [rel dword_2]
        paddd   xmm8, [rel dword_2]

        jmp     start_loop

exit_loop:

        cmp     len, 64
        jbe     gen_64b_only

        ; Generate 128 bytes of keystream
        generate_ks xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                    xmm13, xmm8, xmm9, xmm10, xmm11, xmm12

        ; Load plaintext, XOR with KS and store ciphertext
        movdqu  xmm14, [src]
        movdqu  xmm15, [src + 16]
        pxor    xmm14, xmm4
        pxor    xmm15, xmm5
        movdqu  [dst], xmm14
        movdqu  [dst + 16], xmm15

        movdqu  xmm14, [src + 16*2]
        movdqu  xmm15, [src + 16*3]
        pxor    xmm14, xmm6
        pxor    xmm15, xmm7
        movdqu  [dst + 16*2], xmm14
        movdqu  [dst + 16*3], xmm15

        ; Update pointers
        add     src, 64
        add     dst, 64

        sub     len, 64
        jz      no_partial_block

        jmp     less_equal_64

gen_64b_only:

        ; Generate 64 bytes of keystream
        generate_ks xmm0, xmm1, xmm2, xmm3, xmm9, xmm10, xmm11, xmm12, xmm13

less_equal_64:
        or      len, len
        jz      no_partial_block

        cmp     len, 64
        jne     less_than_64

        ; Load plaintext, XOR with KS and store ciphertext
        movdqu  xmm14, [src]
        movdqu  xmm15, [src + 16]
        pxor    xmm14, xmm9
        pxor    xmm15, xmm10
        movdqu  [dst], xmm14
        movdqu  [dst + 16], xmm15

        movdqu  xmm14, [src + 16*2]
        movdqu  xmm15, [src + 16*3]
        pxor    xmm14, xmm11
        pxor    xmm15, xmm12
        movdqu  [dst + 16*2], xmm14
        movdqu  [dst + 16*3], xmm15

        jmp     no_partial_block

less_than_64:
        cmp     len, 48
        jb      less_than_48

        ; Load plaintext and XOR with keystream
        movdqu  xmm13, [src]
        movdqu  xmm14, [src + 16]
        movdqu  xmm15, [src + 32]

        pxor    xmm13, xmm9
        pxor    xmm14, xmm10
        pxor    xmm15, xmm11

        ; Store resulting ciphertext
        movdqu [dst], xmm13
        movdqu [dst + 16], xmm14
        movdqu [dst + 32], xmm15

        ; Store last KS in xmm9, for partial block
        movdqu  xmm9, xmm12

        sub     len, 48
        add     src, 48
        add     dst, 48

        jmp     check_partial
less_than_48:
        cmp     len, 32
        jb      less_than_32

        ; Load plaintext and XOR with keystream
        movdqu  xmm13, [src]
        movdqu  xmm14, [src + 16]

        pxor    xmm13, xmm9
        pxor    xmm14, xmm10

        ; Store resulting ciphertext
        movdqu [dst], xmm13
        movdqu [dst + 16], xmm14

        ; Store last KS in xmm9, for partial block
        movdqu  xmm9, xmm11

        sub     len, 32
        add     src, 32
        add     dst, 32

        jmp     check_partial

less_than_32:
        cmp     len, 16
        jb      check_partial

        ; Load plaintext and XOR with keystream
        movdqu  xmm13, [src]

        pxor    xmm13, xmm9

        ; Store resulting ciphertext
        movdqu [dst], xmm13

        ; Store last KS in xmm9, for partial block
        movdqu  xmm9, xmm10

        sub     len, 16
        add     src, 16
        add     dst, 16

check_partial:
        or      len, len
        jz      no_partial_block

        ; Load plaintext
        simd_load_sse_15_1 xmm8, src, len

        ; XOR KS with plaintext and store resulting ciphertext
        pxor    xmm8, xmm9

        simd_store_sse_15 dst, xmm8, len, tmp, tmp2

no_partial_block:

%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
%endif
        mov     rax, job
        or      dword [rax + _status], STS_COMPLETED_AES

        ret

;;
;; void poly1305_key_gen_sse(IMB_JOB *job, void *poly_key)
align 32
MKGLOBAL(poly1305_key_gen_sse,function,internal)
poly1305_key_gen_sse:
        ;; prepare chacha state from IV, key
        mov     rax, [job + _enc_keys]
        movdqa  xmm0, [rel constants]
        movdqu  xmm1, [rax]          ; Load key bytes 0-15
        movdqu  xmm2, [rax + 16]     ; Load key bytes 16-31
        ;;  copy nonce (12 bytes)
        mov     rax, [job + _iv]
        movq    xmm3, [rax]
        pinsrd  xmm3, [rax + 8], 2
        pslldq  xmm3, 4

        ;; run one round of chacha20
        generate_ks xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8

        ;; clamp R and store poly1305 key
        ;; R = KEY[0..15] & 0xffffffc0ffffffc0ffffffc0fffffff
        pand    xmm4, [rel poly_clamp_r]
        movdqu  [arg2 + 0 * 16], xmm4
        movdqu  [arg2 + 1 * 16], xmm5

%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
%endif
        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
