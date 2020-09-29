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
constants0:
dd      0x61707865, 0x61707865, 0x61707865, 0x61707865

align 16
constants1:
dd      0x3320646e, 0x3320646e, 0x3320646e, 0x3320646e

align 16
constants2:
dd      0x79622d32, 0x79622d32, 0x79622d32, 0x79622d32

align 16
constants3:
dd      0x6b206574, 0x6b206574, 0x6b206574, 0x6b206574

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
dword_1_4:
dd      0x00000001, 0x00000002, 0x00000003, 0x00000004

align 16
dword_4:
dd      0x00000004, 0x00000004, 0x00000004, 0x00000004

align 16
shuf_mask_rotl8:
db      3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14

align 16
shuf_mask_rotl16:
db      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13

align 16
poly_clamp_r:
dq      0x0ffffffc0fffffff, 0x0ffffffc0ffffffc

struc STACK
_STATE:         reso    16      ; Space to store first 4 states
_XMM_SAVE:      reso    2       ; Space to store up to 2 temporary XMM registers
_RSP_SAVE:      resq    1       ; Space to store rsp pointer
endstruc
%define STACK_SIZE STACK_size

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%else
%define arg1    rcx
%define arg2    rdx
%endif

%define job     arg1

%define APPEND(a,b) a %+ b

section .text

;; 4x4 32-bit transpose function
%macro TRANSPOSE4_U32 6
%define %%r0 %1 ;; [in/out] Input first row / output third column
%define %%r1 %2 ;; [in/out] Input second row / output second column
%define %%r2 %3 ;; [in/clobbered] Input third row
%define %%r3 %4 ;; [in/out] Input fourth row / output fourth column
%define %%t0 %5 ;; [out] Temporary XMM register / output first column
%define %%t1 %6 ;; [clobbered] Temporary XMM register

        movdqa  %%t0, %%r0
        shufps	%%t0, %%r1, 0x44	; t0 = {b1 b0 a1 a0}
        shufps	%%r0, %%r1, 0xEE	; r0 = {b3 b2 a3 a2}
        movdqa  %%t1, %%r2
        shufps  %%t1, %%r3, 0x44	; t1 = {d1 d0 c1 c0}
        shufps	%%r2, %%r3, 0xEE	; r2 = {d3 d2 c3 c2}

        movdqa  %%r1, %%t0
        shufps	%%r1, %%t1, 0xDD	; r1 = {d1 c1 b1 a1}
        movdqa  %%r3, %%r0
        shufps	%%r3, %%r2, 0xDD	; r3 = {d3 c3 b3 a3}
        shufps	%%r0, %%r2, 0x88	; r0 = {d2 c2 b2 a2}
        shufps	%%t0, %%t1, 0x88	; t0 = {d0 c0 b0 a0}
%endmacro

; Rotate dwords on a XMM registers to the left N_BITS
%macro PROLD 3
%define %%XMM_IN %1 ; [in/out] XMM register to be rotated
%define %%N_BITS %2 ; [immediate] Number of bits to rotate
%define %%XTMP   %3 ; [clobbered] XMM temporary register
%if %%N_BITS == 8
        pshufb  %%XMM_IN, [rel shuf_mask_rotl8]
%elif %%N_BITS == 16
        pshufb  %%XMM_IN, [rel shuf_mask_rotl16]
%else
        movdqa  %%XTMP, %%XMM_IN
        psrld   %%XTMP, (32-%%N_BITS)
        pslld   %%XMM_IN, %%N_BITS
        por     %%XMM_IN, %%XTMP
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
%macro GENERATE_64_128_KS 9-14
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

; Perform 4 times the operation in first parameter
%macro XMM_OP_X4 9
%define %%OP         %1 ; [immediate] Instruction
%define %%DST_SRC1_1 %2 ; [in/out] First source/Destination 1
%define %%DST_SRC1_2 %3 ; [in/out] First source/Destination 2
%define %%DST_SRC1_3 %4 ; [in/out] First source/Destination 3
%define %%DST_SRC1_4 %5 ; [in/out] First source/Destination 4
%define %%SRC2_1     %6 ; [in] Second source 1
%define %%SRC2_2     %7 ; [in] Second source 2
%define %%SRC2_3     %8 ; [in] Second source 3
%define %%SRC2_4     %9 ; [in] Second source 4

        %%OP %%DST_SRC1_1, %%SRC2_1
        %%OP %%DST_SRC1_2, %%SRC2_2
        %%OP %%DST_SRC1_3, %%SRC2_3
        %%OP %%DST_SRC1_4, %%SRC2_4
%endmacro

%macro XMM_ROLS_X4  6
%define %%XMM_OP1_1      %1
%define %%XMM_OP1_2      %2
%define %%XMM_OP1_3      %3
%define %%XMM_OP1_4      %4
%define %%BITS_TO_ROTATE %5
%define %%XTMP           %6

        ; Store temporary register when bits to rotate is not 8 and 16,
        ; as the register will be clobbered in these cases,
        ; containing needed information
%if %%BITS_TO_ROTATE != 8 && %%BITS_TO_ROTATE != 16
        movdqa  [rsp + _XMM_SAVE], %%XTMP
%endif
        PROLD   %%XMM_OP1_1, %%BITS_TO_ROTATE, %%XTMP
        PROLD   %%XMM_OP1_2, %%BITS_TO_ROTATE, %%XTMP
        PROLD   %%XMM_OP1_3, %%BITS_TO_ROTATE, %%XTMP
        PROLD   %%XMM_OP1_4, %%BITS_TO_ROTATE, %%XTMP
%if %%BITS_TO_ROTATE != 8 && %%BITS_TO_ROTATE != 16
        movdqa  %%XTMP, [rsp + _XMM_SAVE]
%endif
%endmacro

;;
;; Performs a full chacha20 round on 4 states,
;; consisting of 4 quarter rounds, which are done in parallel
;;
%macro CHACHA20_ROUND 16
%define %%XMM_DWORD_A1  %1  ;; [in/out] XMM register containing dword A for first quarter round
%define %%XMM_DWORD_A2  %2  ;; [in/out] XMM register containing dword A for second quarter round
%define %%XMM_DWORD_A3  %3  ;; [in/out] XMM register containing dword A for third quarter round
%define %%XMM_DWORD_A4  %4  ;; [in/out] XMM register containing dword A for fourth quarter round
%define %%XMM_DWORD_B1  %5  ;; [in/out] XMM register containing dword B for first quarter round
%define %%XMM_DWORD_B2  %6  ;; [in/out] XMM register containing dword B for second quarter round
%define %%XMM_DWORD_B3  %7  ;; [in/out] XMM register containing dword B for third quarter round
%define %%XMM_DWORD_B4  %8  ;; [in/out] XMM register containing dword B for fourth quarter round
%define %%XMM_DWORD_C1  %9  ;; [in/out] XMM register containing dword C for first quarter round
%define %%XMM_DWORD_C2 %10  ;; [in/out] XMM register containing dword C for second quarter round
%define %%XMM_DWORD_C3 %11  ;; [in/out] XMM register containing dword C for third quarter round
%define %%XMM_DWORD_C4 %12  ;; [in/out] XMM register containing dword C for fourth quarter round
%define %%XMM_DWORD_D1 %13  ;; [in/out] XMM register containing dword D for first quarter round
%define %%XMM_DWORD_D2 %14  ;; [in/out] XMM register containing dword D for second quarter round
%define %%XMM_DWORD_D3 %15  ;; [in/out] XMM register containing dword D for third quarter round
%define %%XMM_DWORD_D4 %16  ;; [in/out] XMM register containing dword D for fourth quarter round

        ; A += B
        XMM_OP_X4 paddd, %%XMM_DWORD_A1, %%XMM_DWORD_A2, %%XMM_DWORD_A3, %%XMM_DWORD_A4, \
                         %%XMM_DWORD_B1, %%XMM_DWORD_B2, %%XMM_DWORD_B3, %%XMM_DWORD_B4
        ; D ^= A
        XMM_OP_X4 pxor, %%XMM_DWORD_D1, %%XMM_DWORD_D2, %%XMM_DWORD_D3, %%XMM_DWORD_D4, \
                        %%XMM_DWORD_A1, %%XMM_DWORD_A2, %%XMM_DWORD_A3, %%XMM_DWORD_A4

        ; D <<< 16
        XMM_ROLS_X4 %%XMM_DWORD_D1, %%XMM_DWORD_D2, %%XMM_DWORD_D3, %%XMM_DWORD_D4, 16, \
                    %%XMM_DWORD_B1

        ; C += D
        XMM_OP_X4 paddd, %%XMM_DWORD_C1, %%XMM_DWORD_C2, %%XMM_DWORD_C3, %%XMM_DWORD_C4, \
                         %%XMM_DWORD_D1, %%XMM_DWORD_D2, %%XMM_DWORD_D3, %%XMM_DWORD_D4
        ; B ^= C
        XMM_OP_X4 pxor, %%XMM_DWORD_B1, %%XMM_DWORD_B2, %%XMM_DWORD_B3, %%XMM_DWORD_B4, \
                        %%XMM_DWORD_C1, %%XMM_DWORD_C2, %%XMM_DWORD_C3, %%XMM_DWORD_C4

        ; B <<< 12
        XMM_ROLS_X4 %%XMM_DWORD_B1, %%XMM_DWORD_B2, %%XMM_DWORD_B3, %%XMM_DWORD_B4, 12, \
                    %%XMM_DWORD_D1

        ; A += B
        XMM_OP_X4 paddd, %%XMM_DWORD_A1, %%XMM_DWORD_A2, %%XMM_DWORD_A3, %%XMM_DWORD_A4, \
                          %%XMM_DWORD_B1, %%XMM_DWORD_B2, %%XMM_DWORD_B3, %%XMM_DWORD_B4
        ; D ^= A
        XMM_OP_X4 pxor, %%XMM_DWORD_D1, %%XMM_DWORD_D2, %%XMM_DWORD_D3, %%XMM_DWORD_D4, \
                          %%XMM_DWORD_A1, %%XMM_DWORD_A2, %%XMM_DWORD_A3, %%XMM_DWORD_A4

        ; D <<< 8
        XMM_ROLS_X4 %%XMM_DWORD_D1, %%XMM_DWORD_D2, %%XMM_DWORD_D3, %%XMM_DWORD_D4, 8, \
                    %%XMM_DWORD_B1

        ; C += D
        XMM_OP_X4 paddd, %%XMM_DWORD_C1, %%XMM_DWORD_C2, %%XMM_DWORD_C3, %%XMM_DWORD_C4, \
                          %%XMM_DWORD_D1, %%XMM_DWORD_D2, %%XMM_DWORD_D3, %%XMM_DWORD_D4
        ; B ^= C
        XMM_OP_X4 pxor, %%XMM_DWORD_B1, %%XMM_DWORD_B2, %%XMM_DWORD_B3, %%XMM_DWORD_B4, \
                          %%XMM_DWORD_C1, %%XMM_DWORD_C2, %%XMM_DWORD_C3, %%XMM_DWORD_C4

        ; B <<< 7
        XMM_ROLS_X4 %%XMM_DWORD_B1, %%XMM_DWORD_B2, %%XMM_DWORD_B3, %%XMM_DWORD_B4, 7, \
                    %%XMM_DWORD_D1
%endmacro

;;
;; Encodes 4 Chacha20 states, outputting 256 bytes of keystream
;; Data still needs to be transposed to get the keystream in the correct order
;;
%macro GENERATE_256_KS 16
%define %%XMM_DWORD_0   %1  ;; [out] XMM register to contain encoded dword 0 of the 4 Chacha20 states
%define %%XMM_DWORD_1   %2  ;; [out] XMM register to contain encoded dword 1 of the 4 Chacha20 states
%define %%XMM_DWORD_2   %3  ;; [out] XMM register to contain encoded dword 2 of the 4 Chacha20 states
%define %%XMM_DWORD_3   %4  ;; [out] XMM register to contain encoded dword 3 of the 4 Chacha20 states
%define %%XMM_DWORD_4   %5  ;; [out] XMM register to contain encoded dword 4 of the 4 Chacha20 states
%define %%XMM_DWORD_5   %6  ;; [out] XMM register to contain encoded dword 5 of the 4 Chacha20 states
%define %%XMM_DWORD_6   %7  ;; [out] XMM register to contain encoded dword 6 of the 4 Chacha20 states
%define %%XMM_DWORD_7   %8  ;; [out] XMM register to contain encoded dword 7 of the 4 Chacha20 states
%define %%XMM_DWORD_8   %9  ;; [out] XMM register to contain encoded dword 8 of the 4 Chacha20 states
%define %%XMM_DWORD_9  %10  ;; [out] XMM register to contain encoded dword 9 of the 4 Chacha20 states
%define %%XMM_DWORD_10 %11  ;; [out] XMM register to contain encoded dword 10 of the 4 Chacha20 states
%define %%XMM_DWORD_11 %12  ;; [out] XMM register to contain encoded dword 11 of the 4 Chacha20 states
%define %%XMM_DWORD_12 %13  ;; [out] XMM register to contain encoded dword 12 of the 4 Chacha20 states
%define %%XMM_DWORD_13 %14  ;; [out] XMM register to contain encoded dword 13 of the 4 Chacha20 states
%define %%XMM_DWORD_14 %15  ;; [out] XMM register to contain encoded dword 14 of the 4 Chacha20 states
%define %%XMM_DWORD_15 %16  ;; [out] XMM register to contain encoded dword 15 of the 4 Chacha20 states

%assign i 0
%rep 16
        movdqa  APPEND(%%XMM_DWORD_, i), [rsp + _STATE + 16*i]
%assign i (i + 1)
%endrep

%rep 10
        CHACHA20_ROUND %%XMM_DWORD_0, %%XMM_DWORD_1, %%XMM_DWORD_2, %%XMM_DWORD_3, \
                       %%XMM_DWORD_4, %%XMM_DWORD_5, %%XMM_DWORD_6, %%XMM_DWORD_7, \
                       %%XMM_DWORD_8, %%XMM_DWORD_9, %%XMM_DWORD_10, %%XMM_DWORD_11, \
                       %%XMM_DWORD_12, %%XMM_DWORD_13, %%XMM_DWORD_14, %%XMM_DWORD_15

        CHACHA20_ROUND %%XMM_DWORD_0, %%XMM_DWORD_1, %%XMM_DWORD_2, %%XMM_DWORD_3, \
                       %%XMM_DWORD_5, %%XMM_DWORD_6, %%XMM_DWORD_7, %%XMM_DWORD_4, \
                       %%XMM_DWORD_10, %%XMM_DWORD_11, %%XMM_DWORD_8, %%XMM_DWORD_9, \
                       %%XMM_DWORD_15, %%XMM_DWORD_12, %%XMM_DWORD_13, %%XMM_DWORD_14
%endrep

%assign i 0
%rep 16
        paddd   APPEND(%%XMM_DWORD_, i), [rsp + _STATE + 16*i]
%assign i (i + 1)
%endrep
%endmacro

align 32
MKGLOBAL(submit_job_chacha20_enc_dec_sse,function,internal)
submit_job_chacha20_enc_dec_sse:

%define src     r8
%define dst     r9
%define len     r10
%define iv      r11
%define keys    rdx
%define off     rax
%define tmp     iv
%define tmp2    keys

        ; Read pointers and length
        mov     len, [job + _msg_len_to_cipher_in_bytes]

        ; Check if there is nothing to encrypt
        or      len, len
        jz      exit

        mov     keys, [job + _enc_keys]
        mov     iv, [job + _iv]
        mov     src, [job + _src]
        add     src, [job + _cipher_start_src_offset_in_bytes]
        mov     dst, [job + _dst]

        mov     rax, rsp
        sub     rsp, STACK_SIZE
        and     rsp, -16
        mov     [rsp + _RSP_SAVE], rax ; save RSP

        xor     off, off

        ; If less than or equal to 64*2 bytes, prepare directly states for
        ; up to 2 blocks
        cmp     len, 64*2
        jbe     check_1_or_2_blocks_left

        ; Prepare first 4 chacha states
        movdqa  xmm0, [rel constants0]
        movdqa  xmm1, [rel constants1]
        movdqa  xmm2, [rel constants2]
        movdqa  xmm3, [rel constants3]

        ; Broadcast 8 dwords from key into XMM4-11
        movd    xmm4, [keys]
        movd    xmm5, [keys + 4]
        pshufd  xmm4, xmm4, 0
        pshufd  xmm5, xmm5, 0
        movd    xmm6, [keys + 8]
        movd    xmm7, [keys + 12]
        pshufd  xmm6, xmm6, 0
        pshufd  xmm7, xmm7, 0
        movd    xmm8, [keys + 16]
        movd    xmm9, [keys + 20]
        pshufd  xmm8, xmm8, 0
        pshufd  xmm9, xmm9, 0
        movd    xmm10, [keys + 24]
        movd    xmm11, [keys + 28]
        pshufd  xmm10, xmm10, 0
        pshufd  xmm11, xmm11, 0

        ; Broadcast 3 dwords from IV into XMM13-15
        movd    xmm13, [iv]
        movd    xmm14, [iv + 4]
        pshufd  xmm13, xmm13, 0
        pshufd  xmm14, xmm14, 0
        movd    xmm15, [iv + 8]
        pshufd  xmm15, xmm15, 0

        ; Set block counters for first 4 Chacha20 states
        movdqa  xmm12, [rel dword_1_4]

%assign i 0
%rep 16
        movdqa  [rsp + _STATE + 16*i], xmm %+ i
%assign i (i + 1)
%endrep

        cmp     len, 64*4
        jb      exit_loop

align 32
start_loop:

        ; Generate 256 bytes of keystream
        GENERATE_256_KS xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                        xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15

        ;; Transpose state to get keystream and XOR with plaintext
        ;; to get ciphertext

        ; Save registers to be used as temp registers
        movdqa [rsp + _XMM_SAVE], xmm14
        movdqa [rsp + _XMM_SAVE + 16], xmm15

        ; Transpose to get 0-63 bytes of KS
        TRANSPOSE4_U32 xmm0, xmm1, xmm2, xmm3, xmm14, xmm15

        ; xmm14, xmm1, xmm0, xmm3
        ; xmm2, xmm15 free to use
        movdqu  xmm2, [src + off]
        movdqu  xmm15, [src + off + 16*4]
        pxor    xmm14, xmm2
        pxor    xmm1, xmm15
        movdqu  [dst + off], xmm14
        movdqu  [dst + off + 16*4], xmm1

        movdqu  xmm2, [src + off + 16*8]
        movdqu  xmm15, [src + off + 16*12]
        pxor    xmm0, xmm2
        pxor    xmm3, xmm15
        movdqu  [dst + off + 16*8], xmm0
        movdqu  [dst + off + 16*12], xmm3

        ; Restore registers and use xmm0, xmm1 now that they are free
        movdqa xmm14, [rsp + _XMM_SAVE]
        movdqa xmm15, [rsp + _XMM_SAVE + 16]

        ; Transpose to get bytes 64-127 of KS
        TRANSPOSE4_U32 xmm4, xmm5, xmm6, xmm7, xmm0, xmm1

        ; xmm0, xmm5, xmm4, xmm7
        ; xmm6, xmm1 free to use
        movdqu  xmm6, [src + off + 16]
        movdqu  xmm1, [src + off + 16*5]
        pxor    xmm0, xmm6
        pxor    xmm5, xmm1
        movdqu  [dst + off + 16], xmm0
        movdqu  [dst + off + 16*5], xmm5

        movdqu  xmm6, [src + off + 16*9]
        movdqu  xmm1, [src + off + 16*13]
        pxor    xmm4, xmm6
        pxor    xmm7, xmm1
        movdqu  [dst + off + 16*9], xmm4
        movdqu  [dst + off + 16*13], xmm7

        ; Transpose to get bytes 128-191 of KS
        TRANSPOSE4_U32 xmm8, xmm9, xmm10, xmm11, xmm0, xmm1

        ; xmm0, xmm9, xmm8, xmm11
        ; xmm10, xmm1 free to use
        movdqu  xmm10, [src + off + 16*2]
        movdqu  xmm1, [src + off + 16*6]
        pxor    xmm0, xmm10
        pxor    xmm9, xmm1
        movdqu  [dst + off + 16*2], xmm0
        movdqu  [dst + off + 16*6], xmm9

        movdqu  xmm10, [src + off + 16*10]
        movdqu  xmm1, [src + off + 16*14]
        pxor    xmm8, xmm10
        pxor    xmm11, xmm1
        movdqu  [dst + off + 16*10], xmm8
        movdqu  [dst + off + 16*14], xmm11

        ; Transpose to get bytes 192-255 of KS
        TRANSPOSE4_U32 xmm12, xmm13, xmm14, xmm15, xmm0, xmm1

        ; xmm0, xmm13, xmm12, xmm15
        ; xmm14, xmm1 free to use
        movdqu  xmm14, [src + off + 16*3]
        movdqu  xmm1, [src + off + 16*7]
        pxor    xmm0, xmm14
        pxor    xmm13, xmm1
        movdqu  [dst + off + 16*3], xmm0
        movdqu  [dst + off + 16*7], xmm13

        movdqu  xmm14, [src + off + 16*11]
        movdqu  xmm1, [src + off + 16*15]
        pxor    xmm12, xmm14
        pxor    xmm15, xmm1
        movdqu  [dst + off + 16*11], xmm12
        movdqu  [dst + off + 16*15], xmm15
        ; Update remaining length
        sub     len, 64*4
        add     off, 64*4

        ; Update counter values
        movdqa xmm12, [rsp + 16*12]
        paddd  xmm12, [rel dword_4]
        movdqa [rsp + 16*12], xmm12

        cmp     len, 64*4
        jae     start_loop

exit_loop:

        ; Check if there are no more bytes to encrypt
        or      len, len
        jz      no_partial_block

        cmp     len, 64*2
        ja      more_than_2_blocks_left

check_1_or_2_blocks_left:
        cmp     len, 64
        ja      two_blocks_left

        ;; 1 block left

        ; Get last block counter dividing offset by 64
        shr     off, 6

        ; Prepare next chacha state from IV, key
        movdqu  xmm1, [keys]          ; Load key bytes 0-15
        movdqu  xmm2, [keys + 16]     ; Load key bytes 16-31
        ; Read nonce (12 bytes)
        movq    xmm3, [iv]
        pinsrd  xmm3, [iv + 8], 2
        pslldq  xmm3, 4
        movdqa  xmm0, [rel constants]

        ; Insert next block count
        inc     DWORD(off)
        movd    xmm4, DWORD(off)
        por     xmm3, xmm4
        dec     DWORD(off)
        shl     off, 6 ; Restore offset

        ; Generate 64 bytes of keystream
        GENERATE_64_128_KS xmm0, xmm1, xmm2, xmm3, xmm9, xmm10, xmm11, \
                           xmm12, xmm13

        cmp     len, 64
        jne     less_than_64

        ;; Exactly 64 bytes left

        ; Load plaintext, XOR with KS and store ciphertext
        movdqu  xmm14, [src + off]
        movdqu  xmm15, [src + off + 16]
        pxor    xmm14, xmm9
        pxor    xmm15, xmm10
        movdqu  [dst + off], xmm14
        movdqu  [dst + off + 16], xmm15

        movdqu  xmm14, [src + off + 16*2]
        movdqu  xmm15, [src + off + 16*3]
        pxor    xmm14, xmm11
        pxor    xmm15, xmm12
        movdqu  [dst + off + 16*2], xmm14
        movdqu  [dst + off + 16*3], xmm15

        jmp     no_partial_block

less_than_64:

        cmp     len, 48
        jb      less_than_48

        ; Load plaintext and XOR with keystream
        movdqu  xmm13, [src + off]
        movdqu  xmm14, [src + off + 16]
        movdqu  xmm15, [src + off + 32]

        pxor    xmm13, xmm9
        pxor    xmm14, xmm10
        pxor    xmm15, xmm11

        ; Store resulting ciphertext
        movdqu [dst + off], xmm13
        movdqu [dst + off + 16], xmm14
        movdqu [dst + off + 32], xmm15

        ; Store last KS in xmm9, for partial block
        movdqu  xmm9, xmm12

        sub     len, 48
        add     off, 48

        jmp     check_partial
less_than_48:
        cmp     len, 32
        jb      less_than_32

        ; Load plaintext and XOR with keystream
        movdqu  xmm13, [src + off]
        movdqu  xmm14, [src + off + 16]

        pxor    xmm13, xmm9
        pxor    xmm14, xmm10

        ; Store resulting ciphertext
        movdqu [dst + off], xmm13
        movdqu [dst + off + 16], xmm14

        ; Store last KS in xmm9, for partial block
        movdqu  xmm9, xmm11

        sub     len, 32
        add     off, 32

        jmp     check_partial

less_than_32:
        cmp     len, 16
        jb      check_partial

        ; Load plaintext and XOR with keystream
        movdqu  xmm13, [src + off]

        pxor    xmm13, xmm9

        ; Store resulting ciphertext
        movdqu [dst + off], xmm13

        ; Store last KS in xmm9, for partial block
        movdqu  xmm9, xmm10

        sub     len, 16
        add     off, 16

check_partial:
        or      len, len
        jz      no_partial_block

        add     src, off
        add     dst, off
        ; Load plaintext
        simd_load_sse_15_1 xmm8, src, len

        ; XOR KS with plaintext and store resulting ciphertext
        pxor    xmm8, xmm9

        simd_store_sse_15 dst, xmm8, len, tmp, tmp2

        jmp     no_partial_block

two_blocks_left:

        ; Get last block counter dividing offset by 64
        shr     off, 6

        ; Prepare next 2 chacha states from IV, key
        movdqu  xmm1, [keys]          ; Load key bytes 0-15
        movdqu  xmm2, [keys + 16]     ; Load key bytes 16-31
        ; Read nonce (12 bytes)
        movq    xmm3, [iv]
        pinsrd  xmm3, [iv + 8], 2
        pslldq  xmm3, 4
        movdqa  xmm0, [rel constants]

        movdqa  xmm8, xmm3

        ; Insert next block counts
        inc     DWORD(off)
        movd    xmm4, DWORD(off)
        por     xmm3, xmm4
        inc     DWORD(off)
        movd    xmm5, DWORD(off)
        por     xmm8, xmm5
        sub     off, 2
        shl     off, 6 ; Restore offset

        ; Generate 128 bytes of keystream
        GENERATE_64_128_KS xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                           xmm13, xmm8, xmm9, xmm10, xmm11, xmm12

        cmp     len, 128
        jb      between_64_127

        ; Load plaintext, XOR with KS and store ciphertext
        movdqu  xmm14, [src + off]
        movdqu  xmm15, [src + off + 16]
        pxor    xmm14, xmm4
        pxor    xmm15, xmm5
        movdqu  [dst + off], xmm14
        movdqu  [dst + off + 16], xmm15

        movdqu  xmm14, [src + off + 16*2]
        movdqu  xmm15, [src + off + 16*3]
        pxor    xmm14, xmm6
        pxor    xmm15, xmm7
        movdqu  [dst + off + 16*2], xmm14
        movdqu  [dst + off + 16*3], xmm15

        movdqu  xmm14, [src + off + 16*4]
        movdqu  xmm15, [src + off + 16*5]
        pxor    xmm14, xmm9
        pxor    xmm15, xmm10
        movdqu  [dst + off + 16*4], xmm14
        movdqu  [dst + off + 16*5], xmm15

        movdqu  xmm14, [src + off + 16*6]
        movdqu  xmm15, [src + off + 16*7]
        pxor    xmm14, xmm11
        pxor    xmm15, xmm12
        movdqu  [dst + off + 16*6], xmm14
        movdqu  [dst + off + 16*7], xmm15

        jmp     no_partial_block

between_64_127:
        ; Load plaintext, XOR with KS and store ciphertext for first 64 bytes
        movdqu  xmm14, [src + off]
        movdqu  xmm15, [src + off + 16]
        pxor    xmm14, xmm4
        pxor    xmm15, xmm5
        movdqu  [dst + off], xmm14
        movdqu  [dst + off + 16], xmm15

        movdqu  xmm14, [src + off + 16*2]
        movdqu  xmm15, [src + off + 16*3]
        pxor    xmm14, xmm6
        pxor    xmm15, xmm7
        movdqu  [dst + off + 16*2], xmm14
        movdqu  [dst + off + 16*3], xmm15

        sub     len, 64
        add     off, 64
        ; Handle rest up to 63 bytes in "less_than_64"
        jmp     less_than_64

more_than_2_blocks_left:

        ;; First generate 128 bytes of KS to encrypt next 128 bytes

        ; Get last block counter dividing offset by 64
        shr     off, 6

        ; Prepare next 2 chacha states from IV, key
        movdqu  xmm1, [keys]          ; Load key bytes 0-15
        movdqu  xmm2, [keys + 16]     ; Load key bytes 16-31
        ; Read nonce (12 bytes)
        movq    xmm3, [iv]
        pinsrd  xmm3, [iv + 8], 2
        pslldq  xmm3, 4
        movdqa  xmm0, [rel constants]

        movdqa  xmm8, xmm3

        ; Insert next block counts
        inc     DWORD(off)
        movd    xmm4, DWORD(off)
        por     xmm3, xmm4
        inc     DWORD(off)
        movd    xmm5, DWORD(off)
        por     xmm8, xmm5
        sub     off, 2
        shl     off, 6 ; Restore offset

        ; Generate 128 bytes of keystream
        GENERATE_64_128_KS xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                           xmm13, xmm8, xmm9, xmm10, xmm11, xmm12

        ; Load plaintext, XOR with KS and store ciphertext
        movdqu  xmm14, [src + off]
        movdqu  xmm15, [src + off + 16]
        pxor    xmm14, xmm4
        pxor    xmm15, xmm5
        movdqu  [dst + off], xmm14
        movdqu  [dst + off + 16], xmm15

        movdqu  xmm14, [src + off + 16*2]
        movdqu  xmm15, [src + off + 16*3]
        pxor    xmm14, xmm6
        pxor    xmm15, xmm7
        movdqu  [dst + off + 16*2], xmm14
        movdqu  [dst + off + 16*3], xmm15

        movdqu  xmm14, [src + off + 16*4]
        movdqu  xmm15, [src + off + 16*5]
        pxor    xmm14, xmm9
        pxor    xmm15, xmm10
        movdqu  [dst + off + 16*4], xmm14
        movdqu  [dst + off + 16*5], xmm15

        movdqu  xmm14, [src + off + 16*6]
        movdqu  xmm15, [src + off + 16*7]
        pxor    xmm14, xmm11
        pxor    xmm15, xmm12
        movdqu  [dst + off + 16*6], xmm14
        movdqu  [dst + off + 16*7], xmm15

        sub     len, 128
        add     off, 128

        jmp     check_1_or_2_blocks_left

no_partial_block:

%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
        ; Clear stack frame
%assign i 0
%rep 16
        movdqa  [rsp + _STATE + 16*i], xmm0
%assign i (i + 1)
%endrep
        movdqa  [rsp + _XMM_SAVE], xmm0
        movdqa  [rsp + _XMM_SAVE + 16], xmm0
%endif

        mov     rsp, [rsp + _RSP_SAVE]

exit:
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
        GENERATE_64_128_KS xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8

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
