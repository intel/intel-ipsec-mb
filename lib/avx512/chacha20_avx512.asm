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
%include "include/clear_regs.asm"
%include "include/const.inc"
%include "include/reg_sizes.asm"
%include "include/transpose_avx512.asm"
%include "include/aes_common.asm"

section .data
default rel

align 16
constants:
dd      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

align 64
add_8:
dd      0x00000008, 0x00000000, 0x00000000, 0x00000000
dd      0x00000008, 0x00000000, 0x00000000, 0x00000000
dd      0x00000008, 0x00000000, 0x00000000, 0x00000000
dd      0x00000008, 0x00000000, 0x00000000, 0x00000000

align 64
set_1_4:
dd      0x00000001, 0x00000000, 0x00000000, 0x00000000
dd      0x00000002, 0x00000000, 0x00000000, 0x00000000
dd      0x00000003, 0x00000000, 0x00000000, 0x00000000
dd      0x00000004, 0x00000000, 0x00000000, 0x00000000

align 64
set_5_8:
dd      0x00000005, 0x00000000, 0x00000000, 0x00000000
dd      0x00000006, 0x00000000, 0x00000000, 0x00000000
dd      0x00000007, 0x00000000, 0x00000000, 0x00000000
dd      0x00000008, 0x00000000, 0x00000000, 0x00000000

%define APPEND(a,b) a %+ b

%ifdef LINUX
%define arg1    rdi
%else
%define arg1    rcx
%endif

%define job     arg1

section .text

%macro FUNC_SAVE 0
%ifidn __OUTPUT_FORMAT__, win64
        mov     r11, rsp
        sub     rsp, 16*10 + 8*2
        and     rsp, ~15

        ; xmm6:xmm15 need to be maintained for Windows
        vmovdqa [rsp + 0*16], xmm6
        vmovdqa [rsp + 1*16], xmm7
        vmovdqa [rsp + 2*16], xmm8
        vmovdqa [rsp + 3*16], xmm9
        vmovdqa [rsp + 4*16], xmm10
        vmovdqa [rsp + 5*16], xmm11
        vmovdqa [rsp + 6*16], xmm12
        vmovdqa [rsp + 7*16], xmm13
        vmovdqa [rsp + 8*16], xmm14
        vmovdqa [rsp + 9*16], xmm15
        mov     [rsp + 16*10], r12
        mov     [rsp + 16*10 + 8], r11 ;; rsp pointer
%endif
%endmacro


%macro FUNC_RESTORE 0
%ifidn __OUTPUT_FORMAT__, win64
        vmovdqa xmm6,  [rsp + 0*16]
        vmovdqa xmm7,  [rsp + 1*16]
        vmovdqa xmm8,  [rsp + 2*16]
        vmovdqa xmm9,  [rsp + 3*16]
        vmovdqa xmm10, [rsp + 4*16]
        vmovdqa xmm11, [rsp + 5*16]
        vmovdqa xmm12, [rsp + 6*16]
        vmovdqa xmm13, [rsp + 7*16]
        vmovdqa xmm14, [rsp + 8*16]
        vmovdqa xmm15, [rsp + 9*16]
        mov     r12, [rsp + 16*10]
        mov     rsp, [rsp + 16*10 + 8]
%endif
%endmacro

;;
;; Performs a quarter round on all 4 columns,
;; resulting in a full round
;;
%macro quarter_round 4
%define %%A %1 ;; [in/out] ZMM register containing value A of all 4 columns
%define %%B %2 ;; [in/out] ZMM register containing value B of all 4 columns
%define %%C %3 ;; [in/out] ZMM register containing value C of all 4 columns
%define %%D %4 ;; [in/out] ZMM register containing value D of all 4 columns

        vpaddd          %%A, %%B
        vpxorq          %%D, %%A
        vprold          %%D, 16
        vpaddd          %%C, %%D
        vpxorq          %%B, %%C
        vprold          %%B, 12
        vpaddd          %%A, %%B
        vpxorq          %%D, %%A
        vprold          %%D, 8
        vpaddd          %%C, %%D
        vpxorq          %%B, %%C
        vprold          %%B, 7

%endmacro

;;
;; Rotates the registers to prepare the data
;; from column round to diagonal round
;;
%macro column_to_diag 3
%define %%B %1 ;; [in/out] ZMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] ZMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] ZMM register containing value D of all 4 columns

        vpshufd         %%B, %%B, 0x39 ; 0b00111001 ;; 0,3,2,1
        vpshufd         %%C, %%C, 0x4E ; 0b01001110 ;; 1,0,3,2
        vpshufd         %%D, %%D, 0x93 ; 0b10010011 ;; 2,1,0,3

%endmacro

;;
;; Rotates the registers to prepare the data
;; from diagonal round to column round
;;
%macro diag_to_column 3
%define %%B %1 ;; [in/out] ZMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] ZMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] ZMM register containing value D of all 4 columns

        vpshufd         %%B, %%B, 0x93 ; 0b10010011 ; 2,1,0,3
        vpshufd         %%C, %%C, 0x4E ; 0b01001110 ;  1,0,3,2
        vpshufd         %%D, %%D, 0x39 ; 0b00111001 ;  0,3,2,1

%endmacro

;;
;; Generates up to 64*8 bytes of keystream
;;
%macro GENERATE_KS 21
%define %%STATE_IN_A_L   %1  ;; [in] ZMM containing state "A" part
%define %%STATE_IN_B_L   %2  ;; [in] ZMM containing state "B" part
%define %%STATE_IN_C_L   %3  ;; [in] ZMM containing state "C" part
%define %%STATE_IN_D_L   %4  ;; [in] ZMM containing state "D" part
%define %%STATE_IN_A_H   %5  ;; [in] ZMM containing state "A" part (or "none" in NUM_BLOCKS == 4)
%define %%STATE_IN_B_H   %6  ;; [in] ZMM containing state "B" part (or "none" in NUM_BLOCKS == 4)
%define %%STATE_IN_C_H   %7  ;; [in] ZMM containing state "C" part (or "none" in NUM_BLOCKS == 4)
%define %%STATE_IN_D_H   %8  ;; [in] ZMM containing state "D" part (or "none" in NUM_BLOCKS == 4)
%define %%A_L_KS0        %9  ;; [out] ZMM A / Bytes 0-63    of KS
%define %%B_L_KS1        %10 ;; [out] ZMM B / Bytes 64-127  of KS
%define %%C_L_KS2        %11 ;; [out] ZMM C / Bytes 128-191 of KS
%define %%D_L_KS3        %12 ;; [out] ZMM D / Bytes 192-255 of KS
%define %%A_H_KS4        %13 ;; [out] ZMM A / Bytes 256-319 of KS (or "none" in NUM_BLOCKS == 4)
%define %%B_H_KS5        %14 ;; [out] ZMM B / Bytes 320-383 of KS (or "none" in NUM_BLOCKS == 4)
%define %%C_H_KS6        %15 ;; [out] ZMM C / Bytes 384-447 of KS (or "none" in NUM_BLOCKS == 4)
%define %%D_H_KS7        %16 ;; [out] ZMM D / Bytes 448-511 of KS (or "none" in NUM_BLOCKS == 4)
%define %%ZTMP0          %17 ;; [clobbered] Temp ZMM reg
%define %%ZTMP1          %18 ;; [clobbered] Temp ZMM reg
%define %%ZTMP2          %19 ;; [clobbered] Temp ZMM reg
%define %%ZTMP3          %20 ;; [clobbered] Temp ZMM reg
%define %%NUM_BLOCKS     %21 ;; [in] Num blocks to encrypt (4 or 8)

        vmovdqa64       %%A_L_KS0, %%STATE_IN_A_L
        vmovdqa64       %%B_L_KS1, %%STATE_IN_B_L
        vmovdqa64       %%C_L_KS2, %%STATE_IN_C_L
        vmovdqa64       %%D_L_KS3, %%STATE_IN_D_L
%if %%NUM_BLOCKS == 8
        vmovdqa64       %%A_H_KS4, %%STATE_IN_A_H
        vmovdqa64       %%B_H_KS5, %%STATE_IN_B_H
        vmovdqa64       %%C_H_KS6, %%STATE_IN_C_H
        vmovdqa64       %%D_H_KS7, %%STATE_IN_D_H
%endif
%rep 10
        quarter_round %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
        column_to_diag %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
        quarter_round %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
        diag_to_column %%B_L_KS1, %%C_L_KS2, %%D_L_KS3
%if %%NUM_BLOCKS == 8
        quarter_round %%A_H_KS4, %%B_H_KS5, %%C_H_KS6, %%D_H_KS7
        column_to_diag %%B_H_KS5, %%C_H_KS6, %%D_H_KS7
        quarter_round %%A_H_KS4, %%B_H_KS5, %%C_H_KS6, %%D_H_KS7
        diag_to_column %%B_H_KS5, %%C_H_KS6, %%D_H_KS7
%endif
%endrep

        vpaddd %%A_L_KS0, %%STATE_IN_A_L
        vpaddd %%B_L_KS1, %%STATE_IN_B_L
        vpaddd %%C_L_KS2, %%STATE_IN_C_L
        vpaddd %%D_L_KS3, %%STATE_IN_D_L

        TRANSPOSE4_U128_INPLACE %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3, \
                                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3
%if %%NUM_BLOCKS == 8
        vpaddd %%A_H_KS4, %%STATE_IN_A_H
        vpaddd %%B_H_KS5, %%STATE_IN_B_H
        vpaddd %%C_H_KS6, %%STATE_IN_C_H
        vpaddd %%D_H_KS7, %%STATE_IN_D_H

        TRANSPOSE4_U128_INPLACE %%A_H_KS4, %%B_H_KS5, %%C_H_KS6, %%D_H_KS7, \
                                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3
%endif
%endmacro

;
; Encrypts up to 32 16-byte blocks of data
;
%macro ENCRYPT_4_32_PARALLEL 29
%define %%STATE_IN_A_L   %1  ;; [in] ZMM containing state "A" part
%define %%STATE_IN_B_L   %2  ;; [in] ZMM containing state "B" part
%define %%STATE_IN_C_L   %3  ;; [in] ZMM containing state "C" part
%define %%STATE_IN_D_L   %4  ;; [in] ZMM containing state "D" part
%define %%STATE_IN_A_H   %5  ;; [in] ZMM containing state "A" part (or "none" in NUM_BLOCKS == 4)
%define %%STATE_IN_B_H   %6  ;; [in] ZMM containing state "B" part (or "none" in NUM_BLOCKS == 4)
%define %%STATE_IN_C_H   %7  ;; [in] ZMM containing state "C" part (or "none" in NUM_BLOCKS == 4)
%define %%STATE_IN_D_H   %8  ;; [in] ZMM containing state "D" part (or "none" in NUM_BLOCKS == 4)
%define %%A_L_KS0        %9  ;; [out] ZMM A / Bytes 0-63    of KS
%define %%B_L_KS1        %10 ;; [out] ZMM B / Bytes 64-127  of KS
%define %%C_L_KS2        %11 ;; [out] ZMM C / Bytes 128-191 of KS
%define %%D_L_KS3        %12 ;; [out] ZMM D / Bytes 192-255 of KS
%define %%A_H_KS4        %13 ;; [out] ZMM A / Bytes 256-319 of KS (or "none" in NUM_BLOCKS == 4)
%define %%B_H_KS5        %14 ;; [out] ZMM B / Bytes 320-383 of KS (or "none" in NUM_BLOCKS == 4)
%define %%C_H_KS6        %15 ;; [out] ZMM C / Bytes 384-447 of KS (or "none" in NUM_BLOCKS == 4)
%define %%D_H_KS7        %16 ;; [out] ZMM D / Bytes 448-511 of KS (or "none" in NUM_BLOCKS == 4)
%define %%ZTMP0          %17 ;; [clobbered] Temp ZMM reg
%define %%ZTMP1          %18 ;; [clobbered] Temp ZMM reg
%define %%ZTMP2          %19 ;; [clobbered] Temp ZMM reg
%define %%ZTMP3          %20 ;; [clobbered] Temp ZMM reg
%define %%ZTMP4          %21 ;; [clobbered] Temp ZMM reg
%define %%ZTMP5          %22 ;; [clobbered] Temp ZMM reg
%define %%ZTMP6          %23 ;; [clobbered] Temp ZMM reg
%define %%ZTMP7          %24 ;; [clobbered] Temp ZMM reg
%define %%SRC            %25 ;; [in] Source pointer
%define %%DST            %26 ;; [in] Destination pointer
%define %%OFF            %27 ;; [in/out] Offset for source/destination pointers
%define %%KMASK          %28 ;; [in] Mask register
%define %%NUM_BLOCKS     %29 ;; [in] Number of 16-byte blocks of data to encrypt (4-32 in steps of 4)

%if %%NUM_BLOCKS > 16
        ; Generate 64*8 bytes of keystream
        GENERATE_KS %%STATE_IN_A_L, %%STATE_IN_B_L, %%STATE_IN_C_L, %%STATE_IN_D_L, \
                    %%STATE_IN_A_H, %%STATE_IN_B_H, %%STATE_IN_C_H, %%STATE_IN_D_H, \
                    %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3, \
                    %%A_H_KS4, %%B_H_KS5, %%C_H_KS6, %%D_H_KS7, \
                    %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, 8
%else
        ; Generate 64*4 bytes of keystream
        GENERATE_KS %%STATE_IN_A_L, %%STATE_IN_B_L, %%STATE_IN_C_L, %%STATE_IN_D_L, \
                    no_reg, no_reg, no_reg, no_reg, \
                    %%A_L_KS0, %%B_L_KS1, %%C_L_KS2, %%D_L_KS3, \
                    no_reg, no_reg, no_reg, no_reg, \
                    %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, 4
%endif ;; %%NUM_BLOCKS > 16

        ; Load plaintext (0-255 bytes)
%if %%NUM_BLOCKS < 16
        ZMM_LOAD_MASKED_BLOCKS_0_16 %%NUM_BLOCKS, %%SRC, %%OFF, %%ZTMP4, \
                                    %%ZTMP5, %%ZTMP6, %%ZTMP7, %%KMASK
%else
        ZMM_LOAD_BLOCKS_0_16 16, %%SRC, %%OFF, %%ZTMP4, \
                             %%ZTMP5, %%ZTMP6, %%ZTMP7
%endif

        ; XOR KS with plaintext and store resulting ciphertext
        vpxorq  %%ZTMP4, %%A_L_KS0
%if %%NUM_BLOCKS >= 8
        vpxorq  %%ZTMP5, %%B_L_KS1
%endif
%if %%NUM_BLOCKS >= 12
        vpxorq  %%ZTMP6, %%C_L_KS2
%endif
%if %%NUM_BLOCKS >= 16
        vpxorq  %%ZTMP7, %%D_L_KS3
%endif

%if %%NUM_BLOCKS < 16
        ZMM_STORE_MASKED_BLOCKS_0_16 %%NUM_BLOCKS, %%DST, %%OFF, %%ZTMP4, \
                                     %%ZTMP5, %%ZTMP6, %%ZTMP7, %%KMASK
%else
        ZMM_STORE_BLOCKS_0_16 16, %%DST, %%OFF, %%ZTMP4, \
                              %%ZTMP5, %%ZTMP6, %%ZTMP7
%endif

%if %%NUM_BLOCKS > 16
        ; Update offset into src/dst pointers
        add     off, 64*4
        ; Load plaintext (256-511 bytes)
        ZMM_LOAD_MASKED_BLOCKS_0_16 (%%NUM_BLOCKS - 16), %%SRC, %%OFF, %%ZTMP4, \
                                    %%ZTMP5, %%ZTMP6, %%ZTMP7, %%KMASK

        ; XOR KS with plaintext and store resulting ciphertext
        vpxorq  %%ZTMP4, %%A_H_KS4
%if %%NUM_BLOCKS >= 24
        vpxorq  %%ZTMP5, %%B_H_KS5
%endif
%if %%NUM_BLOCKS >= 28
        vpxorq  %%ZTMP6, %%C_H_KS6
%endif
%if %%NUM_BLOCKS == 32
        vpxorq  %%ZTMP7, %%D_H_KS7
%endif

        ZMM_STORE_MASKED_BLOCKS_0_16 (%%NUM_BLOCKS - 16), %%DST, %%OFF, %%ZTMP4, \
                                     %%ZTMP5, %%ZTMP6, %%ZTMP7, %%KMASK
        ; Update offset into src/dst pointers
        add     off, 64*4
%endif ;; %%NUM_BLOCKS > 16
%endmacro

align 32
MKGLOBAL(submit_job_chacha20_enc_dec_avx512,function,internal)
submit_job_chacha20_enc_dec_avx512:

%define src     r8
%define dst     r9
%define len     r10
%define tmp     r11
%define tmp2    rax
%define tmp3    rdx
%ifdef LINUX
%define off     rcx
%else
%define off     r12
%endif
        FUNC_SAVE

        ; Prepare first 4 chacha states from IV, key
        mov       tmp, [job + _enc_keys]
        vbroadcastf64x2  zmm1, [tmp]            ; Load key bytes 0-15
        vbroadcastf64x2  zmm2, [tmp + 16]       ; Load key bytes 16-31
        mov       rax, 0xfff
        kmovq     k1, rax
        mov       tmp, [job + _iv]
        vmovdqu8  xmm3{k1}, [tmp]               ; Load Nonce (12 bytes)
        vpslldq   xmm3, 4
        vshufi64x2 zmm3, zmm3, 0                ; Brodcast 128 bits to 512 bits
        vbroadcastf64x2 zmm0, [rel constants]

        ;; Prepare chacha states 4-7
        vmovdqa64 zmm4, zmm0
        vmovdqa64 zmm5, zmm1
        vmovdqa64 zmm6, zmm2
        vmovdqa64 zmm7, zmm3

        vporq      zmm3, [rel set_1_4]          ; Set first 4 block counters
        vporq      zmm7, [rel set_5_8]          ; Set next 4 block counters

        xor     off, off

        mov     rax, 0xffffffffffffffff
        kmovq   k1, rax

        mov     len, [job + _msg_len_to_cipher_in_bytes]
        mov     src, [job + _src]
        add     src, [job + _cipher_start_src_offset_in_bytes]

        mov     dst, [job + _dst]
start_loop:
        cmp     len, 128*4
        jb      exit_loop

        ENCRYPT_4_32_PARALLEL zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                              zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                              zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                              src, dst, off, k1, 32

        ; Update remaining length
        sub     len, 128*4

        ; Increment block counters
        vpaddd  zmm3, [rel add_8]
        vpaddd  zmm7, [rel add_8]

        jmp     start_loop

exit_loop:

        ; Check if there are partial block (less than 256 bytes)
        or      len, len
        jz      no_partial_block

        ; Calculate mask if there is a partial block
        mov     tmp, len
        and     tmp, 63
        or      tmp, tmp ;; if 0, no partial block and no need to update k mask
        jz      _no_mask_update

        ; Load mask to read/write partial block
        SHIFT_GP 1, tmp, tmp2, tmp3, left
        dec     tmp2
        or      tmp2, tmp2 ;; if 0, no partial block and no need to update k mask
        kmovq   k1, tmp2
_no_mask_update:
        ; Check how many 64-byte blocks are left (including partial block)

%assign i 1
%rep 7
        cmp     len, 64*i
        jbe     APPEND(blocks_left_, i)
%assign i (i+1)
%endrep

%assign i 8
%rep 8
APPEND(blocks_left_, i):
        ENCRYPT_4_32_PARALLEL zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                              zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                              zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                              src, dst, off, k1, (i*4)
%if (i != 1)
        jmp no_partial_block
%endif
%assign i (i-1)
%endrep

no_partial_block:

        mov     rax, job
        or      dword [rax + _status], STS_COMPLETED_AES

        FUNC_RESTORE

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
