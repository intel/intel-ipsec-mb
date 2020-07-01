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
add_4:
dd      0x00000004, 0x00000000, 0x00000000, 0x00000000
dd      0x00000004, 0x00000000, 0x00000000, 0x00000000
dd      0x00000004, 0x00000000, 0x00000000, 0x00000000
dd      0x00000004, 0x00000000, 0x00000000, 0x00000000

align 64
set_1_4:
dd      0x00000001, 0x00000000, 0x00000000, 0x00000000
dd      0x00000002, 0x00000000, 0x00000000, 0x00000000
dd      0x00000003, 0x00000000, 0x00000000, 0x00000000
dd      0x00000004, 0x00000000, 0x00000000, 0x00000000

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
;; Generates 64*4 bytes of keystream
;;
%macro GENERATE_KS 12
%define %%STATE_IN_A   %1  ;; [in] ZMM containing state "A" part
%define %%STATE_IN_B   %2  ;; [in] ZMM containing state "B" part
%define %%STATE_IN_C   %3  ;; [in] ZMM containing state "C" part
%define %%STATE_IN_D   %4  ;; [in] ZMM containing state "D" part
%define %%A_KS0        %5  ;; [out] ZMM A / Bytes 0-63    of KS
%define %%B_KS1        %6  ;; [out] ZMM B / Bytes 64-127  of KS
%define %%C_KS2        %7  ;; [out] ZMM C / Bytes 128-191 of KS
%define %%D_KS3        %8  ;; [out] ZMM D / Bytes 192-255 of KS
%define %%ZTMP0        %9  ;; [clobbered] Temp ZMM reg
%define %%ZTMP1        %10 ;; [clobbered] Temp ZMM reg
%define %%ZTMP2        %11 ;; [clobbered] Temp ZMM reg
%define %%ZTMP3        %12 ;; [clobbered] Temp ZMM reg

        vmovdqa64       %%A_KS0, %%STATE_IN_A
        vmovdqa64       %%B_KS1, %%STATE_IN_B
        vmovdqa64       %%C_KS2, %%STATE_IN_C
        vmovdqa64       %%D_KS3, %%STATE_IN_D
%rep 10
        quarter_round %%A_KS0, %%B_KS1, %%C_KS2, %%D_KS3
        column_to_diag %%B_KS1, %%C_KS2, %%D_KS3
        quarter_round %%A_KS0, %%B_KS1, %%C_KS2, %%D_KS3
        diag_to_column %%B_KS1, %%C_KS2, %%D_KS3
%endrep

        vpaddd %%A_KS0, %%STATE_IN_A
        vpaddd %%B_KS1, %%STATE_IN_B
        vpaddd %%C_KS2, %%STATE_IN_C
        vpaddd %%D_KS3, %%STATE_IN_D

        TRANSPOSE4_U128_INPLACE %%A_KS0, %%B_KS1, %%C_KS2, %%D_KS3, \
                                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3
%endmacro

;
; Encrypts up to 16 16-byte blocks of data
;
%macro ENCRYPT_4_16_PARALLEL 21
%define %%STATE_IN_A    %1  ;; [in] ZMM containing state "A" part
%define %%STATE_IN_B    %2  ;; [in] ZMM containing state "B" part
%define %%STATE_IN_C    %3  ;; [in] ZMM containing state "C" part
%define %%STATE_IN_D    %4  ;; [in] ZMM containing state "D" part
%define %%A_KS0         %5  ;; [out] ZMM A / Bytes 0-63    of KS
%define %%B_KS1         %6  ;; [out] ZMM B / Bytes 64-127  of KS
%define %%C_KS2         %7  ;; [out] ZMM C / Bytes 128-191 of KS
%define %%D_KS3         %8  ;; [out] ZMM D / Bytes 192-255 of KS
%define %%ZTMP0         %9  ;; [clobbered] Temp ZMM reg
%define %%ZTMP1         %10 ;; [clobbered] Temp ZMM reg
%define %%ZTMP2         %11 ;; [clobbered] Temp ZMM reg
%define %%ZTMP3         %12 ;; [clobbered] Temp ZMM reg
%define %%ZTMP4         %13 ;; [clobbered] Temp ZMM reg
%define %%ZTMP5         %14 ;; [clobbered] Temp ZMM reg
%define %%ZTMP6         %15 ;; [clobbered] Temp ZMM reg
%define %%ZTMP7         %16 ;; [clobbered] Temp ZMM reg
%define %%SRC           %17 ;; [in] Source pointer
%define %%DST           %18 ;; [in] Destination pointer
%define %%OFF           %19 ;; [in] Offset for source/destination pointers
%define %%KMASK         %20 ;; [in] Mask register
%define %%NUM_BLOCKS    %21 ;; [in] Number of 16-byte blocks of data to encrypt (4, 8, 12, 16)

        ; Generate 64*4 bytes of keystream
        GENERATE_KS %%STATE_IN_A, %%STATE_IN_B, %%STATE_IN_C, %%STATE_IN_D, \
                    %%A_KS0, %%B_KS1, %%C_KS2, %%D_KS3, \
                    %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ; Load plaintext
        ZMM_LOAD_MASKED_BLOCKS_0_16 %%NUM_BLOCKS, %%SRC, %%OFF, %%ZTMP4, \
                                    %%ZTMP5, %%ZTMP6, %%ZTMP7, %%KMASK

        ; XOR KS with plaintext and store resulting ciphertext
%if %%NUM_BLOCKS >= 4
        vpxorq  %%ZTMP4, %%A_KS0
%endif
%if %%NUM_BLOCKS >= 8
        vpxorq  %%ZTMP5, %%B_KS1
%endif
%if %%NUM_BLOCKS >= 12
        vpxorq  %%ZTMP6, %%C_KS2
%endif
%if %%NUM_BLOCKS == 16
        vpxorq  %%ZTMP7, %%D_KS3
%endif

        ZMM_STORE_MASKED_BLOCKS_0_16 %%NUM_BLOCKS, %%DST, %%OFF, %%ZTMP4, \
                                     %%ZTMP5, %%ZTMP6, %%ZTMP7, %%KMASK
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
        vporq      zmm3, [rel set_1_4]          ; Set first 4 block counters
        vbroadcastf64x2 zmm0, [rel constants]

        xor     off, off

        mov     rax, 0xffffffffffffffff
        kmovq   k1, rax

        mov     len, [job + _msg_len_to_cipher_in_bytes]
        mov     src, [job + _src]
        add     src, [job + _cipher_start_src_offset_in_bytes]

        mov     dst, [job + _dst]
start_loop:
        cmp     len, 64*4
        jb      exit_loop

        ENCRYPT_4_16_PARALLEL zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                              zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                              src, dst, off, k1, 16
        ; Update remaining length and src/dst index
        sub     len, 64*4
        add     off, 64*4

        ; Increment block counters
        vpaddd  zmm3, [rel add_4]

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
        cmp     len, 64
        jbe     _1_block_left

        cmp     len, 128
        jbe     _2_blocks_left

        cmp     len, 192
        jbe     _3_blocks_left

_4_blocks_left:
        ENCRYPT_4_16_PARALLEL zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                              zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                              src, dst, off, k1, 16
        jmp no_partial_block

_3_blocks_left:
        ENCRYPT_4_16_PARALLEL zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                              zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                              src, dst, off, k1, 12

        jmp no_partial_block

_2_blocks_left:
        ENCRYPT_4_16_PARALLEL zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                              zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                              src, dst, off, k1, 8

        jmp no_partial_block

_1_block_left:
        ENCRYPT_4_16_PARALLEL zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                              zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                              src, dst, off, k1, 4

no_partial_block:

        mov     rax, job
        or      dword [rax + _status], STS_COMPLETED_AES

        FUNC_RESTORE

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
