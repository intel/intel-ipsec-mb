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

section .data
default rel

align 64
constants:
dd      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

align 64
add_1:
dd      0x00000000, 0x00000000, 0x00000000, 0x00000000
dd      0x00000000, 0x00000000, 0x00000000, 0x00000000
dd      0x00000000, 0x00000000, 0x00000000, 0x00000000
dd      0x00000001, 0x00000000, 0x00000000, 0x00000000

%ifdef LINUX
%define arg1    rdi
%else
%define arg1    rcx
%endif

%define job     arg1

section .text

;;
;; Performs a quarter round on all 4 columns,
;; resulting in a full round
;;
%macro quarter_round 4
%define %%A %1 ;; [in/out] XMM register containing value A of all 4 columns
%define %%B %2 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C %3 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D %4 ;; [in/out] XMM register containing value D of all 4 columns

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
%define %%B %1 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] XMM register containing value D of all 4 columns

        vpshufd         %%B, %%B, 0x39 ; 0b00111001 ;; 0,3,2,1
        vpshufd         %%C, %%C, 0x4E ; 0b01001110 ;; 1,0,3,2
        vpshufd         %%D, %%D, 0x93 ; 0b10010011 ;; 2,1,0,3

%endmacro

;;
;; Rotates the registers to prepare the data
;; from diagonal round to column round
;;
%macro diag_to_column 3
%define %%B %1 ;; [in/out] XMM register containing value B of all 4 columns
%define %%C %2 ;; [in/out] XMM register containing value C of all 4 columns
%define %%D %3 ;; [in/out] XMM register containing value D of all 4 columns

        vpshufd         %%B, %%B, 0x93 ; 0b10010011 ; 2,1,0,3
        vpshufd         %%C, %%C, 0x4E ; 0b01001110 ;  1,0,3,2
        vpshufd         %%D, %%D, 0x39 ; 0b00111001 ;  0,3,2,1

%endmacro

;;
;; Generates 64 bytes of keystream
;;
%macro generate_ks 7
%define %%STATE_IN      %1  ;; [in] ZMM containing state
%define %%KS            %2  ;; [out] ZMM to contain Keystream
%define %%ZTMP          %3  ;; [clobbered] Temp ZMM reg
%define %%A             %4  ;; [clobbered] XMM A
%define %%B             %5  ;; [clobbered] XMM B
%define %%C             %6  ;; [clobbered] XMM C
%define %%D             %7  ;; [clobbered] XMM D

        vmovdqa64        %%A, XWORD(%%STATE_IN)
        vextracti64x2   %%B, %%STATE_IN, 1
        vextracti64x2   %%C, %%STATE_IN, 2
        vextracti64x2   %%D, %%STATE_IN, 3
%rep 10
        quarter_round %%A, %%B, %%C, %%D
        column_to_diag %%B, %%C, %%D
        quarter_round %%A, %%B, %%C, %%D
        diag_to_column %%B, %%C, %%D
%endrep

        vmovdqa64       %%ZTMP, ZWORD(%%A)
        vinserti64x2   %%ZTMP, %%B, 1
        vinserti64x2   %%ZTMP, %%C, 2
        vinserti64x2   %%ZTMP, %%D, 3

        vpaddd %%KS, %%STATE_IN, %%ZTMP
%endmacro

align 32
MKGLOBAL(submit_job_chacha20_enc_dec_avx512,function,internal)
submit_job_chacha20_enc_dec_avx512:

%define src     r8
%define dst     r9
%define len     r10
%define tmp     r11
%define tmp2    rax

        ; Prepare chacha state from IV, key
        mov       tmp, [job + _enc_keys]
        vmovdqu64 xmm1, [tmp]          ; Load key bytes 0-15
        vmovdqu64 xmm2, [tmp + 16]     ; Load key bytes 16-31
        mov       rax, 0xfff
        kmovq     k1, rax
        mov       tmp, [job + _iv]
        vmovdqu8  xmm3{k1}, [tmp]          ; Load Nonce (12 bytes)
        vpslldq   xmm3, 4
        vmovdqu64 xmm0, [rel constants]

        vinserti64x2   zmm0, xmm1, 1
        vinserti64x2   zmm0, xmm2, 2
        vinserti64x2   zmm0, xmm3, 3

        mov     len, [job + _msg_len_to_cipher_in_bytes]
        mov     src, [job + _src]
        add     src, [job + _cipher_start_src_offset_in_bytes]

        mov     dst, [job + _dst]
start_loop:
        cmp     len, 64
        jb      exit_loop

        ; Increment block counter and generate 64 bytes of keystream
        vpaddd  zmm0, [rel add_1]
        generate_ks zmm0, zmm1, zmm2, xmm3, xmm4, xmm5, xmm6

        ; Load plaintext
        vmovdqu64 zmm7, [src]

        ; XOR KS with plaintext and store resulting ciphertext
        vpxorq  zmm7, zmm1
        vmovdqu64 [dst], zmm7

        ; Update pointers
        add     src, 64
        add     dst, 64

        sub     len, 64

        jmp     start_loop

exit_loop:

        ; Check if there are partial block (less than 64 bytes)
        or      len, len
        jz      no_partial_block

        ; Load mask to read/write partial block
        SHIFT_GP 1, len, tmp, tmp2, left
        dec     tmp
        kmovq   k1, tmp

        ; Increment block counter and generate 64 bytes of keystream
        vpaddd  zmm0, [rel add_1]
        generate_ks zmm0, zmm1, zmm2, xmm3, xmm4, xmm5, xmm6

        ; Load plaintext
        vmovdqu8 zmm7{k1}, [src]

        ; XOR KS with plaintext and store resulting ciphertext
        vpxorq  zmm7, zmm1
        vmovdqu8 [dst]{k1}, zmm7

no_partial_block:

        mov     rax, job
        or      dword [rax + _status], STS_COMPLETED_AES

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
