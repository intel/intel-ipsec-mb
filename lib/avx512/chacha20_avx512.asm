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
add_16:
dd      0x00000010, 0x00000010, 0x00000010, 0x00000010
dd      0x00000010, 0x00000010, 0x00000010, 0x00000010
dd      0x00000010, 0x00000010, 0x00000010, 0x00000010
dd      0x00000010, 0x00000010, 0x00000010, 0x00000010

align 64
set_1_16:
dd      0x00000001, 0x00000002, 0x00000003, 0x00000004
dd      0x00000005, 0x00000006, 0x00000007, 0x00000008
dd      0x00000009, 0x0000000a, 0x0000000b, 0x0000000c
dd      0x0000000d, 0x0000000e, 0x0000000f, 0x00000010

align 64
len_to_mask:
dq      0xffffffffffffffff, 0x0000000000000001
dq      0x0000000000000003, 0x0000000000000007
dq      0x000000000000000f, 0x000000000000001f
dq      0x000000000000003f, 0x000000000000007f
dq      0x00000000000000ff, 0x00000000000001ff
dq      0x00000000000003ff, 0x00000000000007ff
dq      0x0000000000000fff, 0x0000000000001fff
dq      0x0000000000003fff, 0x0000000000007fff
dq      0x000000000000ffff, 0x000000000001ffff
dq      0x000000000003ffff, 0x000000000007ffff
dq      0x00000000000fffff, 0x00000000001fffff
dq      0x00000000003fffff, 0x00000000007fffff
dq      0x0000000000ffffff, 0x0000000001ffffff
dq      0x0000000003ffffff, 0x0000000007ffffff
dq      0x000000000fffffff, 0x000000001fffffff
dq      0x000000003fffffff, 0x000000007fffffff
dq      0x00000000ffffffff, 0x00000001ffffffff
dq      0x00000003ffffffff, 0x00000007ffffffff
dq      0x0000000fffffffff, 0x0000001fffffffff
dq      0x0000003fffffffff, 0x0000007fffffffff
dq      0x000000ffffffffff, 0x000001ffffffffff
dq      0x000003ffffffffff, 0x000007ffffffffff
dq      0x00000fffffffffff, 0x00001fffffffffff
dq      0x00003fffffffffff, 0x00007fffffffffff
dq      0x0000ffffffffffff, 0x0001ffffffffffff
dq      0x0003ffffffffffff, 0x0007ffffffffffff
dq      0x000fffffffffffff, 0x001fffffffffffff
dq      0x003fffffffffffff, 0x007fffffffffffff
dq      0x00ffffffffffffff, 0x01ffffffffffffff
dq      0x03ffffffffffffff, 0x07ffffffffffffff
dq      0x0fffffffffffffff, 0x1fffffffffffffff
dq      0x3fffffffffffffff, 0x7fffffffffffffff

%define APPEND(a,b) a %+ b

%ifdef LINUX
%define arg1    rdi
%else
%define arg1    rcx
%endif

%define job     arg1

section .text

%macro ZMM_OP_X4 9
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 16, %1,%2,%3,%4,%5,%2,%3,%4,%5,%6,%7,%8,%9
%endmacro

%macro ZMM_ROLS_X4 5
%define %%ZMM_OP1_1      %1
%define %%ZMM_OP1_2      %2
%define %%ZMM_OP1_3      %3
%define %%ZMM_OP1_4      %4
%define %%BITS_TO_ROTATE %5

        vprold  %%ZMM_OP1_1, %%BITS_TO_ROTATE
        vprold  %%ZMM_OP1_2, %%BITS_TO_ROTATE
        vprold  %%ZMM_OP1_3, %%BITS_TO_ROTATE
        vprold  %%ZMM_OP1_4, %%BITS_TO_ROTATE

%endmacro

;;
;; Performs a full chacha20 round on 16 states,
;; consisting of 4 quarter rounds, which are done in parallel
;;
%macro CHACHA20_ROUND 16
%define %%ZMM_DWORD_A1  %1  ;; [in/out] ZMM register containing dword A for first quarter round
%define %%ZMM_DWORD_A2  %2  ;; [in/out] ZMM register containing dword A for second quarter round
%define %%ZMM_DWORD_A3  %3  ;; [in/out] ZMM register containing dword A for third quarter round
%define %%ZMM_DWORD_A4  %4  ;; [in/out] ZMM register containing dword A for fourth quarter round
%define %%ZMM_DWORD_B1  %5  ;; [in/out] ZMM register containing dword B for first quarter round
%define %%ZMM_DWORD_B2  %6  ;; [in/out] ZMM register containing dword B for second quarter round
%define %%ZMM_DWORD_B3  %7  ;; [in/out] ZMM register containing dword B for third quarter round
%define %%ZMM_DWORD_B4  %8  ;; [in/out] ZMM register containing dword B for fourth quarter round
%define %%ZMM_DWORD_C1  %9  ;; [in/out] ZMM register containing dword C for first quarter round
%define %%ZMM_DWORD_C2 %10  ;; [in/out] ZMM register containing dword C for second quarter round
%define %%ZMM_DWORD_C3 %11  ;; [in/out] ZMM register containing dword C for third quarter round
%define %%ZMM_DWORD_C4 %12  ;; [in/out] ZMM register containing dword C for fourth quarter round
%define %%ZMM_DWORD_D1 %13  ;; [in/out] ZMM register containing dword D for first quarter round
%define %%ZMM_DWORD_D2 %14  ;; [in/out] ZMM register containing dword D for second quarter round
%define %%ZMM_DWORD_D3 %15  ;; [in/out] ZMM register containing dword D for third quarter round
%define %%ZMM_DWORD_D4 %16  ;; [in/out] ZMM register containing dword D for fourth quarter round

        ; A += B
        ZMM_OP_X4 vpaddd, %%ZMM_DWORD_A1, %%ZMM_DWORD_A2, %%ZMM_DWORD_A3, %%ZMM_DWORD_A4, \
                          %%ZMM_DWORD_B1, %%ZMM_DWORD_B2, %%ZMM_DWORD_B3, %%ZMM_DWORD_B4
        ; D ^= A
        ZMM_OP_X4 vpxorq, %%ZMM_DWORD_D1, %%ZMM_DWORD_D2, %%ZMM_DWORD_D3, %%ZMM_DWORD_D4, \
                          %%ZMM_DWORD_A1, %%ZMM_DWORD_A2, %%ZMM_DWORD_A3, %%ZMM_DWORD_A4

        ; D <<< 16
        ZMM_ROLS_X4 %%ZMM_DWORD_D1, %%ZMM_DWORD_D2, %%ZMM_DWORD_D3, %%ZMM_DWORD_D4, 16

        ; C += D
        ZMM_OP_X4 vpaddd, %%ZMM_DWORD_C1, %%ZMM_DWORD_C2, %%ZMM_DWORD_C3, %%ZMM_DWORD_C4, \
                          %%ZMM_DWORD_D1, %%ZMM_DWORD_D2, %%ZMM_DWORD_D3, %%ZMM_DWORD_D4
        ; B ^= C
        ZMM_OP_X4 vpxorq, %%ZMM_DWORD_B1, %%ZMM_DWORD_B2, %%ZMM_DWORD_B3, %%ZMM_DWORD_B4, \
                          %%ZMM_DWORD_C1, %%ZMM_DWORD_C2, %%ZMM_DWORD_C3, %%ZMM_DWORD_C4

        ; B <<< 12
        ZMM_ROLS_X4 %%ZMM_DWORD_B1, %%ZMM_DWORD_B2, %%ZMM_DWORD_B3, %%ZMM_DWORD_B4, 12

        ; A += B
        ZMM_OP_X4 vpaddd, %%ZMM_DWORD_A1, %%ZMM_DWORD_A2, %%ZMM_DWORD_A3, %%ZMM_DWORD_A4, \
                          %%ZMM_DWORD_B1, %%ZMM_DWORD_B2, %%ZMM_DWORD_B3, %%ZMM_DWORD_B4
        ; D ^= A
        ZMM_OP_X4 vpxorq, %%ZMM_DWORD_D1, %%ZMM_DWORD_D2, %%ZMM_DWORD_D3, %%ZMM_DWORD_D4, \
                          %%ZMM_DWORD_A1, %%ZMM_DWORD_A2, %%ZMM_DWORD_A3, %%ZMM_DWORD_A4

        ; D <<< 8
        ZMM_ROLS_X4 %%ZMM_DWORD_D1, %%ZMM_DWORD_D2, %%ZMM_DWORD_D3, %%ZMM_DWORD_D4, 8

        ; C += D
        ZMM_OP_X4 vpaddd, %%ZMM_DWORD_C1, %%ZMM_DWORD_C2, %%ZMM_DWORD_C3, %%ZMM_DWORD_C4, \
                          %%ZMM_DWORD_D1, %%ZMM_DWORD_D2, %%ZMM_DWORD_D3, %%ZMM_DWORD_D4
        ; B ^= C
        ZMM_OP_X4 vpxorq, %%ZMM_DWORD_B1, %%ZMM_DWORD_B2, %%ZMM_DWORD_B3, %%ZMM_DWORD_B4, \
                          %%ZMM_DWORD_C1, %%ZMM_DWORD_C2, %%ZMM_DWORD_C3, %%ZMM_DWORD_C4

        ; B <<< 7
        ZMM_ROLS_X4 %%ZMM_DWORD_B1, %%ZMM_DWORD_B2, %%ZMM_DWORD_B3, %%ZMM_DWORD_B4, 7
%endmacro

;;
;; Generates 64*16 bytes of keystream
;;
%macro GENERATE_KS 32
%define %%ZMM_DWORD0       %1   ;; [out] ZMM containing dword 0 of all states and bytes 0-63 of keystream
%define %%ZMM_DWORD1       %2   ;; [out] ZMM containing dword 1 of all states and bytes 64-127 of keystream
%define %%ZMM_DWORD2       %3   ;; [out] ZMM containing dword 2 of all states and bytes 128-191 of keystream
%define %%ZMM_DWORD3       %4   ;; [out] ZMM containing dword 3 of all states and bytes 192-255 of keystream
%define %%ZMM_DWORD4       %5   ;; [out] ZMM containing dword 4 of all states and bytes 256-319 of keystream
%define %%ZMM_DWORD5       %6   ;; [out] ZMM containing dword 5 of all states and bytes 320-383 of keystream
%define %%ZMM_DWORD6       %7   ;; [out] ZMM containing dword 6 of all states and bytes 384-447 of keystream
%define %%ZMM_DWORD7       %8   ;; [out] ZMM containing dword 7 of all states and bytes 448-511 of keystream
%define %%ZMM_DWORD8       %9   ;; [out] ZMM containing dword 8 of all states and bytes 512-575 of keystream
%define %%ZMM_DWORD9       %10  ;; [out] ZMM containing dword 9 of all states and bytes 576-639 of keystream
%define %%ZMM_DWORD10      %11  ;; [out] ZMM containing dword 10 of all states and bytes 640-703 of keystream
%define %%ZMM_DWORD11      %12  ;; [out] ZMM containing dword 11 of all states and bytes 704-767 of keystream
%define %%ZMM_DWORD12      %13  ;; [out] ZMM containing dword 12 of all states and bytes 768-831 of keystream
%define %%ZMM_DWORD13      %14  ;; [out] ZMM containing dword 13 of all states and bytes 832-895 of keystream
%define %%ZMM_DWORD14      %15  ;; [out] ZMM containing dword 14 of all states and bytes 896-959 of keystream
%define %%ZMM_DWORD15      %16  ;; [out] ZMM containing dword 15 of all states and bytes 960-1023 of keystream
%define %%ZMM_DWORD_ORIG0  %17  ;; [in/clobbered] ZMM containing dword 0 of all states
%define %%ZMM_DWORD_ORIG1  %18  ;; [in/clobbered] ZMM containing dword 1 of all states
%define %%ZMM_DWORD_ORIG2  %19  ;; [in/clobbered] ZMM containing dword 2 of all states
%define %%ZMM_DWORD_ORIG3  %20  ;; [in/clobbered] ZMM containing dword 3 of all states
%define %%ZMM_DWORD_ORIG4  %21  ;; [in/clobbered] ZMM containing dword 4 of all states
%define %%ZMM_DWORD_ORIG5  %22  ;; [in/clobbered] ZMM containing dword 5 of all states
%define %%ZMM_DWORD_ORIG6  %23  ;; [in/clobbered] ZMM containing dword 6 of all states
%define %%ZMM_DWORD_ORIG7  %24  ;; [in/clobbered] ZMM containing dword 7 of all states
%define %%ZMM_DWORD_ORIG8  %25  ;; [in/clobbered] ZMM containing dword 8 of all states
%define %%ZMM_DWORD_ORIG9  %26  ;; [in/clobbered] ZMM containing dword 9 of all states
%define %%ZMM_DWORD_ORIG10 %27  ;; [in/clobbered] ZMM containing dword 10 of all states
%define %%ZMM_DWORD_ORIG11 %28  ;; [in/clobbered] ZMM containing dword 11 of all states
%define %%ZMM_DWORD_ORIG12 %29  ;; [in] ZMM containing dword 12 of all states
%define %%ZMM_DWORD_ORIG13 %30  ;; [in/clobbered] ZMM containing dword 13 of all states
%define %%ZMM_DWORD_ORIG14 %31  ;; [in/clobbered] ZMM containing dword 14 of all states
%define %%ZMM_DWORD_ORIG15 %32  ;; [in] ZMM containing dword 15 of all states

%assign i 0
%rep 16
        vmovdqa64 APPEND(%%ZMM_DWORD, i), APPEND(%%ZMM_DWORD_ORIG, i)
%assign i (i + 1)
%endrep

%rep 10

        ;;; Each full round consists of 8 quarter rounds, 4 column rounds and 4 diagonal rounds
        ;;; For first 4 column rounds:
        ;;; A = 0, 1, 2, 3;   B = 4, 5, 6, 7;
        ;;; C = 8, 9, 10, 11; D = 12, 13, 14, 15
        CHACHA20_ROUND %%ZMM_DWORD0, %%ZMM_DWORD1, %%ZMM_DWORD2, %%ZMM_DWORD3, \
                       %%ZMM_DWORD4, %%ZMM_DWORD5, %%ZMM_DWORD6, %%ZMM_DWORD7, \
                       %%ZMM_DWORD8, %%ZMM_DWORD9, %%ZMM_DWORD10, %%ZMM_DWORD11, \
                       %%ZMM_DWORD12, %%ZMM_DWORD13, %%ZMM_DWORD14, %%ZMM_DWORD15
        ;;; For 4 diagonal rounds:
        ;;; A = 0, 1, 2, 3;   B = 5, 6, 7, 4;
        ;;; C = 10, 11, 8, 9; D = 15, 12, 13, 14
        CHACHA20_ROUND %%ZMM_DWORD0, %%ZMM_DWORD1, %%ZMM_DWORD2, %%ZMM_DWORD3, \
                       %%ZMM_DWORD5, %%ZMM_DWORD6, %%ZMM_DWORD7, %%ZMM_DWORD4, \
                       %%ZMM_DWORD10, %%ZMM_DWORD11, %%ZMM_DWORD8, %%ZMM_DWORD9, \
                       %%ZMM_DWORD15, %%ZMM_DWORD12, %%ZMM_DWORD13, %%ZMM_DWORD14
%endrep

%assign %%I 0
%rep 16
        vpaddd APPEND(%%ZMM_DWORD, %%I), APPEND(%%ZMM_DWORD_ORIG, %%I)
%assign %%I (%%I + 1)
%endrep

        ;; Transpose states to form the 64*16 bytes of keystream
        ;; (ZMM_DWORD_ORIG12 is skipped, since that contains the counter values,
        ;; that should be preserved)
        TRANSPOSE16_U32 %%ZMM_DWORD0, %%ZMM_DWORD1, %%ZMM_DWORD2, %%ZMM_DWORD3, \
                        %%ZMM_DWORD4, %%ZMM_DWORD5, %%ZMM_DWORD6, %%ZMM_DWORD7, \
                        %%ZMM_DWORD8, %%ZMM_DWORD9, %%ZMM_DWORD10, %%ZMM_DWORD11, \
                        %%ZMM_DWORD12, %%ZMM_DWORD13, %%ZMM_DWORD14, %%ZMM_DWORD15, \
                        %%ZMM_DWORD_ORIG0, %%ZMM_DWORD_ORIG1, %%ZMM_DWORD_ORIG2, %%ZMM_DWORD_ORIG3, \
                        %%ZMM_DWORD_ORIG4, %%ZMM_DWORD_ORIG5, %%ZMM_DWORD_ORIG6, %%ZMM_DWORD_ORIG7, \
                        %%ZMM_DWORD_ORIG8, %%ZMM_DWORD_ORIG9, %%ZMM_DWORD_ORIG10, %%ZMM_DWORD_ORIG11, \
                        %%ZMM_DWORD_ORIG13, %%ZMM_DWORD_ORIG14
%endmacro

%macro ENCRYPT_1_16_BLOCKS 22
%define %%KS0         %1 ; [in/clobbered] Bytes 0-63 of keystream
%define %%KS1         %2 ; [in/clobbered] Bytes 64-127 of keystream
%define %%KS2         %3 ; [in/clobbered] Bytes 128-191 of keystream
%define %%KS3         %4 ; [in/clobbered] Bytes 192-255 of keystream
%define %%KS4         %5 ; [in/clobbered] Bytes 256-319 of keystream
%define %%KS5         %6 ; [in/clobbered] Bytes 320-383 of keystream
%define %%KS6         %7 ; [in/clobbered] Bytes 384-447 of keystream
%define %%KS7         %8 ; [in/clobbered] Bytes 448-511 of keystream
%define %%KS8         %9 ; [in/clobbered] Bytes 512-575 of keystream
%define %%KS9        %10 ; [in/clobbered] Bytes 576-639 of keystream
%define %%KS10       %11 ; [in/clobbered] Bytes 640-703 of keystream
%define %%KS11       %12 ; [in/clobbered] Bytes 704-767 of keystream
%define %%KS12       %13 ; [in/clobbered] Bytes 768-831 of keystream
%define %%KS13       %14 ; [in/clobbered] Bytes 832-895 of keystream
%define %%KS14       %15 ; [in/clobbered] Bytes 896-959 of keystream
%define %%KS15       %16 ; [in/clobbered] Bytes 960-1023 of keystream
%define %%ZTMP       %17 ; [clobbered] Temporary ZMM register
%define %%SRC        %18 ; [in] Source pointer
%define %%DST        %19 ; [in] Destination pointer
%define %%OFF        %20 ; [in] Offset into src/dst pointers
%define %%KMASK      %21 ; [in] Mask register for final block
%define %%NUM_BLOCKS %22 ; [in] Number of blocks to encrypt

        ; XOR Keystreams with blocks of input data
%assign %%I 0
%rep (%%NUM_BLOCKS - 1)
        vpxorq    APPEND(%%KS, %%I), [%%SRC + %%OFF + 64*%%I]
%assign %%I (%%I + 1)
%endrep
        ; Final block which might have less than 64 bytes, so mask register is used
        vmovdqu8 %%ZTMP{%%KMASK}, [%%SRC + %%OFF + 64*%%I]
        vpxorq  APPEND(%%KS, %%I), %%ZTMP

        ; Write out blocks of ciphertext
%assign %%I 0
%rep (%%NUM_BLOCKS - 1)
        vmovdqu8 [%%DST + %%OFF + 64*%%I], APPEND(%%KS, %%I)
%assign %%I (%%I + 1)
%endrep
        vmovdqu8 [%%DST + %%OFF + 64*%%I]{%%KMASK}, APPEND(%%KS, %%I)
%endmacro

align 32
MKGLOBAL(submit_job_chacha20_enc_dec_avx512,function,internal)
submit_job_chacha20_enc_dec_avx512:

%define src     r8
%define dst     r9
%define len     r10
%define iv      r11
%define tmp     r11
%define keys    rdx
%define tmp2    rdx
%define off     rax

        xor     off, off

        mov     tmp, 0xffffffffffffffff
        kmovq   k1, tmp

        mov     len, [job + _msg_len_to_cipher_in_bytes]
        mov     src, [job + _src]
        add     src, [job + _cipher_start_src_offset_in_bytes]
        mov     dst, [job + _dst]
        mov     keys, [job + _enc_keys]
        mov     iv, [job + _iv]

        ; Prepare first 16 chacha20 states from IV, key, constants and counter values
        vpbroadcastd zmm0, [rel constants]
        vpbroadcastd zmm1, [rel constants + 4]
        vpbroadcastd zmm2, [rel constants + 8]
        vpbroadcastd zmm3, [rel constants + 12]

        vpbroadcastd zmm4, [keys]
        vpbroadcastd zmm5, [keys + 4]
        vpbroadcastd zmm6, [keys + 8]
        vpbroadcastd zmm7, [keys + 12]
        vpbroadcastd zmm8, [keys + 16]
        vpbroadcastd zmm9, [keys + 20]
        vpbroadcastd zmm10, [keys + 24]
        vpbroadcastd zmm11, [keys + 28]

        vpbroadcastd zmm13, [iv]
        vpbroadcastd zmm14, [iv + 4]
        vpbroadcastd zmm15, [iv + 8]
        ;; Set first 16 counter values
        vmovdqa64 zmm12, [rel set_1_16]

align 32
start_loop:
        cmp     len, 64*16
        jb      exit_loop

        GENERATE_KS zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                    zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                    zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                    zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15

        ENCRYPT_1_16_BLOCKS zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                            zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                            zmm0, src, dst, off, k1, 16

        ; Update remaining length
        sub     len, 64*16
        add     off, 64*16

        ; Prepare next 16 chacha20 states from IV, key, constants and counter values
        vpbroadcastd zmm0, [rel constants]
        vpbroadcastd zmm1, [rel constants + 4]
        vpbroadcastd zmm2, [rel constants + 8]
        vpbroadcastd zmm3, [rel constants + 12]

        vpbroadcastd zmm4, [keys]
        vpbroadcastd zmm5, [keys + 4]
        vpbroadcastd zmm6, [keys + 8]
        vpbroadcastd zmm7, [keys + 12]
        vpbroadcastd zmm8, [keys + 16]
        vpbroadcastd zmm9, [keys + 20]
        vpbroadcastd zmm10, [keys + 24]
        vpbroadcastd zmm11, [keys + 28]

        vpbroadcastd zmm13, [iv]
        vpbroadcastd zmm14, [iv + 4]
        vpbroadcastd zmm15, [iv + 8]
        ; Increment counter values
        vpaddd      zmm12, [rel add_16]

        jmp     start_loop

exit_loop:

        ; Check if there are partial block (less than 16*64 bytes)
        or      len, len
        jz      no_partial_block

        ; Generate another 64*16 bytes of keystream and XOR only the leftover plaintext
        GENERATE_KS zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                    zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                    zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                    zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15

        ; Calculate number of final blocks
        mov     tmp, len
        add     tmp, 63
        shr     tmp, 6

        cmp     tmp, 8
        je      final_num_blocks_is_8
        jb      final_num_blocks_is_1_7

        ; Final blocks 9-16
        cmp     tmp, 12
        je      final_num_blocks_is_12
        jb      final_num_blocks_is_9_11

        ; Final blocks 13-16
        cmp     tmp, 14
        je      final_num_blocks_is_14
        jb      final_num_blocks_is_13

        cmp     tmp, 15
        je      final_num_blocks_is_15
        jmp     final_num_blocks_is_16

final_num_blocks_is_9_11:
        cmp     tmp, 10
        je      final_num_blocks_is_10
        jb      final_num_blocks_is_9
        ja      final_num_blocks_is_11

final_num_blocks_is_1_7:
        ; Final blocks 1-7
        cmp     tmp, 4
        je      final_num_blocks_is_4
        jb      final_num_blocks_is_1_3

        ; Final blocks 5-7
        cmp     tmp, 6
        je      final_num_blocks_is_6
        jb      final_num_blocks_is_5
        ja      final_num_blocks_is_7

final_num_blocks_is_1_3:
        cmp     tmp, 2
        je      final_num_blocks_is_2
        ja      final_num_blocks_is_3

        ; 1 final block if no jump
%assign I 1
%rep 16
APPEND(final_num_blocks_is_, I):

        lea     tmp, [rel len_to_mask]
        and     len, 63
        kmovq   k1, [tmp + len*8]

APPEND(no_mask_update, I):
        ENCRYPT_1_16_BLOCKS zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                            zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                            zmm0, src, dst, off, k1, I
        jmp     no_partial_block

%assign I (I + 1)
%endrep

no_partial_block:

        mov     rax, job
        or      dword [rax + _status], STS_COMPLETED_AES

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
