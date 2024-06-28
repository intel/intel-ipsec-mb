;;
;; Copyright (c) 2024, Intel Corporation
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
;;           ^       ^
;;           |       |
;;      MSB--+       +--LSB
;;
;;      a - most significant word in `ymm`
;;      d - least significant word in `ymm`
;; ===========================================================

%use smartalign

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/reg_sizes.inc"
%include "include/mb_mgr_datastruct.inc"

; resdq = res0 => 16 bytes
struc frame
.ABEF_SAVE      resy    1
.CDGH_SAVE      resy    1
.ABEF_SAVEb     resy    1
.CDGH_SAVEb     resy    1
endstruc

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%endif

%define args            arg1
%define NUM_BLKS        arg2

%define INP             arg3
%define INPb            arg4

%define SHA512_CONSTS   rax

%define MSG             ymm0
%define STATE0          ymm1
%define STATE1          ymm2
%define MSGTMP0         ymm3
%define MSGTMP1         ymm4
%define MSGTMP2         ymm5

%define YTMP0           ymm6
%define YTMP1           ymm7

%define STATE0b         ymm8
%define STATE1b         ymm9
%define MSGb            ymm10

%define YTMP2           ymm11
%define YTMP3           ymm12

%define MSGTMP0b        ymm13
%define MSGTMP1b        ymm14
%define MSGTMP2b        ymm15

%define GP_STORAGE      6*8
%ifndef LINUX
%define XMM_STORAGE     10*16
%else
%define XMM_STORAGE     0
%endif

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro FUNC_SAVE 0
    mov     r11, rsp
    sub     rsp, VARIABLE_OFFSET
    and     rsp, ~31    ; align rsp to 32 bytes

    mov     [rsp + 0*8],  rbx
    mov     [rsp + 1*8],  rbp
    mov     [rsp + 2*8],  r12
%ifndef LINUX
    mov     [rsp + 3*8], rsi
    mov     [rsp + 4*8], rdi
    vmovdqa [rsp + 3*16], xmm6
    vmovdqa [rsp + 4*16], xmm7
    vmovdqa [rsp + 5*16], xmm8
    vmovdqa [rsp + 6*16], xmm9
    vmovdqa [rsp + 7*16], xmm10
    vmovdqa [rsp + 8*16], xmm11
    vmovdqa [rsp + 9*16], xmm12
    vmovdqa [rsp + 10*16], xmm13
    vmovdqa [rsp + 11*16], xmm14
    vmovdqa [rsp + 12*16], xmm15
%endif ; LINUX
    mov     [rsp + 5*8], r11 ;; rsp pointer
%endmacro

%macro FUNC_RESTORE 0
    mov     rbx, [rsp + 0*8]
    mov     rbp, [rsp + 1*8]
    mov     r12, [rsp + 2*8]
%ifndef LINUX
    mov     rsi,   [rsp + 3*8]
    mov     rdi,   [rsp + 4*8]
    vmovdqa xmm6,  [rsp + 3*16]
    vmovdqa xmm7,  [rsp + 4*16]
    vmovdqa xmm8,  [rsp + 5*16]
    vmovdqa xmm9,  [rsp + 6*16]
    vmovdqa xmm10, [rsp + 7*16]
    vmovdqa xmm11, [rsp + 8*16]
    vmovdqa xmm12, [rsp + 9*16]
    vmovdqa xmm13, [rsp + 10*16]
    vmovdqa xmm14, [rsp + 11*16]
    vmovdqa xmm15, [rsp + 12*16]
%endif ; LINUX
    mov     rsp,   [rsp + 5*8] ;; rsp pointer
%endmacro

%macro SHA512ROUNDS4 7
%define %%Y0            %1
%define %%Y1            %2
%define %%Y2            %3
%define %%Y3            %4
%define %%Y4            %5
%define %%Y6            %6
%define %%I             %7

        vpaddq          %%Y0, %%Y3, [SHA512_CONSTS+32*%%I]
        vpermq          YTMP3, %%Y3, 0x1b
        vpermq          YTMP1, %%Y6, 0x39
        vpblendd        YTMP1, YTMP3, YTMP1, 0x3f
        vpaddq          %%Y4, %%Y4, YTMP1
        vsha512msg2     %%Y4, %%Y3
        vsha512rnds2    %%Y2, %%Y1, XWORD(%%Y0)
        vperm2i128      %%Y0, %%Y0, %%Y0, 0x01
        vsha512rnds2    %%Y1, %%Y2, XWORD(%%Y0)
        vsha512msg1     %%Y6, XWORD(%%Y3)
%endmacro

%macro SHA512ROUNDS4_FINAL 7
%define %%Y0            %1
%define %%Y1            %2
%define %%Y2            %3
%define %%Y3            %4
%define %%Y4            %5
%define %%Y6            %6
%define %%I             %7

        vpaddq          %%Y0, %%Y3, [SHA512_CONSTS+32*%%I]
        vpermq          YTMP3, %%Y3, 0x1b
        vpermq          YTMP1, %%Y6, 0x39
        vpblendd        YTMP1, YTMP3, YTMP1, 0x3f
        vpaddq          %%Y4, %%Y4, YTMP1
        vsha512msg2     %%Y4, %%Y3
        vsha512rnds2    %%Y2, %%Y1, XWORD(%%Y0)
        vperm2i128      %%Y0, %%Y0, %%Y0, 0x01
        vsha512rnds2    %%Y1, %%Y2, XWORD(%%Y0)
%endmacro

;; re-use symbols from AVX codebase
extern SHA512_K_AVX

mksection .rodata
default rel

align 32
SHUF_MASK:
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f

mksection .text
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha512_ni_x2_avx2(SHA512_ARGS *args, UINT64 size_in_blocks)
;; arg1 : pointer to args
;; arg2 : size (in blocks) ;; assumed to be >= 1
align 32
MKGLOBAL(sha512_ni_x2_avx2,function,internal)
sha512_ni_x2_avx2:
        mov             r11, rsp
        sub             rsp, frame_size
        and             rsp, -32

        or              NUM_BLKS, NUM_BLKS
        je              .done_hash

        ;; load input pointers
        mov             INP, [args + _data_ptr_sha512 + 0*PTR_SZ]
        mov             INPb, [args + _data_ptr_sha512 + 1*PTR_SZ]

        ;; load constants pointer
        lea             SHA512_CONSTS, [rel SHA512_K_AVX]

        ;; load current hash value and transform
        vmovdqu         STATE0, [args + _args_digest_sha512 + 0*SHA512NI_DIGEST_ROW_SIZE]
        vmovdqu         STATE1, [args + _args_digest_sha512 + 0*SHA512NI_DIGEST_ROW_SIZE + 32]
                vmovdqu         STATE0b, [args + _args_digest_sha512 + 1*SHA512NI_DIGEST_ROW_SIZE]
                vmovdqu         STATE1b, [args + _args_digest_sha512 + 1*SHA512NI_DIGEST_ROW_SIZE + 32]

        vperm2i128 YTMP1, STATE0, STATE1, 0x20
                    vperm2i128 YTMP0, STATE0b, STATE1b, 0x20
        vperm2i128 STATE1, STATE0, STATE1, 0x31
                    vperm2i128 STATE1b, STATE0b, STATE1b, 0x31
        vpermq STATE0, YTMP1, 0x1b
                    vpermq STATE0b, YTMP0, 0x1b
        vpermq STATE1, STATE1, 0x1b
                    vpermq STATE1b, STATE1b, 0x1b

align 32
.block_loop:
        ;; Save digests
        vmovdqa         [rsp + frame.ABEF_SAVE], STATE0
        vmovdqa         [rsp + frame.CDGH_SAVE], STATE1
                vmovdqa         [rsp + frame.ABEF_SAVEb], STATE0b
                vmovdqa         [rsp + frame.CDGH_SAVEb], STATE1b

        ;; R0- R3
        vmovdqu MSG, [INP+32*0]
                    vmovdqu MSGb, [INPb+32*0]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu MSGTMP0, MSG
                    vmovdqu MSGTMP0b, MSGb
        vpaddq MSG, MSG, [SHA512_CONSTS+32*0]
                    vpaddq MSGb, MSGb, [SHA512_CONSTS+32*0]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)

        ;; R4-7
        vmovdqu MSG, [INP+32*1]
                    vmovdqu MSGb, [INPb+32*1]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu MSGTMP1, MSG
                    vmovdqu MSGTMP1b, MSGb
        vpaddq MSG, MSG, [SHA512_CONSTS+32*1]
                    vpaddq MSGb, MSGb, [SHA512_CONSTS+32*1]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)
        vsha512msg1 MSGTMP0, XWORD(MSGTMP1)
                    vsha512msg1 MSGTMP0b, XWORD(MSGTMP1b)

        ;; R8-R11
        vmovdqu MSG, [INP+32*2]
                    vmovdqu MSGb, [INPb+32*2]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu MSGTMP2, MSG
                    vmovdqu MSGTMP2b, MSGb


        vpaddq MSG, MSG, [SHA512_CONSTS+32*2]
                    vpaddq MSGb, MSGb, [SHA512_CONSTS+32*2]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)
        vsha512msg1 MSGTMP1, XWORD(MSGTMP2)
                    vsha512msg1 MSGTMP1b, XWORD(MSGTMP2b)

        ;; R12-15
        vmovdqu MSG, [INP+32*3]
                    vmovdqu MSGb, [INPb+32*3]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu YTMP0, MSG
                    vmovdqu YTMP2, MSGb

        ;; R16-75
        SHA512ROUNDS4 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, 3
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 3
        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, 4
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 4

        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, 5
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 5
        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, 6
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 6

        SHA512ROUNDS4 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, 7
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 7
        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, 8
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 8

        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, 9
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 9
        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, 10
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 10

        SHA512ROUNDS4 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, 11
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 11
        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, 12
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 12

        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, 13
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 13
        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, 14
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 14

        SHA512ROUNDS4 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, 15
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 15
        SHA512ROUNDS4 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, 16
        SHA512ROUNDS4 MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 16

        SHA512ROUNDS4_FINAL MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, 17
        SHA512ROUNDS4_FINAL MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 17
        SHA512ROUNDS4_FINAL MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, 18
        SHA512ROUNDS4_FINAL MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 18

        ;; R76-79
        vpaddq MSG, YTMP0, [SHA512_CONSTS+32*19]
                    vpaddq MSGb, YTMP2, [SHA512_CONSTS+32*19]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)

        vpaddq STATE0, STATE0, [rsp + frame.ABEF_SAVE]
        vpaddq STATE1, STATE1, [rsp + frame.CDGH_SAVE]
                    vpaddq STATE0b, STATE0b, [rsp + frame.ABEF_SAVEb]
                    vpaddq STATE1b, STATE1b, [rsp + frame.CDGH_SAVEb]

        lea INP, [INP+128]
                    lea INPb, [INPb+128]

        dec     NUM_BLKS
        jne     .block_loop

        ;; Update input pointers
        mov     [args + _data_ptr_sha512 + 0*PTR_SZ], INP
        mov     [args + _data_ptr_sha512 + 1*PTR_SZ], INPb

        ; Reorder and write back the hash value
        vperm2i128 MSGTMP0, STATE0, STATE1, 0x31
                    vperm2i128 MSGTMP1, STATE0b, STATE1b, 0x31
        vperm2i128 MSGTMP2, STATE0, STATE1, 0x20
                    vperm2i128 YTMP0, STATE0b, STATE1b, 0x20
        vpermq STATE0, MSGTMP0, 0xb1
        vpermq STATE1, MSGTMP2, 0xb1
                    vpermq STATE0b, MSGTMP1, 0xb1
                    vpermq STATE1b, YTMP0, 0xb1

        ;; update digests
        vmovdqu         [args + _args_digest_sha512 + 0*SHA512NI_DIGEST_ROW_SIZE], STATE0
        vmovdqu         [args + _args_digest_sha512 + 0*SHA512NI_DIGEST_ROW_SIZE + 32], STATE1
                vmovdqu         [args + _args_digest_sha512 + 1*SHA512NI_DIGEST_ROW_SIZE], STATE0b
                vmovdqu         [args + _args_digest_sha512 + 1*SHA512NI_DIGEST_ROW_SIZE + 32], STATE1b

        vzeroupper

.done_hash:

        mov     rsp, r11

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; void call_sha512_ni_x2_avx2_from_c(SHA512_ARGS *args, UINT64 size_in_blocks);
MKGLOBAL(call_sha512_ni_x2_avx2_from_c,function,internal)
call_sha512_ni_x2_avx2_from_c:
        FUNC_SAVE
        call sha512_ni_x2_avx2
        FUNC_RESTORE
        ret

mksection stack-noexec
