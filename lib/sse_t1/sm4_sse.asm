;;
;; Copyright (c) 2023, Intel Corporation
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

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/error.inc"

%ifndef SM4_SET_KEY
%define SM4_SET_KEY sm4_set_key_sse
%define SM4_ECB     sm4_ecb_sse
%endif

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

%define APPEND(a,b) a %+ b

mksection .rodata
default rel

align 16
SM4_FK:
dd      0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC

align 16
SM4_CK:
dd      0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
dd      0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
dd      0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
dd      0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
dd      0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
dd      0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
dd      0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
dd      0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279

align 16
in_mask_lo:
db      0x65, 0x41, 0xfd, 0xd9, 0x0a, 0x2e, 0x92, 0xb6, 0x0f, 0x2b, 0x97, 0xb3, 0x60, 0x44, 0xf8, 0xdc

align 16
in_mask_hi:
db      0x00, 0xc9, 0x67, 0xae, 0x80, 0x49, 0xe7, 0x2e, 0x4a, 0x83, 0x2d, 0xe4, 0xca, 0x03, 0xad, 0x64

align 16
out_mask_lo:
db      0xd3, 0x59, 0x38, 0xb2, 0xcc, 0x46, 0x27, 0xad, 0x36, 0xbc, 0xdd, 0x57, 0x29, 0xa3, 0xc2, 0x48

align 16
out_mask_hi:
db      0x00, 0x50, 0x14, 0x44, 0x89, 0xd9, 0x9d, 0xcd, 0xde, 0x8e, 0xca, 0x9a, 0x57, 0x07, 0x43, 0x13

align 16
enc_key:
db      0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63

align 16
mask_Srows:
db      0x00, 0x0d, 0x0a, 0x07, 0x04, 0x01, 0x0e, 0x0b, 0x08, 0x05, 0x02, 0x0f, 0x0c, 0x09, 0x06, 0x03

align 16
low_bits_4:
db      0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f

align 16
swap_bytes:
db      3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

mksection .text

%macro FUNC_SAVE 0
        mov     r11, rsp
        sub     rsp, 4*16 + 8
        and     rsp, ~15

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        movdqa  [rsp + 0*16], xmm6
        movdqa  [rsp + 1*16], xmm7
        movdqa  [rsp + 2*16], xmm8
        movdqa  [rsp + 3*16], xmm9
%endif
        mov     [rsp + 4*16], r11 ;; rsp pointer
%endmacro

%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
        movdqa  xmm6,  [rsp + 0*16]
        movdqa  xmm7,  [rsp + 1*16]
        movdqa  xmm8,  [rsp + 2*16]
        movdqa  xmm9,  [rsp + 3*16]
%endif
        mov     rsp, [rsp + 4*16]
%endmacro

%macro AFFINE 4
%define %%IN_OUT  %1 ; [in/out] Input/output XMM register
%define %%MASK_LO %2 ; [in/clobbered] Low bit mask
%define %%MASK_HI %3 ; [in/clobbered] High bit mask
%define %%XTMP    %4 ; [clobbered] Temporary XMM register

        movdqa  %%XTMP, %%IN_OUT
        psrlq   %%XTMP, 4
        pand    %%XTMP, [rel low_bits_4]

        pand    %%IN_OUT, [rel low_bits_4]

        pshufb  %%MASK_LO, %%IN_OUT
        pshufb  %%MASK_HI, %%XTMP

        movdqa  %%IN_OUT, %%MASK_LO
        pxor    %%IN_OUT, %%MASK_HI
%endmacro

%macro SBOX 4
%define %%IN_OUT %1 ; [in/out] Input/output XMM register
%define %%XTMP1  %2 ; [clobbered] Temporary XMM register
%define %%XTMP2  %3 ; [clobbered] Temporary XMM register
%define %%XTMP3  %4 ; [clobbered] Temporary XMM register

        movdqa  %%XTMP1, [rel in_mask_lo]
        movdqa  %%XTMP2, [rel in_mask_hi]
        AFFINE  %%IN_OUT, %%XTMP1, %%XTMP2, %%XTMP3
        aesenclast %%IN_OUT, [rel enc_key]
        pshufb  %%IN_OUT, [rel mask_Srows]
        movdqa  %%XTMP1, [rel out_mask_lo]
        movdqa  %%XTMP2, [rel out_mask_hi]
        AFFINE  %%IN_OUT, %%XTMP1, %%XTMP2, %%XTMP3
%endmacro

%macro L_TAG 4
%define %%IN_OUT %1 ; [in/out] Input/output XMM register
%define %%XTMP1  %2 ; [clobbered] Temporary XMM register
%define %%XTMP2  %3 ; [clobbered] Temporary XMM register
%define %%XTMP3  %4 ; [clobbered] Temporary XMM register

        movdqa  %%XTMP1, %%IN_OUT
        pslld   %%XTMP1, 13
        movdqa  %%XTMP2, %%IN_OUT
        psrld   %%XTMP2, 19
        movdqa  %%XTMP3, %%IN_OUT
        pslld   %%XTMP3, 23
        psrld   %%IN_OUT, 9
        pxor    %%IN_OUT, %%XTMP1
        pxor    %%IN_OUT, %%XTMP2
        pxor    %%IN_OUT, %%XTMP3

%endmacro

%macro L 5
%define %%IN_OUT %1 ; [in/out] Input/output XMM register
%define %%XTMP1  %2 ; [clobbered] Temporary XMM register
%define %%XTMP2  %3 ; [clobbered] Temporary XMM register
%define %%XTMP3  %4 ; [clobbered] Temporary XMM register
%define %%XTMP4  %5 ; [clobbered] Temporary XMM register

        movdqa  %%XTMP1, %%IN_OUT
        pslld   %%XTMP1, 2
        movdqa  %%XTMP2, %%IN_OUT
        psrld   %%XTMP2, 30
        movdqa  %%XTMP3, %%IN_OUT
        pslld   %%XTMP3, 10
        movdqa  %%XTMP4, %%IN_OUT
        psrld   %%XTMP4, 22

        pxor    %%XTMP4, %%XTMP1
        pxor    %%XTMP4, %%XTMP2
        pxor    %%XTMP4, %%XTMP3

        movdqa  %%XTMP1, %%IN_OUT
        pslld   %%XTMP1, 18
        movdqa  %%XTMP2, %%IN_OUT
        psrld   %%XTMP2, 14
        movdqa  %%XTMP3, %%IN_OUT
        pslld   %%XTMP3, 24
        psrld   %%IN_OUT, 8

        pxor    %%IN_OUT, %%XTMP1
        pxor    %%IN_OUT, %%XTMP2
        pxor    %%IN_OUT, %%XTMP3
        pxor    %%IN_OUT, %%XTMP4
%endmacro

;;
;; Encrypts/decrypts a single 128-bit block with SM4
;;
%macro SM4_ENC_DEC 14
%define %%IN     %1 ; [in] Pointer to 128-bit input block
%define %%OUT    %2 ; [out] Pointer to 128-bit output block
%define %%KEYS   %3 ; [in] Pointer to expanded enc/dec keys
%define %%XTMP1  %4 ; [clobbered] Temporary XMM register
%define %%XTMP2  %5 ; [clobbered] Temporary XMM register
%define %%XTMP3  %6 ; [clobbered] Temporary XMM register
%define %%XTMP4  %7 ; [clobbered] Temporary XMM register
%define %%XTMP5  %8 ; [clobbered] Temporary XMM register
%define %%XTMP6  %9 ; [clobbered] Temporary XMM register
%define %%XTMP7 %10 ; [clobbered] Temporary XMM register
%define %%XTMP8 %11 ; [clobbered] Temporary XMM register
%define %%XTMP9 %12 ; [clobbered] Temporary XMM register
%define %%XTMP  %13 ; [clobbered] Temporary XMM register
%define %%IDX   %14 ; [clobbered] Temporary GP register

        movd    %%XTMP1, [%%IN + 4*0]
        pshufb  %%XTMP1, [rel swap_bytes]
        movd    %%XTMP2, [%%IN + 4*1]
        pshufb  %%XTMP2, [rel swap_bytes]
        movd    %%XTMP3, [%%IN + 4*2]
        pshufb  %%XTMP3, [rel swap_bytes]
        movd    %%XTMP4, [%%IN + 4*3]
        pshufb  %%XTMP4, [rel swap_bytes]

        xor     %%IDX, %%IDX
%%start_loop:
        cmp     %%IDX, 16*8
        je      %%end_loop

        movdqa  %%XTMP5, [%%KEYS + %%IDX]
        pshufd  %%XTMP, %%XTMP5, 0x00
        pxor    %%XTMP, %%XTMP2
        pxor    %%XTMP, %%XTMP3
        pxor    %%XTMP, %%XTMP4

        SBOX    %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8
        pxor    %%XTMP1, %%XTMP
        L       %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9
        pxor    %%XTMP1, %%XTMP

        pshufd  %%XTMP, %%XTMP5, 0x55
        pxor    %%XTMP, %%XTMP3
        pxor    %%XTMP, %%XTMP4
        pxor    %%XTMP, %%XTMP1

        SBOX    %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8
        pxor    %%XTMP2, %%XTMP
        L       %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9
        pxor    %%XTMP2, %%XTMP

        pshufd  %%XTMP, %%XTMP5, 0xAA
        pxor    %%XTMP, %%XTMP4
        pxor    %%XTMP, %%XTMP1
        pxor    %%XTMP, %%XTMP2

        SBOX    %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8
        pxor    %%XTMP3, %%XTMP
        L       %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9
        pxor    %%XTMP3, %%XTMP

        pshufd  %%XTMP, %%XTMP5, 0xFF
        pxor    %%XTMP, %%XTMP1
        pxor    %%XTMP, %%XTMP2
        pxor    %%XTMP, %%XTMP3

        SBOX    %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8
        pxor    %%XTMP4, %%XTMP
        L       %%XTMP, %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9
        pxor    %%XTMP4, %%XTMP

        add     %%IDX, 16
        jmp     %%start_loop

%%end_loop:
        pshufb  %%XTMP4, [rel swap_bytes]
        movd    [%%OUT + 4*0], %%XTMP4
        pshufb  %%XTMP3, [rel swap_bytes]
        movd    [%%OUT + 4*1], %%XTMP3
        pshufb  %%XTMP2, [rel swap_bytes]
        movd    [%%OUT + 4*2], %%XTMP2
        pshufb  %%XTMP1, [rel swap_bytes]
        movd    [%%OUT + 4*3], %%XTMP1

%assign %%i 0
%endmacro


;;
;;void sm4_set_key_sse(const void *key, const uint32_t *exp_enc_keys,
;;                     const uint32_t *exp_dec_keys)
;;
; arg 1: KEY:  pointer to 128-bit key
; arg 2: EXP_ENC_KEYS: pointer to expanded encryption keys
; arg 3: EXP_DEC_KEYS: pointer to expanded decryption keys
;
align 16
MKGLOBAL(SM4_SET_KEY,function,internal)
SM4_SET_KEY:

%define	KEY             arg1
%define	ENC_KEY_EXP     arg2
%define	DEC_KEY_EXP     arg3

%define XTMP1 xmm1
%define XTMP2 xmm2
%define XTMP3 xmm3
%define XTMP4 xmm4
%define XTMP5 xmm5
%define XTMP6 xmm6
%define XTMP7 xmm7
%define XTMP  xmm8

        endbranch64
%ifdef SAFE_PARAM
        IMB_ERR_CHECK_RESET

        cmp     KEY, 0
        jz      error_set_key_sse
        cmp     ENC_KEY_EXP, 0
        jz      error_set_key_sse
        cmp     DEC_KEY_EXP, 0
        jz      error_set_key_sse
%endif
        FUNC_SAVE

        mov     eax, [KEY + 4*0]
        bswap   eax
        xor     eax, [SM4_FK + 4*0]
        movd    XTMP1, eax
        mov     eax, [KEY + 4*1]
        bswap   eax
        xor     eax, [SM4_FK + 4*1]
        movd    XTMP2, eax
        mov     eax, [KEY + 4*2]
        bswap   eax
        xor     eax, [SM4_FK + 4*2]
        movd    XTMP3, eax
        mov     eax, [KEY + 4*3]
        bswap   eax
        xor     eax, [SM4_FK + 4*3]
        movd    XTMP4, eax

%assign i 0
%rep 8
        movd    XTMP, [SM4_CK + i*16 + 4*0]
        pxor    XTMP, XTMP2
        pxor    XTMP, XTMP3
        pxor    XTMP, XTMP4

        SBOX    XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP1, XTMP
        L_TAG   XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP1, XTMP
        movd    [ENC_KEY_EXP + i*16 + 4*0], XTMP1
        movd    [DEC_KEY_EXP + (7-i)*16 + 4*3], XTMP1


        movd    XTMP, [SM4_CK + i*16 + 4*1]
        pxor    XTMP, XTMP3
        pxor    XTMP, XTMP4
        pxor    XTMP, XTMP1

        SBOX    XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP2, XTMP
        L_TAG   XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP2, XTMP
        movd    [ENC_KEY_EXP + i*16 + 4*1], XTMP2
        movd    [DEC_KEY_EXP + (7-i)*16 + 4*2], XTMP2


        movd    XTMP, [SM4_CK + i*16 + 4*2]
        pxor    XTMP, XTMP4
        pxor    XTMP, XTMP1
        pxor    XTMP, XTMP2

        SBOX    XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP3, XTMP
        L_TAG   XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP3, XTMP
        movd    [ENC_KEY_EXP + i*16 + 4*2], XTMP3
        movd    [DEC_KEY_EXP + (7-i)*16 + 4*1], XTMP3


        movd    XTMP, [SM4_CK + i*16 + 4*3]
        pxor    XTMP, XTMP1
        pxor    XTMP, XTMP2
        pxor    XTMP, XTMP3

        SBOX    XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP4, XTMP
        L_TAG   XTMP, XTMP5, XTMP6, XTMP7
        pxor    XTMP4, XTMP
        movd    [ENC_KEY_EXP + i*16 + 4*3], XTMP4
        movd    [DEC_KEY_EXP + (7-i)*16 + 4*0], XTMP4

%assign i (i + 1)
%endrep

%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
%endif
        FUNC_RESTORE

        ret

%ifdef SAFE_PARAM
error_set_key_sse:
        IMB_ERR_CHECK_START rax
        IMB_ERR_CHECK_NULL KEY, rax, IMB_ERR_NULL_KEY
        IMB_ERR_CHECK_NULL ENC_KEY_EXP, rax, IMB_ERR_NULL_EXP_KEY
        IMB_ERR_CHECK_NULL DEC_KEY_EXP, rax, IMB_ERR_NULL_EXP_KEY
        IMB_ERR_CHECK_END rax

        ret
%endif

;;
;;void sm4_ecb_sse(const void *in, void *out, uint64_t len,
;;                 const uint32_t *exp_keys)
;;
; arg 1: IN:   pointer to input (cipher text)
; arg 2: OUT:  pointer to output (plain text)
; arg 3: LEN:  length in bytes (multiple of 16)
; arg 4: KEYS: pointer to keys
;
MKGLOBAL(SM4_ECB,function,internal)
SM4_ECB:

%define	IN      arg1
%define	OUT     arg2
%define SIZE    arg3
%define	KEY_EXP arg4

        FUNC_SAVE

        shr     SIZE, 4 ; Number of blocks

align 16
ecb_loop:
        or      SIZE, SIZE
        jz      end_ecb_loop

        SM4_ENC_DEC IN, OUT, KEY_EXP, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, r10

        dec     SIZE
        add     IN, 16
        add     OUT, 16

        jmp     ecb_loop

end_ecb_loop:

%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
%endif
        FUNC_RESTORE

        ret


;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

mksection stack-noexec
