;;
;; Copyright (c) 2018-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/error.inc"
;;; Routines to generate subkeys for AES-CMAC.
;;; See RFC 4493 for more details.

;; In System V AMD64 ABI
;;      callee saves: RBX, RBP, R12-R15
;; Windows x64 ABI
;;      callee saves: RBX, RBP, RDI, RSI, RSP, R12-R15
;;
;; Registers:           RAX RBX RCX RDX RBP RSI RDI R8  R9  R10 R11 R12 R13 R14 R15
;;                      -----------------------------------------------------------
;; Windows clobbers:
;; Windows preserves:   RAX RBX RCX RDX RBP RSI RDI R8  R9  R10 R11 R12 R13 R14 R15
;;                      -----------------------------------------------------------
;; Linux clobbers:
;; Linux preserves:     RAX RBX RCX RDX RBP RSI RDI R8  R9  R10 R11 R12 R13 R14 R15
;;                      -----------------------------------------------------------
;;
;; Linux/Windows clobbers: xmm0, xmm1, xmm2
;;

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    [rsp + 5*8]
%endif

%define KEY_EXP arg1
%define KEY1    arg2
%define KEY2    arg3

%define XL      xmm0
%define XKEY1   xmm1
%define XKEY2   xmm2
%define XTMP1   xmm3
%define XTMP2   xmm4

mksection .rodata
default rel

align 16
const_Rb:
        ;ddq 0x00000000000000000000000000000087
        dq 0x0000000000000087, 0x0000000000000000

align 16
byteswap_const:
        ;DDQ 0x000102030405060708090A0B0C0D0E0F
        dq 0x08090A0B0C0D0E0F, 0x0001020304050607

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; void aes_cmac_subkey_gen(const void *key_exp, void *key1, void *key2)
;;;
;;; key_exp : IN  : address of expanded encryption key structure
;;; key1    : OUT : address to store subkey 1 (16 bytes)
;;; key2    : OUT : address to store subkey 2 (16 bytes)
;;;
;;; RFC 4493 Figure 2.2 describing function operations at highlevel
;;;
;;; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
;;; +                    Algorithm Generate_Subkey                       +
;;; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
;;; +                                                                    +
;;; +   Input    : K  (128/256-bit key)                                  +
;;; +   Output   : K1 (128-bit first subkey)                             +
;;; +              K2 (128-bit second subkey)                            +
;;; +--------------------------------------------------------------------+
;;; +                                                                    +
;;; +   Constants: const_Zero is 0x00000000000000000000000000000000      +
;;; +              const_Rb   is 0x00000000000000000000000000000087      +
;;; +   Variables: L          for output of AES-128/256 applied to 0^128 +
;;; +                                                                    +
;;; +   Step 1.  L := AES-128/256(K, const_Zero) ;                       +
;;; +   Step 2.  if MSB(L) is equal to 0                                 +
;;; +            then    K1 := L << 1 ;                                  +
;;; +            else    K1 := (L << 1) XOR const_Rb ;                   +
;;; +   Step 3.  if MSB(K1) is equal to 0                                +
;;; +            then    K2 := K1 << 1 ;                                 +
;;; +            else    K2 := (K1 << 1) XOR const_Rb ;                  +
;;; +   Step 4.  return K1, K2                        ;                  +
;;; +                                                                    +
;;; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

;;;
;;; Constant-time 128-bit "shift left by one and conditionally XOR const_Rb"
;;; (SP 800-38B section 6.1 subkey derivation step).
;;; No data dependent branches: the carry between the two 64-bit halves and
;;; the const_Rb reduction are both applied through arithmetic masks.
;;;
;;; %%OUT  : OUT : (IN << 1) XOR (MSB(IN) ? const_Rb : 0)
;;; %%IN   : IN  : 128-bit value (byte-swapped to little endian, preserved)
;;; %%T1   : CLOBBERED
;;; %%T2   : CLOBBERED
;;;
%macro CMAC_SUBKEY_SHIFT_XOR_RB_SSE 4
%define %%OUT   %1
%define %%IN    %2
%define %%T1    %3
%define %%T2    %4

        movdqa          %%OUT, %%IN
        psllq           %%OUT, 1                ; shift each 64-bit half
        movdqa          %%T1, %%IN
        psrlq           %%T1, 63                ; bit 0 of each half = its old MSB
        pslldq          %%T1, 8                 ; carry of low half -> bit 64
        por             %%OUT, %%T1             ; OUT = IN << 1 (128-bit)
        pshufd          %%T2, %%IN, 0xFF        ; broadcast top dword
        psrad           %%T2, 31                ; all ones if MSB(IN) is set
        pand            %%T2, [rel const_Rb]
        pxor            %%OUT, %%T2
%endmacro

%macro CMAC_SUBKEY_SHIFT_XOR_RB_AVX 4
%define %%OUT   %1
%define %%IN    %2
%define %%T1    %3
%define %%T2    %4

        vpsllq          %%OUT, %%IN, 1          ; shift each 64-bit half
        vpsrlq          %%T1, %%IN, 63          ; bit 0 of each half = its old MSB
        vpslldq         %%T1, %%T1, 8           ; carry of low half -> bit 64
        vpor            %%OUT, %%OUT, %%T1      ; OUT = IN << 1 (128-bit)
        vpshufd         %%T2, %%IN, 0xFF        ; broadcast top dword
        vpsrad          %%T2, %%T2, 31          ; all ones if MSB(IN) is set
        vpand           %%T2, %%T2, [rel const_Rb]
        vpxor           %%OUT, %%OUT, %%T2
%endmacro

%macro AES_CMAC_SUBKEY_GEN_SSE 1-2
%define %%NROUNDS       %1
%define %%ARCH          %2

%ifdef SAFE_PARAM
        IMB_ERR_CHECK_RESET

        cmp     KEY_EXP, 0
        jz      %%_cmac_subkey_error
        cmp     KEY1, 0
        jz      %%_cmac_subkey_error
        cmp     KEY2, 0
        jz      %%_cmac_subkey_error
        jmp     %%_cmac_subkey_no_error
%%_cmac_subkey_error:
        IMB_ERR_CHECK_START rax
        IMB_ERR_CHECK_NULL KEY_EXP, rax, IMB_ERR_NULL_EXP_KEY
        IMB_ERR_CHECK_NULL KEY1, rax, IMB_ERR_NULL_KEY
        IMB_ERR_CHECK_NULL KEY2, rax, IMB_ERR_NULL_KEY
        IMB_ERR_CHECK_END rax

        jmp %%_aes_cmac_subkey_gen_sse_return

%%_cmac_subkey_no_error:
%endif

%define AESENC          aesenc
%define AESENCLAST      aesenclast

        ;; Step 1.  L := AES-128(K, const_Zero) ;
        movdqa          XL, [KEY_EXP + 16*0]    ; 0. ARK xor const_Zero
        AESENC          XL, [KEY_EXP + 16*1]    ; 1. ENC
        AESENC          XL, [KEY_EXP + 16*2]    ; 2. ENC
        AESENC          XL, [KEY_EXP + 16*3]    ; 3. ENC
        AESENC          XL, [KEY_EXP + 16*4]    ; 4. ENC
        AESENC          XL, [KEY_EXP + 16*5]    ; 5. ENC
        AESENC          XL, [KEY_EXP + 16*6]    ; 6. ENC
        AESENC          XL, [KEY_EXP + 16*7]    ; 7. ENC
        AESENC          XL, [KEY_EXP + 16*8]    ; 8. ENC
        AESENC          XL, [KEY_EXP + 16*9]    ; 9. ENC
%if %%NROUNDS == 13     ;; CMAC-256
        AESENC          XL, [KEY_EXP + 16*10]   ; 10. ENC
        AESENC          XL, [KEY_EXP + 16*11]   ; 11. ENC
        AESENC          XL, [KEY_EXP + 16*12]   ; 12. ENC
        AESENC          XL, [KEY_EXP + 16*13]   ; 13. ENC
        AESENCLAST      XL, [KEY_EXP + 16*14]   ; 14. ENC
%else                   ;; CMAC-128
        AESENCLAST      XL, [KEY_EXP + 16*10]   ; 10. ENC
%endif

        ;; Step 2.  if MSB(L) is equal to 0
        ;;          then    K1 := L << 1 ;
        ;;          else    K1 := (L << 1) XOR const_Rb ;
        ;;          (constant-time, no data dependent branches)
        pshufb          XL, [rel byteswap_const]
        CMAC_SUBKEY_SHIFT_XOR_RB_SSE XKEY1, XL, XTMP1, XTMP2

        ;; Step 3.  if MSB(K1) is equal to 0
        ;;          then    K2 := K1 << 1 ;
        ;;          else    K2 := (K1 << 1) XOR const_Rb ;
        CMAC_SUBKEY_SHIFT_XOR_RB_SSE XKEY2, XKEY1, XTMP1, XTMP2

        ;; Step 4.  return K1, K2
        pshufb          XKEY1, [rel byteswap_const]
        pshufb          XKEY2, [rel byteswap_const]
        movdqu          [KEY1], XKEY1
        movdqu          [KEY2], XKEY2

%%_aes_cmac_subkey_gen_sse_return:

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_sse_asm
%endif
%endmacro

%macro AES_CMAC_SUBKEY_GEN_AVX 1
%define %%NROUNDS       %1

%ifdef SAFE_PARAM
        IMB_ERR_CHECK_RESET

        cmp     KEY_EXP, 0
        jz      %%_cmac_subkey_error_avx
        cmp     KEY1, 0
        jz      %%_cmac_subkey_error_avx
        cmp     KEY2, 0
        jz      %%_cmac_subkey_error_avx

        jmp     %%_cmac_subkey_no_error_avx
%%_cmac_subkey_error_avx:
        IMB_ERR_CHECK_START rax
        IMB_ERR_CHECK_NULL KEY_EXP, rax, IMB_ERR_NULL_EXP_KEY
        IMB_ERR_CHECK_NULL KEY1, rax, IMB_ERR_NULL_KEY
        IMB_ERR_CHECK_NULL KEY2, rax, IMB_ERR_NULL_KEY
        IMB_ERR_CHECK_END rax

        jmp     %%_aes_cmac_subkey_gen_avx_return

%%_cmac_subkey_no_error_avx:
%endif
        ;; Step 1.  L := AES-128(K, const_Zero) ;
        vmovdqa         XL, [KEY_EXP + 16*0]        ; 0. ARK xor const_Zero
        vaesenc         XL, [KEY_EXP + 16*1]        ; 1. ENC
        vaesenc         XL, [KEY_EXP + 16*2]        ; 2. ENC
        vaesenc         XL, [KEY_EXP + 16*3]        ; 3. ENC
        vaesenc         XL, [KEY_EXP + 16*4]        ; 4. ENC
        vaesenc         XL, [KEY_EXP + 16*5]        ; 5. ENC
        vaesenc         XL, [KEY_EXP + 16*6]        ; 6. ENC
        vaesenc         XL, [KEY_EXP + 16*7]        ; 7. ENC
        vaesenc         XL, [KEY_EXP + 16*8]        ; 8. ENC
        vaesenc         XL, [KEY_EXP + 16*9]        ; 9. ENC
%if %%NROUNDS == 13     ;; CMAC-256
        vaesenc         XL, [KEY_EXP + 16*10]       ; 10. ENC
        vaesenc         XL, [KEY_EXP + 16*11]       ; 11. ENC
        vaesenc         XL, [KEY_EXP + 16*12]       ; 12. ENC
        vaesenc         XL, [KEY_EXP + 16*13]       ; 13. ENC
        vaesenclast     XL, [KEY_EXP + 16*14]       ; 14. ENC
%else                   ;; CMAC-128
        vaesenclast     XL, [KEY_EXP + 16*10]       ; 10. ENC
%endif

        ;; Step 2.  if MSB(L) is equal to 0
        ;;          then    K1 := L << 1 ;
        ;;          else    K1 := (L << 1) XOR const_Rb ;
        ;;          (constant-time, no data dependent branches)
        vpshufb         XL, [rel byteswap_const]
        CMAC_SUBKEY_SHIFT_XOR_RB_AVX XKEY1, XL, XTMP1, XTMP2

        ;; Step 3.  if MSB(K1) is equal to 0
        ;;          then    K2 := K1 << 1 ;
        ;;          else    K2 := (K1 << 1) XOR const_Rb ;
        CMAC_SUBKEY_SHIFT_XOR_RB_AVX XKEY2, XKEY1, XTMP1, XTMP2

        ;; Step 4.  return K1, K2
        vpshufb         XKEY1, [rel byteswap_const]
        vpshufb         XKEY2, [rel byteswap_const]
        vmovdqu         [KEY1], XKEY1
        vmovdqu         [KEY2], XKEY2

%%_aes_cmac_subkey_gen_avx_return:

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_avx_asm
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; void aes_cmac_subkey_gen_sse(const void *key_exp, void *key1, void *key2)
;;;
;;; key_exp : IN  : address of expanded encryption key structure (AES 128)
;;; key1    : OUT : address to store subkey 1 (AES128 - 16 bytes)
;;; key2    : OUT : address to store subkey 2 (AES128 - 16 bytes)
;;;
;;; See aes_cmac_subkey_gen() above for operation details
MKGLOBAL(aes_cmac_subkey_gen_sse,function,)
align 32
aes_cmac_subkey_gen_sse:
        endbranch64
        AES_CMAC_SUBKEY_GEN_SSE 9
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; void aes_cmac_256_subkey_gen_sse(const void *key_exp,
;;;                                  void *key1,
;;;                                  void *key2)
;;;
;;; key_exp : IN  : address of expanded encryption key structure (AES 256)
;;; key1    : OUT : address to store subkey 1 (AES256 - 16 bytes)
;;; key2    : OUT : address to store subkey 2 (AES256 - 16 bytes)
;;;
;;; See aes_cmac_subkey_gen() above for operation details
MKGLOBAL(aes_cmac_256_subkey_gen_sse,function,)
align 32
aes_cmac_256_subkey_gen_sse:
        endbranch64
        AES_CMAC_SUBKEY_GEN_SSE 13
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; void aes_cmac_subkey_gen_avx(const void *key_exp, void *key1, void *key2)
;;;
;;; key_exp : IN  : address of expanded encryption key structure (AES 128)
;;; key1    : OUT : address to store subkey 1 (AES128 - 16 bytes)
;;; key2    : OUT : address to store subkey 2 (AES128 - 16 bytes)
;;;
;;; See aes_cmac_subkey_gen() above for operation details
MKGLOBAL(aes_cmac_subkey_gen_avx,function,)
MKGLOBAL(aes_cmac_subkey_gen_avx2,function,)
MKGLOBAL(aes_cmac_subkey_gen_avx512,function,)
align 32
aes_cmac_subkey_gen_avx:
aes_cmac_subkey_gen_avx2:
aes_cmac_subkey_gen_avx512:
        endbranch64
        AES_CMAC_SUBKEY_GEN_AVX 9
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; void aes_cmac_256_subkey_gen_avx(const void *key_exp,
;;;                                  void *key1,
;;;                                  void *key2)
;;;
;;; key_exp : IN  : address of expanded encryption key structure (AES 256)
;;; key1    : OUT : address to store subkey 1 (AES256 - 16 bytes)
;;; key2    : OUT : address to store subkey 2 (AES256 - 16 bytes)
;;;
;;; See aes_cmac_subkey_gen() above for operation details
MKGLOBAL(aes_cmac_256_subkey_gen_avx,function,)
MKGLOBAL(aes_cmac_256_subkey_gen_avx2,function,)
MKGLOBAL(aes_cmac_256_subkey_gen_avx512,function,)
align 32
aes_cmac_256_subkey_gen_avx:
aes_cmac_256_subkey_gen_avx2:
aes_cmac_256_subkey_gen_avx512:
        endbranch64
        AES_CMAC_SUBKEY_GEN_AVX 13
        ret

mksection stack-noexec
