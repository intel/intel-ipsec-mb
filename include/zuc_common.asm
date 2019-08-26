;;
;; Copyright (c) 2009-2019, Intel Corporation
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

section .data
default rel
align 64
S0:
db	0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb
db	0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90
db	0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac
db	0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38
db	0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b
db	0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c
db	0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad
db	0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8
db	0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56
db	0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe
db	0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d
db	0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23
db	0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1
db	0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f
db	0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65
db	0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60

S1:
db	0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77
db	0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42
db	0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1
db	0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48
db	0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87
db	0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb
db	0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09
db	0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9
db	0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9
db	0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89
db	0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4
db	0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde
db	0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21
db	0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34
db	0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28
db	0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2

EK_d:
dw	0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
dw	0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif

section .text

%define OFFSET_FR1      (16*4)
%define OFFSET_FR2      (17*4)
%define OFFSET_BRC_X0   (18*4)
%define OFFSET_BRC_X1   (19*4)
%define OFFSET_BRC_X2   (20*4)
%define OFFSET_BRC_X3   (21*4)

;
;   BITS_REORG()
;
;   params
;       %1 - round number
;   uses
;       eax, ebx, ecx, edx
;   return
;       updates r12d, r13d, r14d, r15d
;
%macro  BITS_REORG  1
    ;
    ; r12d = LFSR_S15
    ; eax  = LFSR_S14
    ; r13d = LFSR_S11
    ; ebx  = LFSR_S9
    ; r14d = LFSR_S7
    ; ecx  = LFSR_S5
    ; r15d = LFSR_S2
    ; edx  = LFSR_S0

    mov         r12d, [rsi + ((15 + %1) % 16)*4]
    mov          eax, [rsi + ((14 + %1) % 16)*4]
    mov         r13d, [rsi + ((11 + %1) % 16)*4]
    mov          ebx, [rsi + (( 9 + %1) % 16)*4]
    mov         r14d, [rsi + (( 7 + %1) % 16)*4]
    mov          ecx, [rsi + (( 5 + %1) % 16)*4]
    mov         r15d, [rsi + (( 2 + %1) % 16)*4]
    mov          edx, [rsi + (( 0 + %1) % 16)*4]

    shr         r12d, 15
    shl         eax, 16
    shl         ebx, 1
    shl         ecx, 1
    shl         edx, 1
    shld        r12d, eax, 16   ; BRC_X0
    shld        r13d, ebx, 16   ; BRC_X1
    shld        r14d, ecx, 16   ; BRC_X2
    shld        r15d, edx, 16   ; BRC_X3
%endmacro


;
;   NONLIN_FUN()
;
;   params
;       %1 == 1, then calculate W
;   uses
;           rdi rsi eax rdx edx
;           r8d r9d ebx
;   return
;       eax  = W value
;       r10d = F_R1
;       r11d = F_R2
;
%macro NONLIN_FUN   1

%if (%1 == 1)
    mov         eax, r12d
    xor         eax, r10d
    add         eax, r11d   ; W = (BRC_X0 ^ F_R1) + F_R2
%endif
    lea         rdi, [rel S0]
    lea         rsi, [rel S1]

    add         r10d, r13d  ; W1= F_R1 + BRC_X1
    xor         r11d, r14d  ; W2= F_R2 ^ BRC_X2

    mov         rdx, r10
    shld        edx, r11d, 16   ; P = (W1 << 16) | (W2 >> 16)
    shld        r11d, r10d, 16  ; Q = (W2 << 16) | (W1 >> 16)

    mov         ebx, edx
    mov         ecx, edx
    mov         r8d, edx
    mov         r9d, edx

    rol         ebx, 2
    rol         ecx, 10
    rol         r8d, 18
    rol         r9d, 24
    xor         edx, ebx
    xor         edx, ecx
    xor         edx, r8d
    xor         edx, r9d    ; U = L1(P) = EDX, hi(RDX)=0
    ;
    xor         r10, r10
    shld        ebx, edx, 24
    shld        r8d, edx, 16
    shld        r9d, edx, 8
    and         rdx, 0xFF
    movzx       edx, byte [rsi + rdx]
    and         rbx, 0xFF
    movzx       ebx, byte [rdi + rbx]
    and         r8, 0xFF
    movzx       r8d, byte [rsi + r8]
    and         r9, 0xFF
    movzx       r9d, byte [rdi + r9]
    shrd        r10d, edx, 8
    shrd        r10d, ebx, 8
    shrd        r10d, r8d, 8
    shrd        r10d, r9d, 8
    ;
    mov         ebx, r11d
    mov         ecx, r11d
    mov         r8d, r11d
    mov         r9d, r11d
    rol         ebx, 8
    rol         ecx, 14
    rol         r8d, 22
    rol         r9d, 30
    xor         r11d, ebx
    xor         r11d, ecx
    xor         r11d, r8d
    xor         r11d, r9d   ; V = L2(Q) = ECX, hi(RCX)=0
    ;
    shld        ebx, r11d, 24
    shld        r8d, r11d, 16
    shld        r9d, r11d, 8
    and         r11, 0xFF

    movzx       r11d, byte [rsi + r11]
    and         rbx, 0xFF
    movzx       ebx, byte [rdi + rbx]
    and         r8, 0xFF
    movzx       r8d, byte [rsi + r8]
    and         r9, 0xFF
    movzx       r9d, byte [rdi + r9]

    shrd        r11d, r11d, 8

    shrd        r11d, ebx, 8
    shrd        r11d, r8d, 8
    shrd        r11d, r9d, 8
%endmacro


;
;   LFSR_UPDT()
;
;   params
;       %1 - round number
;   uses
;       rax as input (ZERO or W)
;   return
;
%macro  LFSR_UPDT   1
    ;
    ; ebx = LFSR_S0
    ; ecx = LFSR_S4
    ; edx = LFSR_S10
    ; r8d = LFSR_S13
    ; r9d = LFSR_S15
    ;lea         rsi, [LFSR_STA] ; moved to calling function

    mov         ebx, [rsi + (( 0 + %1) % 16)*4]
    mov         ecx, [rsi + (( 4 + %1) % 16)*4]
    mov         edx, [rsi + ((10 + %1) % 16)*4]
    mov         r8d, [rsi + ((13 + %1) % 16)*4]
    mov         r9d, [rsi + ((15 + %1) % 16)*4]

    ; Calculate 64-bit LFSR feedback
    add         rax, rbx
    shl         rbx, 8
    shl         rcx, 20
    shl         rdx, 21
    shl         r8, 17
    shl         r9, 15
    add         rax, rbx
    add         rax, rcx
    add         rax, rdx
    add         rax, r8
    add         rax, r9

    ; Reduce it to 31-bit value
    mov         rbx, rax
    and         rax, 0x7FFFFFFF
    shr         rbx, 31
    add         rax, rbx

    mov rbx, rax
    sub rbx, 0x7FFFFFFF
    cmovns rax, rbx


    ; LFSR_S16 = (LFSR_S15++) = eax
    mov         [rsi + (( 0 + %1) % 16)*4], eax
%endmacro


;
;   make_u31()
;
%macro  make_u31    4

%define %%Rt        %1
%define %%Ke        %2
%define %%Ek        %3
%define %%Iv        %4
    xor         %%Rt, %%Rt
    shrd        %%Rt, %%Iv, 8
    shrd        %%Rt, %%Ek, 15
    shrd        %%Rt, %%Ke, 9
%endmacro


;
;	key_expand()
;
%macro	key_expand	1
	movzx		r8d, byte [pKe +  (%1 + 0)]
	movzx		r9d, word [rbx + ((%1 + 0)*2)]
	movzx		r10d, byte [pIv + (%1 + 0)]
	make_u31	r11d, r8d, r9d, r10d
	mov 		[rax +  ((%1 + 0)*4)], r11d

	movzx		r12d, byte [pKe +  (%1 + 1)]
	movzx		r13d, word [rbx + ((%1 + 1)*2)]
	movzx		r14d, byte [pIv +  (%1 + 1)]
	make_u31	r15d, r12d, r13d, r14d
	mov 		[rax +  ((%1 + 1)*4)], r15d
%endmacro



;----------------------------------------------------------------------------------------
;;
;;extern void Zuc_Initialization(uint8_t* pKey, uint8_t* pIV, uint32_t * pState)
;;
;; WIN64
;;	RCX - pKey
;;	RDX - pIV
;;      R8  - pState
;; LIN64
;;	RDI - pKey
;;	RSI - pIV
;;      RDX - pState
;;
align 16
MKGLOBAL(asm_ZucInitialization,function,internal)
asm_ZucInitialization:

%ifdef LINUX
	%define		pKe	rdi
	%define		pIv	rsi
	%define		pState	rdx
%else
	%define		pKe	rcx
	%define		pIv	rdx
	%define		pState	r8
%endif

    ; save the base pointer
    push rbp

    ;load stack pointer to rbp and reserve memory in the red zone
    mov rbp, rsp
    sub rsp, 196

    ; Save non-volatile registers
    mov [rbp - 8],  rbx
    mov [rbp - 32], r12
    mov [rbp - 40], r13
    mov [rbp - 48], r14
    mov [rbp - 56], r15
%ifndef LINUX
    mov [rbp - 64], rdi
    mov [rbp - 72], rsi
%endif

    lea rbx, [rel EK_d]     ; load pointer to D
    lea rax, [pState]      ; load pointer to pState
    mov [rbp - 88], pState   ; save pointer to pState

    ; Expand key
    key_expand  0
    key_expand  2
    key_expand  4
    key_expand  6
    key_expand  8
    key_expand  10
    key_expand  12
    key_expand  14

    ; Set R1 and R2 to zero
    xor         r10, r10
    xor         r11, r11

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    mov rdx, [rbp - 88]   ; load pointer to pState
    lea rsi, [rdx]

    BITS_REORG  N

    NONLIN_FUN  1
    shr         eax, 1

    mov rdx, [rbp - 88]   ; re-load pointer to pState
    lea rsi, [rdx]

    LFSR_UPDT   N

%assign N N+1
%endrep

    ; And once more, initial round from keygen phase = 33 times
    mov rdx, [rbp - 88]   ; load pointer to pState
    lea         rsi, [rdx]


    BITS_REORG  0
    NONLIN_FUN  0
    xor         rax, rax

    mov         rdx, [rbp - 88]   ; load pointer to pState
    lea         rsi, [rdx]

    LFSR_UPDT   0

    mov         rdx, [rbp - 88]   ; load pointer to pState
    lea         rsi, [rdx]

    ; Save ZUC's state variables
    mov         [rsi + (16*4)],r10d  ;F_R1
    mov         [rsi + (17*4)],r11d  ;F_R2
    mov         [rsi + (18*4)],r12d  ;BRC_X0
    mov         [rsi + (19*4)],r13d  ;BRC_X1
    mov         [rsi + (20*4)],r14d  ;BRC_X2
    mov         [rsi + (21*4)],r15d  ;BRC_X3


    ; Restore non-volatile registers
    mov rbx, [rbp - 8]
    mov r12, [rbp - 32]
    mov r13, [rbp - 40]
    mov r14, [rbp - 48]
    mov r15, [rbp - 56]
%ifndef LINUX
    mov rdi, [rbp - 64]
    mov rsi, [rbp - 72]
%endif

    ; restore base pointer
    mov rsp, rbp
    pop rbp

    ret


;;
;; void asm_ZucGenKeystream8B(void *pKeystream, ZucState_t *pState);
;;
;; WIN64
;;	RCX - KS (key stream pointer)
;; 	RDX - STATE (state pointer)
;; LIN64
;;	RDI - KS (key stream pointer)
;;	RSI - STATE (state pointer)
;;
align 16
MKGLOBAL(asm_ZucGenKeystream8B,function,internal)
asm_ZucGenKeystream8B:

%ifdef LINUX
	%define		pKS	rdi
	%define		pState	rsi
%else
	%define		pKS	rcx
	%define		pState	rdx
%endif
    ; save the base pointer
    push rbp

    ;load stack pointer to rbp and reserve memory in the red zone
    mov rbp, rsp
    sub rsp, 196

    ; Save non-volatile registers
    mov [rbp - 8], rbx
    mov [rbp - 32], r12
    mov [rbp - 40], r13
    mov [rbp - 48], r14
    mov [rbp - 56], r15
%ifndef LINUX
    mov [rbp - 64], rdi
    mov [rbp - 72], rsi
%endif


    ; Load input keystream pointer parameter in RAX
    mov         rax, pKS

    ; Restore ZUC's state variables
    xor         r10, r10
    xor         r11, r11
    mov         r10d, [pState + OFFSET_FR1]
    mov         r11d, [pState + OFFSET_FR2]
    mov         r12d, [pState + OFFSET_BRC_X0]
    mov         r13d, [pState + OFFSET_BRC_X1]
    mov         r14d, [pState + OFFSET_BRC_X2]
    mov         r15d, [pState + OFFSET_BRC_X3]

    ; Store keystream pointer
    mov [rbp - 80], rax

    ; Store ZUC State Pointer
    mov [rbp - 88], pState

    ; Generate 8B of keystream in 2 rounds
%assign N 1
%rep 2

    mov rdx, [rbp - 88]       ; load *pState
    lea rsi, [rdx]

    BITS_REORG  N
    NONLIN_FUN  1

    ;Store the keystream
    mov rbx, [rbp - 80]  ; load *pkeystream
    xor eax, r15d
    mov [rbx], eax
    add rbx, 4          ; increment the pointer
    mov [rbp - 80], rbx   ; save pkeystream

    xor         rax, rax

    mov rdx, [rbp - 88]     ; load *pState
    lea rsi, [rdx]

    LFSR_UPDT   N

%assign N N+1
%endrep

    mov rsi, [rbp - 88]   ; load pState


    ; Save ZUC's state variables
    mov         [rsi + OFFSET_FR1], r10d
    mov         [rsi + OFFSET_FR2], r11d
    mov         [rsi + OFFSET_BRC_X0], r12d
    mov         [rsi + OFFSET_BRC_X1], r13d
    mov         [rsi + OFFSET_BRC_X2], r14d
    mov         [rsi + OFFSET_BRC_X3], r15d

    ; Restore non-volatile registers
    mov rbx, [rbp - 8]
    mov r12, [rbp - 32]
    mov r13, [rbp - 40]
    mov r14, [rbp - 48]
    mov r15, [rbp - 56]
%ifndef LINUX
    mov rdi, [rbp - 64]
    mov rsi, [rbp - 72]
%endif

    mov rsp, rbp
    pop rbp

    ret


;;
;; void asm_ZucGenKeystream64B(uint32_t * pKeystream, uint32_t * pState);
;;
;; WIN64
;;	RCX - KS (key stream pointer)
;; 	RDX - STATE (state pointer)
;; LIN64
;;	RDI - KS (key stream pointer)
;;	RSI - STATE (state pointer)
;;
align 16
MKGLOBAL(asm_ZucGenKeystream64B,function,internal)
asm_ZucGenKeystream64B:

%ifdef LINUX
	%define		pKS	rdi
	%define		pState	rsi
%else
	%define		pKS	rcx
	%define		pState	rdx
%endif
    ; save the base pointer
    push rbp

    ;load stack pointer to rbp and reserve memory in the red zone
    mov rbp, rsp
    sub rsp, 196

    ; Save non-volatile registers
    mov [rbp - 8], rbx
    mov [rbp - 32], r12
    mov [rbp - 40], r13
    mov [rbp - 48], r14
    mov [rbp - 56], r15
%ifndef LINUX
    mov [rbp - 64], rdi
    mov [rbp - 72], rsi
%endif


    ; Load input keystream pointer parameter in RAX
    mov         rax, pKS

    ; Restore ZUC's state variables
    xor         r10, r10
    xor         r11, r11
    mov         r10d, [pState + OFFSET_FR1]
    mov         r11d, [pState + OFFSET_FR2]
    mov         r12d, [pState + OFFSET_BRC_X0]
    mov         r13d, [pState + OFFSET_BRC_X1]
    mov         r14d, [pState + OFFSET_BRC_X2]
    mov         r15d, [pState + OFFSET_BRC_X3]

    ; Store keystream pointer
    mov [rbp - 80], rax

    ; Store ZUC State Pointer
    mov [rbp - 88], pState

    ; Generate 64B of keystream in 16 rounds
%assign N 1
%rep 16

    mov rdx, [rbp - 88]       ; load *pState
    lea rsi, [rdx]

    BITS_REORG  N
    NONLIN_FUN  1

    ;Store the keystream
    mov rbx, [rbp - 80]  ; load *pkeystream
    xor eax, r15d
    mov [rbx], eax
    add rbx, 4          ; increment the pointer
    mov [rbp - 80], rbx   ; save pkeystream

    xor         rax, rax

    mov rdx, [rbp - 88]     ; load *pState
    lea rsi, [rdx]

    LFSR_UPDT   N

%assign N N+1
%endrep

    mov rsi, [rbp - 88]   ; load pState


    ; Save ZUC's state variables
    mov         [rsi + OFFSET_FR1], r10d
    mov         [rsi + OFFSET_FR2], r11d
    mov         [rsi + OFFSET_BRC_X0], r12d
    mov         [rsi + OFFSET_BRC_X1], r13d
    mov         [rsi + OFFSET_BRC_X2], r14d
    mov         [rsi + OFFSET_BRC_X3], r15d

    ; Restore non-volatile registers
    mov rbx, [rbp - 8]
    mov r12, [rbp - 32]
    mov r13, [rbp - 40]
    mov r14, [rbp - 48]
    mov r15, [rbp - 56]
%ifndef LINUX
    mov rdi, [rbp - 64]
    mov rsi, [rbp - 72]
%endif

    mov rsp, rbp
    pop rbp

    ret


