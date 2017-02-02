;;
;; Copyright (c) 2012-2016, Intel Corporation
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

;
; Authors: 
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford

section .data

align 16

POLY:	;DDQ	0xC2000000000000000000000000000001
	DQ	0x0000000000000001, 0xC200000000000000
POLY2:	;DDQ	0xC20000000000000000000001C2000000
	DQ	0x00000001C2000000, 0xC200000000000000
TWOONE:	;DDQ	0x00000001000000000000000000000001
	DQ	0x0000000000000001, 0x0000000100000000

; order of these constants should not change.
; more specifically, ALL_F should follow SHIFT_MASK, and ZERO should follow ALL_F

SHUF_MASK:	;DDQ	0x000102030405060708090A0B0C0D0E0F
	DQ	0x08090A0B0C0D0E0F, 0x0001020304050607
SHIFT_MASK:	;DDQ	0x0f0e0d0c0b0a09080706050403020100
	DQ	0x0706050403020100, 0x0f0e0d0c0b0a0908
ALL_F:		;DDQ	0xffffffffffffffffffffffffffffffff
	DQ	0xffffffffffffffff, 0xffffffffffffffff
ZERO:		;DDQ	0x00000000000000000000000000000000
	DQ	0x0000000000000000, 0x0000000000000000
ONE:		;DDQ	0x00000000000000000000000000000001
	DQ	0x0000000000000001, 0x0000000000000000
ONEf:		;DDQ	0x01000000000000000000000000000000
	DQ	0x0000000000000000, 0x0100000000000000

section .text


;;define the fields of gcm_data struct
;typedef struct gcm_data
;{
;        u8 expanded_keys[16*15];
;        u8 shifted_hkey_1[16];  // store HashKey <<1 mod poly here
;        u8 shifted_hkey_2[16];  // store HashKey^2 <<1 mod poly here
;        u8 shifted_hkey_3[16];  // store HashKey^3 <<1 mod poly here
;        u8 shifted_hkey_4[16];  // store HashKey^4 <<1 mod poly here
;        u8 shifted_hkey_5[16];  // store HashKey^5 <<1 mod poly here
;        u8 shifted_hkey_6[16];  // store HashKey^6 <<1 mod poly here
;        u8 shifted_hkey_7[16];  // store HashKey^7 <<1 mod poly here
;        u8 shifted_hkey_8[16];  // store HashKey^8 <<1 mod poly here
;        u8 shifted_hkey_1_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
;        u8 shifted_hkey_2_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
;        u8 shifted_hkey_3_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
;        u8 shifted_hkey_4_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
;        u8 shifted_hkey_5_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
;        u8 shifted_hkey_6_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
;        u8 shifted_hkey_7_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
;        u8 shifted_hkey_8_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)
;} gcm_data;

%define HashKey         16*15    ; store HashKey <<1 mod poly here
%define HashKey_2       16*16    ; store HashKey^2 <<1 mod poly here
%define HashKey_3       16*17    ; store HashKey^3 <<1 mod poly here
%define HashKey_4       16*18    ; store HashKey^4 <<1 mod poly here
%define HashKey_5       16*19    ; store HashKey^5 <<1 mod poly here
%define HashKey_6       16*20    ; store HashKey^6 <<1 mod poly here
%define HashKey_7       16*21    ; store HashKey^7 <<1 mod poly here
%define HashKey_8       16*22    ; store HashKey^8 <<1 mod poly here
%define HashKey_k       16*23    ; store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
%define HashKey_2_k     16*24    ; store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_3_k     16*25   ; store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_4_k     16*26   ; store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_5_k     16*27   ; store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_6_k     16*28   ; store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_7_k     16*29   ; store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_8_k     16*30   ; store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)

%define reg(q) xmm %+ q




%ifdef WIN_ABI
    %xdefine arg1 rcx
    %xdefine arg2 rdx
    %xdefine arg3 r8
    %xdefine arg4 r9
    %xdefine arg5 [r14 + STACK_OFFSET + 8*5]
    %xdefine arg6 [r14 + STACK_OFFSET + 8*6]
    %xdefine arg7 [r14 + STACK_OFFSET + 8*7]
    %xdefine arg8 [r14 + STACK_OFFSET + 8*8]
    %xdefine arg9 [r14 + STACK_OFFSET + 8*9]

%else
    %xdefine arg1 rdi
    %xdefine arg2 rsi
    %xdefine arg3 rdx
    %xdefine arg4 rcx
    %xdefine arg5 r8
    %xdefine arg6 r9
    %xdefine arg7 [r14 + STACK_OFFSET + 8*1]
    %xdefine arg8 [r14 + STACK_OFFSET + 8*2]
    %xdefine arg9 [r14 + STACK_OFFSET + 8*3]

%endif
