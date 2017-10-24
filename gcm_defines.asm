;;
;; Copyright (c) 2012-2017, Intel Corporation
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

POLY            dq     0x0000000000000001, 0xC200000000000000
POLY2           dq     0x00000001C2000000, 0xC200000000000000
TWOONE          dq     0x0000000000000001, 0x0000000100000000

; order of these constants should not change.
; more specifically, ALL_F should follow SHIFT_MASK, and ZERO should follow ALL_F

SHUF_MASK       dq     0x08090A0B0C0D0E0F, 0x0001020304050607
SHIFT_MASK      dq     0x0706050403020100, 0x0f0e0d0c0b0a0908
ALL_F           dq     0xffffffffffffffff, 0xffffffffffffffff
ZERO            dq     0x0000000000000000, 0x0000000000000000
ONE             dq     0x0000000000000001, 0x0000000000000000
TWO             dq     0x0000000000000002, 0x0000000000000000
ONEf            dq     0x0000000000000000, 0x0100000000000000
TWOf            dq     0x0000000000000000, 0x0200000000000000

section .text

;;define the fields of gcm_key_data struct
;; struct gcm_key_data {
;;         uint8_t expanded_keys[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
;;         uint8_t shifted_hkey_1[GCM_ENC_KEY_LEN];  // store HashKey <<1 mod poly here
;;         uint8_t shifted_hkey_2[GCM_ENC_KEY_LEN];  // store HashKey^2 <<1 mod poly here
;;         uint8_t shifted_hkey_3[GCM_ENC_KEY_LEN];  // store HashKey^3 <<1 mod poly here
;;         uint8_t shifted_hkey_4[GCM_ENC_KEY_LEN];  // store HashKey^4 <<1 mod poly here
;;         uint8_t shifted_hkey_5[GCM_ENC_KEY_LEN];  // store HashKey^5 <<1 mod poly here
;;         uint8_t shifted_hkey_6[GCM_ENC_KEY_LEN];  // store HashKey^6 <<1 mod poly here
;;         uint8_t shifted_hkey_7[GCM_ENC_KEY_LEN];  // store HashKey^7 <<1 mod poly here
;;         uint8_t shifted_hkey_8[GCM_ENC_KEY_LEN];  // store HashKey^8 <<1 mod poly here
;;         uint8_t shifted_hkey_1_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
;;         uint8_t shifted_hkey_2_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
;;         uint8_t shifted_hkey_3_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
;;         uint8_t shifted_hkey_4_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
;;         uint8_t shifted_hkey_5_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
;;         uint8_t shifted_hkey_6_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
;;         uint8_t shifted_hkey_7_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
;;         uint8_t shifted_hkey_8_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)
;; }

%define HashKey         (16*15)   ; store HashKey <<1 mod poly here
%define HashKey_1       (16*15)   ; store HashKey <<1 mod poly here
%define HashKey_2       (16*16)   ; store HashKey^2 <<1 mod poly here
%define HashKey_3       (16*17)   ; store HashKey^3 <<1 mod poly here
%define HashKey_4       (16*18)   ; store HashKey^4 <<1 mod poly here
%define HashKey_5       (16*19)   ; store HashKey^5 <<1 mod poly here
%define HashKey_6       (16*20)   ; store HashKey^6 <<1 mod poly here
%define HashKey_7       (16*21)   ; store HashKey^7 <<1 mod poly here
%define HashKey_8       (16*22)   ; store HashKey^8 <<1 mod poly here
%define HashKey_k       (16*23)   ; store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
%define HashKey_2_k     (16*24)   ; store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_3_k     (16*25)   ; store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_4_k     (16*26)   ; store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_5_k     (16*27)   ; store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_6_k     (16*28)   ; store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_7_k     (16*29)   ; store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_8_k     (16*30)   ; store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)

;;define the fields of gcm_context_data struct
;; struct gcm_context_data {
;;         // init, update and finalize context data
;;         uint8_t  aad_hash[GCM_BLOCK_LEN];
;;         uint64_t aad_length;
;;         uint64_t in_length;
;;         uint8_t  partial_block_enc_key[GCM_BLOCK_LEN];
;;         uint8_t  orig_IV[GCM_BLOCK_LEN];
;;         uint8_t  current_counter[GCM_BLOCK_LEN];
;;         uint64_t  partial_block_length;
;; };

%define AadHash		(16*0)	  ; store current Hash of data which has been input
%define AadLen		(16*1)	  ; store length of input data which will not be encrypted or decrypted
%define InLen		((16*1)+8); store length of input data which will be encrypted or decrypted
%define PBlockEncKey	(16*2)	  ; encryption key for the partial block at the end of the previous update
%define OrigIV		(16*3)	  ; input IV
%define CurCount	(16*4)	  ; Current counter for generation of encryption key
%define PBlockLen	(16*5)	  ; length of partial block at the end of the previous update

%define reg(q) xmm %+ q

%ifdef WIN_ABI
	%xdefine arg1 rcx
	%xdefine arg2 rdx
	%xdefine arg3 r8
	%xdefine arg4 r9
	%xdefine arg5  qword [r14 + STACK_OFFSET + 8*5]
	%xdefine arg6  qword [r14 + STACK_OFFSET + 8*6]
	%xdefine arg7  qword [r14 + STACK_OFFSET + 8*7]
	%xdefine arg8  qword [r14 + STACK_OFFSET + 8*8]
	%xdefine arg9  qword [r14 + STACK_OFFSET + 8*9]
	%xdefine arg10 qword [r14 + STACK_OFFSET + 8*10]
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
	%xdefine arg10 [r14 + STACK_OFFSET + 8*4]
%endif

%ifdef NT_LDST
	%define NT_LD
	%define NT_ST
%endif

;;; Use Non-temporal load/stor
%ifdef NT_LD
	%define	XLDR	movntdqa
	%define	VXLDR	vmovntdqa
%else
	%define	XLDR	movdqu
	%define	VXLDR	vmovdqu
%endif

;;; Use Non-temporal load/stor
%ifdef NT_ST
	%define	XSTR	movntdq
	%define	VXSTR	vmovntdq
%else
	%define	XSTR	movdqu
	%define	VXSTR	vmovdqu
%endif
