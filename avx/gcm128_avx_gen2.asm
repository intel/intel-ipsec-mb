;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2017 Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions 
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;
; Authors:
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford
;
;
; References:
;       This code was derived and highly optimized from the code described in paper:
;               Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation on Intel Architecture Processors. August, 2010
;
;       For the shift-based reductions used in this code, we used the method described in paper:
;               Shay Gueron, Michael E. Kounavis. Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode. January, 2010.
;
;
;
;
; Assumptions:
;
;
;
; iv:
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                             Salt  (From the SA)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     Initialization Vector                     |
;       |         (This is the sequence number from IPSec header)       |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x1                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;
;
; AAD:
;       AAD will be padded with 0 to the next 16byte multiple
;       for example, assume AAD is a u32 vector
;
;       if AAD is 8 bytes:
;       AAD[3] = {A0, A1};
;       padded AAD in xmm register = {A1 A0 0 0}
;
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                               SPI (A1)                        |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     32-bit Sequence Number (A0)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x0                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;                                       AAD Format with 32-bit Sequence Number
;
;       if AAD is 12 bytes:
;       AAD[3] = {A0, A1, A2};
;       padded AAD in xmm register = {A2 A1 A0 0}
;
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                               SPI (A2)                        |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                 64-bit Extended Sequence Number {A1,A0}       |
;       |                                                               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x0                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;        AAD Format with 64-bit Extended Sequence Number
;
;
; aadLen:
;       Must be a multiple of 4 bytes and from the definition of the spec.
;       The code additionally supports any aadLen length.
;
; TLen:
;       from the definition of the spec, TLen can only be 8, 12 or 16 bytes.
;
; poly = x^128 + x^127 + x^126 + x^121 + 1
; throughout the code, one tab and two tab indentations are used. one tab is for GHASH part, two tabs is for AES part.
;

%include "reg_sizes.asm"
%include "gcm_defines.asm"

default rel
; need to push 4 registers into stack to maintain
%define STACK_OFFSET 8*4

%define	TMP2	16*0    ; Temporary storage for AES State 2 (State 1 is stored in an XMM register)
%define	TMP3	16*1    ; Temporary storage for AES State 3
%define	TMP4	16*2    ; Temporary storage for AES State 4
%define	TMP5	16*3    ; Temporary storage for AES State 5
%define	TMP6	16*4    ; Temporary storage for AES State 6
%define	TMP7	16*5    ; Temporary storage for AES State 7
%define	TMP8	16*6    ; Temporary storage for AES State 8

%define	LOCAL_STORAGE	16*7

%ifidn __OUTPUT_FORMAT__, win64
	%define	XMM_STORAGE	16*10
%else
	%define	XMM_STORAGE	0
%endif

%define	VARIABLE_OFFSET	LOCAL_STORAGE + XMM_STORAGE

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Utility Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GHASH_MUL MACRO to implement: Data*HashKey mod (128,127,126,121,0)
; Input: A and B (128-bits each, bit-reflected)
; Output: C = A*B*x mod poly, (i.e. >>1 )
; To compute GH = GH*HashKey mod poly, give HK = HashKey<<1 mod poly as input
; GH = GH * HK * x mod poly which is equivalent to GH*HashKey mod poly.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GHASH_MUL  7
%define %%GH %1         ; 16 Bytes
%define %%HK %2         ; 16 Bytes
%define %%T1 %3
%define %%T2 %4
%define %%T3 %5
%define %%T4 %6
%define %%T5 %7
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; Karatsuba
        vpshufd         %%T2, %%GH, 01001110b
        vpshufd         %%T3, %%HK, 01001110b
        vpxor           %%T2, %%T2, %%GH                ; %%T2 = (a1+a0)
        vpxor           %%T3, %%T3, %%HK                ; %%T3 = (b1+b0)

        vpclmulqdq      %%T1, %%GH, %%HK, 0x11          ; %%T1 = a1*b1
        vpclmulqdq      %%GH, %%HK, 0x00                ; %%GH = a0*b0
        vpclmulqdq      %%T2, %%T3, 0x00                ; %%T2 = (a1+a0)*(b1+b0)
        vpxor           %%T2, %%T2, %%GH
        vpxor           %%T2, %%T2, %%T1                ; %%T2 = a0*b1+a1*b0

        vpslldq         %%T3, %%T2, 8                   ; shift-L %%T3 2 DWs
        vpsrldq         %%T2, %%T2, 8                   ; shift-R %%T2 2 DWs
        vpxor           %%GH, %%GH, %%T3
        vpxor           %%T1, %%T1, %%T2                ; <%%T1:%%GH> = %%GH x %%HK

        ;first phase of the reduction
        vpslld  %%T2, %%GH, 31                          ; packed right shifting << 31
        vpslld  %%T3, %%GH, 30                          ; packed right shifting shift << 30
        vpslld  %%T4, %%GH, 25                          ; packed right shifting shift << 25

        vpxor   %%T2, %%T2, %%T3                        ; xor the shifted versions
        vpxor   %%T2, %%T2, %%T4

        vpsrldq %%T5, %%T2, 4                           ; shift-R %%T5 1 DW

        vpslldq %%T2, %%T2, 12                          ; shift-L %%T2 3 DWs
        vpxor   %%GH, %%GH, %%T2                        ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;second phase of the reduction

        vpsrld  %%T2,%%GH,1                             ; packed left shifting >> 1
        vpsrld  %%T3,%%GH,2                             ; packed left shifting >> 2
        vpsrld  %%T4,%%GH,7                             ; packed left shifting >> 7
        vpxor   %%T2, %%T2, %%T3                        ; xor the shifted versions
        vpxor   %%T2, %%T2, %%T4

        vpxor   %%T2, %%T2, %%T5
        vpxor   %%GH, %%GH, %%T2
        vpxor   %%GH, %%GH, %%T1                        ; the result is in %%GH


%endmacro


%macro PRECOMPUTE 8
%define %%GDATA %1
%define %%HK    %2
%define %%T1    %3
%define %%T2    %4
%define %%T3    %5
%define %%T4    %6
%define %%T5    %7
%define %%T6    %8

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Haskey_i_k holds XORed values of the low and high parts of the Haskey_i
        vmovdqa  %%T5, %%HK

        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^2<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_2], %%T5                    ;  [HashKey_2] = HashKey^2<<1 mod poly
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_2_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^3<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_3], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_3_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^4<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_4], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_4_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^5<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_5], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_5_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^6<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_6], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_6_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^7<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_7], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_7_k], %%T1

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^8<<1 mod poly
        vmovdqu  [%%GDATA + HashKey_8], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqu  [%%GDATA + HashKey_8_k], %%T1
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; READ_SMALL_DATA_INPUT: Packs xmm register with data when data input is less than 16 bytes.
; Returns 0 if data has length 0.
; Input: The input data (INPUT), that data's length (LENGTH).
; Output: The packed xmm register (OUTPUT).
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro READ_SMALL_DATA_INPUT	6
%define	%%OUTPUT		%1 ; %%OUTPUT is an xmm register
%define	%%INPUT			%2
%define	%%LENGTH		%3
%define	%%END_READ_LOCATION	%4 ; All this and the lower inputs are temp registers
%define	%%COUNTER		%5
%define	%%TMP1			%6

	vpxor	%%OUTPUT, %%OUTPUT
	mov	%%COUNTER, %%LENGTH
	mov	%%END_READ_LOCATION, %%INPUT
	add	%%END_READ_LOCATION, %%LENGTH
	xor	%%TMP1, %%TMP1


	cmp	%%COUNTER, 8
	jl	%%_byte_loop_2
	vpinsrq	%%OUTPUT, [%%INPUT],0		;Read in 8 bytes if they exists
	je	%%_done

	sub	%%COUNTER, 8

%%_byte_loop_1:					;Read in data 1 byte at a time while data is left
	shl	%%TMP1, 8			;This loop handles when 8 bytes were already read in
	dec	%%END_READ_LOCATION
	mov	BYTE(%%TMP1), BYTE [%%END_READ_LOCATION]
	dec	%%COUNTER
	jg	%%_byte_loop_1
	vpinsrq	%%OUTPUT, %%TMP1, 1
	jmp	%%_done

%%_byte_loop_2:					;Read in data 1 byte at a time while data is left
	cmp	%%COUNTER, 0
	je	%%_done
	shl	%%TMP1, 8			;This loop handles when no bytes were already read in
	dec	%%END_READ_LOCATION
	mov	BYTE(%%TMP1), BYTE [%%END_READ_LOCATION]
	dec	%%COUNTER
	jg	%%_byte_loop_2
	vpinsrq	%%OUTPUT, %%TMP1, 0
%%_done:

%endmacro ; READ_SMALL_DATA_INPUT


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; CALC_AAD_HASH: Calculates the hash of the data which will not be encrypted.
; Input: The input data (A_IN), that data's length (A_LEN), and the hash key (HASH_KEY).
; Output: The hash of the data (AAD_HASH).
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro	CALC_AAD_HASH	14
%define	%%A_IN		%1
%define	%%A_LEN		%2
%define	%%AAD_HASH	%3
%define	%%HASH_KEY	%4
%define	%%XTMP1		%5	; xmm temp reg 5
%define	%%XTMP2		%6
%define	%%XTMP3		%7
%define	%%XTMP4		%8
%define	%%XTMP5		%9	; xmm temp reg 5
%define	%%T1		%10	; temp reg 1
%define	%%T2		%11
%define	%%T3		%12
%define	%%T4		%13
%define	%%T5		%14	; temp reg 5


	mov	%%T1, %%A_IN		; T1 = AAD
	mov	%%T2, %%A_LEN		; T2 = aadLen
	vpxor	%%AAD_HASH, %%AAD_HASH

	cmp	%%T2, 16
	jl	%%_get_small_AAD_block

%%_get_AAD_loop16:

	vmovdqu	%%XTMP1, [%%T1]
	;byte-reflect the AAD data
	vpshufb	%%XTMP1, [SHUF_MASK]
	vpxor	%%AAD_HASH, %%XTMP1
	GHASH_MUL	%%AAD_HASH, %%HASH_KEY, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5

	sub	%%T2, 16
	je	%%_CALC_AAD_done

	add	%%T1, 16
	cmp	%%T2, 16
	jge	%%_get_AAD_loop16

%%_get_small_AAD_block:
	READ_SMALL_DATA_INPUT	%%XTMP1, %%T1, %%T2, %%T3, %%T4, %%T5
	;byte-reflect the AAD data
	vpshufb	%%XTMP1, [SHUF_MASK]
	vpxor	%%AAD_HASH, %%XTMP1
	GHASH_MUL	%%AAD_HASH, %%HASH_KEY, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5

%%_CALC_AAD_done:

%endmacro ; CALC_AAD_HASH



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; PARTIAL_BLOCK: Handles encryption/decryption and the tag partial blocks between update calls.
; Requires the input data be at least 1 byte long.
; Input: gcm_data struct* (GDATA), gcm_data_comp struct* (GDATA_C), input text (PLAIN_CYPH_IN),
; input text length (PLAIN_CYPH_LEN), the current data offset (DATA_OFFSET), and whether
; encoding or decoding (ENC_DEC)
; Output: A cypher of the first partial block (CYPH_PLAIN_OUT), and updated GDATA_C
; Clobbers rax, r10, r12, r13, r15, xmm0, xmm1, xmm2, xmm3, xmm5, xmm6, xmm9, xmm10, xmm11, xmm13
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PARTIAL_BLOCK	8
%define	%%GDATA			%1
%define	%%GDATA_C		%2
%define	%%CYPH_PLAIN_OUT	%3
%define	%%PLAIN_CYPH_IN		%4
%define	%%PLAIN_CYPH_LEN	%5
%define	%%DATA_OFFSET		%6
%define	%%AAD_HASH		%7
%define	%%ENC_DEC		%8
	mov	r13, [%%GDATA_C + PBlockLen]
	cmp	r13, 0
	je	%%_partial_block_done		;Leave Macro if no partial blocks

	cmp	%%PLAIN_CYPH_LEN, 16		;Read in input data without over reading
	jl	%%_fewer_than_16_bytes
	VXLDR	xmm1, [%%PLAIN_CYPH_IN]		;If more than 16 bytes of data, just fill the xmm register
	jmp	%%_data_read

%%_fewer_than_16_bytes:
	lea	r10, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
	READ_SMALL_DATA_INPUT	xmm1, r10, %%PLAIN_CYPH_LEN, rax, r12, r15

%%_data_read:				;Finished reading in data


	vmovdqu	xmm9, [%%GDATA_C + PBlockEncKey]	;xmm9 = my_comp_data.partial_block_enc_key
	vmovdqu	xmm13, [%%GDATA + HashKey]

	lea	r12, [SHIFT_MASK]

	cmp	r13, rax
	add	r12, r13			; adjust the shuffle mask pointer to be able to shift r13 bytes (16-r13 is the number of bytes in plaintext mod 16)
	vmovdqu	xmm2, [r12]			; get the appropriate shuffle mask
	vpshufb	xmm9, xmm2			;shift right r13 bytes

%ifidn	%%ENC_DEC, DEC
	vmovdqa	xmm3, xmm1
	vpxor	xmm9, xmm1			; Cyphertext XOR E(K, Yn)

	mov	r15, %%PLAIN_CYPH_LEN
	add	r15, r13
	sub	r15, 16				;Set r15 to be the amount of data left in CYPH_PLAIN_IN after filling the block
	jge	%%_no_extra_mask_1		;Determine if if partial block is not being filled and shift mask accordingly
	sub	r12, r15
%%_no_extra_mask_1:

	vmovdqu	xmm1, [r12 + ALL_F-SHIFT_MASK]	; get the appropriate mask to mask out bottom r13 bytes of xmm9
	vpand	xmm9, xmm1			; mask out bottom r13 bytes of xmm9

	vpand	xmm3, xmm1
	vpshufb	xmm3, [SHUF_MASK]
	vpshufb	xmm3, xmm2
	vpxor	%%AAD_HASH, xmm3


	cmp	r15,0
	jl	%%_partial_incomplete_1

	GHASH_MUL	%%AAD_HASH, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6	;GHASH computation for the last <16 Byte block
	xor	rax,rax
	mov	[%%GDATA_C + PBlockLen], rax
	jmp	%%_dec_done
%%_partial_incomplete_1:
	add	[%%GDATA_C + PBlockLen], %%PLAIN_CYPH_LEN
%%_dec_done:
	vmovdqu	[%%GDATA_C + AadHash], %%AAD_HASH

%else
	vpxor	xmm9, xmm1	; Plaintext XOR E(K, Yn)

	mov	r15, %%PLAIN_CYPH_LEN
	add	r15, r13
	sub	r15, 16				;Set r15 to be the amount of data left in CYPH_PLAIN_IN after filling the block
	jge	%%_no_extra_mask_2		;Determine if if partial block is not being filled and shift mask accordingly
	sub	r12, r15
%%_no_extra_mask_2:

	vmovdqu	xmm1, [r12 + ALL_F-SHIFT_MASK]	; get the appropriate mask to mask out bottom r13 bytes of xmm9
	vpand	xmm9, xmm1			; mask out bottom r13  bytes of xmm9

	vpshufb	xmm9, [SHUF_MASK]
	vpshufb	xmm9, xmm2
	vpxor	%%AAD_HASH, xmm9

	cmp	r15,0
	jl	%%_partial_incomplete_2

	GHASH_MUL	%%AAD_HASH, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6	;GHASH computation for the last <16 Byte block
	xor	rax,rax
	mov	[%%GDATA_C + PBlockLen], rax
	jmp	%%_encode_done
%%_partial_incomplete_2:
	add [%%GDATA_C + PBlockLen], %%PLAIN_CYPH_LEN
%%_encode_done:
	vmovdqu	[%%GDATA_C + AadHash], %%AAD_HASH

	vpshufb	xmm9, [SHUF_MASK]	; shuffle xmm9 back to output as ciphertext
	vpshufb	xmm9, xmm2
%endif


	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	; output encrypted Bytes
	cmp	r15,0
	jl	%%_partial_fill
	mov	r12, r13
	mov	r13, 16
	sub	r13, r12			; Set r13 to be the number of bytes to write out
	jmp	%%_count_set
%%_partial_fill:
	mov	r13, %%PLAIN_CYPH_LEN
%%_count_set:
	vmovq	rax, xmm9
	cmp	r13, 8
	jle	%%_less_than_8_bytes_left

	mov	[%%CYPH_PLAIN_OUT+ %%DATA_OFFSET], rax
	add	%%DATA_OFFSET, 8
	vpsrldq	xmm9, xmm9, 8
	vmovq	rax, xmm9
	sub	r13, 8
%%_less_than_8_bytes_left:
	mov	BYTE [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], al
	add	%%DATA_OFFSET, 1
	shr	rax, 8
	sub	r13, 1
	jne	%%_less_than_8_bytes_left
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%%_partial_block_done:
%endmacro ; PARTIAL_BLOCK


; if a = number of total plaintext bytes
; b = floor(a/16)
; %%num_initial_blocks = b mod 8;
; encrypt the initial %%num_initial_blocks blocks and apply ghash on the ciphertext
; %%GDATA, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r14 are used as a pointer only, not modified.
; Updated AAD_HASH is returned in %%T3

%macro INITIAL_BLOCKS 24
%define	%%GDATA			%1
%define	%%GDATA_C		%2
%define	%%CYPH_PLAIN_OUT	%3
%define	%%PLAIN_CYPH_IN		%4
%define	%%LENGTH		%5
%define	%%DATA_OFFSET		%6
%define	%%num_initial_blocks	%7      ; can be 0, 1, 2, 3, 4, 5, 6 or 7
%define	%%T1		%8
%define	%%HASH_KEY	%9
%define	%%T3		%10
%define	%%T4		%11
%define	%%T5		%12
%define	%%CTR		%13
%define	%%XMM1		%14
%define	%%XMM2		%15
%define	%%XMM3		%16
%define	%%XMM4		%17
%define	%%XMM5		%18
%define	%%XMM6		%19
%define	%%XMM7		%20
%define	%%XMM8		%21
%define	%%T6		%22
%define	%%T_key		%23
%define	%%ENC_DEC	%24

%assign i (8-%%num_initial_blocks)
		vmovdqu	reg(i), %%XMM8	; move AAD_HASH to temp reg
	        ; start AES for %%num_initial_blocks blocks
	        vmovdqu  %%CTR, [%%GDATA_C + CurCount]                   ; %%CTR = Y0


%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vpaddd   %%CTR, [ONE]           ; INCR Y0
                vmovdqa  reg(i), %%CTR
                vpshufb  reg(i), [SHUF_MASK]     ; perform a 16Byte swap
%assign i (i+1)
%endrep

vmovdqu  %%T_key, [%%GDATA+16*0]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vpxor    reg(i),%%T_key
%assign i (i+1)
%endrep

%assign j 1
%rep 9
vmovdqu  %%T_key, [%%GDATA+16*j]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenc  reg(i),%%T_key
%assign i (i+1)
%endrep

%assign j (j+1)
%endrep


vmovdqu  %%T_key, [%%GDATA+16*10]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenclast      reg(i),%%T_key
%assign i (i+1)
%endrep

%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
                vpxor    reg(i), %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], reg(i)            ; write back ciphertext for %%num_initial_blocks blocks
                add     %%DATA_OFFSET, 16
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  reg(i), %%T1
                %endif
                vpshufb  reg(i), [SHUF_MASK]     ; prepare ciphertext for GHASH computations
%assign i (i+1)
%endrep


%assign i (8-%%num_initial_blocks)
%assign j (9-%%num_initial_blocks)

%rep %%num_initial_blocks
        vpxor    reg(j), reg(i)
        GHASH_MUL       reg(j), %%HASH_KEY, %%T1, %%T3, %%T4, %%T5, %%T6      ; apply GHASH on %%num_initial_blocks blocks
%assign i (i+1)
%assign j (j+1)
%endrep
	; %%XMM8 has the current Hash Value
        vmovdqa  %%T3, %%XMM8

        cmp     %%LENGTH, 128
        jl      %%_initial_blocks_done                  ; no need for precomputed constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Haskey_i_k holds XORed values of the low and high parts of the Haskey_i
                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM1, %%CTR
                vpshufb  %%XMM1, [SHUF_MASK]             ; perform a 16Byte swap

                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM2, %%CTR
                vpshufb  %%XMM2, [SHUF_MASK]             ; perform a 16Byte swap

                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM3, %%CTR
                vpshufb  %%XMM3, [SHUF_MASK]             ; perform a 16Byte swap

                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM4, %%CTR
                vpshufb  %%XMM4, [SHUF_MASK]             ; perform a 16Byte swap

                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM5, %%CTR
                vpshufb  %%XMM5, [SHUF_MASK]             ; perform a 16Byte swap

                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM6, %%CTR
                vpshufb  %%XMM6, [SHUF_MASK]             ; perform a 16Byte swap

                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM7, %%CTR
                vpshufb  %%XMM7, [SHUF_MASK]             ; perform a 16Byte swap

                vpaddd   %%CTR, [ONE]                   ; INCR Y0
                vmovdqa  %%XMM8, %%CTR
                vpshufb  %%XMM8, [SHUF_MASK]             ; perform a 16Byte swap

                vmovdqu  %%T_key, [%%GDATA+16*0]
                vpxor    %%XMM1, %%T_key
                vpxor    %%XMM2, %%T_key
                vpxor    %%XMM3, %%T_key
                vpxor    %%XMM4, %%T_key
                vpxor    %%XMM5, %%T_key
                vpxor    %%XMM6, %%T_key
                vpxor    %%XMM7, %%T_key
                vpxor    %%XMM8, %%T_key


%assign i 1
%rep    9       ; do 9 rounds
                vmovdqu  %%T_key, [%%GDATA+16*i]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key
%assign i (i+1)
%endrep


                vmovdqu          %%T_key, [%%GDATA+16*i]
                vaesenclast      %%XMM1, %%T_key
                vaesenclast      %%XMM2, %%T_key
                vaesenclast      %%XMM3, %%T_key
                vaesenclast      %%XMM4, %%T_key
                vaesenclast      %%XMM5, %%T_key
                vaesenclast      %%XMM6, %%T_key
                vaesenclast      %%XMM7, %%T_key
                vaesenclast      %%XMM8, %%T_key

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*0]
                vpxor    %%XMM1, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*0], %%XMM1
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM1, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*1]
                vpxor    %%XMM2, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*1], %%XMM2
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM2, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*2]
                vpxor    %%XMM3, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*2], %%XMM3
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM3, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*3]
                vpxor    %%XMM4, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*3], %%XMM4
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM4, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*4]
                vpxor    %%XMM5, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*4], %%XMM5
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM5, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*5]
                vpxor    %%XMM6, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*5], %%XMM6
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM6, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*6]
                vpxor    %%XMM7, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*6], %%XMM7
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM7, %%T1
                %endif

                VXLDR  %%T1, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 16*7]
                vpxor    %%XMM8, %%T1
                VXSTR  [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 16*7], %%XMM8
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM8, %%T1
                %endif

                add     %%DATA_OFFSET, 128

                vpshufb  %%XMM1, [SHUF_MASK]             ; perform a 16Byte swap
                vpxor    %%XMM1, %%T3                   	 ; combine GHASHed value with the corresponding ciphertext
                vpshufb  %%XMM2, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM3, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM4, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM5, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM6, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM7, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM8, [SHUF_MASK]             ; perform a 16Byte swap

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_initial_blocks_done:


%endmacro


; encrypt 8 blocks at a time
; ghash the 8 previously encrypted ciphertext blocks
; %%GDATA, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN are used as pointers only, not modified
; r11 is the data offset value
%macro	GHASH_8_ENCRYPT_8_PARALLEL 22
%define	%%GDATA			%1
%define	%%CYPH_PLAIN_OUT	%2
%define	%%PLAIN_CYPH_IN		%3
%define	%%DATA_OFFSET		%4
%define	%%T1	%5
%define	%%T2	%6
%define	%%T3	%7
%define	%%T4	%8
%define	%%T5	%9
%define	%%T6	%10
%define	%%CTR	%11
%define	%%XMM1	%12
%define	%%XMM2	%13
%define	%%XMM3	%14
%define	%%XMM4	%15
%define	%%XMM5	%16
%define	%%XMM6	%17
%define	%%XMM7	%18
%define	%%XMM8	%19
%define	%%T7	%20
%define	%%loop_idx	%21
%define	%%ENC_DEC	%22

        vmovdqa %%T2, %%XMM1
        vmovdqu [rsp + TMP2], %%XMM2
        vmovdqu [rsp + TMP3], %%XMM3
        vmovdqu [rsp + TMP4], %%XMM4
        vmovdqu [rsp + TMP5], %%XMM5
        vmovdqu [rsp + TMP6], %%XMM6
        vmovdqu [rsp + TMP7], %%XMM7
        vmovdqu [rsp + TMP8], %%XMM8

%ifidn %%loop_idx, in_order
                vpaddd  %%XMM1, %%CTR,  [ONE]           ; INCR CNT
                vpaddd  %%XMM2, %%XMM1, [ONE]
                vpaddd  %%XMM3, %%XMM2, [ONE]
                vpaddd  %%XMM4, %%XMM3, [ONE]
                vpaddd  %%XMM5, %%XMM4, [ONE]
                vpaddd  %%XMM6, %%XMM5, [ONE]
                vpaddd  %%XMM7, %%XMM6, [ONE]
                vpaddd  %%XMM8, %%XMM7, [ONE]
                vmovdqa %%CTR, %%XMM8

                vpshufb %%XMM1, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM2, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM3, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM4, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM5, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM6, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM7, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM8, [SHUF_MASK]             ; perform a 16Byte swap
%else
                vpaddd  %%XMM1, %%CTR,  [ONEf]                  ; INCR CNT
                vpaddd  %%XMM2, %%XMM1, [ONEf]
                vpaddd  %%XMM3, %%XMM2, [ONEf]
                vpaddd  %%XMM4, %%XMM3, [ONEf]
                vpaddd  %%XMM5, %%XMM4, [ONEf]
                vpaddd  %%XMM6, %%XMM5, [ONEf]
                vpaddd  %%XMM7, %%XMM6, [ONEf]
                vpaddd  %%XMM8, %%XMM7, [ONEf]
                vmovdqa %%CTR, %%XMM8
%endif



        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                vmovdqu %%T1, [%%GDATA + 16*0]
                vpxor   %%XMM1, %%T1
                vpxor   %%XMM2, %%T1
                vpxor   %%XMM3, %%T1
                vpxor   %%XMM4, %%T1
                vpxor   %%XMM5, %%T1
                vpxor   %%XMM6, %%T1
                vpxor   %%XMM7, %%T1
                vpxor   %%XMM8, %%T1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;





                vmovdqu %%T1, [%%GDATA + 16*1]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1


                vmovdqu %%T1, [%%GDATA + 16*2]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        vmovdqu         %%T5, [%%GDATA + HashKey_8]
        vpclmulqdq      %%T4, %%T2, %%T5, 0x11                  ; %%T4 = a1*b1
        vpclmulqdq      %%T7, %%T2, %%T5, 0x00                  ; %%T7 = a0*b0

        vpshufd         %%T6, %%T2, 01001110b
        vpxor           %%T6, %%T2

        vmovdqu         %%T5, [%%GDATA + HashKey_8_k]
        vpclmulqdq      %%T6, %%T6, %%T5, 0x00                  ;


                vmovdqu %%T1, [%%GDATA + 16*3]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP2]
        vmovdqu         %%T5, [%%GDATA + HashKey_7]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqu         %%T5, [%%GDATA + HashKey_7_k]
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*4]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu         %%T1, [rsp + TMP3]
        vmovdqu         %%T5, [%%GDATA + HashKey_6]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqu         %%T5, [%%GDATA + HashKey_6_k]
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*5]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1


        vmovdqu         %%T1, [rsp + TMP4]
        vmovdqu         %%T5, [%%GDATA + HashKey_5]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqu         %%T5, [%%GDATA + HashKey_5_k]
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*6]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP5]
        vmovdqu         %%T5, [%%GDATA + HashKey_4]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqu         %%T5, [%%GDATA + HashKey_4_k]
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3


                vmovdqu %%T1, [%%GDATA + 16*7]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP6]
        vmovdqu         %%T5, [%%GDATA + HashKey_3]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqu         %%T5, [%%GDATA + HashKey_3_k]
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

                vmovdqu %%T1, [%%GDATA + 16*8]
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

        vmovdqu         %%T1, [rsp + TMP7]
        vmovdqu         %%T5, [%%GDATA + HashKey_2]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqu         %%T5, [%%GDATA + HashKey_2_k]
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                vmovdqu %%T5, [%%GDATA + 16*9]
                vaesenc %%XMM1, %%T5
                vaesenc %%XMM2, %%T5
                vaesenc %%XMM3, %%T5
                vaesenc %%XMM4, %%T5
                vaesenc %%XMM5, %%T5
                vaesenc %%XMM6, %%T5
                vaesenc %%XMM7, %%T5
                vaesenc %%XMM8, %%T5

        vmovdqu         %%T1, [rsp + TMP8]
        vmovdqu         %%T5, [%%GDATA + HashKey]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqu         %%T5, [%%GDATA + HashKey_k]
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10
        vpxor           %%T6, %%T6, %%T3

        vpxor           %%T6, %%T4
        vpxor           %%T6, %%T7


		vmovdqu         %%T5, [%%GDATA + 16*10]

%assign i 0
%assign j 1
%rep 8
		%ifidn %%ENC_DEC, ENC

		%ifdef	NT_LD
		VXLDR	%%T2, [%%PLAIN_CYPH_IN+%%DATA_OFFSET+16*i]
		vpxor	%%T2, %%T2, %%T5
		%else
		vpxor   %%T2, %%T5, [%%PLAIN_CYPH_IN+%%DATA_OFFSET+16*i]
		%endif

		vaesenclast     reg(j), reg(j), %%T2

		%else

		VXLDR	%%T2, [%%PLAIN_CYPH_IN+%%DATA_OFFSET+16*i]
		vpxor	%%T2, %%T2, %%T5
		vaesenclast     %%T3, reg(j), %%T2
		vpxor	reg(j), %%T2, %%T5
		VXSTR [%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*i], %%T3

		%endif

%assign i (i+1)
%assign j (j+1)
%endrep

        vpslldq %%T3, %%T6, 8           ; shift-L %%T3 2 DWs
        vpsrldq %%T6, %%T6, 8           ; shift-R %%T2 2 DWs
        vpxor   %%T7, %%T3
        vpxor   %%T6, %%T4              ; accumulate the results in %%T6:%%T7


        ;first phase of the reduction

        vpslld  %%T2, %%T7, 31                                  ; packed right shifting << 31
        vpslld  %%T3, %%T7, 30                                  ; packed right shifting shift << 30
        vpslld  %%T4, %%T7, 25                                  ; packed right shifting shift << 25

        vpxor   %%T2, %%T2, %%T3                                ; xor the shifted versions
        vpxor   %%T2, %%T2, %%T4

        vpsrldq %%T1, %%T2, 4                                   ; shift-R %%T1 1 DW

        vpslldq %%T2, %%T2, 12                                  ; shift-L %%T2 3 DWs
        vpxor   %%T7, %%T2                                      ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		%ifidn %%ENC_DEC, ENC
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*0], %%XMM1			; Write to the Ciphertext buffer
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*1], %%XMM2			; Write to the Ciphertext buffer
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*2], %%XMM3			; Write to the Ciphertext buffer
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*3], %%XMM4			; Write to the Ciphertext buffer
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*4], %%XMM5			; Write to the Ciphertext buffer
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*5], %%XMM6			; Write to the Ciphertext buffer
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*6], %%XMM7			; Write to the Ciphertext buffer
		VXSTR	[%%CYPH_PLAIN_OUT+%%DATA_OFFSET+16*7], %%XMM8			; Write to the Ciphertext buffer
                %endif

        ;second phase of the reduction

        vpsrld  %%T2,%%T7,1                                     ; packed left shifting >> 1
        vpsrld  %%T3,%%T7,2                                     ; packed left shifting >> 2
        vpsrld  %%T4,%%T7,7                                     ; packed left shifting >> 7
        vpxor   %%T2, %%T2,%%T3                                 ; xor the shifted versions
        vpxor   %%T2, %%T2,%%T4

        vpxor   %%T2, %%T2, %%T1
        vpxor   %%T7, %%T7, %%T2
        vpxor   %%T6, %%T6, %%T7                                ; the result is in %%T6



                vpshufb %%XMM1, [SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM2, [SHUF_MASK]
                vpshufb %%XMM3, [SHUF_MASK]
                vpshufb %%XMM4, [SHUF_MASK]
                vpshufb %%XMM5, [SHUF_MASK]
                vpshufb %%XMM6, [SHUF_MASK]
                vpshufb %%XMM7, [SHUF_MASK]
                vpshufb %%XMM8, [SHUF_MASK]


        vpxor   %%XMM1, %%T6

%endmacro


; GHASH the last 4 ciphertext blocks.
%macro	GHASH_LAST_8 16
%define	%%GDATA	%1
%define	%%T1	%2
%define	%%T2	%3
%define	%%T3	%4
%define	%%T4	%5
%define	%%T5	%6
%define	%%T6	%7
%define	%%T7	%8
%define	%%XMM1	%9
%define	%%XMM2	%10
%define	%%XMM3	%11
%define	%%XMM4	%12
%define	%%XMM5	%13
%define	%%XMM6	%14
%define	%%XMM7	%15
%define	%%XMM8	%16
        ;; Karatsuba Method


        vpshufd         %%T2, %%XMM1, 01001110b
        vpxor           %%T2, %%XMM1
        vmovdqu         %%T5, [%%GDATA + HashKey_8]
        vpclmulqdq      %%T6, %%XMM1, %%T5, 0x11
        vpclmulqdq      %%T7, %%XMM1, %%T5, 0x00

        vmovdqu         %%T3, [%%GDATA + HashKey_8_k]
        vpclmulqdq      %%XMM1, %%T2, %%T3, 0x00


        ;;;;;;;;;;;;;;;;;;;;;;


        vpshufd         %%T2, %%XMM2, 01001110b
        vpxor           %%T2, %%XMM2
        vmovdqu         %%T5, [%%GDATA + HashKey_7]
        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vmovdqu         %%T3, [%%GDATA + HashKey_7_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;


        vpshufd         %%T2, %%XMM3, 01001110b
        vpxor           %%T2, %%XMM3
        vmovdqu         %%T5, [%%GDATA + HashKey_6]
        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vmovdqu         %%T3, [%%GDATA + HashKey_6_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;


        vpshufd         %%T2, %%XMM4, 01001110b
        vpxor           %%T2, %%XMM4
        vmovdqu         %%T5, [%%GDATA + HashKey_5]
        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vmovdqu         %%T3, [%%GDATA + HashKey_5_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vpshufd         %%T2, %%XMM5, 01001110b
        vpxor           %%T2, %%XMM5
        vmovdqu         %%T5, [%%GDATA + HashKey_4]
        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vmovdqu         %%T3, [%%GDATA + HashKey_4_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vpshufd         %%T2, %%XMM6, 01001110b
        vpxor           %%T2, %%XMM6
        vmovdqu         %%T5, [%%GDATA + HashKey_3]

        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vmovdqu         %%T3, [%%GDATA + HashKey_3_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vpshufd         %%T2, %%XMM7, 01001110b
        vpxor           %%T2, %%XMM7
        vmovdqu         %%T5, [%%GDATA + HashKey_2]
        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vmovdqu         %%T3, [%%GDATA + HashKey_2_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vpshufd         %%T2, %%XMM8, 01001110b
        vpxor           %%T2, %%XMM8
        vmovdqu         %%T5, [%%GDATA + HashKey]
        vpclmulqdq      %%T4, %%XMM8, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4

        vpclmulqdq      %%T4, %%XMM8, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4

        vmovdqu         %%T3, [%%GDATA + HashKey_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00

        vpxor           %%XMM1, %%XMM1, %%T2
        vpxor           %%XMM1, %%XMM1, %%T6
        vpxor           %%T2, %%XMM1, %%T7




        vpslldq         %%T4, %%T2, 8
        vpsrldq         %%T2, %%T2, 8

        vpxor           %%T7, %%T4
        vpxor           %%T6, %%T2                                      ; <%%T6:%%T7> holds the result of the accumulated carry-less multiplications

        ;first phase of the reduction

        vpslld          %%T2, %%T7, 31                                  ; packed right shifting << 31
        vpslld          %%T3, %%T7, 30                                  ; packed right shifting shift << 30
        vpslld          %%T4, %%T7, 25                                  ; packed right shifting shift << 25

        vpxor           %%T2, %%T2, %%T3                                ; xor the shifted versions
        vpxor           %%T2, %%T2, %%T4

        vpsrldq         %%T1, %%T2, 4                                   ; shift-R %%T1 1 DW

        vpslldq         %%T2, %%T2, 12                                  ; shift-L %%T2 3 DWs
        vpxor           %%T7, %%T2                                      ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;second phase of the reduction

        vpsrld          %%T2,%%T7,1                                     ; packed left shifting >> 1
        vpsrld          %%T3,%%T7,2                                     ; packed left shifting >> 2
        vpsrld          %%T4,%%T7,7                                     ; packed left shifting >> 7
        vpxor           %%T2, %%T2,%%T3                                 ; xor the shifted versions
        vpxor           %%T2, %%T2,%%T4

        vpxor           %%T2, %%T2, %%T1
        vpxor           %%T7, %%T7, %%T2
        vpxor           %%T6, %%T6, %%T7                                ; the result is in %%T6


%endmacro


; Encryption of a single block
%macro	ENCRYPT_SINGLE_BLOCK 2
%define	%%GDATA	%1
%define	%%XMM0	%2

                vpxor    %%XMM0, [%%GDATA+16*0]
%assign i 1
%rep 9
                vaesenc  %%XMM0, [%%GDATA+16*i]
%assign i (i+1)
%endrep
                vaesenclast      %%XMM0, [%%GDATA+16*10]
%endmacro


;; Start of Stack Setup

%macro FUNC_SAVE 0
	;; Required for Update/GMC_ENC
	;the number of pushes must equal STACK_OFFSET
	push    r12
	push    r13
	push    r14
	push    r15
	mov     r14, rsp

	sub     rsp, VARIABLE_OFFSET
	and     rsp, ~63

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
	vmovdqu [rsp + LOCAL_STORAGE + 0*16],xmm6
	vmovdqu [rsp + LOCAL_STORAGE + 1*16],xmm7
	vmovdqu [rsp + LOCAL_STORAGE + 2*16],xmm8
	vmovdqu [rsp + LOCAL_STORAGE + 3*16],xmm9
	vmovdqu [rsp + LOCAL_STORAGE + 4*16],xmm10
	vmovdqu [rsp + LOCAL_STORAGE + 5*16],xmm11
	vmovdqu [rsp + LOCAL_STORAGE + 6*16],xmm12
	vmovdqu [rsp + LOCAL_STORAGE + 7*16],xmm13
	vmovdqu [rsp + LOCAL_STORAGE + 8*16],xmm14
	vmovdqu [rsp + LOCAL_STORAGE + 9*16],xmm15
%endif
%endmacro


%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqu xmm15  , [rsp + LOCAL_STORAGE + 9*16]
	vmovdqu xmm14  , [rsp + LOCAL_STORAGE + 8*16]
	vmovdqu xmm13  , [rsp + LOCAL_STORAGE + 7*16]
	vmovdqu xmm12  , [rsp + LOCAL_STORAGE + 6*16]
	vmovdqu xmm11  , [rsp + LOCAL_STORAGE + 5*16]
	vmovdqu xmm10  , [rsp + LOCAL_STORAGE + 4*16]
	vmovdqu xmm9 , [rsp + LOCAL_STORAGE + 3*16]
	vmovdqu xmm8 , [rsp + LOCAL_STORAGE + 2*16]
	vmovdqu xmm7 , [rsp + LOCAL_STORAGE + 1*16]
	vmovdqu xmm6 , [rsp + LOCAL_STORAGE + 0*16]
%endif

;; Required for Update/GMC_ENC
	mov     rsp, r14
	pop     r15
	pop     r14
	pop     r13
	pop     r12
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_INIT initializes a gcm_data struct to prepare for encoding/decoding.
; Input: gcm_data struct* (GDATA), gcm_data_comp struct* (GDATA_C), IV, Additional
; Authentication data (A_IN), Additional Data length (A_LEN)
; Output: Updated GDATA_C with the hash of A_IN (AadHash) and initialized other parts of GDATA_C.
; Clobbers rax, r10-r13, and xmm0-xmm6
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro	GCM_INIT 	5
%define	%%GDATA		%1
%define	%%GDATA_C	%2
%define	%%IV		%3
%define	%%A_IN		%4
%define	%%A_LEN		%5
%define	%%AAD_HASH	xmm0
%define	%%SUBHASH	xmm1


	vmovdqu	%%SUBHASH, [%%GDATA + HashKey]

	CALC_AAD_HASH %%A_IN, %%A_LEN, %%AAD_HASH, %%SUBHASH, xmm2, xmm3, xmm4, xmm5, xmm6, r10, r11, r12, r13, rax
	vpxor	xmm2, xmm3
	mov	r10, %%A_LEN

	vmovdqu	[%%GDATA_C + AadHash], %%AAD_HASH	; my_comp_data.aad hash = aad_hash
	mov	[%%GDATA_C + AadLen], r10		; my_comp_data.aad_length = aad_length
	xor	r10, r10
	mov	[%%GDATA_C + InLen], r10		; my_comp_data.in_length = 0
	mov	[%%GDATA_C + PBlockLen], r10		; my_comp_data.partial_block_length = 0
	vmovdqu	[%%GDATA_C + PBlockEncKey], xmm2	; my_comp_data.partial_block_enc_key = 0
	mov	r10, %%IV
	vmovdqu	xmm2, [r10]
	vmovdqu	[%%GDATA_C + OrigIV], xmm2		; my_comp_data.orig_IV = iv

	vpshufb xmm2, [SHUF_MASK]

	vmovdqu	[%%GDATA_C + CurCount], xmm2		; my_comp_data.current_counter = iv
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_ENC_DEC Encodes/Decodes given data. Assumes that the passed gcm_data struct has been
; initialized by GCM_INIT
; Requires the input data be at least 1 byte long because of READ_SMALL_INPUT_DATA.
; Input: gcm_data struct* (GDATA), gcm_data_comp struct* (GDATA_C), input text (PLAIN_CYPH_IN),
; input text length (PLAIN_CYPH_LEN), and whether encoding or decoding (ENC_DEC)
; Output: A cypher of the given plain text (CYPH_PLAIN_OUT), and updated GDATA
; Clobbers rax, r10-r15, and xmm0-xmm15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro	GCM_ENC_DEC 		6
%define	%%GDATA			%1
%define	%%GDATA_C		%2
%define	%%CYPH_PLAIN_OUT	%3
%define	%%PLAIN_CYPH_IN		%4
%define	%%PLAIN_CYPH_LEN	%5
%define	%%ENC_DEC		%6
%define	%%DATA_OFFSET		r11

; Macro flow:
; calculate the number of 16byte blocks in the message
; process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
; process 8 16 byte blocks at a time until all are done '%%_encrypt_by_8_new .. %%_eight_cipher_left'
; if there is a block of less tahn 16 bytes process it '%%_zero_cipher_left .. %%_multiple_of_16_bytes'
	cmp	%%PLAIN_CYPH_LEN, 0
	je	%%_multiple_of_16_bytes

	xor %%DATA_OFFSET, %%DATA_OFFSET
	add [%%GDATA_C + InLen], %%PLAIN_CYPH_LEN ;Update length of data processed
	vmovdqu  xmm13, [%%GDATA + HashKey]                 ; xmm13 = HashKey
	vmovdqu xmm8, [%%GDATA_C + AadHash]


	PARTIAL_BLOCK %%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%PLAIN_CYPH_LEN, %%DATA_OFFSET, xmm8, %%ENC_DEC


	mov	r13, %%PLAIN_CYPH_LEN
	sub	r13, %%DATA_OFFSET
	mov	r10, r13				; save the amount of data left to process in r10
	and     r13, -16                                ; r13 = r13 - (r13 mod 16)

        mov     r12, r13
        shr     r12, 4
        and     r12, 7

        jz      %%_initial_num_blocks_is_0

        cmp     r12, 7
        je      %%_initial_num_blocks_is_7
        cmp     r12, 6
        je      %%_initial_num_blocks_is_6
        cmp     r12, 5
        je      %%_initial_num_blocks_is_5
        cmp     r12, 4
        je      %%_initial_num_blocks_is_4
        cmp     r12, 3
        je      %%_initial_num_blocks_is_3
        cmp     r12, 2
        je      %%_initial_num_blocks_is_2

        jmp     %%_initial_num_blocks_is_1

%%_initial_num_blocks_is_7:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 7, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*7
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_6:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 6, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*6
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_5:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 5, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*5
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_4:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 4, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*4
        jmp     %%_initial_blocks_encrypted


%%_initial_num_blocks_is_3:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 3, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*3
        jmp     %%_initial_blocks_encrypted
%%_initial_num_blocks_is_2:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 2, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*2
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_1:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 1, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_0:
	INITIAL_BLOCKS	%%GDATA, %%GDATA_C, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, r13, %%DATA_OFFSET, 0, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC


%%_initial_blocks_encrypted:
        cmp     r13, 0
        je      %%_zero_cipher_left

        sub     r13, 128
        je      %%_eight_cipher_left




        vmovd    r15d, xmm9
        and     r15d, 255
        vpshufb  xmm9, [SHUF_MASK]


%%_encrypt_by_8_new:
        cmp     r15d, 255-8
        jg      %%_encrypt_by_8



        add     r15b, 8
	GHASH_8_ENCRYPT_8_PARALLEL	%%GDATA, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, %%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, out_order, %%ENC_DEC
        add     %%DATA_OFFSET, 128
        sub     r13, 128
        jne     %%_encrypt_by_8_new

        vpshufb  xmm9, [SHUF_MASK]
        jmp     %%_eight_cipher_left

%%_encrypt_by_8:
        vpshufb  xmm9, [SHUF_MASK]
        add     r15b, 8
	GHASH_8_ENCRYPT_8_PARALLEL	%%GDATA, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN,%%DATA_OFFSET, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, in_order, %%ENC_DEC
        vpshufb  xmm9, [SHUF_MASK]
        add     %%DATA_OFFSET, 128
        sub     r13, 128
        jne     %%_encrypt_by_8_new

        vpshufb  xmm9, [SHUF_MASK]




%%_eight_cipher_left:
	GHASH_LAST_8	%%GDATA, xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8


%%_zero_cipher_left:
	vmovdqu	[%%GDATA_C + AadHash], xmm14		; my_comp_data.aad hash = xmm14
	vmovdqu	[%%GDATA_C + CurCount], xmm9		; my_comp_data.current_counter = xmm9

        mov     r13, r10
        and     r13, 15                                 ; r13 = (%%PLAIN_CYPH_LEN mod 16)

        je      %%_multiple_of_16_bytes

	mov	[%%GDATA_C + PBlockLen], r13		; my_comp_data.partial_blck_length = r13
        ; handle the last <16 Byte block seperately

        vpaddd   xmm9, [ONE]                     ; INCR CNT to get Yn
        vmovdqu [%%GDATA_C + CurCount], xmm9		; my_comp_data.current_counter = xmm9
        vpshufb  xmm9, [SHUF_MASK]
        ENCRYPT_SINGLE_BLOCK   %%GDATA, xmm9             ; E(K, Yn)
	vmovdqu	[%%GDATA_C + PBlockEncKey], xmm9	; my_comp_data.partial_block_enc_key = xmm9

	cmp	%%PLAIN_CYPH_LEN, 16
	jge	%%_large_enough_update

	lea	r10, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
	READ_SMALL_DATA_INPUT	xmm1, r10, r13, r12, r15, rax
	lea	r12, [SHIFT_MASK + 16]
        sub     r12, r13
	jmp	%%_data_read

%%_large_enough_update:
        sub     %%DATA_OFFSET, 16
        add     %%DATA_OFFSET, r13

        vmovdqu  xmm1, [%%PLAIN_CYPH_IN+%%DATA_OFFSET]	; receive the last <16 Byte block

	sub     %%DATA_OFFSET, r13
        add     %%DATA_OFFSET, 16


        lea     r12, [SHIFT_MASK + 16]
        sub     r12, r13                                ; adjust the shuffle mask pointer to be able to shift 16-r13 bytes (r13 is the number of bytes in plaintext mod 16)

        vmovdqu  xmm2, [r12]                             ; get the appropriate shuffle mask
        vpshufb  xmm1, xmm2                              ; shift right 16-r13 bytes
%%_data_read:
        %ifidn  %%ENC_DEC, DEC
        vmovdqa  xmm2, xmm1
        vpxor    xmm9, xmm1                              ; Plaintext XOR E(K, Yn)
        vmovdqu  xmm1, [r12 + ALL_F - SHIFT_MASK]        ; get the appropriate mask to mask out top 16-r13 bytes of xmm9
        vpand    xmm9, xmm1                              ; mask out top 16-r13 bytes of xmm9
        vpand    xmm2, xmm1
        vpshufb  xmm2, [SHUF_MASK]
        vpxor    xmm14, xmm2
	 vmovdqu	[%%GDATA_C + AadHash], xmm14

        %else
        vpxor    xmm9, xmm1                              ; Plaintext XOR E(K, Yn)
        vmovdqu  xmm1, [r12 + ALL_F - SHIFT_MASK]        ; get the appropriate mask to mask out top 16-r13 bytes of xmm9
        vpand    xmm9, xmm1                              ; mask out top 16-r13 bytes of xmm9
        vpshufb  xmm9, [SHUF_MASK]
        vpxor    xmm14, xmm9
	vmovdqu	[%%GDATA_C + AadHash], xmm14

        vpshufb  xmm9, [SHUF_MASK]               ; shuffle xmm9 back to output as ciphertext
        %endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; output r13 Bytes
        vmovq    rax, xmm9
        cmp     r13, 8
        jle     %%_less_than_8_bytes_left

        mov     [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], rax
        add     %%DATA_OFFSET, 8
        vpsrldq xmm9, xmm9, 8
        vmovq    rax, xmm9
        sub     r13, 8

%%_less_than_8_bytes_left:
        mov     BYTE [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], al
        add     %%DATA_OFFSET, 1
        shr     rax, 8
        sub     r13, 1
        jne     %%_less_than_8_bytes_left
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%%_multiple_of_16_bytes:



%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GCM_COMPLETE Finishes Encyrption/Decryption of last partial block after GCM_UPDATE finishes.
; Input: A gcm_data struct* (GDATA) with a gcm_data_comp struct* (GDATA_C) and  whether
; encoding or decoding (ENC_DEC).
; Output: Authorization Tag (AUTH_TAG) and Authorization Tag length (AUTH_TAG_LEN)
; Clobbers rax, r10-r12, and xmm0, xmm1, xmm5, xmm6, xmm9, xmm11, xmm14, xmm15
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro	GCM_COMPLETE		5
%define	%%GDATA			%1
%define	%%GDATA_C		%2
%define	%%AUTH_TAG		%3
%define	%%AUTH_TAG_LEN		%4
%define	%%ENC_DEC		%5
%define	%%PLAIN_CYPH_LEN	rax

	mov	r12, [%%GDATA_C + PBlockLen]
	vmovdqu	xmm14, [%%GDATA_C + AadHash]
	vmovdqu xmm13, [%%GDATA+HashKey]

	cmp	r12, 0

	je %%_partial_done

	GHASH_MUL xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6 ;GHASH computation for the last <16 Byte block
	vmovdqu [%%GDATA_C + AadHash], xmm14

%%_partial_done:

        mov     r12, [%%GDATA_C + AadLen]		; r12 = aadLen (number of bytes)
	mov	%%PLAIN_CYPH_LEN, [%%GDATA_C + InLen]

        shl     r12, 3                                  ; convert into number of bits
        vmovd    xmm15, r12d                             ; len(A) in xmm15

        shl     %%PLAIN_CYPH_LEN, 3                                 ; len(C) in bits  (*128)
        vmovq    xmm1, %%PLAIN_CYPH_LEN
        vpslldq  xmm15, xmm15, 8                        ; xmm15 = len(A)|| 0x0000000000000000
        vpxor    xmm15, xmm1                            ; xmm15 = len(A)||len(C)

        vpxor    xmm14, xmm15
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6    ; final GHASH computation
        vpshufb  xmm14, [SHUF_MASK]              ; perform a 16Byte swap

        vmovdqu  xmm9, [%%GDATA_C + OrigIV]                            ; xmm9 = Y0

        ENCRYPT_SINGLE_BLOCK %%GDATA, xmm9                    ; E(K, Y0)

        vpxor    xmm9, xmm14


%%_return_T:
        mov     r10, %%AUTH_TAG             ; r10 = authTag
        mov     r11, %%AUTH_TAG_LEN         ; r11 = auth_tag_len

        cmp     r11, 16
        je      %%_T_16

        cmp     r11, 12
        je      %%_T_12

%%_T_8:
        vmovq    rax, xmm9
        mov     [r10], rax
        jmp     %%_return_T_done
%%_T_12:
        vmovq    rax, xmm9
        mov     [r10], rax
        vpsrldq xmm9, xmm9, 8
        vmovd    eax, xmm9
        mov     [r10 + 8], eax
        jmp     %%_return_T_done

%%_T_16:
        vmovdqu  [r10], xmm9

%%_return_T_done:
%endmacro ; GCM_COMPLETE


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_precomp_avx_gen2
;        (gcm_data     *my_ctx_data);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_precomp_avx_gen2
aesni_gcm128_precomp_avx_gen2:
        push    r12
        push    r13
        push    r14
        push    r15

        mov     r14, rsp



        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~63                                ; align rsp to 64 bytes

%ifidn __OUTPUT_FORMAT__, win64
        ; only xmm6 needs to be maintained
        vmovdqu [rsp + LOCAL_STORAGE + 0*16],xmm6
%endif

	vpxor	xmm6, xmm6
	ENCRYPT_SINGLE_BLOCK	arg1, xmm6		; xmm6 = HashKey

        vpshufb  xmm6, [SHUF_MASK]
        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        vmovdqa  xmm2, xmm6
        vpsllq   xmm6, 1
        vpsrlq   xmm2, 63
        vmovdqa  xmm1, xmm2
        vpslldq  xmm2, xmm2, 8
        vpsrldq  xmm1, xmm1, 8
        vpor     xmm6, xmm2
        ;reduction
        vpshufd  xmm2, xmm1, 00100100b
        vpcmpeqd xmm2, [TWOONE]
        vpand    xmm2, [POLY]
        vpxor    xmm6, xmm2                             ; xmm6 holds the HashKey<<1 mod poly
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu  [arg1 + HashKey], xmm6                  ; store HashKey<<1 mod poly


        PRECOMPUTE arg1, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm6, [rsp + LOCAL_STORAGE + 0*16]
%endif
        mov     rsp, r14

        pop     r15
        pop     r14
        pop     r13
        pop     r12
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_init_avx_gen2(
;        gcm_data        *my_ctx_data,
;        gcm_data_comp   *my_comp_data,
;        u8      *iv, /* Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer. */
;        const   u8 *aad, /* Additional Authentication Data (AAD)*/
;        u64     aad_len); /* Length of AAD in bytes (must be a multiple of 4 bytes). */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_init_avx_gen2
aesni_gcm128_init_avx_gen2:

	push	r12
	push	r13

%ifidn __OUTPUT_FORMAT__, win64
	; xmm6:xmm15 need to be maintained for Windows
	sub	rsp, 1*16
	vmovdqu	[rsp + 0*16],xmm6
%endif

	GCM_INIT arg1, arg2, arg3, arg4, arg5

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqu	xmm6 , [rsp + 0*16]
	add	rsp, 1*16
%endif
	pop	r13
	pop	r12
ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_enc_update_avx_gen2(
;        gcm_data        *my_ctx_data,
;        gcm_data_comp   *my_comp_data,
;        u8      *out, /* Ciphertext output. Encrypt in-place is allowed.  */
;        const   u8 *in, /* Plaintext input */
;        u64     plaintext_len); /* Length of data in Bytes for encryption. must be a multiple of 16 bytes*/
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_enc_update_avx_gen2
aesni_gcm128_enc_update_avx_gen2:

	FUNC_SAVE

	GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, ENC

	FUNC_RESTORE

	ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_dec_update_avx_gen2(
;        gcm_data        *my_ctx_data,
;        gcm_data_comp   *my_comp_data,
;        u8      *out, /* Plaintext output. Encrypt in-place is allowed.  */
;        const   u8 *in, /* Cyphertext input */
;        u64     plaintext_len); /* Length of data in Bytes for encryption. must be a multiple of 16 bytes*/
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_dec_update_avx_gen2
aesni_gcm128_dec_update_avx_gen2:

	FUNC_SAVE

	GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, DEC

	FUNC_RESTORE

	ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_enc_finalize_avx_gen2(
;        gcm_data        *my_ctx_data,
;        gcm_data_comp   *my_comp_data,
;        u8      *auth_tag, /* Authenticated Tag output. */
;        u64     auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_enc_finalize_avx_gen2
aesni_gcm128_enc_finalize_avx_gen2:

	push r12

%ifidn __OUTPUT_FORMAT__, win64
	; xmm6:xmm15 need to be maintained for Windows
	sub	rsp, 5*16
	vmovdqu	[rsp + 0*16],xmm6
	vmovdqu	[rsp + 1*16],xmm9
	vmovdqu	[rsp + 2*16],xmm11
	vmovdqu	[rsp + 3*16],xmm14
	vmovdqu	[rsp + 4*16],xmm15
%endif
	GCM_COMPLETE	arg1, arg2, arg3, arg4, ENC

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqu	xmm15  , [rsp + 4*16]
	vmovdqu	xmm14  , [rsp + 3*16]
	vmovdqu	xmm11  , [rsp + 2*16]
	vmovdqu	xmm9 , [rsp + 1*16]
	vmovdqu	xmm6 , [rsp + 0*16]
	add	rsp, 5*16
%endif

	pop r12
ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_dec_finalize_avx_gen2(
;	 gcm_data        *my_ctx_data,
;        gcm_data_comp   *my_comp_data,
;        u8      *auth_tag, /* Authenticated Tag output. */
;        u64     auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_dec_finalize_avx_gen2
aesni_gcm128_dec_finalize_avx_gen2:

	push r12

%ifidn __OUTPUT_FORMAT__, win64
	; xmm6:xmm15 need to be maintained for Windows
	sub	rsp, 5*16
	vmovdqu	[rsp + 0*16],xmm6
	vmovdqu	[rsp + 1*16],xmm9
	vmovdqu	[rsp + 2*16],xmm11
	vmovdqu	[rsp + 3*16],xmm14
	vmovdqu	[rsp + 4*16],xmm15
%endif
	GCM_COMPLETE	arg1, arg2, arg3, arg4, DEC

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqu	xmm15  , [rsp + 4*16]
	vmovdqu	xmm14  , [rsp + 3*16]
	vmovdqu	xmm11  , [rsp + 2*16]
	vmovdqu	xmm9 , [rsp + 1*16]
	vmovdqu	xmm6 , [rsp + 0*16]
	add	rsp, 5*16
%endif

	pop r12
ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_enc_avx_gen2(
;        gcm_data        *my_ctx_data,
;        gcm_data_comp   *my_comp_data,
;        u8      *out, /* Ciphertext output. Encrypt in-place is allowed.  */
;        const   u8 *in, /* Plaintext input */
;        u64     plaintext_len, /* Length of data in Bytes for encryption. */
;        u8      *iv, /* Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer. */
;        const   u8 *aad, /* Additional Authentication Data (AAD)*/
;        u64     aad_len, /* Length of AAD in bytes (must be a multiple of 4 bytes). */
;        u8      *auth_tag, /* Authenticated Tag output. */
;        u64     auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_enc_avx_gen2
aesni_gcm128_enc_avx_gen2:

	FUNC_SAVE

	GCM_INIT arg1, arg2, arg6, arg7, arg8

	GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, ENC

	GCM_COMPLETE arg1, arg2, arg9, arg10, ENC

	FUNC_RESTORE

	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm128_dec_avx_gen2(
;        gcm_data        *my_ctx_data,
;        gcm_data_comp   *my_comp_data,
;        u8      *out, /* Plaintext output. Decrypt in-place is allowed.  */
;        const   u8 *in, /* Ciphertext input */
;        u64     plaintext_len, /* Length of data in Bytes for encryption. */
;        u8      *iv, /* Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer. */
;        const   u8 *aad, /* Additional Authentication Data (AAD)*/
;        u64     aad_len, /* Length of AAD in bytes (must be a multiple of 4 bytes). */
;        u8      *auth_tag, /* Authenticated Tag output. */
;        u64     auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm128_dec_avx_gen2
aesni_gcm128_dec_avx_gen2:

	FUNC_SAVE

	GCM_INIT arg1, arg2, arg6, arg7, arg8

	GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, DEC

	GCM_COMPLETE arg1, arg2, arg9, arg10, DEC

	FUNC_RESTORE

	ret
