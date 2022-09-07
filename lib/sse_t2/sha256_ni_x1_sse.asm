;
;; Copyright (c) 2022, Intel Corporation
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

;; Stack must be aligned to 32 bytes before call
;;
;; Registers:		RAX RBX RCX RDX RBP RSI RDI R8  R9  R10 R11 R12 R13 R14 R15
;;			-----------------------------------------------------------
;; Windows clobbers:	        RCX RDX     RSI RDI             R11
;; Windows preserves:	RAX RBX         RBP         R8  R9  R10     R12 R13 R14 R15
;;			-----------------------------------------------------------
;; Linux clobbers:	        RCX RDX     RSI RDI             R11
;; Linux preserves:	RAX RBX         RBP         R8  R9  R10     R12 R13 R14 R15
;;			-----------------------------------------------------------
;;
;; Linux/Windows clobbers: xmm0 - xmm15

%include "include/os.asm"
%include "include/cet.inc"
%include "include/mb_mgr_datastruct.asm"
%include "include/clear_regs.asm"

; resdq = res0 => 16 bytes
struc frame
.ABEF_SAVE	reso	1
.CDGH_SAVE	reso	1
.align		resq	1
endstruc

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rdx
%define arg4	rcx
%else
%define arg1	rcx
%define arg2	rdx
%define arg3	r8
%define arg4	r9
%endif

%define args            arg1
%define NUM_BLKS 	arg2
%define lane            arg3

%define INP		r10

;; MSG MUST be xmm0 (implicit argument)
%define MSG		xmm0
%define STATE0		xmm1
%define STATE1		xmm2
%define MSGTMP0		xmm3
%define MSGTMP1		xmm4
%define MSGTMP2		xmm5
%define MSGTMP3		xmm6
%define MSGTMP4		xmm7
%define MSGTMP		xmm14
%define SHUF_MASK	xmm15

mksection .rodata
default rel

extern K256

align 64
PSHUFFLE_BYTE_FLIP_MASK:
	dq 0x0405060700010203, 0x0c0d0e0f08090a0b

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha256_ni_x1(SHA256_ARGS *args, UINT32 size_in_blocks)
;; arg1 : pointer to args
;; arg2 : size (in blocks) ;; assumed to be >= 1
mksection .text

%define XMM_STORAGE     10*16
%define GP_STORAGE      6*8

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro FUNC_SAVE 0
    mov     r11, rsp
    sub     rsp, VARIABLE_OFFSET
    and     rsp, ~15	; align rsp to 16 bytes

    mov     [rsp + 0*8],  rbx
    mov     [rsp + 1*8],  rbp
    mov     [rsp + 2*8],  r12
%ifndef LINUX
    mov     [rsp + 3*8], rsi
    mov     [rsp + 4*8], rdi
    movdqa  [rsp + 3*16], xmm6
    movdqa  [rsp + 4*16], xmm7
    movdqa  [rsp + 5*16], xmm8
    movdqa  [rsp + 6*16], xmm9
    movdqa  [rsp + 7*16], xmm10
    movdqa  [rsp + 8*16], xmm11
    movdqa  [rsp + 9*16], xmm12
    movdqa  [rsp + 10*16], xmm13
    movdqa  [rsp + 11*16], xmm14
    movdqa  [rsp + 12*16], xmm15
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
    movdqa  xmm6,  [rsp + 3*16]
    movdqa  xmm7,  [rsp + 4*16]
    movdqa  xmm8,  [rsp + 5*16]
    movdqa  xmm9,  [rsp + 6*16]
    movdqa  xmm10, [rsp + 7*16]
    movdqa  xmm11, [rsp + 8*16]
    movdqa  xmm12, [rsp + 9*16]
    movdqa  xmm13, [rsp + 10*16]
    movdqa  xmm14, [rsp + 11*16]
    movdqa  xmm15, [rsp + 12*16]

%ifdef SAFE_DATA
    pxor    xmm5, xmm5
    movdqa [rsp + 3*16], xmm5
    movdqa [rsp + 4*16], xmm5
    movdqa [rsp + 5*16], xmm5
    movdqa [rsp + 6*16], xmm5
    movdqa [rsp + 7*16], xmm5
    movdqa [rsp + 8*16], xmm5
    movdqa [rsp + 9*16], xmm5
    movdqa [rsp + 10*16], xmm5
    movdqa [rsp + 11*16], xmm5
    movdqa [rsp + 12*16], xmm5

%endif
%endif ; LINUX
    mov     rsp,   [rsp + 5*8] ;; rsp pointer
%endmacro

MKGLOBAL(sha256_ni_x1,function,internal)
align 32
sha256_ni_x1:
	sub		rsp, frame_size

	shl		NUM_BLKS, 6	; convert to bytes
	jz		done_hash

	;; load input pointers
	mov		INP, [args + _data_ptr_sha256 + lane*PTR_SZ]

	add		NUM_BLKS, INP	; pointer to end of data

	;; load initial digest
	;; Probably need to reorder these appropriately
	;; DCBA, HGFE -> ABEF, CDGH
        shl             lane, 5
	movdqu		STATE0, [args + lane]
	movdqu		STATE1,	[args + lane + 16]
 
	pshufd		STATE0, STATE0, 0xB1	; CDAB
	pshufd		STATE1, STATE1, 0x1B	; EFGH
	movdqa		MSGTMP4, STATE0
	palignr		STATE0, STATE1, 8	; ABEF
	pblendw		STATE1, MSGTMP4, 0xF0	; CDGH

	movdqa		SHUF_MASK, [rel PSHUFFLE_BYTE_FLIP_MASK]

.loop0:
	;; Save digests
	movdqa		[rsp + frame.ABEF_SAVE], STATE0
	movdqa		[rsp + frame.CDGH_SAVE], STATE1

	;; Rounds 0-3
	movdqu		MSG, [INP + 0*16]
	pshufb		MSG, SHUF_MASK
	movdqa		MSGTMP0, MSG
	paddd		MSG, [rel K256 + 0*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument

	;; Rounds 4-7
	movdqu		MSG, [INP + 1*16]
	pshufb		MSG, SHUF_MASK
	movdqa		MSGTMP1, MSG
	paddd		MSG, [rel K256 + 1*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP0, MSGTMP1

	;; Rounds 8-11
	movdqu		MSG, [INP + 2*16]
	pshufb		MSG, SHUF_MASK
	movdqa		MSGTMP2, MSG
	paddd		MSG, [rel K256 + 2*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP1, MSGTMP2

	;; Rounds 12-15
	movdqu		MSG, [INP + 3*16]
	pshufb		MSG, SHUF_MASK
	movdqa		MSGTMP3, MSG
	paddd		MSG, [rel K256 + 3*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP3
	palignr		MSGTMP, MSGTMP2, 4
	paddd		MSGTMP0, MSGTMP
	sha256msg2	MSGTMP0, MSGTMP3
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP2, MSGTMP3

	;; Rounds 16-19
	movdqa		MSG, MSGTMP0
	paddd		MSG, [rel K256 + 4*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP0
	palignr		MSGTMP, MSGTMP3, 4
	paddd		MSGTMP1, MSGTMP
	sha256msg2	MSGTMP1, MSGTMP0
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP3, MSGTMP0

	;; Rounds 20-23
	movdqa		MSG, MSGTMP1
	paddd		MSG, [rel K256 + 5*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP1
	palignr		MSGTMP, MSGTMP0, 4
	paddd		MSGTMP2, MSGTMP
	sha256msg2	MSGTMP2, MSGTMP1
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP0, MSGTMP1

	;; Rounds 24-27
	movdqa		MSG, MSGTMP2
	paddd		MSG, [rel K256 + 6*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP2
	palignr		MSGTMP, MSGTMP1, 4
	paddd		MSGTMP3, MSGTMP
	sha256msg2	MSGTMP3, MSGTMP2
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP1, MSGTMP2

	;; Rounds 28-31
	movdqa		MSG, MSGTMP3
	paddd		MSG, [rel K256 + 7*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP3
	palignr		MSGTMP, MSGTMP2, 4
	paddd		MSGTMP0, MSGTMP
	sha256msg2	MSGTMP0, MSGTMP3
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP2, MSGTMP3

	;; Rounds 32-35
	movdqa		MSG, MSGTMP0
	paddd		MSG, [rel K256 + 8*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP0
	palignr		MSGTMP, MSGTMP3, 4
	paddd		MSGTMP1, MSGTMP
	sha256msg2	MSGTMP1, MSGTMP0
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP3, MSGTMP0

	;; Rounds 36-39
        movdqa		MSG, MSGTMP1
	paddd		MSG, [rel K256 + 9*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP1
	palignr		MSGTMP, MSGTMP0, 4
	paddd		MSGTMP2, MSGTMP
	sha256msg2	MSGTMP2, MSGTMP1
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP0, MSGTMP1

	;; Rounds 40-43
	movdqa		MSG, MSGTMP2
	paddd		MSG, [rel K256 + 10*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP2
	palignr		MSGTMP, MSGTMP1, 4
	paddd		MSGTMP3, MSGTMP
	sha256msg2	MSGTMP3, MSGTMP2
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP1, MSGTMP2

	;; Rounds 44-47
	movdqa		MSG, MSGTMP3
	paddd		MSG, [rel K256 + 11*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP3
	palignr		MSGTMP, MSGTMP2, 4
	paddd		MSGTMP0, MSGTMP
	sha256msg2	MSGTMP0, MSGTMP3
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP2, MSGTMP3

	;; Rounds 48-51
	movdqa		MSG, MSGTMP0
	paddd		MSG, [rel K256 + 12*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP0
	palignr		MSGTMP, MSGTMP3, 4
	paddd		MSGTMP1, MSGTMP
	sha256msg2	MSGTMP1, MSGTMP0
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument
	sha256msg1	MSGTMP3, MSGTMP0

	;; Rounds 52-55
	movdqa		MSG, MSGTMP1
	paddd		MSG, [rel K256 + 13*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP1
	palignr		MSGTMP, MSGTMP0, 4
	paddd		MSGTMP2, MSGTMP
	sha256msg2	MSGTMP2, MSGTMP1
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument

	;; Rounds 56-59
	movdqa		MSG, MSGTMP2
	paddd		MSG, [rel K256 + 14*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	movdqa		MSGTMP, MSGTMP2
	palignr		MSGTMP, MSGTMP1, 4
	paddd		MSGTMP3, MSGTMP
	sha256msg2	MSGTMP3, MSGTMP2
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument

	;; Rounds 60-63
	movdqa		MSG, MSGTMP3
	paddd		MSG, [rel K256 + 15*16]
	sha256rnds2	STATE1, STATE0, MSG	; MSG is implicit argument
	pshufd 		MSG, MSG, 0x0E
	sha256rnds2	STATE0, STATE1, MSG	; MSG is implicit argument

	paddd		STATE0, [rsp + frame.ABEF_SAVE]
	paddd		STATE1, [rsp + frame.CDGH_SAVE]

	add		INP, 64
	cmp		INP, NUM_BLKS
	jne		.loop0


	; Reorder for writeback
	pshufd		STATE0, STATE0, 0x1B	; FEBA
	pshufd		STATE1, STATE1, 0xB1	; DCHG
	movdqa		MSGTMP4, STATE0
	pblendw		STATE0, STATE1,  0xF0	; DCBA
	palignr		STATE1, MSGTMP4,  8	; HGFE

	;; update digests
	movdqu		[args + lane + 0*16], STATE0
	movdqu		[args + lane + 1*16], STATE1
        shr             lane, 5

        ;; update data pointers
	mov		[args + _data_ptr_sha256 + lane*PTR_SZ], INP

done_hash:

        ;; Clear stack frame (4*16 bytes)
%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
        movdqa [rsp + frame.ABEF_SAVE], xmm0
        movdqa [rsp + frame.CDGH_SAVE], xmm0
%endif

        add		rsp, frame_size
	ret

; void call_sha256_ni_x1_sse_from_c(SHA256_ARGS *args, UINT32 size_in_blocks);
MKGLOBAL(call_sha256_ni_x1_sse_from_c,function,internal)
call_sha256_ni_x1_sse_from_c:
	FUNC_SAVE
	call sha256_ni_x1
	FUNC_RESTORE
	ret

mksection stack-noexec
