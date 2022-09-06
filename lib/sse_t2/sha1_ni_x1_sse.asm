;;
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
;; Windows clobbers:	            RDX                     R10 R11
;; Windows preserves:	RAX RBX RCX     RBP RSI RDI R8  R9          R12 R13 R14 R15
;;			-----------------------------------------------------------
;; Linux clobbers:	                        RDI         R10 R11
;; Linux preserves:	RAX RBX RCX RDX RBP RSI     R8  R9          R12 R13 R14 R15
;;			-----------------------------------------------------------
;;
;; Linux/Windows clobbers: xmm0 - xmm15

%include "include/os.asm"
;%define DO_DBGPRINT
%include "include/dbgprint.asm"
%include "include/clear_regs.asm"
%include "include/mb_mgr_datastruct.asm"

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
%define tmp             arg4
; reso = resdq => 16 bytes
struc frame
.ABCD_SAVE	reso	1
.E_SAVE		reso	1
.ABCD_SAVEb	reso	1
.E_SAVEb	reso	1
.XMM_SAVE	reso	3
.align		resq	1
endstruc

%define INP		r10

%define ABCD		xmm0
%define E0		xmm1	; Need two E's b/c they ping pong
%define E1		xmm2
%define MSG0		xmm3
%define MSG1		xmm4
%define MSG2		xmm5
%define MSG3		xmm6

%define SHUF_MASK	xmm14
%define E_MASK		xmm15

mksection .rodata
default rel
align 64
PSHUFFLE_BYTE_FLIP_MASK: ;ddq 0x000102030405060708090a0b0c0d0e0f
	dq 0x08090a0b0c0d0e0f, 0x0001020304050607
UPPER_WORD_MASK:         ;ddq 0xFFFFFFFF000000000000000000000000
	dq 0x0000000000000000, 0xFFFFFFFF00000000

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha1_ni_x1(SHA1_ARGS *args, UINT32 size_in_blocks, uint64_t lane)
;; arg1 : pointer to args
;; arg2 : size (in blocks) ;; assumed to be >= 1
;; arg3 : lane number

mksection .text
MKGLOBAL(sha1_ni_x1,function,internal)
align 32
sha1_ni_x1:
	sub		rsp, frame_size

	movdqa		[rsp + frame.XMM_SAVE], xmm6
	movdqa		[rsp + frame.XMM_SAVE + 16], xmm14
	movdqa		[rsp + frame.XMM_SAVE + 16*2], xmm15

	shl		NUM_BLKS, 6	; convert to bytes
	jz		done_hash

	;; load input pointers
	mov		INP, [args + _data_ptr_sha1 + lane*PTR_SZ]

	add		NUM_BLKS, INP	; pointer to end of data block -> loop exit condition

	;; load initial digest
        mov             tmp, SHA1NI_DIGEST_ROW_SIZE
        imul            tmp, lane
	movdqu		ABCD, [args + tmp]
	pxor		E0, E0
	pinsrd		E0, [args + tmp + 4*SHA1_DIGEST_WORD_SIZE], 3
	pshufd		ABCD, ABCD, 0x1B

	movdqa		SHUF_MASK, [rel PSHUFFLE_BYTE_FLIP_MASK]
	movdqa		E_MASK, [rel UPPER_WORD_MASK]

loop0:
	;; Copy digests
	movdqa		[rsp + frame.ABCD_SAVE], ABCD
	movdqa		[rsp + frame.E_SAVE],    E0

	;; Only needed if not using sha1nexte for rounds 0-3
	pand		E0,   E_MASK

	;; Rounds 0-3
	movdqu		MSG0, [INP + 0*16]
	pshufb		MSG0, SHUF_MASK
	paddd		E0, MSG0
	movdqa		E1, ABCD
	sha1rnds4	ABCD, E0, 0

	;; Rounds 4-7
	movdqu		MSG1, [INP + 1*16]
	pshufb		MSG1, SHUF_MASK
	sha1nexte	E1, MSG1
	movdqa		E0, ABCD
	sha1rnds4	ABCD, E1, 0
	sha1msg1	MSG0, MSG1

	;; Rounds 8-11
	movdqu		MSG2, [INP + 2*16]
	pshufb		MSG2, SHUF_MASK
	sha1nexte	E0, MSG2
	movdqa		E1, ABCD
	sha1rnds4	ABCD, E0, 0
	sha1msg1	MSG1, MSG2
	pxor		MSG0, MSG2

	;; Rounds 12-15
	movdqu		MSG3, [INP + 3*16]
	pshufb		MSG3, SHUF_MASK
	sha1nexte	E1, MSG3
	movdqa		E0, ABCD
	sha1msg2	MSG0, MSG3
	sha1rnds4	ABCD, E1, 0
	sha1msg1	MSG2, MSG3
	pxor		MSG1, MSG3

	;; Rounds 16-19
	sha1nexte	E0, MSG0
	movdqa		E1, ABCD
	sha1msg2	MSG1, MSG0
	sha1rnds4	ABCD, E0, 0
	sha1msg1	MSG3, MSG0
	pxor		MSG2, MSG0

	;; Rounds 20-23
	sha1nexte	E1, MSG1
	movdqa		E0, ABCD
	sha1msg2	MSG2, MSG1
	sha1rnds4	ABCD, E1, 1
	sha1msg1	MSG0, MSG1
	pxor		MSG3, MSG1

	;; Rounds 24-27
	sha1nexte	E0, MSG2
	movdqa		E1, ABCD
	sha1msg2	MSG3, MSG2
	sha1rnds4	ABCD, E0, 1
	sha1msg1	MSG1, MSG2
	pxor		MSG0, MSG2

	;; Rounds 28-31
	sha1nexte	E1, MSG3
	movdqa		E0, ABCD
	sha1msg2	MSG0, MSG3
	sha1rnds4	ABCD, E1, 1
	sha1msg1	MSG2, MSG3
	pxor		MSG1, MSG3

	;; Rounds 32-35
	sha1nexte	E0, MSG0
	movdqa		E1, ABCD
	sha1msg2	MSG1, MSG0
	sha1rnds4	ABCD, E0, 1
	sha1msg1	MSG3, MSG0
	pxor		MSG2, MSG0

	;; Rounds 36-39
	sha1nexte	E1, MSG1
	movdqa		E0, ABCD
	sha1msg2	MSG2, MSG1
	sha1rnds4	ABCD, E1, 1
	sha1msg1	MSG0, MSG1
	pxor		MSG3, MSG1

	;; Rounds 40-43
	sha1nexte	E0, MSG2
	movdqa		E1, ABCD
	sha1msg2	MSG3, MSG2
	sha1rnds4	ABCD, E0, 2
	sha1msg1	MSG1, MSG2
	pxor		MSG0, MSG2

	;; Rounds 44-47
	sha1nexte	E1, MSG3
	movdqa		E0, ABCD
	sha1msg2	MSG0, MSG3
	sha1rnds4	ABCD, E1, 2
	sha1msg1	MSG2, MSG3
	pxor		MSG1, MSG3

	;; Rounds 48-51
	sha1nexte	E0, MSG0
	movdqa		E1, ABCD
	sha1msg2	MSG1, MSG0
	sha1rnds4	ABCD, E0, 2
	sha1msg1	MSG3, MSG0
	pxor		MSG2, MSG0

	;; Rounds 52-55
	sha1nexte	E1, MSG1
	movdqa		E0, ABCD
	sha1msg2	MSG2, MSG1
	sha1rnds4	ABCD, E1, 2
	sha1msg1	MSG0, MSG1
	pxor		MSG3, MSG1

	;; Rounds 56-59
	sha1nexte	E0, MSG2
	movdqa		E1, ABCD
	sha1msg2	MSG3, MSG2
	sha1rnds4	ABCD, E0, 2
	sha1msg1	MSG1, MSG2
	pxor		MSG0, MSG2

	;; Rounds 60-63
	sha1nexte	E1, MSG3
	movdqa		E0, ABCD
	sha1msg2	MSG0, MSG3
	sha1rnds4	ABCD, E1, 3
	sha1msg1	MSG2, MSG3
	pxor		MSG1, MSG3

	;; Rounds 64-67
	sha1nexte	E0, MSG0
	movdqa		E1, ABCD
	sha1msg2	MSG1, MSG0
	sha1rnds4	ABCD, E0, 3
	sha1msg1	MSG3, MSG0
	pxor		MSG2, MSG0

	;; Rounds 68-71
	sha1nexte	E1, MSG1
	movdqa		E0, ABCD
	sha1msg2	MSG2, MSG1
	sha1rnds4	ABCD, E1, 3
	pxor		MSG3, MSG1

	;; Rounds 72-75
	sha1nexte	E0, MSG2
	movdqa		E1, ABCD
	sha1msg2	MSG3, MSG2
	sha1rnds4	ABCD, E0, 3

	;; Rounds 76-79
	sha1nexte	E1, MSG3
	movdqa		E0, ABCD
	sha1rnds4	ABCD, E1, 3

	;; Need to rotate E left by 30
	movdqa		E1, E0
	pslld		E0, 30
	psrld		E1, 2
	pxor		E0, E1

	paddd		ABCD, [rsp + frame.ABCD_SAVE]
	paddd		E0,   [rsp + frame.E_SAVE]

	add		INP, 64
	cmp		INP, NUM_BLKS
	jne		loop0

	;; write out digests
	pshufd		ABCD, ABCD, 0x1B
	movdqu		[args + tmp], ABCD
	pextrd		[args + tmp + 4*SHA1_DIGEST_WORD_SIZE], E0, 3

	;; update input pointers
	mov		[args + _data_ptr_sha1 + lane*PTR_SZ], INP

done_hash:

        ;; Clear stack frame (4*16 bytes)
%ifdef SAFE_DATA
        pxor    MSG0, MSG0
        pxor    MSG1, MSG1
        pxor    MSG2, MSG2
        pxor    MSG3, MSG3

        movdqa   [rsp + 0*16], MSG0
        movdqa   [rsp + 1*16], MSG0
        movdqa   [rsp + 2*16], MSG0
        movdqa   [rsp + 3*16], MSG0
%endif

	movdqa		xmm6, [rsp + frame.XMM_SAVE]
	movdqa		xmm14, [rsp + frame.XMM_SAVE + 16]
	movdqa		xmm15, [rsp + frame.XMM_SAVE + 16*2]
	add		rsp, frame_size

	ret

mksection stack-noexec
