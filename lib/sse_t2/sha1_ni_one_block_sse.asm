;;
;; Copyright (c) 2023-2024, Intel Corporation
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
%ifdef LINUX
%define INP	rdi ; 1st arg
%define CTX     rsi ; 2nd arg
%define REG3	edx
%define REG4	ecx
%else
%define INP	rcx ; 1st arg
%define CTX     rdx ; 2nd arg
%define REG3	edi
%define REG4	esi
%endif

struc frame
.ABCD_SAVE	reso	1
.E_SAVE		reso	1
.XMM_SAVE	reso	3
.align		resq	1
endstruc

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
;; void sha1_ni_block_sse(void *input_data, UINT32 digest[5])
;; arg 1 : (in) pointer to one block of data
;; arg 2 : (in/out) pointer to read/write digest

mksection .text
MKGLOBAL(sha1_ni_block_sse,function,internal)
align 32
sha1_ni_block_sse:
	sub		rsp, frame_size

%ifndef LINUX
	movdqa		[rsp + frame.XMM_SAVE], xmm6
	movdqa		[rsp + frame.XMM_SAVE + 16], xmm14
	movdqa		[rsp + frame.XMM_SAVE + 16*2], xmm15
%endif

	;; load initial digest
        movdqu          ABCD, [CTX]
        pxor            E0, E0
        pinsrd          E0, [CTX + 16], 3
	pshufd		ABCD, ABCD, 0x1B

	movdqa		SHUF_MASK, [rel PSHUFFLE_BYTE_FLIP_MASK]
	movdqa		E_MASK, [rel UPPER_WORD_MASK]

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

	;; write out digests
	pshufd		ABCD, ABCD, 0x1B
        movdqu          [CTX], ABCD
        pextrd          [CTX + 16], E0, 3

        ;; Clear stack frame (4*16 bytes)
%ifdef SAFE_DATA
        pxor    MSG0, MSG0
        pxor    MSG1, MSG1
        pxor    MSG2, MSG2
        pxor    MSG3, MSG3

        movdqa   [rsp + frame.ABCD_SAVE], MSG0
        movdqa   [rsp + frame.E_SAVE], MSG0
%endif

%ifndef LINUX
	movdqa		xmm6, [rsp + frame.XMM_SAVE]
	movdqa		xmm14, [rsp + frame.XMM_SAVE + 16]
	movdqa		xmm15, [rsp + frame.XMM_SAVE + 16*2]
%endif
	add		rsp, frame_size

	ret

mksection stack-noexec
