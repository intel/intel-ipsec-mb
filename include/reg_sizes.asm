;;
;; Copyright (c) 2012-2018, Intel Corporation
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

; define d and w variants for registers

%define	raxd	eax
%define raxw	ax
%define raxb	al

%define	rbxd	ebx
%define rbxw	bx
%define rbxb	bl

%define	rcxd	ecx
%define rcxw	cx
%define rcxb	cl

%define	rdxd	edx
%define rdxw	dx
%define rdxb	dl

%define	rsid	esi
%define rsiw	si
%define rsib	sil

%define	rdid	edi
%define rdiw	di
%define rdib	dil

%define	rbpd	ebp
%define rbpw	bp
%define rbpb	bpl

%define zmm0x xmm0
%define zmm1x xmm1
%define zmm2x xmm2
%define zmm3x xmm3
%define zmm4x xmm4
%define zmm5x xmm5
%define zmm6x xmm6
%define zmm7x xmm7
%define zmm8x xmm8
%define zmm9x xmm9
%define zmm10x xmm10
%define zmm11x xmm11
%define zmm12x xmm12
%define zmm13x xmm13
%define zmm14x xmm14
%define zmm15x xmm15

%define ymm0x xmm0
%define ymm1x xmm1
%define ymm2x xmm2
%define ymm3x xmm3
%define ymm4x xmm4
%define ymm5x xmm5
%define ymm6x xmm6
%define ymm7x xmm7
%define ymm8x xmm8
%define ymm9x xmm9
%define ymm10x xmm10
%define ymm11x xmm11
%define ymm12x xmm12
%define ymm13x xmm13
%define ymm14x xmm14
%define ymm15x xmm15

%define zmm0y ymm0
%define zmm1y ymm1
%define zmm2y ymm2
%define zmm3y ymm3
%define zmm4y ymm4
%define zmm5y ymm5
%define zmm6y ymm6
%define zmm7y ymm7
%define zmm8y ymm8
%define zmm9y ymm9
%define zmm10y ymm10
%define zmm11y ymm11
%define zmm12y ymm12
%define zmm13y ymm13
%define zmm14y ymm14
%define zmm15y ymm15


%define DWORD(reg) reg %+ d
%define WORD(reg)  reg %+ w
%define BYTE(reg)  reg %+ b

%define XWORD(reg) reg %+ x
%define YWORD(reg) reg %+ y
