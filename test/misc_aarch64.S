/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/
.global	dump_gps
.type	dump_gps,%function
.align	5
dump_gps:
	str	x28,[sp,#-16]!
	ldr	x28,=gps
	stp	x0,x1,[x28]
	stp	x2,x3,[x28,#16]
	stp	x4,x5,[x28,#32]
	stp	x6,x7,[x28,#48]
	stp	x8,x9,[x28,#64]
	stp	x10,x11,[x28,#80]
	stp	x12,x13,[x28,#96]
	stp	x14,x15,[x28,#112]
	stp	x16,x17,[x28,#128]
	stp	x18,x19,[x28,#144]
	stp	x20,x21,[x28,#160]
	stp	x22,x23,[x28,#176]
	stp	x24,x25,[x28,#192]
	stp	x26,x27,[x28,#208]
	ldr	x0,[sp],#16
	str	x0,[x28,#224]
	mov	x28,x0

	ret


.global	dump_simd_regs
.type	dump_simd_regs,%function
.align	5
dump_simd_regs:
	ldr	x0,=simd_regs
	stp	q0,q1,[x0]
	stp	q2,q3,[x0,#32]
	stp	q4,q5,[x0,#64]
	stp	q6,q7,[x0,#96]
	stp	q8,q9,[x0,#128]
	stp	q10,q11,[x0,#160]
	stp	q12,q13,[x0,#192]
	stp	q14,q15,[x0,#224]
	stp	q16,q17,[x0,#256]
	stp	q18,q19,[x0,#288]
	stp	q20,q21,[x0,#320]
	stp	q22,q23,[x0,#352]
	stp	q24,q25,[x0,#384]
	stp	q26,q27,[x0,#416]
	stp	q28,q29,[x0,#448]
	stp	q30,q31,[x0,#480]

	ret


.global rdrsp
.type	rdrsp,%function
.align	5
rdrsp:
	mov	x0,sp

	ret
