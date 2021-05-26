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
.globl	lookup_16x8bit_neon
.type	lookup_16x8bit_neon,%function
.align	5
lookup_16x8bit_neon:
/* param[in]:	x0	table pointer
 * 		v0	indexes
 */
	// table: v16-v31
	mov	v1.16b,v0.16b

	ld1	{v16.16b,v17.16b,v18.16b,v19.16b},[x0],#64
	ld1	{v20.16b,v21.16b,v22.16b,v23.16b},[x0],#64
	ld1	{v24.16b,v25.16b,v26.16b,v27.16b},[x0],#64
	ld1	{v28.16b,v29.16b,v30.16b,v31.16b},[x0]

	movi	v2.16b,#64

	eor	v3.16b,v3.16b,v3.16b
	tbx	v3.16b,{v16.16b,v17.16b,v18.16b,v19.16b},v1.16b
	sub	v1.16b,v1.16b,v2.16b
	tbx	v3.16b,{v20.16b,v21.16b,v22.16b,v23.16b},v1.16b
	sub	v1.16b,v1.16b,v2.16b
	tbx	v3.16b,{v24.16b,v25.16b,v26.16b,v27.16b},v1.16b
	sub	v1.16b,v1.16b,v2.16b
	tbx	v3.16b,{v28.16b,v29.16b,v30.16b,v31.16b},v1.16b

	mov	v0.16b,v3.16b

	ret
