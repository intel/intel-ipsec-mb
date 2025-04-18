;;
;; Copyright (c) 2024, Intel Corporation
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

%ifndef GCM_DATA_SSE_INC_INCLUDED
%define GCM_DATA_SSE_INC_INCLUDED

;
; Authors:
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford

mksection .rodata
default rel

align 16
POLY:
        dq     0x0000000000000001, 0xC200000000000000

align 16
POLY2:
        dq     0x00000001C2000000, 0xC200000000000000

align 16
SHUF_MASK:
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607

;;; @note Order of these constants should not change.
;;; More specifically, ALL_F should follow SHIFT_MASK, and ZERO should follow ALL_F
align 16
SHIFT_MASK:
        dq     0x0706050403020100, 0x0f0e0d0c0b0a0908

ALL_F:
        dq     0xffffffffffffffff, 0xffffffffffffffff

ZERO:
        dq     0x0000000000000000, 0x0000000000000000

align 16
ONE:
        dq     0x0000000000000001, 0x0000000000000000

align 16
ONEf:
        dq     0x0000000000000000, 0x0100000000000000

align 16
TWOONE:
        dq     0x0000000000000001, 0x0000000100000000

;; NIST SP 800-38-D, section 5.2.1.1: len(M) < 2^39 - 256 [bits]
align 8
gcm_max_len:
        dq      (((1<<39) - 256) / 8) - 1

%endif ; GCM_DATA_SSE_INC_INCLUDED
