;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2024, Intel Corporation All rights reserved.
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

%define GCM128_MODE

%use smartalign

%define GCM_UTIL_IMPLEMENTATION
%include "include/gcm_common_avx2_avx512.inc"
%include "include/align_avx.inc"

mksection .text
default rel

;; IN:
;;   arg1  - key pointer
;;   arg3  - destination buffer
;;   arg4  - source buffer
;;   r15   - pointer to store cipher text for GHASH
;;   r10   - number of AESENC rounds (9, 11 or 13)
;;   r11   - data offset
;;   r12   - number of blocks to process
;;   r13   - length in bytes
;;   xmm8  - AAD HASH IN
;;   xmm9  - CTR block
;;
;; OUT:
;;   xmm14 - T3   - AAD HASH OUT when not producing 8 AES keys
;;   xmm1 to xmm8 - [out] cipher text blocks for GHASH
;;
;; CLOBBERED:
;;   xmm0, xmm10-xmm13, xmm15
align_function
MKGLOBAL(gcm_initial_blocks_enc_avx_gen4,function,internal)
gcm_initial_blocks_enc_avx_gen4:
        and     r12, 7  ; don't allow 8 initial blocks
        je      .initial_num_blocks_is_0
        cmp     r12, 6
        ja      .initial_num_blocks_is_7
        je      .initial_num_blocks_is_6
        cmp     r12, 4
        ja      .initial_num_blocks_is_5
        je      .initial_num_blocks_is_4
        cmp     r12, 2
        ja      .initial_num_blocks_is_3
        je      .initial_num_blocks_is_2

        jmp     .initial_num_blocks_is_1

%assign L 7
%rep 8
align_label
.initial_num_blocks_is_ %+ L:
        INITIAL_BLOCKS  arg1, arg3, arg4, r13, r11, L, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, ENC, r10, r15
        ret
%assign L (L - 1)
%endrep


;; IN:
;;   arg1  - key pointer
;;   arg3  - destination buffer
;;   arg4  - source buffer
;;   r15   - pointer to store cipher text for GHASH
;;   r10   - number of AESENC rounds (9, 11 or 13)
;;   r11   - data offset
;;   r12   - number of blocks to process
;;   r13   - length in bytes
;;   xmm8  - AAD HASH IN
;;   xmm9  - CTR block
;;
;; OUT:
;;   xmm14 - T3   - AAD HASH OUT when not producing 8 AES keys
;;   xmm1 to xmm8 - [out] cipher text blocks for GHASH
;;
;; CLOBBERED:
;;   xmm0, xmm10-xmm13, xmm15
align_function
MKGLOBAL(gcm_initial_blocks_dec_avx_gen4,function,internal)
gcm_initial_blocks_dec_avx_gen4:
        and     r12, 7  ; don't allow 8 initial blocks
        je      .initial_num_blocks_is_0
        cmp     r12, 6
        ja      .initial_num_blocks_is_7
        je      .initial_num_blocks_is_6
        cmp     r12, 4
        ja      .initial_num_blocks_is_5
        je      .initial_num_blocks_is_4
        cmp     r12, 2
        ja      .initial_num_blocks_is_3
        je      .initial_num_blocks_is_2

        jmp     .initial_num_blocks_is_1

%assign L 7
%rep 8
align_label
.initial_num_blocks_is_ %+ L:
        INITIAL_BLOCKS  arg1, arg3, arg4, r13, r11, L, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, DEC, r10, r15
        ret
%assign L (L - 1)
%endrep

mksection stack-noexec
