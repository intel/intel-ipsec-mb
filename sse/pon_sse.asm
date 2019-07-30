;;
;; Copyright (c) 2019, Intel Corporation
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

%include "job_aes_hmac.asm"
%include "include/os.asm"

;;; This is implementation of stitched algorithms: AES128-CTR + CRC32 + BIP
;;; This combination is required by PON/xPON/gPON standard.
;;; Note: BIP is running XOR of double words
;;; Order of operations:
;;; - encrypt: CRC32, AES-CTR and BIP
;;; - decrypt: BIP, AES-CTR and CRC32

%ifndef DEC_FN_NAME
%define DEC_FN_NAME submit_job_pon_dec_sse
%endif
%ifndef ENC_FN_NAME
%define ENC_FN_NAME submit_job_pon_enc_sse
%endif
%ifndef ENC_NO_CTR_FN_NAME
%define ENC_NO_CTR_FN_NAME submit_job_pon_enc_no_ctr_sse
%endif
%ifndef DEC_NO_CTR_FN_NAME
%define DEC_NO_CTR_FN_NAME submit_job_pon_dec_no_ctr_sse
%endif

extern byteswap_const
extern ddq_add_1

section .data
default rel

;;; Precomputed constants for CRC32
;;;   Details of the CRC algorithm and 4 byte buffer of
;;;   {0x01, 0x02, 0x03, 0x04}:
;;;     Result     Poly       Init        RefIn  RefOut  XorOut
;;;     0xB63CFBCD 0x04C11DB7 0xFFFFFFFF  true   true    0xFFFFFFFF
align 16
rk1:
        dq 0x00000000ccaa009e, 0x00000001751997d0

align 16
rk5:
        dq 0x00000000ccaa009e, 0x0000000163cd6124

align 16
rk7:
        dq 0x00000001f7011640, 0x00000001db710640

align 16
pshufb_shf_table:
        ;;  use these values for shift registers with the pshufb instruction
        dq 0x8786858483828100, 0x8f8e8d8c8b8a8988
        dq 0x0706050403020100, 0x000e0d0c0b0a0908

align 16
init_crc_value:
        dq 0x00000000FFFFFFFF, 0x0000000000000000

align 16
mask:
        dq 0xFFFFFFFFFFFFFFFF, 0x0000000000000000

align 16
mask2:
        dq 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF
align 16
mask3:
        dq 0x8080808080808080, 0x8080808080808080

align 16
mask_out_top_bytes:
        dq 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
        dq 0x0000000000000000, 0x0000000000000000

section .text

%define NUM_AES_ROUNDS 10

;; note: leave xmm0 free for implicit blend
%define xcounter xmm7
%define xbip    xmm1
%define xcrc    xmm2
%define xcrckey xmm3
%define xtmp1   xmm4
%define xtmp2   xmm5
%define xtmp3   xmm6

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define tmp_1   r8
%define tmp_2   r9
%define tmp_3   r10
%define tmp_4   r11
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define tmp_1   r10
%define tmp_2   r11
%define tmp_3   rax
%endif

%define job     arg1

%define p_in    arg2
%define p_keys  arg3
%define p_out   arg4

%define num_bytes tmp_1
%define tmp       tmp_2
%define ctr_check tmp_3

;;; ============================================================================
;;; Loads 4, 8 or 12 bytes from memory location into XMM register
%macro simd_load_sse_4_8_12 3
%define %%XMM           %1      ; [out] XMM to read data into
%define %%INP           %2      ; [in] GP input data pointer
%define %%NUM           %3      ; [in] GP with number of bytes to read (4, 8 or 12)

        cmp     %%NUM, 4
        jne     %%_simd_load_not_4
        movd    %%XMM, [%%INP]
        jmp     %%_simd_load_end
%%_simd_load_not_4:
        cmp     %%NUM, 8
        jne     %%_simd_load_not_8
        movq    %%XMM, [%%INP]
        jmp     %%_simd_load_end
%%_simd_load_not_8:
        movq    %%XMM, [%%INP]
        pinsrd  %%XMM, [%%INP + 8], 2
%%_simd_load_end:
%endmacro

;;; ============================================================================
;;; Does all AES encryption rounds
%macro AES_ENC_ROUNDS 3
%define %%KP            %1      ; [in] pointer to expanded keys
%define %%N_ROUNDS      %2      ; [in] max rounds (128bit: 10, 12, 14)
%define %%BLOCK         %3      ; [in/out] XMM with encrypted block

%assign round 0
        pxor            %%BLOCK, [%%KP + (round * 16)]

%rep (%%N_ROUNDS - 1)
%assign round (round + 1)
        aesenc          %%BLOCK, [%%KP + (round * 16)]
%endrep

%assign round (round + 1)
        aesenclast      %%BLOCK, [%%KP + (round * 16)]

%endmacro

;;; ============================================================================
;;; PON stitched algorithm round on a single AES block (16 bytes):
;;;   AES-CTR (optional, depending on %%CIPH)
;;;   - prepares counter blocks
;;;   - encrypts counter blocks
;;;   - loads text
;;;   - xor's text against encrypted blocks
;;;   - stores cipher text
;;;   BIP
;;;   - BIP update on 4 x 32-bits
;;;   CRC32
;;;   - CRC32 calculation
;;; Note: via selection of no_crc, no_bip, no_load, no_store different macro
;;;       behavior can be achieved to match needs of the overall algorithm.
%macro DO_PON 15
%define %%KP            %1      ; [in] GP, pointer to expanded keys
%define %%N_ROUNDS      %2      ; [in] number of AES rounds (10, 12 or 14)
%define %%CTR           %3      ; [in/out] XMM with counter block
%define %%INP           %4      ; [in/out] GP with input text pointer or "no_load"
%define %%OUTP          %5      ; [in/out] GP with output text pointer or "no_store"
%define %%XBIP_IN_OUT   %6      ; [in/out] XMM with BIP value or "no_bip"
%define %%XCRC_IN_OUT   %7      ; [in/out] XMM with CRC (can be anything if "no_crc" below)
%define %%XCRC_MUL      %8      ; [in] XMM with CRC multiplier constant (can be anything if "no_crc" below)
%define %%TXMM0         %9      ; [clobbered|out] XMM temporary or data out (no_store)
%define %%TXMM1         %10     ; [clobbered|in] XMM temporary or data in (no_load)
%define %%TXMM2         %11     ; [clobbered] XMM temporary
%define %%CRC_TYPE      %12     ; [in] "first_crc" or "next_crc" or "no_crc"
%define %%DIR           %13     ; [in] "ENC" or "DEC"
%define %%CIPH          %14     ; [in] "CTR" or "NO_CTR"
%define %%CTR_CHECK     %15     ; [in/out] GP with 64bit counter (to identify overflow)

%ifidn %%CIPH, CTR
        ;; prepare counter blocks for encryption
        movdqa          %%TXMM0, %%CTR
        pshufb          %%TXMM0, [rel byteswap_const]
        ;; perform 1 increment on whole 128 bits
        movdqa          %%TXMM2,  [rel ddq_add_1]
        paddq           %%CTR, %%TXMM2
        add             %%CTR_CHECK, 1
        jnc             %%_no_ctr_overflow
        ;; Add 1 to the top 64 bits. First shift left value 1 by 64 bits.
        pslldq          %%TXMM2, 8
        paddq           %%CTR, %%TXMM2
%%_no_ctr_overflow:
%endif
        ;; CRC calculation
%ifidn %%CRC_TYPE, next_crc
        movdqa          %%TXMM2, %%XCRC_IN_OUT
        pclmulqdq       %%TXMM2, %%XCRC_MUL, 0x01
        pclmulqdq       %%XCRC_IN_OUT, %%XCRC_MUL, 0x10
%endif

%ifnidn %%INP, no_load
        movdqu          %%TXMM1, [%%INP]
%endif

%ifidn %%CIPH, CTR
        ;; AES rounds
        AES_ENC_ROUNDS  %%KP, %%N_ROUNDS, %%TXMM0

        ;; xor plaintext/ciphertext against encrypted counter blocks
        pxor            %%TXMM0, %%TXMM1
%else ;; CIPH = NO_CTR
        ;; if no encryption needs to be done, move from input to output reg
        movdqa          %%TXMM0, %%TXMM1
%endif ;; CIPH = CTR

%ifidn %%CIPH, CTR
%ifidn %%DIR, ENC
        ;; CRC calculation for ENCRYPTION
%ifidn %%CRC_TYPE, first_crc
        ;; in the first run just XOR initial CRC with the first block
        pxor            %%XCRC_IN_OUT, %%TXMM1
%endif
%ifidn %%CRC_TYPE, next_crc
        ;; - XOR results of CLMUL's together
        ;; - then XOR against text block
        pxor            %%XCRC_IN_OUT, %%TXMM2
        pxor            %%XCRC_IN_OUT, %%TXMM1
%endif
%else
        ;; CRC calculation for DECRYPTION
%ifidn %%CRC_TYPE, first_crc
        ;; in the first run just XOR initial CRC with the first block
        pxor            %%XCRC_IN_OUT, %%TXMM0
%endif
%ifidn %%CRC_TYPE, next_crc
        ;; - XOR results of CLMUL's together
        ;; - then XOR against text block
        pxor            %%XCRC_IN_OUT, %%TXMM2
        pxor            %%XCRC_IN_OUT, %%TXMM0
%endif
%endif                        ; DECRYPT
%else ;; CIPH = NO_CTR
        ;; CRC calculation for DECRYPTION
%ifidn %%CRC_TYPE, first_crc
        ;; in the first run just XOR initial CRC with the first block
        pxor            %%XCRC_IN_OUT, %%TXMM1
%endif
%ifidn %%CRC_TYPE, next_crc
        ;; - XOR results of CLMUL's together
        ;; - then XOR against text block
        pxor            %%XCRC_IN_OUT, %%TXMM2
        pxor            %%XCRC_IN_OUT, %%TXMM1
%endif

%endif ;; CIPH = CTR

        ;; store the result in the output buffer
%ifnidn %%OUTP, no_store
        movdqu          [%%OUTP], %%TXMM0
%endif

        ;; update BIP value - always use cipher text for BIP
%ifidn %%DIR, ENC
%ifnidn %%XBIP_IN_OUT, no_bip
        pxor            %%XBIP_IN_OUT, %%TXMM0
%endif
%else
%ifnidn %%XBIP_IN_OUT, no_bip
        pxor            %%XBIP_IN_OUT, %%TXMM1
%endif
%endif                          ; DECRYPT

        ;; increment in/out pointers
%ifnidn %%INP, no_load
        add             %%INP,  16
%endif
%ifnidn %%OUTP, no_store
        add             %%OUTP, 16
%endif
%endmacro                       ; DO_PON

;;; ============================================================================
;;; CIPHER and BIP specified number of bytes
%macro CIPHER_BIP_REST 12
%define %%NUM_BYTES   %1        ; [in/clobbered] number of bytes to cipher
%define %%DIR         %2        ; [in] "ENC" or "DEC"
%define %%CIPH        %3        ; [in] "CTR" or "NO_CTR"
%define %%PTR_IN      %4        ; [in/clobbered] GPR pointer to input buffer
%define %%PTR_OUT     %5        ; [in/clobbered] GPR pointer to output buffer
%define %%PTR_KEYS    %6        ; [in] GPR pointer to expanded keys
%define %%XBIP_IN_OUT %7        ; [in/out] XMM 128-bit BIP state
%define %%XCTR_IN_OUT %8        ; [in/out] XMM 128-bit AES counter block
%define %%XMMT1       %9        ; [clobbered] temporary XMM
%define %%XMMT2       %10       ; [clobbered] temporary XMM
%define %%XMMT3       %11       ; [clobbered] temporary XMM
%define %%CTR_CHECK   %12       ; [in/out] GP with 64bit counter (to identify overflow)

%%_cipher_last_blocks:
        cmp     %%NUM_BYTES, 16
        jb      %%_partial_block_left

        DO_PON  %%PTR_KEYS, NUM_AES_ROUNDS, %%XCTR_IN_OUT, %%PTR_IN, %%PTR_OUT, %%XBIP_IN_OUT, \
                no_crc, no_crc, %%XMMT1, %%XMMT2, %%XMMT3, no_crc, %%DIR, %%CIPH, %%CTR_CHECK
        sub     %%NUM_BYTES, 16
        jz      %%_bip_done
        jmp     %%_cipher_last_blocks

%%_partial_block_left:
        ;; 4, 8 or 12 bytes of partial block possible here
        simd_load_sse_4_8_12 %%XMMT2, %%PTR_IN, %%NUM_BYTES

        ;; DO_PON() is not loading nor storing the data in this case:
        ;; XMMT2 = data in
        ;; XMMT1 = data out
        DO_PON  %%PTR_KEYS, NUM_AES_ROUNDS, %%XCTR_IN_OUT, no_load, no_store, no_bip, \
                no_crc, no_crc, %%XMMT1, %%XMMT2, %%XMMT3, no_crc, %%DIR, %%CIPH, %%CTR_CHECK

        ;; store partial bytes and update BIP
        cmp     %%NUM_BYTES, 4
        jne     %%_partial_block_not_4_bytes
        movd    [%%PTR_OUT], %%XMMT1
        movdqu  %%XMMT3, [rel mask_out_top_bytes + 16 - 4]
        jmp     %%_partial_block_end
%%_partial_block_not_4_bytes:
        cmp     %%NUM_BYTES, 8
        jne     %%_partial_block_not_8_bytes
        movq    [%%PTR_OUT], %%XMMT1
        movdqu  %%XMMT3, [rel mask_out_top_bytes + 16 - 8]
        jmp     %%_partial_block_end
%%_partial_block_not_8_bytes:
        movq    [%%PTR_OUT], %%XMMT1
        pextrd  [p_out + 8], %%XMMT1, 2
        movdqu  %%XMMT3, [rel mask_out_top_bytes + 16 - 12]
%%_partial_block_end:
        ;; bip update for partial block (mask out bytes outside the message)
%ifidn %%DIR, ENC
        pand    %%XMMT1, %%XMMT3
        pxor    %%XBIP_IN_OUT, %%XMMT1
%else
        pand    %%XMMT2, %%XMMT3
        pxor    %%XBIP_IN_OUT, %%XMMT2
%endif
%%_bip_done:
%endmacro                       ; CIPHER_BIP_REST

;;; ============================================================================
;;; PON stitched algorithm of AES128-CTR, CRC and BIP
;;; - this is master macro that implements encrypt/decrypt API
;;; - calls other macros and directly uses registers
;;;   defined at the top of the file
%macro AES128_CTR_PON 2
%define %%DIR   %1              ; [in] direction "ENC" or "DEC"
%define %%CIPH  %2              ; [in] cipher "CTR" or "NO_CTR"

%ifidn %%CIPH, CTR
        ;; - read 16 bytes of IV
        ;; - convert to little endian format
        ;; - save least significant 8 bytes in GP register for overflow check
        mov     tmp, [job + _iv]
        movdqu  xcounter, [tmp]
        pshufb  xcounter, [rel byteswap_const]
        movq    ctr_check, xcounter
%endif

        ;; load 8 bytes of payload for BIP (not part of encrypted message)
        ;; @todo these 8 bytes are hardcoded for now (per standard spec)
        mov     tmp, [job + _src]
        add     tmp, [job + _hash_start_src_offset_in_bytes]
        movq    xbip, [tmp]

        ;; get input buffer (after XGEM header)
        mov     p_in, [job + _src]
        add     p_in, [job + _cipher_start_src_offset_in_bytes]

        ;; get output buffer
        mov     p_out, [job + _dst]

%ifidn %%CIPH, CTR
        ;; get key pointers
        mov     p_keys, [job + _aes_enc_key_expanded]
%endif

        ;; initial CRC value
        movdqa  xcrc, [rel init_crc_value]

        ;; load CRC constants
        movdqa  xcrckey, [rel rk1] ; rk1 and rk2 in xcrckey

        ;; get number of bytes to cipher and crc
        ;; - computed CRC needs to be encrypted at the end too
%ifidn %%CIPH, CTR
        mov     num_bytes, [job + _msg_len_to_cipher_in_bytes]
        sub     num_bytes, 4    ; subtract size of CRC at the end of the message
%else
        ;; Message length to cipher is 0, so length is obtained from hash params
        mov     num_bytes, [job + _msg_len_to_hash_in_bytes]
        ;; subtract size of header and CRC at the end of the message
        sub     num_bytes, 12
%endif

        jz      %%_crc_done

        cmp     num_bytes, 32
        jae     %%_at_least_32_bytes

%ifidn %%DIR, DEC
        ;; decrypt the buffer first (with appended CRC)
        lea     tmp, [num_bytes + 4] ; add size of appended CRC

        CIPHER_BIP_REST tmp, %%DIR, %%CIPH, p_in, p_out, p_keys, xbip, \
                        xcounter, xtmp1, xtmp2, xtmp3, ctr_check

        ;; correct in/out pointers
        lea     tmp, [num_bytes + 4] ; add size of appended CRC
        and     tmp, -16
        sub     p_in, tmp
        sub     p_out, tmp
%endif                          ; DECRYPTION

        ;; less than 32 bytes
        cmp     num_bytes, 16
        je      %%_exact_16_left
        jl      %%_less_than_16_left
        ;; load the plaintext
%ifidn %%DIR, ENC
        movdqu  xtmp1, [p_in]
%else
        movdqu  xtmp1, [p_out]
%endif
        pxor    xcrc, xtmp1   ; xor the initial crc value
        jmp     %%_crc_two_xmms

%%_exact_16_left:
%ifidn %%DIR, ENC
        movdqu  xtmp1, [p_in]
%else
        movdqu  xtmp1, [p_out]
%endif
        pxor    xcrc, xtmp1 ; xor the initial crc value
        jmp     %%_128_done

%%_less_than_16_left:
        ;; @note: due to message size restrictions (multiple of 4 bytes)
        ;;        there will never be a case in which there is less than
        ;;        4 bytes to process here

%ifidn %%DIR, ENC
        simd_load_sse_4_8_12 xtmp1, p_in, num_bytes
%else
        simd_load_sse_4_8_12 xtmp1, p_out, num_bytes
%endif
        pxor    xcrc, xtmp1 ; xor the initial crc value

        lea     tmp, [rel pshufb_shf_table]
        movdqu  xtmp1, [tmp + num_bytes]
        pshufb  xcrc, xtmp1
        jmp     %%_128_done

%%_at_least_32_bytes:
        DO_PON  p_keys, NUM_AES_ROUNDS, xcounter, p_in, p_out, xbip, \
                xcrc, xcrckey, xtmp1, xtmp2, xtmp3, first_crc, %%DIR, %%CIPH, ctr_check
        sub     num_bytes, 16

%%_main_loop:
        cmp     num_bytes, 16
        jb      %%_exit_loop
        DO_PON  p_keys, NUM_AES_ROUNDS, xcounter, p_in, p_out, xbip, \
                xcrc, xcrckey, xtmp1, xtmp2, xtmp3, next_crc, %%DIR, %%CIPH, ctr_check
        sub     num_bytes, 16
%ifidn %%DIR, ENC
        jz      %%_128_done
%endif
        jmp     %%_main_loop

%%_exit_loop:

%ifidn %%DIR, DEC
        ;; decrypt the buffer including trailing CRC
        lea     tmp, [num_bytes + 4] ; add CRC size

        CIPHER_BIP_REST tmp, %%DIR, %%CIPH, p_in, p_out, p_keys, xbip, \
                        xcounter, xtmp1, xtmp2, xtmp3, ctr_check

        lea     tmp, [num_bytes + 4] ; correct in/out pointers
        and     tmp, -16
        sub     p_in, tmp
        sub     p_out, tmp

        or      num_bytes, num_bytes
        jz      %%_128_done
%endif                          ; DECRYPTION

        ;; Partial bytes left - complete CRC calculation
%%_crc_two_xmms:
        lea             tmp, [rel pshufb_shf_table]
        movdqu          xtmp2, [tmp + num_bytes]
%ifidn %%DIR, ENC
        movdqu          xtmp1, [p_in - 16 + num_bytes]  ; xtmp1 = data for CRC
%else
        movdqu          xtmp1, [p_out - 16 + num_bytes]  ; xtmp1 = data for CRC
%endif
        movdqa          xtmp3, xcrc
        pshufb          xcrc, xtmp2  ; top num_bytes with LSB xcrc
        pxor            xtmp2, [rel mask3]
        pshufb          xtmp3, xtmp2 ; bottom (16 - num_bytes) with MSB xcrc

        ;; data num_bytes (top) blended with MSB bytes of CRC (bottom)
        movdqa          xmm0, xtmp2
        pblendvb        xtmp3, xtmp1 ; xmm0 implicit

        ;; final CRC calculation
        movdqa          xtmp1, xcrc
        pclmulqdq       xtmp1, xcrckey, 0x01
        pclmulqdq       xcrc, xcrckey, 0x10
        pxor            xcrc, xtmp3
        pxor            xcrc, xtmp1

%%_128_done:
        ;;  compute crc of a 128-bit value
        movdqa          xcrckey, [rel rk5]

        ;; 64b fold
        movdqa          xtmp1, xcrc
        pclmulqdq       xtmp1, xcrckey, 0x00
        psrldq          xcrc, 8
        pxor            xcrc, xtmp1

        ;; 32b fold
        movdqa          xtmp1, xcrc
        pslldq          xtmp1, 4
        pclmulqdq       xtmp1, xcrckey, 0x10
        pxor            xcrc, xtmp1

%%_crc_barrett:
        ;; barrett reduction
        pand            xcrc, [rel mask2]
        movdqa          xtmp1, xcrc
        movdqa          xtmp2, xcrc
        movdqa          xcrckey, [rel rk7]

        pclmulqdq       xcrc, xcrckey, 0x00
        pxor            xcrc, xtmp2
        pand            xcrc, [rel mask]
        movdqa          xtmp2, xcrc
        pclmulqdq       xcrc, xcrckey, 0x10
        pxor            xcrc, xtmp2
        pxor            xcrc, xtmp1
        pextrd          eax, xcrc, 2 ; EAX = CRC
        not             eax

%%_crc_done:
        ;; @todo - store-to-load problem in ENC case (to be fixed later)
        ;; - store CRC in input buffer and authentication tag output
        ;; - encrypt remaining bytes
        mov     tmp, [job + _auth_tag_output]
%ifidn %%DIR, ENC
        mov     [p_in + num_bytes], eax
%endif
        mov     [tmp + 4], eax

%ifidn %%DIR, ENC
        add     num_bytes, 4 ; add size of appended CRC

        CIPHER_BIP_REST num_bytes, %%DIR, %%CIPH, p_in, p_out, p_keys, xbip, \
                        xcounter, xtmp1, xtmp2, xtmp3, ctr_check
%endif                          ; ENCRYPTION

        ;; finalize BIP
        mov     tmp, [job + _auth_tag_output]
        movdqa  xtmp1, xbip
        movdqa  xtmp2, xbip
        movdqa  xtmp3, xbip
        psrldq  xtmp1, 4
        psrldq  xtmp2, 8
        psrldq  xtmp3, 12
        pxor    xtmp1, xtmp2
        pxor    xbip, xtmp3
        pxor    xbip, xtmp1
        movd    [tmp], xbip

        ;; set job status
        or      dword [job + _status], STS_COMPLETED

        ;;  return job
        mov     rax, job
%endmacro                       ; AES128_CTR_PON

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; aes_cntr_128_pon_enc_sse(JOB_AES_HMAC *job)
align 32
MKGLOBAL(ENC_FN_NAME,function,internal)
ENC_FN_NAME:
        AES128_CTR_PON ENC, CTR
        ret

;;; aes_cntr_128_pon_dec_sse(JOB_AES_HMAC *job)
align 32
MKGLOBAL(DEC_FN_NAME,function,internal)
DEC_FN_NAME:
        AES128_CTR_PON DEC, CTR
        ret

;;; aes_cntr_128_pon_enc_no_ctr_sse(JOB_AES_HMAC *job)
align 32
MKGLOBAL(ENC_NO_CTR_FN_NAME,function,internal)
ENC_NO_CTR_FN_NAME:
        AES128_CTR_PON ENC, NO_CTR
        ret

;;; aes_cntr_128_pon_dec_no_ctr_sse(JOB_AES_HMAC *job)
align 32
MKGLOBAL(DEC_NO_CTR_FN_NAME,function,internal)
DEC_NO_CTR_FN_NAME:
        AES128_CTR_PON DEC, NO_CTR
        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
