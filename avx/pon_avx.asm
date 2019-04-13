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

%define xcounter xmm0
%define xbip    xmm1
%define xcrc    xmm2
%define xcrckey xmm3
%define xtmp1   xmm4
%define xtmp2   xmm5
%define xtmp3   xmm6
%define xtmp4   xmm7

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
%endif

%define job     arg1

%define p_in    arg2
%define p_keys  arg3
%define p_out   arg4

%define num_bytes tmp_1
%define tmp     tmp_2

;;; ============================================================================
;;; Loads 4, 8 or 12 bytes from memory location into XMM register
%macro simd_load_avx_4_8_12 3
%define %%XMM           %1      ; [out] XMM to read data into
%define %%INP           %2      ; [in] GP input data pointer
%define %%NUM           %3      ; [in] GP with number of bytes to read (4, 8 or 12)

        cmp     %%NUM, 4
        jne     %%_simd_load_not_4
        vmovd   %%XMM, [%%INP]
        jmp     %%_simd_load_end
%%_simd_load_not_4:
        cmp     %%NUM, 8
        jne     %%_simd_load_not_8
        vmovq   %%XMM, [%%INP]
        jmp     %%_simd_load_end
%%_simd_load_not_8:
        vmovq   %%XMM, [%%INP]
        vpinsrd %%XMM, [%%INP + 8], 2
%%_simd_load_end:
%endmacro

;;; ============================================================================
;;; Does all AES encryption rounds
%macro AES_ENC_ROUNDS 3
%define %%KP            %1      ; [in] pointer to expanded keys
%define %%N_ROUNDS      %2      ; [in] max rounds (128bit: 10, 12, 14)
%define %%BLOCK         %3      ; [in/out] XMM with encrypted block

%assign round 0
        vpxor           %%BLOCK, %%BLOCK, [%%KP + (round * 16)]

%rep (%%N_ROUNDS - 1)
%assign round (round + 1)
        vaesenc         %%BLOCK, %%BLOCK, [%%KP + (round * 16)]
%endrep

%assign round (round + 1)
        vaesenclast     %%BLOCK, %%BLOCK, [%%KP + (round * 16)]

%endmacro

;;; ============================================================================
;;; PON stitched algorithm round on a single AES block (16 bytes):
;;;   AES-CTR
;;;   - prepares counter block
;;;   - encrypts counter block
;;;   - loads text
;;;   - xor's text against encrypted blocks
;;;   - stores cipher text
;;;   BIP
;;;   - BIP update on 4 x 32-bits
;;;   CRC32
;;;   - CRC32 calculation
;;; Note: via selection of no_crc, no_bip, no_load, no_store different macro
;;;       behavior can be achieved to match needs of the overall algorithm.
%macro DO_PON 13
%define %%KP            %1      ; [in] GP, pointer to expanded keys
%define %%N_ROUNDS      %2      ; [in] number of AES rounds (10, 12 or 14)
%define %%CTR           %3      ; [in/out] XMM with counter block
%define %%INP           %4      ; [in/out] GP with input text pointer or "no_load"
%define %%OUTP          %5      ; [in/out] GP with output text pointer or "no_store"
%define %%XBIP_IN_OUT   %6      ; [in/out] XMM with BIP value or "no_bip"
%define %%XCRC_IN_OUT   %7      ; [in/out] XMM with CRC (can be anything if "no_crc" below)
%define %%XCRC_MUL      %8      ; [in] XMM with CRC constant  (can be anything if "no_crc" below)
%define %%TXMM0         %9      ; [clobbered|out] XMM temporary or data out (no_store)
%define %%TXMM1         %10     ; [clobbered|in] XMM temporary or data in (no_load)
%define %%TXMM2         %11     ; [clobbered] XMM temporary
%define %%CRC_TYPE      %12     ; [in] "first_crc" or "next_crc" or "no_crc"
%define %%DIR           %13     ; [in] "ENC" or "DEC"

        ;; prepare counter blocks for encryption
        vpshufb         %%TXMM0, %%CTR, [rel byteswap_const]
        vpaddd          %%CTR, %%CTR, [rel ddq_add_1]

        ;; CRC calculation
%ifidn %%CRC_TYPE, next_crc
        vpclmulqdq      %%TXMM2, %%XCRC_IN_OUT, %%XCRC_MUL, 0x01
        vpclmulqdq      %%XCRC_IN_OUT, %%XCRC_IN_OUT, %%XCRC_MUL, 0x10
%endif

        ;; AES rounds
        AES_ENC_ROUNDS  %%KP, %%N_ROUNDS, %%TXMM0

        ;; load text and xor against encrypted counter blocks
%ifnidn %%INP, no_load
        vmovdqu         %%TXMM1, [%%INP]
%endif
        vpxor           %%TXMM0, %%TXMM0, %%TXMM1

%ifidn %%DIR, ENC
        ;; CRC calculation for ENCRYPTION
%ifidn %%CRC_TYPE, first_crc
        ;; in the first run just XOR initial CRC with the first block
        vpxor           %%XCRC_IN_OUT, %%XCRC_IN_OUT, %%TXMM1
%endif
%ifidn %%CRC_TYPE, next_crc
        ;; - XOR results of CLMUL's together
        ;; - then XOR against text block
        vpxor           %%XCRC_IN_OUT, %%XCRC_IN_OUT, %%TXMM2
        vpxor           %%XCRC_IN_OUT, %%XCRC_IN_OUT, %%TXMM1
%endif
%else
        ;; CRC calculation for DECRYPTION
%ifidn %%CRC_TYPE, first_crc
        ;; in the first run just XOR initial CRC with the first block
        vpxor           %%XCRC_IN_OUT, %%XCRC_IN_OUT, %%TXMM0
%endif
%ifidn %%CRC_TYPE, next_crc
        ;; - XOR results of CLMUL's together
        ;; - then XOR against text block
        vpxor           %%XCRC_IN_OUT, %%XCRC_IN_OUT, %%TXMM2
        vpxor           %%XCRC_IN_OUT, %%XCRC_IN_OUT, %%TXMM0
%endif
%endif                        ; DECRYPT

        ;; store the result in the output buffer
%ifnidn %%OUTP, no_store
        vmovdqu         [%%OUTP], %%TXMM0
%endif

        ;; update BIP value - always use cipher text for BIP
%ifidn %%DIR, ENC
%ifnidn %%XBIP_IN_OUT, no_bip
        vpxor           %%XBIP_IN_OUT, %%XBIP_IN_OUT, %%TXMM0
%endif
%else
%ifnidn %%XBIP_IN_OUT, no_bip
        vpxor           %%XBIP_IN_OUT, %%XBIP_IN_OUT, %%TXMM1
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
%macro CIPHER_BIP_REST 10
%define %%NUM_BYTES   %1        ; [in/clobbered] number of bytes to cipher
%define %%DIR         %2        ; [in] "ENC" or "DEC"
%define %%PTR_IN      %3        ; [in/clobbered] GPR pointer to input buffer
%define %%PTR_OUT     %4        ; [in/clobbered] GPR pointer to output buffer
%define %%PTR_KEYS    %5        ; [in] GPR pointer to expanded keys
%define %%XBIP_IN_OUT %6        ; [in/out] XMM 128-bit BIP state
%define %%XCTR_IN_OUT %7        ; [in/out] XMM 128-bit AES counter block
%define %%XMMT1       %8        ; [clobbered] temporary XMM
%define %%XMMT2       %9        ; [clobbered] temporary XMM
%define %%XMMT3       %10       ; [clobbered] temporary XMM

%%_cipher_last_blocks:
        cmp     %%NUM_BYTES, 16
        jb      %%_partial_block_left

        DO_PON  %%PTR_KEYS, NUM_AES_ROUNDS, %%XCTR_IN_OUT, %%PTR_IN, %%PTR_OUT, %%XBIP_IN_OUT, \
                no_crc, no_crc, %%XMMT1, %%XMMT2, %%XMMT3, no_crc, %%DIR
        sub     %%NUM_BYTES, 16
        jz      %%_bip_done
        jmp     %%_cipher_last_blocks

%%_partial_block_left:
        ;; 4, 8 or 12 bytes of partial block possible here
        simd_load_avx_4_8_12 %%XMMT2, %%PTR_IN, %%NUM_BYTES

        ;; DO_PON() is not loading nor storing the data in this case:
        ;; XMMT2 = data in
        ;; XMMT1 = data out
        DO_PON  %%PTR_KEYS, NUM_AES_ROUNDS, %%XCTR_IN_OUT, no_load, no_store, no_bip, \
                no_crc, no_crc, %%XMMT1, %%XMMT2, %%XMMT3, no_crc, %%DIR

        ;; store partial bytes and update BIP
        cmp     %%NUM_BYTES, 4
        jne     %%_partial_block_not_4_bytes
        vmovd   [%%PTR_OUT], %%XMMT1
        vmovdqu %%XMMT3, [rel mask_out_top_bytes + 16 - 4]
        jmp     %%_partial_block_end
%%_partial_block_not_4_bytes:
        cmp     %%NUM_BYTES, 8
        jne     %%_partial_block_not_8_bytes
        vmovq   [%%PTR_OUT], %%XMMT1
        vmovdqu %%XMMT3, [rel mask_out_top_bytes + 16 - 8]
        jmp     %%_partial_block_end
%%_partial_block_not_8_bytes:
        vmovq   [%%PTR_OUT], %%XMMT1
        vpextrd [%%PTR_OUT + 8], %%XMMT1, 2
        vmovdqu %%XMMT3, [rel mask_out_top_bytes + 16 - 12]
%%_partial_block_end:
        ;; bip update for partial block (mask out bytes outside the message)
%ifidn %%DIR, ENC
        vpand   %%XMMT1, %%XMMT3
        vpxor   %%XBIP_IN_OUT, %%XMMT1
%else
        vpand   %%XMMT2, %%XMMT3
        vpxor   %%XBIP_IN_OUT, %%XMMT2
%endif
%%_bip_done:
%endmacro                       ; CIPHER_BIP_REST

;;; ============================================================================
;;; PON stitched algorithm of AES128-CTR, CRC and BIP
;;; - this is master macro that implements encrypt/decrypt API
;;; - calls other macros and directly uses registers
;;;   defined at the top of the file
%macro AES128_CTR_PON 1
%define %%DIR   %1              ; [in] direction "ENC" or "DEC"

        ;; - read 16 bytes of IV
        ;;   nonce 12 bytes, 4 bytes block counter
        ;; - convert to little endian format
        mov     tmp, [job + _iv]
        vmovdqu xcounter, [tmp]
        vpshufb xcounter, [rel byteswap_const]

        ;; load 8 bytes of payload for BIP (not part of encrypted message)
        ;; @todo these 8 bytes are hardcoded for now (per standard spec)
        mov     tmp, [job + _src]
        add     tmp, [job + _hash_start_src_offset_in_bytes]
        vmovq   xbip, [tmp]

        ;; get input buffer
        mov     p_in, [job + _src]
        add     p_in, [job + _cipher_start_src_offset_in_bytes]

        ;; get output buffer
        mov     p_out, [job + _dst]

        ;; get key pointers
        mov     p_keys, [job + _aes_enc_key_expanded]

        ;; initial CRC value
        vmovdqa xcrc, [rel init_crc_value]

        ;; load CRC constants
        vmovdqa xcrckey, [rel rk1] ; rk1 and rk2 in xcrckey

        ;; get number of bytes to cipher and crc
        ;; - computed CRC needs to be encrypted at the end too
        mov     num_bytes, [job + _msg_len_to_cipher_in_bytes]
        sub     num_bytes, 4    ; subtract size of CRC at the end of the message
        jz      %%_crc_done

        cmp     num_bytes, 32
        jae     %%_at_least_32_bytes

%ifidn %%DIR, DEC
        ;; decrypt the buffer first (with appended CRC)
        lea     tmp, [num_bytes + 4] ; add size of appended CRC

        CIPHER_BIP_REST tmp, %%DIR, p_in, p_out, p_keys, xbip, \
                        xcounter, xtmp1, xtmp2, xtmp3

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
        vmovdqu xtmp1, [p_in]
%else
        vmovdqu xtmp1, [p_out]
%endif
        vpxor   xcrc, xtmp1   ; xor the initial crc value
        jmp     %%_crc_two_xmms

%%_exact_16_left:
%ifidn %%DIR, ENC
        vmovdqu xtmp1, [p_in]
%else
        vmovdqu xtmp1, [p_out]
%endif
        vpxor   xcrc, xtmp1 ; xor the initial crc value
        jmp     %%_128_done

%%_less_than_16_left:
        ;; @note: due to message size restrictions (multiple of 4 bytes)
        ;;        there will never be a case in which there is less than
        ;;        4 bytes to process here

%ifidn %%DIR, ENC
        simd_load_avx_4_8_12 xtmp1, p_in, num_bytes
%else
        simd_load_avx_4_8_12 xtmp1, p_out, num_bytes
%endif
        vpxor   xcrc, xtmp1 ; xor the initial crc value

        lea     tmp, [rel pshufb_shf_table]
        vmovdqu xtmp1, [tmp + num_bytes]
        vpshufb xcrc, xtmp1
        jmp     %%_128_done

%%_at_least_32_bytes:
        DO_PON  p_keys, NUM_AES_ROUNDS, xcounter, p_in, p_out, xbip, \
                xcrc, xcrckey, xtmp1, xtmp2, xtmp3, first_crc, %%DIR
        sub     num_bytes, 16

%%_main_loop:
        cmp     num_bytes, 16
        jb      %%_exit_loop
        DO_PON  p_keys, NUM_AES_ROUNDS, xcounter, p_in, p_out, xbip, \
                xcrc, xcrckey, xtmp1, xtmp2, xtmp3, next_crc, %%DIR
        sub     num_bytes, 16
%ifidn %%DIR, ENC
        jz      %%_128_done
%endif
        jmp     %%_main_loop

%%_exit_loop:

%ifidn %%DIR, DEC
        ;; decrypt the buffer including trailing CRC
        lea     tmp, [num_bytes + 4] ; add CRC size

        CIPHER_BIP_REST tmp, %%DIR, p_in, p_out, p_keys, xbip, \
                        xcounter, xtmp1, xtmp2, xtmp3

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
        vmovdqu         xtmp2, [tmp + num_bytes]
%ifidn %%DIR, ENC
        vmovdqu         xtmp1, [p_in - 16 + num_bytes]  ; xtmp1 = data for CRC
%else
        vmovdqu         xtmp1, [p_out - 16 + num_bytes]  ; xtmp1 = data for CRC
%endif
        vmovdqa         xtmp3, xcrc
        vpshufb         xcrc, xtmp2  ; top num_bytes with LSB xcrc
        vpxor           xtmp2, [rel mask3]
        vpshufb         xtmp3, xtmp2 ; bottom (16 - num_bytes) with MSB xcrc

        ;; data num_bytes (top) blended with MSB bytes of CRC (bottom)
        vpblendvb       xtmp3, xtmp1, xtmp2

        ;; final CRC calculation
        vpclmulqdq      xtmp1, xcrc, xcrckey, 0x01
        vpclmulqdq      xcrc, xcrc, xcrckey, 0x10
        vpxor           xcrc, xtmp3
        vpxor           xcrc, xtmp1

%%_128_done:
        ;;  compute crc of a 128-bit value
        vmovdqa         xcrckey, [rel rk5]

        ;; 64b fold
        vpclmulqdq      xtmp1, xcrc, xcrckey, 0x00
        vpsrldq         xcrc, xcrc, 8
        vpxor           xcrc, xcrc, xtmp1

        ;; 32b fold
        vpslldq         xtmp1, xcrc, 4
        vpclmulqdq      xtmp1, xtmp1, xcrckey, 0x10
        vpxor           xcrc, xcrc, xtmp1

%%_crc_barrett:
        ;; barrett reduction
        vpand           xcrc, [rel mask2]
        vmovdqa         xtmp1, xcrc
        vmovdqa         xtmp2, xcrc
        vmovdqa         xcrckey, [rel rk7]

        vpclmulqdq      xcrc, xcrckey, 0x00
        vpxor           xcrc, xtmp2
        vpand           xcrc, [rel mask]
        vmovdqa         xtmp2, xcrc
        vpclmulqdq      xcrc, xcrckey, 0x10
        vpxor           xcrc, xtmp2
        vpxor           xcrc, xtmp1
        vpextrd         eax, xcrc, 2 ; EAX = CRC
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

        CIPHER_BIP_REST num_bytes, %%DIR, p_in, p_out, p_keys, xbip, \
                        xcounter, xtmp1, xtmp2, xtmp3
%endif                          ; ENCRYPTION

        ;; finalize BIP
        mov     tmp, [job + _auth_tag_output]
        vpsrldq xtmp1, xbip, 4
        vpsrldq xtmp2, xbip, 8
        vpsrldq xtmp3, xbip, 12
        vpxor   xtmp1, xtmp1, xtmp2
        vpxor   xbip, xbip, xtmp3
        vpxor   xbip, xbip, xtmp1
        vmovd   [tmp], xbip

        ;; set job status
        or      dword [job + _status], STS_COMPLETED

        ;;  return job
        mov     rax, job
%endmacro                       ; AES128_CTR_PON

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; submit_job_pon_enc_avx(JOB_AES_HMAC *job)
align 32
MKGLOBAL(submit_job_pon_enc_avx,function,internal)
submit_job_pon_enc_avx:
        AES128_CTR_PON ENC
        ret

;;; submit_job_pon_dec_avx(JOB_AES_HMAC *job)
align 32
MKGLOBAL(submit_job_pon_dec_avx,function,internal)
submit_job_pon_dec_avx:
        AES128_CTR_PON DEC
        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
