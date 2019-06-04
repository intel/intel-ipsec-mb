;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019, Intel Corporation All rights reserved.
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


; NOTE: this is included after GCM single-buffer implementation module
%include "mb_mgr_datastruct.asm"
%include "job_aes_hmac.asm"

%ifndef GCM128_MODE
%ifndef GCM192_MODE
%ifndef GCM256_MODE
%error "No GCM mode selected for gcm_avx512.asm!"
%endif
%endif
%endif

section .text
default rel


;;; ===========================================================================
;;; AESROUND4x128 macro
;;; - 4 lanes, 8 blocks per lane
;;; - it handles special cases: the last and zero rounds
;;; Uses NROUNDS macro defined at the top of the file to check the last round
%macro AESROUND4x128 25
%define %%L0B03 %1              ; [in/out] lane 0, blocks 0 to 3
%define %%L0B47 %2              ; [in/out] lane 0, blocks 4 to 7
%define %%L1B03 %3              ; [in/out] lane 1, blocks 0 to 3
%define %%L1B47 %4              ; ...
%define %%L2B03 %5
%define %%L2B47 %6
%define %%L3B03 %7              ; ...
%define %%L3B47 %8              ; [in/out] lane 3, blocks 4 to 7
%define %%TMP0  %9
%define %%TMP1  %10
%define %%TMP2  %11
%define %%TMP3  %12
%define %%KP0   %13             ; [in] expanded key pointer lane 0
%define %%KP1   %14             ; [in] expanded key pointer lane 1
%define %%KP2   %15             ; [in] expanded key pointer lane 2
%define %%KP3   %16             ; [in] expanded key pointer lane 3
%define %%ROUND %17             ; [in] round number
%define %%D0L   %18             ; [in] plain/cipher text blocks 0-3 lane 0 - NEEDED FOR THE LAST ROUND ONLY (CAN BE EMPTY OTHERWISE)
%define %%D0H   %19             ; [in] plain/cipher text blocks 4-7 lane 0
%define %%D1L   %20             ; [in] plain/cipher text blocks 0-3 lane 1
%define %%D1H   %21             ; ...
%define %%D2L   %22
%define %%D2H   %23
%define %%D3L   %24             ; ...
%define %%D3H   %25             ; [in] plain/cipher text blocks 4-7 lane 3

        vbroadcastf64x2 %%TMP0, [%%KP0 + 16*(%%ROUND)]
        vbroadcastf64x2 %%TMP1, [%%KP1 + 16*(%%ROUND)]
        vbroadcastf64x2 %%TMP2, [%%KP2 + 16*(%%ROUND)]
        vbroadcastf64x2 %%TMP3, [%%KP3 + 16*(%%ROUND)]
%if %%ROUND < 1
        ;;  round 0
        vpxorq          %%L0B03, %%L0B03, %%TMP0
        vpxorq          %%L0B47, %%L0B47, %%TMP0
        vpxorq          %%L1B03, %%L1B03, %%TMP1
        vpxorq          %%L1B47, %%L1B47, %%TMP1
        vpxorq          %%L2B03, %%L2B03, %%TMP2
        vpxorq          %%L2B47, %%L2B47, %%TMP2
        vpxorq          %%L3B03, %%L3B03, %%TMP3
        vpxorq          %%L3B47, %%L3B47, %%TMP3
%else
%if %%ROUND <= NROUNDS
        ;; rounds 1 to 9/11/13
        vaesenc         %%L0B03, %%L0B03, %%TMP0
        vaesenc         %%L0B47, %%L0B47, %%TMP0
        vaesenc         %%L1B03, %%L1B03, %%TMP1
        vaesenc         %%L1B47, %%L1B47, %%TMP1
        vaesenc         %%L2B03, %%L2B03, %%TMP2
        vaesenc         %%L2B47, %%L2B47, %%TMP2
        vaesenc         %%L3B03, %%L3B03, %%TMP3
        vaesenc         %%L3B47, %%L3B47, %%TMP3
%else
        ;; the last round - mix enclast with text xor's
        vaesenclast     %%L0B03, %%L0B03, %%TMP0
        vpxorq          %%L0B03, %%L0B03, %%D0L
        vaesenclast     %%L0B47, %%L0B47, %%TMP0
        vpxorq          %%L0B47, %%L0B47, %%D0H
        vaesenclast     %%L1B03, %%L1B03, %%TMP1
        vpxorq          %%L1B03, %%L1B03, %%D1L
        vaesenclast     %%L1B47, %%L1B47, %%TMP1
        vpxorq          %%L1B47, %%L1B47, %%D1H
        vaesenclast     %%L2B03, %%L2B03, %%TMP2
        vpxorq          %%L2B03, %%L2B03, %%D2L
        vaesenclast     %%L2B47, %%L2B47, %%TMP2
        vpxorq          %%L2B47, %%L2B47, %%D2H
        vaesenclast     %%L3B03, %%L3B03, %%TMP3
        vpxorq          %%L3B03, %%L3B03, %%D3L
        vaesenclast     %%L3B47, %%L3B47, %%TMP3
        vpxorq          %%L3B47, %%L3B47, %%D3H
%endif
%endif
%endmacro                       ; AESROUND4x128

;;; ===========================================================================
;;; ===========================================================================
;;; Encrypt the initial 8 blocks from 4 lanes and apply ghash on the ciphertext
%macro INITIAL_BLOCKS_x4 33
%define %%IN                    %1      ; pointer to array of pointers to input text
%define %%OUT                   %2      ; pointer to array of pointers to output text
%define %%KEYP0                 %3      ; pointer to expanded keys, lane 0
%define %%KEYP1                 %4      ; pointer to expanded keys, lane 1
%define %%KEYP2                 %5      ; pointer to expanded keys, lane 2
%define %%KEYP3                 %6      ; pointer to expanded keys, lane 3
%define %%TPTR0                 %7      ; temporary GP register
%define %%TPTR1                 %8      ; temporary GP register
%define %%TPTR2                 %9      ; temporary GP register
%define %%TPTR3                 %10     ; temporary GP register
%define %%L0B03                 %11     ; [out] cipher text blocks 0 to 3, lane 0
%define %%L0B47                 %12     ; [out] cipher text blocks 4 to 7, lane 0
%define %%L1B03                 %13     ; [out] cipher text blocks 0 to 3, lane 1
%define %%L1B47                 %14     ; ...
%define %%L2B03                 %15
%define %%L2B47                 %16
%define %%L3B03                 %17     ; ...
%define %%L3B47                 %18     ; [out] cipher text blocks 4 to 7, lane 3
%define %%GHASH                 %19     ; [in] AAD lane 0, 1, 2 and 3
%define %%T0                    %20     ; temporary AVX512 register
%define %%T1                    %21     ; temporary AVX512 register
%define %%T2                    %22     ; temporary AVX512 register
%define %%T3                    %23     ; temporary AVX512 register
%define %%T4                    %24     ; temporary AVX512 register
%define %%T5                    %25     ; temporary AVX512 register
%define %%T6                    %26     ; temporary AVX512 register
%define %%T7                    %27     ; temporary AVX512 register
%define %%T8                    %28     ; temporary AVX512 register
%define %%T9                    %29     ; temporary AVX512 register
%define %%T10                   %30     ; temporary AVX512 register
%define %%T11                   %31     ; temporary AVX512 register
%define %%ZMM_SHFMASK           %32     ; [in] shuffle mask changing byte order in 4 128bit words
%define %%ENC_DEC               %33     ; [in] ENC (encrypt) or DEC (decrypt) selector

%define %%INP0                  %%TPTR0
%define %%INP1                  %%TPTR1
%define %%INP2                  %%TPTR2
%define %%INP3                  %%TPTR3

%define %%OUTP0                 %%TPTR0
%define %%OUTP1                 %%TPTR1
%define %%OUTP2                 %%TPTR2
%define %%OUTP3                 %%TPTR3

        ;; load data in
        mov             %%INP0, [%%IN + 8*0]
        mov             %%INP1, [%%IN + 8*1]
        mov             %%INP2, [%%IN + 8*2]
        mov             %%INP3, [%%IN + 8*3]

        VX512LDR        %%T4, [%%INP0 + (16*0)]
        VX512LDR        %%T5, [%%INP0 + (16*4)]
        VX512LDR        %%T6, [%%INP1 + (16*0)]
        VX512LDR        %%T7, [%%INP1 + (16*4)]
        VX512LDR        %%T8, [%%INP2 + (16*0)]
        VX512LDR        %%T9, [%%INP2 + (16*4)]
        VX512LDR        %%T10,[%%INP3 + (16*0)]
        VX512LDR        %%T11,[%%INP3 + (16*4)]

        ;; shuffle IVB's
        vpshufb         %%L0B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L0B47, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L1B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L1B47, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L2B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L2B47, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L3B03, %%ZMM_SHFMASK    ; perform a 16Byte swap
        vpshufb         %%L3B47, %%ZMM_SHFMASK    ; perform a 16Byte swap

        ;; move to AES encryption rounds
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 0, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 1, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 2, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 3, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 4, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 5, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 6, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 7, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 8, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 9, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 10, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

%ifndef GCM128_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 11, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 12, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

%ifdef GCM256_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 13, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 14, \
                %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11
%endif
%endif

        ;; store
        mov             %%OUTP0, [%%OUT + 8*0]
        mov             %%OUTP1, [%%OUT + 8*1]
        mov             %%OUTP2, [%%OUT + 8*2]
        mov             %%OUTP3, [%%OUT + 8*3]

        VX512STR        [%%OUTP0 + (16*0)], %%L0B03
        VX512STR        [%%OUTP0 + (16*4)], %%L0B47
        VX512STR        [%%OUTP1 + (16*0)], %%L1B03
        VX512STR        [%%OUTP1 + (16*4)], %%L1B47
        VX512STR        [%%OUTP2 + (16*0)], %%L2B03
        VX512STR        [%%OUTP2 + (16*4)], %%L2B47
        VX512STR        [%%OUTP3 + (16*0)], %%L3B03
        VX512STR        [%%OUTP3 + (16*4)], %%L3B47

%ifidn  %%ENC_DEC, DEC
        ;; decryption - cipher text needs to go to GHASH phase
        vpshufb         %%L0B03, %%T4, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%T5, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%T6, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%T7, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%T8, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%T9, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%T10, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%T11, %%ZMM_SHFMASK
%else
        ;; encryption
        vpshufb         %%L0B03, %%L0B03, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%L0B47, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%L1B03, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%L1B47, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%L2B03, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%L2B47, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%L3B03, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%L3B47, %%ZMM_SHFMASK
%endif

        ;; xor encrypted block 0 with GHASH for the next GHASH round
        vmovdqa64       XWORD(%%T1), XWORD(%%GHASH)
        vextracti32x4   XWORD(%%T2), %%GHASH, 1
        vextracti32x4   XWORD(%%T3), %%GHASH, 2
        vextracti32x4   XWORD(%%T4), %%GHASH, 3

        vpxorq          %%L0B03, %%T1
        vpxorq          %%L1B03, %%T2
        vpxorq          %%L2B03, %%T3
        vpxorq          %%L3B03, %%T4
%endmacro                       ;INITIAL_BLOCKS_x4

;;; ===========================================================================
;;; ===========================================================================
;;; Encrypt 8 blocks at a time on 4 lanes
;;; GHASH the 8 previously encrypted ciphertext blocks (4 lanes)
%macro  GHASH_8_ENCRYPT_8_PARALLEL_x4 44
%define %%IN                    %1      ; pointer to array of pointers to plain/cipher text
%define %%OUT                   %2      ; pointer to array of pointers to cipher/plain text
%define %%KEYP0                 %3      ; pointer to expanded keys, lane 0
%define %%KEYP1                 %4      ; pointer to expanded keys, lane 1
%define %%KEYP2                 %5      ; pointer to expanded keys, lane 2
%define %%KEYP3                 %6      ; pointer to expanded keys, lane 3
%define %%TPTR0                 %7      ; temporary GP register (used as pointer)
%define %%TPTR1                 %8      ; temporary GP register (used as pointer)
%define %%TPTR2                 %9      ; temporary GP register (used as pointer)
%define %%TPTR3                 %10     ; temporary GP register (used as pointer)
%define %%DATA_OFFSET           %11     ; current data offset (used with text loads and stores)
%define %%CTRL0                 %12     ; counter blocks 4 to 7 for lane 0
%define %%CTRL1                 %13     ; counter blocks 4 to 7 for lane 1
%define %%CTRL2                 %14     ; counter blocks 4 to 7 for lane 2
%define %%CTRL3                 %15     ; counter blocks 4 to 7 for lane 3
%define %%L0B03                 %16     ; lane 0 blocks 0 to 3
%define %%L0B47                 %17     ; lane 0 blocks 4 to 7
%define %%L1B03                 %18	; lane 1 blocks 0 to 3
%define %%L1B47                 %19	; lane 1 blocks 4 to 7
%define %%L2B03                 %20	; lane 2 blocks 0 to 3
%define %%L2B47                 %21	; lane 2 blocks 4 to 7
%define %%L3B03                 %22	; lane 3 blocks 0 to 3
%define %%L3B47                 %23	; lane 3 blocks 4 to 7
%define %%GHASH    		%24     ; [in/out] GHASH for 4 lanes
%define %%T0    		%25
%define %%T1    		%26
%define %%T2    		%27
%define %%T3    		%28
%define %%T4    		%29
%define %%T5    		%30
%define %%T6    		%31
%define %%T7    		%32
%define %%T8    		%33
%define %%T9    		%34
%define %%PREVLO0		%35     ; [in] 4 lanes x 8 blocks of cipher text for GHASH
%define %%PREVHI0		%36
%define %%PREVLO1		%37
%define %%PREVHI1		%38
%define %%PREVLO2		%39
%define %%PREVHI2		%40
%define %%PREVLO3		%41
%define %%PREVHI3		%42
%define %%ZMM_SHFMASK           %43     ; [in] byte swap shuffle mask for 128 bits
%define %%ENC_DEC               %44     ; [in] ENC (encryption) or DEC (decryption)

;;; ============================================================================
;;; a few virtual register mappings
%define %%INP0                  %%TPTR0
%define %%INP1                  %%TPTR1
%define %%INP2                  %%TPTR2
%define %%INP3                  %%TPTR3

%define %%OUTP0                 %%TPTR0
%define %%OUTP1                 %%TPTR1
%define %%OUTP2                 %%TPTR2
%define %%OUTP3                 %%TPTR3

%define %%TH                    %%T5
%define %%TM                    %%T6
%define %%TL                    %%T7

%define %%TEXTL0B03		%%T8
%define %%TEXTL0B47		%%T9
%define %%TEXTL1B03		%%PREVLO1 ; GHASH needs to be complete before using these
%define %%TEXTL1B47		%%PREVHI1
%define %%TEXTL2B03		%%PREVLO2
%define %%TEXTL2B47		%%PREVHI2
%define %%TEXTL3B03		%%PREVLO3
%define %%TEXTL3B47		%%PREVHI3
;;; ============================================================================

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 0, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        mov             %%INP0, [%%IN + 8*0]
        mov             %%INP1, [%%IN + 8*1]
        mov             %%INP2, [%%IN + 8*2]
        mov             %%INP3, [%%IN + 8*3]

        ;; =====================================================================
        VCLMUL_STEP1 %%KEYP0, %%PREVHI0, %%T4, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 1, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP0, %%PREVHI0, %%PREVLO0, %%T4, %%T8, %%T9, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 2, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; =====================================================================

        VCLMUL_STEP1 %%KEYP1, %%PREVHI1, %%T4, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 3, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP1, %%PREVHI1, %%PREVLO1, %%T4, %%T8, %%T9, %%TH, %%TM, %%TL

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 4, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; accumulate GHASH results from 4 lanes into [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]
        vinserti64x2    %%PREVLO0, XWORD(%%PREVLO1), 1
        vinserti64x2    %%PREVHI0, XWORD(%%PREVHI1), 1

        ;; =====================================================================

        VCLMUL_STEP1 %%KEYP2, %%PREVHI2, %%T4, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 5, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP2, %%PREVHI2, %%PREVLO2, %%T4, %%T8, %%T9, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 6, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; accumulate GHASH results from 4 lanes into [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]
        vinserti64x2    %%PREVLO0, XWORD(%%PREVLO2), 2
        vinserti64x2    %%PREVHI0, XWORD(%%PREVHI2), 2

        ;; =====================================================================

        VCLMUL_STEP1 %%KEYP3, %%PREVHI3, %%T4, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 7, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        VCLMUL_STEP2 %%KEYP3, %%PREVHI3, %%PREVLO3, %%T4, %%T8, %%T9, %%T5, %%T6, %%T7

                AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%T0, %%T1, %%T2, %%T3, \
                        %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 8, \
                        %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                        %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        ;; accumulate GHASH results from 4 lanes into [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]
        vinserti64x2    %%PREVLO0, XWORD(%%PREVLO3), 3
        vinserti64x2    %%PREVHI0, XWORD(%%PREVHI3), 3

        ;; =====================================================================
        ;; load plain/cipher text
        ;; - this cannot be done before GHASH is complete (reuses same registers)

        VX512LDR        %%TEXTL0B03, [%%INP0 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL0B47, [%%INP0 + %%DATA_OFFSET + 64*1]
        VX512LDR        %%TEXTL1B03, [%%INP1 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL1B47, [%%INP1 + %%DATA_OFFSET + 64*1]
        VX512LDR        %%TEXTL2B03, [%%INP2 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL2B47, [%%INP2 + %%DATA_OFFSET + 64*1]
        VX512LDR        %%TEXTL3B03, [%%INP3 + %%DATA_OFFSET + 64*0]
        VX512LDR        %%TEXTL3B47, [%%INP3 + %%DATA_OFFSET + 64*1]

        mov             %%OUTP0, [%%OUT + 8*0]
        mov             %%OUTP1, [%%OUT + 8*1]
        mov             %%OUTP2, [%%OUT + 8*2]
        mov             %%OUTP3, [%%OUT + 8*3]

        ;; =====================================================================
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 9, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 10, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47

%ifndef GCM128_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 11, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 12, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
%ifdef GCM256_MODE
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 13, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
        AESROUND4x128 %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                %%T0, %%T1, %%T2, %%T3, \
                %%KEYP0, %%KEYP1, %%KEYP2, %%KEYP3, 14, \
                %%TEXTL0B03, %%TEXTL0B47, %%TEXTL1B03, %%TEXTL1B47, \
                %%TEXTL2B03, %%TEXTL2B47, %%TEXTL3B03, %%TEXTL3B47
%endif                          ; GCM256
%endif                          ; !GCM128

        ;; =====================================================================
        ;; =====================================================================
        ;; =====================================================================

        ;; =====================================================================
        ;; first phase of the reduction (barret)
        ;; - becasue of bit ordering, LSB 128 bit word is reduced rather than MSB
        ;; - accumulated GHASH in [%%PREVHI0 (msb) : %%PREVLO0 (lsb)]

        vmovdqu64       %%T3, [rel POLY2]

        vpclmulqdq      %%T4, %%T3, %%PREVLO0, 0x01
        vpslldq         %%T4, %%T4, 8                   ; shift-L 2 DWs
        vpxorq          %%PREVLO0, %%PREVLO0, %%T4      ; first phase of the reduction complete

        ;; =====================================================================
        ;; store cipher/plain text

        VX512STR        [%%OUTP0 + %%DATA_OFFSET + 64*0], %%L0B03
        VX512STR        [%%OUTP0 + %%DATA_OFFSET + 64*1], %%L0B47
        VX512STR        [%%OUTP1 + %%DATA_OFFSET + 64*0], %%L1B03
        VX512STR        [%%OUTP1 + %%DATA_OFFSET + 64*1], %%L1B47
        VX512STR        [%%OUTP2 + %%DATA_OFFSET + 64*0], %%L2B03
        VX512STR        [%%OUTP2 + %%DATA_OFFSET + 64*1], %%L2B47
        VX512STR        [%%OUTP3 + %%DATA_OFFSET + 64*0], %%L3B03
        VX512STR        [%%OUTP3 + %%DATA_OFFSET + 64*1], %%L3B47

        ;; =====================================================================
        ;; second phase of the reduction
        vpclmulqdq      %%T4, %%T3, %%PREVLO0, 0x00
        vpsrldq         %%T4, %%T4, 4                   ; shift-R 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%GHASH, %%T3, %%PREVLO0, 0x10
        vpslldq         %%GHASH, %%GHASH, 4             ; shift-L 1 DW (Shift-L 1-DW to obtain result with no shifts)

        ;; second phase of the reduction complete
        vpternlogq      %%GHASH, %%T4, %%PREVHI0, 0x96  ; GHASH = GHASH xor T4 xor PREVHI0

        ;; =====================================================================

        ;; prepare cipher blocks for the next GHASH round
%ifidn %%ENC_DEC, ENC
        vpshufb         %%L0B03, %%L0B03, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%L0B47, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%L1B03, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%L1B47, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%L2B03, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%L2B47, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%L3B03, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%L3B47, %%ZMM_SHFMASK
%else
        ;; GHASH is computed over cipher text (use text)
        vpshufb         %%L0B03, %%TEXTL0B03, %%ZMM_SHFMASK
        vpshufb         %%L0B47, %%TEXTL0B47, %%ZMM_SHFMASK
        vpshufb         %%L1B03, %%TEXTL1B03, %%ZMM_SHFMASK
        vpshufb         %%L1B47, %%TEXTL1B47, %%ZMM_SHFMASK
        vpshufb         %%L2B03, %%TEXTL2B03, %%ZMM_SHFMASK
        vpshufb         %%L2B47, %%TEXTL2B47, %%ZMM_SHFMASK
        vpshufb         %%L3B03, %%TEXTL3B03, %%ZMM_SHFMASK
        vpshufb         %%L3B47, %%TEXTL3B47, %%ZMM_SHFMASK
%endif

        ;; xor encrypted block 0 with GHASH for the next round
        vmovdqa64       XWORD(%%T1), XWORD(%%GHASH)
        vextracti32x4   XWORD(%%T2), %%GHASH, 1
        vextracti32x4   XWORD(%%T3), %%GHASH, 2
        vextracti32x4   XWORD(%%T4), %%GHASH, 3

        vpxorq          %%L0B03, %%T1
        vpxorq          %%L1B03, %%T2
        vpxorq          %%L2B03, %%T3
        vpxorq          %%L3B03, %%T4
%endmacro                       ; GHASH_8_ENCRYPT_8_PARALLEL_x4

;;; ===========================================================================
;;; ===========================================================================
;;; GHASH the last 8 ciphertext blocks on 4 lanes
%macro  GHASH_LAST_8x4 25
%define %%KEYP0                 %1      ; [in] pointer to expanded keys, lane 0
%define %%KEYP1                 %2      ; [in] pointer to expanded keys, lane 1
%define %%KEYP2                 %3      ; [in] pointer to expanded keys, lane 2
%define %%KEYP3                 %4      ; [in] pointer to expanded keys, lane 3
%define %%L0B03                 %5      ; [in] clobbered, ciper text, lane 0, blocks 0 to 3 (Y0 already XOR'ed on X1)
%define %%L0B47                 %6      ; [in] clobbered, ciper text, lane 0, blocks 4 to 7
%define %%L1B03                 %7      ; ...
%define %%L1B47                 %8
%define %%L2B03                 %9
%define %%L2B47                 %10
%define %%L3B03                 %11     ; ...
%define %%L3B47                 %12     ; [in] clobbered, ciper text, lane 3, blocks 4 to 7
%define %%GHASH    		%13     ; [out] ghash output
%define %%T1    		%14
%define %%T2    		%15
%define %%T3    		%16
%define %%T4    		%17
%define %%T5    		%18
%define %%T6    		%19
%define %%T7    		%20
%define %%T8    		%21
%define %%T9    		%22
%define %%T10    		%23
%define %%T11    		%24
%define %%T12   		%25

%define %%TH                    %%T5
%define %%TM                    %%T6
%define %%TL                    %%T7

%define %%L                     %%T1
%define %%H                     %%T2

        ;; =====================================================================
        ;; lane 0, 8 blocks

        VCLMUL_STEP1    %%KEYP0, %%L0B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP0, %%L0B47, %%L0B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vmovdqa64       XWORD(%%L), XWORD(%%L0B03)
        vmovdqa64       XWORD(%%H), XWORD(%%L0B47)

        ;; =====================================================================
        ;; lane 1, 8 blocks

        VCLMUL_STEP1    %%KEYP1, %%L1B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP1, %%L1B47, %%L1B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vinserti64x2    %%L, XWORD(%%L1B03), 1
        vinserti64x2    %%H, XWORD(%%L1B47), 1

        ;; =====================================================================
        ;; lane 2, 8 blocks

        VCLMUL_STEP1    %%KEYP2, %%L2B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP2, %%L2B47, %%L2B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vinserti64x2    %%L, XWORD(%%L2B03), 2
        vinserti64x2    %%H, XWORD(%%L2B47), 2

        ;; =====================================================================
        ;; lane 3, 8 blocks

        VCLMUL_STEP1    %%KEYP3, %%L3B47, %%T4, %%TH, %%TM, %%TL
        VCLMUL_STEP2    %%KEYP3, %%L3B47, %%L3B03, \
                        %%T4, %%T8, %%T9, \
                        %%TH, %%TM, %%TL

        vinserti64x2    %%L, XWORD(%%L3B03), 3
        vinserti64x2    %%H, XWORD(%%L3B47), 3

        ;; =====================================================================
        ;; =====================================================================
        ;; first phase of the reduction <H(hi):L(low)>
        ;; - reducing L, rather H, due to bit ordering

        vmovdqu64       %%T3, [rel POLY2]

        vpclmulqdq      %%T4, %%T3, %%L, 0x01
        vpslldq         %%T4, %%T4, 8           ; shift-L xmm2 2 DWs

        vpxorq          %%L, %%L, %%T4          ; first phase of the reduction complete

        ;; =====================================================================
        ;; second phase of the reduction
        vpclmulqdq      %%T4, %%T3, %%L, 0x00
        vpsrldq         %%T4, %%T4, 4           ; shift-R 1 DW (Shift-R only 1-DW to obtain 2-DWs shift-R)

        vpclmulqdq      %%GHASH, %%T3, %%L, 0x10
        vpslldq         %%GHASH, %%GHASH, 4     ; shift-L 1 DW (Shift-L 1-DW to obtain result with no shifts)

        ;; second phase of the reduction complete
        vpternlogq      %%GHASH, %%T4, %%H, 0x96  ; GHASH = GHASH xor T4 xor H
        ;; =====================================================================
%endmacro

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_ENC_DEC_4x128 Encodes/Decodes given data
;;; - 4 lanes, 8 blocks at a time (hence 4x128 bytes or 4x8 blocks)
;;; - assumes that the passed gcm_context_data struct has been initialized by GCM_INIT
;;; - requires the input data be multiple of 128 bytes
;;; Input: gcm_key_data struct *GDATA_KEY[4]
;;;        gcm_context_data *GDATA_CTX[4]
;;;        input text PLAIN_CYPH_IN[4]
;;;        input text length (PLAIN_CYPH_LEN) and
;;;        whether encoding or decoding (ENC_DEC).
;;; Output: A cipher of the given plain text CYPH_PLAIN_OUT[4]
;;;         updated GDATA_CTX[4]
;;; Linux clobbers:   rax, rbx, rcx, rdx, rbp, r8-r15, zmm0-zmm31
;;; Windows clobbers: rax, rbx, rdi ,rsi, rbp, r8-r15, zmm0-zmm31
;;; ===========================================================================
%macro  GCM_ENC_DEC_4x128       3
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded keys
%define %%PLAIN_CYPH_LEN        %2 ; [in] length of the text to process (multiple of 128 bytes)
%define %%ENC_DEC               %3 ; [in] ENC (encrypt) or DEC (decrypt) selector

%define %%GDATA_KEY             %%STATE + _gcm_args_keys
%define %%GDATA_CTX             %%STATE + _gcm_args_ctx
%define %%CYPH_PLAIN_OUT        %%STATE + _gcm_args_out
%define %%PLAIN_CYPH_IN         %%STATE + _gcm_args_in

%define %%LEN_REG               %%PLAIN_CYPH_LEN
%define %%DATA_OFFSET           r14 ;; @note: on windows this reg is used to retrive stack args

;;; ===========================================================================
;;; register mappings within the macro

%define %%TPTR0                 r9
%define %%TPTR1                 r10
%define %%TPTR2                 r11
%define %%TPTR3                 r12

%define %%GPR0                  rax
%define %%GPR1                  rbx
%define %%GPR2                  rbp
%define %%GPR3                  r15

%ifidn __OUTPUT_FORMAT__, win64
%define %%KPTR0                 r8
%define %%KPTR1                 r13
%define %%KPTR2                 rdi
%define %%KPTR3                 rsi
%else
%define %%KPTR0                 rdx
%define %%KPTR1                 rcx
%define %%KPTR2                 r8
%define %%KPTR3                 r13
%endif

%define %%L0B03                 zmm0
%define %%L0B47                 zmm1
%define %%L1B03                 zmm2
%define %%L1B47                 zmm3
%define %%L2B03                 zmm4
%define %%L2B47                 zmm5
%define %%L3B03                 zmm6
%define %%L3B47                 zmm7

%define %%T1                    zmm8
%define %%T2                    zmm9
%define %%T3                    zmm10
%define %%T4                    zmm11
%define %%T5                    zmm12
%define %%T6                    zmm13
%define %%T7                    zmm14
%define %%T8                    zmm15
%define %%T9                    zmm16
%define %%T10                   zmm17
%define %%T11                   zmm18
%define %%T12                   zmm19
%define %%T13                   zmm20
%define %%T14                   zmm21
%define %%T15                   zmm22
%define %%T16                   zmm23
%define %%T17                   zmm24
%define %%T18                   zmm25

%define %%GHASH                 zmm26

%define %%CTRL0                 zmm27
%define %%CTRL1                 zmm28
%define %%CTRL2                 zmm29
%define %%CTRL3                 zmm30

%define %%ZMM_SHUF_MASK         zmm31

;;; ===========================================================================
;;; virtual register mappings

%define %%PREVLO0		%%T11 ; 4 lanes x 8 blocks of cipher text for GHASH
%define %%PREVHI0		%%T12
%define %%PREVLO1		%%T13
%define %%PREVHI1		%%T14
%define %%PREVLO2		%%T15
%define %%PREVHI2		%%T16
%define %%PREVLO3		%%T17
%define %%PREVHI3		%%T18

;;; ===========================================================================

        or              %%LEN_REG, %%LEN_REG
        jz              %%_enc_dec_done_x4

        mov             %%DATA_OFFSET, 128

        ;; load GCM CTX pointers for 4 lanes
        mov             %%TPTR0, [%%GDATA_CTX + (0*8)]
        mov             %%TPTR1, [%%GDATA_CTX + (1*8)]
        mov             %%TPTR2, [%%GDATA_CTX + (2*8)]
        mov             %%TPTR3, [%%GDATA_CTX + (3*8)]

        ;;  load common constants used in the code
        vmovdqa64       %%ZMM_SHUF_MASK, [rel SHUF_MASK]

        ;; Update length of data processed
        add             [%%TPTR0 + InLen], %%LEN_REG
        add             [%%TPTR1 + InLen], %%LEN_REG
        add             [%%TPTR2 + InLen], %%LEN_REG
        add             [%%TPTR3 + InLen], %%LEN_REG

        ;; extract current hash values from 4 lanes
        vmovdqu64       XWORD(%%GHASH), [%%TPTR0 + AadHash]
        vinserti64x2    %%GHASH, [%%TPTR1 + AadHash], 1
        vinserti64x2    %%GHASH, [%%TPTR2 + AadHash], 2
        vinserti64x2    %%GHASH, [%%TPTR3 + AadHash], 3

        ;;  lift CTR set from initial_blocks to here
        vmovdqa64       %%T1, [rel ddq_add_1234]
        vmovdqa64       %%T2, [rel ddq_add_5678]
        vbroadcastf64x2 %%CTRL0, [%%TPTR0 + CurCount]
        vbroadcastf64x2 %%CTRL1, [%%TPTR1 + CurCount]
        vbroadcastf64x2 %%CTRL2, [%%TPTR2 + CurCount]
        vbroadcastf64x2 %%CTRL3, [%%TPTR3 + CurCount]
        vpaddd          %%L0B03, %%CTRL0, %%T1
        vpaddd          %%L1B03, %%CTRL1, %%T1
        vpaddd          %%L2B03, %%CTRL2, %%T1
        vpaddd          %%L3B03, %%CTRL3, %%T1
        vpaddd          %%L0B47, %%CTRL0, %%T2
        vpaddd          %%L1B47, %%CTRL1, %%T2
        vpaddd          %%L2B47, %%CTRL2, %%T2
        vpaddd          %%L3B47, %%CTRL3, %%T2
        vmovdqa64       %%CTRL0, %%L0B47
        vmovdqa64       %%CTRL1, %%L1B47
        vmovdqa64       %%CTRL2, %%L2B47
        vmovdqa64       %%CTRL3, %%L3B47

        ;; load GCM key pointers for 4 lanes
        mov             %%KPTR0, [%%GDATA_KEY + (0*8)]
        mov             %%KPTR1, [%%GDATA_KEY + (1*8)]
        mov             %%KPTR2, [%%GDATA_KEY + (2*8)]
        mov             %%KPTR3, [%%GDATA_KEY + (3*8)]

%%_cipher_only_x4:
        ;; run cipher only over the first 8 blocks
        INITIAL_BLOCKS_x4       %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, \
                                %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                                %%TPTR0, %%TPTR1, %%TPTR2, %%TPTR3, \
                                %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                                %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                                %%GHASH, \
                                %%T1, %%T2, %%T3, %%T4, %%T5, %%T6, %%T7, %%T8, \
                                %%T9, %%T10, %%T11, %%T12, \
                                %%ZMM_SHUF_MASK, %%ENC_DEC

        ;; Update length
        sub     %%LEN_REG, 128
        jz      %%_encrypt_done_x4

        vmovq   %%GPR0, XWORD(%%CTRL0)
        vmovq   %%GPR1, XWORD(%%CTRL1)
        vmovq   %%GPR2, XWORD(%%CTRL2)
        vmovq   %%GPR3, XWORD(%%CTRL3)

        and     %%GPR0, 255
        and     %%GPR1, 255
        and     %%GPR2, 255
        and     %%GPR3, 255

        ;; shuffle the counters to BE
	vpshufb %%CTRL0, %%ZMM_SHUF_MASK
	vpshufb %%CTRL1, %%ZMM_SHUF_MASK
	vpshufb %%CTRL2, %%ZMM_SHUF_MASK
	vpshufb %%CTRL3, %%ZMM_SHUF_MASK

%%_encrypt_by_8_parallel_x4:
        ;; get max counter value
        cmp     %%GPR0, %%GPR1
        cmova   %%GPR1, %%GPR0
        cmp     %%GPR2, %%GPR1
        cmova   %%GPR1, %%GPR2
        cmp     %%GPR3, %%GPR1
        cmova   %%GPR1, %%GPR3
        ;; at this stage %%GPR1 includes max 8-bit LS counter from 4 lanes

        ;; if max counter is above 244 then overflow will occur
        cmp     %%GPR1, 244
        ja      %%_encrypt_by_8_overflow_x4

        ;; (256 - 8) because we process 8 blocks at a time
        ;; Max number of blocks that can be processed in a lane
        ;; without shuffling is (256 - 8)
        mov     %%GPR0, (256 - 8)
        sub     %%GPR0, %%GPR1
        shr     %%GPR0, 3
        ;; GPR0 holds number of iterations based on remaing blocks before overflow

        ;; get number of iterations from the remaining byte length
        mov     %%GPR1, %%LEN_REG
        shr     %%GPR1, 7

        ;; pick the smallest one (GPR0 will be the counter)
        cmp     %%GPR1, %%GPR0
        cmovb   %%GPR0, %%GPR1

%%_encrypt_by_8_x4:
        ;; copy previously encrypted blocks for GHASH
	vmovdqa64	%%PREVLO0, %%L0B03
	vmovdqa64	%%PREVHI0, %%L0B47
	vmovdqa64	%%PREVLO1, %%L1B03
	vmovdqa64	%%PREVHI1, %%L1B47
	vmovdqa64	%%PREVLO2, %%L2B03
	vmovdqa64	%%PREVHI2, %%L2B47
	vmovdqa64	%%PREVLO3, %%L3B03
	vmovdqa64	%%PREVHI3, %%L3B47

        ;; - no byte overflow and no shuffling required
        vmovdqa64       %%T1, [rel ddq_addbe_4444]
        vmovdqa64       %%T2, [rel ddq_addbe_8888]

        vpaddd          %%L0B03, %%CTRL0, %%T1
        vpaddd          %%L1B03, %%CTRL1, %%T1
        vpaddd          %%L2B03, %%CTRL2, %%T1
        vpaddd          %%L3B03, %%CTRL3, %%T1
        vpaddd          %%L0B47, %%CTRL0, %%T2
        vpaddd          %%L1B47, %%CTRL1, %%T2
        vpaddd          %%L2B47, %%CTRL2, %%T2
        vpaddd          %%L3B47, %%CTRL3, %%T2

        vmovdqa64       %%CTRL0, %%L0B47
        vmovdqa64       %%CTRL1, %%L1B47
        vmovdqa64       %%CTRL2, %%L2B47
        vmovdqa64       %%CTRL3, %%L3B47

        GHASH_8_ENCRYPT_8_PARALLEL_x4   %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, \
                                        %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                                        %%TPTR0, %%TPTR1, %%TPTR2, %%TPTR3, \
                                        %%DATA_OFFSET, \
                                        %%CTRL0, %%CTRL1, %%CTRL2, %%CTRL3, \
                                        %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                                        %%GHASH, \
                                        %%T1, %%T2, %%T3,  %%T4,  %%T5,  %%T6,  %%T7, \
                                        %%T8, %%T9, %%T10, \
                                        %%PREVLO0, %%PREVHI0, %%PREVLO1, %%PREVHI1, \
                                        %%PREVLO2, %%PREVHI2, %%PREVLO3, %%PREVHI3, \
                                        %%ZMM_SHUF_MASK, %%ENC_DEC
        add     %%DATA_OFFSET, 128
        sub     %%LEN_REG, 128
        sub     %%GPR0, 1
        jnz     %%_encrypt_by_8_x4

%%_encrypt_by_8_overflow_x4:
        ;; shuffle the counters back to LE
	vpshufb %%CTRL0, %%ZMM_SHUF_MASK
	vpshufb %%CTRL1, %%ZMM_SHUF_MASK
	vpshufb %%CTRL2, %%ZMM_SHUF_MASK
	vpshufb %%CTRL3, %%ZMM_SHUF_MASK

        or      %%LEN_REG, %%LEN_REG
        jz      %%_encrypt_done_x4

        ;; copy previously encrypted blocks for GHASH
	vmovdqa64	%%PREVLO0, %%L0B03
	vmovdqa64	%%PREVHI0, %%L0B47
	vmovdqa64	%%PREVLO1, %%L1B03
	vmovdqa64	%%PREVHI1, %%L1B47
	vmovdqa64	%%PREVLO2, %%L2B03
	vmovdqa64	%%PREVHI2, %%L2B47
	vmovdqa64	%%PREVLO3, %%L3B03
	vmovdqa64	%%PREVHI3, %%L3B47

        ;; prepare new counter blocks in LE
        vmovdqa64       %%T1, [rel ddq_add_4444]
        vmovdqa64       %%T2, [rel ddq_add_8888]
        vpaddd          %%L0B03, %%CTRL0, %%T1
        vpaddd          %%L1B03, %%CTRL1, %%T1
        vpaddd          %%L2B03, %%CTRL2, %%T1
        vpaddd          %%L3B03, %%CTRL3, %%T1
        vpaddd          %%L0B47, %%CTRL0, %%T2
        vpaddd          %%L1B47, %%CTRL1, %%T2
        vpaddd          %%L2B47, %%CTRL2, %%T2
        vpaddd          %%L3B47, %%CTRL3, %%T2

        ;; save the counter to GPR's for calculation of number of loops
        vmovq   %%GPR0, XWORD(%%L0B47)
        vmovq   %%GPR1, XWORD(%%L1B47)
        vmovq   %%GPR2, XWORD(%%L2B47)
        vmovq   %%GPR3, XWORD(%%L3B47)

        and     %%GPR0, 255
        and     %%GPR1, 255
        and     %%GPR2, 255
        and     %%GPR3, 255

        ;; convert counter blocks to BE
	vpshufb 	%%L0B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L0B47, %%ZMM_SHUF_MASK
	vpshufb 	%%L1B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L1B47, %%ZMM_SHUF_MASK
	vpshufb 	%%L2B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L2B47, %%ZMM_SHUF_MASK
	vpshufb 	%%L3B03, %%ZMM_SHUF_MASK
	vpshufb 	%%L3B47, %%ZMM_SHUF_MASK

        ;; update 4 lane CTR in BE
        vmovdqa64       %%CTRL0, %%L0B47
        vmovdqa64       %%CTRL1, %%L1B47
        vmovdqa64       %%CTRL2, %%L2B47
        vmovdqa64       %%CTRL3, %%L3B47

        GHASH_8_ENCRYPT_8_PARALLEL_x4   %%PLAIN_CYPH_IN, %%CYPH_PLAIN_OUT, \
                                        %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                                        %%TPTR0, %%TPTR1, %%TPTR2, %%TPTR3, \
                                        %%DATA_OFFSET, \
                                        %%CTRL0, %%CTRL1, %%CTRL2, %%CTRL3, \
                                        %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                                        %%GHASH, \
                                        %%T1, %%T2, %%T3,  %%T4,  %%T5,  %%T6,  %%T7, \
                                        %%T8, %%T9, %%T10, \
                                        %%PREVLO0, %%PREVHI0, %%PREVLO1, %%PREVHI1, \
                                        %%PREVLO2, %%PREVHI2, %%PREVLO3, %%PREVHI3, \
                                        %%ZMM_SHUF_MASK, %%ENC_DEC
        add     %%DATA_OFFSET, 128
        sub     %%LEN_REG, 128
        jnz     %%_encrypt_by_8_parallel_x4

        ;; shuffle the counters back to LE
	vpshufb %%CTRL0, %%ZMM_SHUF_MASK
	vpshufb %%CTRL1, %%ZMM_SHUF_MASK
	vpshufb %%CTRL2, %%ZMM_SHUF_MASK
	vpshufb %%CTRL3, %%ZMM_SHUF_MASK

%%_encrypt_done_x4:
        GHASH_LAST_8x4  %%KPTR0, %%KPTR1, %%KPTR2, %%KPTR3, \
                        %%L0B03, %%L0B47, %%L1B03, %%L1B47, \
                        %%L2B03, %%L2B47, %%L3B03, %%L3B47, \
                        %%GHASH, \
                        %%T1, %%T2, %%T3, %%T4, %%T5, %%T6, \
                        %%T7, %%T8, %%T9, %%T10, %%T11, %%T12

%%_ghash_done_x4:
        mov     %%TPTR0, [%%GDATA_CTX + (0*8)]
        mov     %%TPTR1, [%%GDATA_CTX + (1*8)]
        mov     %%TPTR2, [%%GDATA_CTX + (2*8)]
        mov     %%TPTR3, [%%GDATA_CTX + (3*8)]

        ;; save current counter blocks
        vextracti32x4   [%%TPTR0 + CurCount], %%CTRL0, 3
        vextracti32x4   [%%TPTR1 + CurCount], %%CTRL1, 3
        vextracti32x4   [%%TPTR2 + CurCount], %%CTRL2, 3
        vextracti32x4   [%%TPTR3 + CurCount], %%CTRL3, 3

        ;; save current hash values
        vmovdqu64       [%%TPTR0 + AadHash], XWORD(%%GHASH)
        vextracti64x2   [%%TPTR1 + AadHash], %%GHASH, 1
        vextracti64x2   [%%TPTR2 + AadHash], %%GHASH, 2
        vextracti64x2   [%%TPTR3 + AadHash], %%GHASH, 3

        ;; decrement lens
        ;; increment the input / output pointers
        ;; - output and input pointers are next to one another in the structure
        ;;   so updating all 8 pointers with a single zmm
        vpbroadcastq    %%T1, %%DATA_OFFSET     ; DATA_OFFSET should be equal to length
        vpaddq          %%T2, %%T1, [%%CYPH_PLAIN_OUT]
        vmovdqu64       [%%CYPH_PLAIN_OUT], %%T2
        vmovdqu64       YWORD(%%T3), [%%STATE + _gcm_lens]
        vpsubq          YWORD(%%T3), YWORD(%%T3), YWORD(%%T1)
        vmovdqu64       [%%STATE + _gcm_lens], YWORD(%%T3)

%%_enc_dec_done_x4:


%endmacro                       ; GCM_ENC_DEC_4x128

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_COMPLETE_x4 - completes one of MB jobs
;;; Clobbers rax, r9-r12, r14, r15 and zmm0-zmm31
;;; ===========================================================================
%macro  GCM_COMPLETE_x4         3
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%IDX                   %2 ; [in] lane index to be completed
%define %%ENC_DEC               %3

%ifidn __OUTPUT_FORMAT__, win64
%define %%GDATA_KEY             rdi
%define %%GDATA_CTX             rsi
%define %%CYPH_PLAIN_OUT        r11
%define %%PLAIN_CYPH_IN         r9
%else
%define %%GDATA_KEY             arg3
%define %%GDATA_CTX             arg4
%define %%CYPH_PLAIN_OUT        r8
%define %%PLAIN_CYPH_IN         r9
%endif


%define %%PLAIN_CYPH_LEN        rbp
%define %%AUTH_TAG              rbp
%define %%AUTH_TAGLEN           rbp

%define %%GPR                   rax

%define %%DATA_OFFSET           rbx

        mov             %%PLAIN_CYPH_LEN, [%%STATE + _gcm_lens + %%IDX*8]
        mov             %%GDATA_KEY, [%%STATE + _gcm_args_keys + %%IDX*8]
        mov             %%GDATA_CTX, [%%STATE + _gcm_args_ctx + %%IDX*8]
        mov             %%PLAIN_CYPH_IN, [%%STATE + _gcm_args_in + %%IDX*8]
        mov             %%CYPH_PLAIN_OUT, [%%STATE + _gcm_args_out + %%IDX*8]

        vmovdqu64       xmm16, [%%GDATA_KEY + HashKey]
        vmovdqu64       xmm17, [%%GDATA_CTX + AadHash]

;;; ===========================================================================
;;; finalize last blocks (<128 bytes)

;;; Macro flow:
;;; calculate the number of 16byte blocks in the message
;;; process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
;;; process 8 16 byte blocks at a time until all are done '%%_encrypt_by_8_new .. %%_eight_cipher_left'
;;; if there is a block of less tahn 16 bytes process it '%%_zero_cipher_left .. %%_multiple_of_16_bytes'

        or      %%PLAIN_CYPH_LEN, %%PLAIN_CYPH_LEN
        je      %%_enc_dec_done_x4

        xor     %%DATA_OFFSET, %%DATA_OFFSET

        ;; Update length of data processed
        add    [%%GDATA_CTX + InLen], %%PLAIN_CYPH_LEN

        vmovdqa64       xmm13, xmm16    ; load HashKey
        vmovdqu         xmm9, [%%GDATA_CTX + CurCount]

        ;; Save the amount of data left to process in r10
        mov     r13, %%PLAIN_CYPH_LEN

        ;; Determine how many blocks to process in INITIAL
        ;; - round up number of blocks for INITIAL in case of partial block
        mov     r12, %%PLAIN_CYPH_LEN
        add     r12, 15
        shr     r12, 4

        GCM_ENC_DEC_SMALL %%GDATA_KEY, %%GDATA_CTX, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%PLAIN_CYPH_LEN, %%ENC_DEC, %%DATA_OFFSET, \
                r13, r12, xmm9, xmm17, single_call, \
                zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, zmm24, zmm25, zmm26, %%GPR, r15, k1

%%_ghash_done_x4:
        vmovdqu         [%%GDATA_CTX + CurCount], xmm9  ; current_counter = xmm9

%%_enc_dec_done_x4:
;;; ===========================================================================
;;; COMPLETE

        ;; Start AES as early as possible
        vmovdqu64       xmm9, [%%GDATA_CTX + OrigIV]    ; xmm9 = Y0
        ENCRYPT_SINGLE_BLOCK %%GDATA_KEY, xmm9  ; E(K, Y0)

        ;; If the GCM function is called as a single function call rather
        ;; than invoking the individual parts (init, update, finalize) we
        ;; can remove a write to read dependency on AadHash.
        vmovdqa64       xmm14, xmm17    ; xmm14 = AadHash
        vmovdqa64       xmm13, xmm16    ; load HashKey

%%_partial_done_x4:
        mov             %%GPR, [%%GDATA_CTX + AadLen]    ; aadLen (number of bytes)
        shl             %%GPR, 3                         ; convert into number of bits
        vmovd           xmm15, DWORD(%%GPR)              ; len(A) in xmm15

        mov             %%GPR, [%%GDATA_CTX + InLen]
        shl             %%GPR, 3                         ; len(C) in bits  (*128)
        vmovq           xmm1, %%GPR
        vpslldq         xmm15, xmm15, 8                  ; xmm15 = len(A)|| 0x0000000000000000
        vpor            xmm15, xmm15, xmm1               ; xmm15 = len(A)||len(C)

        ;; prep auth_tag store mask
        mov             %%AUTH_TAGLEN, [%%STATE + _gcm_args_taglen + %%IDX*8]
        lea             %%GPR, [rel byte_len_to_mask_table]
        kmovw           k1, [%%GPR + %%AUTH_TAGLEN*2]
        mov             %%AUTH_TAG, [%%STATE + _gcm_args_tag + %%IDX*8]

        ;; XOR current hash value with the next block xmm15
        vpxorq          xmm14, xmm15

        ;; xmm14: hash value [in/out]
        ;; xmm13: hash key [in]
        ;; xmm0, xmm10, xmm11, xmm5, xmm6 - temporary registers
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6
        vpshufb         xmm14, [rel SHUF_MASK]         ; perform a 16Byte swap

        vpxorq          xmm9, xmm9, xmm14

%%_return_T:
        vmovdqu8        [%%AUTH_TAG]{k1}, xmm9         ; store TAG
	vmovdqu64       [%%GDATA_CTX + AadHash], xmm17 ; store AadHash

        ;; put the lane back on free list
        mov             rax, [%%STATE + _gcm_unused_lanes]
        shl             rax, 4
        or              rax, %%IDX
        mov             [%%STATE + _gcm_unused_lanes], rax

        ;; mark job as complete
        mov             rax, [%%STATE + _gcm_job_in_lane + 8*%%IDX]
        or              dword [rax + _status], STS_COMPLETED
        ;; clear job pointer in this lane
        mov             qword [%%STATE + _gcm_job_in_lane + 8*%%IDX], 0
        ;; return finished job (rax)
%%_return_T_done:
%endmacro ; GCM_COMPLETE_x4


;;; ===========================================================================
;;; ===========================================================================
;;; GCM_FINALIZE_x4:
;;; - runs all lanes in parallel for %LEN
;;; - completes slected lane (any outstanding bytes < 128 bytes)
;;; - returns pointer of completed JOB
;;; Clobbers rax, r9-r12, r14, r15 and zmm0-zmm31
;;; ===========================================================================
%macro  GCM_FINALIZE_x4         4
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%IDX                   %2 ; [in] lane index to be completed
%define %%LEN                   %3 ; [in] common length to be prcessed across all lanes
%define %%ENC_DEC               %4

%%_gcm_finalize_4x128:
        ;;  save %IDX as it will get clobbered
        mov     [rsp + STACK_LOCAL_OFFSET + 0*8], %%IDX
        and     %%LEN, -128
        mov     arg2, %%LEN
        GCM_ENC_DEC_4x128 %%STATE, arg2, %%ENC_DEC

%%_gcm_complete_min_lane:
        ;;  restore %%IDX
        mov     arg2, [rsp + STACK_LOCAL_OFFSET + 0*8]
        GCM_COMPLETE_x4 %%STATE, arg2, %%ENC_DEC
%endmacro ; GCM_FINALIZE_x4
;;; ===========================================================================

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_FLUSH_MB:
;;; - finds min not null lane
;;; - replicates non_null data across null lanes
;;; - returns min length lane index and length
;;; ===========================================================================
%macro  GCM_FLUSH_MB 3
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%IDX                   %2 ; [out] lane index to be completed
%define %%LEN                   %3 ; [out] common length to be prcessed across all lanes

        ;; put max length into null lanes
        vmovdqu64       ymm0, [%%STATE + _gcm_job_in_lane]
        vpxorq          ymm1, ymm1
        vpcmpq          k2, ymm0, ymm1, 0 ; EQ

        kmovq           rax, k2           ; k2 = mask for null lanes
        xor             rax, 0xf
        kmovq           k1, rax           ; k1 = mask for not null lanes (~k2)

        vmovdqu64       ymm2, [%%STATE + _gcm_lens]
        vbroadcastf64x2 ymm4, [rel ALL_F]
        vporq           ymm2{k2}, ymm2, ymm4

        ;; find min lane & index
        vpsllq          ymm3, ymm2, 2 ;
        vporq           ymm3, ymm3, [rel index_to_lane4]
        vextracti32x4   xmm2, ymm3, 1
        vpminuq         xmm2, xmm3, xmm2
        vpsrldq         xmm3, xmm2, 8
        vpminuq         xmm2, xmm3, xmm2
        vmovq           %%LEN, xmm2
        mov             %%IDX, %%LEN
        and             %%IDX, 3
        shr             %%LEN, 2
        ;; At this stage:
        ;;   %%LEN - min length
        ;;   %%IDX - lane index

        ;; load context structure content from the non-null lane
        ;; it is 88 bytes long (64 + 24)
        ;; zmm7:ymm11
        mov             rax, 0x7
        kmovq           k3, rax
        mov             r10, [%%STATE + _gcm_args_ctx + 8*%%IDX]
        vmovdqu64       zmm7, [r10]
        vmovdqu64       ymm11{k3}, [r10 + 64]

        vmovdqu64       ymm7, [%%STATE + _gcm_args_in]
        vmovdqu64       ymm8, [%%STATE + _gcm_args_out]
        vmovdqu64       ymm9, [%%STATE + _gcm_args_keys]
        mov             r10, [%%STATE + _gcm_args_in + 8*%%IDX]
        mov             r11, [%%STATE + _gcm_args_out + 8*%%IDX]
        mov             r12, [%%STATE + _gcm_args_keys + 8*%%IDX]
        ;; r10 = (min lane) valid in ptr
        ;; r11 = (min lane) valid out ptr
        ;; r12 = (min lane) valid keys ptr

        ;; store valid in/out/key pointers to empty lanes
        vpbroadcastq    ymm4, r10
        vpbroadcastq    ymm5, r11
        vpbroadcastq    ymm6, r12

        vmovdqa64       ymm4{k1}, ymm7
        vmovdqa64       ymm5{k1}, ymm8
        vmovdqa64       ymm6{k1}, ymm9

        vmovdqu64       [%%STATE + _gcm_args_in], ymm4
        vmovdqu64       [%%STATE + _gcm_args_out], ymm5
        vmovdqu64       [%%STATE + _gcm_args_keys], ymm6

        ;; copy valid context into empty lanes
        kmovq           rax, k2 ; null lane mask to rax
        test            rax, 1
        jz              %%_copy_ctx_lane1
        mov             r10, [%%STATE + _gcm_args_ctx + 8*0]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_lane1:
        test            rax, 2
        jz              %%_copy_ctx_lane2
        mov             r10, [%%STATE + _gcm_args_ctx + 8*1]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_lane2:
        test            rax, 4
        jz              %%_copy_ctx_lane3
        mov             r10, [%%STATE + _gcm_args_ctx + 8*2]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_lane3:
        test            rax, 8
        jz              %%_copy_ctx_end
        mov             r10, [%%STATE + _gcm_args_ctx + 8*3]
        vmovdqu64       [r10], zmm7
        vmovdqu64       [r10 + 64]{k3}, ymm11
%%_copy_ctx_end:

%endmacro ; GCM_FLUSH_MB
;;; ===========================================================================

;;; ===========================================================================
;;; ===========================================================================
;;; GCM_SUBMIT_MB:
;;; - finds free lane and populates it with data from JOB
;;; - if all lanes populated then finds min common length
;;; - returns min length lane index and size
;;; ===========================================================================
%macro  GCM_SUBMIT_MB 4
%define %%STATE                 %1 ; [in] pointer to an array with 4 pointers to expanded key
%define %%JOB                   %2 ; [in] lane index to be completed / [out] index
%define %%LEN                   %3 ; [out] common length to be prcessed across all lanes
%define %%ENC_DEC               %4 ; [in] encrypt / decrypt selector

%define %%IDX       rbp
%define %%RET_IDX   %%JOB
%ifidn __OUTPUT_FORMAT__, win64
%define %%LCTX      rdi
%else
%define %%LCTX      r8
%endif
        ;; get free lane
        mov             rbx, [%%STATE + _gcm_unused_lanes]
        mov             %%IDX, rbx
        shr             rbx, 4
        and             %%IDX, 0xf
        mov             [%%STATE + _gcm_unused_lanes], rbx

        ;; copy job data into the lane
        mov             [%%STATE + _gcm_job_in_lane + 8*%%IDX], %%JOB

        mov             r9, [%%JOB + _aes_enc_key_expanded]
        mov             [%%STATE + _gcm_args_keys + 8*%%IDX], r9

        mov             rax, [%%JOB + _src]
        add             rax, [%%JOB + _cipher_start_src_offset_in_bytes]
        mov             [%%STATE + _gcm_args_in + 8*%%IDX], rax

        mov             rax, [%%JOB + _dst]
        mov             [%%STATE + _gcm_args_out + 8*%%IDX], rax

        mov             rax, [%%JOB + _auth_tag_output]
        mov             [%%STATE + _gcm_args_tag + 8*%%IDX], rax

        mov             rax, [%%JOB + _auth_tag_output_len_in_bytes]
        mov             [%%STATE + _gcm_args_taglen + 8*%%IDX], rax

        vpbroadcastq    ymm15, [%%JOB + _msg_len_to_cipher_in_bytes]

        lea             rax, [rel index_to_lane4_mask]
        kmovw           k2, [rax + (index_to_lane4_not_mask - index_to_lane4_mask) + %%IDX*2]
        kmovw           k1, [rax + %%IDX*2]
        vmovdqu64       ymm14{k2}{z}, [%%STATE + _gcm_lens]
        vporq           ymm14{k1}, ymm14, ymm15
        vmovdqu64       [%%STATE + _gcm_lens], ymm14
        vmovdqu64       ymm31, ymm14

        ;; call gcm_init
        mov             r13, [%%JOB + _iv]
        mov             r14, [%%JOB + _gcm_aad]
        mov             rax, [%%JOB + _gcm_aad_len]
        mov             %%LCTX, [%%STATE + _gcm_args_ctx + 8*%%IDX]

        ;; GDATA_KEY     %1
        ;; GDATA_CTX     %2
        ;; IV            %3
        ;; A_IN          %4
        ;; A_LEN         %5
        ;; r10-r12 - temporary GPR's
        GCM_INIT        r9, %%LCTX, r13, r14, rax, r10, r11, r12, k1, xmm14, xmm2, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10

        ;; check if all lanes populated
        cmp             rbx, 0xf
        je              %%_gcm_ooo_ready
%%_gcm_ooo_not_ready:
        xor             rax, rax ; return NULL
        jmp             %%_gcm_submit_return

%%_gcm_ooo_ready:
        ;; find min lane & index
        vpsllq          ymm2, ymm31, 2 ;
        vporq           ymm2, ymm2, [rel index_to_lane4]
        vextracti32x4   xmm3, ymm2, 1
        vpminuq         xmm2, xmm3, xmm2
        vpsrldq         xmm3, xmm2, 8
        vpminuq         xmm2, xmm3, xmm2
        vmovq           %%LEN, xmm2
        mov             %%RET_IDX, %%LEN
        and             %%RET_IDX, 3
        shr             %%LEN, 2
        ;; At this stage:
        ;;   %%LEN - min length
        ;;   %%RET_IDX - lane index

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
%%_gcm_ooo_run:
        GCM_FINALIZE_x4 arg1, arg2, arg3, %%ENC_DEC
        ;; rax = finished job pointer
%%_gcm_submit_return:

%endmacro ; GCM_SUBMIT_MB
;;; ===========================================================================

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_enc_128_submit_vaes_avx512 / aes_gcm_enc_192_submit_vaes_avx512 /
;       aes_gcm_enc_256_submit_vaes_avx512
;       (MB_MGR_GCM_OOO *state, JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_submit_),function,internal)
FN_NAME(enc,_submit_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [in] job / [out] index
        ;; arg3 - [out] length
        GCM_SUBMIT_MB arg1, arg2, arg3, ENC
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_enc_128_flush_vaes_avx512 / aes_gcm_enc_192_flush_vaes_avx512 /
;       aes_gcm_enc_256_flush_vaes_avx512
;       (MB_MGR_GCM_OOO *state)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(enc,_flush_),function,internal)
FN_NAME(enc,_flush_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [out] index
        ;; arg3 - [out] length
        GCM_FLUSH_MB arg1, arg2, arg3

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
        GCM_FINALIZE_x4 arg1, arg2, arg3, ENC
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_dec_128_submit_vaes_avx512 / aes_gcm_dec_192_submit_vaes_avx512 /
;       aes_gcm_dec_256_submit_vaes_avx512
;       (MB_MGR_GCM_OOO *state, JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_submit_),function,internal)
FN_NAME(dec,_submit_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [in] job / [out] index
        ;; arg3 - [out] length
        GCM_SUBMIT_MB arg1, arg2, arg3, DEC
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;JOB_AES_HMAC *aes_gcm_dec_128_flush_vaes_avx512 / aes_gcm_dec_192_flush_vaes_avx512 /
;       aes_gcm_dec_256_flush_vaes_avx512
;       (MB_MGR_GCM_OOO *state)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(FN_NAME(dec,_flush_),function,internal)
FN_NAME(dec,_flush_):
        FUNC_SAVE
        ;; arg1 - [in] state
        ;; arg2 - [out] index
        ;; arg3 - [out] length
        GCM_FLUSH_MB arg1, arg2, arg3

        ;; finalize puts returned job into RAX
        ;; arg1 - state
        ;; arg2 - min_lane_idx
        ;; arg3 - min_len
        GCM_FINALIZE_x4 arg1, arg2, arg3, DEC

        FUNC_RESTORE
        ret


%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
