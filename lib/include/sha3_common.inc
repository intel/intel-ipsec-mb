; Copyright (c) 2026,  Intel Corporation.
; All rights reserved.
;
; SPDX-License-Identifier: BSD-3-Clause

%ifdef LINUX
;; SYSV x64 calling convention
%define arg1  rdi
%define arg2  rsi
%define arg3  rdx
%define arg4  rcx

%else
;; Windows x64 calling convention

%define arg1  rcx
%define arg2  rdx
%define arg3  r8
%define arg4  r9

%endif

;; SHA3 rates
%define SHA3_224_RATE 144
%define SHA3_256_RATE 136
%define SHA3_384_RATE 104
%define SHA3_512_RATE 72
%define SHAKE128_RATE 168
%define SHAKE256_RATE 136

;; SHA3 digest sizes
%define SHA3_224_DIGEST_SZ 28
%define SHA3_256_DIGEST_SZ 32
%define SHA3_384_DIGEST_SZ 48
%define SHA3_512_DIGEST_SZ 64

;; SHA3 multi-rate padding byte (added after the message)
%define SHA3_MRATE_PADDING  0x06
%define SHAKE_MRATE_PADDING 0x1F

%define APPEND(a,b) a %+ b

;; ---------------------------------------------------------------------------
;; Multi-buffer Keccak per-algorithm parameters
;;
;; The multi-buffer submit routines derive the sponge rate and the domain
;; separation byte from IMB_JOB::hash_alg, so they need the numeric value of
;; the first of the six consecutive Keccak entries of the IMB_HASH_ALG
;; enumeration in lib/intel-ipsec-mb.h.  Keep this in step with that header;
;; a mismatch selects the wrong rate and is caught immediately by the SHA3
;; known answer tests and by the library self-test.
;; ---------------------------------------------------------------------------
%define SHA3_MB_ALG_FIRST       47      ; IMB_AUTH_SHA3_224

;; Everything the multi-buffer code needs to know about an algorithm, one byte
;; per algorithm, with SHA3-224 in the least significant byte.  Each byte holds
;; that algorithm's rate, which is below 256 and always a multiple of eight, so
;; the three low bits are free; bit 0 carries the only other property that
;; varies, whether the algorithm is an extendable output function and so which
;; domain separation byte it appends.
;;
;; Indexing this with the algorithm number turns the parameters into immediate
;; arithmetic, so no lookup table and no relocation are needed.
%define SHA3_MB_PARAMS_PACKED \
        (SHA3_224_RATE | (SHA3_256_RATE << 8) | (SHA3_384_RATE << 16) | \
        (SHA3_512_RATE << 24) | ((SHAKE128_RATE | 1) << 32) | \
        ((SHAKE256_RATE | 1) << 40))

;; Reads the parameters of the job's algorithm and records them in the lane.
;; Sets rate[], pad[], lens[] and blocks[] of lane %%LANE.
;;
;; Clobbers RAX, RCX, RDX and %%T1.
%macro SHA3_MB_SET_LANE_PARAMS 4
%define %%STATE %1              ; MB_MGR_SHA3_OOO pointer
%define %%JOB   %2              ; IMB_JOB pointer
%define %%LANE  %3              ; lane index
%define %%T1    %4              ; temporary GP register

        mov     eax, [%%JOB + _hash_alg]
        sub     eax, SHA3_MB_ALG_FIRST          ; 0 .. 5 (number of algorithms)
        lea     ecx, [rax*8]                    ; bit position of this entry

        mov     %%T1, SHA3_MB_PARAMS_PACKED
        shr     %%T1, cl
        movzx   %%T1, BYTE(%%T1)                ; rate, with the XOF flag in bit 0

        mov     edx, SHA3_MRATE_PADDING
        mov     ecx, SHAKE_MRATE_PADDING
        test    %%T1, 1
        cmovnz  edx, ecx
        mov     [%%STATE + _sha3_args_pad + %%LANE*8], rdx

        and     %%T1, -8
        mov     [%%STATE + _sha3_args_rate + %%LANE*8], %%T1

        ;; blocks = msg_len / rate.  The per-algorithm rate is nonzero and is
        ;; expressed in bytes, matching msg_len_to_hash_in_bytes.
        mov     rax, [%%JOB + _msg_len_to_hash_in_bytes]
        mov     [%%STATE + _sha3_lens + %%LANE*8], rax
        xor     edx, edx
        div     %%T1
        mov     [%%STATE + _sha3_blocks + %%LANE*8], rax
%endmacro

;; Absorb input bytes into state registers (AVX512 ISA)
%macro ABSORB_BYTES 3
%define %%INPUT         %1
%define %%OFFSET        %2
%define %%RATE          %3

        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*0]
        vpxorq  ymm0, ymm0, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*1]
        vpxorq  ymm1, ymm1, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*2]
        vpxorq  ymm2, ymm2, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*3]
        vpxorq  ymm3, ymm3, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*4]
        vpxorq  ymm4, ymm4, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*5]
        vpxorq  ymm5, ymm5, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*6]
        vpxorq  ymm6, ymm6, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*7]
        vpxorq  ymm7, ymm7, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*8]
        vpxorq  ymm8, ymm8, ymm31
        ;; SHA3_512 RATE, 72 bytes

%if %%RATE > SHA3_512_RATE
        ;; SHA3_384 RATE
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*9]
        vpxorq  ymm9, ymm9, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*10]
        vpxorq  ymm10, ymm10, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*11]
        vpxorq  ymm11, ymm11, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*12]
        vpxorq  ymm12, ymm12, ymm31
%endif
%if %%RATE > SHA3_384_RATE
        ;; SHA3_256 and SHAKE256 RATE
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*13]
        vpxorq  ymm13, ymm13, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*14]
        vpxorq  ymm14, ymm14, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*15]
        vpxorq  ymm15, ymm15, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*16]
        vpxorq  ymm16, ymm16, ymm31
%endif
%if %%RATE > SHA3_256_RATE
        ;; SHA3_224 RATE - qword 17
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*17]
        vpxorq  ymm17, ymm17, ymm31
%endif
%if %%RATE > SHA3_224_RATE
        ;; SHAKE128 RATE - qwords 18-20
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*18]
        vpxorq  ymm18, ymm18, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*19]
        vpxorq  ymm19, ymm19, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*20]
        vpxorq  ymm20, ymm20, ymm31
%endif
%endmacro

;; Store state from SIMD registers to memory (AVX512 ISA)
;; State registers are kept in xmm0-xmm24
%macro STATE_EXTRACT 3
%define %%OUTPUT        %1      ; [in] destination pointer
%define %%OFFSET        %2      ; [in] destination offset
%define %%N             %3      ; [in] numerical values, number of 8-byte state registers to save

%assign I 0
%rep %%N
        vmovq   [%%OUTPUT + %%OFFSET + 8*I], APPEND(xmm, I)
%assign I (I + 1)
%endrep
%endmacro
