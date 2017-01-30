;;
;; Copyright (c) 2012-2016, Intel Corporation
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

;
; Authors: 
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford
;
;
; References:
;       This code was derived and highly optimized from the code described in paper:
;               Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation on Intel Architecture Processors. August, 2010
;       
;       For the shift-based reductions used in this code, we used the method described in paper:
;               Shay Gueron, Michael E. Kounavis. Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode. January, 2010.
;
; Example YASM command lines:
;       Windows:  yasm -Xvc -f x64 -rnasm -pnasm -D "WIN_ABI" -o aesni_gcm_enc_avx_2nd_gen_core_mainfunc.obj -g cv8 aesni_gcm_enc_avx_2nd_gen_core_mainfunc.asm
;       Linux:    yasm -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o aesni_gcm_enc_avx_2nd_gen_core_mainfunc.o aesni_gcm_enc_avx_2nd_gen_core_mainfunc.asm
;
;
;
; Assumptions:
;
;
;
; iv:
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                             Salt  (From the SA)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     Initialization Vector                     |
;       |         (This is the sequence number from IPSec header)       |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x1                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;
;
; AAD:
;       AAD padded to 128 bits with 0
;       for example, assume AAD is a u32 vector
;
;       if AAD is 8 bytes:
;       AAD[3] = {A0, A1};
;       padded AAD in xmm register = {A1 A0 0 0}
;
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                               SPI (A1)                        |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     32-bit Sequence Number (A0)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x0                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;                                       AAD Format with 32-bit Sequence Number
;
;       if AAD is 12 bytes:
;       AAD[3] = {A0, A1, A2};
;       padded AAD in xmm register = {A2 A1 A0 0}
;
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                               SPI (A2)                        |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                 64-bit Extended Sequence Number {A1,A0}       |
;       |                                                               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x0                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
;        AAD Format with 64-bit Extended Sequence Number
;
;
; aadLen:
;       from the definition of the spec, aadLen can only be 8 or 12 bytes. The code additionally supports aadLen of length 16 bytes.
;
; TLen:
;       from the definition of the spec, TLen can only be 8, 12 or 16 bytes.
;
; poly = x^128 + x^127 + x^126 + x^121 + 1
; throughout the code, one tab and two tab indentations are used. one tab is for GHASH part, two tabs is for AES part.
;


%include "gcm_defines.asm"

; need to push 4 registers into stack to maintain
%define STACK_OFFSET 8*4

%define TMP1    16*0      ; Temporary storage for AAD
%define TMP2    16*1    ; Temporary storage for AES State 2 (State 1 is stored in an XMM register)
%define TMP3    16*2    ; Temporary storage for AES State 3
%define TMP4    16*3    ; Temporary storage for AES State 4
%define TMP5    16*4    ; Temporary storage for AES State 5
%define TMP6    16*5    ; Temporary storage for AES State 6
%define TMP7    16*6    ; Temporary storage for AES State 7
%define TMP8    16*7    ; Temporary storage for AES State 8


%ifndef LINUX
        %define XMM_SAVE 16*8
        %define VARIABLE_OFFSET 16*18
%else
        %define VARIABLE_OFFSET 16*8
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Utility Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; GHASH_MUL MACRO to implement: Data*HashKey mod (128,127,126,121,0)
; Input: A and B (128-bits each, bit-reflected)
; Output: C = A*B*x mod poly, (i.e. >>1 )
; To compute GH = GH*HashKey mod poly, give HK = HashKey<<1 mod poly as input
; GH = GH * HK * x mod poly which is equivalent to GH*HashKey mod poly.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  GHASH_MUL  7
%define %%GH %1         ; 16 Bytes
%define %%HK %2         ; 16 Bytes
%define %%T1 %3
%define %%T2 %4
%define %%T3 %5
%define %%T4 %6
%define %%T5 %7
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; Karatsuba    
        vpshufd         %%T2, %%GH, 01001110b
        vpshufd         %%T3, %%HK, 01001110b
        vpxor           %%T2, %%T2, %%GH                ; %%T2 = (a1+a0)
        vpxor           %%T3, %%T3, %%HK                ; %%T3 = (b1+b0)

        vpclmulqdq      %%T1, %%GH, %%HK, 0x11          ; %%T1 = a1*b1
        vpclmulqdq      %%GH, %%HK, 0x00                ; %%GH = a0*b0
        vpclmulqdq      %%T2, %%T3, 0x00                ; %%T2 = (a1+a0)*(b1+b0)
        vpxor           %%T2, %%T2, %%GH
        vpxor           %%T2, %%T2, %%T1                ; %%T2 = a0*b1+a1*b0

        vpslldq         %%T3, %%T2, 8                   ; shift-L %%T3 2 DWs
        vpsrldq         %%T2, %%T2, 8                   ; shift-R %%T2 2 DWs
        vpxor           %%GH, %%GH, %%T3
        vpxor           %%T1, %%T1, %%T2                ; <%%T1:%%GH> = %%GH x %%HK

        ;first phase of the reduction
        vpslld  %%T2, %%GH, 31                          ; packed right shifting << 31
        vpslld  %%T3, %%GH, 30                          ; packed right shifting shift << 30
        vpslld  %%T4, %%GH, 25                          ; packed right shifting shift << 25
        
        vpxor   %%T2, %%T2, %%T3                        ; xor the shifted versions
        vpxor   %%T2, %%T2, %%T4
        
        vpsrldq %%T5, %%T2, 4                           ; shift-R %%T5 1 DW
        
        vpslldq %%T2, %%T2, 12                          ; shift-L %%T2 3 DWs    
        vpxor   %%GH, %%GH, %%T2                        ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;second phase of the reduction

        vpsrld  %%T2,%%GH,1                             ; packed left shifting >> 1
        vpsrld  %%T3,%%GH,2                             ; packed left shifting >> 2
        vpsrld  %%T4,%%GH,7                             ; packed left shifting >> 7
        vpxor   %%T2, %%T2, %%T3                        ; xor the shifted versions
        vpxor   %%T2, %%T2, %%T4
        
        vpxor   %%T2, %%T2, %%T5
        vpxor   %%GH, %%GH, %%T2        
        vpxor   %%GH, %%GH, %%T1                        ; the result is in %%GH

                        
%endmacro


%macro PRECOMPUTE 7
%define %%HK    %1
%define %%T1    %2
%define %%T2    %3
%define %%T3    %4
%define %%T4    %5
%define %%T5    %6
%define %%T6    %7

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Haskey_i_k holds XORed values of the low and high parts of the Haskey_i
        vmovdqa  %%T5, %%HK

        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_k], %%T1  

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^2<<1 mod poly
        vmovdqa  [arg1 + HashKey_2], %%T5                       ;  [HashKey_2] = HashKey^2<<1 mod poly
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_2_k], %%T1  

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^3<<1 mod poly
        vmovdqa  [arg1 + HashKey_3], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_3_k], %%T1  

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^4<<1 mod poly
        vmovdqa  [arg1 + HashKey_4], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_4_k], %%T1  

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^5<<1 mod poly
        vmovdqa  [arg1 + HashKey_5], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_5_k], %%T1  

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^6<<1 mod poly
        vmovdqa  [arg1 + HashKey_6], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_6_k], %%T1  

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^7<<1 mod poly
        vmovdqa  [arg1 + HashKey_7], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_7_k], %%T1  

        GHASH_MUL %%T5, %%HK, %%T1, %%T3, %%T4, %%T6, %%T2      ;  %%T5 = HashKey^8<<1 mod poly
        vmovdqa  [arg1 + HashKey_8], %%T5
        vpshufd  %%T1, %%T5, 01001110b
        vpxor    %%T1, %%T5
        vmovdqa  [arg1 + HashKey_8_k], %%T1   
%endmacro

; if a = number of total plaintext bytes
; b = floor(a/16)
; %%num_initial_blocks = b mod 4;
; encrypt the initial %%num_initial_blocks blocks and apply ghash on the ciphertext
; r10, r11, r12, rax are clobbered
; arg1, arg2, arg3, r14 are used as a pointer only, not modified

%macro INITIAL_BLOCKS 18
%define %%num_initial_blocks    %1      ; can be 0, 1, 2, 3, 4, 5, 6 or 7
%define %%T1    %2
%define %%T2    %3
%define %%T3    %4
%define %%T4    %5
%define %%T5    %6

%define %%CTR  %7
%define %%XMM1  %8
%define %%XMM2  %9
%define %%XMM3  %10
%define %%XMM4  %11
%define %%XMM5  %12
%define %%XMM6  %13
%define %%XMM7  %14
%define %%XMM8  %15
%define %%T6    %16
%define %%T_key %17
%define %%ENC_DEC       %18
%assign i       (8-%%num_initial_blocks)        
        
        mov     r10, arg6                       ; r10 = AAD
        mov     r12, arg7                       ; r12 = aadLen  
        

        mov     r11, r12
                
        vpxor    reg(i), reg(i)
%%_get_AAD_loop:
        vmovd    %%T1, DWORD [r10]
        vpslldq %%T1, %%T1, 12
        vpsrldq reg(i), reg(i), 4
        vpxor   reg(i), reg(i), %%T1
        
        add     r10, 4  
        sub     r12, 4
        jg     %%_get_AAD_loop
        
        
        cmp     r11, 16
        je      %%_get_AAD_loop2_done
        mov     r12, 16
        
%%_get_AAD_loop2:       
        vpsrldq reg(i), reg(i), 4
        sub     r12, 4
        cmp     r12, r11
        jg     %%_get_AAD_loop2
        
%%_get_AAD_loop2_done:  

        ;byte-reflect the AAD data
        vpshufb  reg(i), [rel SHUF_MASK]
                
                ; initialize the data pointer offset as zero
                xor     r11, r11
                
                ; start AES for %%num_initial_blocks blocks
                mov     rax, arg5                       ; rax = *Y0
                vmovdqu  %%CTR, [rax]                   ; %%CTR = Y0
                vpshufb  %%CTR, [rel SHUF_MASK]
                
                
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vpaddd   %%CTR, [rel ONE]           ; INCR Y0
                vmovdqa  reg(i), %%CTR
                vpshufb  reg(i), [rel SHUF_MASK]     ; perform a 16Byte swap
%assign i (i+1)
%endrep

vmovdqa  %%T_key, [arg1+16*0]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vpxor    reg(i),%%T_key
%assign i (i+1)
%endrep

%assign j 1
%rep 13
vmovdqa  %%T_key, [arg1+16*j]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenc  reg(i),%%T_key
%assign i (i+1)
%endrep 

%assign j (j+1)
%endrep 


vmovdqa  %%T_key, [arg1+16*j]
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vaesenclast      reg(i),%%T_key
%assign i (i+1)
%endrep 
        
%assign i (9-%%num_initial_blocks)
%rep %%num_initial_blocks
                vmovdqu  %%T1, [arg3 + r11]
                vpxor    reg(i), %%T1
                vmovdqu  [arg2 + r11], reg(i)            ; write back ciphertext for %%num_initial_blocks blocks
                add     r11, 16
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  reg(i), %%T1
                %endif
                vpshufb  reg(i), [rel SHUF_MASK]     ; prepare ciphertext for GHASH computations
%assign i (i+1)
%endrep
        

%assign i (8-%%num_initial_blocks)
%assign j (9-%%num_initial_blocks)
        GHASH_MUL       reg(i), %%T2, %%T1, %%T3, %%T4, %%T5, %%T6

%rep %%num_initial_blocks
        vpxor    reg(j), reg(i)  
        GHASH_MUL       reg(j), %%T2, %%T1, %%T3, %%T4, %%T5, %%T6      ; apply GHASH on %%num_initial_blocks blocks
%assign i (i+1)
%assign j (j+1)
%endrep 
        ; %%XMM8 has the combined result here

        vmovdqa  [rsp + TMP1], %%XMM8
        vmovdqa  %%T3, %%XMM8
        
        cmp     r13, 128
        jl      %%_initial_blocks_done                  ; no need for precomputed constants

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Haskey_i_k holds XORed values of the low and high parts of the Haskey_i
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM1, %%CTR
                vpshufb  %%XMM1, [rel SHUF_MASK]             ; perform a 16Byte swap
                
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM2, %%CTR
                vpshufb  %%XMM2, [rel SHUF_MASK]             ; perform a 16Byte swap
                
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM3, %%CTR
                vpshufb  %%XMM3, [rel SHUF_MASK]             ; perform a 16Byte swap
                
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM4, %%CTR
                vpshufb  %%XMM4, [rel SHUF_MASK]             ; perform a 16Byte swap
                
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM5, %%CTR
                vpshufb  %%XMM5, [rel SHUF_MASK]             ; perform a 16Byte swap
                
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM6, %%CTR
                vpshufb  %%XMM6, [rel SHUF_MASK]             ; perform a 16Byte swap
                
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM7, %%CTR
                vpshufb  %%XMM7, [rel SHUF_MASK]             ; perform a 16Byte swap
                
                vpaddd   %%CTR, [rel ONE]                   ; INCR Y0
                vmovdqa  %%XMM8, %%CTR
                vpshufb  %%XMM8, [rel SHUF_MASK]             ; perform a 16Byte swap

                vmovdqa  %%T_key, [arg1+16*0]
                vpxor    %%XMM1, %%T_key
                vpxor    %%XMM2, %%T_key
                vpxor    %%XMM3, %%T_key
                vpxor    %%XMM4, %%T_key
                vpxor    %%XMM5, %%T_key
                vpxor    %%XMM6, %%T_key
                vpxor    %%XMM7, %%T_key
                vpxor    %%XMM8, %%T_key
        
        
%assign i 1
%rep    13       ; do 13 rounds
                vmovdqa  %%T_key, [arg1+16*i]
                vaesenc  %%XMM1, %%T_key
                vaesenc  %%XMM2, %%T_key
                vaesenc  %%XMM3, %%T_key
                vaesenc  %%XMM4, %%T_key
                vaesenc  %%XMM5, %%T_key
                vaesenc  %%XMM6, %%T_key
                vaesenc  %%XMM7, %%T_key
                vaesenc  %%XMM8, %%T_key
%assign i (i+1)
%endrep 

        
                vmovdqa          %%T_key, [arg1+16*i]
                vaesenclast      %%XMM1, %%T_key
                vaesenclast      %%XMM2, %%T_key
                vaesenclast      %%XMM3, %%T_key
                vaesenclast      %%XMM4, %%T_key
                vaesenclast      %%XMM5, %%T_key
                vaesenclast      %%XMM6, %%T_key
                vaesenclast      %%XMM7, %%T_key
                vaesenclast      %%XMM8, %%T_key

                vmovdqu  %%T1, [arg3 + r11 + 16*0]
                vpxor    %%XMM1, %%T1
                vmovdqu  [arg2 + r11 + 16*0], %%XMM1
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM1, %%T1
                %endif

                vmovdqu  %%T1, [arg3 + r11 + 16*1]
                vpxor    %%XMM2, %%T1
                vmovdqu  [arg2 + r11 + 16*1], %%XMM2
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM2, %%T1
                %endif

                vmovdqu  %%T1, [arg3 + r11 + 16*2]
                vpxor    %%XMM3, %%T1
                vmovdqu  [arg2 + r11 + 16*2], %%XMM3
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM3, %%T1
                %endif

                vmovdqu  %%T1, [arg3 + r11 + 16*3]
                vpxor    %%XMM4, %%T1
                vmovdqu  [arg2 + r11 + 16*3], %%XMM4
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM4, %%T1
                %endif

                vmovdqu  %%T1, [arg3 + r11 + 16*4]
                vpxor    %%XMM5, %%T1
                vmovdqu  [arg2 + r11 + 16*4], %%XMM5
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM5, %%T1
                %endif

                vmovdqu  %%T1, [arg3 + r11 + 16*5]
                vpxor    %%XMM6, %%T1
                vmovdqu  [arg2 + r11 + 16*5], %%XMM6
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM6, %%T1
                %endif

                vmovdqu  %%T1, [arg3 + r11 + 16*6]
                vpxor    %%XMM7, %%T1
                vmovdqu  [arg2 + r11 + 16*6], %%XMM7
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM7, %%T1
                %endif

                vmovdqu  %%T1, [arg3 + r11 + 16*7]
                vpxor    %%XMM8, %%T1
                vmovdqu  [arg2 + r11 + 16*7], %%XMM8
                %ifidn  %%ENC_DEC, DEC
                vmovdqa  %%XMM8, %%T1
                %endif

                add     r11, 128
                
                vpshufb  %%XMM1, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpxor    %%XMM1, [rsp + TMP1]                    ; combine GHASHed value with the corresponding ciphertext
                vpshufb  %%XMM2, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM3, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM4, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM5, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM6, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM7, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb  %%XMM8, [rel SHUF_MASK]             ; perform a 16Byte swap
        
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;        

%%_initial_blocks_done: 


%endmacro       



; encrypt 8 blocks at a time
; ghash the 8 previously encrypted ciphertext blocks 
; arg1, arg2, arg3 are used as pointers only, not modified
; r11 is the data offset value
%macro GHASH_8_ENCRYPT_8_PARALLEL 18
%define %%T1    %1
%define %%T2    %2
%define %%T3    %3
%define %%T4    %4
%define %%T5    %5
%define %%T6    %6
%define %%CTR  %7
%define %%XMM1  %8
%define %%XMM2  %9
%define %%XMM3  %10
%define %%XMM4  %11
%define %%XMM5  %12
%define %%XMM6  %13
%define %%XMM7  %14
%define %%XMM8  %15
%define %%T7    %16
%define %%loop_idx      %17
%define %%ENC_DEC       %18

        vmovdqa %%T2, %%XMM1
        vmovdqa [rsp + TMP2], %%XMM2
        vmovdqa [rsp + TMP3], %%XMM3
        vmovdqa [rsp + TMP4], %%XMM4
        vmovdqa [rsp + TMP5], %%XMM5
        vmovdqa [rsp + TMP6], %%XMM6
        vmovdqa [rsp + TMP7], %%XMM7
        vmovdqa [rsp + TMP8], %%XMM8
        
%ifidn %%loop_idx, in_order
                vpaddd  %%XMM1, %%CTR,  [rel ONE]           ; INCR CNT
                vpaddd  %%XMM2, %%XMM1, [rel ONE]
                vpaddd  %%XMM3, %%XMM2, [rel ONE]
                vpaddd  %%XMM4, %%XMM3, [rel ONE]
                vpaddd  %%XMM5, %%XMM4, [rel ONE]
                vpaddd  %%XMM6, %%XMM5, [rel ONE]
                vpaddd  %%XMM7, %%XMM6, [rel ONE]
                vpaddd  %%XMM8, %%XMM7, [rel ONE]
                vmovdqa %%CTR, %%XMM8
                
                vpshufb %%XMM1, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM2, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM3, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM4, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM5, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM6, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM7, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM8, [rel SHUF_MASK]             ; perform a 16Byte swap
%else
                vpaddd  %%XMM1, %%CTR,  [rel ONEf]                  ; INCR CNT
                vpaddd  %%XMM2, %%XMM1, [rel ONEf]
                vpaddd  %%XMM3, %%XMM2, [rel ONEf]
                vpaddd  %%XMM4, %%XMM3, [rel ONEf]
                vpaddd  %%XMM5, %%XMM4, [rel ONEf]
                vpaddd  %%XMM6, %%XMM5, [rel ONEf]
                vpaddd  %%XMM7, %%XMM6, [rel ONEf]
                vpaddd  %%XMM8, %%XMM7, [rel ONEf]
                vmovdqa %%CTR, %%XMM8
%endif



        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
                
                vmovdqu %%T1, [arg1 + 16*0]
                vpxor   %%XMM1, %%T1
                vpxor   %%XMM2, %%T1
                vpxor   %%XMM3, %%T1
                vpxor   %%XMM4, %%T1
                vpxor   %%XMM5, %%T1
                vpxor   %%XMM6, %%T1
                vpxor   %%XMM7, %%T1
                vpxor   %%XMM8, %%T1
                 
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        
        

        

                vmovdqu %%T1, [arg1 + 16*1]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1

                        
                vmovdqu %%T1, [arg1 + 16*2]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1 

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        vmovdqa         %%T5, [arg1 + HashKey_8]
        vpclmulqdq      %%T4, %%T2, %%T5, 0x11                  ; %%T4 = a1*b1
        vpclmulqdq      %%T7, %%T2, %%T5, 0x00                  ; %%T7 = a0*b0

        vpshufd         %%T6, %%T2, 01001110b
        vpxor           %%T6, %%T2

        vmovdqa         %%T5, [arg1 + HashKey_8_k]
        vpclmulqdq      %%T6, %%T6, %%T5, 0x00                  ;

                       
                vmovdqu %%T1, [arg1 + 16*3]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1 
        
        vmovdqa         %%T1, [rsp + TMP2]
        vmovdqa         %%T5, [arg1 + HashKey_7]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11                  
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqa         %%T5, [arg1 + HashKey_7_k]                 
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10                  
        vpxor           %%T6, %%T6, %%T3
                                       
                vmovdqu %%T1, [arg1 + 16*4]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1 

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqa         %%T1, [rsp + TMP3]
        vmovdqa         %%T5, [arg1 + HashKey_6]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11                  
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqa         %%T5, [arg1 + HashKey_6_k]                 
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10                  
        vpxor           %%T6, %%T6, %%T3
    
                vmovdqu %%T1, [arg1 + 16*5]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1 
        
        
        vmovdqa         %%T1, [rsp + TMP4]
        vmovdqa         %%T5, [arg1 + HashKey_5]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11                  
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqa         %%T5, [arg1 + HashKey_5_k]                 
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10                  
        vpxor           %%T6, %%T6, %%T3
                                  
                vmovdqu %%T1, [arg1 + 16*6]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1 

        vmovdqa         %%T1, [rsp + TMP5]
        vmovdqa         %%T5, [arg1 + HashKey_4]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11                  
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqa         %%T5, [arg1 + HashKey_4_k]                 
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10                  
        vpxor           %%T6, %%T6, %%T3
       
                                  
                vmovdqu %%T1, [arg1 + 16*7]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1 
                
        vmovdqa         %%T1, [rsp + TMP6]
        vmovdqa         %%T5, [arg1 + HashKey_3]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11                  
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqa         %%T5, [arg1 + HashKey_3_k]                 
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10                  
        vpxor           %%T6, %%T6, %%T3
                                
                vmovdqu %%T1, [arg1 + 16*8]                                             
                vaesenc %%XMM1, %%T1
                vaesenc %%XMM2, %%T1
                vaesenc %%XMM3, %%T1
                vaesenc %%XMM4, %%T1
                vaesenc %%XMM5, %%T1
                vaesenc %%XMM6, %%T1
                vaesenc %%XMM7, %%T1
                vaesenc %%XMM8, %%T1 

        vmovdqa         %%T1, [rsp + TMP7]
        vmovdqa         %%T5, [arg1 + HashKey_2]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11                  
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqa         %%T5, [arg1 + HashKey_2_k]                 
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10                  
        vpxor           %%T6, %%T6, %%T3
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
                  
                vmovdqu %%T5, [arg1 + 16*9]                                             
                vaesenc %%XMM1, %%T5
                vaesenc %%XMM2, %%T5
                vaesenc %%XMM3, %%T5
                vaesenc %%XMM4, %%T5
                vaesenc %%XMM5, %%T5
                vaesenc %%XMM6, %%T5
                vaesenc %%XMM7, %%T5
                vaesenc %%XMM8, %%T5 

        vmovdqa         %%T1, [rsp + TMP8]
        vmovdqa         %%T5, [arg1 + HashKey]
        vpclmulqdq      %%T3, %%T1, %%T5, 0x11                  
        vpxor           %%T4, %%T4, %%T3
        vpclmulqdq      %%T3, %%T1, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T3

        vpshufd         %%T3, %%T1, 01001110b
        vpxor           %%T3, %%T1
        vmovdqa         %%T5, [arg1 + HashKey_k]                 
        vpclmulqdq      %%T3, %%T3, %%T5, 0x10                  
        vpxor           %%T6, %%T6, %%T3
        
        vpxor           %%T6, %%T4
        vpxor           %%T6, %%T7
                                
                
                vmovdqu         %%T5, [arg1 + 16*10]
		vaesenc	%%XMM1, %%T5
		vaesenc	%%XMM2, %%T5
		vaesenc	%%XMM3, %%T5
		vaesenc	%%XMM4, %%T5
		vaesenc	%%XMM5, %%T5
		vaesenc	%%XMM6, %%T5
		vaesenc	%%XMM7, %%T5
		vaesenc	%%XMM8, %%T5

		vmovdqu		%%T5, [arg1 + 16*11]

		vaesenc	%%XMM1, %%T5
		vaesenc	%%XMM2, %%T5
		vaesenc	%%XMM3, %%T5
		vaesenc	%%XMM4, %%T5
		vaesenc	%%XMM5, %%T5
		vaesenc	%%XMM6, %%T5
		vaesenc	%%XMM7, %%T5
		vaesenc	%%XMM8, %%T5

		vmovdqu		%%T5, [arg1 + 16*12]
		vaesenc	%%XMM1, %%T5
		vaesenc	%%XMM2, %%T5
		vaesenc	%%XMM3, %%T5
		vaesenc	%%XMM4, %%T5
		vaesenc	%%XMM5, %%T5
		vaesenc	%%XMM6, %%T5
		vaesenc	%%XMM7, %%T5
		vaesenc	%%XMM8, %%T5

		vmovdqu		%%T5, [arg1 + 16*13]
		vaesenc	%%XMM1, %%T5
		vaesenc	%%XMM2, %%T5
		vaesenc	%%XMM3, %%T5
		vaesenc	%%XMM4, %%T5
		vaesenc	%%XMM5, %%T5
		vaesenc	%%XMM6, %%T5
		vaesenc	%%XMM7, %%T5
		vaesenc	%%XMM8, %%T5

		vmovdqu		%%T5, [arg1 + 16*14]

%assign i 0
%assign j 1
%rep 8                
		vpxor	%%T2, %%T5, [arg3+r11+16*i]					
                %ifidn %%ENC_DEC, ENC
                vaesenclast     reg(j), reg(j), %%T2
                %else
                vaesenclast     %%T3, reg(j), %%T2
                vmovdqu reg(j), [arg3+r11+16*i]
                vmovdqu [arg2+r11+16*i], %%T3
                %endif
%assign i (i+1)    
%assign j (j+1)            
%endrep   

        vpslldq %%T3, %%T6, 8           ; shift-L %%T3 2 DWs
        vpsrldq %%T6, %%T6, 8           ; shift-R %%T2 2 DWs
        vpxor   %%T7, %%T3      
        vpxor   %%T6, %%T4              ; accumulate the results in %%T6:%%T7
        
        
        ;first phase of the reduction
        
        vpslld  %%T2, %%T7, 31                                  ; packed right shifting << 31
        vpslld  %%T3, %%T7, 30                                  ; packed right shifting shift << 30
        vpslld  %%T4, %%T7, 25                                  ; packed right shifting shift << 25
        
        vpxor   %%T2, %%T2, %%T3                                ; xor the shifted versions
        vpxor   %%T2, %%T2, %%T4
        
        vpsrldq %%T1, %%T2, 4                                   ; shift-R %%T1 1 DW
        
        vpslldq %%T2, %%T2, 12                                  ; shift-L %%T2 3 DWs    
        vpxor   %%T7, %%T2                                      ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		%ifidn %%ENC_DEC, ENC
		vmovdqu	[arg2+r11+16*0], %%XMM1			; Write to the Ciphertext buffer	  
		vmovdqu	[arg2+r11+16*1], %%XMM2			; Write to the Ciphertext buffer	  
		vmovdqu	[arg2+r11+16*2], %%XMM3			; Write to the Ciphertext buffer
		vmovdqu	[arg2+r11+16*3], %%XMM4			; Write to the Ciphertext buffer
		vmovdqu	[arg2+r11+16*4], %%XMM5			; Write to the Ciphertext buffer
		vmovdqu	[arg2+r11+16*5], %%XMM6			; Write to the Ciphertext buffer
		vmovdqu	[arg2+r11+16*6], %%XMM7			; Write to the Ciphertext buffer
		vmovdqu	[arg2+r11+16*7], %%XMM8			; Write to the Ciphertext buffer
                %endif

        ;second phase of the reduction
        
        vpsrld  %%T2,%%T7,1                                     ; packed left shifting >> 1
        vpsrld  %%T3,%%T7,2                                     ; packed left shifting >> 2
        vpsrld  %%T4,%%T7,7                                     ; packed left shifting >> 7
        vpxor   %%T2, %%T2,%%T3                                 ; xor the shifted versions
        vpxor   %%T2, %%T2,%%T4
        
        vpxor   %%T2, %%T2, %%T1
        vpxor   %%T7, %%T7, %%T2      
        vpxor   %%T6, %%T6, %%T7                                ; the result is in %%T6



                vpshufb %%XMM1, [rel SHUF_MASK]             ; perform a 16Byte swap
                vpshufb %%XMM2, [rel SHUF_MASK]
                vpshufb %%XMM3, [rel SHUF_MASK]
                vpshufb %%XMM4, [rel SHUF_MASK]
                vpshufb %%XMM5, [rel SHUF_MASK]
                vpshufb %%XMM6, [rel SHUF_MASK]
                vpshufb %%XMM7, [rel SHUF_MASK]
                vpshufb %%XMM8, [rel SHUF_MASK]
        

        vpxor   %%XMM1, %%T6        

%endmacro


; GHASH the last 4 ciphertext blocks. 
%macro  GHASH_LAST_8 15
%define %%T1    %1
%define %%T2    %2
%define %%T3    %3
%define %%T4    %4
%define %%T5    %5
%define %%T6    %6
%define %%T7    %7
%define %%XMM1  %8
%define %%XMM2  %9
%define %%XMM3  %10
%define %%XMM4  %11
%define %%XMM5  %12
%define %%XMM6  %13
%define %%XMM7  %14
%define %%XMM8  %15
        ;; Karatsuba Method
        
        
        vpshufd         %%T2, %%XMM1, 01001110b
        vpxor           %%T2, %%XMM1
        vmovdqa         %%T5, [arg1 + HashKey_8]
        vpclmulqdq      %%T6, %%XMM1, %%T5, 0x11
        vpclmulqdq      %%T7, %%XMM1, %%T5, 0x00
        
        vmovdqa         %%T3, [arg1 + HashKey_8_k]
        vpclmulqdq      %%XMM1, %%T2, %%T3, 0x00

       
        ;;;;;;;;;;;;;;;;;;;;;;

        
        vpshufd         %%T2, %%XMM2, 01001110b
        vpxor           %%T2, %%XMM2
        vmovdqa         %%T5, [arg1 + HashKey_7]
        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4
        
        vpclmulqdq      %%T4, %%XMM2, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4
        
        vmovdqa         %%T3, [arg1 + HashKey_7_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        
        vpshufd         %%T2, %%XMM3, 01001110b
        vpxor           %%T2, %%XMM3
        vmovdqa         %%T5, [arg1 + HashKey_6]
        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4
        
        vpclmulqdq      %%T4, %%XMM3, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4
        
        vmovdqa         %%T3, [arg1 + HashKey_6_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        
        vpshufd         %%T2, %%XMM4, 01001110b
        vpxor           %%T2, %%XMM4
        vmovdqa         %%T5, [arg1 + HashKey_5]
        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4
        
        vpclmulqdq      %%T4, %%XMM4, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4
        
        vmovdqa         %%T3, [arg1 + HashKey_5_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;
        
        vpshufd         %%T2, %%XMM5, 01001110b
        vpxor           %%T2, %%XMM5
        vmovdqa         %%T5, [arg1 + HashKey_4]
        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4
        
        vpclmulqdq      %%T4, %%XMM5, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4
        
        vmovdqa         %%T3, [arg1 + HashKey_4_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vpshufd         %%T2, %%XMM6, 01001110b
        vpxor           %%T2, %%XMM6
        vmovdqa         %%T5, [arg1 + HashKey_3]

        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4
        
        vpclmulqdq      %%T4, %%XMM6, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4
        
        vmovdqa         %%T3, [arg1 + HashKey_3_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;

        vpshufd         %%T2, %%XMM7, 01001110b
        vpxor           %%T2, %%XMM7
        vmovdqa         %%T5, [arg1 + HashKey_2]
        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4
        
        vpclmulqdq      %%T4, %%XMM7, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4
        
        vmovdqa         %%T3, [arg1 + HashKey_2_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        vpxor           %%XMM1, %%XMM1, %%T2

        ;;;;;;;;;;;;;;;;;;;;;;
        
        vpshufd         %%T2, %%XMM8, 01001110b
        vpxor           %%T2, %%XMM8
        vmovdqa         %%T5, [arg1 + HashKey]
        vpclmulqdq      %%T4, %%XMM8, %%T5, 0x11
        vpxor           %%T6, %%T6, %%T4
        
        vpclmulqdq      %%T4, %%XMM8, %%T5, 0x00
        vpxor           %%T7, %%T7, %%T4
        
        vmovdqa         %%T3, [arg1 + HashKey_k]
        vpclmulqdq      %%T2, %%T2, %%T3, 0x00
        
        vpxor           %%XMM1, %%XMM1, %%T2
        vpxor           %%XMM1, %%XMM1, %%T6
        vpxor           %%T2, %%XMM1, %%T7
        
                


        vpslldq         %%T4, %%T2, 8
        vpsrldq         %%T2, %%T2, 8
        
        vpxor           %%T7, %%T4
        vpxor           %%T6, %%T2                                      ; <%%T6:%%T7> holds the result of the accumulated carry-less multiplications
        
        ;first phase of the reduction
        
        vpslld          %%T2, %%T7, 31                                  ; packed right shifting << 31
        vpslld          %%T3, %%T7, 30                                  ; packed right shifting shift << 30
        vpslld          %%T4, %%T7, 25                                  ; packed right shifting shift << 25
        
        vpxor           %%T2, %%T2, %%T3                                ; xor the shifted versions
        vpxor           %%T2, %%T2, %%T4
        
        vpsrldq         %%T1, %%T2, 4                                   ; shift-R %%T1 1 DW
        
        vpslldq         %%T2, %%T2, 12                                  ; shift-L %%T2 3 DWs    
        vpxor           %%T7, %%T2                                      ; first phase of the reduction complete
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;second phase of the reduction
        
        vpsrld          %%T2,%%T7,1                                     ; packed left shifting >> 1
        vpsrld          %%T3,%%T7,2                                     ; packed left shifting >> 2
        vpsrld          %%T4,%%T7,7                                     ; packed left shifting >> 7
        vpxor           %%T2, %%T2,%%T3                                 ; xor the shifted versions
        vpxor           %%T2, %%T2,%%T4
        
        vpxor           %%T2, %%T2, %%T1
        vpxor           %%T7, %%T7, %%T2      
        vpxor           %%T6, %%T6, %%T7                                ; the result is in %%T6


%endmacro

; Encryption of a single block
%macro ENCRYPT_SINGLE_BLOCK 1
%define %%XMM0  %1

                vpxor    %%XMM0, [arg1+16*0]
%assign i 1
%rep 13
                vaesenc  %%XMM0, [arg1+16*i]
%assign i (i+1)
%endrep
                vaesenclast      %%XMM0, [arg1+16*i]
%endmacro




; combined for GCM encryp and decrypt functions
; clobbering all xmm registers
; clobbering r10, r11, r12, r13, r14, r15
%macro  GCM_ENC_DEC     1
%define %%ENC_DEC %1
        ;the number of pushes must equal STACK_OFFSET
        push    r12
        push    r13
        push    r14
        push    r15

        mov     r14, rsp
        


        
        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~63                                ; align rsp to 64 bytes


%ifdef WIN_ABI 
        ; xmm6:xmm15 need to be maintained for Windows
        vmovdqa [rsp + XMM_SAVE + 0*16],xmm6
        vmovdqa [rsp + XMM_SAVE + 1*16],xmm7
        vmovdqa [rsp + XMM_SAVE + 2*16],xmm8
        vmovdqa [rsp + XMM_SAVE + 3*16],xmm9
        vmovdqa [rsp + XMM_SAVE + 4*16],xmm10
        vmovdqa [rsp + XMM_SAVE + 5*16],xmm11
        vmovdqa [rsp + XMM_SAVE + 6*16],xmm12
        vmovdqa [rsp + XMM_SAVE + 7*16],xmm13
        vmovdqa [rsp + XMM_SAVE + 8*16],xmm14
        vmovdqa [rsp + XMM_SAVE + 9*16],xmm15
%endif          
        
        
        vmovdqu  xmm13, [arg1 + HashKey]                 ; xmm13 = HashKey

        mov     r13, arg4                               ; save the number of bytes of plaintext/ciphertext
        and     r13, -16                                ; r13 = r13 - (r13 mod 16)
        
        mov     r12, r13
        shr     r12, 4
        and     r12, 7
        jz      %%_initial_num_blocks_is_0
        
        cmp     r12, 7
        je      %%_initial_num_blocks_is_7
        cmp     r12, 6
        je      %%_initial_num_blocks_is_6
        cmp     r12, 5
        je      %%_initial_num_blocks_is_5
        cmp     r12, 4
        je      %%_initial_num_blocks_is_4
        cmp     r12, 3
        je      %%_initial_num_blocks_is_3
        cmp     r12, 2
        je      %%_initial_num_blocks_is_2
        
        jmp     %%_initial_num_blocks_is_1
        
%%_initial_num_blocks_is_7:
        INITIAL_BLOCKS  7, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*7
        jmp     %%_initial_blocks_encrypted
        
%%_initial_num_blocks_is_6:
        INITIAL_BLOCKS  6, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*6
        jmp     %%_initial_blocks_encrypted
        
%%_initial_num_blocks_is_5:
        INITIAL_BLOCKS  5, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*5
        jmp     %%_initial_blocks_encrypted
        
%%_initial_num_blocks_is_4:
        INITIAL_BLOCKS  4, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*4
        jmp     %%_initial_blocks_encrypted
        
                
%%_initial_num_blocks_is_3:
        INITIAL_BLOCKS  3, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*3
        jmp     %%_initial_blocks_encrypted
%%_initial_num_blocks_is_2:
        INITIAL_BLOCKS  2, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16*2
        jmp     %%_initial_blocks_encrypted

%%_initial_num_blocks_is_1:
        INITIAL_BLOCKS  1, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        sub     r13, 16
        jmp     %%_initial_blocks_encrypted
        
%%_initial_num_blocks_is_0:
        INITIAL_BLOCKS  0, xmm12, xmm13, xmm14, xmm15, xmm11, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm10, xmm0, %%ENC_DEC
        
        
%%_initial_blocks_encrypted:      
        cmp     r13, 0
        je      %%_zero_cipher_left
        
        sub     r13, 128
        je      %%_eight_cipher_left




        vmovd    r15d, xmm9
        and     r15d, 255
        vpshufb  xmm9, [rel SHUF_MASK]


%%_encrypt_by_8_new:
        cmp     r15d, 255-8
        jg      %%_encrypt_by_8



        add     r15b, 8
        GHASH_8_ENCRYPT_8_PARALLEL      xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, out_order, %%ENC_DEC
        add     r11, 128
        sub     r13, 128
        jne     %%_encrypt_by_8_new
        
        vpshufb  xmm9, [rel SHUF_MASK]
        jmp     %%_eight_cipher_left

%%_encrypt_by_8:
        vpshufb  xmm9, [rel SHUF_MASK]
        add     r15b, 8
        GHASH_8_ENCRYPT_8_PARALLEL      xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm9, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm15, in_order, %%ENC_DEC
        vpshufb  xmm9, [rel SHUF_MASK]
        add     r11, 128
        sub     r13, 128
        jne     %%_encrypt_by_8_new
        
        vpshufb  xmm9, [rel SHUF_MASK]




%%_eight_cipher_left:
        GHASH_LAST_8    xmm0, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8

        
%%_zero_cipher_left:
        mov     r13, arg4
        and     r13, 15                                 ; r13 = (arg4 mod 16)
        
        je      %%_multiple_of_16_bytes
        
        ; handle the last <16 Byte block seperately
        
        
        vpaddd   xmm9, [rel ONE]                     ; INCR CNT to get Yn
        vpshufb  xmm9, [rel SHUF_MASK]
        ENCRYPT_SINGLE_BLOCK    xmm9                    ; E(K, Yn)
        
        sub     r11, 16
        add     r11, r13
        vmovdqu  xmm1, [arg3+r11]                        ; receive the last <16 Byte block
        
        lea     r12, [rel SHIFT_MASK + 16]
        sub     r12, r13                                ; adjust the shuffle mask pointer to be able to shift 16-r13 bytes (r13 is the number of bytes in plaintext mod 16)
        vmovdqu  xmm2, [r12]                             ; get the appropriate shuffle mask      
        vpshufb  xmm1, xmm2                              ; shift right 16-r13 bytes

        %ifidn  %%ENC_DEC, DEC
        vmovdqa  xmm2, xmm1
        vpxor    xmm9, xmm1                              ; Plaintext XOR E(K, Yn)
        vmovdqu  xmm1, [r12 + ALL_F - SHIFT_MASK]        ; get the appropriate mask to mask out top 16-r13 bytes of xmm9
        vpand    xmm9, xmm1                              ; mask out top 16-r13 bytes of xmm9
        vpand    xmm2, xmm1
        vpshufb  xmm2, [rel SHUF_MASK]
        vpxor    xmm14, xmm2
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6    ;GHASH computation for the last <16 Byte block
        sub     r11, r13
        add     r11, 16
        %else
        vpxor    xmm9, xmm1                              ; Plaintext XOR E(K, Yn)
        vmovdqu  xmm1, [r12 + ALL_F - SHIFT_MASK]        ; get the appropriate mask to mask out top 16-r13 bytes of xmm9
        vpand    xmm9, xmm1                              ; mask out top 16-r13 bytes of xmm9
        vpshufb  xmm9, [rel SHUF_MASK]
        vpxor    xmm14, xmm9
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6    ;GHASH computation for the last <16 Byte block
        sub     r11, r13
        add     r11, 16
        vpshufb  xmm9, [rel SHUF_MASK]               ; shuffle xmm9 back to output as ciphertext
        %endif


        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; output r13 Bytes      
        vmovq    rax, xmm9
        cmp     r13, 8
        jle     %%_less_than_8_bytes_left
        
        mov     [arg2 + r11], rax
        add     r11, 8
        vpsrldq xmm9, xmm9, 8
        vmovq    rax, xmm9
        sub     r13, 8
                
%%_less_than_8_bytes_left:
        mov     BYTE [arg2 + r11], al
        add     r11, 1
        shr     rax, 8
        sub     r13, 1
        jne     %%_less_than_8_bytes_left
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        
%%_multiple_of_16_bytes:
        mov     r12, arg7                               ; r12 = aadLen (number of bytes)
        shl     r12, 3                                  ; convert into number of bits
        vmovd    xmm15, r12d                             ; len(A) in xmm15
        
        shl     arg4, 3                                 ; len(C) in bits  (*128)
        vmovq    xmm1, arg4
        vpslldq  xmm15, xmm15, 8                        ; xmm15 = len(A)|| 0x0000000000000000                   
        vpxor    xmm15, xmm1                            ; xmm15 = len(A)||len(C)
        
        vpxor    xmm14, xmm15
        GHASH_MUL       xmm14, xmm13, xmm0, xmm10, xmm11, xmm5, xmm6    ; final GHASH computation
        vpshufb  xmm14, [rel SHUF_MASK]             ; perform a 16Byte swap
        
        mov     rax, arg5                               ; rax = *Y0
        vmovdqu  xmm9, [rax]                            ; xmm9 = Y0
        
        ENCRYPT_SINGLE_BLOCK    xmm9                    ; E(K, Y0)
        
        vpxor    xmm9, xmm14

        
        
%%_return_T:      
        mov     r10, arg8               ; r10 = authTag
        mov     r11, arg9              ; r11 = auth_tag_len
        
        cmp     r11, 16
        je      %%_T_16
        
        cmp     r11, 12
        je      %%_T_12

%%_T_8:
        vmovq    rax, xmm9
        mov     [r10], rax
        jmp     %%_return_T_done
%%_T_12:
        vmovq    rax, xmm9
        mov     [r10], rax
        vpsrldq xmm9, xmm9, 8
        vmovd    eax, xmm9
        mov     [r10 + 8], eax
        jmp     %%_return_T_done
        
%%_T_16:
        vmovdqu  [r10], xmm9

%%_return_T_done: 
%ifdef WIN_ABI
        vmovdqa xmm15  , [rsp + XMM_SAVE + 9*16]
        vmovdqa xmm14  , [rsp + XMM_SAVE + 8*16]
        vmovdqa xmm13  , [rsp + XMM_SAVE + 7*16]
        vmovdqa xmm12  , [rsp + XMM_SAVE + 6*16]
        vmovdqa xmm11  , [rsp + XMM_SAVE + 5*16]
        vmovdqa xmm10  , [rsp + XMM_SAVE + 4*16]
        vmovdqa xmm9 , [rsp + XMM_SAVE + 3*16]
        vmovdqa xmm8 , [rsp + XMM_SAVE + 2*16]
        vmovdqa xmm7 , [rsp + XMM_SAVE + 1*16]
        vmovdqa xmm6 , [rsp + XMM_SAVE + 0*16]
%endif          
        mov     rsp, r14

        pop     r15
        pop     r14
        pop     r13
        pop     r12
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm256_precomp_avx_gen2 
;        (gcm_data     *my_ctx_data, 
;        u8     *hash_subkey); /* H, the Hash sub key input. Data starts on a 16-byte boundary. */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm256_precomp_avx_gen2
aesni_gcm256_precomp_avx_gen2:
        ;the number of pushes must equal STACK_OFFSET
        push    r12
        push    r13
        push    r14
        push    r15

        mov     r14, rsp
        

        
        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~63                                ; align rsp to 64 bytes

%ifdef WIN_ABI  
        ; only xmm6 needs to be maintained
        vmovdqa [rsp + XMM_SAVE + 0*16],xmm6
%endif          
        mov     r12, arg2                               ; arg2 NULL then ignored
        or      r12, r12
        je      ._zerohash

        vmovdqu  xmm6, [arg2]                           ; xmm6 = HashKey
        jmp     ._ecbenc

._zerohash:        
        vpxor    xmm6, xmm6                             ; xmm6 = ZERO
        
._ecbenc:
        ENCRYPT_SINGLE_BLOCK xmm6

        vpshufb  xmm6, [rel SHUF_MASK]
        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        vmovdqa  xmm2, xmm6
        vpsllq   xmm6, 1
        vpsrlq   xmm2, 63
        vmovdqa  xmm1, xmm2
        vpslldq  xmm2, xmm2, 8 
        vpsrldq  xmm1, xmm1, 8
        vpor     xmm6, xmm2     
        ;reduction
        vpshufd  xmm2, xmm1, 00100100b
        vpcmpeqd xmm2, [rel TWOONE]
        vpand    xmm2, [rel POLY]
        vpxor    xmm6, xmm2                             ; xmm6 holds the HashKey<<1 mod poly   
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 
        vmovdqa  [arg1 + HashKey], xmm6                  ; store HashKey<<1 mod poly

        
        PRECOMPUTE  xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
 
%ifdef WIN_ABI
        vmovdqa xmm6, [rsp + XMM_SAVE + 0*16]
%endif          
        mov     rsp, r14

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        ret
       
                
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm_enc_avx_gen2(
;        gcm_data        *my_ctx_data,     /* aligned to 16 Bytes */
;        u8      *out, /* Ciphertext output. Encrypt in-place is allowed.  */
;        const   u8 *in, /* Plaintext input */
;        u64     plaintext_len, /* Length of data in Bytes for encryption. */
;        u8      *iv, /* Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte aligned pointer. */
;        const   u8 *aad, /* Additional Authentication Data (AAD)*/
;        u64     aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
;        u8      *auth_tag, /* Authenticated Tag output. */
;        u64     auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm256_enc_avx_gen2
aesni_gcm256_enc_avx_gen2:
        GCM_ENC_DEC     ENC
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aesni_gcm_dec_avx_gen2(
;        gcm_data        *my_ctx_data,     /* aligned to 16 Bytes */
;        u8      *out, /* Plaintext output. Decrypt in-place is allowed.  */
;        const   u8 *in, /* Ciphertext input */
;        u64     plaintext_len, /* Length of data in Bytes for encryption. */
;        u8      *iv, /* Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte aligned pointer. */
;        const   u8 *aad, /* Additional Authentication Data (AAD)*/
;        u64     aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
;        u8      *auth_tag, /* Authenticated Tag output. */
;        u64     auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global aesni_gcm256_dec_avx_gen2
aesni_gcm256_dec_avx_gen2:
        GCM_ENC_DEC     DEC
ret
