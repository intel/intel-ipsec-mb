;;
;; Copyright (c) 2023-2024, Intel Corporation
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

;; FIPS PUB 180-4, FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION, Secure Hash Standard (SHS)
;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

extern sha512_update_ni_x1

%include "include/os.inc"
%include "include/constants.inc"
%include "include/reg_sizes.inc"
%include "include/imb_job.inc"
%include "include/memcpy.inc"

%ifdef LINUX

%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx

%define gp1     rax
%define gp2     r8
%define gp3     r9
%define gp4     r10
%define gp5     r11
%define gp6     arg4
%define gp7     r12
%define gp8     r13
%define gp9     r14
%define gp10    r15
%define gp11    rbx
%define gp12    rbp

%else

%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9

%define gp1     rax
%define gp2     r10
%define gp3     r11
%define gp4     arg4
%define gp5     rdi
%define gp6     rsi
%define gp7     r12
%define gp8     r13
%define gp9     r14
%define gp10    r15
%define gp11    rbx
%define gp12    rbp

%endif

%xdefine t1     gp1
%xdefine t2     gp2
%xdefine t3     gp3
%xdefine t4     gp4

%xdefine r1     gp12
%xdefine r2     gp11
%xdefine r3     gp10
%xdefine r4     gp9

%define arg_job         r1
%define arg_msg         r2
%define arg_msg_length  r3
%define arg_sha_type    r4

;; HMAC-SHA512/384 stack frame
struc STACK
_B:             resb    SHA512_BLK_SZ           ; two SHA512 blocks (aligned to 16)
_D:             resb    SHA512_DIGEST_SIZE      ; digest
_gpr_save:      resq    8       ; space for GPR's
_rsp_save:      resq    1       ; space for rsp pointer
endstruc

mksection .rodata

align 32
SHUFF_MASK:
	dq 0x0001020304050607, 0x08090a0b0c0d0e0f
	dq 0x0001020304050607, 0x08090a0b0c0d0e0f

;; End-of-Message pattern
align 32
EOM_32BYTES:
	db 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

;; PAD BLOCKS are used for OPAD where digest of IPAD + message is put into the block.
;; The blocks below fill up top 32 bytes of the block,
;; low 64/48 bytes get filled with the digest followed by EOM.
align 32
SHA512_OPAD_LENGTH:
        ;; last two qwords has to encode length in bits of: BLOCK size + DIGEST size
        ;; (128 + 64) * 8 = 1536 = 0x600 in hex
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00

align 32
SHA384_OPAD_LENGTH:
        ;; last two qwords has to encode length in bits of: BLOCK size + DIGEST size
        ;; (128 + 48) * 8 = 1408 = 0x580 in hex
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x80

mksection .text

;; =============================================================================
;; Save registers on the stack and create stack frame
;; =============================================================================

%macro FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -32
        mov     [rsp + _rsp_save], rax
        mov     [rsp + _gpr_save + 0*8], rbx
        mov     [rsp + _gpr_save + 1*8], rbp
        mov     [rsp + _gpr_save + 2*8], r12
        mov     [rsp + _gpr_save + 3*8], r13
        mov     [rsp + _gpr_save + 4*8], r14
        mov     [rsp + _gpr_save + 5*8], r15
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + _gpr_save + 6*8], rdi
        mov     [rsp + _gpr_save + 7*8], rsi
%endif
%endmacro

;; =============================================================================
;; Restore registers from the stack
;; =============================================================================

%macro FUNC_END 0
        mov     rbx, [rsp + _gpr_save + 0*8]
        mov     rbp, [rsp + _gpr_save + 1*8]
        mov     r12, [rsp + _gpr_save + 2*8]
        mov     r13, [rsp + _gpr_save + 3*8]
        mov     r14, [rsp + _gpr_save + 4*8]
        mov     r15, [rsp + _gpr_save + 5*8]
%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + _gpr_save + 6*8]
        mov     rsi, [rsp + _gpr_save + 7*8]
%endif
        mov     rsp, [rsp + _rsp_save]
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha512_tag_store(void *tag_ptr, uint64_t tag_len, ymm1:ymm0 tag)
align 32
MKGLOBAL(sha512_tag_store,function,internal)
sha512_tag_store:
        cmp     arg2, 16
        jb      .tag_store_1_15
        je      .tag_store_16

        cmp     arg2, 32
        je      .tag_store_32
        jb      .tag_store_17_31

        cmp     arg2, 48
        je      .tag_store_48
        jb      .tag_store_33_47

        cmp     arg2, 64
        je      .tag_store_64

.tag_store_49_63:
        vmovdqu [arg1 + 0*32], ymm0
        vmovdqu [arg1 + 1*32], xmm1
        vextracti128 xmm0, ymm1, 1
        lea     arg1, [arg1 + 48]
        sub     arg2, 48
        jmp     .tag_store_1_15

.tag_store_33_47:
        vmovdqu [arg1 + 0*32], ymm0
        lea     arg1, [arg1 + 32]
        vmovdqa ymm0, ymm1
        sub     arg2, 32
        jmp     .tag_store_1_15

.tag_store_17_31:
        vmovdqu [arg1 + 0*16], xmm0
        vextracti128 xmm0, ymm0, 1
        lea     arg1, [arg1 + 16]
        sub     arg2, 16
        ;; fall through to store remaining tag bytes

.tag_store_1_15:
        simd_store_avx  arg1, xmm0, arg2, t1, t2
        jmp     .tag_store_end

.tag_store_16:
        vmovdqu [arg1 + 0*16], xmm0
        jmp     .tag_store_end

.tag_store_32:
        vmovdqu [arg1 + 0*32], ymm0
        jmp     .tag_store_end

.tag_store_48:
        vmovdqu [arg1 + 0*32], ymm0
        vmovdqu [arg1 + 1*32], xmm1
        jmp     .tag_store_end

.tag_store_64:
        vmovdqu [arg1 + 0*32], ymm0
        vmovdqu [arg1 + 1*32], ymm1

.tag_store_end:
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; IMB_JOB *sha512_384_hmac_submit_ni_avx2(const unsigned sha_type, IMB_JOB *job)
align 32
MKGLOBAL(sha512_384_hmac_submit_ni_avx2,function,internal)
sha512_384_hmac_submit_ni_avx2:
        FUNC_START

        ;; save input arguments
        mov     arg_job, arg2
        mov     arg_sha_type, arg1

        ;; init the digest with IPAD
        mov     t1, [arg_job + _auth_key_xor_ipad]
        vmovdqu ymm0, [t1 + 0*32]
        vmovdqu ymm1, [t1 + 1*32]
        vmovdqa [rsp + _D + 0*32], ymm0
        vmovdqa [rsp + _D + 1*32], ymm1

        ;; update digest for full number of blocks
        lea     arg1, [rsp + _D]
        mov     arg2, [arg_job + _src]
        add     arg2, [arg_job + _hash_start_src_offset]
        mov     arg_msg, arg2
        mov     arg_msg_length, [arg_job + _msg_len_to_hash_in_bytes]
        mov     arg3, arg_msg_length
        shr     arg3, 7                 ;; msg_length / SHA512_BLK_SZ
        call    sha512_update_ni_x1

        ;; prepare partial block
        mov     DWORD(arg3), SHA512_BLK_SZ - 1
        not     arg3
        and     arg3, arg_msg_length    ;; number of bytes processed already
        add     arg_msg, arg3           ;; move message pointer to start of the partial block
        mov     t2, arg_msg_length
        sub     t2, arg3                ;; t2 =  number of bytes left

        xor     DWORD(arg1), DWORD(arg1)
.partial_block_copy:
        cmp     DWORD(arg1), DWORD(t2)
        je      .partial_block_copy_exit
        mov     BYTE(t1), [arg_msg + arg1]
        mov     [rsp + _B + arg1], BYTE(t1)
        inc     DWORD(arg1)
        jmp     .partial_block_copy

.partial_block_copy_exit:
        ;; put end of message marker
        mov     BYTE [rsp + _B + arg1], 0x80
        inc     DWORD(arg1)

        xor     DWORD(t1), DWORD(t1)
.partial_block_zero:
        cmp     DWORD(arg1), SHA512_BLK_SZ
        je      .partial_block_zero_exit
        mov     [rsp + _B + arg1], BYTE(t1)
        inc     DWORD(arg1)
        jmp     .partial_block_zero

.partial_block_zero_exit:
        cmp     DWORD(t2), SHA512_BLK_SZ - 16
        jb      .add_msg_length

        ;; if length field doesn't fit into this partial block
        ;; - compute digest on the current block
        ;; - clear the block for the length to be put into it next
        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sha512_update_ni_x1

        ;; clear the block
        vpxor   xmm0, xmm0, xmm0
        vmovdqa [rsp + _B + 0*32], ymm0
        vmovdqa [rsp + _B + 1*32], ymm0
        vmovdqa [rsp + _B + 2*32], ymm0
        vmovdqa [rsp + _B + 3*32], xmm0 ;; the last 16 bytes will be set below

.add_msg_length:
        lea     arg2, [arg_msg_length + SHA512_BLK_SZ]  ;; original message length + IPAD block
        lea     arg1, [arg2 * 8]        ;; length in bits
        shr     arg2, 61
        movbe   [rsp + _B + SHA512_BLK_SZ - 2*8], arg2
        movbe   [rsp + _B + SHA512_BLK_SZ - 1*8], arg1

        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sha512_update_ni_x1

.process_opad:
        cmp     DWORD(arg_sha_type), 512
        jne     .opad_hmac_sha384

.opad_hmac_sha512:
        vmovdqa ymm0, [rsp + _D + 0*32]
        vmovdqa ymm1, [rsp + _D + 1*32]
        vpshufb ymm0, ymm0, [rel SHUFF_MASK]
        vpshufb ymm1, ymm1, [rel SHUFF_MASK]
        vmovdqa ymm2, [rel EOM_32BYTES]
        vmovdqa ymm3, [rel SHA512_OPAD_LENGTH]
        vmovdqa [rsp + _B + 0*32], ymm0
        vmovdqa [rsp + _B + 1*32], ymm1
        vmovdqa [rsp + _B + 2*32], ymm2
        vmovdqa [rsp + _B + 3*32], ymm3
        jmp     .opad_update

.opad_hmac_sha384:
        vmovdqa ymm0, [rsp + _D + 0*32]
        vmovdqa xmm1, [rsp + _D + 1*32]
        vpshufb ymm0, ymm0, [rel SHUFF_MASK]
        vpshufb xmm1, xmm1, [rel SHUFF_MASK]
        vinserti128 ymm1, [rel EOM_32BYTES], 1
        vpxor   xmm2, xmm2, xmm2
        vmovdqa ymm3, [rel SHA384_OPAD_LENGTH]
        vmovdqa [rsp + _B + 0*32], ymm0
        vmovdqa [rsp + _B + 1*32], ymm1
        vmovdqa [rsp + _B + 2*32], ymm2
        vmovdqa [rsp + _B + 3*32], ymm3

.opad_update:
        ;; init the digest with OPAD
        mov     t1, [arg_job + _auth_key_xor_opad]
        vmovdqu ymm0, [t1 + 0*32]
        vmovdqu ymm1, [t1 + 1*32]
        vmovdqa [rsp + _D + 0*32], ymm0
        vmovdqa [rsp + _D + 1*32], ymm1

        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sha512_update_ni_x1

.tag_store_start:
        ;; byte swap the digest and write it back
        lea     arg1, [rsp + _D]
        vmovdqa ymm0, [arg1 + 0*32]
        vmovdqa ymm1, [arg1 + 1*32]
        vpshufb ymm0, ymm0, [rel SHUFF_MASK]
        vpshufb ymm1, ymm1, [rel SHUFF_MASK]

        mov     arg1, [arg_job + _auth_tag_output]
        mov     arg2, [arg_job + _auth_tag_output_len_in_bytes]
        call    sha512_tag_store

%ifdef SAFE_DATA
        vpxor   xmm0, xmm0, xmm0
        vpxor   xmm1, xmm1, xmm1
        vpxor   xmm2, xmm2, xmm2
        vpxor   xmm3, xmm3, xmm3

        vmovdqu [rsp + _B + 0*32], ymm0
        vmovdqu [rsp + _B + 1*32], ymm0
        vmovdqu [rsp + _B + 2*32], ymm0
        vmovdqu [rsp + _B + 3*32], ymm0
%endif
        vzeroupper

        mov     rax, arg_job
        or      dword [arg_job + _status], IMB_STATUS_COMPLETED_AUTH
        FUNC_END
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; IMB_JOB *submit_job_hmac_sha_512_ni_avx2(MB_MGR_HMAC_SHA_512_OOO *state, IMB_JOB *job)
align 32
MKGLOBAL(submit_job_hmac_sha_512_ni_avx2,function,internal)
submit_job_hmac_sha_512_ni_avx2:
        mov     DWORD(arg1), 512
        jmp     sha512_384_hmac_submit_ni_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; IMB_JOB *submit_job_hmac_sha_384_ni_avx2(MB_MGR_SHA384_OOO *state, IMB_JOB *job)
align 32
MKGLOBAL(submit_job_hmac_sha_384_ni_avx2,function,internal)
submit_job_hmac_sha_384_ni_avx2:
        mov     DWORD(arg1), 384
        jmp     sha512_384_hmac_submit_ni_avx2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; IMB_JOB *flush_job_hmac_sha_512_ni_avx2(MB_MGR_SHA512_OOO *state)
;; IMB_JOB *flush_job_hmac_sha_384_ni_avx2(MB_MGR_SHA384_OOO *state)
align 32
MKGLOBAL(flush_job_hmac_sha_512_ni_avx2,function,internal)
MKGLOBAL(flush_job_hmac_sha_384_ni_avx2,function,internal)
flush_job_hmac_sha_512_ni_avx2:
flush_job_hmac_sha_384_ni_avx2:
        xor     rax, rax
        ret

mksection stack-noexec
