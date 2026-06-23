;;
;; Copyright (c) 2026, Intel Corporation
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

;;
;; HMAC-SHA3-{224,256,384,512} single-buffer AVX-512 submit.
;;
;; IMB_JOB *hmac_sha3_NNN_submit_avx512(IMB_JOB *job)
;;
;; HMAC-SHA3(K, m) = SHA3(K' XOR opad || SHA3(K' XOR ipad || m))
;;
;; The _hashed_auth_key_xor_ipad/_opad fields hold raw K' XOR 0x36/0x5c blocks
;; of exactly block_size (= rate) bytes, computed by imb_hmac_ipad_opad().
;;
;; Implementation:
;;   Inner: zero state, absorb ipad (1 full rate block), absorb msg
;;          (multi-block + padded partial), squeeze inner digest.
;;   Outer: zero state, absorb opad (1 full rate block), absorb
;;          inner_digest (padded partial block), squeeze tag to output.
;;
;; keccak1600_block_64bit is the single-lane AVX-512 Keccak-f[1600] permutation
;; from sha3_avx512.asm.  It operates on ymm0-ymm24 (in/out state) and clobbers
;; ymm25-ymm31, r13d, and r14.

default rel

%include "include/sha3_common.inc"
%include "include/imb_job.inc"
%include "include/align_avx512.inc"
%include "include/cet.inc"
%include "include/clear_regs.inc"

extern keccak1600_block_64bit
extern keccak_1600_init_state

;; Stack frame layout (offsets from rsp after alignment and sub):
;;
;;   [rsp + _PARTIAL]  256-byte scratch buffer (padded partial block / digest)
;;   [rsp + _XMM_SAVE] xmm6-xmm15 save area  (Windows only, 10 * 16 = 160 B)
;;   [rsp + _RDI_SAVE] rdi save slot          (Windows only, 8 B)
;;   --- pad to next multiple of 32 ---
;;
%define PARTIAL_SZ      256             ; 8 x 32-byte YMM = 256 bytes
%define XMM_SAVE_SZ     (10 * 16)       ; xmm6-xmm15 = 160 bytes
%define RDI_SAVE_SZ     8               ; one GP register

%define _PARTIAL        0
%define _XMM_SAVE       (_PARTIAL  + PARTIAL_SZ)    ; 256
%define _RDI_SAVE       (_XMM_SAVE + XMM_SAVE_SZ)   ; 416

;; FRAME_SZ must be a multiple of 32 (keeps rsp 32-byte aligned after
;; the 'and rsp,-32' alignment step).
;; Linux:   only the _PARTIAL region.
;; Windows: _PARTIAL + xmm saves + rdi save, rounded up to next 32.
%ifdef LINUX
%define FRAME_SZ        (_PARTIAL + PARTIAL_SZ)
%else
%define FRAME_SZ        ((_RDI_SAVE + RDI_SAVE_SZ + 31) & ~31)
%endif


;; Zero the 256-byte _PARTIAL buffer on the stack
%macro ZERO_PARTIAL 0
        vpxorq          ymm31, ymm31, ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*0], ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*1], ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*2], ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*3], ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*4], ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*5], ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*6], ymm31
        vmovdqu64       [rsp + _PARTIAL + 32*7], ymm31
%endmacro

;; Copy RBP bytes from [R12] to [rsp + _PARTIAL] using 32-byte YMM stores.
;; Masked load/store for the final < 32-byte tail.  Caller must have already
;; called ZERO_PARTIAL so uncopied bytes remain zero.
;; Clobbers: rax, rcx, rdx, ymm30, k1
%macro COPY_MSG_TO_PARTIAL 1
        test            rbp, rbp
        jz              %%copy_done
        mov             rax, rbp
        xor             ecx, ecx
%%copy_block:
        cmp             rax, 32
        jb              %%copy_tail
        vmovdqu8        ymm30, [r12 + rcx]
        vmovdqu8        [rsp + _PARTIAL + rcx], ymm30
        add             ecx, 32
        sub             rax, 32
        jnz             %%copy_block
        jmp             %%copy_done
%%copy_tail:
        mov             rdx, 1
        shlx            rdx, rdx, rax
        dec             rdx
        kmovd           k1, edx
        vmovdqu8        ymm30{k1}{z}, [r12 + rcx]
        vmovdqu8        [rsp + _PARTIAL + rcx]{k1}, ymm30
%%copy_done:
%endmacro

;; ============================================================================
;; HMAC-SHA3 submit function template
;; ============================================================================
%macro HMAC_SHA3_SUBMIT 5
%define %%SFX           %1      ; [in] variant suffix (224 / 256 / 384 / 512)
%define %%RATE          %2      ; [in] rate in bytes  (144 / 136 / 104 / 72)
%define %%DSIZ          %3      ; [in] digest size in bytes (28 / 32 / 48 / 64)
%define %%DQW           %4      ; [in] complete 8-byte qwords in digest (3 / 4 / 6 / 8)
%define %%DREM          %5      ; [in] remaining bytes after qwords (4 / 0 / 0 / 0)

;; Register aliases
%define job             rbx     ; IMB_JOB pointer
%define saved_rsp       r15     ; pre-alignment rsp (restored in epilogue)
%define data_ptr        r12     ; ipad / msg / opad / partial block pointer
%define msg_len         r11     ; message byte count, then partial remainder
%define copy_len        rbp     ; byte count passed to COPY_MSG_TO_PARTIAL
%define tag_out         rdi     ; job->auth_tag_output

;; ---------------------------------------------------------------------------
align_function
MKGLOBAL(hmac_sha3_ %+ %%SFX %+ _submit_avx512,function,internal)
hmac_sha3_ %+ %%SFX %+ _submit_avx512:
        endbranch64
        push            rbp
        push            rbx
        push            r12
        push            r13
        push            r14
        push            r15
        mov             saved_rsp, rsp  ; save pre-alignment rsp for epilogue
        and             rsp, -32        ; align _PARTIAL buffer to 32 bytes
        sub             rsp, FRAME_SZ
        mov             job, arg1

%ifndef LINUX
        ;; Windows x64 ABI: xmm6-xmm15 and rdi are callee-saved.
        ;; Save them now, before keccak_1600_init_state clobbers ymm6-ymm15.
        movdqa          [rsp + _XMM_SAVE + 0*16], xmm6
        movdqa          [rsp + _XMM_SAVE + 1*16], xmm7
        movdqa          [rsp + _XMM_SAVE + 2*16], xmm8
        movdqa          [rsp + _XMM_SAVE + 3*16], xmm9
        movdqa          [rsp + _XMM_SAVE + 4*16], xmm10
        movdqa          [rsp + _XMM_SAVE + 5*16], xmm11
        movdqa          [rsp + _XMM_SAVE + 6*16], xmm12
        movdqa          [rsp + _XMM_SAVE + 7*16], xmm13
        movdqa          [rsp + _XMM_SAVE + 8*16], xmm14
        movdqa          [rsp + _XMM_SAVE + 9*16], xmm15
        mov             [rsp + _RDI_SAVE], rdi
%endif

        ;; ================================================================
        ;; INNER HASH: SHA3(ipad_block || msg)
        ;; ================================================================

        call            keccak_1600_init_state

        ;; Absorb ipad block — exactly %%RATE bytes into sponge
        mov             data_ptr, [job + _auth_key_xor_ipad]
        ABSORB_BYTES    data_ptr, 0, %%RATE
        call            keccak1600_block_64bit

        ;; Set up message pointer and length
        mov             data_ptr, [job + _src]
        add             data_ptr, [job + _hash_start_src_offset]   ; data_ptr = msg base
        mov             msg_len, [job + _msg_len_to_hash_in_bytes]

        ;; Compute full block count = msg_len / %%RATE (compile-time constant divisor).
        ;; Remainder (< %%RATE) stays in msg_len for the padded partial block later.
        ;; div is called once; Keccak permutation dominates per-block cost.
        mov             rax, msg_len
        xor             edx, edx
        mov             rcx, %%RATE
        div             rcx                     ;; rax = block count, rdx = remainder
        mov             msg_len, rdx            ;; msg_len = remaining bytes < %%RATE

        ;; Absorb all full rate-sized blocks — 1 backward jump per block
        test            rax, rax
        jz              %%inner_loop_done
align_loop
%%inner_loop:
        ABSORB_BYTES    data_ptr, 0, %%RATE
        call            keccak1600_block_64bit
        add             data_ptr, %%RATE
        dec             rax
        jnz             %%inner_loop
align_label
%%inner_loop_done:
        ;; msg_len = remaining bytes (< %%RATE), data_ptr = partial msg start
        ZERO_PARTIAL
        mov             copy_len, msg_len       ; copy_len = byte count for COPY_MSG_TO_PARTIAL
        COPY_MSG_TO_PARTIAL %%RATE
        ;; SHA3 padding (FIPS 202 §B.2): domain suffix 0x06 at first byte
        ;; after message, multi-rate pad end-bit 0x80 at last byte of block
        mov             byte [rsp + _PARTIAL + msg_len], 0x06
        xor             byte [rsp + _PARTIAL + %%RATE - 1], 0x80

        ;; Absorb padded partial block
        lea             rax, [rsp + _PARTIAL]
        ABSORB_BYTES    rax, 0, %%RATE
        call            keccak1600_block_64bit

        ;; Squeeze inner digest once, directly into a fresh _PARTIAL —
        ;; pad in-place and absorb without a separate _DIGEST staging copy.
        ZERO_PARTIAL
%assign %%I 0
%rep %%DQW
        vmovq           [rsp + _PARTIAL + 8*%%I], xmm %+ %%I
%assign %%I (%%I+1)
%endrep
%if %%DREM > 0
        vmovd           DWORD [rsp + _PARTIAL + 8*%%DQW], xmm %+ %%DQW
%endif
        mov             byte [rsp + _PARTIAL + %%DSIZ], 0x06
        xor             byte [rsp + _PARTIAL + %%RATE - 1], 0x80

        ;; ================================================================
        ;; OUTER HASH: SHA3(opad_block || inner_digest)
        ;; ================================================================

        call            keccak_1600_init_state

        ;; Absorb opad block — exactly %%RATE bytes
        mov             data_ptr, [job + _auth_key_xor_opad]
        ABSORB_BYTES    data_ptr, 0, %%RATE
        call            keccak1600_block_64bit

        ;; Absorb padded inner-digest block (_PARTIAL already set up above)
        lea             rax, [rsp + _PARTIAL]
        ABSORB_BYTES    rax, 0, %%RATE
        call            keccak1600_block_64bit

        ;; Squeeze outer digest into _PARTIAL, then masked-store to output.
%assign %%I 0
%rep %%DQW
        vmovq           [rsp + _PARTIAL + 8*%%I], xmm %+ %%I
%assign %%I (%%I+1)
%endrep
%if %%DREM > 0
        vmovd           DWORD [rsp + _PARTIAL + 8*%%DQW], xmm %+ %%DQW
%endif

        ;; Write auth_tag_output_len bytes to job->auth_tag_output.
        ;; bzhi with index >= 64 leaves all bits set (handles SHA3-512 len=64).
        mov             rcx, [job + _auth_tag_output_len_in_bytes]
        mov             tag_out, [job + _auth_tag_output]
        mov             rax, -1
        bzhi            rax, rax, rcx
        kmovq           k1, rax
        vmovdqu8        zmm0, [rsp + _PARTIAL]
        vmovdqu8        [tag_out]{k1}, zmm0

align_label
%%store_done:

%ifdef SAFE_DATA
        ;; Zero stack buffers that held key-derived / plaintext material.
        vpxorq          ymm0, ymm0, ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*0], ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*1], ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*2], ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*3], ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*4], ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*5], ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*6], ymm0
        vmovdqu64       [rsp + _PARTIAL + 32*7], ymm0
        ;; Zero all ZMM registers using the standard library macro.
        ;; XMM-form vpxorq + vzeroupper is faster than ZMM-form and
        ;; clears all 512 bits (upper 256 bits zeroed by vzeroupper).
        clear_scratch_zmms_asm
%endif

        or              dword [job + _status], IMB_STATUS_COMPLETED_AUTH
        mov             rax, job        ; return job

%ifndef LINUX
        ;; Restore Windows callee-saved registers before releasing the frame.
        movdqa          xmm6,  [rsp + _XMM_SAVE + 0*16]
        movdqa          xmm7,  [rsp + _XMM_SAVE + 1*16]
        movdqa          xmm8,  [rsp + _XMM_SAVE + 2*16]
        movdqa          xmm9,  [rsp + _XMM_SAVE + 3*16]
        movdqa          xmm10, [rsp + _XMM_SAVE + 4*16]
        movdqa          xmm11, [rsp + _XMM_SAVE + 5*16]
        movdqa          xmm12, [rsp + _XMM_SAVE + 6*16]
        movdqa          xmm13, [rsp + _XMM_SAVE + 7*16]
        movdqa          xmm14, [rsp + _XMM_SAVE + 8*16]
        movdqa          xmm15, [rsp + _XMM_SAVE + 9*16]
        mov             rdi,   [rsp + _RDI_SAVE]
%endif

        mov             rsp, saved_rsp  ; restore pre-alignment rsp
        pop             r15
        pop             r14
        pop             r13
        pop             r12
        pop             rbx
        pop             rbp
        ret

%undef job
%undef saved_rsp
%undef data_ptr
%undef msg_len
%undef copy_len
%undef tag_out
%endmacro

;; ============================================================================
;; Instantiate all four variants
;;
;;              suffix  rate  dsiz  dqw  drem
;; ============================================================================
mksection .text

HMAC_SHA3_SUBMIT  224,  144,   28,   3,    4
HMAC_SHA3_SUBMIT  256,  136,   32,   4,    0
HMAC_SHA3_SUBMIT  384,  104,   48,   6,    0
HMAC_SHA3_SUBMIT  512,   72,   64,   8,    0

mksection .note.GNU-stack noalloc noexec nowrite progbits
