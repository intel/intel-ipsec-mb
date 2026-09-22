;;
;; Copyright (c) 2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;;
;; HMAC-SHA3-{224,256,384,512} single-buffer AVX-512 submit.
;;
;; IMB_JOB *hmac_sha3_submit_avx512(IMB_JOB *job)
;;
;; One function serves all four digest sizes.  The rate is read from
;; job->hash_alg at run time and the digest size follows from it as
;; (200 - rate) / 2, so the block loop, the padding and the squeeze are all
;; shared instead of being instantiated once per algorithm.
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
%include "include/reg_sizes.inc"

extern keccak1600_block_64bit
extern keccak_1600_init_state

;; Rates of the four HMAC-SHA3 algorithms, one byte each, with HMAC-SHA3-224 in
;; the least significant byte.  Indexed by (hash_alg - HMAC_SHA3_ALG_FIRST) this
;; turns the rate into immediate arithmetic, so no lookup table and no
;; relocation are needed.  The digest size follows from the rate as
;; (200 - rate) / 2, so it needs no table of its own.
%define HMAC_SHA3_ALG_FIRST     58      ; IMB_AUTH_HMAC_SHA3_224 .. _512 are contiguous
                                        ; (checked at compile time by the
                                        ;  _Static_assert in arch_avx512_type1.h)
%define HMAC_SHA3_RATES_PACKED \
        (SHA3_224_RATE | (SHA3_256_RATE << 8) | (SHA3_384_RATE << 16) | \
        (SHA3_512_RATE << 24))

mksection .text

;; Stack frame layout (offsets from rsp after alignment and sub):
;;
;;   [rsp + _PARTIAL]  256-byte scratch buffer (padded partial block, and
;;                     the squeeze staging area for the inner/outer digest)
;;   [rsp + _XMM_SAVE] xmm6-xmm15 save area  (Windows only, 10 * 16 = 160 B)
;;   [rsp + _RDI_SAVE] rdi save slot          (Windows only, 8 B)
;;   --- pad to next multiple of 32 ---
;;
%define PARTIAL_SZ      256             ; 8 x 32-byte YMM = 256 bytes
%define XMM_SAVE_SZ     (10 * 16)       ; xmm6-xmm15 = 160 bytes
%define RDI_SAVE_SZ     8               ; one GP register

%define _PARTIAL        0
%define _XMM_SAVE       (_PARTIAL  + PARTIAL_SZ)   ; 256
%define _RDI_SAVE       (_XMM_SAVE + XMM_SAVE_SZ)   ; 416

;; FRAME_SZ must be a multiple of 32 (keeps rsp 32-byte aligned after
;; the 'and rsp,-32' alignment step).
;; Linux:   just the _PARTIAL region.
;; Windows: that plus xmm saves and rdi save, rounded up to next 32.
%ifdef LINUX
%define FRAME_SZ        (_PARTIAL + PARTIAL_SZ)
%else
%define FRAME_SZ        (_RDI_SAVE + RDI_SAVE_SZ)
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

;; ============================================================================
;; HMAC-SHA3 submit function, shared by all four digest sizes
;; ============================================================================

;; Register aliases
%define job             rbx     ; IMB_JOB pointer
%define saved_rsp       r15     ; pre-alignment rsp (restored in epilogue)
%define data_ptr        r12     ; ipad / msg / opad / partial block pointer
%define msg_len         r11     ; message byte count, then partial remainder
%define tag_out         rdi     ; job->auth_tag_output
%define rate            r10     ; sponge rate of job->hash_alg, in bytes
%define dsiz            r13     ; digest size, (200 - rate) / 2
;;
;; Physical register use not covered by the aliases above:
;;   rax, rcx, rdx  scratch, never live across a permutation call
;;   r11            msg_len doubles as the block loop counter, so like rate it
;;                  relies on the permutation preserving it
;;   r13, r14       clobbered by keccak1600_block_64bit, so dsiz is only ever
;;                  live between permutations, never across one
;;   ymm0-ymm24     the sponge state, owned by the keccak routines
;;   ymm30          scratch for the partial-block copy
;;   ymm31          scratch for ZERO_PARTIAL and absorb_block_and_permute
;;   k1             mask for the partial copy and the tag store
;;
;; rate lives in r10 because the permutation preserves every GP register
;; except r13d and r14, so it survives all the calls below.

;; ---------------------------------------------------------------------------
;; absorb_block_and_permute
;;
;; XOR one full rate-sized block into the sponge state and run the Keccak
;; permutation over it.
;;
;; The rate is only known at run time, and only the four SHA3 rates occur
;; (72/104/136/144) - SHAKE128's 168 has no HMAC form.
;;
;; This is a private helper, not an ABI function - arguments are passed in
;; fixed registers and nothing is saved or restored.
;;
;; in:      data_ptr (r12)  pointer to the block, rate bytes
;;          rate     (r10)  sponge rate in bytes
;;          ymm0-ymm24      sponge state, updated in place
;; clobbers ymm31, plus whatever keccak1600_block_64bit clobbers (r13d, r14)
;; ---------------------------------------------------------------------------
align_function
absorb_block_and_permute:
        vmovq           xmm31, [data_ptr + 8*0]
        vpxorq          ymm0, ymm0, ymm31
        vmovq           xmm31, [data_ptr + 8*1]
        vpxorq          ymm1, ymm1, ymm31
        vmovq           xmm31, [data_ptr + 8*2]
        vpxorq          ymm2, ymm2, ymm31
        vmovq           xmm31, [data_ptr + 8*3]
        vpxorq          ymm3, ymm3, ymm31
        vmovq           xmm31, [data_ptr + 8*4]
        vpxorq          ymm4, ymm4, ymm31
        vmovq           xmm31, [data_ptr + 8*5]
        vpxorq          ymm5, ymm5, ymm31
        vmovq           xmm31, [data_ptr + 8*6]
        vpxorq          ymm6, ymm6, ymm31
        vmovq           xmm31, [data_ptr + 8*7]
        vpxorq          ymm7, ymm7, ymm31
        vmovq           xmm31, [data_ptr + 8*8]
        vpxorq          ymm8, ymm8, ymm31
        ;; SHA3_512 rate, 72 bytes, reached
        cmp             rate, SHA3_512_RATE
        jbe             .absorb_done

        vmovq           xmm31, [data_ptr + 8*9]
        vpxorq          ymm9, ymm9, ymm31
        vmovq           xmm31, [data_ptr + 8*10]
        vpxorq          ymm10, ymm10, ymm31
        vmovq           xmm31, [data_ptr + 8*11]
        vpxorq          ymm11, ymm11, ymm31
        vmovq           xmm31, [data_ptr + 8*12]
        vpxorq          ymm12, ymm12, ymm31
        ;; SHA3_384 rate, 104 bytes, reached
        cmp             rate, SHA3_384_RATE
        jbe             .absorb_done

        vmovq           xmm31, [data_ptr + 8*13]
        vpxorq          ymm13, ymm13, ymm31
        vmovq           xmm31, [data_ptr + 8*14]
        vpxorq          ymm14, ymm14, ymm31
        vmovq           xmm31, [data_ptr + 8*15]
        vpxorq          ymm15, ymm15, ymm31
        vmovq           xmm31, [data_ptr + 8*16]
        vpxorq          ymm16, ymm16, ymm31
        ;; SHA3_256 rate, 136 bytes, reached
        cmp             rate, SHA3_256_RATE
        jbe             .absorb_done

        ;; SHA3_224 rate, 144 bytes
        vmovq           xmm31, [data_ptr + 8*17]
        vpxorq          ymm17, ymm17, ymm31
.absorb_done:
        jmp             keccak1600_block_64bit

align_function
MKGLOBAL(hmac_sha3_submit_avx512,function,internal)
hmac_sha3_submit_avx512:
        endbranch64
        push            rbx
        push            r12
        push            r13
        push            r14
        push            r15
        mov             saved_rsp, rsp  ; save pre-alignment rsp for epilogue
        sub             rsp, FRAME_SZ
        and             rsp, -32        ; align _PARTIAL buffer to 32 bytes
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

        ;; Rate of this job's algorithm, from the packed per-algorithm table.
        ;; The four HMAC-SHA3 algorithms are contiguous in IMB_HASH_ALG.
        mov             eax, [job + _hash_alg]
        sub             eax, HMAC_SHA3_ALG_FIRST        ; 0 .. 3
        lea             ecx, [rax*8]                    ; bit position of this entry
        mov             rate, HMAC_SHA3_RATES_PACKED
        shr             rate, cl
        movzx           rate, BYTE(rate)

        ;; ================================================================
        ;; INNER HASH: SHA3(ipad_block || msg)
        ;; ================================================================

        call            keccak_1600_init_state

        ;; Absorb ipad block - exactly rate bytes into sponge
        mov             data_ptr, [job + _auth_key_xor_ipad]
        call            absorb_block_and_permute

        ;; Set up message pointer and length
        mov             data_ptr, [job + _src]
        add             data_ptr, [job + _hash_start_src_offset]   ; data_ptr = msg base
        mov             msg_len, [job + _msg_len_to_hash_in_bytes]

        ;; Absorb all full rate-sized blocks, counting msg_len down as we go.
        ;; msg_len is left holding the remainder (< rate) for the padded
        ;; partial block below.
align_loop
.inner_loop:
        cmp             msg_len, rate
        jb              .inner_loop_done
        call            absorb_block_and_permute
        add             data_ptr, rate
        sub             msg_len, rate
        jmp             .inner_loop

align_label
.inner_loop_done:
        ;; msg_len = remaining bytes (< rate), data_ptr = partial msg start
        ZERO_PARTIAL

        ;; Copy the msg_len (< rate) leftover bytes into the freshly zeroed
        ;; _PARTIAL with 32-byte stores, masking the final < 32-byte tail.
        ;; Bytes not copied stay zero, which is what the padding below needs.
        test            msg_len, msg_len
        jz              .copy_done
        mov             rax, msg_len            ; scratch count, msg_len is needed below
        xor             ecx, ecx
align_loop
.copy_block:
        cmp             rax, 32
        jb              .copy_tail
        vmovdqu8        ymm30, [data_ptr + rcx]
        vmovdqu8        [rsp + _PARTIAL + rcx], ymm30
        add             ecx, 32
        sub             rax, 32
        jz              .copy_done
        jmp             .copy_block

align_label
.copy_tail:
        mov             rdx, 1
        shlx            rdx, rdx, rax
        dec             rdx                     ; rdx = (1 << tail) - 1
        kmovd           k1, edx
        vmovdqu8        ymm30{k1}{z}, [data_ptr + rcx]
        vmovdqu8        [rsp + _PARTIAL + rcx]{k1}, ymm30

align_label
.copy_done:
        ;; SHA3 padding (FIPS 202 §B.2): domain suffix 0x06 at first byte
        ;; after message, multi-rate pad end-bit 0x80 at last byte of block
        mov             byte [rsp + _PARTIAL + msg_len], 0x06
        xor             byte [rsp + _PARTIAL + rate - 1], 0x80

        ;; Absorb padded partial block
        lea             data_ptr, [rsp + _PARTIAL]
        call            absorb_block_and_permute

        ;; Squeeze the inner digest and pad it in place, ready to be absorbed
        ;; by the outer hash.
        ;;
        ;; The digest is 28, 32, 48 or 64 bytes, so the widest case is exactly
        ;; the first eight state qwords.  Squeeze all eight straight into a
        ;; freshly zeroed _PARTIAL and then masked-zero the bytes from dsiz up
        ;; to 64 again, so the block is left holding just the digest followed by
        ;; zeroes for the padding below.  Writing the state out and masking in
        ;; place keeps this store-only; staging via a separate buffer and
        ;; reading it back costs a store-to-load forwarding stall per job.
        ;; Bytes 64..rate-1 are untouched and stay zero because rate >= 72.
        ZERO_PARTIAL
        STATE_EXTRACT   rsp, _PARTIAL, 8

        mov             dsiz, 200
        sub             dsiz, rate
        shr             dsiz, 1                 ; dsiz = (200 - rate) / 2
        mov             rax, -1
        bzhi            rax, rax, dsiz          ; low dsiz bits set
        not             rax                     ; bits dsiz..63 set
        kmovq           k1, rax
        vpxorq          zmm30, zmm30, zmm30
        vmovdqu8        [rsp + _PARTIAL]{k1}, zmm30

        ;; SHA3 padding, as for the message block above
        mov             byte [rsp + _PARTIAL + dsiz], 0x06
        xor             byte [rsp + _PARTIAL + rate - 1], 0x80

        ;; ================================================================
        ;; OUTER HASH: SHA3(opad_block || inner_digest)
        ;; ================================================================

        call            keccak_1600_init_state

        ;; Absorb opad block - exactly rate bytes
        mov             data_ptr, [job + _auth_key_xor_opad]
        call            absorb_block_and_permute

        ;; Absorb padded inner-digest block (_PARTIAL already set up above)
        lea             data_ptr, [rsp + _PARTIAL]
        call            absorb_block_and_permute

        ;; Squeeze the outer digest, then masked-store the tag to the output.
        ;; The tag length never exceeds the digest size, so bytes of the staging
        ;; area past the digest are never copied out.
        ;; _PARTIAL has already been absorbed, so it is reused as the staging
        ;; area for the outer digest.
        STATE_EXTRACT   rsp, _PARTIAL, 8

        ;; Write auth_tag_output_len bytes to job->auth_tag_output.
        ;; bzhi with index >= 64 leaves all bits set (handles SHA3-512 len=64).
        mov             rcx, [job + _auth_tag_output_len_in_bytes]
        mov             tag_out, [job + _auth_tag_output]
        mov             rax, -1
        bzhi            rax, rax, rcx
        kmovq           k1, rax
        vmovdqu8        zmm0, [rsp + _PARTIAL]
        vmovdqu8        [tag_out]{k1}, zmm0

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
%else
        ;; avoid AVX-SSE transition penalty (clear_scratch_zmms_asm
        ;; issues vzeroupper in the SAFE_DATA case)
        vzeroupper
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
        ret
mksection stack-noexec
