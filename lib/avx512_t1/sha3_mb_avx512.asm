; Copyright (c) 2026, Intel Corporation
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
;   * Redistributions of source code must retain the above copyright notice,
;     this list of conditions and the following disclaimer.
;   * Redistributions in binary form must reproduce the above copyright notice,
;     this list of conditions and the following disclaimer in the documentation
;     and/or other materials provided with the distribution.
;   * Neither the name of Intel Corporation nor the names of its contributors
;     may be used to endorse or promote products derived from this software
;     without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

; AVX-512 SHA3 multi-buffer (4-lane) submit / flush.

; ============================================================
; Named register aliases – used throughout SHA3_OOO_SUBMIT_FLUSH_FN
; ============================================================
%define state           rbx     ; MB_MGR_SHA3_OOO* (callee-saved)
%define lane            r12     ; current / selected lane index (0-3)
%define min_idx         r13     ; index of lane with minimum length
%define num_blocks      r14     ; number of full rate-blocks to absorb
%define remaining       r15     ; bytes left after full blocks (min_len % rate)
%define min_len         rbp     ; minimum message length across active lanes

%define job             rsi     ; IMB_JOB* (submit: input arg; flush: result)
%define lane_data_off   rax     ; scratch: imul result for ldata[] offset
;
; Public symbols (function:internal = IMB_DLL_LOCAL):
;   submit_job_sha3_224_avx512, flush_job_sha3_224_avx512
;   submit_job_sha3_256_avx512, flush_job_sha3_256_avx512
;   submit_job_sha3_384_avx512, flush_job_sha3_384_avx512
;   submit_job_sha3_512_avx512, flush_job_sha3_512_avx512

default rel

%include "include/sha3_common.inc"
%include "include/imb_job.inc"
%include "include/align_avx512.inc"
%include "include/mb_mgr_datastruct.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    [rsp + 5*8]
%endif

; ============================================================
; Inline state load / save  (ymm0-ymm24 <-> memory)
; %1 = base register pointing at keccak_state[0]
; ============================================================
%macro X4_LOAD_STATE 1
%assign %%I 0
%rep 25
        vmovdqu64  APPEND(ymm,%%I), [%1 + %%I*32]
%assign %%I (%%I+1)
%endrep
%endmacro

%macro X4_SAVE_STATE 1
%assign %%I 0
%rep 25
        vmovdqu64  [%1 + %%I*32], APPEND(ymm,%%I)
%assign %%I (%%I+1)
%endrep
%endmacro

; ============================================================
; SHA3_OOO_SUBMIT_FLUSH_FN  fn_name, rate, digest_sz, is_submit
;
; Register allocation (callee-saved throughout):
;   state  = state (MB_MGR_SHA3_OOO*)
;   lane  = lane  (submit) / first non-null lane (flush)
;   min_idx  = min_idx
;   num_blocks  = num_blocks
;   remaining  = remaining bytes
;   min_len  = min_len
; Caller-saved (freely clobbered): rax, arg1-arg4, r8-r11
; Note: keccak1600_block_64bit clobbers min_idx and num_blocks; the absorb loop saves/restores them around each call.
; ============================================================
extern keccak1600_block_64bit

; ============================================================
; Windows x64 ABI: xmm6-xmm15 and rdi/job are non-volatile.
; We save them in a small stack frame allocated in the prologue.
;
; After 6 pushes (48 bytes) plus the caller's return address (8 bytes)
; the stack is offset 56 bytes from 16-byte alignment → rsp mod 16 = 8.
; Subtracting WIN_FRAME_SIZE = 232 (≡ 8 mod 16) restores 16-byte alignment.
;
;   [rsp +   0 ..  159]  xmm6–xmm15  (10 × 16 bytes)
;   [rsp + 160]          rdi
;   [rsp + 168]          job (rsi)
;   [rsp + 176]          rbx (state)
;   [rsp + 184]          rbp (min_len)
;   [rsp + 192]          r12 (lane)
;   [rsp + 200]          r13 (min_idx)
;   [rsp + 208]          r14 (num_blocks)
;   [rsp + 216]          r15 (remaining)
;   [rsp + 224 ..  231]  alignment padding
; ============================================================
%ifidn __OUTPUT_FORMAT__, win64
%define WIN_FRAME_SIZE   232
%define WIN_XMM_OFF        0
%define WIN_RDI_OFF      160
%define WIN_RSI_OFF      168
%define WIN_RBX_OFF      176
%define WIN_RBP_OFF      184
%define WIN_R12_OFF      192
%define WIN_R13_OFF      200
%define WIN_R14_OFF      208
%define WIN_R15_OFF      216
%endif

%macro SHA3_OOO_SUBMIT_FLUSH_FN 4
%xdefine %%FN      %1      ; function name
%xdefine %%RATE    %2      ; SHA3 rate in bytes
%xdefine %%DSIZ    %3      ; digest size in bytes
%xdefine %%SUB     %4      ; operation mode: 1 = submit, 0 = flush

align_function
MKGLOBAL(%%FN,function,internal)
%%FN:
        push    remaining
        push    num_blocks
        push    min_idx
        push    lane
        push    state
        push    min_len
%ifidn __OUTPUT_FORMAT__, win64
        sub     rsp, WIN_FRAME_SIZE
        vmovdqa [rsp + WIN_XMM_OFF +  0*16], xmm6
        vmovdqa [rsp + WIN_XMM_OFF +  1*16], xmm7
        vmovdqa [rsp + WIN_XMM_OFF +  2*16], xmm8
        vmovdqa [rsp + WIN_XMM_OFF +  3*16], xmm9
        vmovdqa [rsp + WIN_XMM_OFF +  4*16], xmm10
        vmovdqa [rsp + WIN_XMM_OFF +  5*16], xmm11
        vmovdqa [rsp + WIN_XMM_OFF +  6*16], xmm12
        vmovdqa [rsp + WIN_XMM_OFF +  7*16], xmm13
        vmovdqa [rsp + WIN_XMM_OFF +  8*16], xmm14
        vmovdqa [rsp + WIN_XMM_OFF +  9*16], xmm15
        mov     [rsp + WIN_RDI_OFF], rdi
        mov     [rsp + WIN_RSI_OFF], job
        mov     [rsp + WIN_RBX_OFF], state
        mov     [rsp + WIN_RBP_OFF], min_len
        mov     [rsp + WIN_R12_OFF], lane
        mov     [rsp + WIN_R13_OFF], min_idx
        mov     [rsp + WIN_R14_OFF], num_blocks
        mov     [rsp + WIN_R15_OFF], remaining
%endif
        mov     state, arg1              ; MB_MGR_SHA3_OOO*
        mov     job, arg2              ; IMB_JOB*

%if %%SUB
        ;; --- SUBMIT: allocate free lane ---
        mov     lane, [state + _sha3_unused_lanes]
        mov     min_idx, lane
        and     min_idx, 0xF           ; extract lane index (low nibble)
        shr     lane, 4
        mov     [state + _sha3_unused_lanes], lane
        inc     dword [state + _sha3_num_lanes_inuse]

        mov     rax, [job + _src]
        add     rax, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _sha3_args_data_ptr + min_idx*8], rax

        ;; zero state words for this lane
        ;; Use vpbroadcastq to write all 4 lane slots at once, then
        ;; overwrite with a masked store so only lane min_idx is zeroed.
        ;; This avoids store-to-load forwarding stalls that arise when
        ;; a scalar qword store is immediately followed by a wide YMM load
        ;; to the same cache line (different granularity -> forwarding fail).
        vpxorq  ymm31, ymm31, ymm31
        mov     eax, 1
        shlx    eax, eax, r13d          ; eax = 1 << lane
        kmovd   k1, eax                 ; k1  = write-mask: only lane min_idx
%assign %%W 0
%rep 25
        vmovdqu64  ymm30, [state + _sha3_args_kstate + %%W*32]
        vmovdqu64  ymm30 {k1}, ymm31    ; zero only the selected lane slot
        vmovdqu64  [state + _sha3_args_kstate + %%W*32], ymm30
%assign %%W (%%W+1)
%endrep
        imul    rax, min_idx, _SHA3_LANE_DATA_size
        mov     [state + _sha3_ldata + rax + _sha3_job_in_lane], job
        mov     dword [state + _sha3_ldata + rax + _sha3_finalized], 0

        mov     rcx, [job + _msg_len_to_hash_in_bytes]
        mov     [state + _sha3_lens + min_idx*8], rcx

        cmp     dword [state + _sha3_num_lanes_inuse], MAX_SHA3_LANES
        jne     %%ret_null
%else
        ;; --- FLUSH: find first occupied lane ---
        cmp     dword [state + _sha3_num_lanes_inuse], 0
        je      %%ret_null
        xor     lane, lane
%%find_lane:
        imul    rax, lane, _SHA3_LANE_DATA_size
        cmp     qword [state + _sha3_ldata + rax + _sha3_job_in_lane], 0
        jne     %%lane_found
        inc     lane
        jmp     %%find_lane
%%lane_found:
%endif

        ;; =============================================
        ;; do { find-min; absorb; finalize } while lens[min]!=0
        ;; =============================================
align_loop
%%do_loop:

%if %%SUB
        mov     min_len, [state + _sha3_lens + 0*8]
        xor     min_idx, min_idx
        mov     rax, [state + _sha3_lens + 1*8]
        cmp     rax, min_len
        cmovb   min_len, rax
        mov     rcx, 1
        cmovb   min_idx, rcx
        mov     rax, [state + _sha3_lens + 2*8]
        cmp     rax, min_len
        cmovb   min_len, rax
        mov     rcx, 2
        cmovb   min_idx, rcx
        mov     rax, [state + _sha3_lens + 3*8]
        cmp     rax, min_len
        cmovb   min_len, rax
        mov     rcx, 3
        cmovb   min_idx, rcx
%%min_done:
%else
        mov     min_idx, lane
        mov     min_len, [state + _sha3_lens + lane*8]
        xor     rax, rax
        ; SIMD: gather job_in_lane[0..3], build null-lane mask,
        ;       broadcast live lane's data_ptr into null slots,
        ;       and preset null-lane lens to UINT64_MAX so they
        ;       never win the subsequent scalar min-find.
        mov     rax,  [state + _sha3_ldata + 0*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        mov     arg3, [state + _sha3_ldata + 1*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        mov     arg4, [state + _sha3_ldata + 2*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        mov     r11,  [state + _sha3_ldata + 3*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vmovq      xmm27, rax
        vpinsrq    xmm27, xmm27, arg3, 1
        vmovq      xmm28, arg4
        vpinsrq    xmm28, xmm28, r11,  1
        vinserti32x4 ymm27, ymm27, xmm28, 1        ; ymm27 = job_in_lane[0..3]
        vpxorq     ymm28, ymm28, ymm28
        vpcmpeqq   k2, ymm27, ymm28                ; k2 = null-lane mask

        vpbroadcastq ymm29, [state + _sha3_args_data_ptr + lane*8]
        vmovdqa64   ymm28, [state + _sha3_args_data_ptr]
        vmovdqa64   ymm28 {k2}, ymm29              ; fill null slots with live data_ptr
        vmovdqa64   [state + _sha3_args_data_ptr], ymm28

        vpternlogq  ymm27, ymm27, ymm27, 0xFF       ; all-ones = UINT64_MAX
        vmovdqa64   ymm29, [state + _sha3_lens]
        vmovdqa64   ymm29 {k2}, ymm27              ; null slots: lens = UINT64_MAX (won't win min)
        vmovdqa64   [state + _sha3_lens], ymm29

        ; scalar min-find: null lanes have UINT64_MAX so they are harmless;
        ; lane lane has lens[lane]==min_len so it won't update min_idx either.
        xor     rax, rax
%%fill_live:
        mov     arg3, [state + _sha3_lens + rax*8]
        cmp     arg3, min_len
        jae     %%fill_next
        mov     min_len, arg3
        mov     min_idx, rax
%%fill_next:
        inc     rax
        cmp     rax, MAX_SHA3_LANES
        jb      %%fill_live
%endif

        ;; num_blocks = min_len / RATE,  remaining = min_len % RATE
        mov     rax, min_len
        xor     rdx, rdx        ; DIV uses implicit RDX:RAX on all ABIs
        mov     arg4, %%RATE
        div     arg4
        mov     num_blocks, rax
        mov     remaining, rdx

        ;; subtract num_blocks*RATE from all lens
        ;; rdx already holds min_len MOD RATE, so num_blocks*RATE = min_len - rdx
        sub     min_len, remaining
        mov     rax, min_len
        sub     qword [state + _sha3_lens + 0*8], rax
        sub     qword [state + _sha3_lens + 1*8], rax
        sub     qword [state + _sha3_lens + 2*8], rax
        sub     qword [state + _sha3_lens + 3*8], rax

        ;; absorb full blocks
        test    num_blocks, num_blocks
        jz      %%no_absorb

        lea     rax, [state + _sha3_args_kstate]
        X4_LOAD_STATE rax

        mov     r8,  [state + _sha3_args_data_ptr + 0*8]
        mov     r9,  [state + _sha3_args_data_ptr + 1*8]
        mov     r10, [state + _sha3_args_data_ptr + 2*8]
        mov     r11, [state + _sha3_args_data_ptr + 3*8]
align_loop
%%absorb_loop:
        ABSORB_BYTES_x4 r8, r9, r10, r11, 0, %%RATE
        add     r8,  %%RATE
        add     r9,  %%RATE
        add     r10, %%RATE
        add     r11, %%RATE
        push    min_idx                    ; keccak1600_block_64bit clobbers min_idx (round ctr) and num_blocks (RC ptr)
        push    num_blocks
        call    keccak1600_block_64bit
        pop     num_blocks
        pop     min_idx
        dec     num_blocks
        jnz     %%absorb_loop

        lea     rax, [state + _sha3_args_kstate]
        X4_SAVE_STATE rax
        mov     [state + _sha3_args_data_ptr + 0*8], r8
        mov     [state + _sha3_args_data_ptr + 1*8], r9
        mov     [state + _sha3_args_data_ptr + 2*8], r10
        mov     [state + _sha3_args_data_ptr + 3*8], r11
align_label
%%no_absorb:
        ;; finalize min lane if padding not yet applied
        imul    rax, min_idx, _SHA3_LANE_DATA_size
        cmp     dword [state + _sha3_ldata + rax + _sha3_finalized], 1
        je      %%check_done

        ;; zero extra_block[0..RATE-1]
        vpxorq  ymm31, ymm31, ymm31
        lea     arg1, [state + _sha3_ldata + rax]  ; arg1 = &ldata[min_idx]
%assign %%OFF 0
%assign %%REM %%RATE
%rep (%%RATE / 32)
        vmovdqu64  [arg1 + _sha3_extra_block + %%OFF], ymm31
%assign %%OFF (%%OFF+32)
%assign %%REM (%%REM-32)
%endrep
%if %%REM >= 16
        vmovdqu64  [arg1 + _sha3_extra_block + %%OFF], xmm31
%assign %%OFF (%%OFF+16)
%assign %%REM (%%REM-16)
%endif
%if %%REM >= 8
        vmovq      [arg1 + _sha3_extra_block + %%OFF], xmm31
%endif

        ;; copy remaining message bytes into extra_block
        ;; arg1 = &ldata[min_idx], so arg1+_sha3_extra_block = &extra_block[0]
        mov     arg2, [state + _sha3_args_data_ptr + min_idx*8]
        lea     arg1, [arg1 + _sha3_extra_block]  ; arg1 = &extra_block[0]
        mov     arg4, remaining
        test    arg4, arg4
        jz      %%no_copy
%ifndef LINUX
        mov     r10, rdi                 ; preserve nonvolatile regs for Win64 ABI
        mov     r11, job
%endif
        mov     rdi, arg1                ; rep movsb uses rdi/job/rcx implicitly
        mov     job, arg2
        mov     rcx, arg4
        rep     movsb
        mov     arg1, rdi                ; after copy: arg1 = &extra_block[remaining]
%ifndef LINUX
        mov     rdi, r10
        mov     job, r11
%endif
%%no_copy:
        ;; arg1 points at extra_block[remaining] -- apply domain byte
        xor     byte [arg1], SHA3_MRATE_PADDING

        ;; flip EOM bit at extra_block[RATE-1]
        imul    rax, min_idx, _SHA3_LANE_DATA_size
        xor     byte [state + _sha3_ldata + rax + _sha3_extra_block + %%RATE - 1], 0x80

        ;; data_ptr[min_idx] = &extra_block[0]
        lea     rax, [state + _sha3_ldata + rax + _sha3_extra_block]
        mov     [state + _sha3_args_data_ptr + min_idx*8], rax

        ;; lens[min_idx] = RATE
        mov     qword [state + _sha3_lens + min_idx*8], %%RATE

        ;; finalized = 1  (padding has been applied)
        imul    rax, min_idx, _SHA3_LANE_DATA_size
        mov     dword [state + _sha3_ldata + rax + _sha3_finalized], 1

%%check_done:
        cmp     qword [state + _sha3_lens + min_idx*8], 0
        jnz     %%do_loop

        ;; ==========================================================
        ;; collect result
        ;; ==========================================================
        imul    rax, min_idx, _SHA3_LANE_DATA_size
        mov     rax, [state + _sha3_ldata + rax + _sha3_job_in_lane]   ; rax = IMB_JOB*

        mov     arg4, [state + _sha3_unused_lanes]
        shl     arg4, 4
        or      arg4, min_idx
        mov     [state + _sha3_unused_lanes], arg4
        dec     dword [state + _sha3_num_lanes_inuse]

        ;; write digest from interleaved state
        mov     arg1, [rax + _auth_tag_output]
%assign %%W 0
%rep (%%DSIZ / 8)
        mov     r11, [state + _sha3_args_kstate + %%W*32 + min_idx*8]
        mov     [arg1 + %%W*8], r11
%assign %%W (%%W+1)
%endrep
%if (%%DSIZ % 8) != 0
        mov     r11d, [state + _sha3_args_kstate + %%W*32 + min_idx*8]
        mov     [arg1 + %%W*8], r11d
%endif

        or      dword [rax + _status], IMB_STATUS_COMPLETED_AUTH

        imul    arg4, min_idx, _SHA3_LANE_DATA_size
        mov     qword [state + _sha3_ldata + arg4 + _sha3_job_in_lane], 0

%ifdef SAFE_DATA
        ;; zero extra_block of completed lane (clear sensitive message data)
        vpxorq  ymm31, ymm31, ymm31
        lea     arg1, [state + _sha3_ldata + arg4]
%assign %%OFF 0
%assign %%REM %%RATE
%rep (%%RATE / 32)
        vmovdqu64  [arg1 + _sha3_extra_block + %%OFF], ymm31
%assign %%OFF (%%OFF+32)
%assign %%REM (%%REM-32)
%endrep
%if %%REM >= 16
        vmovdqu64  [arg1 + _sha3_extra_block + %%OFF], xmm31
%assign %%OFF (%%OFF+16)
%assign %%REM (%%REM-16)
%endif
%if %%REM >= 8
        vmovq      [arg1 + _sha3_extra_block + %%OFF], xmm31
%endif
%endif ; SAFE_DATA

%%return:
%ifidn __OUTPUT_FORMAT__, win64
        vmovdqa xmm6,  [rsp + WIN_XMM_OFF +  0*16]
        vmovdqa xmm7,  [rsp + WIN_XMM_OFF +  1*16]
        vmovdqa xmm8,  [rsp + WIN_XMM_OFF +  2*16]
        vmovdqa xmm9,  [rsp + WIN_XMM_OFF +  3*16]
        vmovdqa xmm10, [rsp + WIN_XMM_OFF +  4*16]
        vmovdqa xmm11, [rsp + WIN_XMM_OFF +  5*16]
        vmovdqa xmm12, [rsp + WIN_XMM_OFF +  6*16]
        vmovdqa xmm13, [rsp + WIN_XMM_OFF +  7*16]
        vmovdqa xmm14, [rsp + WIN_XMM_OFF +  8*16]
        vmovdqa xmm15, [rsp + WIN_XMM_OFF +  9*16]
        mov     rdi, [rsp + WIN_RDI_OFF]
        mov     job, [rsp + WIN_RSI_OFF]
        mov     state, [rsp + WIN_RBX_OFF]
        mov     min_len, [rsp + WIN_RBP_OFF]
        mov     lane, [rsp + WIN_R12_OFF]
        mov     min_idx, [rsp + WIN_R13_OFF]
        mov     num_blocks, [rsp + WIN_R14_OFF]
        mov     remaining, [rsp + WIN_R15_OFF]
        add     rsp, WIN_FRAME_SIZE
%endif
        pop     min_len
        pop     state
        pop     lane
        pop     min_idx
        pop     num_blocks
        pop     remaining
        ret

%%ret_null:
        xor     eax, eax
        jmp     %%return
%endmacro

; ============================================================
section .text
; ============================================================

SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_224_avx512, SHA3_224_RATE, SHA3_224_DIGEST_SZ, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_224_avx512,  SHA3_224_RATE, SHA3_224_DIGEST_SZ, 0
SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_256_avx512, SHA3_256_RATE, SHA3_256_DIGEST_SZ, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_256_avx512,  SHA3_256_RATE, SHA3_256_DIGEST_SZ, 0
SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_384_avx512, SHA3_384_RATE, SHA3_384_DIGEST_SZ, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_384_avx512,  SHA3_384_RATE, SHA3_384_DIGEST_SZ, 0
SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_512_avx512, SHA3_512_RATE, SHA3_512_DIGEST_SZ, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_512_avx512,  SHA3_512_RATE, SHA3_512_DIGEST_SZ, 0

section .note.GNU-stack noalloc noexec nowrite progbits
