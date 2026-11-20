; Copyright (c) 2026, Intel Corporation
; All rights reserved.
;
; SPDX-License-Identifier: BSD-3-Clause

;; SHAKE128 and SHAKE256 x4 functions for ML-KEM and ML-DSA (AVX512VL).
;;
;; Four independent Keccak states are kept interleaved: state word i of
;; lanes 0-3 is held in ymm<i> (ymm0-ymm24), or in memory at offset 32*i of
;; the 808-byte context. The last qword of the context (s[100]) holds the
;; byte position within the current block.
;;
;; The function bodies use the System V argument registers (rdi, rsi, rdx,
;; rcx, r8, r9). On Windows, the exported entry points save rdi, rsi and
;; xmm6-xmm15, move the arguments into those registers and call the body.

%include "include/os.inc"
%include "include/align_avx512.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"

extern keccak1600_block_64bit
extern keccak_1600_init_state

%define SHAKE128_RATE   168
%define SHAKE256_RATE   136

%define X4_STATE_SZ     (25 * 32 + 8)
%define X4_POS          (25 * 32)       ; s[100]: byte position in block

;; Stack frame of the one-shot functions (offsets from rbx = rsp after
;; 'sub rsp, ONESHOT_FRAME_SZ')
%define _os_out         0               ; 4 output pointers
%define _os_outlen      (4 * 8)
%define _os_state       (6 * 8)
%define _os_xmm         (_os_state + X4_STATE_SZ)
%ifdef LINUX
%define ONESHOT_FRAME_SZ _os_xmm
%define OS_ARG7         (rbp + 16)
%else
%define ONESHOT_FRAME_SZ (_os_xmm + 10 * 16)
%define OS_ARG5         (rbp + 16 + 32)
%define OS_ARG6         (rbp + 16 + 40)
%define OS_ARG7         (rbp + 16 + 48)
%endif

;; Windows entry stub frame: xmm6-xmm15 save area plus 8 bytes so that the
;; body is called with a 16-byte aligned stack
%define WIN_STUB_FRAME_SZ (10 * 16 + 8)
;; Offset of the 5th argument from rsp after the stub prologue
%define WIN_STUB_ARG5     (WIN_STUB_FRAME_SZ + 2 * 8 + 8 + 32)

;; Windows entry stub: save rdi, rsi and xmm6-xmm15, move the arguments
;; into the System V registers and call the body
%macro WIN_SYSV_STUB 2
%define %%BODY  %1      ; [in] System V body label
%define %%NARGS %2      ; [in] number of arguments (1 to 6)
        push    rdi
        push    rsi
        sub     rsp, WIN_STUB_FRAME_SZ
%assign i 6
%rep 10
        vmovdqu [rsp + (i - 6) * 16], xmm %+ i
%assign i (i + 1)
%endrep
        mov     rdi, rcx
%if %%NARGS > 1
        mov     rsi, rdx
        mov     rdx, r8
        mov     rcx, r9
%endif
%if %%NARGS > 4
        mov     r8, [rsp + WIN_STUB_ARG5]
        mov     r9, [rsp + WIN_STUB_ARG5 + 8]
%endif
        call    %%BODY
%assign i 6
%rep 10
        vmovdqu xmm %+ i, [rsp + (i - 6) * 16]
%assign i (i + 1)
%endrep
        add     rsp, WIN_STUB_FRAME_SZ
        pop     rsi
        pop     rdi
        ret
%endmacro

mksection .text

;; Load the x4 state into ymm0-ymm24
;; input: rdi - state pointer
align_function
keccak_1600_load_state_x4:
%assign i 0
%rep 25
        vmovdqu64       ymm %+ i, [rdi + i * 32]
%assign i (i + 1)
%endrep
        ret

;; Store the x4 state from ymm0-ymm24
;; input: rdi - state pointer
align_function
keccak_1600_save_state_x4:
%assign i 0
%rep 25
        vmovdqu64       [rdi + i * 32], ymm %+ i
%assign i (i + 1)
%endrep
        ret

;; Add input bytes to the in-memory state, starting at position s[100],
;; when the length is below the rate
;;   r10        [in] state pointer (clobbered)
;;   rsi-r8     [in/out] lane 0-3 input pointers, advanced by the length
;;   r12        [in] length in bytes (clobbered)
;; Clobbers: r9, rbx, r15, k1, ymm29-ymm31
align_function
keccak_1600_partial_add_x4:
        mov     r9, [r10 + X4_POS]
        test    r9d, 7
        jz      .start_aligned_to_4x8

        ;; Start offset is not aligned to the register size
        mov     r15, r9                 ; r15 = s[100]

        and     r9d, 7
        neg     r9d
        add     r9d, 8                  ; register capacity = 8 - (offset % 8)
        cmp     r12d, r9d
        cmovb   r9d, r12d               ; r9d = min(register capacity, length)

        lea     rbx, [rel byte_kmask_0_to_7]
        kmovb   k1, [rbx + r9]          ; message load mask

        mov     rbx, r15
        and     ebx, ~7
        lea     r10, [r10 + rbx * 4]    ; state starting register

        mov     rbx, r15
        and     ebx, 7                  ; rbx = byte offset within the state word

        vmovdqu8        ymm31, [r10]    ; load & store / allocate SB for the register
        vmovdqu8        [r10], ymm31

        ;; XOR 1 to 7 input bytes of each lane into its state word,
        ;; starting at byte offset rbx
        vmovdqu8        xmm31{k1}{z}, [rsi]             ; lane 0
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx]
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx]{k1}, xmm31

        vmovdqu8        xmm31{k1}{z}, [rdx]             ; lane 1
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx + 8]
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx + 8]{k1}, xmm31

        vmovdqu8        xmm31{k1}{z}, [rcx]             ; lane 2
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx + 16]
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx + 16]{k1}, xmm31

        vmovdqu8        xmm31{k1}{z}, [r8]              ; lane 3
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx + 24]
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx + 24]{k1}, xmm31

        sub     r12, r9
        jz      .zero_bytes

        add     rsi, r9
        add     rdx, r9
        add     rcx, r9
        add     r8, r9
        add     r10, 32
        xor     r9, r9
        jmp     .ymm_loop

.start_aligned_to_4x8:
        lea     r10, [r10 + r9 * 4]
        xor     r9, r9

align_loop
.ymm_loop:
        cmp     r12d, 8
        jb      .lt_8_bytes

        vmovq           xmm31, [rsi + r9]               ; 8 bytes of lane 0
        vpinsrq         xmm31, xmm31, [rdx + r9], 1     ; 8 bytes of lane 1
        vmovq           xmm30, [rcx + r9]               ; 8 bytes of lane 2
        vpinsrq         xmm30, xmm30, [r8 + r9], 1      ; 8 bytes of lane 3
        vinserti32x4    ymm31, ymm31, xmm30, 1
        vpxorq          ymm31, ymm31, [r10 + r9 * 4]    ; add data to the state
        vmovdqu64       [r10 + r9 * 4], ymm31
        add     r9, 8
        sub     r12, 8
        jz      .zero_bytes

        jmp     .ymm_loop

align_loop
.zero_bytes:
        add     rsi, r9
        add     rdx, r9
        add     rcx, r9
        add     r8, r9
        ret

align_loop
.lt_8_bytes:
        add     rsi, r9
        add     rdx, r9
        add     rcx, r9
        add     r8, r9
        lea     r10, [r10 + r9 * 4]

        lea     rbx, [rel byte_kmask_0_to_7]
        kmovb   k1, [rbx + r12]         ; message load mask

        vmovdqu8        xmm31{k1}{z}, [rsi]     ; 1 to 7 bytes of lane 0
        vmovdqu8        xmm30{k1}{z}, [rdx]     ; 1 to 7 bytes of lane 1
        vpunpcklqdq     xmm31, xmm31, xmm30     ; interleave lanes 0 and 1
        vmovdqu8        xmm30{k1}{z}, [rcx]     ; 1 to 7 bytes of lane 2
        vmovdqu8        xmm29{k1}{z}, [r8]      ; 1 to 7 bytes of lane 3
        vpunpcklqdq     xmm30, xmm30, xmm29     ; interleave lanes 2 and 3
        vinserti32x4    ymm31, ymm31, xmm30, 1

        vpxorq          ymm31, ymm31, [r10]     ; add data to the state
        vmovdqu64       [r10], ymm31

        add     rsi, r12
        add     rdx, r12
        add     rcx, r12
        add     r8, r12
        ret

;; Extract bytes from the in-memory state to the outputs
;;   r10        [in] state pointer (clobbered)
;;   rdi-rcx    [in/out] lane 0-3 output pointers, advanced by the length
;;   r12        [in] length in bytes (clobbered)
;;   r11        [in] state offset to start extracting from
;; Clobbers: r9, rbx, k1, ymm30-ymm31
align_function
keccak_1600_extract_bytes_x4:
        or      r12, r12
        jz      .extract_zero_bytes

        test    r11d, 7
        jz      .extract_start_aligned_to_4x8

        ;; Extract offset is not aligned to the register size
        mov     r9, r11

        and     r9d, 7
        neg     r9d
        add     r9d, 8                  ; register capacity = 8 - (offset % 8)
        cmp     r12d, r9d
        cmovb   r9d, r12d               ; r9d = min(register capacity, length)

        lea     rbx, [rel byte_kmask_0_to_7]
        kmovb   k1, [rbx + r9]          ; message store mask

        mov     rbx, r11
        and     ebx, ~7
        lea     r10, [r10 + rbx * 4]    ; state starting register

        mov     rbx, r11
        and     ebx, 7                  ; rbx = byte offset within the state word

        ;; store 1 to 7 bytes of each lane's state word, starting at byte
        ;; offset rbx
        vmovdqu8        xmm31{k1}{z}, [r10 + rbx]       ; lane 0
        vmovdqu8        [rdi]{k1}, xmm31
        vmovdqu8        xmm31{k1}{z}, [r10 + rbx + 8]   ; lane 1
        vmovdqu8        [rsi]{k1}, xmm31
        vmovdqu8        xmm31{k1}{z}, [r10 + rbx + 16]  ; lane 2
        vmovdqu8        [rdx]{k1}, xmm31
        vmovdqu8        xmm31{k1}{z}, [r10 + rbx + 24]  ; lane 3
        vmovdqu8        [rcx]{k1}, xmm31

        add     rdi, r9
        add     rsi, r9
        add     rdx, r9
        add     rcx, r9

        sub     r12, r9
        jz      .extract_zero_bytes

        add     r10, 32
        xor     r9, r9
        jmp     .extract_ymm_loop

.extract_start_aligned_to_4x8:
        lea     r10, [r10 + r11 * 4]
        xor     r9, r9

align_loop
.extract_ymm_loop:
        cmp     r12, 8
        jb      .extract_lt_8_bytes

        vmovdqu64       xmm31, [r10]
        vmovdqu64       xmm30, [r10 + 16]
        vmovq           [rdi + r9], xmm31
        vpextrq         [rsi + r9], xmm31, 1
        vmovq           [rdx + r9], xmm30
        vpextrq         [rcx + r9], xmm30, 1
        add     r9, 8
        sub     r12, 8
        jz      .zero_bytes_left

        add     r10, 32
        jmp     .extract_ymm_loop

align_loop
.zero_bytes_left:
        add     rdi, r9
        add     rsi, r9
        add     rdx, r9
        add     rcx, r9
.extract_zero_bytes:
        ret

align_loop
.extract_lt_8_bytes:
        add     rdi, r9
        add     rsi, r9
        add     rdx, r9
        add     rcx, r9

        lea     r9, [rel byte_kmask_0_to_7]
        kmovb   k1, [r9 + r12]          ; mask of bytes to store

        ;; store the first 1 to 7 bytes of each lane's state word
        vmovq           xmm31, [r10]                    ; lane 0
        vmovdqu8        [rdi]{k1}, xmm31
        vmovq           xmm31, [r10 + 8]                ; lane 1
        vmovdqu8        [rsi]{k1}, xmm31
        vmovq           xmm31, [r10 + 16]               ; lane 2
        vmovdqu8        [rdx]{k1}, xmm31
        vmovq           xmm31, [r10 + 24]               ; lane 3
        vmovdqu8        [rcx]{k1}, xmm31

        add     rdi, r12
        add     rsi, r12
        add     rdx, r12
        add     rcx, r12
        ret

;; SHAKE x4 functions for one rate
%macro SHAKE_X4_FUNCS 2
%define %%BITS  %1      ; [in] SHAKE variant (128 or 256)
%define %%RATE  %2      ; [in] rate in bytes

;; void SHA3_shake<BITS>_x4_inc_absorb_avx512vl(uint64_t *state,
;;                                              const void *in0, const void *in1,
;;                                              const void *in2, const void *in3,
;;                                              size_t inlen)
;;
;; Absorbs inlen bytes of each lane into the x4 state, permuting the state
;; after each full block.
align_function
MKGLOBAL(SHA3_shake %+ %%BITS %+ _x4_inc_absorb_avx512vl,function,internal)
SHA3_shake %+ %%BITS %+ _x4_inc_absorb_avx512vl:
        endbranch64
%ifndef LINUX
        WIN_SYSV_STUB shake %+ %%BITS %+ _x4_absorb_sysv, 6
%endif
;; System V body, also called by the Windows entry stub and the one-shot
shake %+ %%BITS %+ _x4_absorb_sysv:
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15

        ;; check for a partially processed block
        mov     r14, [rdi + X4_POS]
        or      r14, r14
        je      .main_loop_start

        ;; process the remaining bytes of the block if the input is long enough
        mov     r12, %%RATE
        sub     r12, r14                ; r12 = capacity

        cmp     r9, r12                 ; inlen <= capacity: no permute
        jbe     .skip_permute

        sub     r9, r12
        mov     r11, r9                 ; remaining length across helper calls

        mov     r10, rdi
        call    keccak_1600_partial_add_x4      ; rsi-r8 are updated

        call    keccak_1600_load_state_x4

        call    keccak1600_block_64bit

        mov     qword [rdi + X4_POS], 0
        jmp     .partial_block_done

.skip_permute:
        mov     r10, rdi
        mov     r12, r9
        mov     r11, r9                 ; input length across helper call
        call    keccak_1600_partial_add_x4

        lea     r15, [r11 + r14]
        mov     [rdi + X4_POS], r15     ; s[100] += inlen

        cmp     r15, %%RATE
        jb      .absorb_exit

        call    keccak_1600_load_state_x4

        call    keccak1600_block_64bit

        call    keccak_1600_save_state_x4

        mov     qword [rdi + X4_POS], 0
        jmp     .absorb_exit

.main_loop_start:
        call    keccak_1600_load_state_x4
        mov     r11, r9                 ; full input length

.partial_block_done:
        xor     r12, r12                ; message offset

align_loop
.absorb_while_loop:
        cmp     r11, %%RATE
        jb      .absorb_while_loop_done

%assign i 0
%rep (%%RATE / 8)
        vmovq           xmm31, [rsi + r12 + i * 8]
        vpinsrq         xmm31, xmm31, [rdx + r12 + i * 8], 1
        vmovq           xmm30, [rcx + r12 + i * 8]
        vpinsrq         xmm30, xmm30, [r8 + r12 + i * 8], 1
        vinserti32x4    ymm31, ymm31, xmm30, 1
        vpxorq          ymm %+ i, ymm %+ i, ymm31
%assign i (i + 1)
%endrep

        sub     r11, %%RATE
        add     r12, %%RATE
        call    keccak1600_block_64bit

        jmp     .absorb_while_loop

align_loop
.absorb_while_loop_done:
        call    keccak_1600_save_state_x4

        mov     [rdi + X4_POS], r11
        or      r11, r11
        jz      .absorb_exit

        mov     qword [rdi + X4_POS], 0

        mov     r10, rdi
        add     rsi, r12
        add     rdx, r12
        add     rcx, r12
        add     r8, r12
        mov     r12, r11
        call    keccak_1600_partial_add_x4

        mov     [rdi + X4_POS], r11

.absorb_exit:
        clear_all_zmms_asm

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

;; void SHA3_shake<BITS>_x4_inc_finalize_avx512vl(uint64_t *state)
;;
;; Adds the SHAKE padding to the x4 state and clears the block position,
;; ready for squeezing.
align_function
MKGLOBAL(SHA3_shake %+ %%BITS %+ _x4_inc_finalize_avx512vl,function,internal)
SHA3_shake %+ %%BITS %+ _x4_inc_finalize_avx512vl:
        endbranch64
%ifndef LINUX
        WIN_SYSV_STUB shake %+ %%BITS %+ _x4_finalize_sysv, 1
%endif
;; System V body, also called by the Windows entry stub and the one-shot
shake %+ %%BITS %+ _x4_finalize_sysv:
        mov     r11, [rdi + X4_POS]
        mov     r10, r11
        and     r10d, ~7                ; offset of the state register
        and     r11d, 7                 ; offset within the register

        ;; add the padding byte right after the message
        vmovdqu32       ymm31, [rdi + r10 * 4]
        lea     r9, [rel shake_msg_pad_x4]
        sub     r9, r11
        vmovdqu32       ymm30, [r9]
        vpxorq          ymm31, ymm31, ymm30
        vmovdqu32       [rdi + r10 * 4], ymm31

        ;; add the terminating bit at byte rate - 1
        vmovdqu32       ymm31, [rdi + (%%RATE * 4 - 32)]
        vmovdqa32       ymm30, [rel shake_terminator_byte_x4]
        vpxorq          ymm31, ymm31, ymm30
        vmovdqu32       [rdi + (%%RATE * 4 - 32)], ymm31

        mov     qword [rdi + X4_POS], 0
        vpxorq          ymm31, ymm31, ymm31
        ret

;; void SHA3_shake<BITS>_x4_inc_squeeze_avx512vl(void *out0, void *out1,
;;                                               void *out2, void *out3,
;;                                               size_t outlen,
;;                                               uint64_t *state)
;;
;; Writes outlen bytes of each lane from the finalized x4 state. Can be
;; called repeatedly.
align_function
MKGLOBAL(SHA3_shake %+ %%BITS %+ _x4_inc_squeeze_avx512vl,function,internal)
SHA3_shake %+ %%BITS %+ _x4_inc_squeeze_avx512vl:
        endbranch64
%ifndef LINUX
        WIN_SYSV_STUB shake %+ %%BITS %+ _x4_squeeze_sysv, 6
%endif
;; System V body, also called by the Windows entry stub and the one-shot
shake %+ %%BITS %+ _x4_squeeze_sysv:
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15

        or      r8, r8
        jz      .squeeze_done

        ;; check for a partially processed block
        mov     r15, [r9 + X4_POS]      ; s[100] = bytes left in the block
        or      r15, r15
        jnz     .squeeze_no_init_permute

        mov     r14, rdi
        mov     rdi, r9
        call    keccak_1600_load_state_x4

        mov     rdi, r14

        xor     rbp, rbp
        jmp     .squeeze_loop

align_loop
.squeeze_no_init_permute:
        mov     r10, r9
        mov     r14, r9                 ; state pointer across extract helper

        mov     r12, r15
        cmp     r8, r15
        cmovb   r12, r8                 ; r12 = min(bytes left, outlen)

        sub     r8, r12                 ; outlen -= length

        mov     r11d, %%RATE
        sub     r11, r15                ; state offset

        sub     r15, r12                ; bytes left -= length
        mov     [r9 + X4_POS], r15

        call    keccak_1600_extract_bytes_x4
        mov     r9, r14

        or      r15, r15
        jnz     .squeeze_done

        mov     r13, rdi
        mov     rdi, r14
        call    keccak_1600_load_state_x4

        mov     rdi, r13
        xor     rbp, rbp

align_loop
.squeeze_loop:
        cmp     r8, %%RATE
        jb      .squeeze_final_extract

        call    keccak1600_block_64bit

%assign i 0
%rep (%%RATE / 8)
        vextracti64x2   xmm31, ymm %+ i, 1
        vmovq           [rdi + rbp + i * 8], xmm %+ i
        vpextrq         [rsi + rbp + i * 8], xmm %+ i, 1
        vmovq           [rdx + rbp + i * 8], xmm31
        vpextrq         [rcx + rbp + i * 8], xmm31, 1
%assign i (i + 1)
%endrep

        add     rbp, %%RATE
        sub     r8, %%RATE
        jmp     .squeeze_loop

align_loop
.squeeze_final_extract:
        or      r8, r8
        jz      .squeeze_no_end_permute

        add     rdi, rbp
        add     rsi, rbp
        add     rdx, rbp
        add     rcx, rbp

        mov     r15d, %%RATE
        sub     r15, r8
        mov     [r9 + X4_POS], r15      ; bytes left in the block

        call    keccak1600_block_64bit

        mov     r14, rdi
        mov     rdi, r9
        call    keccak_1600_save_state_x4

        mov     rdi, r14

        mov     r10, r9
        mov     r12, r8
        xor     r11, r11
        call    keccak_1600_extract_bytes_x4

        jmp     .squeeze_done

.squeeze_no_end_permute:
        mov     qword [r9 + X4_POS], 0
        mov     rdi, r9
        call    keccak_1600_save_state_x4

.squeeze_done:
        clear_all_zmms_asm

        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

;; void SHA3_shake<BITS>_x4_avx512vl(void *out0, void *out1, void *out2,
;;                                   void *out3, size_t outlen,
;;                                   const void *in0, const void *in1,
;;                                   const void *in2, const void *in3,
;;                                   size_t inlen)
;;
;; One-shot SHAKE x4: absorbs inlen bytes of each lane and writes outlen
;; bytes of each lane's output.
align_function
MKGLOBAL(SHA3_shake %+ %%BITS %+ _x4_avx512vl,function,internal)
SHA3_shake %+ %%BITS %+ _x4_avx512vl:
        endbranch64
        push    rbp
        mov     rbp, rsp
        push    rbx
%ifndef LINUX
        push    rdi
        push    rsi
%endif
        sub     rsp, ONESHOT_FRAME_SZ
        mov     rbx, rsp

%ifndef LINUX
%assign i 6
%rep 10
        vmovdqu [rbx + _os_xmm + (i - 6) * 16], xmm %+ i
%assign i (i + 1)
%endrep
        mov     rdi, rcx
        mov     rsi, rdx
        mov     rdx, r8
        mov     rcx, r9
        mov     r8, [OS_ARG5]
        mov     r9, [OS_ARG6]
%endif
        mov     [rbx + _os_out + 0 * 8], rdi
        mov     [rbx + _os_out + 1 * 8], rsi
        mov     [rbx + _os_out + 2 * 8], rdx
        mov     [rbx + _os_out + 3 * 8], rcx
        mov     [rbx + _os_outlen], r8

        ;; zero the x4 state on the stack
        lea     rdi, [rbx + _os_state]
        call    keccak_1600_init_state
        call    keccak_1600_save_state_x4
        mov     qword [rdi + X4_POS], 0

        mov     rsi, r9                 ; in0
        mov     rdx, [OS_ARG7]          ; in1
        mov     rcx, [OS_ARG7 + 8]      ; in2
        mov     r8, [OS_ARG7 + 16]      ; in3
        mov     r9, [OS_ARG7 + 24]      ; inlen
        call    shake %+ %%BITS %+ _x4_absorb_sysv

        lea     rdi, [rbx + _os_state]
        call    shake %+ %%BITS %+ _x4_finalize_sysv

        mov     rdi, [rbx + _os_out + 0 * 8]
        mov     rsi, [rbx + _os_out + 1 * 8]
        mov     rdx, [rbx + _os_out + 2 * 8]
        mov     rcx, [rbx + _os_out + 3 * 8]
        mov     r8, [rbx + _os_outlen]
        lea     r9, [rbx + _os_state]
        call    shake %+ %%BITS %+ _x4_squeeze_sysv

        ;; clear the x4 state on the stack
        vpxorq          ymm31, ymm31, ymm31
%assign i 0
%rep 25
        vmovdqu64       [rbx + _os_state + i * 32], ymm31
%assign i (i + 1)
%endrep
        vmovq           [rbx + _os_state + X4_POS], xmm31

%ifndef LINUX
%assign i 6
%rep 10
        vmovdqu xmm %+ i, [rbx + _os_xmm + (i - 6) * 16]
%assign i (i + 1)
%endrep
%endif
        add     rsp, ONESHOT_FRAME_SZ
%ifndef LINUX
        pop     rsi
        pop     rdi
%endif
        pop     rbx
        pop     rbp
        ret
%endmacro

SHAKE_X4_FUNCS 128, SHAKE128_RATE
SHAKE_X4_FUNCS 256, SHAKE256_RATE

mksection .rodata
default rel

align 8
byte_kmask_0_to_7:
        db      0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f

align 32
shake_terminator_byte_x4:
        db      0, 0, 0, 0, 0, 0, 0, 0x80
        db      0, 0, 0, 0, 0, 0, 0, 0x80
        db      0, 0, 0, 0, 0, 0, 0, 0x80
        db      0, 0, 0, 0, 0, 0, 0, 0x80

;; 8 zero bytes before the table so that it can be read from
;; shake_msg_pad_x4 - (offset % 8)
align 8
        db      0, 0, 0, 0, 0, 0, 0, 0
shake_msg_pad_x4:
        db      0x1F, 0, 0, 0, 0, 0, 0, 0
        db      0x1F, 0, 0, 0, 0, 0, 0, 0
        db      0x1F, 0, 0, 0, 0, 0, 0, 0
        db      0x1F, 0, 0, 0, 0, 0, 0, 0

mksection stack-noexec
