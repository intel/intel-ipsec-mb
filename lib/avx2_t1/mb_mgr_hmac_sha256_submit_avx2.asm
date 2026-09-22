;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/memcpy.inc"
%include "include/const.inc"
%include "include/align_avx.inc"

extern sha256_oct_avx2

mksection .rodata
default rel
align 16
byteswap:       ;ddq 0x0c0d0e0f08090a0b0405060700010203
        dq 0x0405060700010203, 0x0c0d0e0f08090a0b

mksection .text

%ifndef FUNC
%define FUNC submit_job_hmac_sha_256_avx2
%endif

%if 1
%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define reg3    rcx
%define reg4    rdx
%else
%define arg1    rcx
%define arg2    rdx
%define reg3    rdi
%define reg4    rsi
%endif

%define state   arg1
%define job     arg2
%define len2    arg2

; idx needs to be in rbp, r15
%define last_len        rbp
%define idx             rbp

%define p               r11
%define start_offset    r11

%define unused_lanes    rbx
%define p2              rbx
%define tmp4            rbx

%define job_rax         rax
%define len             rax

%define size_offset     reg3
%define tmp2            reg3

%define lane            reg4
%define tmp3            reg4

%define extra_blocks    r8

%define tmp             r9

%define lane_data       r10

%endif

; we clobber rbx, rsi, rdi, rbp; called routine also clobbers r12, r13, r14
; NOTE: _gpr_save is padded to 8 qwords (rather than the 7 registers
; actually saved) so that _xmm_save starts at a 16-byte aligned offset,
; as required by the vmovdqa (aligned) instructions used below.
struc STACK
_gpr_save:      resq    8
%ifndef LINUX
_xmm_save:      resq    20
%endif
_rsp_save:      resq    1
endstruc

; JOB* FUNC(MB_MGR_HMAC_SHA_256_OOO *state, IMB_JOB *job)
; arg 1 : rcx : state
; arg 2 : rdx : job
MKGLOBAL(FUNC,function,internal)
align_function
FUNC:
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -32
        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*5], rsi
        mov     [rsp + _gpr_save + 8*6], rdi

        vmovdqa [rsp + _xmm_save + 16*0], xmm6
        vmovdqa [rsp + _xmm_save + 16*1], xmm7
        vmovdqa [rsp + _xmm_save + 16*2], xmm8
        vmovdqa [rsp + _xmm_save + 16*3], xmm9
        vmovdqa [rsp + _xmm_save + 16*4], xmm10
        vmovdqa [rsp + _xmm_save + 16*5], xmm11
        vmovdqa [rsp + _xmm_save + 16*6], xmm12
        vmovdqa [rsp + _xmm_save + 16*7], xmm13
        vmovdqa [rsp + _xmm_save + 16*8], xmm14
        vmovdqa [rsp + _xmm_save + 16*9], xmm15
%endif
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _unused_lanes_sha256]
        mov     lane, unused_lanes
        and     lane, 0xF           ;; just a nibble
        shr     unused_lanes, 4

        imul    lane_data, lane, _HMAC_SHA1_LANE_DATA_size
        lea     lane_data, [state + _ldata_sha256 + lane_data]
        mov     [state + _unused_lanes_sha256], unused_lanes
        mov     len, [job + _msg_len_to_hash_in_bytes]
        mov     tmp, len
        shr     tmp, 6  ; divide by 64, len in terms of blocks

        mov     [lane_data + _job_in_lane], job
        mov     dword [lane_data + _outer_done], 0

        vmovdqa xmm0, [state + _lens_sha256]
        XVPINSRW xmm0, xmm1, extra_blocks, lane, tmp, scale_x16
        vmovdqa [state + _lens_sha256], xmm0

        mov     last_len, len
        and     last_len, 63
        lea     extra_blocks, [last_len + 9 + 63]
        shr     extra_blocks, 6
        mov     [lane_data + _extra_blocks], DWORD(extra_blocks)

        ; zero length check - skip src load and copy for empty messages
        test    len, len
        jz      end_fast_copy

        mov     p, [job + _src]
        add     p, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _args_data_ptr_sha256 + 8*lane], p

        cmp     len, 64
        jb      copy_lt64

align_label
fast_copy:
        add     p, len
        vmovdqu ymm0, [p - 64 + 0 * 32]
        vmovdqu ymm1, [p - 64 + 1 * 32]
        vmovdqu [lane_data + _extra_block + 0*32], ymm0
        vmovdqu [lane_data + _extra_block + 1*32], ymm1

align_label
end_fast_copy:
        mov     size_offset, extra_blocks
        shl     size_offset, 6
        sub     size_offset, last_len
        add     size_offset, 64-8
        mov     [lane_data + _size_offset], DWORD(size_offset)
        mov     start_offset, 64
        sub     start_offset, last_len
        mov     [lane_data + _start_offset], DWORD(start_offset)

        lea     tmp, [8*64 + 8*len]
        bswap   tmp
        mov     [lane_data + _extra_block + size_offset], tmp

        mov     tmp, [job + _auth_key_xor_ipad]
        vmovdqu xmm0, [tmp]
        vmovdqu xmm1, [tmp + 4*4]
        vmovd   [state + _args_digest_sha256 + 4*lane + 0*SHA256_DIGEST_ROW_SIZE], xmm0
        vpextrd [state + _args_digest_sha256 + 4*lane + 1*SHA256_DIGEST_ROW_SIZE], xmm0, 1
        vpextrd [state + _args_digest_sha256 + 4*lane + 2*SHA256_DIGEST_ROW_SIZE], xmm0, 2
        vpextrd [state + _args_digest_sha256 + 4*lane + 3*SHA256_DIGEST_ROW_SIZE], xmm0, 3
        vmovd   [state + _args_digest_sha256 + 4*lane + 4*SHA256_DIGEST_ROW_SIZE], xmm1
        vpextrd [state + _args_digest_sha256 + 4*lane + 5*SHA256_DIGEST_ROW_SIZE], xmm1, 1
        vpextrd [state + _args_digest_sha256 + 4*lane + 6*SHA256_DIGEST_ROW_SIZE], xmm1, 2
        vpextrd [state + _args_digest_sha256 + 4*lane + 7*SHA256_DIGEST_ROW_SIZE], xmm1, 3

        test    len, ~63
        jnz     ge64_bytes

align_label
lt64_bytes:
        vmovdqa xmm0, [state + _lens_sha256]
        XVPINSRW xmm0, xmm1, tmp, lane, extra_blocks, scale_x16
        vmovdqa [state + _lens_sha256], xmm0

        lea     tmp, [lane_data + _extra_block + start_offset]
        mov     [state + _args_data_ptr_sha256 + 8*lane], tmp
        mov     dword [lane_data + _extra_blocks], 0

align_label
ge64_bytes:
        cmp     unused_lanes, 0xf
        jne     return_null
        jmp     start_loop

align_loop
start_loop:
        ; Find min length
        vmovdqa xmm0, [state + _lens_sha256]
        vphminposuw     xmm1, xmm0
        vpextrw DWORD(len2), xmm1, 0    ; min value
        vpextrw DWORD(idx), xmm1, 1     ; min index (0...7)
        cmp     len2, 0
        je      len_is_0

        vpbroadcastw    xmm1, xmm1 ; duplicate words across all lanes
        vpsubw  xmm0, xmm0, xmm1
        vmovdqa [state + _lens_sha256], xmm0

        ; "state" and "args" are the same address, arg1
        ; len is arg2
        call    sha256_oct_avx2
        ; state and idx are intact

align_label
len_is_0:
        ; process completed job "idx"
        imul    lane_data, idx, _HMAC_SHA1_LANE_DATA_size
        lea             lane_data, [state + _ldata_sha256 + lane_data]
        mov             DWORD(extra_blocks), [lane_data + _extra_blocks]
        cmp             extra_blocks, 0
        jne             proc_extra_blocks
        cmp             dword [lane_data + _outer_done], 0
        jne             end_loop

align_label
proc_outer:
        mov             dword [lane_data + _outer_done], 1
        mov             DWORD(size_offset), [lane_data + _size_offset]
        mov             qword [lane_data + _extra_block + size_offset], 0

        vmovdqa xmm0, [state + _lens_sha256]
        XVPINSRW xmm0, xmm1, tmp, idx, 1, scale_x16
        vmovdqa [state + _lens_sha256], xmm0

        lea             tmp, [lane_data + _outer_block]
        mov             job, [lane_data + _job_in_lane]
        mov             [state + _args_data_ptr_sha256 + 8*idx], tmp

        vmovd   xmm0, [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE]
        vpinsrd xmm0, xmm0, [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE], 1
        vpinsrd xmm0, xmm0, [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE], 2
        vpinsrd xmm0, xmm0, [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE], 3
        vpshufb xmm0, xmm0, [rel byteswap]
        vmovd   xmm1, [state + _args_digest_sha256 + 4*idx + 4*SHA256_DIGEST_ROW_SIZE]
        vpinsrd xmm1, xmm1, [state + _args_digest_sha256 + 4*idx + 5*SHA256_DIGEST_ROW_SIZE], 1
        vpinsrd xmm1, xmm1, [state + _args_digest_sha256 + 4*idx + 6*SHA256_DIGEST_ROW_SIZE], 2
%ifndef SHA224
        vpinsrd xmm1, xmm1, [state + _args_digest_sha256 + 4*idx + 7*SHA256_DIGEST_ROW_SIZE], 3
%endif
        vpshufb xmm1, xmm1, [rel byteswap]
        vmovdqa [lane_data + _outer_block], xmm0
        vmovdqa [lane_data + _outer_block + 4*4], xmm1
%ifdef SHA224
        mov     dword [lane_data + _outer_block + 7*4], 0x80
%endif

        mov     tmp, [job + _auth_key_xor_opad]
        vmovdqu xmm0, [tmp]
        vmovdqu xmm1, [tmp + 4*4]
        vmovd   [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE], xmm0
        vpextrd [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE], xmm0, 1
        vpextrd [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE], xmm0, 2
        vpextrd [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE], xmm0, 3
        vmovd   [state + _args_digest_sha256 + 4*idx + 4*SHA256_DIGEST_ROW_SIZE], xmm1
        vpextrd [state + _args_digest_sha256 + 4*idx + 5*SHA256_DIGEST_ROW_SIZE], xmm1, 1
        vpextrd [state + _args_digest_sha256 + 4*idx + 6*SHA256_DIGEST_ROW_SIZE], xmm1, 2
        vpextrd [state + _args_digest_sha256 + 4*idx + 7*SHA256_DIGEST_ROW_SIZE], xmm1, 3

        jmp     start_loop

align_label
proc_extra_blocks:
        mov     DWORD(start_offset), [lane_data + _start_offset]

        vmovdqa xmm0, [state + _lens_sha256]
        XVPINSRW xmm0, xmm1, tmp, idx, extra_blocks, scale_x16
        vmovdqa [state + _lens_sha256], xmm0

        lea     tmp, [lane_data + _extra_block + start_offset]
        mov     [state + _args_data_ptr_sha256 + 8*idx], tmp
        mov     dword [lane_data + _extra_blocks], 0
        jmp     start_loop

align_label
copy_lt64:
        ;; less than one message block of data
        ;; beginning of source block
        ;; destination extrablock but backwards by len from where 0x80 pre-populated
        lea     p2, [lane_data + _extra_block  + 64]
        sub     p2, len
        memcpy_avx2_64_1 p2, p, len, tmp, tmp2, ymm0, ymm1
        mov     unused_lanes, [state + _unused_lanes_sha256]
        jmp     end_fast_copy

align_label
return_null:
        xor     job_rax, job_rax
        jmp     return

align_label
end_loop:
        mov     job_rax, [lane_data + _job_in_lane]
        mov     unused_lanes, [state + _unused_lanes_sha256]
        mov     qword [lane_data + _job_in_lane], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _unused_lanes_sha256], unused_lanes

        mov     p, [job_rax + _auth_tag_output]

%ifdef SHA224
        cmp     qword [job_rax + _auth_tag_output_len_in_bytes], 14
        jne     copy_full_digest
%else
        cmp     qword [job_rax + _auth_tag_output_len_in_bytes], 16
        jne     copy_full_digest
%endif
        ;; copy 14 bytes for SHA224 / 16 bytes for SHA256
        movbe   DWORD(tmp),  [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE]
        movbe   DWORD(tmp2), [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE]
        movbe   DWORD(tmp3), [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE]
        movbe   DWORD(tmp4), [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE]
        mov     [p + 0*4], DWORD(tmp)
        mov     [p + 1*4], DWORD(tmp2)
        mov     [p + 2*4], DWORD(tmp3)
%ifdef SHA224
        mov     [p + 3*4], WORD(tmp4)
%else
        mov     [p + 3*4], DWORD(tmp4)
%endif
        jmp     clear_ret

align_label
copy_full_digest:
        cmp     qword [job_rax + _auth_tag_output_len_in_bytes], 16
        ja      copy_tag_gt16

        ;; copy up to 16 bytes
        mov     tmp2, qword [job_rax + _auth_tag_output_len_in_bytes]
        vmovd   xmm0, [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE]
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE], 1
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE], 2
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE], 3
        vpshufb xmm0, [rel byteswap]
        simd_store_avx {p + 0*4}, xmm0, tmp2, tmp4, tmp
        jmp     clear_ret

align_label
copy_tag_gt16:
        ;; copy 16 bytes first
        mov     tmp2, qword 16
        vmovd   xmm0, [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE]
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE], 1
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE], 2
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE], 3
        vpshufb xmm0, [rel byteswap]
        vmovdqu [p + 0*4], xmm0

        ;; calculate remaining bytes to copy
        mov     tmp2, qword [job_rax + _auth_tag_output_len_in_bytes]
        sub     tmp2, 16 ; copied 16 bytes already

        ;; copy remaining bytes
        vmovd   xmm0, [state + _args_digest_sha256 + 4*idx + 4*SHA256_DIGEST_ROW_SIZE]
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 5*SHA256_DIGEST_ROW_SIZE], 1
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 6*SHA256_DIGEST_ROW_SIZE], 2
%ifndef SHA224
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 7*SHA256_DIGEST_ROW_SIZE], 3
%endif
        vpshufb xmm0, [rel byteswap]
        simd_store_avx {p + 4*4}, xmm0, tmp2, tmp4, tmp

align_label
clear_ret:

%ifdef SAFE_DATA
        ;; Clear extra_block (64B) of returned job
        vpxor   ymm0, ymm0
        imul    lane_data, idx, _HMAC_SHA1_LANE_DATA_size
        lea     lane_data, [state + _ldata_sha256 + lane_data]
        ;; Clear first 64 bytes of extra_block
        vmovdqa  [lane_data + _extra_block],      ymm0
        vmovdqa  [lane_data + _extra_block + 32], ymm0
%endif ;; SAFE_DATA

align_label
return:
        vzeroupper

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*5]
        mov     rdi, [rsp + _gpr_save + 8*6]

        vmovdqa xmm6,  [rsp + _xmm_save + 16*0]
        vmovdqa xmm7,  [rsp + _xmm_save + 16*1]
        vmovdqa xmm8,  [rsp + _xmm_save + 16*2]
        vmovdqa xmm9,  [rsp + _xmm_save + 16*3]
        vmovdqa xmm10, [rsp + _xmm_save + 16*4]
        vmovdqa xmm11, [rsp + _xmm_save + 16*5]
        vmovdqa xmm12, [rsp + _xmm_save + 16*6]
        vmovdqa xmm13, [rsp + _xmm_save + 16*7]
        vmovdqa xmm14, [rsp + _xmm_save + 16*8]
        vmovdqa xmm15, [rsp + _xmm_save + 16*9]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        ret

mksection stack-noexec
