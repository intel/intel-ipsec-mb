;;
;; Copyright (c) 2024, Intel Corporation
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

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"

%use smartalign
alignmode nop

%ifndef FUNC
%define FUNC flush_job_hmac_sha_512_ni_avx2
%define SHA_X_DIGEST_SIZE 512
%endif

extern sha512_ni_x2_avx2

mksection .rodata
default rel

align 16
byteswap:
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f
len_masks:
        dq 0xFFFFFFFF0000FFFF, 0xFFFFFFFFFFFFFFFF
        dq 0xFFFFFFFFFFFF0000, 0xFFFFFFFFFFFFFFFF
lane_1: dq  1

mksection .text

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%else
%define arg1    rcx
%define arg2    rdx
%endif

%define state   arg1
%define job     arg2
%define len2    arg2

; idx needs to be in rbp, r15
%define idx             rbp

%define unused_lanes    rbx
%define lane_data       rbx
%define tmp2            rbx

%define job_rax         rax
%define size_offset     rax
%define tmp             rax
%define start_offset    rax

%define tmp3            arg1
%define extra_blocks    arg2
%define p               arg2

%define tmp4            r8
%define tmp5            r9
%define tmp6            r10

struc STACK
_gpr_save:      resq    3
_rsp_save:      resq    1
endstruc

%define APPEND(a,b) a %+ b

; JOB* FUNC(MB_MGR_HMAC_SHA_512_OOO *state)
; arg 1 : state
align 32
MKGLOBAL(FUNC,function,internal)
FUNC:
        mov     rax, rsp
        sub     rsp, STACK_size
        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _unused_lanes_sha512]
        bt      unused_lanes, 16+7
        jc      return_null

        ; find a lane with a non-null job
        xor     DWORD(idx), DWORD(idx)
        cmp     qword [state + _ldata_sha512 + 1 * _SHA512_LANE_DATA_size + _job_in_lane_sha512], idx ; recycle idx being 0
        cmovne  idx, [rel lane_1]

copy_lane_data:
        ; copy good lane (idx) to empty lanes
        mov     tmp, [state + _args_sha512 + _data_ptr_sha512 + PTR_SZ*idx]
        mov     DWORD(tmp6), DWORD(idx)
        xor     DWORD(tmp6), 1

        ;; copy lane 0 data to lane 1, or lane 1 to lane 0
        mov     [state + _args_sha512 + _data_ptr_sha512 + PTR_SZ*tmp6], tmp

        movzx   DWORD(len2), word [state + _lens_sha512 + idx*2]

        ; No need to find min length - only two lanes available
        or      len2, len2
        je      len_is_0

        ; set both lane lengths to 0
        mov     dword [state + _lens_sha512], 0

        ; "state" and "args" are the same address, arg1
        ; len is arg2
        call    sha512_ni_x2_avx2
        ; state and idx are intact

len_is_0:
        ; process completed job "idx"
        imul    lane_data, idx, _SHA512_LANE_DATA_size
        lea     lane_data, [state + _ldata_sha512 + lane_data]
        mov     DWORD(extra_blocks), [lane_data + _extra_blocks_sha512]
        cmp     extra_blocks, 0
        jne     proc_extra_blocks
        cmp     dword [lane_data + _outer_done_sha512], 0
        jne     end_loop

proc_outer:
        mov     dword [lane_data + _outer_done_sha512], 1
        mov     DWORD(size_offset), [lane_data + _size_offset_sha512]
        mov     qword [lane_data + _extra_block_sha512 + size_offset], 0
        mov     word [state + _lens_sha512 + 2*idx], 1
        lea     tmp, [lane_data + _outer_block_sha512]
        mov     job, [lane_data + _job_in_lane_sha512]
        mov     [state + _args_data_ptr_sha512 + PTR_SZ*idx], tmp

        ; move digest into data location
        lea     tmp5, [idx*8] ;; scale up to SHA512_DIGEST_ROW_SIZE (8*8)
        vmovdqu ymm0, [state + _args_digest_sha512 + tmp5*8]
        vmovdqu ymm1, [state + _args_digest_sha512 + tmp5*8 + 32]
        vpshufb ymm0, [rel byteswap]
        vpshufb ymm1, [rel byteswap]
        vmovdqu [lane_data + _outer_block_sha512], ymm0
%if (SHA_X_DIGEST_SIZE != 384)
        vmovdqu [lane_data + _outer_block_sha512+32], ymm1
%else
        vmovdqu [lane_data + _outer_block_sha512+32], xmm1
%endif

        ; move the opad key into digest
        mov     tmp, [job + _auth_key_xor_opad]

        vmovdqu ymm0, [tmp]
        vmovdqu ymm1, [tmp + 32]
        vmovdqu [state + _args_digest_sha512 + tmp5*8], ymm0
        vmovdqu [state + _args_digest_sha512 + tmp5*8 + 32], ymm1

        jmp     copy_lane_data

align 32
proc_extra_blocks:
        mov     DWORD(start_offset), [lane_data + _start_offset_sha512]
        mov     [state + _lens_sha512 + 2*idx], WORD(extra_blocks)
        lea     tmp, [lane_data + _extra_block_sha512 + start_offset]
        mov     [state + _args_data_ptr_sha512 + PTR_SZ*idx], tmp
        mov     dword [lane_data + _extra_blocks_sha512], 0
        jmp     copy_lane_data

align 32
return_null:
        xor     job_rax, job_rax
        jmp     return

align 32
end_loop:
        mov     job_rax, [lane_data + _job_in_lane_sha512]
        mov     qword [lane_data + _job_in_lane_sha512], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        mov     unused_lanes, [state + _unused_lanes_sha512]
        shl     unused_lanes, 8
        or      unused_lanes, idx
        mov     [state + _unused_lanes_sha512], unused_lanes

        mov     p, [job_rax + _auth_tag_output]

        ;; scale idx*64
        shl     idx, 6

%if (SHA_X_DIGEST_SIZE != 384)
        cmp     qword [job_rax + _auth_tag_output_len_in_bytes], 32
        jne     copy_full_digest
%else
        cmp     qword [job_rax + _auth_tag_output_len_in_bytes], 24
        jne     copy_full_digest
%endif

%if (SHA_X_DIGEST_SIZE != 384)
        ;; copy 32 bytes for SHA512 / 24 bytes for SHA384
        vmovdqu ymm0, [state + _args_digest_sha512 + idx]
        vpshufb ymm0, [rel byteswap]
        vmovdqu [p], ymm0
%else
        vmovdqu xmm0, [state + _args_digest_sha512 + idx]
        vpshufb xmm0, [rel byteswap]
        mov     QWORD(tmp2), [state + _args_digest_sha512 + idx + 16]
        bswap   QWORD(tmp2)
        vmovdqu [p], xmm0
        mov     [p + 16], QWORD(tmp2)
%endif
        jmp     clear_ret

copy_full_digest:
        ;; copy 64 bytes for SHA512 / 48 bytes for SHA384
%if (SHA_X_DIGEST_SIZE != 384)
        vmovdqu ymm0, [state + _args_digest_sha512 + idx + 0*SHA512_DIGEST_WORD_SIZE]
        vmovdqu ymm1, [state + _args_digest_sha512 + idx + 4*SHA512_DIGEST_WORD_SIZE]
        vpshufb ymm0, [rel byteswap]
        vpshufb ymm1, [rel byteswap]
        vmovdqu [p], ymm0
        vmovdqu [p + 32], ymm1
%else
        vmovdqu ymm0, [state + _args_digest_sha512 + idx + 0*SHA512_DIGEST_WORD_SIZE]
        vmovdqu xmm1, [state + _args_digest_sha512 + idx + 4*SHA512_DIGEST_WORD_SIZE]
        vpshufb ymm0, [rel byteswap]
        vpshufb xmm1, [rel byteswap]
        vmovdqu [p], ymm0
        vmovdqu [p + 32], xmm1
%endif

clear_ret:
%ifdef SAFE_DATA
        vpxor   ymm0, ymm0

        ;; Clear digest (48B/64B), outer_block (48B/64B) and extra_block (128B) of returned job
%assign I 0
%rep 2
        cmp     qword [state + _ldata_sha512 + (I*_SHA512_LANE_DATA_size) + _job_in_lane_sha512], 0
        jne     APPEND(skip_clear_,I)

        ;; Clear digest (48 bytes for SHA-384, 64 bytes for SHA-512 bytes)
        vmovdqa [state + _args_digest_sha512 + I*64], ymm0
%if (SHA_X_DIGEST_SIZE == 384)
        vmovdqa [state + _args_digest_sha512 + I*64 + 32], xmm0
%else
        vmovdqa [state + _args_digest_sha512 + I*64 + 32], ymm0
%endif

        lea     lane_data, [state + _ldata_sha512 + (I*_SHA512_LANE_DATA_size)]
        ;; Clear first 128 bytes of extra_block
%assign offset 0
%rep 4
        vmovdqa [lane_data + _extra_block + offset], ymm0
%assign offset (offset + 32)
%endrep

        ;; Clear first 48 bytes (SHA-384) or 64 bytes (SHA-512) of outer_block
        vmovdqu [lane_data + _outer_block], ymm0
%if (SHA_X_DIGEST_SIZE == 384)
        vmovdqa [lane_data + _outer_block + 32], xmm0
%else
        vmovdqu [lane_data + _outer_block + 32], ymm0
%endif

APPEND(skip_clear_,I):
%assign I (I+1)
%endrep

%endif ;; SAFE_DATA

return:
        vzeroupper

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     rsp, [rsp + _rsp_save]  ; original SP

        ret

mksection stack-noexec
