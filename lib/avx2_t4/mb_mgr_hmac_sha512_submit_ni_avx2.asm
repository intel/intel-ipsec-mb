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
%include "include/memcpy.inc"
%include "include/const.inc"

%use smartalign
alignmode nop

%ifndef FUNC
%define FUNC submit_job_hmac_sha_512_ni_avx2
%define SHA_X_DIGEST_SIZE 512
%endif

extern sha512_ni_x2_avx2

mksection .rodata
default rel
align 16
byteswap:
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f

unused_lane_lens:
        dq 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF

mksection .text

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

; idx needs to be in rbp, r13, r14, r16
%define last_len        rbp
%define idx             rbp

%define p               r11
%define start_offset    r11

%define unused_lanes    rbx
%define tmp4            rbx

%define job_rax         rax
%define len             rax

%define size_offset     reg3
%define tmp2            reg3

%define lane            reg4
%define tmp3            reg4

%define extra_blocks    r8

%define tmp             r9
%define p2              r9

%define lane_data       r10

; Define stack usage
struc STACK
_gpr_save:      resq    5
_rsp_save:      resq    1
endstruc

; JOB* FUNC(MB_MGR_HMAC_sha_512_OOO *state, IMB_JOB *job)
; arg 1 : rcx : state
; arg 2 : rdx : job
align 32
MKGLOBAL(FUNC,function,internal)
FUNC:
        mov     rax, rsp
        sub     rsp, STACK_size
        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*3], rsi
        mov     [rsp + _gpr_save + 8*4], rdi
%endif
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _unused_lanes_sha512]
        movzx   lane, BYTE(unused_lanes)
        shr     unused_lanes, 8
        imul    lane_data, lane, _SHA512_LANE_DATA_size
        lea     lane_data, [state + _ldata_sha512 + lane_data]
        mov     [state + _unused_lanes_sha512], unused_lanes
        mov     len, [job + _msg_len_to_hash_in_bytes]
        mov     tmp, len
        shr     tmp, 7  ; divide by 128, len in terms of blocks

        mov     [lane_data + _job_in_lane_sha512], job
        mov     dword [lane_data + _outer_done_sha512], 0

        mov     [state + _lens_sha512 + 2*lane], WORD(tmp)

        mov     last_len, len
        and     last_len, 127
        lea     extra_blocks, [last_len + 17 + 127]
        shr     extra_blocks, 7
        mov     [lane_data + _extra_blocks_sha512], DWORD(extra_blocks)

        mov     p, [job + _src]
        add     p, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _args_data_ptr_sha512 + PTR_SZ*lane], p

        cmp     len, 128
        jb      copy_lt128

fast_copy:
        add     p, len
        vmovdqu ymm0, [p - 128 + 0*32]
        vmovdqu ymm1, [p - 128 + 1*32]
        vmovdqu ymm2, [p - 128 + 2*32]
        vmovdqu ymm3, [p - 128 + 3*32]
        vmovdqu [lane_data + _extra_block_sha512 + 0*32], ymm0
        vmovdqu [lane_data + _extra_block_sha512 + 1*32], ymm1
        vmovdqu [lane_data + _extra_block_sha512 + 2*32], ymm2
        vmovdqu [lane_data + _extra_block_sha512 + 3*32], ymm3
end_fast_copy:

        mov     size_offset, extra_blocks
        shl     size_offset, 7
        sub     size_offset, last_len
        add     size_offset, 128-8
        mov     [lane_data + _size_offset_sha512], DWORD(size_offset)
        mov     start_offset, 128
        sub     start_offset, last_len
        mov     [lane_data + _start_offset_sha512], DWORD(start_offset)

        lea     tmp, [8*128 + 8*len]
        bswap   tmp
        mov     [lane_data + _extra_block_sha512 + size_offset], tmp

        mov     tmp, [job + _auth_key_xor_ipad]

        vmovdqu ymm0, [tmp]
        vmovdqu ymm1, [tmp + 32]
        lea     tmp, [lane*8]
        vmovdqu [state + _args_digest_sha512 + tmp*8], ymm0
        vmovdqu [state + _args_digest_sha512 + tmp*8 + 32], ymm1

        test    len, ~127
        jnz     ge128_bytes

lt128_bytes:
        mov     [state + _lens_sha512 + 2*lane], WORD(extra_blocks)
        lea     tmp, [lane_data + _extra_block_sha512 + start_offset]
        mov     [state + _args_data_ptr_sha512 + PTR_SZ*lane], tmp ;; 8 to hold a UINT8
        mov     dword [lane_data + _extra_blocks_sha512], 0

ge128_bytes:
        cmp     unused_lanes, 0xff
        jne     return_null

align 32
start_loop:
        ; Find min length
        xor     len2, len2
        mov     tmp, 0x10000
        mov     WORD(len2), word [state + _lens_sha512 + 0*2]   ; [0:15] - lane 0 length, [16:31] - lane index (0)
        mov     WORD(tmp), word [state + _lens_sha512 + 1*2]    ; [0:15] - lane 1 length, [16:31] - lane index (1)
        cmp     WORD(len2), WORD(tmp)
        cmovg   DWORD(len2), DWORD(tmp) ; move if lane 0 length is greater than lane 1 length

        mov     idx, len2               ; retrieve index & length from [16:31] and [0:15] bit fields
        shr     DWORD(idx), 16
        and     DWORD(len2), 0xffff
        je      len_is_0

        sub     word [state + _lens_sha512 + 0*2], WORD(len2)
        sub     word [state + _lens_sha512 + 1*2], WORD(len2)

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

        lea     idx, [idx*8] ;; scale up to SHA512_DIGEST_ROW_SIZE (8*8)
        vmovdqu ymm0, [state + _args_digest_sha512 + idx*8]
        vmovdqu ymm1, [state + _args_digest_sha512 + idx*8 + 32]
        vpshufb ymm0, [rel byteswap]
        vpshufb ymm1, [rel byteswap]
        vmovdqu [lane_data + _outer_block_sha512], ymm0
%if (SHA_X_DIGEST_SIZE != 384)
        vmovdqu [lane_data + _outer_block_sha512+32], ymm1
%else
        vmovdqu [lane_data + _outer_block_sha512+32], xmm1
%endif

        mov     tmp, [job + _auth_key_xor_opad]
        vmovdqu ymm0, [tmp]
        vmovdqu ymm1, [tmp + 32]
        vmovdqu [state + _args_digest_sha512 + idx*8], ymm0
        vmovdqu [state + _args_digest_sha512 + idx*8 + 32], ymm1

        jmp     start_loop

align 32
proc_extra_blocks:
        mov     DWORD(start_offset), [lane_data + _start_offset_sha512]

        mov     [state + _lens_sha512 + 2*idx], WORD(extra_blocks)

        lea     tmp, [lane_data + _extra_block_sha512 + start_offset]
        mov     [state + _args_data_ptr_sha512 + PTR_SZ*idx], tmp ;;  idx is index of shortest length message
        mov     dword [lane_data + _extra_blocks_sha512], 0
        jmp     start_loop

align 32
copy_lt128:
        ;; less than one message block of data
        ;; destination extra block but backwards by len from where 0x80 pre-populated
        lea     p2, [lane_data + _extra_block  + 128]
        sub     p2, len
        memcpy_avx2_128_1 p2, p, len, tmp4, tmp2, ymm0, ymm1, ymm2, ymm3
        mov     unused_lanes, [state + _unused_lanes_sha512]
        jmp     end_fast_copy

return_null:
        xor     job_rax, job_rax
        jmp     return

align 32
end_loop:
        mov     job_rax, [lane_data + _job_in_lane_sha512]
        mov     unused_lanes, [state + _unused_lanes_sha512]
        mov     qword [lane_data + _job_in_lane_sha512], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
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

align 32
copy_full_digest:
	cmp 	qword [job_rax + _auth_tag_output_len_in_bytes], 16
	ja 	copy_tag_gt16

	;; copy up to 16 bytes
	mov    	tmp2, qword [job_rax + _auth_tag_output_len_in_bytes]
	vmovdqa xmm0, [state + _args_digest_sha512 + idx]
	vpshufb xmm0, [rel byteswap]
	simd_store_avx {p + 0*4}, xmm0, tmp2, tmp4, tmp
	jmp 	clear_ret

copy_tag_gt16:
	;; copy 16 bytes first
	vmovdqa xmm0, [state + _args_digest_sha512 + idx]
	vpshufb xmm0, [rel byteswap]
	vmovdqu [p + 0*4], xmm0

	;; calculate remaining bytes to copy
	mov    	tmp2, qword [job_rax + _auth_tag_output_len_in_bytes]
	sub    	tmp2, 16 ; copied 16 bytes already
	cmp 	qword [job_rax + _auth_tag_output_len_in_bytes], 32
	ja	copy_tag_gt32

	;; copy up to 32 bytes
	vmovdqa xmm0, [state + _args_digest_sha512 + idx + 16]
	vpshufb xmm0, [rel byteswap]
	simd_store_avx {p + 4*4}, xmm0, tmp2, tmp4, tmp
	jmp 	clear_ret

copy_tag_gt32:
	;; copy 32 bytes
	vmovdqa xmm0, [state + _args_digest_sha512 + idx + 16]
	vpshufb xmm0, [rel byteswap]
	vmovdqu [p + 4*4], xmm0

	sub    	tmp2, 16 ; copied another 16 bytes
%if (SHA_X_DIGEST_SIZE != 384)
	cmp 	qword [job_rax + _auth_tag_output_len_in_bytes], 48
	ja	copy_tag_gt48
%endif
	;; copy up to 48 bytes
	vmovdqa xmm0, [state + _args_digest_sha512 + idx + 32]
	vpshufb xmm0, [rel byteswap]
	simd_store_avx {p + 8*4}, xmm0, tmp2, tmp4, tmp
	jmp 	clear_ret

copy_tag_gt48:
	;; copy 48 bytes
	vmovdqa xmm0, [state + _args_digest_sha512 + idx + 32]
	vpshufb xmm0, [rel byteswap]
	vmovdqu [p + 8*4], xmm0

	sub    	tmp2, 16 ; copied another 16 bytes

	;; copy up to 64 bytes
	vmovdqa xmm0, [state + _args_digest_sha512 + idx + 48]
	vpshufb xmm0, [rel byteswap]
	simd_store_avx {p + 12*4}, xmm0, tmp2, tmp4, tmp

clear_ret:
%ifdef SAFE_DATA
        ;; Clear digest (48B/64B), outer_block (48B/64B) and extra_block (128B) of returned job
        vpxor   ymm0, ymm0
        vmovdqa [state + _args_digest_sha512 + idx], ymm0
%if (SHA_X_DIGEST_SIZE == 384)
        vmovdqa [state + _args_digest_sha512 + idx + 32], xmm0
%else
        vmovdqa [state + _args_digest_sha512 + idx + 32], ymm0
%endif

        shr     idx, 6 ;; Restore lane idx to 0 or 1
        imul  lane_data, idx, _SHA512_LANE_DATA_size
        lea   lane_data, [state + _ldata_sha512 + lane_data]

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
%endif ;; SAFE_DATA

return:
        vzeroupper

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*3]
        mov     rdi, [rsp + _gpr_save + 8*4]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
        ret

mksection stack-noexec
