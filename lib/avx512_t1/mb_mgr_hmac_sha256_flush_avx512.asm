;;
;; Copyright (c) 2017-2024, Intel Corporation
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

;; In System V AMD64 ABI
;;	callee saves: RBX, RBP, R12-R15
;; Windows x64 ABI
;;	callee saves: RBX, RBP, RDI, RSI, RSP, R12-R15
;;
;; Registers:		RAX RBX RCX RDX RBP RSI RDI R8  R9  R10 R11 R12 R13 R14 R15
;;			-----------------------------------------------------------
;; Windows clobbers:	RAX     RCX RDX             R8  R9  R10 R11
;; Windows preserves:	    RBX         RBP RSI RDI                 R12 R13 R14 R15
;;			-----------------------------------------------------------
;; Linux clobbers:	RAX     RCX RDX     RSI RDI R8  R9  R10 R11
;; Linux preserves:	    RBX         RBP                         R12 R13 R14 R15
;;			-----------------------------------------------------------
;; Clobbers ZMM0-31

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/const.inc"
;; %define DO_DBGPRINT
%include "include/dbgprint.inc"
%include "include/align_avx512.inc"

extern sha256_x16_avx512

mksection .rodata
default rel
align 16
byteswap:
        dq 0x0405060700010203, 0x0c0d0e0f08090a0b
        dq 0x0405060700010203, 0x0c0d0e0f08090a0b

align 32
len_masks:
        dq 0x000000000000FFFF, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
        dq 0x00000000FFFF0000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
        dq 0x0000FFFF00000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
        dq 0xFFFF000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0x000000000000FFFF, 0x0000000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0x00000000FFFF0000, 0x0000000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0x0000FFFF00000000, 0x0000000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0xFFFF000000000000, 0x0000000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0x0000000000000000, 0x000000000000FFFF, 0x0000000000000000
        dq 0x0000000000000000, 0x0000000000000000, 0x00000000FFFF0000, 0x0000000000000000
        dq 0x0000000000000000, 0x0000000000000000, 0x0000FFFF00000000, 0x0000000000000000
        dq 0x0000000000000000, 0x0000000000000000, 0xFFFF000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x000000000000FFFF
        dq 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00000000FFFF0000
        dq 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000FFFF00000000
        dq 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xFFFF000000000000

lane_1: dq  1
lane_2: dq  2
lane_3: dq  3
lane_4: dq  4
lane_5: dq  5
lane_6: dq  6
lane_7: dq  7
lane_8: dq  8
lane_9: dq  9
lane_10: dq  10
lane_11: dq  11
lane_12: dq  12
lane_13: dq  13
lane_14: dq  14
lane_15: dq  15

mksection .text

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    rsi
%endif

%define state   arg1
%define job     arg2
%define len2    arg2

; idx needs to be in rbp, r15
%define idx             rbp

%define unused_lanes    r10
%define tmp5            r10

%define lane_data       rbx
%define tmp2            rbx

%define job_rax         rax
%define tmp1            rax
%define size_offset     rax
%define start_offset    rax

%define tmp3            arg1

%define extra_blocks    arg2
%define p               arg2

%define tmp4            arg3
%define tmp             r9

%define len_upper       r13
%define idx_upper       r14

; we clobber rsi, rbp; called routine also clobbers rax, r9 to r15
struc STACK
_gpr_save:      resq    8
_rsp_save:      resq    1
endstruc

%define APPEND(a,b) a %+ b

; JOB* flush_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state)
; JOB* flush_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state)
; arg 1 : state
align_function
%ifdef SHA224
MKGLOBAL(flush_job_hmac_sha_224_avx512,function,internal)
flush_job_hmac_sha_224_avx512:
%else
MKGLOBAL(flush_job_hmac_sha_256_avx512,function,internal)
flush_job_hmac_sha_256_avx512:
%endif
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -32
        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _rsp_save], rax  ; original SP

        ; if bit (32+3) is set, then all lanes are empty
        cmp     dword [state + _num_lanes_inuse_sha256], 0
        jz      return_null

        ; find lanes with NULL jobs
        xor     idx, idx
        vpxorq          zmm0, zmm0
        vmovdqa64       zmm1, [state + _job_in_lane_sha256]
        vmovdqa64       zmm2, [state + _job_in_lane_sha256 + (8*8)]
        vpcmpq          k1, zmm1, zmm0, 0 ; EQ ; mask of null jobs (L8)
        vpcmpq          k2, zmm2, zmm0, 0 ; EQ ; mask of null jobs (H8)
        kshiftlw        k3, k2, 8
        korw            k3, k3, k1 ; mask of NULL jobs for all lanes

align_label
find_min_len:
        ; - Update lengths of NULL lanes to 0xFFFF, to find minimum
        vmovdqa         ymm0, [state + _lens_sha256]
        mov             DWORD(tmp), 0xffff
        vpbroadcastw    ymm1, DWORD(tmp)
        vmovdqu16       ymm0{k3}, ymm1
        vmovdqa64       [state + _lens_sha256], ymm0

        ;; Find min length for lanes 0-7
        vphminposuw     xmm1, xmm0

        ; extract min length of lanes 0-7
        vpextrw         DWORD(len2), xmm1, 0  ; min value
        vpextrw         DWORD(idx), xmm1, 1   ; min index

        ;; Update lens and find min for lanes 8-15
        vextracti128    xmm2, ymm0, 1
        vphminposuw     xmm3, xmm2
        vpextrw         DWORD(len_upper), xmm3, 0  ; min value
        cmp             DWORD(len2), DWORD(len_upper)
        jbe             copy_lane_data

        vmovdqa         xmm1, xmm3
        vpextrw         DWORD(idx), xmm3, 1   ; min index
        add             DWORD(idx), 8         ; but index +8
        mov             len2, len_upper       ; min len

align_loop
copy_lane_data:
        ; copy valid lane (idx) to empty lanes
        vpbroadcastq    zmm4, [state + _args_data_ptr_sha256 + idx*8]
        vmovdqa64       [state + _args_data_ptr_sha256 + (0*PTR_SZ)]{k1}, zmm4
        vmovdqa64       [state + _args_data_ptr_sha256 + (8*PTR_SZ)]{k2}, zmm4

align_label
use_min:
        cmp     len2, 0
        je      len_is_0

        vpbroadcastw    ymm1, xmm1 ; duplicate words across all lanes
        vpsubw  ymm0, ymm0, ymm1
        vmovdqa [state + _lens_sha256], ymm0

        ; "state" and "args" are the same address, arg1
        ; len is arg2
        call    sha256_x16_avx512
        ; state and idx are intact

align_label
len_is_0:
        ; process completed job "idx"
        imul    lane_data, idx, _HMAC_SHA1_LANE_DATA_size
        lea     lane_data, [state + _ldata_sha256 + lane_data]
        mov     DWORD(extra_blocks), [lane_data + _extra_blocks]
        cmp     extra_blocks, 0
        jne     proc_extra_blocks
        cmp     dword [lane_data + _outer_done], 0
        jne     end_loop

align_label
proc_outer:
        mov     dword [lane_data + _outer_done], 1
        mov     DWORD(size_offset), [lane_data + _size_offset]
        mov     qword [lane_data + _extra_block + size_offset], 0
        vmovdqa ymm5, [state + _lens_sha256]
        VPINSRW_256 ymm5, xmm0, xmm1, tmp, idx, 1, scale_x16
        vmovdqa64 [state + _lens_sha256], ymm5
        lea     tmp, [lane_data + _outer_block]
        mov     [state + _args_data_ptr_sha256 + PTR_SZ*idx], tmp

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

        mov     job, [state + _job_in_lane_sha256 + idx*8]
        mov     tmp, [job + _auth_key_xor_opad]
        vmovdqu xmm0, [tmp]
        vmovdqu xmm1,  [tmp + 4*4]
        vmovd   [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE], xmm0
        vpextrd [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE], xmm0, 1
        vpextrd [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE], xmm0, 2
        vpextrd [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE], xmm0, 3
        vmovd   [state + _args_digest_sha256 + 4*idx + 4*SHA256_DIGEST_ROW_SIZE], xmm1
        vpextrd [state + _args_digest_sha256 + 4*idx + 5*SHA256_DIGEST_ROW_SIZE], xmm1, 1
        vpextrd [state + _args_digest_sha256 + 4*idx + 6*SHA256_DIGEST_ROW_SIZE], xmm1, 2
        vpextrd [state + _args_digest_sha256 + 4*idx + 7*SHA256_DIGEST_ROW_SIZE], xmm1, 3
        jmp     find_min_len

align_label
proc_extra_blocks:
        mov     DWORD(start_offset), [lane_data + _start_offset]
        vmovdqa ymm5, [state + _lens_sha256]
        VPINSRW_256 ymm5, xmm0, xmm1, tmp, idx, extra_blocks, scale_x16
        vmovdqa64 [state + _lens_sha256], ymm5
        lea     tmp, [lane_data + _extra_block + start_offset]
        mov     [state + _args_data_ptr_sha256 + PTR_SZ*idx], tmp
        mov     dword [lane_data + _extra_blocks], 0
        jmp     find_min_len

align_label
return_null:
        xor     job_rax, job_rax
        jmp     return

align_label
end_loop:
        mov     job_rax, [state + _job_in_lane_sha256 + idx*8]
        VPINSRQ_M512x2 state + _job_in_lane_sha256, 0, r12d, zmm6, zmm7, k4, idx
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        mov     unused_lanes, [state + _unused_lanes_sha256]
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _unused_lanes_sha256], unused_lanes

        sub     dword [state + _num_lanes_inuse_sha256], 1

        mov     p, [job_rax + _auth_tag_output]

%ifdef SHA224
        cmp     qword [job_rax + _auth_tag_output_len_in_bytes], 14
        jne     copy_full_digest
%else
        cmp     qword [job_rax + _auth_tag_output_len_in_bytes], 16
        jne     copy_full_digest
%endif

        ;; copy SHA224 14 bytes / SHA256 16 bytes
        movbe   DWORD(tmp),  [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE]
        movbe   DWORD(tmp2), [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE]
        movbe   DWORD(tmp4), [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE]
        movbe   DWORD(tmp5), [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE]
        mov     [p + 0*4], DWORD(tmp)
        mov     [p + 1*4], DWORD(tmp2)
        mov     [p + 2*4], DWORD(tmp4)
%ifdef SHA224
        mov     [p + 3*4], WORD(tmp5)
%else
        mov     [p + 3*4], DWORD(tmp5)
%endif
        jmp     clear_ret

align_label
copy_full_digest:
%ifndef LINUX
        mov     tmp2, rcx ; save rcx
%endif
        mov     rcx, qword [job_rax + _auth_tag_output_len_in_bytes]

        mov     tmp4, 1
        shl     tmp4, cl  ; Calculate the mask for copying bytes
        dec     tmp4
        kmovq   k1, tmp4

%ifndef LINUX
        mov     rcx, tmp2 ; restore rcx
%endif

        ;; copy up to 28/32 bytes
        vmovd   xmm0, [state + _args_digest_sha256 + 4*idx + 0*SHA256_DIGEST_ROW_SIZE]
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 1*SHA256_DIGEST_ROW_SIZE], 1
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 2*SHA256_DIGEST_ROW_SIZE], 2
        vpinsrd xmm0, [state + _args_digest_sha256 + 4*idx + 3*SHA256_DIGEST_ROW_SIZE], 3

        vmovd   xmm1, [state + _args_digest_sha256 + 4*idx + 4*SHA256_DIGEST_ROW_SIZE]
        vpinsrd xmm1, [state + _args_digest_sha256 + 4*idx + 5*SHA256_DIGEST_ROW_SIZE], 1
        vpinsrd xmm1, [state + _args_digest_sha256 + 4*idx + 6*SHA256_DIGEST_ROW_SIZE], 2
%ifndef SHA224
        vpinsrd xmm1, [state + _args_digest_sha256 + 4*idx + 7*SHA256_DIGEST_ROW_SIZE], 3
%endif

        vinserti128 ymm0, xmm1, 1
        vpshufb ymm0, ymm0, [rel byteswap]
        vmovdqu8 [p + 0*4]{k1}, ymm0 ; Store bytes

align_label
clear_ret:

%ifdef SAFE_DATA
        vpxorq  zmm0, zmm0

        ;; Clear extra_block (64B) of returned job and NULL jobs
%assign I 0
%rep 16
        cmp     qword [state + _job_in_lane_sha256 + I*8], 0
        jne     APPEND(skip_clear_,I)

        lea     lane_data, [state + _ldata_sha256 + (I*_HMAC_SHA1_LANE_DATA_size)]
        ;; Clear first 64 bytes of extra_block
        vmovdqu64 [lane_data + _extra_block], zmm0

APPEND(skip_clear_,I):
%assign I (I+1)
%endrep

%endif ;; SAFE_DATA

%ifdef SAFE_DATA
        clear_all_zmms_asm
%else
        vzeroupper
%endif

align_label
return:
        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        ret

mksection stack-noexec
