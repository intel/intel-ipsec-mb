;;
;; Copyright (c) 2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/mb_mgr_aes_ccm_submit_flush_sse.inc"
%include "include/align_sse.inc"

mksection .rodata
default rel

align 16
len_masks:
        dq 0x000000000000FFFF, 0x0000000000000000
        dq 0x00000000FFFF0000, 0x0000000000000000
        dq 0x0000FFFF00000000, 0x0000000000000000
        dq 0xFFFF000000000000, 0x0000000000000000
        dq 0x0000000000000000, 0x000000000000FFFF
        dq 0x0000000000000000, 0x00000000FFFF0000
        dq 0x0000000000000000, 0x0000FFFF00000000
        dq 0x0000000000000000, 0xFFFF000000000000

align 16
len_shuf_masks:
        dq 0XFFFFFFFF09080100, 0XFFFFFFFFFFFFFFFF
        dq 0X09080100FFFFFFFF, 0XFFFFFFFFFFFFFFFF
        dq 0XFFFFFFFFFFFFFFFF, 0XFFFFFFFF09080100
        dq 0XFFFFFFFFFFFFFFFF, 0X09080100FFFFFFFF

align 16
dupw:
        dq 0x0100010001000100, 0x0100010001000100

align 16
counter_mask:
        dq 0xFFFFFFFFFFFFFF07, 0x0000FFFFFFFFFFFF

one:    dq  1
two:    dq  2
three:  dq  3
four:   dq  4
five:   dq  5
six:    dq  6
seven:  dq  7

mksection .text

extern aes128_cbc_mac_x8_sse
extern aes256_cbc_mac_x8_sse

; IMB_JOB * submit_job_aes128_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(submit_job_aes128_ccm_auth_x8_sse,function,internal)
align_function
submit_job_aes128_ccm_auth_x8_sse:
        endbranch64
        GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_SSE SUBMIT, aes128_cbc_mac_x8_sse, 9

; IMB_JOB * flush_job_aes128_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state)
; arg 1 : state
MKGLOBAL(flush_job_aes128_ccm_auth_x8_sse,function,internal)
align_function
flush_job_aes128_ccm_auth_x8_sse:
        endbranch64
        GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_SSE FLUSH, aes128_cbc_mac_x8_sse, 9

; IMB_JOB * submit_job_aes256_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(submit_job_aes256_ccm_auth_x8_sse,function,internal)
align_function
submit_job_aes256_ccm_auth_x8_sse:
        endbranch64
        GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_SSE SUBMIT, aes256_cbc_mac_x8_sse, 13

; IMB_JOB * flush_job_aes256_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state)
; arg 1 : state
MKGLOBAL(flush_job_aes256_ccm_auth_x8_sse,function,internal)
align_function
flush_job_aes256_ccm_auth_x8_sse:
        endbranch64
        GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_SSE FLUSH, aes256_cbc_mac_x8_sse, 13

mksection stack-noexec
