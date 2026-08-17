;;
;; Copyright (c) 2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/mb_mgr_aes_cmac_submit_flush_sse.inc"
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
dupw:
        dq 0x0100010001000100, 0x0100010001000100

one:    dq  1
two:    dq  2
three:  dq  3
four:   dq  4
five:   dq  5
six:    dq  6
seven:  dq  7

align 16
len_shuf_masks:
        dq 0XFFFFFFFF09080100, 0XFFFFFFFFFFFFFFFF
        dq 0X09080100FFFFFFFF, 0XFFFFFFFFFFFFFFFF
        dq 0XFFFFFFFFFFFFFFFF, 0XFFFFFFFF09080100
        dq 0XFFFFFFFFFFFFFFFF, 0X09080100FFFFFFFF

mksection .text
extern aes128_cbc_mac_x8_sse
extern aes256_cbc_mac_x8_sse

; IMB_JOB * submit_job_aes128_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(submit_job_aes128_cmac_auth_x8_sse,function,internal)
align_function
submit_job_aes128_cmac_auth_x8_sse:
        GENERIC_SUBMIT_FLUSH_JOB_AES_CMAC_SSE SUBMIT, aes128_cbc_mac_x8_sse

; IMB_JOB * flush_job_aes128_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state)
; arg 1 : state
MKGLOBAL(flush_job_aes128_cmac_auth_x8_sse,function,internal)
align_function
flush_job_aes128_cmac_auth_x8_sse:
        GENERIC_SUBMIT_FLUSH_JOB_AES_CMAC_SSE FLUSH, aes128_cbc_mac_x8_sse

; IMB_JOB * submit_job_aes256_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(submit_job_aes256_cmac_auth_x8_sse,function,internal)
align_function
submit_job_aes256_cmac_auth_x8_sse:
        GENERIC_SUBMIT_FLUSH_JOB_AES_CMAC_SSE SUBMIT, aes256_cbc_mac_x8_sse

; IMB_JOB * flush_job_aes256_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state)
; arg 1 : state
MKGLOBAL(flush_job_aes256_cmac_auth_x8_sse,function,internal)
align_function
flush_job_aes256_cmac_auth_x8_sse:
        GENERIC_SUBMIT_FLUSH_JOB_AES_CMAC_SSE FLUSH, aes256_cbc_mac_x8_sse

mksection stack-noexec
