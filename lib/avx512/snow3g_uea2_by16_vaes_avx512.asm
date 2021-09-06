;;
;; Copyright (c) 2021, Intel Corporation
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
%include "include/mb_mgr_datastruct.asm"
%include "include/transpose_avx512.asm"
%include "include/imb_job.asm"
%include "include/constant_lookup.asm"

section .data
default rel

align 64
dw_len_to_db_mask:
        dq 0x0000000000000000, 0x000000000000000f, 0x00000000000000ff, 0x0000000000000fff
        dq 0x000000000000ffff, 0x00000000000fffff, 0x0000000000ffffff, 0x000000000fffffff
        dq 0x00000000ffffffff, 0x0000000fffffffff, 0x000000ffffffffff, 0x00000fffffffffff
        dq 0x0000ffffffffffff, 0x000fffffffffffff, 0x00ffffffffffffff, 0x0fffffffffffffff
        dq 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000

align 64
const_byte_shuff_mask:
        times 4 dq 0x0405060700010203, 0x0c0d0e0f08090a0b

align 64
const_fixup:
        ;; MSbits in qw shuffled according to aes mix col matrix mul
        times 8 dq 0x273f372f071f170f

align 64
const_fixup_mask:
        times 8 dq 0x7272727272727272

align 64
const_fixed_rotate_mask:
        ;; inverse of aesenc shift rows operation
        times 4 dq 0x0b0e0104070a0d00, 0x0306090c0f020508

align 64
const_mulalpha_map_00_0f:
        dq 0xe19fcf1300000000, 0x8a08f8356b973726
        dq 0x3718a15fd6876e4c, 0x5c8f9679bd10596a
        dq 0xe438138b05a7dc98, 0x8faf24ad6e30ebbe
        dq 0x32bf7dc7d320b2d4, 0x59284ae1b8b785f2
        dq 0xeb78de8a0ae71199, 0x80efe9ac617026bf
        dq 0x3dffb0c6dc607fd5, 0x566887e0b7f748f3
        dq 0xeedf02120f40cd01, 0x8548353464d7fa27
        dq 0x38586c5ed9c7a34d, 0x53cf5b78b250946b
        dq 0xf5f8ed881467229b, 0x9e6fdaae7ff015bd
        dq 0x237f83c4c2e04cd7, 0x48e8b4e2a9777bf1
        dq 0xf05f311011c0fe03, 0x9bc806367a57c925
        dq 0x26d85f5cc747904f, 0x4d4f687aacd0a769
        dq 0xff1ffc111e803302, 0x9488cb3775170424
        dq 0x2998925dc8075d4e, 0x420fa57ba3906a68
        dq 0xfab820891b27ef9a, 0x912f17af70b0d8bc
        dq 0x2c3f4ec5cda081d6, 0x47a879e3a637b6f0
        dq 0xc9518b8c28ce449f, 0xa2c6bcaa435973b9
        dq 0x1fd6e5c0fe492ad3, 0x7441d2e695de1df5
        dq 0xccf657142d699807, 0xa761603246feaf21
        dq 0x1a713958fbeef64b, 0x71e60e7e9079c16d
        dq 0xc3b69a1522295506, 0xa821ad3349be6220
        dq 0x1531f459f4ae3b4a, 0x7ea6c37f9f390c6c
        dq 0xc611468d278e899e, 0xad8671ab4c19beb8
        dq 0x109628c1f109e7d2, 0x7b011fe79a9ed0f4
        dq 0xdd36a9173ca96604, 0xb6a19e31573e5122
        dq 0x0bb1c75bea2e0848, 0x6026f07d81b93f6e
        dq 0xd891758f390eba9c, 0xb30642a952998dba
        dq 0x0e161bc3ef89d4d0, 0x65812ce5841ee3f6
        dq 0xd7d1b88e364e779d, 0xbc468fa85dd940bb
        dq 0x0156d6c2e0c919d1, 0x6ac1e1e48b5e2ef7
        dq 0xd276641633e9ab05, 0xb9e15330587e9c23
        dq 0x04f10a5ae56ec549, 0x6f663d7c8ef9f26f

align 64
const_mulalpha_map_80_8f:
        dq 0xb1aa478450358897, 0xda3d70a23ba2bfb1
        dq 0x672d29c886b2e6db, 0x0cba1eeeed25d1fd
        dq 0xb40d9b1c5592540f, 0xdf9aac3a3e056329
        dq 0x628af55083153a43, 0x091dc276e8820d65
        dq 0xbb4d561d5ad2990e, 0xd0da613b3145ae28
        dq 0x6dca38518c55f742, 0x065d0f77e7c2c064
        dq 0xbeea8a855f754596, 0xd57dbda334e272b0
        dq 0x686de4c989f22bda, 0x03fad3efe2651cfc
        dq 0xa5cd651f4452aa0c, 0xce5a52392fc59d2a
        dq 0x734a0b5392d5c440, 0x18dd3c75f942f366
        dq 0xa06ab98741f57694, 0xcbfd8ea12a6241b2
        dq 0x76edd7cb977218d8, 0x1d7ae0edfce52ffe
        dq 0xaf2a74864eb5bb95, 0xc4bd43a025228cb3
        dq 0x79ad1aca9832d5d9, 0x123a2decf3a5e2ff
        dq 0xaa8da81e4b12670d, 0xc11a9f382085502b
        dq 0x7c0ac6529d950941, 0x179df174f6023e67
        dq 0x9964031b78fbcc08, 0xf2f3343d136cfb2e
        dq 0x4fe36d57ae7ca244, 0x24745a71c5eb9562
        dq 0x9cc3df837d5c1090, 0xf754e8a516cb27b6
        dq 0x4a44b1cfabdb7edc, 0x21d386e9c04c49fa
        dq 0x93831282721cdd91, 0xf81425a4198beab7
        dq 0x45047ccea49bb3dd, 0x2e934be8cf0c84fb
        dq 0x9624ce1a77bb0109, 0xfdb3f93c1c2c362f
        dq 0x40a3a056a13c6f45, 0x2b349770caab5863
        dq 0x8d0321806c9cee93, 0xe69416a6070bd9b5
        dq 0x5b844fccba1b80df, 0x301378ead18cb7f9
        dq 0x88a4fd18693b320b, 0xe333ca3e02ac052d
        dq 0x5e239354bfbc5c47, 0x35b4a472d42b6b61
        dq 0x87e43019667bff0a, 0xec73073f0decc82c
        dq 0x51635e55b0fc9146, 0x3af46973db6ba660
        dq 0x8243ec8163dc2392, 0xe9d4dba7084b14b4
        dq 0x54c482cdb55b4dde, 0x3f53b5ebdecc7af8

align 64
const_divalpha_map_00_0f:
        dq 0x180f40cd00000000, 0x2811c0fe301e8033
        dq 0x7833e9ab603ca966, 0x482d699850222955
        dq 0xd877bb01c078fbcc, 0xe8693b32f0667bff
        dq 0xb84b1267a04452aa, 0x88559254905ad299
        dq 0x31ff1ffc29f05f31, 0x01e19fcf19eedf02
        dq 0x51c3b69a49ccf657, 0x61dd36a979d27664
        dq 0xf187e430e988a4fd, 0xc1996403d99624ce
        dq 0x91bb4d5689b40d9b, 0xa1a5cd65b9aa8da8
        dq 0x4a46feaf5249be62, 0x7a587e9c62573e51
        dq 0x2a7a57c932751704, 0x1a64d7fa026b9737
        dq 0x8a3e0563923145ae, 0xba208550a22fc59d
        dq 0xea02ac05f20decc8, 0xda1c2c36c2136cfb
        dq 0x63b6a19e7bb9e153, 0x53a821ad4ba76160
        dq 0x038a08f81b854835, 0x339488cb2b9bc806
        dq 0xa3ce5a52bbc11a9f, 0x93d0da618bdf9aac
        dq 0xc3f2f334dbfdb3f9, 0xf3ec7307ebe333ca
        dq 0xbc9d9509a492d5c4, 0x8c83153a948c55f7
        dq 0xdca13c6fc4ae7ca2, 0xecbfbc5cf4b0fc91
        dq 0x7ce56ec564ea2e08, 0x4cfbeef654f4ae3b
        dq 0x1cd9c7a304d6876e, 0x2cc7479034c8075d
        dq 0x956dca388d628af5, 0xa5734a0bbd7c0ac6
        dq 0xf551635eed5e2393, 0xc54fe36ddd40a3a0
        dq 0x551531f44d1a7139, 0x650bb1c77d04f10a
        dq 0x352998922d26d85f, 0x053718a11d38586c
        dq 0xeed42b6bf6db6ba6, 0xdecaab58c6c5eb95
        dq 0x8ee8820d96e7c2c0, 0xbef6023ea6f942f3
        dq 0x2eacd0a736a3906a, 0x1eb2509406bd1059
        dq 0x4e9079c1569f390c, 0x7e8ef9f26681b93f
        dq 0xc724745adf2b3497, 0xf73af469ef35b4a4
        dq 0xa718dd3cbf179df1, 0x97065d0f8f091dc2
        dq 0x075c8f961f53cf5b, 0x37420fa52f4d4f68
        dq 0x676026f07f6f663d, 0x577ea6c34f71e60e

align 64
const_divalpha_map_80_8f:
        dq 0xf98243ece18d0321, 0xc99cc3dfd1938312
        dq 0x99beea8a81b1aa47, 0xa9a06ab9b1af2a74
        dq 0x39fab82021f5f8ed, 0x09e4381311eb78de
        dq 0x59c6114641c9518b, 0x69d8917571d7d1b8
        dq 0xd0721cddc87d5c10, 0xe06c9ceef863dc23
        dq 0xb04eb5bba841f576, 0x80503588985f7545
        dq 0x100ae7110805a7dc, 0x20146722381b27ef
        dq 0x70364e7768390eba, 0x4028ce4458278e89
        dq 0xabcbfd8eb3c4bd43, 0x9bd57dbd83da3d70
        dq 0xcbf754e8d3f81425, 0xfbe9d4dbe3e69416
        dq 0x6bb3064273bc468f, 0x5bad867143a2c6bc
        dq 0x0b8faf241380efe9, 0x3b912f17239e6fda
        dq 0x823ba2bf9a34e272, 0xb225228caa2a6241
        dq 0xe2070bd9fa084b14, 0xd2198beaca16cb27
        dq 0x424359735a4c19be, 0x725dd9406a52998d
        dq 0x227ff0153a70b0d8, 0x126170260a6e30eb
        dq 0x5d109628451fd6e5, 0x6d0e161b750156d6
        dq 0x3d2c3f4e25237f83, 0x0d32bf7d153dffb0
        dq 0x9d686de485672d29, 0xad76edd7b579ad1a
        dq 0xfd54c482e55b844f, 0xcd4a44b1d545047c
        dq 0x74e0c9196cef89d4, 0x44fe492a5cf109e7
        dq 0x14dc607f0cd320b2, 0x24c2e04c3ccda081
        dq 0xb49832d5ac977218, 0x8486b2e69c89f22b
        dq 0xd4a49bb3ccabdb7e, 0xe4ba1b80fcb55b4d
        dq 0x0f59284a17566887, 0x3f47a8792748e8b4
        dq 0x6f65812c776ac1e1, 0x5f7b011f477441d2
        dq 0xcf21d386d72e934b, 0xff3f53b5e7301378
        dq 0xaf1d7ae0b7123a2d, 0x9f03fad3870cba1e
        dq 0x26a9777b3ea637b6, 0x16b7f7480eb8b785
        dq 0x4695de1d5e9a9ed0, 0x768b5e2e6e841ee3
        dq 0xe6d18cb7fedecc7a, 0xd6cf0c84cec04c49
        dq 0x86ed25d19ee2651c, 0xb6f3a5e2aefce52f

align 64
const_transf_map:
        dq 0x08A7BE0D0A8FA6C2, 0x9F11D2135945991D
        dq 0xC1588D92A4D4E6AE, 0x3BBC4F9D84C897D0
        dq 0xEEE34E725327EB2D, 0xDB442F5C4DAA7FDA
        dq 0x4C166AC3C5673A3E, 0x19F26270DDD7CC38
        dq 0x0386C9614B980910, 0x8C5D546E335A6BA8
        dq 0x80F8C682F6F71A41, 0xBA7B2C65B3FEC7C0
        dq 0x5FF5730C222AFCB4, 0x143524B2942E6864
        dq 0x0743EDDE48BFFB78, 0x46577D74BDE432B6
        dq 0x55F38A51B7C4373C, 0x93E1A377AB79CF6C
        dq 0x8B7E9A2B5B816DD5, 0x5247A191D385B504
        dq 0xF0268720BBD6ECA5, 0x50CB25CEF4894AAF
        dq 0xA93D219042D93F00, 0xCDFA5E36F10129E7
        dq 0x76A09EFD051B31E5, 0x1CEA569BB075B130
        dq 0xFF1588957A6906EF, 0x0B280FD8230EACCA
        dq 0x9C3966831E63F918, 0xA27C34D1E81F49E2
        dq 0x71ADDFE91202E0B9, 0xDC176040B86F8E96

align 64
dw_e0s:
        times 16 dd 0x000000e0

align 64
dw_20s:
        times 16 dd 0x00000020

align 64
dw_40s:
        times 16 dd 0x00000040

align 64
dw_60s:
        times 16 dd 0x00000060

align 64
dw_80s:
        times 16 dd 0x00000080

align 64
dw_a0s:
        times 16 dd 0x000000a0

align 64
dw_c0s:
        times 16 dd 0x000000c0

align 64
all_fs:
        times 16 dq 0xffffffffffffffff

section .text

%xdefine KEYSTREAM              zmm0
%xdefine KEYSTREAM_XMM_TEMP     XWORD(KEYSTREAM)

%xdefine FSM1                   zmm1
%xdefine FSM2                   zmm2
%xdefine FSM3                   zmm3

%xdefine FIXED_ROTATE_MASK      zmm4
%xdefine FIXED_M_MASK           zmm5
%xdefine FIXED_PATTERN_SHUF     zmm6
%xdefine FIXED_MAP_TAB_0        zmm7
%xdefine FIXED_MAP_TAB_1        zmm8
%xdefine FIXED_MAP_TAB_2        zmm9
%xdefine FIXED_MAP_TAB_3        zmm10

%xdefine LFSR_0                 zmm11
%xdefine LFSR_1                 zmm12
%xdefine LFSR_2                 zmm13
%xdefine LFSR_3                 zmm14
%xdefine LFSR_4                 zmm15
%xdefine LFSR_5                 zmm16
%xdefine LFSR_6                 zmm17
%xdefine LFSR_7                 zmm18
%xdefine LFSR_8                 zmm19
%xdefine LFSR_9                 zmm20
%xdefine LFSR_10                zmm21
%xdefine LFSR_11                zmm22
%xdefine LFSR_12                zmm23
%xdefine LFSR_13                zmm24
%xdefine LFSR_14                zmm25
%xdefine LFSR_15                zmm26

%xdefine TEMP_27                zmm27
%xdefine TEMP_28                zmm28
%xdefine TEMP_29                zmm29
%xdefine TEMP_30                zmm30
%xdefine TEMP_31                zmm31

struc STACK
_keystream:     resb    (16 * 64)
_gpr_save:      resq    10
_rsp_save:      resq    1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Saves register contents and creates stack frame for key stream
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, ~63

        mov     [rsp + _gpr_save + 8 * 0], rbx
        mov     [rsp + _gpr_save + 8 * 1], rbp
        mov     [rsp + _gpr_save + 8 * 2], rcx
        mov     [rsp + _gpr_save + 8 * 3], rdx
        mov     [rsp + _gpr_save + 8 * 4], r12
        mov     [rsp + _gpr_save + 8 * 5], r13
        mov     [rsp + _gpr_save + 8 * 6], r14
        mov     [rsp + _gpr_save + 8 * 7], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8 * 8], rsi
        mov     [rsp + _gpr_save + 8 * 9], rdi
%endif
        mov     [rsp + _rsp_save], rax          ;; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restores register contents and removes the stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_FUNC_END 0
%ifndef SAFE_DATA
        vzeroupper
%endif
        mov     rbx, [rsp + _gpr_save + 8 * 0]
        mov     rbp, [rsp + _gpr_save + 8 * 1]
        mov     rcx, [rsp + _gpr_save + 8 * 2] ;; @todo rcx, rdx don't need to be preserved per windows / sysv abi
        mov     rdx, [rsp + _gpr_save + 8 * 3]
        mov     r12, [rsp + _gpr_save + 8 * 4]
        mov     r13, [rsp + _gpr_save + 8 * 5]
        mov     r14, [rsp + _gpr_save + 8 * 6]
        mov     r15, [rsp + _gpr_save + 8 * 7]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8 * 8]
        mov     rdi, [rsp + _gpr_save + 8 * 9]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; CLOCK FSM
;; Updates FSM state and returns generated keystream for 16 buffers
;; The same macro is used for initialization and keygen phase
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro FSM_CLOCK 19
%define %%FSM_X1            %1  ;;[in/out] zmm with 16 FSM 1 values
%define %%FSM_X2            %2  ;;[in/out] zmm with 16 FSM 2 values
%define %%FSM_X3            %3  ;;[in/out] zmm with 16 FSM 3 values
%define %%LFSR_5            %4  ;;[in] zmm with 16 LFSR 5 values
%define %%LFSR_15           %5  ;;[in] zmm with 16 LFSR 15 values
%define %%OUT_F             %6  ;; [out] zmm for generated keystreams
%define %%ZERO              %7  ;; [clobbered] temporary zmm register
%define %%TEMP_R            %8  ;; [clobbered] temporary zmm register
%define %%TEMP_MIX          %9  ;; [clobbered] temporary zmm register
%define %%TEMP_NO_MIX       %10 ;; [clobbered] temporary zmm register
%define %%TEMP              %11 ;; [clobbered] temporary zmm register
%define %%MAP_TAB_0         %12 ;; [in] lookup values for bytes eq 0-3f
%define %%MAP_TAB_1         %13 ;; [in] lookup values for bytes eq 40-7f
%define %%MAP_TAB_2         %14 ;; [in] lookup values for bytes eq 80-bf
%define %%MAP_TAB_3         %15 ;; [in] lookup values for bytes eq c0-ff
%define %%KR1               %16 ;; [clobbered] temporary k-register
%define %%KR2               %17 ;; [clobbered] temporary k-register
%define %%KR3               %18 ;; [clobbered] temporary k-register
%define %%KR4               %19 ;; [clobbered] temporary k-register

        ;; TEMP_R = S2(FSM[2])
        LOOKUP8_64_AVX512_VBMI_4_MAP_TABLES \
                        %%FSM_X2, %%TEMP_R, %%ZERO, \
                        %%TEMP_MIX, %%TEMP_NO_MIX, %%TEMP, \
                        %%MAP_TAB_0, %%MAP_TAB_1, \
                        %%MAP_TAB_2, %%MAP_TAB_3, \
                        %%KR1, %%KR2, %%KR3, %%KR4

        vpxord          %%ZERO, %%ZERO, %%ZERO
        vpshufb         %%TEMP, %%TEMP_R, FIXED_ROTATE_MASK

        ;; u32 r = ( FSM[2] + ( FSM[3] ^ LFSR[5] ) ) & 0xffffffff
        vpxord          %%TEMP_R, %%FSM_X3, %%LFSR_5
        vpaddd          %%TEMP_R, %%TEMP_R, %%FSM_X2

        ;; u32 F = ( ( LFSR[15] + FSM[1] ) & 0xffffffff ) ^ FSM[2]
        vpaddd          %%TEMP_NO_MIX, %%FSM_X1, %%LFSR_15
        vpxord          %%OUT_F, %%TEMP_NO_MIX, %%FSM_X2

        vaesenc         %%TEMP_MIX, %%TEMP, %%ZERO
        vaesenclast     %%TEMP_NO_MIX, %%TEMP, %%ZERO

        vpcmpgtb        %%KR1, %%ZERO, %%TEMP_NO_MIX
        vpshufbitqmb    %%KR2, %%TEMP_NO_MIX, FIXED_PATTERN_SHUF
        kxorq           %%KR3, %%KR1, %%KR2

        vmovdqu8        %%ZERO{%%KR3}, FIXED_M_MASK

        vpxord          %%FSM_X3, %%TEMP_MIX, %%ZERO

        ;; FSM[2] = S1(FSM[1])
        vpxord          %%ZERO, %%ZERO, %%ZERO

        vpshufb         %%TEMP, %%FSM_X1, FIXED_ROTATE_MASK
        vaesenc         %%TEMP, %%TEMP, %%ZERO
        vmovdqa32       %%FSM_X2, %%TEMP

        ;; FSM[1] = R
        vmovdqa32       %%FSM_X1, %%TEMP_R
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; LFSR INIT
;; Initialize LFSRs0-15 for single key-iv pair
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro LFSR_INIT_2 5
%xdefine %%ALL_FS            %1 ;; [in] zmm with all bits set to 1
%xdefine %%KPOS              %2 ;; [in] k-register with lane mask
%xdefine %%KEY               %3 ;; [in] address of key
%xdefine %%IV                %4 ;; [in] address of iv
%xdefine %%TEMP              %5 ;; [clobbered] temporary zmm register

        vpbroadcastd    %%TEMP, [%%KEY]
        vmovdqa32       LFSR_4{%%KPOS}, %%TEMP
        vmovdqa32       LFSR_12{%%KPOS}, %%TEMP
        vpxord          LFSR_0{%%KPOS}, %%ALL_FS, %%TEMP
        vpxord          LFSR_8{%%KPOS}, %%ALL_FS, %%TEMP

        vpbroadcastd    %%TEMP, [%%KEY + 4]
        vmovdqa32       LFSR_5{%%KPOS}, %%TEMP
        vmovdqa32       LFSR_13{%%KPOS}, %%TEMP
        vpxord          LFSR_1{%%KPOS}, %%ALL_FS, %%TEMP
        vpxord          LFSR_9{%%KPOS}, %%ALL_FS, %%TEMP

        vpbroadcastd    %%TEMP, [%%KEY + 8]
        vmovdqa32       LFSR_6{%%KPOS}, %%TEMP
        vmovdqa32       LFSR_14{%%KPOS}, %%TEMP
        vpxord          LFSR_2{%%KPOS}, %%ALL_FS, %%TEMP
        vpxord          LFSR_10{%%KPOS}, %%ALL_FS, %%TEMP

        vpbroadcastd    %%TEMP, [%%KEY + 12]
        vmovdqa32       LFSR_7{%%KPOS}, %%TEMP
        vmovdqa32       LFSR_15{%%KPOS}, %%TEMP
        vpxord          LFSR_3{%%KPOS}, %%ALL_FS, %%TEMP
        vpxord          LFSR_11{%%KPOS}, %%ALL_FS, %%TEMP

        vpbroadcastd    %%TEMP, [%%IV + 12]
        vpshufb         %%TEMP, %%TEMP, [rel const_byte_shuff_mask]
        vpxord          LFSR_15{%%KPOS}, LFSR_15, %%TEMP

        vpbroadcastd    %%TEMP, [%%IV + 8]
        vpshufb         %%TEMP, %%TEMP, [rel const_byte_shuff_mask]
        vpxord          LFSR_12{%%KPOS}, LFSR_12, %%TEMP

        vpbroadcastd    %%TEMP, [%%IV + 4]
        vpshufb         %%TEMP, %%TEMP, [rel const_byte_shuff_mask]
        vpxord          LFSR_10{%%KPOS}, LFSR_10, %%TEMP

        vpbroadcastd    %%TEMP, [%%IV]
        vpshufb         %%TEMP, %%TEMP, [rel const_byte_shuff_mask]
        vpxord          LFSR_9{%%KPOS}, LFSR_9, %%TEMP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; MulAlpha/DivAlpha operation
;; Note:
;;    arg5, arg6 - addresses for low and high part of maps used to do transpose,
;;                 maps differ for mul and div operations
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro ALPHA_OP_16 11
%xdefine %%IO_LFSR_X    %1  ;; [in/out] zmm reg for Mulalpha/Divalpha result
%xdefine %%TEMP_MAP     %2  ;; [clobbered] temporary zmm register
%xdefine %%TEMP1        %3  ;; [clobbered] temporary zmm register
%xdefine %%TEMP2        %4  ;; [clobbered] temporary zmm register
%xdefine %%MAP_LO       %5  ;; [in] ptr to low part of transpose map
%xdefine %%MAP_HI       %6  ;; [in] ptr to hihg part of transpose map
%xdefine %%KR1          %7  ;; [clobbered] temporary k-register
%xdefine %%KR2          %8  ;; [clobbered] temporary k-register
%xdefine %%KR3          %9  ;; [clobbered] temporary k-register
%xdefine %%KR4          %10 ;; [clobbered] temporary k-register
%xdefine %%KR5          %11 ;; [clobbered] temporary k-register

        vpandq             %%TEMP1, %%IO_LFSR_X, [rel dw_e0s] ;; 3 MSB on each dw

        vpxorq             %%TEMP2, %%TEMP2
        vpcmpeqd           %%KR1, %%TEMP1, %%TEMP2
        vpcmpeqd           %%KR2, %%TEMP1, [rel dw_20s]
        vpcmpeqd           %%KR3, %%TEMP1, [rel dw_40s]
        vpcmpeqd           %%KR4, %%TEMP1, [rel dw_60s]
        vpcmpeqd           %%KR5, %%TEMP1, [rel dw_80s]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_LO + 64*0]
        vpermi2d           %%IO_LFSR_X{%%KR1}, %%TEMP_MAP, [rel %%MAP_LO + 64*1]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_LO + 64*2]
        vpermi2d           %%IO_LFSR_X{%%KR2}, %%TEMP_MAP, [rel %%MAP_LO + 64*3]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_LO + 64*4]
        vpermi2d           %%IO_LFSR_X{%%KR3}, %%TEMP_MAP, [rel %%MAP_LO + 64*5]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_LO + 64*6]
        vpermi2d           %%IO_LFSR_X{%%KR4}, %%TEMP_MAP, [rel %%MAP_LO + 64*7]
        vpcmpeqd           %%KR1, %%TEMP1, [rel dw_e0s]
        vpcmpeqd           %%KR2, %%TEMP1, [rel dw_c0s]
        vpcmpeqd           %%KR3, %%TEMP1, [rel dw_a0s]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_HI + 64*0]
        vpermi2d           %%IO_LFSR_X{%%KR5}, %%TEMP_MAP, [rel %%MAP_HI + 64*1]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_HI + 64*2]
        vpermi2d           %%IO_LFSR_X{%%KR3}, %%TEMP_MAP, [rel %%MAP_HI + 64*3]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_HI + 64*4]
        vpermi2d           %%IO_LFSR_X{%%KR2}, %%TEMP_MAP, [rel %%MAP_HI + 64*5]

        vmovdqa64          %%TEMP_MAP, [rel %%MAP_HI + 64*6]
        vpermi2d           %%IO_LFSR_X{%%KR1}, %%TEMP_MAP, [rel %%MAP_HI + 64*7]
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; LFSR_CLOCK
;; updates LFSRs0-15
;; The same macro is used for initialization and keygen phase
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro LFSR_CLOCK 10
%xdefine %%TEMP      %1  ;; [clobbered] temporary zmm register
%xdefine %%TEMP1     %2  ;; [clobbered] temporary zmm register
%xdefine %%TEMP2     %3  ;; [clobbered] temporary zmm register
%xdefine %%TEMP3     %4  ;; [clobbered] temporary zmm register
%xdefine %%TEMP4     %5  ;; [clobbered] temporary zmm register
%xdefine %%KR1       %6  ;; [clobbered] temporary k-register
%xdefine %%KR2       %7  ;; [clobbered] temporary k-register
%xdefine %%KR3       %8  ;; [clobbered] temporary k-register
%xdefine %%KR4       %9  ;; [clobbered] temporary k-register
%xdefine %%KR5       %10 ;; [clobbered] temporary k-register

        vpslld          %%TEMP, LFSR_0, 8
        vpxord          %%TEMP, %%TEMP, LFSR_2

        vpsrld          %%TEMP4, LFSR_0, 24

        ;; LFSR_0 = Mulalpha(LFSR[0]>>24 & 0xff)
        ALPHA_OP_16     %%TEMP4, %%TEMP1, %%TEMP2, %%TEMP3, \
                        const_mulalpha_map_00_0f, \
                        const_mulalpha_map_80_8f, \
                        %%KR1, %%KR2, %%KR3, %%KR4, %%KR5

        vpxord          %%TEMP,  %%TEMP, %%TEMP4

        vmovdqa32       LFSR_0, LFSR_1
        vmovdqa32       LFSR_1, LFSR_2
        vmovdqa32       LFSR_2, LFSR_3
        vmovdqa32       LFSR_3, LFSR_4
        vmovdqa32       LFSR_4, LFSR_5
        vmovdqa32       LFSR_5, LFSR_6
        vmovdqa32       LFSR_6, LFSR_7
        vmovdqa32       LFSR_7, LFSR_8
        vmovdqa32       LFSR_8, LFSR_9
        vmovdqa32       LFSR_9, LFSR_10
        vmovdqa32       LFSR_10, LFSR_11

        ;; LFSR[11] >> 8 & 0x00ffffff
        vpsrld          %%TEMP4, LFSR_11, 8
        vpxord          %%TEMP,  %%TEMP, %%TEMP4

        vmovdqa32       %%TEMP1, LFSR_11

        ;; LFSR_11 = DIValpha(LFSR[11] & 0xff)
        ALPHA_OP_16     %%TEMP1, %%TEMP2, %%TEMP3, %%TEMP4, \
                        const_divalpha_map_00_0f, \
                        const_divalpha_map_80_8f, \
                        %%KR1, %%KR2, %%KR3, %%KR4, %%KR5

        vmovdqa32       %%TEMP4, LFSR_12
        vmovdqa32       LFSR_12, LFSR_13
        vmovdqa32       LFSR_13, LFSR_14
        vmovdqa32       LFSR_13, LFSR_14
        vmovdqa32       LFSR_14, LFSR_15

        vpxord          LFSR_15, %%TEMP, %%TEMP1
        vmovdqa32       LFSR_11, %%TEMP4
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Initializes global registers with constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro INIT_CONSTANTS 0
       vmovdqa64        FIXED_MAP_TAB_0, [rel const_transf_map + 64 * 0]
       vmovdqa64        FIXED_MAP_TAB_1, [rel const_transf_map + 64 * 1]
       vmovdqa64        FIXED_MAP_TAB_2, [rel const_transf_map + 64 * 2]
       vmovdqa64        FIXED_MAP_TAB_3, [rel const_transf_map + 64 * 3]
       vmovdqa64        FIXED_ROTATE_MASK, [rel const_fixed_rotate_mask]
       vmovdqa64        FIXED_PATTERN_SHUF, [rel const_fixup]
       vmovdqa64        FIXED_M_MASK, [rel const_fixup_mask]
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Stores to/loads from memory from/to vector registers key stream state registers
;; - uses global register mapping for load/store operation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro LFSR_FSM_STATE 2
%define %%PTR   %1 ;; [in] pointer to state structure
%define %%TYPE  %2 ;; [in] "STORE" or "LOAD" selector

%ifidn %%TYPE, STORE

%assign i 0
%rep    16
        vmovdqu64      [%%PTR + _snow3g_args_LFSR_ %+ i], LFSR_ %+ i
%assign i (i + 1)
%endrep

        vmovdqu64       [%%PTR + _snow3g_args_FSM_1], FSM1
        vmovdqu64       [%%PTR + _snow3g_args_FSM_2], FSM2
        vmovdqu64       [%%PTR + _snow3g_args_FSM_3], FSM3
%else   ;; LOAD

%assign i 0
%rep    16
        vmovdqu64       LFSR_ %+ i, [%%PTR + _snow3g_args_LFSR_ %+ i]
%assign i (i + 1)
%endrep

        vmovdqu64       FSM1, [%%PTR + _snow3g_args_FSM_1]
        vmovdqu64       FSM2, [%%PTR + _snow3g_args_FSM_2]
        vmovdqu64       FSM3, [%%PTR + _snow3g_args_FSM_3]
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Takes 64 byte of key stream, loads plain text,
;; xor's key stream against the plain text, stores the result.
;;
;; Note: if lane is in initialization mode loads and stores
;;       don't really happen (mask) and key stream is simply discarded
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro STORE_KEYSTREAM_ZMM 9
%xdefine %%SRC_PTRS   %1 ;; [in] addr of array of pointers to 16 src buffs or "NULL"
%xdefine %%DST_PTRS   %2 ;; [in] addr of array of pointers to 16 dst buffs
%xdefine %%STATE_PTR  %3 ;; [in] pointer to state structure
%xdefine %%OFFSET     %4 ;; [in] current offset to src/dst
%xdefine %%LANEID     %5 ;; [in] imm value used as lane index
%xdefine %%TGP0       %6 ;; [clobbered] temporary 64bit register
%xdefine %%TZMM1      %7 ;; [clobbered] temporary zmm register
%xdefine %%TZMM2      %8 ;; [clobbered] temporary zmm register
%xdefine %%KREG       %9 ;; [clobbered] k register

        kmovq           %%KREG, [%%STATE_PTR + _snow3g_args_INITIALIZED + (%%LANEID * 8)]
        vpshufb         %%TZMM1, LFSR_ %+ %%LANEID, [rel const_byte_shuff_mask]
%ifnidn %%SRC_PTRS, NULL
        mov             %%TGP0, [%%SRC_PTRS + (%%LANEID * 8)]
        vmovdqu8        %%TZMM2{%%KREG}{z}, [%%TGP0 + %%OFFSET]
        vpxord          %%TZMM1, %%TZMM1, %%TZMM2
%endif
        mov             %%TGP0, [%%DST_PTRS + (%%LANEID * 8)]
        vmovdqu8        [%%TGP0 + %%OFFSET]{%%KREG}, %%TZMM1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Takes 64 byte of key stream, loads plain text,
;; xor's key stream against the plain text, stores the result.
;; - here it takes into account partial cases
;;
;; @todo writing aligned to DW, loading & reading more than needed
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro STORE_KEYSTREAM_ZMM_LAST 10
%xdefine %%SRC_PTRS     %1 ;; [in] array of pointers to 16 src buffs or "NULL"
%xdefine %%DST_PTRS     %2 ;; [in] array of pointers to 16 dst buffs
%xdefine %%STATE_PTR    %3 ;; [in] pointer to state structure
%xdefine %%OFFSET       %4 ;; [in] current offset to src/dst
%xdefine %%LANEID       %5 ;; [in] imm value used as lane index
%xdefine %%TGP0         %6 ;; [clobbered] temporary 64bit register
%xdefine %%TZMM1        %7 ;; [clobbered] temporary zmm register
%xdefine %%TZMM2        %8 ;; [clobbered] temporary zmm register
%xdefine %%KMASK_DB     %9 ;; [in] k register with byte mask limiting input/output
%xdefine %%KTMP         %10;; [clobbered] temporary k register

        kmovq           %%KTMP, [%%STATE_PTR + _snow3g_args_INITIALIZED + (%%LANEID * 8)]
        kandq           %%KTMP, %%KMASK_DB, %%KTMP
        vpshufb         %%TZMM1, LFSR_ %+ %%LANEID, [rel const_byte_shuff_mask]
%ifnidn %%SRC_PTRS, NULL
        mov             %%TGP0, [%%SRC_PTRS + (%%LANEID * 8)]
        vmovdqu8        %%TZMM2{%%KTMP}{z}, [%%TGP0 + %%OFFSET]
        vpxord          %%TZMM1, %%TZMM1, %%TZMM2
%endif
        mov             %%TGP0, [%%DST_PTRS + (%%LANEID * 8)]
        vmovdqu8        [%%TGP0 + %%OFFSET]{%%KTMP}, %%TZMM1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Keystreams are kept in stack in following way:
;; rsp + _keystream + 64*0  KEYSTREAM 0  : [buff15_0, buff_14_0, ..., buff0_0]
;; ...
;; rsp + _keystream + 64*14 KEYSTREAM 14 : [buff15_14, buff_14_14, ..., buff0_14]
;; rsp + _keystream + 64*15 KEYSTREAM 15 : [buff15_15, buff_14_15, ..., buff0_15]
;; @note Uses LFSR registers for the transpostion
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro TRANSPOSE_FROM_STACK 4
%xdefine %%TEMP1            %1 ;; [clobbered] temporary zmm register
%xdefine %%TEMP2            %2 ;; [clobbered] temporary zmm register
%xdefine %%TEMP3            %3 ;; [clobbered] temporary zmm register
%xdefine %%TEMP4            %4 ;; [clobbered] temporary zmm register

        TRANSPOSE16_U32_LOAD_FIRST8 \
                        LFSR_0, LFSR_1, LFSR_2, LFSR_3, LFSR_4, LFSR_5, LFSR_6, LFSR_7, \
                        LFSR_8, LFSR_9, LFSR_10, LFSR_11, LFSR_12, LFSR_13, LFSR_14, LFSR_15, \
                        {rsp + _keystream + (64 * 0)}, {rsp + _keystream + (64 * 1)}, \
                        {rsp + _keystream + (64 * 2)}, {rsp + _keystream + (64 * 3)}, \
                        {rsp + _keystream + (64 * 4)}, {rsp + _keystream + (64 * 5)}, \
                        {rsp + _keystream + (64 * 6)}, {rsp + _keystream + (64 * 7)}, 0

        TRANSPOSE16_U32_LOAD_LAST8 \
                        LFSR_0, LFSR_1, LFSR_2, LFSR_3, LFSR_4, LFSR_5, LFSR_6, LFSR_7, \
                        LFSR_8, LFSR_9, LFSR_10, LFSR_11, LFSR_12, LFSR_13, LFSR_14, LFSR_15, \
                        {rsp + _keystream + (64 * 8)},  {rsp + _keystream + (64 * 9)}, \
                        {rsp + _keystream + (64 * 10)}, {rsp + _keystream + (64 * 11)}, \
                        {rsp + _keystream + (64 * 12)}, {rsp + _keystream + (64 * 13)}, \
                        {rsp + _keystream + (64 * 14)}, {rsp + _keystream + (64 * 15)}, 0

        TRANSPOSE16_U32_PRELOADED \
                        LFSR_0, LFSR_1, LFSR_2, LFSR_3, LFSR_4, LFSR_5, LFSR_6, LFSR_7, \
                        LFSR_8, LFSR_9, LFSR_10, LFSR_11, LFSR_12, LFSR_13, LFSR_14, LFSR_15, \
                        %%TEMP1, %%TEMP2, %%TEMP3, %%TEMP4
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SNOW3G cipher code generating required number key stream double words
;; - it is multi-buffer implementation (16 buffers)
;; - buffers can be in initialization or working mode
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW_3G_KEYSTREAM 14
%xdefine %%STATE_PTR    %1  ;; [in] FSM_LFSR state struct ptr
%xdefine %%COUNT        %2  ;; [in/clobbered] nr of dwords to be processed
%xdefine %%SRC_PTRS     %3  ;; [in] addr of array of pointers to 16 src buff
%xdefine %%DST_PTRS     %4  ;; [in] addr of array of pointers to 16 dst buff
%xdefine %%OFFSET       %5  ;; [clobbered] temporary 64bit register
%xdefine %%TGP0         %6  ;; [clobbered] temporary 64bit register
%xdefine %%TGP1         %7  ;; [clobbered] temporary 64bit register
%xdefine %%TGP2         %8  ;; [clobbered] temporary 64bit register
%xdefine %%KR1          %9  ;; [clobbered] temporary k-register
%xdefine %%KR2          %10 ;; [clobbered] temporary k-register
%xdefine %%KR3          %11 ;; [clobbered] temporary k-register
%xdefine %%KR4          %12 ;; [clobbered] temporary k-register
%xdefine %%KR5          %13 ;; [clobbered] temporary k-register
%xdefine %%KR6          %14 ;; [clobbered] temporary k-register

        xor             %%OFFSET,  %%OFFSET

        ;; Number of DWORD's MOD 16
        mov             %%TGP1, %%COUNT
        and             DWORD(%%TGP1), 15

        kmovw           %%KR6, [%%STATE_PTR + _snow3g_INIT_MASK]

        INIT_CONSTANTS
        LFSR_FSM_STATE  %%STATE_PTR, LOAD


        ;; used as offset for storing key stream on the stack frame
        xor             %%TGP0, %%TGP0

%%next_keyword:
        FSM_CLOCK       FSM1, FSM2, FSM3, LFSR_5, LFSR_15, KEYSTREAM, \
                        TEMP_27, TEMP_28, TEMP_29, TEMP_30, TEMP_31, \
                        FIXED_MAP_TAB_0, FIXED_MAP_TAB_1, \
                        FIXED_MAP_TAB_2, FIXED_MAP_TAB_3, \
                        %%KR1, %%KR2, %%KR3, %%KR4

        ;; this xor happens only in keystream gen mode (working mode)
        knotw           %%KR6, %%KR6    ;; bits are set if lane is initialized
        vpxord          KEYSTREAM{%%KR6}, LFSR_0, KEYSTREAM

        ;; put key stream on the satck frame
        vmovdqa32       [rsp + %%TGP0], KEYSTREAM
        add             DWORD(%%TGP0), 64

        LFSR_CLOCK      TEMP_27, TEMP_28, TEMP_29, TEMP_30, TEMP_31, \
                        %%KR1, %%KR2, %%KR3, %%KR4, %%KR5

        ;; this xor happens only in init gen mode (initialization mode)
        knotw           %%KR6, %%KR6    ;; bits are zero if lane is initialized
        vpxord          LFSR_15{%%KR6}, LFSR_15, KEYSTREAM

        cmp             DWORD(%%TGP0), (16 * 64)
        jnz             %%no_write_yet

        ;; clear the offset to start again
        xor             %%TGP0, %%TGP0

        ;; temporarily free LFSR and FSM registers for the transpose
        LFSR_FSM_STATE  %%STATE_PTR, STORE

        TRANSPOSE_FROM_STACK \
                        TEMP_27, TEMP_28, TEMP_29, TEMP_30

%assign i 0
%rep 16
        STORE_KEYSTREAM_ZMM \
                        %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, %%OFFSET, i, \
                        %%TGP2, TEMP_27, TEMP_28, %%KR2
%assign i (i + 1)
%endrep

        ;; restore LFSR and FSM state
        LFSR_FSM_STATE  %%STATE_PTR, LOAD

        add             %%OFFSET, 64

%%no_write_yet:
        dec             %%COUNT
        jnz             %%next_keyword

        ;; save LSFR & FSM registers
        LFSR_FSM_STATE  %%STATE_PTR, STORE

        or              %%TGP0, %%TGP0
        jz              %%fin

        TRANSPOSE_FROM_STACK \
                        TEMP_27, TEMP_28, TEMP_29, TEMP_30

        lea             %%TGP2, [rel dw_len_to_db_mask]
        kmovq           %%KR1, [%%TGP2 + %%TGP1 * 8]
%assign i 0
%rep 16
        STORE_KEYSTREAM_ZMM_LAST \
                        %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, %%OFFSET, i, \
                        %%TGP2, TEMP_27, TEMP_29, %%KR1, %%KR2
%assign i (i + 1)
%endrep
        lea             %%OFFSET, [%%OFFSET + %%TGP1 * 4]

%%fin:

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate 5 double words of key stream for SNOW3G authentication
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro   SNOW3G_AUTH_INIT_5 15
%xdefine %%STATE        %1  ;; [in] pointer to state
%xdefine %%KEY          %2  ;; [in] address of array of pointers to 16 keys
%xdefine %%IV           %3  ;; [in] address of array of pointers to 16 ivs
%xdefine %%DST_PTR      %4  ;; [in] address of array of pointers to (16buffers * 5DW) out keystreams
%xdefine %%OFFSET       %5  ;; [clobbered] 64b register
%xdefine %%COUNT        %6  ;; [clobbered] 64b register
%xdefine %%TGP0         %7  ;; [clobbered] 64b register
%xdefine %%TGP1         %8  ;; [clobbered] 64b register
%xdefine %%TGP2         %9  ;; [clobbered] 64b register
%xdefine %%KR1          %10 ;; [clobbered] temporary k-register
%xdefine %%KR2          %11 ;; [clobbered] temporary k-register
%xdefine %%KR3          %12 ;; [clobbered] temporary k-register
%xdefine %%KR4          %13 ;; [clobbered] temporary k-register
%xdefine %%KR5          %14 ;; [clobbered] temporary k-register
%xdefine %%KR6          %15 ;; [clobbered] temporary k-register

        INIT_CONSTANTS

        vmovdqa64       TEMP_31, [rel all_fs]

        mov             DWORD(%%COUNT), 1
        kmovd           %%KR1, DWORD(%%COUNT)
        ;; @todo this can be changed to read & transpose
%assign i 0
%rep 16
        mov             %%TGP1, [%%KEY + i*8]
        mov             %%TGP2, [%%IV + i*8]
        LFSR_INIT_2     TEMP_31, %%KR1, %%TGP1, %%TGP2, TEMP_30
        kshiftlw        %%KR1, %%KR1, 1
%assign i (i + 1)
%endrep

        vpxord          FSM1, FSM1, FSM1
        vpxord          FSM2, FSM2, FSM2
        vpxord          FSM3, FSM3, FSM3

        LFSR_FSM_STATE  %%STATE, STORE

        ;; 33 iterations of FSM and LFSR clock are needed
        ;; set flag to not initialized

        ;; 1st phase of initialziation mode - 32 double words
        mov             dword [%%STATE + _snow3g_INIT_MASK], 0xffffffff

        xor             DWORD(%%COUNT), DWORD(%%COUNT)
%assign i 0
%rep 16
        mov             [%%STATE + _snow3g_args_INITIALIZED + i*8], %%COUNT
%assign i (i + 1)
%endrep

        mov             DWORD(%%COUNT), 32
        SNOW_3G_KEYSTREAM \
                        %%STATE, %%COUNT, NULL, %%DST_PTR, %%OFFSET, \
                        %%TGP0, %%TGP1, %%TGP2, \
                        %%KR1, %%KR2, %%KR3, %%KR4, %%KR5, %%KR6

        ;; 2nd phase of initialization mode - 1 double word
        mov             dword [%%STATE + _snow3g_INIT_MASK], 0
        mov             DWORD(%%COUNT), 1
        SNOW_3G_KEYSTREAM \
                        %%STATE, %%COUNT, NULL, %%DST_PTR, %%OFFSET, \
                        %%TGP0, %%TGP1, %%TGP2, \
                        %%KR1, %%KR2, %%KR3, %%KR4, %%KR5, %%KR6

        ;; working mode - 5 double words
        mov             %%COUNT, 0xffffffff_ffffffff
%assign i 0
%rep 16
        mov             [%%STATE + _snow3g_args_INITIALIZED + i*8], %%COUNT
%assign i (i + 1)
%endrep
        mov             DWORD(%%COUNT), 5

        SNOW_3G_KEYSTREAM \
                        %%STATE, %%COUNT, NULL, %%DST_PTR, %%OFFSET, \
                        %%TGP0, %%TGP1, %%TGP2, \
                        %%KR1, %%KR2, %%KR3, %%KR4, %%KR5, %%KR6
%endmacro
