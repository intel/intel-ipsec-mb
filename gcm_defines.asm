;;
;; Copyright (c) 2012-2019, Intel Corporation
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

;
; Authors:
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford

section .data
default rel

align 16
POLY:   dq     0x0000000000000001, 0xC200000000000000

align 64
POLY2:
        dq     0x00000001C2000000, 0xC200000000000000
        dq     0x00000001C2000000, 0xC200000000000000
        dq     0x00000001C2000000, 0xC200000000000000
        dq     0x00000001C2000000, 0xC200000000000000

align 16
TWOONE: dq     0x0000000000000001, 0x0000000100000000

;;; @note Order of these constants should not change.
;;; More specifically, ALL_F should follow SHIFT_MASK, and ZERO should follow ALL_F
align 64
SHUF_MASK:
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607

align 16
SHIFT_MASK:
        dq     0x0706050403020100, 0x0f0e0d0c0b0a0908

ALL_F:
        dq     0xffffffffffffffff, 0xffffffffffffffff

ZERO:
        dq     0x0000000000000000, 0x0000000000000000

align 16
ONE:
        dq     0x0000000000000001, 0x0000000000000000

align 16
TWO:
        dq     0x0000000000000002, 0x0000000000000000

align 16
ONEf:
        dq     0x0000000000000000, 0x0100000000000000

align 16
TWOf:
        dq     0x0000000000000000, 0x0200000000000000

align 64
ddq_add_5678:
        dq	0x0000000000000005, 0x0000000000000000
        dq	0x0000000000000006, 0x0000000000000000
        dq	0x0000000000000007, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000

align 64
ddq_addbe_5678:
        dq	0x0000000000000000, 0x0500000000000000
        dq	0x0000000000000000, 0x0600000000000000
        dq	0x0000000000000000, 0x0700000000000000
        dq	0x0000000000000000, 0x0800000000000000

align 64
ddq_add_1234:
        dq	0x0000000000000001, 0x0000000000000000
        dq	0x0000000000000002, 0x0000000000000000
        dq	0x0000000000000003, 0x0000000000000000
        dq	0x0000000000000004, 0x0000000000000000

align 64
ddq_addbe_1234:
        dq	0x0000000000000000, 0x0100000000000000
        dq	0x0000000000000000, 0x0200000000000000
        dq	0x0000000000000000, 0x0300000000000000
        dq	0x0000000000000000, 0x0400000000000000

align 64
ddq_sub_3210:
        dq	0x0000000000000003, 0x0000000000000000
        dq	0x0000000000000002, 0x0000000000000000
        dq	0x0000000000000001, 0x0000000000000000
        dq	0x0000000000000000, 0x0000000000000000

align 64
ddq_add_4444:
        dq	0x0000000000000004, 0x0000000000000000
        dq	0x0000000000000004, 0x0000000000000000
        dq	0x0000000000000004, 0x0000000000000000
        dq	0x0000000000000004, 0x0000000000000000

align 64
ddq_addbe_4444:
        dq	0x0000000000000000, 0x0400000000000000
        dq	0x0000000000000000, 0x0400000000000000
        dq	0x0000000000000000, 0x0400000000000000
        dq	0x0000000000000000, 0x0400000000000000

align 64
ddq_add_8888:
        dq	0x0000000000000008, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000

align 64
ddq_addbe_8888:
        dq	0x0000000000000000, 0x0800000000000000
        dq	0x0000000000000000, 0x0800000000000000
        dq	0x0000000000000000, 0x0800000000000000
        dq	0x0000000000000000, 0x0800000000000000

align 64
ddq_add_16161616:
        dq	0x0000000000000010, 0x0000000000000000
        dq	0x0000000000000010, 0x0000000000000000
        dq	0x0000000000000010, 0x0000000000000000
        dq	0x0000000000000010, 0x0000000000000000

align 64
ddq_addbe_16161616:
        dq	0x0000000000000000, 0x1000000000000000
        dq	0x0000000000000000, 0x1000000000000000
        dq	0x0000000000000000, 0x1000000000000000
        dq	0x0000000000000000, 0x1000000000000000

align 64
index_to_lane4:
        dq	0x0000000000000000, 0x0000000000000001
        dq	0x0000000000000002, 0x0000000000000003
        dq	0x0000000000000000, 0x0000000000000000
        dq	0x0000000000000000, 0x0000000000000000

align 64
byte_len_to_mask_table:
        dw      0x0000, 0x0001, 0x0003, 0x0007,
        dw      0x000f, 0x001f, 0x003f, 0x007f,
        dw      0x00ff, 0x01ff, 0x03ff, 0x07ff,
        dw      0x0fff, 0x1fff, 0x3fff, 0x7fff,
        dw      0xffff

align 64
byte64_len_to_mask_table:
        dq      0x0000000000000000, 0x0000000000000001
        dq      0x0000000000000003, 0x0000000000000007
        dq      0x000000000000000f, 0x000000000000001f
        dq      0x000000000000003f, 0x000000000000007f
        dq      0x00000000000000ff, 0x00000000000001ff
        dq      0x00000000000003ff, 0x00000000000007ff
        dq      0x0000000000000fff, 0x0000000000001fff
        dq      0x0000000000003fff, 0x0000000000007fff
        dq      0x000000000000ffff, 0x000000000001ffff
        dq      0x000000000003ffff, 0x000000000007ffff
        dq      0x00000000000fffff, 0x00000000001fffff
        dq      0x00000000003fffff, 0x00000000007fffff
        dq      0x0000000000ffffff, 0x0000000001ffffff
        dq      0x0000000003ffffff, 0x0000000007ffffff
        dq      0x000000000fffffff, 0x000000001fffffff
        dq      0x000000003fffffff, 0x000000007fffffff
        dq      0x00000000ffffffff, 0x00000001ffffffff
        dq      0x00000003ffffffff, 0x00000007ffffffff
        dq      0x0000000fffffffff, 0x0000001fffffffff
        dq      0x0000003fffffffff, 0x0000007fffffffff
        dq      0x000000ffffffffff, 0x000001ffffffffff
        dq      0x000003ffffffffff, 0x000007ffffffffff
        dq      0x00000fffffffffff, 0x00001fffffffffff
        dq      0x00003fffffffffff, 0x00007fffffffffff
        dq      0x0000ffffffffffff, 0x0001ffffffffffff
        dq      0x0003ffffffffffff, 0x0007ffffffffffff
        dq      0x000fffffffffffff, 0x001fffffffffffff
        dq      0x003fffffffffffff, 0x007fffffffffffff
        dq      0x00ffffffffffffff, 0x01ffffffffffffff
        dq      0x03ffffffffffffff, 0x07ffffffffffffff
        dq      0x0fffffffffffffff, 0x1fffffffffffffff
        dq      0x3fffffffffffffff, 0x7fffffffffffffff
        dq      0xffffffffffffffff

align 64
mask_out_top_block:
        dq      0xffffffffffffffff, 0xffffffffffffffff
        dq      0xffffffffffffffff, 0xffffffffffffffff
        dq      0xffffffffffffffff, 0xffffffffffffffff
        dq      0x0000000000000000, 0x0000000000000000

;;; @note these 2 need to be next one another
;;; - they are used to map lane index onto coresponding bit mask and
;;;   NOT version of the bitmask
index_to_lane4_mask:
        dw      0x0001, 0x0002, 0x0004, 0x0008
index_to_lane4_not_mask:
        dw      0x000e, 0x000d, 0x000b, 0x0007

section .text

;;define the fields of gcm_key_data struct
;; struct gcm_key_data {
;;         uint8_t expanded_keys[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
;;         uint8_t padding[GCM_ENC_KEY_LEN];
;;         uint8_t shifted_hkey_9_128[GCM_ENC_KEY_LEN * (128 - 8)];
;;         uint8_t shifted_hkey_8[GCM_ENC_KEY_LEN]; // HashKey^8 <<1 mod poly
;;         uint8_t shifted_hkey_7[GCM_ENC_KEY_LEN]; // HashKey^7 <<1 mod poly
;;         uint8_t shifted_hkey_6[GCM_ENC_KEY_LEN]; // HashKey^6 <<1 mod poly
;;         uint8_t shifted_hkey_5[GCM_ENC_KEY_LEN]; // HashKey^5 <<1 mod poly
;;         uint8_t shifted_hkey_4[GCM_ENC_KEY_LEN]; // HashKey^4 <<1 mod poly
;;         uint8_t shifted_hkey_3[GCM_ENC_KEY_LEN]; // HashKey^3 <<1 mod poly
;;         uint8_t shifted_hkey_2[GCM_ENC_KEY_LEN]; // HashKey^2 <<1 mod poly
;;         uint8_t shifted_hkey_1[GCM_ENC_KEY_LEN]; // HashKey   <<1 mod poly
;;         uint8_t shifted_hkey_1_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of HashKey <<1 mod poly (Karatsuba)
;;         uint8_t shifted_hkey_2_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^2 <<1 mod poly (Karatsuba)
;;         uint8_t shifted_hkey_3_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^3 <<1 mod poly (Karatsuba)
;;         uint8_t shifted_hkey_4_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^4 <<1 mod poly (Karatsuba)
;;         uint8_t shifted_hkey_5_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^5 <<1 mod poly (Karatsuba)
;;         uint8_t shifted_hkey_6_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^6 <<1 mod poly (Karatsuba)
;;         uint8_t shifted_hkey_7_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^7 <<1 mod poly (Karatsuba)
;;         uint8_t shifted_hkey_8_k[GCM_ENC_KEY_LEN]; // XOR of High and Low 64 bits of  HashKey^8 <<1 mod poly (Karatsuba)
;; }

%define Padding         (16*15)

%ifdef GCM_BIG_DATA
;;
;; Key structure holds up to 128 ghash keys
;;
%define HashKey_128     (16*16)   ; HashKey^128 <<1 mod poly
%define HashKey_127     (16*17)   ; HashKey^127 <<1 mod poly
%define HashKey_126     (16*18)   ; HashKey^126 <<1 mod poly
%define HashKey_125     (16*19)   ; HashKey^125 <<1 mod poly
%define HashKey_124     (16*20)   ; HashKey^124 <<1 mod poly
%define HashKey_123     (16*21)   ; HashKey^123 <<1 mod poly
%define HashKey_122     (16*22)   ; HashKey^122 <<1 mod poly
%define HashKey_121     (16*23)   ; HashKey^121 <<1 mod poly
%define HashKey_120     (16*24)   ; HashKey^120 <<1 mod poly
%define HashKey_119     (16*25)   ; HashKey^119 <<1 mod poly
%define HashKey_118     (16*26)   ; HashKey^118 <<1 mod poly
%define HashKey_117     (16*27)   ; HashKey^117 <<1 mod poly
%define HashKey_116     (16*28)   ; HashKey^116 <<1 mod poly
%define HashKey_115     (16*29)   ; HashKey^115 <<1 mod poly
%define HashKey_114     (16*30)   ; HashKey^114 <<1 mod poly
%define HashKey_113     (16*31)   ; HashKey^113 <<1 mod poly
%define HashKey_112     (16*32)   ; HashKey^112 <<1 mod poly
%define HashKey_111     (16*33)   ; HashKey^111 <<1 mod poly
%define HashKey_110     (16*34)   ; HashKey^110 <<1 mod poly
%define HashKey_109     (16*35)   ; HashKey^109 <<1 mod poly
%define HashKey_108     (16*36)   ; HashKey^108 <<1 mod poly
%define HashKey_107     (16*37)   ; HashKey^107 <<1 mod poly
%define HashKey_106     (16*38)   ; HashKey^106 <<1 mod poly
%define HashKey_105     (16*39)   ; HashKey^105 <<1 mod poly
%define HashKey_104     (16*40)   ; HashKey^104 <<1 mod poly
%define HashKey_103     (16*41)   ; HashKey^103 <<1 mod poly
%define HashKey_102     (16*42)   ; HashKey^102 <<1 mod poly
%define HashKey_101     (16*43)   ; HashKey^101 <<1 mod poly
%define HashKey_100     (16*44)   ; HashKey^100 <<1 mod poly
%define HashKey_99      (16*45)   ; HashKey^99 <<1 mod poly
%define HashKey_98      (16*46)   ; HashKey^98 <<1 mod poly
%define HashKey_97      (16*47)   ; HashKey^97 <<1 mod poly
%define HashKey_96      (16*48)   ; HashKey^96 <<1 mod poly
%define HashKey_95      (16*49)   ; HashKey^95 <<1 mod poly
%define HashKey_94      (16*50)   ; HashKey^94 <<1 mod poly
%define HashKey_93      (16*51)   ; HashKey^93 <<1 mod poly
%define HashKey_92      (16*52)   ; HashKey^92 <<1 mod poly
%define HashKey_91      (16*53)   ; HashKey^91 <<1 mod poly
%define HashKey_90      (16*54)   ; HashKey^90 <<1 mod poly
%define HashKey_89      (16*55)   ; HashKey^89 <<1 mod poly
%define HashKey_88      (16*56)   ; HashKey^88 <<1 mod poly
%define HashKey_87      (16*57)   ; HashKey^87 <<1 mod poly
%define HashKey_86      (16*58)   ; HashKey^86 <<1 mod poly
%define HashKey_85      (16*59)   ; HashKey^85 <<1 mod poly
%define HashKey_84      (16*60)   ; HashKey^84 <<1 mod poly
%define HashKey_83      (16*61)   ; HashKey^83 <<1 mod poly
%define HashKey_82      (16*62)   ; HashKey^82 <<1 mod poly
%define HashKey_81      (16*63)   ; HashKey^81 <<1 mod poly
%define HashKey_80      (16*64)   ; HashKey^80 <<1 mod poly
%define HashKey_79      (16*65)   ; HashKey^79 <<1 mod poly
%define HashKey_78      (16*66)   ; HashKey^78 <<1 mod poly
%define HashKey_77      (16*67)   ; HashKey^77 <<1 mod poly
%define HashKey_76      (16*68)   ; HashKey^76 <<1 mod poly
%define HashKey_75      (16*69)   ; HashKey^75 <<1 mod poly
%define HashKey_74      (16*70)   ; HashKey^74 <<1 mod poly
%define HashKey_73      (16*71)   ; HashKey^73 <<1 mod poly
%define HashKey_72      (16*72)   ; HashKey^72 <<1 mod poly
%define HashKey_71      (16*73)   ; HashKey^71 <<1 mod poly
%define HashKey_70      (16*74)   ; HashKey^70 <<1 mod poly
%define HashKey_69      (16*75)   ; HashKey^69 <<1 mod poly
%define HashKey_68      (16*76)   ; HashKey^68 <<1 mod poly
%define HashKey_67      (16*77)   ; HashKey^67 <<1 mod poly
%define HashKey_66      (16*78)   ; HashKey^66 <<1 mod poly
%define HashKey_65      (16*79)   ; HashKey^65 <<1 mod poly
%define HashKey_64      (16*80)   ; HashKey^64 <<1 mod poly
%define HashKey_63      (16*81)   ; HashKey^63 <<1 mod poly
%define HashKey_62      (16*82)   ; HashKey^62 <<1 mod poly
%define HashKey_61      (16*83)   ; HashKey^61 <<1 mod poly
%define HashKey_60      (16*84)   ; HashKey^60 <<1 mod poly
%define HashKey_59      (16*85)   ; HashKey^59 <<1 mod poly
%define HashKey_58      (16*86)   ; HashKey^58 <<1 mod poly
%define HashKey_57      (16*87)   ; HashKey^57 <<1 mod poly
%define HashKey_56      (16*88)   ; HashKey^56 <<1 mod poly
%define HashKey_55      (16*89)   ; HashKey^55 <<1 mod poly
%define HashKey_54      (16*90)   ; HashKey^54 <<1 mod poly
%define HashKey_53      (16*91)   ; HashKey^53 <<1 mod poly
%define HashKey_52      (16*92)   ; HashKey^52 <<1 mod poly
%define HashKey_51      (16*93)   ; HashKey^51 <<1 mod poly
%define HashKey_50      (16*94)   ; HashKey^50 <<1 mod poly
%define HashKey_49      (16*95)   ; HashKey^49 <<1 mod poly
%define HashKey_48      (16*96)   ; HashKey^48 <<1 mod poly
%define HashKey_47      (16*97)   ; HashKey^47 <<1 mod poly
%define HashKey_46      (16*98)   ; HashKey^46 <<1 mod poly
%define HashKey_45      (16*99)   ; HashKey^45 <<1 mod poly
%define HashKey_44      (16*100)  ; HashKey^44 <<1 mod poly
%define HashKey_43      (16*101)  ; HashKey^43 <<1 mod poly
%define HashKey_42      (16*102)  ; HashKey^42 <<1 mod poly
%define HashKey_41      (16*103)  ; HashKey^41 <<1 mod poly
%define HashKey_40      (16*104)  ; HashKey^40 <<1 mod poly
%define HashKey_39      (16*105)  ; HashKey^39 <<1 mod poly
%define HashKey_38      (16*106)  ; HashKey^38 <<1 mod poly
%define HashKey_37      (16*107)  ; HashKey^37 <<1 mod poly
%define HashKey_36      (16*108)  ; HashKey^36 <<1 mod poly
%define HashKey_35      (16*109)  ; HashKey^35 <<1 mod poly
%define HashKey_34      (16*110)  ; HashKey^34 <<1 mod poly
%define HashKey_33      (16*111)  ; HashKey^33 <<1 mod poly
%define HashKey_32      (16*112)  ; HashKey^32 <<1 mod poly
%define HashKey_31      (16*113)  ; HashKey^31 <<1 mod poly
%define HashKey_30      (16*114)  ; HashKey^30 <<1 mod poly
%define HashKey_29      (16*115)  ; HashKey^29 <<1 mod poly
%define HashKey_28      (16*116)  ; HashKey^28 <<1 mod poly
%define HashKey_27      (16*117)  ; HashKey^27 <<1 mod poly
%define HashKey_26      (16*118)  ; HashKey^26 <<1 mod poly
%define HashKey_25      (16*119)  ; HashKey^25 <<1 mod poly
%define HashKey_24      (16*120)  ; HashKey^24 <<1 mod poly
%define HashKey_23      (16*121)  ; HashKey^23 <<1 mod poly
%define HashKey_22      (16*122)  ; HashKey^22 <<1 mod poly
%define HashKey_21      (16*123)  ; HashKey^21 <<1 mod poly
%define HashKey_20      (16*124)  ; HashKey^20 <<1 mod poly
%define HashKey_19      (16*125)  ; HashKey^19 <<1 mod poly
%define HashKey_18      (16*126)  ; HashKey^18 <<1 mod poly
%define HashKey_17      (16*127)  ; HashKey^17 <<1 mod poly
%define HashKey_16      (16*128)  ; HashKey^16 <<1 mod poly
%define HashKey_15      (16*129)  ; HashKey^15 <<1 mod poly
%define HashKey_14      (16*130)  ; HashKey^14 <<1 mod poly
%define HashKey_13      (16*131)  ; HashKey^13 <<1 mod poly
%define HashKey_12      (16*132)  ; HashKey^12 <<1 mod poly
%define HashKey_11      (16*133)  ; HashKey^11 <<1 mod poly
%define HashKey_10      (16*134)  ; HashKey^10 <<1 mod poly
%define HashKey_9       (16*135)  ; HashKey^9 <<1 mod poly
%define HashKey_8       (16*136)  ; HashKey^8 <<1 mod poly
%define HashKey_7       (16*137)  ; HashKey^7 <<1 mod poly
%define HashKey_6       (16*138)  ; HashKey^6 <<1 mod poly
%define HashKey_5       (16*139)  ; HashKey^5 <<1 mod poly
%define HashKey_4       (16*140)  ; HashKey^4 <<1 mod poly
%define HashKey_3       (16*141)  ; HashKey^3 <<1 mod poly
%define HashKey_2       (16*142)  ; HashKey^2 <<1 mod poly
%define HashKey_1       (16*143)  ; HashKey <<1 mod poly
%define HashKey         (16*143)  ; HashKey <<1 mod poly
%define HashKey_k       (16*144)  ; XOR of High 64 bits and Low 64 bits of HashKey <<1 mod poly here (for Karatsuba purposes)
%define HashKey_1_k     (16*144   ; XOR of High 64 bits and Low 64 bits of HashKey <<1 mod poly here (for Karatsuba purposes)
%define HashKey_2_k     (16*145)  ; XOR of High 64 bits and Low 64 bits of HashKey^2 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_3_k     (16*146)  ; XOR of High 64 bits and Low 64 bits of HashKey^3 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_4_k     (16*147)  ; XOR of High 64 bits and Low 64 bits of HashKey^4 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_5_k     (16*148)  ; XOR of High 64 bits and Low 64 bits of HashKey^5 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_6_k     (16*149)  ; XOR of High 64 bits and Low 64 bits of HashKey^6 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_7_k     (16*150)  ; XOR of High 64 bits and Low 64 bits of HashKey^7 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_8_k     (16*151)  ; XOR of High 64 bits and Low 64 bits of HashKey^8 <<1 mod poly here (for Karatsuba purposes)
%else
;;
;; Key structure holds up to 48 ghash keys
;;
%define HashKey_48      (16*16)   ; HashKey^48 <<1 mod poly
%define HashKey_47      (16*17)   ; HashKey^47 <<1 mod poly
%define HashKey_46      (16*18)   ; HashKey^46 <<1 mod poly
%define HashKey_45      (16*19)   ; HashKey^45 <<1 mod poly
%define HashKey_44      (16*20)   ; HashKey^44 <<1 mod poly
%define HashKey_43      (16*21)   ; HashKey^43 <<1 mod poly
%define HashKey_42      (16*22)   ; HashKey^42 <<1 mod poly
%define HashKey_41      (16*23)   ; HashKey^41 <<1 mod poly
%define HashKey_40      (16*24)   ; HashKey^40 <<1 mod poly
%define HashKey_39      (16*25)   ; HashKey^39 <<1 mod poly
%define HashKey_38      (16*26)   ; HashKey^38 <<1 mod poly
%define HashKey_37      (16*27)   ; HashKey^37 <<1 mod poly
%define HashKey_36      (16*28)   ; HashKey^36 <<1 mod poly
%define HashKey_35      (16*29)   ; HashKey^35 <<1 mod poly
%define HashKey_34      (16*30)   ; HashKey^34 <<1 mod poly
%define HashKey_33      (16*31)   ; HashKey^33 <<1 mod poly
%define HashKey_32      (16*32)   ; HashKey^32 <<1 mod poly
%define HashKey_31      (16*33)   ; HashKey^31 <<1 mod poly
%define HashKey_30      (16*34)   ; HashKey^30 <<1 mod poly
%define HashKey_29      (16*35)   ; HashKey^29 <<1 mod poly
%define HashKey_28      (16*36)   ; HashKey^28 <<1 mod poly
%define HashKey_27      (16*37)   ; HashKey^27 <<1 mod poly
%define HashKey_26      (16*38)   ; HashKey^26 <<1 mod poly
%define HashKey_25      (16*39)   ; HashKey^25 <<1 mod poly
%define HashKey_24      (16*40)   ; HashKey^24 <<1 mod poly
%define HashKey_23      (16*41)   ; HashKey^23 <<1 mod poly
%define HashKey_22      (16*42)   ; HashKey^22 <<1 mod poly
%define HashKey_21      (16*43)   ; HashKey^21 <<1 mod poly
%define HashKey_20      (16*44)   ; HashKey^20 <<1 mod poly
%define HashKey_19      (16*45)   ; HashKey^19 <<1 mod poly
%define HashKey_18      (16*46)   ; HashKey^18 <<1 mod poly
%define HashKey_17      (16*47)   ; HashKey^17 <<1 mod poly
%define HashKey_16      (16*48)   ; HashKey^16 <<1 mod poly
%define HashKey_15      (16*49)   ; HashKey^15 <<1 mod poly
%define HashKey_14      (16*50)   ; HashKey^14 <<1 mod poly
%define HashKey_13      (16*51)   ; HashKey^13 <<1 mod poly
%define HashKey_12      (16*52)   ; HashKey^12 <<1 mod poly
%define HashKey_11      (16*53)   ; HashKey^11 <<1 mod poly
%define HashKey_10      (16*54)   ; HashKey^10 <<1 mod poly
%define HashKey_9       (16*55)   ; HashKey^9 <<1 mod poly
%define HashKey_8       (16*56)   ; HashKey^8 <<1 mod poly
%define HashKey_7       (16*57)   ; HashKey^7 <<1 mod poly
%define HashKey_6       (16*58)   ; HashKey^6 <<1 mod poly
%define HashKey_5       (16*59)   ; HashKey^5 <<1 mod poly
%define HashKey_4       (16*60)   ; HashKey^4 <<1 mod poly
%define HashKey_3       (16*61)   ; HashKey^3 <<1 mod poly
%define HashKey_2       (16*62)   ; HashKey^2 <<1 mod poly
%define HashKey_1       (16*63)   ; HashKey <<1 mod poly
%define HashKey         (16*63)  ; HashKey <<1 mod poly
%define HashKey_k       (16*64)  ; XOR of High 64 bits and Low 64 bits of HashKey <<1 mod poly here (for Karatsuba purposes)
%define HashKey_1_k     (16*64   ; XOR of High 64 bits and Low 64 bits of HashKey <<1 mod poly here (for Karatsuba purposes)
%define HashKey_2_k     (16*65)  ; XOR of High 64 bits and Low 64 bits of HashKey^2 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_3_k     (16*66)  ; XOR of High 64 bits and Low 64 bits of HashKey^3 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_4_k     (16*67)  ; XOR of High 64 bits and Low 64 bits of HashKey^4 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_5_k     (16*68)  ; XOR of High 64 bits and Low 64 bits of HashKey^5 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_6_k     (16*69)  ; XOR of High 64 bits and Low 64 bits of HashKey^6 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_7_k     (16*70)  ; XOR of High 64 bits and Low 64 bits of HashKey^7 <<1 mod poly here (for Karatsuba purposes)
%define HashKey_8_k     (16*71)  ; XOR of High 64 bits and Low 64 bits of HashKey^8 <<1 mod poly here (for Karatsuba purposes)

%endif  ; !GCM_BIG_DATA

;;define the fields of gcm_context_data struct
;; struct gcm_context_data {
;;         // init, update and finalize context data
;;         uint8_t  aad_hash[GCM_BLOCK_LEN];
;;         uint64_t aad_length;
;;         uint64_t in_length;
;;         uint8_t  partial_block_enc_key[GCM_BLOCK_LEN];
;;         uint8_t  orig_IV[GCM_BLOCK_LEN];
;;         uint8_t  current_counter[GCM_BLOCK_LEN];
;;         uint64_t  partial_block_length;
;; };

%define AadHash		(16*0)	  ; store current Hash of data which has been input
%define AadLen		(16*1)	  ; store length of input data which will not be encrypted or decrypted
%define InLen		((16*1)+8); store length of input data which will be encrypted or decrypted
%define PBlockEncKey	(16*2)	  ; encryption key for the partial block at the end of the previous update
%define OrigIV		(16*3)	  ; input IV
%define CurCount	(16*4)	  ; Current counter for generation of encryption key
%define PBlockLen	(16*5)	  ; length of partial block at the end of the previous update

%define reg(q) xmm %+ q
%define regy(q) ymm %+ q
%define regz(q) zmm %+ q

%ifdef WIN_ABI
	%xdefine arg1 rcx
	%xdefine arg2 rdx
	%xdefine arg3 r8
	%xdefine arg4 r9
	%xdefine arg5  qword [r14 + STACK_OFFSET + 8*5]
	%xdefine arg6  qword [r14 + STACK_OFFSET + 8*6]
	%xdefine arg7  qword [r14 + STACK_OFFSET + 8*7]
	%xdefine arg8  qword [r14 + STACK_OFFSET + 8*8]
	%xdefine arg9  qword [r14 + STACK_OFFSET + 8*9]
	%xdefine arg10 qword [r14 + STACK_OFFSET + 8*10]
%else
	%xdefine arg1 rdi
	%xdefine arg2 rsi
	%xdefine arg3 rdx
	%xdefine arg4 rcx
	%xdefine arg5 r8
	%xdefine arg6 r9
	%xdefine arg7 [r14 + STACK_OFFSET + 8*1]
	%xdefine arg8 [r14 + STACK_OFFSET + 8*2]
	%xdefine arg9 [r14 + STACK_OFFSET + 8*3]
	%xdefine arg10 [r14 + STACK_OFFSET + 8*4]
%endif

%ifdef NT_LDST
	%define NT_LD
	%define NT_ST
%endif

;;; Use Non-temporal load/stor
%ifdef NT_LD
	%define	XLDR	 movntdqa
	%define	VXLDR	 vmovntdqa
	%define	VX512LDR vmovntdqa
%else
	%define	XLDR	 movdqu
	%define	VXLDR	 vmovdqu
	%define	VX512LDR vmovdqu8
%endif

;;; Use Non-temporal load/stor
%ifdef NT_ST
	%define	XSTR	 movntdq
	%define	VXSTR	 vmovntdq
	%define	VX512STR vmovntdq
%else
	%define	XSTR	 movdqu
	%define	VXSTR	 vmovdqu
	%define	VX512STR vmovdqu8
%endif
