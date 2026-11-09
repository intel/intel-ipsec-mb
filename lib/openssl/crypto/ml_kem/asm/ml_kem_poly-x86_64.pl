#! /usr/bin/env perl
#
# Copyright (c) 2026, Intel Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

###############################################################################
# ML-KEM AVX2 Polynomial Sampling and Packing Routines
#
# Description:
#   AVX2 implementations of the ML-KEM polynomial operations outside the NTT
#   (FIPS 203): SampleNTT rejection sampling, and Compress/Decompress with
#   packing for d = 4, 5, 10 and 11.
#
# Notes:
#   - Rejection sampling branches on public data (derived from rho) only;
#     the other routines have a fixed trip count
#   - Only YMM0-YMM5 are used (volatile on SysV and Win64); they are cleared
#     before returning
#   - Must be kept functionally synchronized with the base implementations
#     in ml_kem.c
###############################################################################

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64 = 0;
$win64 = 1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$avx2 = 0;

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
$dir = $1;
($xlate = "${dir}x86_64-xlate.pl" and -f $xlate)
    or ($xlate = "${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate)
    or die "can't locate x86_64-xlate.pl";

# Assembler used for the nasm flavour. The build forwards its choice via
# $ENV{ASM} so the probe inspects the same nasm that assembles the output.
my $nasm = $ENV{ASM} || "nasm";

# Check for AVX2 support in assembler
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1` =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
  $avx2 = ($1 >= 2.22);
}

if (!$avx2
  && $win64
  && ($flavour =~ /nasm/ || ($ENV{ASM} // "") =~ /nasm/)
  && `"$nasm" -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/)
{
  $avx2 = ($1 >= 2.10);
}

if (!$avx2 && `$ENV{CC} -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
    $avx2 = ($2>=3.3); # minimal tested version for AVX2
}

# The optimised kernels are mandatory: fail the build (rather than emit
# trapping stubs) when the assembler cannot encode them.
$avx2 > 0
    or die "AVX2 support is required in the assembler to build the ML-KEM polynomial kernels.\nMinimum assembler versions: GNU as 2.22, clang 3.3, nasm 2.10.\n";

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $code = '';

$code .= <<___;
.text

###############################################################################
# ml_kem_rej_uniform_block_avx2
#
# SampleNTT rejection sampling of one SHAKE128 block (FIPS 203, Algorithm 7,
# steps 5-17).
#
# C Prototype:
#   uint32_t ml_kem_rej_uniform_block_avx2(
#       uint16_t *out,              // (rdi) Output coefficients
#       const uint32_t capacity,    // (esi) Free output slots, in [0, 256]
#       const uint8_t *in           // (rdx) SHAKE128 block
#   );
#
# Description:
#   Each 3-byte group yields two 12-bit candidates, accepted if below q.
#   While at least 16 output slots are free, 16 candidates (24 bytes) are
#   checked at once and the accepted ones left-packed with a vpshufb lookup
#   table indexed by the 8-bit acceptance mask of each 128-bit lane. Up to 8
#   unaccepted words beyond the accepted ones are written as scratch, inside
#   the free slots. The rest of the block is processed one candidate at a
#   time, keeping stream order. Branches depend only on public data derived
#   from rho.
#
# Inputs:
#   in - exactly 168 bytes read
#
# Output:
#   out - accepted coefficients in [0, q), at most capacity written
#   eax - number of coefficients written
###############################################################################
.align 32
.globl  ml_kem_rej_uniform_block_avx2
.type   ml_kem_rej_uniform_block_avx2,\@function,3
ml_kem_rej_uniform_block_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d
    xor     %eax, %eax
    vpbroadcastw ml_kem_q(%rip), %ymm3
    vpbroadcastw ml_kem_mask_12(%rip), %ymm4
    vmovdqa ml_kem_rej_shuf(%rip), %ymm5
    lea     ml_kem_rej_pack(%rip), %r11

.align 32
.Lrej_block_loop:
    lea     16(%rax), %r8d
    cmp     %esi, %r8d
    ja      .Lrej_block_scalar
    vmovdqu (%rdx,%r10), %xmm0
    vinserti128 \$1, 8(%rdx,%r10), %ymm0, %ymm0
    vpshufb %ymm5, %ymm0, %ymm0
    vpsrlw  \$4, %ymm0, %ymm1
    vpblendw \$0xaa, %ymm1, %ymm0, %ymm0
    vpand   %ymm4, %ymm0, %ymm0
    vpcmpgtw %ymm0, %ymm3, %ymm1
    vpacksswb %ymm1, %ymm1, %ymm1
    vpmovmskb %ymm1, %ecx
    movzbl  %cl, %r8d
    shr     \$16, %ecx
    movzbl  %cl, %r9d
    shl     \$4, %r8d
    shl     \$4, %r9d
    vpshufb (%r11,%r8), %xmm0, %xmm1
    vmovdqu %xmm1, (%rdi,%rax,2)
    popcnt  %r8d, %r8d
    vextracti128 \$1, %ymm0, %xmm0
    vpshufb (%r11,%r9), %xmm0, %xmm0
    popcnt  %r9d, %r9d
    add     %r8d, %eax
    vmovdqu %xmm0, (%rdi,%rax,2)
    add     %r9d, %eax

    add     \$8*3, %r10
    cmp     \$168, %r10
    jb      .Lrej_block_loop
    jmp     .Lrej_block_done

.align 32
.Lrej_block_scalar:
    cmp     %esi, %eax
    jae     .Lrej_block_done
    movzwl  (%rdx,%r10), %ecx
    and     \$0xfff, %ecx
    cmp     \$3329, %ecx
    jae     .Lrej_block_odd
    mov     %cx, (%rdi,%rax,2)
    inc     %eax
    cmp     %esi, %eax
    jae     .Lrej_block_done
.Lrej_block_odd:
    movzwl  1(%rdx,%r10), %ecx
    shr     \$4, %ecx
    add     \$3, %r10
    cmp     \$3329, %ecx
    jae     .Lrej_block_next
    mov     %cx, (%rdi,%rax,2)
    inc     %eax
.Lrej_block_next:
    cmp     \$168, %r10
    jb      .Lrej_block_scalar

.Lrej_block_done:
    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_rej_uniform_block_avx2, .-ml_kem_rej_uniform_block_avx2
___

###############################################################################
# decompress_tail
#
# Description:
#   Finishes 16 coefficients from the gathered dwords of two groups: aligns
#   and masks each field, packs to words in order, applies Decompress_d and
#   stores them to (%rdi).
#
# Parameters:
#   d     - compressed bit width
#   lo    - YMM with the gathered first group; clobbered
#   hi    - YMM with the gathered second group; clobbered
#   shift - YMM with the per-dword field shifts
#   mask  - YMM with the dword field mask
#   q     - YMM loaded with q (words)
###############################################################################
sub decompress_tail {
    my ($d, $lo, $hi, $shift, $mask, $q) = @_;

    $code .= <<___;
    vpsrlvd $shift, $lo, $lo
    vpsrlvd $shift, $hi, $hi
    vpand   $mask, $lo, $lo
    vpand   $mask, $hi, $hi
    vpackusdw $hi, $lo, $lo
    vpermq  \$0xd8, $lo, $lo
    vpsllw  \$@{[15 - $d]}, $lo, $lo
    vpmulhrsw $q, $lo, $lo
    vmovdqu $lo, (%rdi)
___
}

###############################################################################
# store_bytes
#
# Description:
#   Stores exactly the low d bytes of an XMM register to off(%rdi).
#
# Parameters:
#   x   - XMM holding the packed bytes
#   off - byte offset from %rdi
#   d   - number of bytes to store (4, 5, 10 or 11)
###############################################################################
sub store_bytes {
    my ($x, $off, $d) = @_;

    if ($d == 4) {
        $code .= "    vmovd   $x, $off(%rdi)\n";
    } elsif ($d == 5) {
        $code .= "    vmovd   $x, $off(%rdi)\n";
        $code .= "    vpextrb \$4, $x, " . ($off + 4) . "(%rdi)\n";
    } else {
        $code .= "    vmovq   $x, $off(%rdi)\n";
        $code .= "    vpextrw \$4, $x, " . ($off + 8) . "(%rdi)\n";
        $code .= "    vpextrb \$10, $x, " . ($off + 10) . "(%rdi)\n" if ($d == 11);
    }
}

###############################################################################
# decompress_safe_iters
#
# Description:
#   Returns the number of leading ByteDecode_d iterations whose two 16-byte
#   group loads stay inside the 32 * d byte input.
###############################################################################
sub decompress_safe_iters {
    my ($d) = @_;

    return int((31 * $d - 16) / (2 * $d)) + 1;
}

foreach my $d (4, 5, 10, 11) {
    my $s32 = 32 - 2 * $d;
    my $bytes = 32 * $d;
    my $safe = &decompress_safe_iters($d);

    $code .= <<___;

###############################################################################
# ml_kem_poly_compress${d}_avx2
#
# Compress_d followed by ByteEncode_d for d = $d (FIPS 203, Section 4.2.1).
#
# C Prototype:
#   void ml_kem_poly_compress${d}_avx2(
#       uint8_t *out,               // (rdi) $bytes output bytes
#       const uint16_t *in          // (rsi) 256 input coefficients
#   );
#
# Description:
#   Compress_d is computed exactly with 16-bit multiplies (round(x * 2^d / q)
#   via a Barrett style estimate and rounding multiply). The 16 d-bit values
#   of each iteration are then merged: pairs into dwords with vpmaddwd, dword
#   pairs into qwords with a variable shift and qword pairs into each 128-bit
#   lane, which then holds $d packed bytes.
#
# Inputs:
#   in - coefficients in [0, q)
###############################################################################
.align 32
.globl  ml_kem_poly_compress${d}_avx2
.type   ml_kem_poly_compress${d}_avx2,\@function,2
ml_kem_poly_compress${d}_avx2:
.cfi_startproc
    endbranch
    mov     \$16, %ecx

.align 32
.Lcompress${d}_loop:
    vmovdqu (%rsi), %ymm0
___
    if ($d < 10) {
        $code .= <<___;
    vpmulhw ml_kem_cmp_v(%rip), %ymm0, %ymm0
    vpmulhrsw ml_kem_cmp_sh$d(%rip), %ymm0, %ymm0
___
    } else {
        $code .= <<___;
    vpmullw ml_kem_cmp_v8(%rip), %ymm0, %ymm1
    vpaddw  ml_kem_cmp_off$d(%rip), %ymm0, %ymm2
    vpsllw  \$3, %ymm0, %ymm0
    vpmulhw ml_kem_cmp_v(%rip), %ymm0, %ymm0
    vpsubw  %ymm2, %ymm1, %ymm2
    vpandn  %ymm2, %ymm1, %ymm1
    vpsrlw  \$15, %ymm1, %ymm1
    vpsubw  %ymm1, %ymm0, %ymm0
    vpmulhrsw ml_kem_cmp_sh$d(%rip), %ymm0, %ymm0
___
    }
    $code .= <<___;
    vpand   ml_kem_mask_d$d(%rip), %ymm0, %ymm0
    vpmaddwd ml_kem_pack_madd$d(%rip), %ymm0, %ymm0
    vpsllvd ml_kem_pack_sllv$d(%rip), %ymm0, %ymm0
    vpsrlq  \$$s32, %ymm0, %ymm0
    vpsrldq \$8, %ymm0, %ymm1
    vpsllq  \$@{[4 * $d]}, %ymm1, %ymm1
    vpsrlvq ml_kem_pack_srlv$d(%rip), %ymm0, %ymm2
    vpblendd \$0xcc, %ymm2, %ymm0, %ymm0
    vpor    %ymm1, %ymm0, %ymm0
    vextracti128 \$1, %ymm0, %xmm1
___
    &store_bytes("%xmm0", 0, $d);
    &store_bytes("%xmm1", $d, $d);
    $code .= <<___;

    add     \$32, %rsi
    add     \$@{[2 * $d]}, %rdi
    dec     %ecx
    jnz     .Lcompress${d}_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_poly_compress${d}_avx2, .-ml_kem_poly_compress${d}_avx2

###############################################################################
# ml_kem_poly_decompress${d}_avx2
#
# ByteDecode_d followed by Decompress_d for d = $d (FIPS 203, Section 4.2.1).
#
# C Prototype:
#   void ml_kem_poly_decompress${d}_avx2(
#       uint16_t *out,              // (rdi) 256 output coefficients
#       const uint8_t *in           // (rsi) $bytes input bytes
#   );
#
# Description:
#   Each group of 8 coefficients ($d bytes) is broadcast to both lanes and
#   each field is gathered into a dword with vpshufb, aligned with vpsrlvd
#   and masked. Decompress_d is round(x * q / 2^d) = vpmulhrsw(x << (15 - d),
#   q). Groups near the end of the input are loaded from the last 16 input
#   bytes with adjusted gathers, so no byte past the input is read.
#
# Output:
#   out - coefficients in [0, q)
###############################################################################
.align 32
.globl  ml_kem_poly_decompress${d}_avx2
.type   ml_kem_poly_decompress${d}_avx2,\@function,2
ml_kem_poly_decompress${d}_avx2:
.cfi_startproc
    endbranch
    vmovdqa ml_kem_unpack_srlv$d(%rip), %ymm3
    vpbroadcastd ml_kem_unpack_mask$d(%rip), %ymm4
    vpbroadcastw ml_kem_q(%rip), %ymm5
    mov     \$$safe, %ecx

.align 32
.Ldecompress${d}_loop:
    vbroadcasti128 (%rsi), %ymm0
    vbroadcasti128 $d(%rsi), %ymm1
    vpshufb ml_kem_unpack_shuf$d(%rip), %ymm0, %ymm0
    vpshufb ml_kem_unpack_shuf$d(%rip), %ymm1, %ymm1
___
    &decompress_tail($d, "%ymm0", "%ymm1", "%ymm3", "%ymm4", "%ymm5");
    $code .= <<___;

    add     \$@{[2 * $d]}, %rsi
    add     \$32, %rdi
    dec     %ecx
    jnz     .Ldecompress${d}_loop
___
    for my $it ($safe .. 15) {
        for my $h (0, 1) {
            my $g = 2 * $it + $h;
            my $off = $g * $d - ($bytes - 16);
            my $src = ($off > 0) ? ($bytes - 16) - $it * 2 * $d : $h * $d;
            my $tbl = ($off > 0) ? "ml_kem_unpack_shuf${d}_g$g" : "ml_kem_unpack_shuf$d";
            $code .= <<___;
    vbroadcasti128 $src(%rsi), %ymm$h
    vpshufb $tbl(%rip), %ymm$h, %ymm$h
___
        }
        &decompress_tail($d, "%ymm0", "%ymm1", "%ymm3", "%ymm4", "%ymm5");
        $code .= <<___;
    add     \$@{[2 * $d]}, %rsi
    add     \$32, %rdi
___
    }
    $code .= <<___;

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_poly_decompress${d}_avx2, .-ml_kem_poly_decompress${d}_avx2
___
}

$code .= <<___;

.section    .rodata

# Modulus q = 3329 (FIPS 203, Section 2.4)
.align 2
ml_kem_q:
    .value 3329

# 12-bit candidate mask
.align 2
ml_kem_mask_12:
    .value 0xfff

# SampleNTT gather: lane 0 takes candidates 0-7 from bytes 0-11, lane 1
# takes candidates 8-15 from bytes 12-23 (its load starts at byte 8). Each
# 3-byte group b0,b1,b2 gives the words (b1:b0) and (b2:b1); the odd words
# are shifted right by 4 and both masked to 12 bits.
.align 32
ml_kem_rej_shuf:
    .byte 0,1,1,2,3,4,4,5,6,7,7,8,9,10,10,11
    .byte 4,5,5,6,7,8,8,9,10,11,11,12,13,14,14,15

# Left-pack vpshufb masks: entry m moves the words selected by the bits of
# m to the front of the lane, in order.
.align 16
ml_kem_rej_pack:
___

for (my $m = 0; $m < 256; $m++) {
    my @b = map { (2 * $_, 2 * $_ + 1) } grep { ($m >> $_) & 1 } 0 .. 7;
    push @b, ("0x80") x (16 - @b);
    $code .= "    .byte " . join(",", @b) . "\n";
}

###############################################################################
# vec16
#
# Description:
#   Returns a 32-byte rodata entry holding 16 copies of a word constant.
###############################################################################
sub vec16 {
    my ($label, $val) = @_;

    return "$label:\n    .value " . join(",", ($val) x 16) . "\n";
}

###############################################################################
# decompress_shuf
#
# Description:
#   Returns a vpshufb mask gathering 8 d-bit fields (4 per lane) from a
#   16-byte load starting off bytes before the group: each dword gets the
#   bytes holding its field, lowest first.
###############################################################################
sub decompress_shuf {
    my ($d, $off) = @_;
    my @b;

    for my $j (0 .. 7) {
        my $lo = int($j * $d / 8);
        my $hi = int(($j * $d + $d - 1) / 8);
        for my $k (0 .. 3) {
            push @b, ($lo + $k <= $hi) ? $lo + $k + $off : "0x80";
        }
    }
    return "    .byte " . join(",", @b[0 .. 15]) . "\n    .byte " . join(",", @b[16 .. 31]) . "\n";
}

$code .= <<___;

# ByteDecode_d field masks, 2^d - 1
___

foreach my $d (4, 5, 10, 11) {
    $code .= ".align 4\nml_kem_unpack_mask$d:\n    .long " . ((1 << $d) - 1) . "\n";
}

$code .= <<___;

# Compress_d constants, used as memory operands inside the loops and
# therefore stored at full vector width: Barrett estimate of x / q (v and
# 8 * v for d >= 10), correction offsets for d = 10 and 11, rounding scales
# and d-bit masks
.align 32
___

$code .= &vec16("ml_kem_cmp_v", 20159);
$code .= &vec16("ml_kem_cmp_v8", 30200);
$code .= &vec16("ml_kem_cmp_off10", 15);
$code .= &vec16("ml_kem_cmp_off11", 36);
foreach my $d (4, 5, 10, 11) {
    $code .= &vec16("ml_kem_cmp_sh$d", ($d < 10) ? 1 << ($d + 5) : 1 << ($d + 2));
    $code .= &vec16("ml_kem_mask_d$d", (1 << $d) - 1);
}

$code .= <<___;

# ByteEncode_d merge tables (vpmaddwd weights, dword and qword shifts),
# ByteDecode_d field shifts and gathers, including the adjusted gathers of
# the groups loaded from the last 16 input bytes
.align 32
___

foreach my $d (4, 5, 10, 11) {
    my $bytes = 32 * $d;
    my $safe = &decompress_safe_iters($d);

    $code .= "ml_kem_pack_madd$d:\n    .value " . join(",", (1, 1 << $d) x 8) . "\n";
    $code .= "ml_kem_pack_sllv$d:\n    .long " . join(",", (32 - 2 * $d, 0) x 4) . "\n";
    $code .= "ml_kem_pack_srlv$d:\n    .quad " . join(",", (64, 64 - 4 * $d) x 2) . "\n";
    $code .= "ml_kem_unpack_srlv$d:\n    .long " . join(",", map { ($_ * $d) % 8 } (0 .. 7)) . "\n";
    $code .= "ml_kem_unpack_shuf$d:\n" . &decompress_shuf($d, 0);
    for my $g (2 * $safe .. 31) {
        my $off = $g * $d - ($bytes - 16);
        $code .= "ml_kem_unpack_shuf${d}_g$g:\n" . &decompress_shuf($d, $off) if ($off > 0);
    }
}

$code .= <<___;

.section    .note.GNU-stack,"",\@progbits
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
