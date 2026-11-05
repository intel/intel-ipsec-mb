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
#   (FIPS 203): SampleNTT rejection sampling.
#
# Notes:
#   - Rejection sampling branches on public data (derived from rho) only
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

$code .= <<___;

.section    .note.GNU-stack,"",\@progbits
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
