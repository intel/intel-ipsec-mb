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
#   (FIPS 203): SampleNTT rejection sampling, Compress/Decompress with
#   packing for d = 1, 4, 5, 10 and 11, and SamplePolyCBD for eta = 2 and 3.
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

###############################################################################
# ml_kem_poly_tomsg_avx2
#
# Compress_1 followed by ByteEncode_1 (FIPS 203, Algorithm 15, step 7).
#
# C Prototype:
#   void ml_kem_poly_tomsg_avx2(
#       uint8_t *out,               // (rdi) 32 output bytes
#       const uint16_t *in          // (rsi) 256 input coefficients
#   );
#
# Description:
#   Compress_1(x) is 1 for x in [833, 2496]. The range check is a single
#   signed compare of x - 833 + 2^15 against 1664 - 2^15; the word masks are
#   packed to bytes and collected with vpmovmskb. Constant time.
#
# Inputs:
#   in - coefficients in [0, q)
###############################################################################
.align 32
.globl  ml_kem_poly_tomsg_avx2
.type   ml_kem_poly_tomsg_avx2,\@function,2
ml_kem_poly_tomsg_avx2:
.cfi_startproc
    endbranch
    vpbroadcastw ml_kem_msg_off(%rip), %ymm4
    vpbroadcastw ml_kem_msg_lim(%rip), %ymm5
    mov     \$8, %ecx

.align 32
.Ltomsg_loop:
    vpaddw  (%rsi), %ymm4, %ymm0
    vpaddw  32(%rsi), %ymm4, %ymm1
    vpcmpgtw %ymm0, %ymm5, %ymm0
    vpcmpgtw %ymm1, %ymm5, %ymm1
    vpacksswb %ymm1, %ymm0, %ymm0
    vpermq  \$0xd8, %ymm0, %ymm0
    vpmovmskb %ymm0, %eax
    mov     %eax, (%rdi)

    add     \$64, %rsi
    add     \$4, %rdi
    dec     %ecx
    jnz     .Ltomsg_loop

    xor     %eax, %eax
    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_poly_tomsg_avx2, .-ml_kem_poly_tomsg_avx2

###############################################################################
# ml_kem_poly_frommsg_add_avx2
#
# ByteDecode_1 and Decompress_1 of the message, added to a polynomial
# (FIPS 203, Algorithm 14, steps 20-21).
#
# C Prototype:
#   void ml_kem_poly_frommsg_add_avx2(
#       uint16_t *out,              // (rdi) 256 input/output coefficients
#       const uint8_t *in           // (rsi) 32 message bytes
#   );
#
# Description:
#   Each 16 message bits are broadcast, isolated with a per-word bit mask and
#   turned into a word mask selecting (q + 1) / 2, then added and reduced
#   once. Constant time (see scalar_decode_decompress_add).
#
# Inputs:
#   out - coefficients in [0, q)
#
# Output:
#   out - coefficients in [0, q)
###############################################################################
.align 32
.globl  ml_kem_poly_frommsg_add_avx2
.type   ml_kem_poly_frommsg_add_avx2,\@function,2
ml_kem_poly_frommsg_add_avx2:
.cfi_startproc
    endbranch
    vmovdqa ml_kem_msg_bits(%rip), %ymm3
    vpbroadcastw ml_kem_half_q(%rip), %ymm4
    vpbroadcastw ml_kem_q(%rip), %ymm5
    mov     \$16, %ecx

.align 32
.Lfrommsg_loop:
    vpbroadcastw (%rsi), %ymm0
    vpand   %ymm3, %ymm0, %ymm0
    vpcmpeqw %ymm3, %ymm0, %ymm0
    vpand   %ymm4, %ymm0, %ymm0
    vpaddw  (%rdi), %ymm0, %ymm0
    vpsubw  %ymm5, %ymm0, %ymm1
    vpminuw %ymm1, %ymm0, %ymm0
    vmovdqu %ymm0, (%rdi)

    add     \$2, %rsi
    add     \$32, %rdi
    dec     %ecx
    jnz     .Lfrommsg_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_poly_frommsg_add_avx2, .-ml_kem_poly_frommsg_add_avx2
___

###############################################################################
# cbd_fixup
#
# Description:
#   Maps 16 words holding c + bias, with c in [-bias, bias], to c mod q in
#   [0, q). x - bias wraps to a large unsigned value when c < 0, so the
#   unsigned minimum of (x - bias) and (x - bias + q) selects the right one.
#
# Parameters:
#   x    - YMM with input/output coefficients
#   bias - YMM loaded with bias (words)
#   qb   - YMM loaded with q - bias (words)
#   tmp  - scratch YMM
###############################################################################
sub cbd_fixup {
    my ($x, $bias, $qb, $tmp) = @_;

    $code .= <<___;
    vpaddw  $qb, $x, $tmp
    vpsubw  $bias, $x, $x
    vpminuw $tmp, $x, $x
___
}

$code .= <<___;

###############################################################################
# ml_kem_poly_cbd2_avx2
#
# SamplePolyCBD for eta = 2 (FIPS 203, Algorithm 8).
#
# C Prototype:
#   void ml_kem_poly_cbd2_avx2(
#       uint16_t *out,              // (rdi) 256 output coefficients
#       const uint8_t *in           // (rsi) 128 PRF output bytes
#   );
#
# Description:
#   Each byte yields two coefficients: (b0 + b1) - (b2 + b3) from the low
#   nibble and (b4 + b5) - (b6 + b7) from the high nibble. Bit pairs are
#   summed with byte-wise shifts and masks, then each nibble is formed as
#   a + 3 - b in [1, 5], so no borrow crosses a nibble, and the bias of 3
#   is removed by cbd_fixup. 32 input bytes give
#   64 coefficients per iteration.
#
# Output:
#   out - coefficients in [0, q)
###############################################################################
.align 32
.globl  ml_kem_poly_cbd2_avx2
.type   ml_kem_poly_cbd2_avx2,\@function,2
ml_kem_poly_cbd2_avx2:
.cfi_startproc
    endbranch
    mov     \$4, %ecx

.align 32
.Lcbd2_loop:
    vpbroadcastd ml_kem_cbd_mask_55(%rip), %ymm5
    vpbroadcastd ml_kem_cbd_mask_33(%rip), %ymm4
    vpbroadcastd ml_kem_cbd_mask_0f(%rip), %ymm3
    vmovdqu (%rsi), %ymm0
    vpsrlw  \$1, %ymm0, %ymm1
    vpand   %ymm5, %ymm0, %ymm0
    vpand   %ymm5, %ymm1, %ymm1
    vpaddb  %ymm1, %ymm0, %ymm0
    vpsrlw  \$2, %ymm0, %ymm1
    vpand   %ymm4, %ymm0, %ymm0
    vpand   %ymm4, %ymm1, %ymm1
    vpaddb  %ymm4, %ymm0, %ymm0
    vpsubb  %ymm1, %ymm0, %ymm0
    vpsrlw  \$4, %ymm0, %ymm1
    vpand   %ymm3, %ymm0, %ymm0
    vpand   %ymm3, %ymm1, %ymm1
    vpunpcklbw %ymm1, %ymm0, %ymm2
    vpunpckhbw %ymm1, %ymm0, %ymm0
    vpbroadcastw ml_kem_cbd_bias(%rip), %ymm4
    vpbroadcastw ml_kem_cbd_qbias(%rip), %ymm5
    vpmovzxbw %xmm2, %ymm1
___
    &cbd_fixup("%ymm1", "%ymm4", "%ymm5", "%ymm3");
$code .= <<___;
    vmovdqu %ymm1, (%rdi)
    vpmovzxbw %xmm0, %ymm1
___
    &cbd_fixup("%ymm1", "%ymm4", "%ymm5", "%ymm3");
$code .= <<___;
    vmovdqu %ymm1, 32(%rdi)
    vextracti128 \$1, %ymm2, %xmm2
    vpmovzxbw %xmm2, %ymm1
___
    &cbd_fixup("%ymm1", "%ymm4", "%ymm5", "%ymm3");
$code .= <<___;
    vmovdqu %ymm1, 64(%rdi)
    vextracti128 \$1, %ymm0, %xmm0
    vpmovzxbw %xmm0, %ymm1
___
    &cbd_fixup("%ymm1", "%ymm4", "%ymm5", "%ymm3");
$code .= <<___;
    vmovdqu %ymm1, 96(%rdi)

    add     \$32, %rsi
    add     \$128, %rdi
    dec     %ecx
    jnz     .Lcbd2_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_poly_cbd2_avx2, .-ml_kem_poly_cbd2_avx2

###############################################################################
# ml_kem_poly_cbd3_avx2
#
# SamplePolyCBD for eta = 3 (FIPS 203, Algorithm 8).
#
# C Prototype:
#   void ml_kem_poly_cbd3_avx2(
#       uint16_t *out,              // (rdi) 256 output coefficients
#       const uint8_t *in           // (rsi) 192 PRF output bytes
#   );
#
# Description:
#   Every 3 bytes (24 bits) yield four coefficients, each from 6 bits:
#   (b0 + b1 + b2) - (b3 + b4 + b5). Each 3-byte group is gathered into a
#   dword, the 3-bit fields are summed in place and a + 3 - b is formed per
#   coefficient (in [0, 6], no borrow across fields). 24 input bytes give 32
#   coefficients per iteration.
#
# Output:
#   out - coefficients in [0, q)
###############################################################################
.align 32
.globl  ml_kem_poly_cbd3_avx2
.type   ml_kem_poly_cbd3_avx2,\@function,2
ml_kem_poly_cbd3_avx2:
.cfi_startproc
    endbranch
    mov     \$8, %ecx

.align 32
.Lcbd3_loop:
    vmovdqu (%rsi), %xmm0
    vinserti128 \$1, 8(%rsi), %ymm0, %ymm0
    vpshufb ml_kem_cbd3_shuf(%rip), %ymm0, %ymm0
    vpbroadcastd ml_kem_cbd3_mask_249(%rip), %ymm5
    vpsrld  \$1, %ymm0, %ymm1
    vpsrld  \$2, %ymm0, %ymm2
    vpand   %ymm5, %ymm0, %ymm0
    vpand   %ymm5, %ymm1, %ymm1
    vpand   %ymm5, %ymm2, %ymm2
    vpaddd  %ymm1, %ymm0, %ymm0
    vpaddd  %ymm2, %ymm0, %ymm0
    vpsrld  \$3, %ymm0, %ymm1
    vpbroadcastd ml_kem_cbd3_bias_6db(%rip), %ymm5
    vpaddd  %ymm5, %ymm0, %ymm0
    vpsubd  %ymm1, %ymm0, %ymm0
    vpslld  \$10, %ymm0, %ymm1
    vpsrld  \$12, %ymm0, %ymm2
    vpsrld  \$2, %ymm0, %ymm3
    vpbroadcastd ml_kem_cbd3_mask_07(%rip), %ymm5
    vpbroadcastd ml_kem_cbd3_mask_70000(%rip), %ymm4
    vpand   %ymm5, %ymm0, %ymm0
    vpand   %ymm4, %ymm1, %ymm1
    vpand   %ymm5, %ymm2, %ymm2
    vpand   %ymm4, %ymm3, %ymm3
    vpaddw  %ymm1, %ymm0, %ymm0
    vpaddw  %ymm3, %ymm2, %ymm1
    vpunpckldq %ymm1, %ymm0, %ymm2
    vpunpckhdq %ymm1, %ymm0, %ymm3
    vperm2i128 \$0x20, %ymm3, %ymm2, %ymm0
    vperm2i128 \$0x31, %ymm3, %ymm2, %ymm1
    vpbroadcastw ml_kem_cbd_bias(%rip), %ymm4
    vpbroadcastw ml_kem_cbd_qbias(%rip), %ymm5
___
    &cbd_fixup("%ymm0", "%ymm4", "%ymm5", "%ymm2");
    &cbd_fixup("%ymm1", "%ymm4", "%ymm5", "%ymm3");
$code .= <<___;
    vmovdqu %ymm0, (%rdi)
    vmovdqu %ymm1, 32(%rdi)

    add     \$24, %rsi
    add     \$64, %rdi
    dec     %ecx
    jnz     .Lcbd3_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_kem_poly_cbd3_avx2, .-ml_kem_poly_cbd3_avx2
___

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

# Compress_1 range check offset and limit, x - 833 + 2^15 and 1664 - 2^15
# (see ml_kem_poly_tomsg_avx2)
.align 2
ml_kem_msg_off:
    .value 31935
.align 2
ml_kem_msg_lim:
    .value -31104

# Decompress_1 value (q + 1) / 2
.align 2
ml_kem_half_q:
    .value 1665

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

# Decompress_1 bit selectors, word i holds 2^i
.align 32
ml_kem_msg_bits:
    .value @{[join(",", map { sprintf("0x%x", 1 << $_) } (0 .. 15))]}

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

# CBD eta = 2: bit-pair, nibble-pair and nibble masks
.align 4
ml_kem_cbd_mask_55:
    .long 0x55555555
ml_kem_cbd_mask_33:
    .long 0x33333333
ml_kem_cbd_mask_0f:
    .long 0x0f0f0f0f

# CBD eta = 3: 3-bit field masks and the a + 3 - b bias of every field
ml_kem_cbd3_mask_249:
    .long 0x00249249
ml_kem_cbd3_bias_6db:
    .long 0x006db6db
ml_kem_cbd3_mask_07:
    .long 0x00000007
ml_kem_cbd3_mask_70000:
    .long 0x00070000

# CBD fixup bias (both eta) and q - bias (words)
.align 2
ml_kem_cbd_bias:
    .value 3
ml_kem_cbd_qbias:
    .value 3326

# CBD eta = 3 gather: lane 0 takes bytes 0-11, lane 1 bytes 12-23 (its load
# starts at byte 8), one 3-byte group per dword
.align 32
ml_kem_cbd3_shuf:
    .byte 0,1,2,0x80,3,4,5,0x80,6,7,8,0x80,9,10,11,0x80
    .byte 4,5,6,0x80,7,8,9,0x80,10,11,12,0x80,13,14,15,0x80
___

$code .= <<___;

.section    .note.GNU-stack,"",\@progbits
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
