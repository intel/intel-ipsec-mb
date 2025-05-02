#!/usr/bin/perl

=pod
**********************************************************************
  Copyright(c) 2025, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************
=cut

use strict;
use warnings;
use List::Util qw(sum min max);
use POSIX qw(floor);

# Check if file names are provided as command-line arguments
if (@ARGV == 0) {
    die "The tool is used to convert one or more performance slope files into a stat file (STDOUT).\n" .
        "Stat files include average, median, min, max, stdev and stdev/average data for all slope and intercept input.\n" .
        "Usage: $0 file1.slope file2.slope ... > file.stat\n";
}

sub calculate_stats {
    my @values = @_;
    my $count = scalar @values;
    return unless $count > 0;

    # Calculate average
    my $sum = sum @values;
    my $average = $sum / $count;

    # Calculate standard deviation
    my $sum_sq = sum(map { $_ * $_ } @values);
    my $variance = ($sum_sq / $count) - ($average * $average);
    my $stdev = sqrt($variance);
    my $stdev_percent = ($stdev / $average) * 100;

    # Calculate median
    @values = sort { $a <=> $b } @values;
    my $median;
    if ($count % 2 == 1) {
        $median = $values[floor($count / 2)];
    } else {
        $median = ($values[$count / 2 - 1] + $values[$count / 2]) / 2;
    }

    # Calculate min and max
    my $min = min @values;
    my $max = max @values;

    return ($average, $median, $min, $max, $stdev, $stdev_percent);
}

# Initialize an array to store arrays of the split text lines
my @list;
my $id = 0;

# Iterate over each file provided as a command-line argument
foreach my $filename (@ARGV) {
    # Open the file for reading
    open my $fh, '<', $filename or die "Cannot open file '$filename': $!\n";

    # Read the file line by line
    while (my $line = <$fh>) {
        chomp $line;  # Remove the newline character
        my @fields = split ' ', $line;  # Split the line into words/fields
        # Check if the first element is a number
        if (@fields && $fields[0] =~ /^\d+$/) {
            push @list, \@fields;  # Push the reference to the array with split text
            if ($id < $fields[0]) {
                $id = $fields[0];
            }
        }
    }

    # Close the file
    close $fh;
}

print "NO\tARCH\tCIPHER\tDIR\tHASH\tKEYSZ\t" .
    "SLOPE_AVG\tSLOPE_MED\tSLOPE_MIN\tSLOPE_MAX\tSLOPE_STDEV\tSLOPE_STDEV\%\t" .
    "INT_AVG\tINT_MED\tINT_MIN\tINT_MAX\tINT_STDEV\tINT_STDEV\%\n";

for (my $i = 1; $i <= $id; $i++) {
    my (@values7, @values8);
    my @algo;

    foreach my $sublist (@list) {
        if (@$sublist[0] == $i) {
            push @values7, @$sublist[6];  # Column 7 (0-indexed)
            push @values8, @$sublist[7];  # Column 8 (0-indexed)
            @algo = @$sublist;
        }
    }

    my ($avg7, $med7, $min7, $max7, $stdev7, $stdev_percent7) = calculate_stats(@values7);
    my ($avg8, $med8, $min8, $max8, $stdev8, $stdev_percent8) = calculate_stats(@values8);

    my $fmt7 = sprintf("%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.1f", $avg7, $med7, $min7, $max7, $stdev7, $stdev_percent7);
    my $fmt8 = sprintf("%.1f\t%.1f\t%.1f\t%.1f\t%.1f\t%.1f", $avg8, $med8, $min8, $max8, $stdev8, $stdev_percent8);
    print "$algo[0]\t$algo[1]\t$algo[2]\t$algo[3]\t$algo[4]\t$algo[5]\t$fmt7\t$fmt8\n";
}
