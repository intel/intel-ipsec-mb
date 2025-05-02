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
use POSIX qw(floor);

# Check if file names are provided as command-line arguments
if (@ARGV == 0) {
    die "The script takes one or more stat files as input and produces a report.\n" .
        "The report includes average stat data from from each input file across all algorithms.\n" .
        "Usage: $0 file1.stat file2.stat ...\n";
}

sub process_stat_file {
    my ($filename) = @_;

    # Open the file for reading
    open my $fh, '<', $filename or die "Cannot open file '$filename': $!\n";

    my $count = 0;
    my @avg;

    # Read the file line by line
    while (my $line = <$fh>) {
        chomp $line;  # Remove the newline character
        my @fields = split ' ', $line;  # Split the line into words/fields

        # Check if the first element is a number
        if (@fields && $fields[0] =~ /^\d+$/) {
            if ($count == 0) {
                @avg = @fields;
            } else {
                for my $index (6 .. 17) {
                    $avg[$index] += $fields[$index];
                }
            }
            $count++;
        }
    }

    if ($count != 0) {
        my @fmt = ("%14.3f|", "%14.3f|", "%14.3f|", "%14.3f|", "%14.3f|", "%14.1f|",
                   "%14.1f|", "%14.1f|", "%14.1f|", "%14.1f|", "%14.1f|", "%14.1f|");
        printf("%20s|", $filename);

        for my $index (6 .. 17) {
            if ($index == 11 || $index == 17) {
                # Recalculate STDEV % for average values, otherwise it is off
                my $value = ($avg[$index - 1] / $avg[$index - 5]) * 100;
                printf($fmt[$index - 6], $value);
            } else {
                my $value = $avg[$index] / $count;
                printf($fmt[$index - 6], $value);
            }
        }
    }
    printf("\n");

    # Close the file
    close $fh;
}

# print report header line
printf("%20s|%14s|%14s|%14s|%14s|%14s|%14s|%14s|%14s|%14s|%14s|%14s|%14s|\n", "FILE NAME / FILE AVG",
       "SLOPE AVG", "SLOPE MED", "SLOPE MIN", "SLOPE MAX", "SLOPE STDEV", "SLOPE STEDEV\%",
       "INT AVG", "INT MED", "INT MIN", "INT MAX", "INT STDEV", "INT STEDEV\%");

# Iterate over each file provided as a command-line argument
foreach my $filename (@ARGV) {
    process_stat_file($filename);
}
