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
    die "The script takes one or more stat files as input and produces a report.\n" .
        "The report includes percentage of algorithms that score best for given stat file and predefined criteria.\n" .
        "Usage: $0 file1.stat file2.stat ...\n";
}

# Initialize an array to store arrays of the split text lines
my @list;
my $id = 0;
my $num_rows = 0;

# Iterate over each file provided as a command-line argument and build input list of lists
foreach my $filename (@ARGV) {
    # Open the file for reading
    open my $fh, '<', $filename or die "Cannot open file '$filename': $!\n";

    my $rows = 0;

    # Read the file line by line
    while (my $line = <$fh>) {
        chomp $line;  # Remove the newline character
        my @fields = split ' ', $line;  # Split the line into words/fields

        # Check if the first element is a number
        if (@fields && $fields[0] =~ /^\d+$/) {
            push @fields, $filename;# Add file name at the end of @fields array
            push @list, \@fields;   # Push the reference to the array with split text
            if ($id < $fields[0]) {
                $id = $fields[0];
            }
            $rows++;
        }
    }
    if ($num_rows == 0) {
        $num_rows = $rows;
    } else {
        die "Input files have different number of input rows!" unless $rows == $num_rows;
    }

    # Close the file
    close $fh;
}

sub get_cycles {
    my ($size, $slope, $intercept) = @_;
    return ($size * $slope) + $intercept;
}

sub min_avg_cycles {
    my ($old, $new, $size) = @_;
    my $old_cycles = get_cycles($size, $old->[6], $old->[12]);
    my $new_cycles = get_cycles($size, $new->[6], $new->[12]);

    if ($new_cycles < $old_cycles) {
        return $new;
    } else {
        return $old;
    }
}

sub min_avg_cycles_64 {
    my ($old, $new) = @_;
    return min_avg_cycles($old, $new, 64);
}

sub min_avg_cycles_700 {
    my ($old, $new) = @_;
    return min_avg_cycles($old, $new, 700);
}

sub min_avg_cycles_1420 {
    my ($old, $new) = @_;
    return min_avg_cycles($old, $new, 1420);
}

sub min_avgstdev_cycles {
    my ($old, $new, $size) = @_;
    my $old_cycles = get_cycles($size, $old->[6] + $old->[10], $old->[12] + $old->[16]);
    my $new_cycles = get_cycles($size, $new->[6] + $new->[10], $new->[12] + $new->[16]);

    if ($new_cycles < $old_cycles) {
        return $new;
    } else {
        return $old;
    }
}

sub min_avgstdev_cycles_64 {
    my ($old, $new) = @_;
    return min_avgstdev_cycles($old, $new, 64);
}

sub min_avgstdev_cycles_700 {
    my ($old, $new) = @_;
    return min_avgstdev_cycles($old, $new, 700);
}

sub min_avgstdev_cycles_1420 {
    my ($old, $new) = @_;
    return min_avgstdev_cycles($old, $new, 1420);
}

sub min_cycle_diff {
    my ($old, $new, $size) = @_;
    my $old_max = get_cycles($size, $old->[9], $old->[15]);
    my $new_max = get_cycles($size, $new->[9], $new->[15]);
    my $old_min = get_cycles($size, $old->[8], $old->[14]);
    my $new_min = get_cycles($size, $new->[8], $new->[14]);
    my $old_diff = $old_max - $old_min;
    my $new_diff = $new_max - $new_min;

    if ($new_diff < $old_diff) {
        return $new;
    } else {
        return $old;
    }
}

sub min_cycle_diff_64 {
    my ($old, $new) = @_;
    return min_cycle_diff($old, $new, 64);
}

sub min_cycle_diff_700 {
    my ($old, $new) = @_;
    return min_cycle_diff($old, $new, 700);
}

sub min_cycle_diff_1420 {
    my ($old, $new) = @_;
    return min_cycle_diff($old, $new, 1420);
}

sub generate_report {
    my ($cmp_ref, $algo_dim, $title, @vars) = @_;
    my %report;

    foreach my $sublist (@vars) {
        $report{$sublist->[18]} = 0;
    }

    for (my $i = 1; $i <= $algo_dim; $i++) {
        my @algo;

        foreach my $sublist (@vars) {
            if ($sublist->[0] == $i) {
                push @algo, $sublist;
            }
        }

        my $count = scalar @algo;
        next unless $count > 0;

        my $ret = $algo[0];

        for (my $i = 1; $i < $count; $i++) {
            $ret = $cmp_ref->($ret, $algo[$i]);
        }

        $report{$ret->[18]}++;
    }

    my @ret_array = ($title, \%report); # create an array to return reference to it next
    return \@ret_array;
}

my @reports;

push @reports, generate_report(\&min_avg_cycles_64, $id, "Avg cycles 64", @list);
push @reports, generate_report(\&min_avg_cycles_700, $id, "Avg cycles 700", @list);
push @reports, generate_report(\&min_avg_cycles_1420, $id, "Avg cycles 1420", @list);
push @reports, generate_report(\&min_avgstdev_cycles_64, $id, "Avg+stdev cycles 64", @list);
push @reports, generate_report(\&min_avgstdev_cycles_700, $id, "Avg+stdev cycles 700", @list);
push @reports, generate_report(\&min_avgstdev_cycles_1420, $id, "Avg+stdev cycles 1420", @list);
push @reports, generate_report(\&min_cycle_diff_64, $id, "(Max-Min) cycles 64", @list);
push @reports, generate_report(\&min_cycle_diff_700, $id, "(Max-Min) cycles 700", @list);
push @reports, generate_report(\&min_cycle_diff_1420, $id, "(Max-Min) cycles 1420", @list);

my $first_line = 1;
my %total;
my $total_num = 0;

foreach my $sublist (@reports) {
    my ($title, $href) = @$sublist;

    if ($first_line != 0) {
        # print header line
        printf("%22s|", "Report Type / Algo \%");
        foreach my $key (sort keys %$href) {
            my $str = $key . "[\%]";
            printf("%17s|", $str);
        }
        printf("\n");
        $first_line = 0;
    }

    printf("%22s|", $title);
    foreach my $key (sort keys %$href) {
        my $value = ($href->{$key} / $num_rows) * 100;
        printf("%17.1f|", $value);
        if (exists $total{$key}) {
            $total{$key} += $value;
        } else {
            $total{$key} = $value;
        }
    }
    printf("\n");
    $total_num++;
}

if ($total_num > 0) {
    # print line with total average values
    printf("%22s|", "TOTAL AVG [\%]");
    foreach my $key (sort keys %total) {
        my $value = $total{$key} / $total_num;
        printf("%17.1f|", $value);
    }
    printf("\n");
}
