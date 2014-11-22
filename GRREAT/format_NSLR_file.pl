#!/usr/bin/perl
use strict;
use warnings;

open(INPUT, '<ssdb4096.txt') or die('File not found.');
open(OUTPUT, '>nslr400.txt') or die('File not found.');
while(my $line = <INPUT>) {
	# Each line in the original file has the format:
	# 0459S875Z531D040K2AH0           ssdeep[4096]=ssdeep_hash,"filename"
	# This regex removes the first part and keeps only the ssdeep hash and filename.
	$line =~ s/^\w+\s+ssdeep\[4096\]=(.+)$/$1/i;
	print OUTPUT $line;
}
close(INPUT);
close(OUTPUT);