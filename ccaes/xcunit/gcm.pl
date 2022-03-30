# Copyright (c) (2011,2014,2015,2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/usr/bin/perl -w

sub stringit
{
	my ($arg)=@_;
	$arg =~ s/(\w\w)/\\x$1/g;
	return "\"".$arg."\"";
}

sub readit
{
	$_ = <STDIN>;
	s/\r//;
	s/\n//;
	return $_;
}

sub readstring
{
	my ($k)=@_;

	$s = readit;
	$s =~ s/^${k} = (\w*).*/$1/;
	$l = length($s)/2;
	$s = stringit($s);

	return ($l, $s);
}

while(<STDIN>)
{

	if($_ =~ /^\[/)
	{
		s/\r//;
		s/\n//;

		printf "/* $_ */\n";
	}

	if($_ =~ /^Count = /)
	{

		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

		($kl, $k) = readstring("Key");
		($il, $i) = readstring("IV");
		($pl, $p) = readstring("PT");
		($al, $a) = readstring("AAD");
		($cl, $c) = readstring("CT");
		($tl, $t) = readstring("Tag");

		print "{ /* $count */\n";
		print "\t$kl, $k,\n";
		print "\t$il, $i,\n";
		print "\t$pl, $p,\n";
		print "\t$al, $a,\n";
		print "\t$cl, $c,\n";
		print "\t$tl, $t,\n";
		print "},\n";
	}
}
