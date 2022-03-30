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

while(<STDIN>)
{

	if($_ =~ /^COUNT = /) {

		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

		$key = readit;
		$key =~ s/^KEY = (\w*).*/$1/;
		$keylen = length($key)/2;
		$key = stringit($key);

		$iv = readit;
		$iv =~ s/^IV = (\w*).*/$1/;
		$iv = stringit($iv);

		$pt=readit;
		$pt =~ s/^PLAINTEXT = (\w*).*/$1/;
		$ptlen = length($pt)/2;
		$pt = stringit($pt);

		$ct=readit;
		$ct =~ s/^CIPHERTEXT = (\w*).*/$1/;
		$ct = stringit($ct);

		print "{ /* $count */\n";
		print "\t$keylen,\n";
		print "\t$key,\n";
		print "\t$iv,\n";
		print "\t$ptlen,\n";
		print "\t$pt,\n";
		print "\t$ct\n";
		print "},\n";
	}
}
