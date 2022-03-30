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

my $enc=1;

while(<STDIN>)
{

	if(/^\[ENCRYPT\]/) {
		$enc=1;
		print "/* ENCRYPT */\n";
	}

	if(/^\[DECRYPT\]/) {
		$enc=0;
		print "/* DECRYPT */\n";
	}

	if($_ =~ /^COUNT = /) {

		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

		$dul = readit;
		$dul =~ s/^DataUnitLen = (\w*).*/$1/;

		$key = readit;
		$key =~ s/^Key = (\w*).*/$1/;
		$keylen = length($key)/4;
		$dkey = substr $key, 0, $keylen*2;
		$tkey = substr $key, $keylen*2;
		$dkey = stringit($dkey);
		$tkey = stringit($tkey);

		$i = readit;
		$i =~ s/^i = (\w*).*/$1/;
		$i = stringit($i);

		if($enc==0) {
			$ct=readit;
			$ct =~ s/^CT = (\w*).*/$1/;
			$ct = stringit($ct);
		}

		$pt=readit;
		$pt =~ s/^PT = (\w*).*/$1/;
		$ptlen = length($pt)/2;
		$pt = stringit($pt);

		if($enc==1) {
			$ct=readit;
			$ct =~ s/^CT = (\w*).*/$1/;
			$ct = stringit($ct);
		}


		print "{ /* $count */\n";
		print "\t$keylen,\n";
		print "\t$dkey,\n";
		print "\t$tkey,\n";
		print "\t$i,\n";
		print "\t$ptlen,\n";
		print "\t$pt,\n";
		print "\t$ct\n";
		print "},\n";
	}

}
