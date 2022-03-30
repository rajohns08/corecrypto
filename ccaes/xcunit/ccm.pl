# Copyright (c) (2012,2014,2015,2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/usr/bin/perl -w
use feature qw{ switch };

sub stringit
{
	my ($arg)=@_;
	$arg =~ s/(\w\w)/\\x$1/g;
	return "\"".$arg."\"";
}

sub readstring
{
	my ($s)=@_;

	$s =~ s/^\w+ = (\w*).*/$1/;
    if ($s eq "00") { return (0, "\"\""); }
	$l = length($s)/2;
	$s = stringit($s);

	return ($l, $s);
}


print "/* Key, Nonce, Payload, Adata, CT => Tag|CT */\n";

while(<STDIN>)
{

    s/\r//;
    s/\n//;

	if($_ =~ /^[\[#]/)
	{

		printf "/* $_ */\n";
	}

	if($_ =~ /^Count = /)
	{
		$count = $_;
        $new_test = 1;
    }

    given ($_) {
		($kl, $k) = readstring($_) when /^Key/;
		($il, $i) = readstring($_) when /^Nonce/;
		($pl, $p) = readstring($_) when /^Payload/;
		($al, $a) = readstring($_) when /^Adata/;
		($cl, $c) = readstring($_) when /^CT/;
    }

    if ($_ =~ /^$/ and $new_test)
    {
		print "{ /* $count */\n";
		print "\t$kl, $k,\n";
		print "\t$il, $i,\n";
		print "\t$pl, $p,\n";
		print "\t$al, $a,\n";
		print "\t$cl, $c,\n";
		print "},\n";
        $new_test = 0;
	}
}
