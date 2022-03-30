# Copyright (c) (2011,2014,2015,2019) Apple Inc. All rights reserved.
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

	if(/^\[L=(\w*)\]/) {
		$L = $1;
	}

	if($_ =~ /^Count = /) {

		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

		$kl = readit;
		$kl =~ s/^Klen = (\w*).*/$1/;

		$tl = readit;
		$tl =~ s/^Tlen = (\w*).*/$1/;

		$key = readit;
		$key =~ s/^Key = (\w*).*/$1/;
		$keylen = length($key)/2;
		$key = stringit($key);

		$msg = readit;
		$msg =~ s/^Msg = (\w*).*/$1/;
		$msglen = length($msg)/2;
		$msg = stringit($msg);

		$mac = readit;
		$mac =~ s/^Mac = (\w*).*/$1/;
		$maclen = length($mac)/2;
		$mac = stringit($mac);


		print "{ /* $count */\n";
		print "\thmac_di_$L,\n";
		print "\t$keylen,\n";
		print "\t$key,\n";
		print "\t$msglen,\n";
		print "\t$msg,\n";
		print "\t$maclen,\n";
		print "\t$mac,\n";
		print "},\n";
	}

}
