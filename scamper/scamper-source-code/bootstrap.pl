#!/usr/bin/env perl
#
# $Id: bootstrap.pl,v 1.5 2015/04/24 04:52:14 mjl Exp $
#
# script to ship scamper with generated configure script ready to build.

use strict;
use warnings;

my @aclocal = ("aclocal", "aclocal-1.11", "aclocal-1.9");
my @libtoolize = ("libtoolize", "glibtoolize");
my @autoheader = ("autoheader", "autoheader-2.68", "autoheader259");
my @automake = ("automake", "automake-1.11");
my @autoconf = ("autoconf", "autoconf-2.68");

my $ax_check_openssl =
    "http://git.savannah.gnu.org/gitweb/" .
    "?p=autoconf-archive.git;a=blob_plain;f=m4/ax_check_openssl.m4";

sub which($)
{
    my ($bin) = @_;
    my $rc = undef;
    open(WHICH, "which $bin |") or die "could not which";
    while(<WHICH>)
    {
	chomp;
	$rc = $_;
	last;
    }
    close WHICH;
    return $rc;
}

sub tryexec
{
    my $args = shift;
    my $rc = -1;

    foreach my $util (@_)
    {
	$util = which($util);
	if(defined($util))
	{
	    print "===> $util $args\n";
	    $rc = system("$util $args");
	    last;
	}
    }

    return $rc;
}

if(!-d "m4")
{
    exit -1 if(!(mkdir "m4"));
}

if(!-r "m4/ax_check_openssl.m4")
{
    foreach my $util ("fetch", "wget")
    {
	my $fetch = which($util);
	next if(!defined($fetch));

	if($util eq "wget")
	{
	    system("wget -O m4/ax_check_openssl.m4 \"$ax_check_openssl\"");
	    last;
	}
	elsif($util eq "fetch")
	{
	    system("fetch -o m4/ax_check_openssl.m4 \"$ax_check_openssl\"");
	    last;
	}
    }

    my $sum;
    foreach my $util ("sha256", "sha256sum", "shasum")
    {
	my $sha256 = which($util);
	next if(!defined($sha256));
	$sha256 .= " -a 256" if($util eq "shasum");

	open(SUM, "$sha256 m4/ax_check_openssl.m4 |")
	    or die "could not $sha256 m4/ax_check_openssl.m4";
	while(<SUM>)
	{
	    chomp;
	    if(/^SHA256 \(m4\/ax_check_openssl\.m4\) \= (.+)/) {
		$sum = $1;
		last;
	    } elsif(/^(.+?)\s+m4\/ax_check_openssl\.m4/) {
		$sum = $1;
		last;
	    }
	}
	close SUM;
	last if(defined($sum));
    }
    if(!defined($sum) || $sum ne
       "6abec1e9efba7081fc2dc547714bad021a43d41fdd1628c47112f9f10383ce6e")
    {
	print STDERR "ax_check_openssl.m4 has unexpected sha256 sum\n";
	exit -1;
    }
    else
    {
	print STDERR "ax_check_openssl.m4 has valid sha256 sum\n";
    }
}

if(tryexec("", @aclocal) != 0)
{
    print STDERR "could not exec aclocal\n";
    exit -1;
}

if(tryexec("--force --copy", @libtoolize) != 0)
{
    print STDERR "could not libtoolize\n";
    exit -1;
}

if(tryexec("", @autoheader) != 0)
{
    print STDERR "could not autoheader\n";
    exit -1;
}

if(tryexec("--add-missing --copy --foreign", @automake) != 0)
{
    print STDERR "could not automake\n";
    exit -1;
}

if(tryexec("", @autoconf) != 0)
{
    print STDERR "could not autoconf\n";
    exit -1;
}

exit 0;
