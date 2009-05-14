#!/usr/bin/perl -w
#
# dmc-setup.pl
#
# A wrapper script for setting up dm-cache
#
# Copyright (C) International Business Machines Corp., 2006
# Author: Ming Zhao
#
# This file is subject to the terms and conditions of the GNU Lesser
# General Public License. See the file COPYING in the main directory
# of this archive for more details.
#

use strict;
use Getopt::Long;

require 'sys/ioctl.ph';

my $lsmod = "/proc/modules";
my $modprobe = "/sbin/modprobe dm-cache";

my $srcdev = "";
my $cachedev = "";
my $name = "";
my $persistence = 0;	#default is to not load metadata from cache disk
my $size = 65536;
my $assoc = 16;
my $block = 8;
my $writeback = 0;		#default is to not use write delay
my $help = "";
my $cmd = "";

my $result = GetOptions("orgdev=s" => \$srcdev,
                        "cachedev=s" => \$cachedev,
                        "name=s" => \$name,
						"persistence" => \$persistence,
                        "size=i" => \$size,
                        "assoc=i" => \$assoc,
                        "block=i" => \$block,
						"writeback" => \$writeback,
                        "help"=>\$help);

usage() if $help;
usage() unless $result && $srcdev && $cachedev && $name;

open MOD, "< $lsmod";
my @mods = <MOD>;
close MOD;
if (!grep(/dm_cache/, @mods)) {
	die unless system($modprobe) == 0;
}

open(DEV, "< $srcdev");
my $devsize;
$devsize = pack("L", 0);
ioctl(DEV, 0x00001260, $devsize)
	or die "Failed to call ioctl: $!\n";
$devsize = unpack("L", $devsize);
#print $devsize, "\n";
close(DEV);

if ($persistence) {
	$cmd = "echo 0 $devsize cache $srcdev $cachedev $persistence";
} else {
	$cmd = "echo 0 $devsize cache $srcdev $cachedev $persistence $block $size $assoc $writeback";
}
$cmd .= " | dmsetup create $name";
print "$cmd\n";
exec($cmd);

sub usage {
    print <<EOM;
Usage: 
	$0 -o srcdev -c cachedev -n name [-p persistence] [-b blocksize] 
		[-s cachesize] [-a associativity] [-w writeback]
	$0 -h
Examples:
	'$0 -o /dev/hda2 -c /dev/hda3 -n cache '
	'$0 -o /dev/hda2 -c /dev/hda3 -n cache -p'
	'$0 -o /dev/hda2 -c /dev/hda3 -n cache -b 8 -s 65536 -a 16'
	'$0 -orgdev /dev/hda2 -cachedev -name cache /dev/hda3 -block 8 -size 65536 -assoc 16'

	-h, --help			displays this help and exit
	-o, --orgdev		indicates the full path of the source device
	-c, --cachedev		indicates the full path of the cache device
	-n, --name			indicates the name of the cache
	-p, --persistence	indicates whether to load metadata from cache disk
	-b, --block			indicates the cache block size (in number of sectors)
	-s, --size			indicates the cache size (in number of blocks)
	-a, --assoc			indicates the cache associativity
	-w, --writeback		indicates whether to use write delay
EOM
    exit (1);
}
exit (0);

__END__

=head1 NAME

dmc-setup.pl - creates a block-level disk cache using the dm-cache device mapper target.

=head1 SYNOPSIS

dmc-setup.pl -o srcdev -c cachedev -n name [-p persistence] [-b blocksize] 
          [-s cachesize] [-a associativity] [-w writeback]

dmc-setup.pl -h

Examples:

dmc-setup.pl -o /dev/hda2 -c /dev/hda3 -n cache

dmc-setup.pl -o /dev/hda2 -c /dev/hda3 -n cache -p

dmc-setup.pl -o /dev/hda2 -c /dev/hda3 -n cache -b 8 -s 65536 -a 16
	
dmc-setup.pl -orgdev /dev/hda2 -cachedev -name cache /dev/hda3 -block 8 -size 65536 -assoc 16

=head1 OPTIONS

-h, --help		displays this help and exit

-o, --orgdev		indicates the full path of the source device

-c, --cachedev		indicates the full path of the cache device

-n, --name		indicates the name of the cache

-p, --persistence	indicates whether to load metadata from cache disk

-b, --block		indicates the cache block size (in number of sectors)

-s, --size		indicates the cache size (in number of blocks)

-a, --assoc		indicates the cache associativity

-w, --writeback	indicates whether to use write delay

=head1 DESCRIPTION

Creates a block-level disk cache using the dm-cache device mapper target. A
virtual device is created under /dev/mapper, which provides the cahce mapping 
between the source device and the cache device.

=over 4

=item *

orgdev: The path to the source device where data is originally stored. The device
can be a disk remotely accessed through SAN, iSCSI or fiber channels.

=item *

cachedev: The path to the cache device where data is locally cached. The device
can be any type of disk that is locally attached to the system.

=item *

name: The name of the cache. Once the cache is created, the virtual device 
/dev/mapper/<cache_name> can be accessed like a regular device, but it automatically
caches the data blocks in the local cache when they are accessed.

=item *

persistence: The flag to indicate whether to load metadata (including cache
parameters and block mappings) from cache disk. If it is set, the metadata 
previously stored in the cache device is loaded so that the existing cached data 
blocks can be reused. Otherwise, a new cache is started from scratch.

=item *

block: The cache block size. A disk cache is organized in data blocks, which
are in the size of multiple disk sectors (typically 512B per sector).

=item *

size: The cache capacity (in number of blocks). The cache capacity is limited by
the storage size of the cache device.

=item *

assoc: The cache associativity. Using a larger associativity may relatively
reduce the number of cache conflicts (data blocks that are mapped to the same
cache location).

=item *

writeback: The flag to indicate whether to use write delay. If it is set, writes
are stored in the cache device first, and submitted to the source device later
(before the cache is removed). This helps to improve the performance of write
operations. But it is not recommended if the cache device is not stable, which
may cause data loss if it crashes.

=back

Note 1: To remove a cache, use command: dmsetup remove <cache_name>

Note 2: If the program fails to create a cache, check /var/log/kern.log for more
information.

=head1 COPYRIGHT

Copyright (C) International Business Machines Corp., 2006

Author: Ming Zhao (mingzhao99th@gmail.com)

=head1 SEE ALSO

man dmsetup

dm-cache project page: http://www.acis.ufl.edu/~ming/dmcache
