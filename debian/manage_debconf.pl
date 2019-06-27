#!/usr/bin/perl
#
# Interface between our config files and the debconf database.
#
# Usage:
#
#   manage_debconf.pl <action>
#
# where <action> can be:
#
#   read:    read the configuration from the yaml into debconf
#   update:  update the yaml config according to the debconf database
use strict;
use warnings;

use Debconf::Client::ConfModule (qw/get set/);

# map from the name of a setting in our .yaml file to the relevant debconf
# setting.
my %MAPPINGS=(
    server_name => 'matrix-synapse/server-name',
    report_stats => 'matrix-synapse/report-stats',
);

# enable debug if dpkg --debug
my $DEBUG = $ENV{DPKG_MAINTSCRIPT_DEBUG};

sub read_config {
    my @files = @_;

    foreach my $file (@files)  {
        print STDERR "reading $file\n" if $DEBUG;

        open my $FH, "<", $file or next;

        # rudimentary parsing which (a) avoids having to depend on a yaml library,
        # and (b) is tolerant of yaml errors
        while($_ = <$FH>) {
            while (my ($setting, $debconf) = each %MAPPINGS) {
                $setting = quotemeta $setting;
                if(/^${setting}\s*:(.*)$/) {
                    my $val = $1;

                    # remove leading/trailing whitespace
                    $val =~ s/^\s*//;
                    $val =~ s/\s*$//;

                    # remove surrounding quotes
                    if ($val =~ /^"(.*)"$/ || $val =~ /^'(.*)'$/) {
                        $val = $1;
                    }

                    print STDERR ">> $debconf = $val\n" if $DEBUG;
                    set($debconf, $val);
                }
            }
        }
        close $FH;
    }
}

sub update_config {
    my @files = @_;

    my %substs = ();
    while (my ($setting, $debconf) = each %MAPPINGS) {
        my @res = get($debconf);
        $substs{$setting} = $res[1] if $res[0] == 0;
    }

    foreach my $file (@files) {
        print STDERR "checking $file\n" if $DEBUG;

        open my $FH, "<", $file or next;

        my $updated = 0;

        # read the whole file into memory
        my @lines = <$FH>;

        while (my ($setting, $val) = each %substs) {
            $setting = quotemeta $setting;

            map {
                if (/^${setting}\s*:\s*(.*)\s*$/) {
                    my $current = $1;
                    if ($val ne $current) {
                        $_ = "${setting}: $val\n";
                        $updated = 1;
                    }
                }
            } @lines;
        }
        close $FH;

        next unless $updated;

        print STDERR "updating $file\n" if $DEBUG;
        open $FH, ">", $file or die "unable to update $file";
        print $FH @lines;
        close $FH;
    }
}


my $cmd = $ARGV[0];

my $read = 0;
my $update = 0;

if (not $cmd) {
    die "must specify a command to perform\n";
} elsif ($cmd eq 'read') {
    $read = 1;
} elsif ($cmd eq 'update') {
    $update = 1;
} else {
    die "unknown command '$cmd'\n";
}

my @files = (
    "/etc/matrix-synapse/homeserver.yaml",
    glob("/etc/matrix-synapse/conf.d/*.yaml"),
);

if ($read) {
    read_config(@files);
} elsif ($update) {
    update_config(@files);
}
