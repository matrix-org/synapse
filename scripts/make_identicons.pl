#!/usr/bin/env perl

use strict;
use warnings;

use DBI;
use DBD::SQLite;
use JSON;
use Getopt::Long;

my $db; # = "homeserver.db";
my $server = "http://localhost:8008";
my $size = 320;

GetOptions("db|d=s",     \$db,
           "server|s=s", \$server,
           "width|w=i",  \$size) or usage();

usage() unless $db;

my $dbh = DBI->connect("dbi:SQLite:dbname=$db","","") || die $DBI::errstr;

my $res = $dbh->selectall_arrayref("select token, name from access_tokens, users where access_tokens.user_id = users.id group by user_id") || die $DBI::errstr;

foreach (@$res) {
    my ($token, $mxid) = ($_->[0], $_->[1]);
    my ($user_id) = ($mxid =~ m/@(.*):/);
    my ($url) = $dbh->selectrow_array("select avatar_url from profiles where user_id=?", undef, $user_id);
    if (!$url || $url =~ /#auto$/) {
        `curl -s -o tmp.png "$server/_matrix/media/v1/identicon?name=${mxid}&width=$size&height=$size"`;
        my $json = `curl -s -X POST -H "Content-Type: image/png" -T "tmp.png" $server/_matrix/media/v1/upload?access_token=$token`;
        my $content_uri = from_json($json)->{content_uri};
        `curl -X PUT -H "Content-Type: application/json" --data '{ "avatar_url": "${content_uri}#auto"}' $server/_matrix/client/api/v1/profile/${mxid}/avatar_url?access_token=$token`;
    }
}

sub usage {
    die "usage: ./make-identicons.pl\n\t-d database [e.g. homeserver.db]\n\t-s homeserver (default: http://localhost:8008)\n\t-w identicon size in pixels (default 320)";
}