#!/usr/bin/env perl

use strict;
use warnings;

use DBI;
use DBD::SQLite;
use JSON;

my $dbh = DBI->connect("dbi:SQLite:dbname=homeserver.db","","") || die DBI->error;

my $res = $dbh->selectall_arrayref("select token, name from access_tokens, users where access_tokens.user_id = users.id group by user_id") || die DBI->error;

foreach (@$res) {
    my ($token, $mxid) = ($_->[0], $_->[1]);
    my ($user_id) = ($mxid =~ m/@(.*):/);
    my ($url) = $dbh->selectrow_array("select avatar_url from profiles where user_id=?", undef, $user_id);
    if (!$url || $url =~ /#auto$/) {
        `curl -o tmp.png "http://localhost:8008/_matrix/media/v1/identicon?name=${mxid}&width=320&height=320"`;
        my $json = `curl -X POST -H "Content-Type: image/png" -T "tmp.png" http://localhost:8008/_matrix/media/v1/upload?access_token=$token`;
        my $content_uri = from_json($json)->{content_uri};
        `curl -X PUT -H "Content-Type: application/json" --data '{ "avatar_url": "${content_uri}#auto"}' http://localhost:8008/_matrix/client/api/v1/profile/${mxid}/avatar_url?access_token=$token`;
    }
}
