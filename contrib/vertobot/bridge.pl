#!/usr/bin/env perl 

use strict;
use warnings;
use 5.010; # //
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use IO::Async::Loop;
use Net::Async::WebSocket::Client;
use Net::Async::HTTP;
use Net::Async::HTTP::Server;
use JSON;
use YAML;
use Data::UUID;
use Getopt::Long;
use Data::Dumper;
use URI::Encode qw(uri_encode uri_decode);
    
binmode STDOUT, ":encoding(UTF-8)";
binmode STDERR, ":encoding(UTF-8)";

my $msisdn_to_matrix = {
    '447417892400' => '@matthew:matrix.org',
};

my $matrix_to_msisdn = {};
foreach (keys %$msisdn_to_matrix) {
    $matrix_to_msisdn->{$msisdn_to_matrix->{$_}} = $_;
}


my $loop = IO::Async::Loop->new;
# Net::Async::HTTP + SSL + IO::Poll doesn't play well. See
#   https://rt.cpan.org/Ticket/Display.html?id=93107
# ref $loop eq "IO::Async::Loop::Poll" and
#     warn "Using SSL with IO::Poll causes known memory-leaks!!\n";

GetOptions(
   'C|config=s' => \my $CONFIG,
   'eval-from=s' => \my $EVAL_FROM,
) or exit 1;

if( defined $EVAL_FROM ) {
    # An emergency 'eval() this file' hack
    $SIG{HUP} = sub {
        my $code = do {
            open my $fh, "<", $EVAL_FROM or warn( "Cannot read - $!" ), return;
            local $/; <$fh>
        };

        eval $code or warn "Cannot eval() - $@";
    };
}

defined $CONFIG or die "Must supply --config\n";

my %CONFIG = %{ YAML::LoadFile( $CONFIG ) };

my %MATRIX_CONFIG = %{ $CONFIG{matrix} };
# No harm in always applying this
$MATRIX_CONFIG{SSL_verify_mode} = SSL_VERIFY_NONE;

my $bridgestate = {};
my $roomid_by_callid = {};
    
my $sessid = lc new Data::UUID->create_str();    
my $as_token = $CONFIG{"matrix-bot"}->{as_token};
my $hs_domain = $CONFIG{"matrix-bot"}->{domain};

my $http = Net::Async::HTTP->new();
$loop->add( $http );

sub create_virtual_user
{
    my ($localpart) = @_;
    my ( $response ) = $http->do_request(
        method => "POST",
        uri => URI->new(
            $CONFIG{"matrix"}->{server}.
                "/_matrix/client/api/v1/register?".
                "access_token=$as_token&user_id=$localpart"
        ),
        content_type => "application/json",
        content => <<EOT
{
    "type": "m.login.application_service",
    "user": "$localpart"
}
EOT
    )->get;
    warn $response->as_string if ($response->code != 200);
}
    
my $http_server =  Net::Async::HTTP::Server->new(
    on_request => sub {
        my $self = shift;
        my ( $req ) = @_;

        my $response;
        my $path = uri_decode($req->path);
        warn("request: $path");
        if ($path =~ m#/users/\@(\+.*)#) {
            # when queried about virtual users, auto-create them in the HS
            my $localpart = $1;
            create_virtual_user($localpart);
            $response = HTTP::Response->new( 200 );
            $response->add_content('{}');
            $response->content_type( "application/json" );
        }
        elsif ($path =~ m#/transactions/(.*)#) {
            my $event = JSON->new->decode($req->body);
            print Dumper($event);

            my $room_id = $event->{room_id};
            my %dp = %{$CONFIG{'verto-dialog-params'}};
            $dp{callID} = $bridgestate->{$room_id}->{callid};

            if ($event->{type} eq 'm.room.membership') {
                my $membership = $event->{content}->{membership};
                my $state_key = $event->{state_key};
                my $room_id = $event->{state_id};
                
                if ($membership eq 'invite') {
                    # autojoin invites
                    my ( $response ) = $http->do_request(
                        method => "POST",
                        uri => URI->new(
                            $CONFIG{"matrix"}->{server}.
                                "/_matrix/client/api/v1/rooms/$room_id/join?".
                                "access_token=$as_token&user_id=$state_key"
                        ),
                        content_type => "application/json",
                        content => "{}",
                    )->get;
                    warn $response->as_string if ($response->code != 200);
                }
            }
            elsif ($event->{type} eq 'm.call.invite') {
                my $room_id = $event->{room_id};
                $bridgestate->{$room_id}->{matrix_callid} = $event->{content}->{call_id};
                $bridgestate->{$room_id}->{callid} = lc new Data::UUID->create_str();
                $bridgestate->{$room_id}->{sessid} = $sessid;                
                # $bridgestate->{$room_id}->{offer} = $event->{content}->{offer}->{sdp};
                my $offer = $event->{content}->{offer}->{sdp};
                # $bridgestate->{$room_id}->{gathered_candidates} = 0;
                $roomid_by_callid->{ $bridgestate->{$room_id}->{callid} } = $room_id;
                # no trickle ICE in verto apparently

                my $f = send_verto_json_request("verto.invite", {
                    "sdp" => $offer,
                    "dialogParams" => \%dp,
                    "sessid" => $bridgestate->{$room_id}->{sessid},
                });
                $self->adopt_future($f);
            }
            # elsif ($event->{type} eq 'm.call.candidates') {
            #     # XXX: this could fire for both matrix->verto and verto->matrix calls
            #     # and races as it collects candidates. much better to just turn off
            #     # candidate gathering in the webclient entirely for now
            #     
            #     my $room_id = $event->{room_id};
            #     # XXX: compare call IDs
            #     if (!$bridgestate->{$room_id}->{gathered_candidates}) {
            #         $bridgestate->{$room_id}->{gathered_candidates} = 1;
            #         my $offer = $bridgestate->{$room_id}->{offer};
            #         my $candidate_block = "";
            #         foreach (@{$event->{content}->{candidates}}) {
            #             $candidate_block .= "a=" . $_->{candidate} . "\r\n";
            #         }
            #         # XXX: collate using the right m= line - for now assume audio call
            #         $offer =~ s/(a=rtcp.*[\r\n]+)/$1$candidate_block/;
            #     
            #         my $f = send_verto_json_request("verto.invite", {
            #             "sdp" => $offer,
            #             "dialogParams" => \%dp,
            #             "sessid" => $bridgestate->{$room_id}->{sessid},
            #         });
            #         $self->adopt_future($f);
            #     }
            #     else {
            #         # ignore them, as no trickle ICE, although we might as well
            #         # batch them up
            #         # foreach (@{$event->{content}->{candidates}}) {
            #         #     push @{$bridgestate->{$room_id}->{candidates}}, $_;
            #         # }
            #     }
            # }
            elsif ($event->{type} eq 'm.call.answer') {
                # grab the answer and relay it to verto as a verto.answer
                my $room_id = $event->{room_id};
                
                my $answer = $event->{content}->{answer}->{sdp};
                my $f = send_verto_json_request("verto.answer", {
                    "sdp" => $answer,
                    "dialogParams" => \%dp,
                    "sessid" => $bridgestate->{$room_id}->{sessid},
                });
                $self->adopt_future($f);
            }
            elsif ($event->{type} eq 'm.call.hangup') {
                my $room_id = $event->{room_id};
                if ($bridgestate->{$room_id}->{matrix_callid} eq $event->{content}->{call_id}) {
                    my $f = send_verto_json_request("verto.bye", {
                        "dialogParams" => \%dp,
                        "sessid" => $bridgestate->{$room_id}->{sessid},
                    });
                    $self->adopt_future($f);
                }
                else {
                    warn "Ignoring unrecognised callid: ".$event->{content}->{call_id};
                }
            }
            else {
                warn "Unhandled event: $event->{type}";
            }
            
            $response = HTTP::Response->new( 200 );
            $response->add_content('{}');
            $response->content_type( "application/json" );            
        }
        else {
            warn "Unhandled path: $path";
            $response = HTTP::Response->new( 404 );
        }

        $req->respond( $response );
    },
);
$loop->add( $http_server );

$http_server->listen(
    addr => { family => "inet", socktype => "stream", port => 8009 },
    on_listen_error => sub { die "Cannot listen - $_[-1]\n" },
);

my $bot_verto = Net::Async::WebSocket::Client->new(
    on_frame => sub {
          my ( $self, $frame ) = @_;
          warn "[Verto] receiving $frame";
          on_verto_json($frame);
    },
);
$loop->add( $bot_verto );

my $verto_connecting = $loop->new_future;
$bot_verto->connect(
    %{ $CONFIG{"verto-bot"} },
    on_connected => sub {
        warn("[Verto] connected to websocket");
        if (not $verto_connecting->is_done) {
            $verto_connecting->done($bot_verto);

            send_verto_json_request("login", {
                'login' => $CONFIG{'verto-dialog-params'}{'login'},
                'passwd' => $CONFIG{'verto-config'}{'passwd'},
                'sessid' => $sessid,
            });
        }
    },
    on_connect_error => sub { die "Cannot connect to verto - $_[-1]" },
    on_resolve_error => sub { die "Cannot resolve to verto - $_[-1]" },        
);

# die Dumper($verto_connecting);

my $as_url = $CONFIG{"matrix-bot"}->{as_url};

Future->needs_all(
    $http->do_request(
            method => "POST",
            uri => URI->new( $CONFIG{"matrix"}->{server}."/_matrix/appservice/v1/register" ),
            content_type => "application/json",
            content => <<EOT
{
    "as_token": "$as_token",
    "url": "$as_url",
    "namespaces": { "users": [ { "regex": "\@\\\\+.*", "exclusive": false } ] }
}
EOT
    )->then( sub{
        my ($response) = (@_);
        warn $response->as_string if ($response->code != 200);
        return Future->done;
    }),
    $verto_connecting,
)->get;

$loop->attach_signal(
    PIPE => sub { warn "pipe\n" }
);
$loop->attach_signal(
    INT => sub { $loop->stop },
);
$loop->attach_signal(
    TERM => sub { $loop->stop },
);

eval {
   $loop->run;
} or my $e = $@;

die $e if $e;

exit 0;

{    
    my $json_id;
    my $requests;

    sub send_verto_json_request
    {
        $json_id ||= 1;
        
        my ($method, $params) = @_;
        my $json = {
            jsonrpc => "2.0",
            method  => $method,
            params  => $params,
            id      => $json_id,
        };
        my $text = JSON->new->encode( $json );
        warn "[Verto] sending $text";
        $bot_verto->send_frame ( $text );
        my $request = $loop->new_future;
        $requests->{$json_id} = $request;
        $json_id++;
        return $request;
    }
    
    sub send_verto_json_response
    {
        my ($result, $id) = @_;
        my $json = {
            jsonrpc => "2.0",
            result  => $result,
            id      => $id,
        };
        my $text = JSON->new->encode( $json );
        warn "[Verto] sending $text";
        $bot_verto->send_frame ( $text );
    }
    
    sub on_verto_json
    {
        my $json = JSON->new->decode( $_[0] );
        if ($json->{method}) {
            if (($json->{method} eq 'verto.answer' && $json->{params}->{sdp}) ||
                $json->{method} eq 'verto.media') {

                my $caller = $json->{dialogParams}->{caller_id_number};
                my $callee = $json->{dialogParams}->{destination_number};
                my $caller_user = '@+' . $caller . ':' . $hs_domain;
                my $callee_user = $msisdn_to_matrix->{$callee} || warn "unrecogised callee: $callee";                                
                my $room_id = $roomid_by_callid->{$json->{params}->{callID}};

                if ($json->{params}->{sdp}) {
                    $http->do_request(
                        method => "POST",
                        uri => URI->new(
                            $CONFIG{"matrix"}->{server}.
                                "/_matrix/client/api/v1/send/m.call.answer?".
                                "access_token=$as_token&user_id=$caller_user"
                        ),
                        content_type => "application/json",
                        content => JSON->new->encode({
                            call_id => $bridgestate->{$room_id}->{matrix_callid},
                            version => 0,
                            answer  => {
                                sdp => $json->{params}->{sdp},
                                type => "answer",
                            },
                        }),
                    )->then( sub {
                        send_verto_json_response( {
                            method => $json->{method},
                        }, $json->{id});
                    })->get;
                }
            }
            elsif ($json->{method} eq 'verto.invite') {
                my $caller = $json->{dialogParams}->{caller_id_number};
                my $callee = $json->{dialogParams}->{destination_number};
                my $caller_user = '@+' . $caller . ':' . $hs_domain;
                my $callee_user = $msisdn_to_matrix->{$callee} || warn "unrecogised callee: $callee";
                    
                my $alias = ($caller lt $callee) ? ($caller.'-'.$callee) : ($callee.'-'.$caller);
                my $room_id;

                # create a virtual user for the caller if needed.
                create_virtual_user($caller);
                
                # create a room of form #peer-peer and invite the callee
                $http->do_request(
                    method => "POST",
                    uri => URI->new(
                        $CONFIG{"matrix"}->{server}.
                            "/_matrix/client/api/v1/createRoom?".
                            "access_token=$as_token&user_id=$caller_user"
                    ),
                    content_type => "application/json",
                    content => JSON->new->encode({
                        room_alias_name => $alias,
                        invite => [ $callee_user ],
                    }),
                )->then( sub {
                    my ( $response ) = @_;
                    my $resp = JSON->new->decode($response->content);
                    $room_id = $resp->{room_id};
                    $roomid_by_callid->{$json->{params}->{callID}} = $room_id;
                })->get;

                # join it
                my ($response) = $http->do_request(
                    method => "POST",
                    uri => URI->new(
                        $CONFIG{"matrix"}->{server}.
                            "/_matrix/client/api/v1/join/$room_id?".
                            "access_token=$as_token&user_id=$caller_user"
                    ),
                    content_type => "application/json",
                    content => '{}',
                )->get;

                $bridgestate->{$room_id}->{matrix_callid} = lc new Data::UUID->create_str();
                $bridgestate->{$room_id}->{callid} = $json->{dialogParams}->{callID};
                $bridgestate->{$room_id}->{sessid} = $sessid;

                # put the m.call.invite in there
                $http->do_request(
                    method => "POST",
                    uri => URI->new(
                        $CONFIG{"matrix"}->{server}.
                            "/_matrix/client/api/v1/send/m.call.invite?".
                            "access_token=$as_token&user_id=$caller_user"
                    ),
                    content_type => "application/json",
                    content => JSON->new->encode({
                        call_id => $bridgestate->{$room_id}->{matrix_callid},
                        version => 0,
                        answer  => {
                            sdp => $json->{params}->{sdp},
                            type => "offer",
                        },
                    }),
                )->then( sub {
                    # acknowledge the verto
                    send_verto_json_response( {
                        method => $json->{method},
                    }, $json->{id});
                })->get;
            }
            elsif ($json->{method} eq 'verto.bye') {
                my $caller = $json->{dialogParams}->{caller_id_number};
                my $callee = $json->{dialogParams}->{destination_number};
                my $caller_user = '@+' . $caller . ':' . $hs_domain;
                my $callee_user = $msisdn_to_matrix->{$callee} || warn "unrecogised callee: $callee";                                
                my $room_id = $roomid_by_callid->{$json->{params}->{callID}};
                
                # put the m.call.hangup into the room
                $http->do_request(
                    method => "POST",
                    uri => URI->new(
                        $CONFIG{"matrix"}->{server}.
                            "/_matrix/client/api/v1/send/m.call.hangup?".
                            "access_token=$as_token&user_id=$caller_user"
                    ),
                    content_type => "application/json",
                    content => JSON->new->encode({
                        call_id => $bridgestate->{$room_id}->{matrix_callid},
                        version => 0,
                    }),
                )->then( sub {
                    # acknowledge the verto
                    send_verto_json_response( {
                        method => $json->{method},
                    }, $json->{id});
                })->get;
            }
            else {
                warn ("[Verto] unhandled method: " . $json->{method});
                send_verto_json_response( {
                    method => $json->{method},
                }, $json->{id});
            }
        }
        elsif ($json->{result}) {
            $requests->{$json->{id}}->done($json->{result});
        }
        elsif ($json->{error}) {
            $requests->{$json->{id}}->fail($json->{error}->{message}, $json->{error});
        }
    }
}

