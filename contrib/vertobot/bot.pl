#!/usr/bin/env perl 

use strict;
use warnings;
use 5.010; # //
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use IO::Async::Loop;
use Net::Async::WebSocket::Client;
use Net::Async::Matrix 0.11_002;
use JSON;
use YAML;
use Data::UUID;
use Getopt::Long;
use Data::Dumper;

binmode STDOUT, ":encoding(UTF-8)";
binmode STDERR, ":encoding(UTF-8)";

my $loop = IO::Async::Loop->new;
# Net::Async::HTTP + SSL + IO::Poll doesn't play well. See
#   https://rt.cpan.org/Ticket/Display.html?id=93107
ref $loop eq "IO::Async::Loop::Poll" and
    warn "Using SSL with IO::Poll causes known memory-leaks!!\n";

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

# Track every Room object, so we can ->leave them all on shutdown
my %bot_matrix_rooms;

my $bridgestate = {};
my $roomid_by_callid = {};

my $bot_verto = Net::Async::WebSocket::Client->new(
    on_frame => sub {
          my ( $self, $frame ) = @_;
          warn "[Verto] receiving $frame";
          on_verto_json($frame);
    },
);
$loop->add( $bot_verto );

my $sessid = lc new Data::UUID->create_str();

my $bot_matrix = Net::Async::Matrix->new(
    %MATRIX_CONFIG,
    on_log => sub { warn "log: @_\n" },
    on_invite => sub {
        my ($matrix, $invite) = @_;
        warn "[Matrix] invited to: " . $invite->{room_id} . " by " . $invite->{inviter} . "\n";
        
        $matrix->join_room( $invite->{room_id} )->get;
    },
    on_room_new => sub {
        my ($matrix, $room) = @_;

        warn "[Matrix] have a room ID: " . $room->room_id . "\n";

        $bot_matrix_rooms{$room->room_id} = $room;
        
        # log in to verto on behalf of this room
        $bridgestate->{$room->room_id}->{sessid} = $sessid;
         
        $room->configure(
            on_message => \&on_room_message,
        );
        
        my $f = send_verto_json_request("login", {
                'login' => $CONFIG{'verto-dialog-params'}{'login'},
                'passwd' => $CONFIG{'verto-config'}{'passwd'},
                'sessid' => $sessid,
            });
        $matrix->adopt_future($f);
        
        # we deliberately don't paginate the room, as we only care about
        # new calls
    },
    on_unknown_event => \&on_unknown_event,
    on_error => sub {
        print STDERR "Matrix failure: @_\n";
    },
);
$loop->add( $bot_matrix );

sub on_unknown_event
{
    my ($matrix, $event) = @_;
    print Dumper($event);
    
    my $room_id = $event->{room_id};
    my %dp = %{$CONFIG{'verto-dialog-params'}};
    $dp{callID} = $bridgestate->{$room_id}->{callid};
    
    if ($event->{type} eq 'm.call.invite') {
        $bridgestate->{$room_id}->{matrix_callid} = $event->{content}->{call_id};
        $bridgestate->{$room_id}->{callid} = lc new Data::UUID->create_str();
        $bridgestate->{$room_id}->{offer} = $event->{content}->{offer}->{sdp};
        $bridgestate->{$room_id}->{gathered_candidates} = 0;
        $roomid_by_callid->{ $bridgestate->{$room_id}->{callid} } = $room_id;
        # no trickle ICE in verto apparently
    }
    elsif ($event->{type} eq 'm.call.candidates') {
        # XXX: compare call IDs
        if (!$bridgestate->{$room_id}->{gathered_candidates}) {
            $bridgestate->{$room_id}->{gathered_candidates} = 1;
            my $offer = $bridgestate->{$room_id}->{offer};
            my $candidate_block = {
                audio => '',
                video => '',
            };
            foreach (@{$event->{content}->{candidates}}) {
                if ($_->{sdpMid}) {
                    $candidate_block->{$_->{sdpMid}} .= "a=" . $_->{candidate} . "\r\n";
                }
                else {
                    $candidate_block->{audio} .= "a=" . $_->{candidate} . "\r\n";
                    $candidate_block->{video} .= "a=" . $_->{candidate} . "\r\n";
                }
            }

            # XXX: assumes audio comes first
            #$offer =~ s/(a=rtcp-mux[\r\n]+)/$1$candidate_block->{audio}/;
            #$offer =~ s/(a=rtcp-mux[\r\n]+)/$1$candidate_block->{video}/;

            $offer =~ s/(m=video)/$candidate_block->{audio}$1/;
            $offer =~ s/(.$)/$1\n$candidate_block->{video}$1/;
            
            my $f = send_verto_json_request("verto.invite", {
                "sdp" => $offer,
                "dialogParams" => \%dp,
                "sessid" => $bridgestate->{$room_id}->{sessid},
            });
            $matrix->adopt_future($f);
        }
        else {
            # ignore them, as no trickle ICE, although we might as well
            # batch them up
            # foreach (@{$event->{content}->{candidates}}) {
            #     push @{$bridgestate->{$room_id}->{candidates}}, $_;
            # }
        }
    }
    elsif ($event->{type} eq 'm.call.hangup') {
        if ($bridgestate->{$room_id}->{matrix_callid} eq $event->{content}->{call_id}) {
            my $f = send_verto_json_request("verto.bye", {
                "dialogParams" => \%dp,
                "sessid" => $bridgestate->{$room_id}->{sessid},
            });
            $matrix->adopt_future($f);
        }
        else {
            warn "Ignoring unrecognised callid: ".$event->{content}->{call_id};
        }
    }
    else {
        warn "Unhandled event: $event->{type}";
    }
}

sub on_room_message
{
    my ($room, $from, $content) = @_;
    my $room_id = $room->room_id;
    warn "[Matrix] in $room_id: $from: " . $content->{body} . "\n";    
}

Future->needs_all(
    $bot_matrix->login( %{ $CONFIG{"matrix-bot"} } )->then( sub {
        $bot_matrix->start;
    }),
    
    $bot_verto->connect(
        %{ $CONFIG{"verto-bot"} },
        on_connect_error => sub { die "Cannot connect to verto - $_[-1]" },
        on_resolve_error => sub { die "Cannot resolve to verto - $_[-1]" },        
    )->on_done( sub { 
        warn("[Verto] connected to websocket");
    }),
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

# When the bot gets shut down, have it leave the rooms so it's clear to observers
# that it is no longer running.
# if( $CONFIG{"leave-on-shutdown"} // 1 ) {
#     print STDERR "Removing bot from Matrix rooms...\n";
#     Future->wait_all( map { $_->leave->else_done() } values %bot_matrix_rooms )->get;
# }
# else {
#     print STDERR "Leaving bot users in Matrix rooms.\n";
# }

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
                                
                my $room_id = $roomid_by_callid->{$json->{params}->{callID}};
                my $room = $bot_matrix_rooms{$room_id};

                if ($json->{params}->{sdp}) {
                    # HACK HACK HACK HACK
                    $room->_do_POST_json( "/send/m.call.answer", {
                        call_id => $bridgestate->{$room_id}->{matrix_callid},
                        version => 0,
                        answer  => {
                            sdp => $json->{params}->{sdp},
                            type => "answer",
                        },
                    })->then( sub {
                        send_verto_json_response( {
                            method => $json->{method},
                        }, $json->{id});
                    })->get;
                }
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

