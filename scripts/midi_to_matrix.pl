#!/opt/local/bin/perl

use strict;
use warnings;

use Data::Dumper;
use IO::Async::Loop;
use Net::Async::Matrix;
use Net::Pcap;
use Data::HexDump;
use JSON;
use Music::Chord::Namer qw/chordname/;
  
$| = 1;

our $notes = {};
our $notenames = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B'];

our $room;

my $loop = IO::Async::Loop->new;
my $matrix = Net::Async::Matrix->new(
    server => "echo-matrix:8008",
    on_log => sub { warn "log: @_\n" },
    on_room_new => sub {
      my ($matrix, $new_room) = @_;
      warn "[Matrix] have a room ID: " . $new_room->room_id . "\n";
      $room = $new_room if ($new_room->room_id eq '!GaUcuyvZyXfoqmQTNR:echo-matrix');
    },
    on_error => sub {
      print STDERR "Matrix failure: @_\n";
    },
);

$loop->add( $matrix );
$matrix->login(
    # XXX: password is broke
    user_id      => 'matthew',
    access_token => 'QG1hdHRoZXc6ZWNoby1tYXRyaXg..ZVZbCQuOmnhwakNnOt',
)->get;

$matrix->join_room( '#midi:echo-matrix' )->get;
# ->on_done(sub {
#     print Dumper([@_]);
#     ($room) = @_;
#     warn "joined $room";
# } )->get;

$matrix->start();

my $err = '';
my $dev = "en1";

my $pcap = pcap_open_live($dev, 1024, 0, 100, \$err);
die $err if $err;

my ($net, $mask);
pcap_lookupnet($dev, \$net, \$mask, \$err);
die $err if $err;

my $filter_str = "src host 10.12.76.65 and udp and port 5005";
my $filter;
if (pcap_compile($pcap, \$filter, $filter_str, 1, $net) == -1) {
    die "Unable to compile filter string '$filter_str'\n";
}

pcap_setfilter($pcap, $filter);

while (1) {
    pcap_dispatch($pcap, -1, \&process_packet, "");
    #print ".\n";
}

pcap_close($pcap);

sub handle_event {
    my ($event) = @_;
    print to_json($event, { pretty => 1 });
    
    if ($event->{state} eq 'on') {
        $notes->{$event->{note}} = 1;
    }
    else {
        delete $notes->{$event->{note}};
    }
    
    if (scalar keys %$notes >= 3) {
        my $chord = (chordname(map { $notenames->[$_ % 12] } sort keys %$notes))[0];
        print "$chord\n";
        $room->send_message( $chord )->get;
    }
    
    # HACK HACK HACK HACK
    $room->_do_POST_json( "/send/org.matrix.midi", $event )->get;
}

sub process_packet {
    my ($user_data, $header, $packet) = @_;
    my ($ether, $ip, $udp, $rtp_byte, $payload, $seqnum, $ts, $ssrc, @midi)
        = unpack("a14a20a8CCSNNC*", $packet);
    
    return if ($rtp_byte == 0xff);
    #print HexDump $packet;
    
    my $midilen;
    if ($midi[0] & 0x80) { # long header
        $midilen = (($midi[0] & 0x0f) << 8) | $midi[1];
        shift @midi;
        shift @midi;
    }
    else { # short header
        $midilen = ($midi[0] & 0x0f);
        shift @midi;
    }

    my $midiparsed = 0;
    my $state = ($midi[0] >> 4 == 0x9 ? "on" : "off");
    my $channel = ($midi[0] & 0x0f) + 1;
    shift (@midi); $midiparsed++;
    
    while ($midiparsed < $midilen) {
        my ($event) = {
            midi_ts => $ts,
            note => $midi[0],
            channel => $channel,
            state => ($midi[1] == 0 ? "off" : $state),
            velocity => $midi[1],
        };
        handle_event($event);
        shift (@midi); $midiparsed++;
        shift (@midi); $midiparsed++;
        if (scalar @midi) {
            $ts += shift @midi; $midiparsed++;
        }
    }
}
