#!/usr/bin/perl
#
# Write a summary of a TAP file in a format suitable for Github Actions output
#
# See: https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions

use strict;
use warnings FATAL => 'all';

use TAP::Parser;

my $RED = "\e[31m";
my $RESET_FG = "\e[39m";

my $tap_file = $ARGV[0];

my $parser = TAP::Parser->new( { source => $tap_file } );
my $in_error = 0;
my $expected_fail = 0;

while ( my $result = $parser->next ) {
   if ( $result->is_test ) {
      # conclude any previous error block
      if( $in_error ) {
         print "::endgroup::\n"
      }

      $in_error = 0;

      if ( not $result->is_ok ) {
         $in_error = 1;

         my $number = $result->number;
         my $description = $result->description;

         print "::error ::FAILURE:#$number: $description\n";
         print "::group::Logs\n"
      } elsif ( $result->directive and not $result->is_actual_ok ) {
         $expected_fail++;
      }
   } elsif ( $result->is_comment and $in_error == 1 ) {
      print $result->raw, "\n";
   }
}

if( $in_error ) {
   print "::endgroup::\n"
}

printf "Totals: %i passed, %i expected fail, %i failed\n", (
   # actual_passed includes unexpected passes (ie expected failures which accidentally passed)
   scalar $parser->actual_passed,
   $expected_fail,
   scalar $parser->failed,
);
