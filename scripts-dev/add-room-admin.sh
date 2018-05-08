#!/bin/bash
# A room created by the @appservice_irc user of the IRC-bridge has only that user as admin
# This script manipulates a matrix room, created by the @appservice_irc user by adding another administrator to it

### config settings ####################
SERVER="matrix.yourserver.org"
ROOM='!vOCcdPDdvueotEgTms:matrix.org'
ADMIN="new_admin_username"
TOKEN="8KnWIxCa17exampletokenD"
# find your as_token with
# grep as_token matrix-appservice-irc/appservice-registration-irc.yaml
#########################################

# get original settings
curl 'localhost:8008/_matrix/client/r0/rooms/'$ROOM'/state/m.room.power_levels?access_token='$TOKEN -o /tmp/matrix_room

# genarate output
echo
echo copy and paste this into bash:
echo
echo "curl -X PUT --header 'Content-Type: application/json' --header 'Accept: application/json' -d '"
sed '/@appservice_irc:'$SERVER'/a ,"@'$ADMIN':matrix.eclabs.de": 100' /tmp/matrix_room
echo "' '"localhost:8008/_matrix/client/r0/rooms/$ROOM/state/m.room.power_levels?access_token=$TOKEN"'"

exit
