#!/usr/bin/env bash

# this script will use the api:
#    https://github.com/matrix-org/synapse/blob/master/docs/admin_api/purge_history_api.rst
# 
# It will purge all messages in a list of rooms up to a cetrain event

###################################################################################################
# define your domain and admin user
###################################################################################################
# add this user as admin in your home server:
DOMAIN=yourserver.tld
# add this user as admin in your home server:
ADMIN="@you_admin_username:$DOMAIN"

API_URL="$DOMAIN:8008/_matrix/client/r0"

###################################################################################################
#choose the rooms to prune old messages from (add a free comment at the end)
###################################################################################################
# the room_id's you can get e.g. from your Riot clients "View Source" button on each message
ROOMS_ARRAY=(
'!DgvjtOljKujDBrxyHk:matrix.org#riot:matrix.org'
'!QtykxKocfZaZOUrTwp:matrix.org#Matrix HQ'
)

# ALTERNATIVELY:
# you can select all the rooms that are not encrypted and loop over the result:
# SELECT room_id FROM rooms WHERE room_id NOT IN (SELECT DISTINCT room_id FROM events WHERE type ='m.room.encrypted')
# or
# select all rooms with at least 100 members:
# SELECT q.room_id FROM (select count(*) as numberofusers, room_id FROM current_state_events WHERE type ='m.room.member'
#   GROUP BY room_id) AS q LEFT JOIN room_aliases a ON q.room_id=a.room_id WHERE q.numberofusers > 100 ORDER BY numberofusers desc

###################################################################################################
# evaluate the EVENT_ID before which should be pruned
###################################################################################################
# choose a time before which the messages should be pruned:
TIME='12 months ago'
# ALTERNATIVELY:
# a certain time:
# TIME='2016-08-31 23:59:59'

# creates a timestamp from the given time string:
UNIX_TIMESTAMP=$(date +%s%3N --date='TZ="UTC+2" '"$TIME")

# ALTERNATIVELY:
# prune all messages that are older than 1000 messages ago:
# LAST_MESSAGES=1000
# SQL_GET_EVENT="SELECT event_id from events WHERE type='m.room.message' AND room_id ='$ROOM' ORDER BY received_ts DESC LIMIT 1 offset $(($LAST_MESSAGES - 1))"

# ALTERNATIVELY:
# select the EVENT_ID manually:
#EVENT_ID='$1471814088343495zpPNI:matrix.org' # an example event from 21st of Aug 2016 by Matthew

###################################################################################################
# make the admin user a server admin in the database with
###################################################################################################
# psql -A -t --dbname=synapse -c "UPDATE users SET admin=1 WHERE name LIKE '$ADMIN'"

###################################################################################################
# database function
###################################################################################################
sql (){
  # for sqlite3:
  #sqlite3 homeserver.db "pragma busy_timeout=20000;$1" | awk '{print $2}'
  # for postgres:
  psql -A -t --dbname=synapse -c "$1" | grep -v 'Pager'
}

###################################################################################################
# get an access token
###################################################################################################
# for example externally by watching Riot in your browser's network inspector
# or internally on the server locally, use this:
TOKEN=$(sql "SELECT token FROM access_tokens WHERE user_id='$ADMIN' ORDER BY id DESC LIMIT 1")
AUTH="Authorization: Bearer $TOKEN"

###################################################################################################
# check, if your TOKEN works. For example this works: 
###################################################################################################
# $ curl --header "$AUTH" "$API_URL/rooms/$ROOM/state/m.room.power_levels" 

###################################################################################################
# finally start pruning the room:
###################################################################################################
POSTDATA='{"delete_local_events":"true"}' # this will really delete local events, so the messages in the room really disappear unless they are restored by remote federation

for ROOM in "${ROOMS_ARRAY[@]}"; do
    echo "########################################### $(date) ################# "
    echo "pruning room: $ROOM ..."
    ROOM=${ROOM%#*}
    #set -x
    echo "check for alias in db..."
    # for postgres:
    sql "SELECT * FROM room_aliases WHERE room_id='$ROOM'"
    echo "get event..."
    # for postgres:
    EVENT_ID=$(sql "SELECT event_id FROM events WHERE type='m.room.message' AND received_ts<'$UNIX_TIMESTAMP' AND room_id='$ROOM' ORDER BY received_ts DESC LIMIT 1;")
    if [ "$EVENT_ID" == "" ]; then
      echo "no event $TIME"
    else
      echo "event: $EVENT_ID"
      SLEEP=2
      set -x
      # call purge
      OUT=$(curl --header "$AUTH" -s -d $POSTDATA POST "$API_URL/admin/purge_history/$ROOM/$EVENT_ID")
      PURGE_ID=$(echo "$OUT" |grep purge_id|cut -d'"' -f4 )
      if [ "$PURGE_ID" == "" ]; then
        # probably the history purge is already in progress for $ROOM
        : "continuing with next room"
      else
        while : ; do
          # get status of purge and sleep longer each time if still active
          sleep $SLEEP
          STATUS=$(curl --header "$AUTH" -s GET "$API_URL/admin/purge_history_status/$PURGE_ID" |grep status|cut -d'"' -f4)
          : "$ROOM --> Status: $STATUS"
          [[ "$STATUS" == "active" ]] || break 
          SLEEP=$((SLEEP + 1))
        done 
      fi
      set +x
      sleep 1
    fi  
done


###################################################################################################
# additionally
###################################################################################################
# to benefit from pruning large amounts of data, you need to call VACUUM to free the unused space.
# This can take a very long time (hours) and the client have to be stopped while you do so:
# $ synctl stop
# $ sqlite3 -line homeserver.db "vacuum;"
# $ synctl start

# This could be set, so you don't need to prune every time after deleting some rows:
# $ sqlite3 homeserver.db "PRAGMA auto_vacuum = FULL;"
# be cautious, it could make the database somewhat slow if there are a lot of deletions

exit
