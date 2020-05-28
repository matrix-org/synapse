#!/bin/bash

DOMAIN=yourserver.tld
# add this user as admin in your home server:
ADMIN="@you_admin_username:$DOMAIN"

API_URL="$DOMAIN:8008/_matrix/client/r0"

# choose a time before which the messages should be pruned:
# TIME='2016-08-31 23:59:59'
TIME='12 months ago'

# creates a timestamp from the given time string:
UNIX_TIMESTAMP=$(date +%s%3N --date='TZ="UTC+2" '"$TIME")


###################################################################################################
# database function
###################################################################################################
sql (){
  # for sqlite3:
  #sqlite3 homeserver.db "pragma busy_timeout=20000;$1" | awk '{print $2}'
  # for postgres:
  psql -A -t --dbname=synapse -c "$1" | grep -v 'Pager'
}

###############################################################################
# make the admin user a server admin in the database with
###############################################################################
# sql "UPDATE users SET admin=1 WHERE name LIKE '$ADMIN'"

###############################################################################
# get an access token
###############################################################################
# for example externally by watching Riot in your browser's network inspector
# or internally on the server locally, use this:
TOKEN=$(sql "SELECT token FROM access_tokens WHERE user_id='$ADMIN' ORDER BY id DESC LIMIT 1")

###############################################################################
# check, if your TOKEN works. For example this works: 
###############################################################################
# curl --header "Authorization: Bearer $TOKEN" "$API_URL/rooms/$ROOM/state/m.room.power_levels"

###############################################################################
# optional check size before
###############################################################################
# echo calculate used storage before ...
# du -shc ../.synapse/media_store/*

###############################################################################
# finally start pruning media:
###############################################################################
set -x # for debugging the generated string
curl --header "Authorization: Bearer $TOKEN" -X POST "$API_URL/admin/purge_media_cache/?before_ts=$UNIX_TIMESTAMP"
