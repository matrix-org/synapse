Purge Remote Media API
======================

The purge remote media API allows server admins to purge old cached remote
media.

The API is::

    POST /_matrix/client/r0/admin/purge_media_cache?before_ts=<unix_timestamp_in_ms>&access_token=<access_token>

    {}

Which will remove all cached media that was last accessed before
``<unix_timestamp_in_ms>``.

If the user re-requests purged remote media, synapse will re-request the media
from the originating server.

You can use this script, to prune a certain room up to a certain time::

    #!/bin/bash

    DOMAIN=yourserver.tld
    # add this user as admin in your home server:
    ADMIN="@username:$DOMAIN"
    
    # choose a time before which the messages should be pruned:
    # TIME='2016-08-31 23:59:59'
    TIME='3 months ago'
    
    # creates a timestamp from the given time string:
    UNIX_TIMESTAMP=$(date +%s%3N --date='TZ="UTC+2" '"$TIME")
    
    #for sqlite3:
    DB="sqlite3 homeserver.db"
    
    # for postgres:
    # DB="psql -A -t --dbname=synapse -c"
    
    #first make the admin user a server admin in the database with
    # $DB "UPDATE users SET admin=1 WHERE name like '$ADMIN'"
    
    #second, get an access token
    # for exaple externally by watching Riot in your browser's network inspector
    # or internally on the server locally, use this:
    TOKEN=$($DB "pragma busy_timeout=20000;select token from access_tokens where user_id like '$ADMIN' order by id desc limit 1;"|awk '{print $2}')
    # on postgres:
    # TOKEN=$($DB "select token from access_tokens where user_id='$ADMIN' order by id desc limit 1;" |grep -v "Pager")

    # check, if your TOKEN works. For example this works: 
    # $ curl '$DOMAIN:8008/_matrix/client/r0/rooms/'$ROOM'/state/m.room.power_levels?access_token='$TOKEN 
    
    #du -shc media_store/ # optionally check size before

    #finally start pruning:
    set -x # for debugging the generated string
    curl -v -X POST '$DOMAIN:8008/_matrix/client/r0/admin/purge_media_cache/?before_ts='$UNIX_TIMESTAMP'&access_token='$TOKEN
    
