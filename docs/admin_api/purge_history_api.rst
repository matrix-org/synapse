Purge History API
=================

The purge history API allows server admins to purge historic events from their
database, reclaiming disk space.

Depending on the amount of history being purged a call to the API may take
several minutes or longer. During this period users will not be able to
paginate further back in the room from the point being purged from.

The API is:

``POST /_matrix/client/r0/admin/purge_history/<room_id>[/<event_id>]?access_token=<admin_token>``

including an ``access_token`` of a server admin.

By default, events sent by local users are not deleted, as they may represent
the only copies of this content in existence. (Events sent by remote users are
deleted.)

Room state data (such as joins, leaves, topic) is always preserved.

To delete local message events as well, set ``delete_local_events`` in the body:

.. code:: json

   {
       "delete_local_events": true
   }

The caller must specify the point in the room to purge up to. This can be
specified by including an event_id in the URI, or by setting a
``purge_up_to_event_id`` or ``purge_up_to_ts`` in the request body. If an event
id is given, that event (and others at the same graph depth) will be retained.
If ``purge_up_to_ts`` is given, it should be a timestamp since the unix epoch,
in milliseconds.

The API starts the purge running, and returns immediately with a JSON body with
a purge id:

.. code:: json

    {
        "purge_id": "<opaque id>"
    }

Purge status query
------------------

It is possible to poll for updates on recent purges with a second API;

``GET /_matrix/client/r0/admin/purge_history_status/<purge_id>``

(again, with a suitable ``access_token``). This API returns a JSON body like
the following:

.. code:: json

    {
        "status": "active"
    }

The status will be one of ``active``, ``complete``, or ``failed``.


You can use this script, to prune a certain room up to a certain event::

    #!/bin/bash
    
    # this script will use the api:
    #    https://github.com/matrix-org/synapse/blob/master/docs/admin_api/purge_history_api.rst
    # 
    # It will purge all messages of a given room up to a cetrain event
    # that room_id and event_id you can get e.g. from your Riot clients "View Source" button
    
    DOMAIN=yourserver.tld
    # add this user as admin in your home server:
    ADMIN="@username:$DOMAIN"
    
    #choose the room to prune old messages from
    ROOM='!cURbafjkfsMDVwdRDQ:matrix.org' # for example: "Matrix HQ"
    
    # choose a time before which the messages should be pruned:
    # TIME='2016-08-31 23:59:59'
    TIME='3 months ago'
    
    # creates a timestamp from the given time string:
    UNIX_TIMESTAMP=$(date +%s%3N --date='TZ="UTC+2" '"$TIME")
    
    SQL_GET_EVENT="select event_id from events where type='m.room.message' and received_ts<'$UNIX_TIMESTAMP' and room_id='$ROOM' order by received_ts desc limit 1"
    
    #for sqlite3:
    DB="sqlite3 homeserver.db"
    BUSY="pragma busy_timeout=20000"
    BUFFER=$($DB "$BUSY;$SQL_GET_EVENT;")
    EVENT_ID=$(echo $BUFFER|awk '{print $2}')
    
    # for postgres:
    # DB="psql -A -t --dbname=synapse -c"
    # BUSY=""
    # EVENT_ID=$($DB "$SQL_GET_EVENT;"|grep -v 'Pager')
    
    if [ "$EVENT_ID" == "" ]; then
      echo "no event $TIME"
      exit
    fi
    
    # optionally instead select the id that should be kept (all older events are seleted)
    #EVENT_ID='$1471814088343495zpPNI:matrix.org' # an example event from 21st of Aug 2016 by Matthew
    
    #first make the admin user a server admin in the database with
    # $DB "UPDATE users SET admin=1 WHERE name like '$ADMIN'"
    
    #second, get an access token
    # for exaple externally by watching Riot in your browser's network inspector
    # or internally on the server locally, use this:
    TOKEN=$($DB "$BUSY;select token from access_tokens where user_id like '$ADMIN' order by id desc limit 1;"|awk '{print $2}')
    # on postgres:
    # TOKEN=$($DB "select token from access_tokens where user_id='$ADMIN' order by id desc limit 1;" |grep -v "Pager")
    
    # check, if your TOKEN works. For example this works: 
    # $ curl '$DOMAIN:8008/_matrix/client/r0/rooms/'$ROOM'/state/m.room.power_levels?access_token='$TOKEN 
    
    #finally start pruning the room:
    POSTDATA='{"delete_local_events":"true"}' # this will really delete local events, so the messages in the room really disappear unless they are restored by remote federation
    set -x # for debugging the generated string
    curl -d $POSTDATA -v -X POST '$DOMAIN:8008/_matrix/client/r0/admin/purge_history/'$ROOM'/'$EVENT_ID'?access_token='$TOKEN
    
    # to get benefit of pruning large amounts of data, you need to call VACUUM to free the unused space.
    # This can take a very long time (hours) and the client have to be stopped while you do so:
    # $ synctl stop
    # $ sqlite3 -line homeserver.db "vacuum;"
    # $ synctl start

    # This could be set, so you don't need to prune every time after deleting some rows:
    # $ sqlite3 homeserver.db "PRAGMA auto_vacuum = FULL;"
    # be cautious, it could make the database somewhat slow if there are a lot of deletions
    
    exit
