#!/bin/bash

## CAUTION:
## This script will remove (hopefully) all trace of the given room ID from
## your homeserver.db

## Do not run it lightly.

set -e

if [ "$1" == "-h" ] || [ "$1" == "" ]; then
  echo "Call with ROOM_ID as first option and then pipe it into the database. So for instance you might run"
  echo " nuke-room-from-db.sh <room_id> | sqlite3 homeserver.db"
  echo "or"
  echo " nuke-room-from-db.sh <room_id> | psql --dbname=synapse"
  exit
fi

ROOMID="$1"

cat <<EOF
SELECT 'deleting entries ...' as event_forward_extremities;
DELETE FROM event_forward_extremities WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as event_backward_extremities;
DELETE FROM event_backward_extremities WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as event_edges;
DELETE FROM event_edges WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_depth;
DELETE FROM room_depth WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as state_forward_extremities;
DELETE FROM state_forward_extremities WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as events;
DELETE FROM events WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as event_json;
DELETE FROM event_json WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as state_events;
DELETE FROM state_events WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as current_state_events;
DELETE FROM current_state_events WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_memberships;
DELETE FROM room_memberships WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as feedback;
DELETE FROM feedback WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as topics;
DELETE FROM topics WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_names;
DELETE FROM room_names WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as rooms;
DELETE FROM rooms WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_hosts;
DELETE FROM room_hosts WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_aliases;
DELETE FROM room_aliases WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as state_groups;
DELETE FROM state_groups WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as state_groups_state;
DELETE FROM state_groups_state WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as receipts_graph;
DELETE FROM receipts_graph WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as receipts_linearized;
DELETE FROM receipts_linearized WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as event_search;
DELETE FROM event_search WHERE room_id = '$ROOMID'; 
SELECT 'deleting entries ...' as guest_access;
DELETE FROM guest_access WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as history_visibility;
DELETE FROM history_visibility WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_tags;
DELETE FROM room_tags WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_tags_revisions;
DELETE FROM room_tags_revisions WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as room_account_data;
DELETE FROM room_account_data WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as event_push_actions;
DELETE FROM event_push_actions WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as local_invites;
DELETE FROM local_invites WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as pusher_throttle;
DELETE FROM pusher_throttle WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as event_reports;
DELETE FROM event_reports WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as public_room_list_stream;
DELETE FROM public_room_list_stream WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as stream_ordering_to_exterm;
DELETE FROM stream_ordering_to_exterm WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as event_auth;
DELETE FROM event_auth WHERE room_id = '$ROOMID';
SELECT 'deleting entries ...' as appservice_room_list;
DELETE FROM appservice_room_list WHERE room_id = '$ROOMID';
SELECT 'calling vacuum ...' as vacuum;
VACUUM;
EOF
