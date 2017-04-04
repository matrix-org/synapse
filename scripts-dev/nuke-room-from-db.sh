#!/bin/bash

## CAUTION:
## This script will remove (hopefully) all trace of the given room ID from
## your homeserver.db

## Do not run it lightly.

ROOMID="$1"

sqlite3 homeserver.db <<EOF
DELETE FROM event_forward_extremities WHERE room_id = '$ROOMID';
DELETE FROM event_backward_extremities WHERE room_id = '$ROOMID';
DELETE FROM event_edges WHERE room_id = '$ROOMID';
DELETE FROM room_depth WHERE room_id = '$ROOMID';
DELETE FROM state_forward_extremities WHERE room_id = '$ROOMID';
DELETE FROM events WHERE room_id = '$ROOMID';
DELETE FROM event_json WHERE room_id = '$ROOMID';
DELETE FROM state_events WHERE room_id = '$ROOMID';
DELETE FROM current_state_events WHERE room_id = '$ROOMID';
DELETE FROM room_memberships WHERE room_id = '$ROOMID';
DELETE FROM feedback WHERE room_id = '$ROOMID';
DELETE FROM topics WHERE room_id = '$ROOMID';
DELETE FROM room_names WHERE room_id = '$ROOMID';
DELETE FROM rooms WHERE room_id = '$ROOMID';
DELETE FROM room_hosts WHERE room_id = '$ROOMID';
DELETE FROM room_aliases WHERE room_id = '$ROOMID';
DELETE FROM state_groups WHERE room_id = '$ROOMID';
DELETE FROM state_groups_state WHERE room_id = '$ROOMID';
DELETE FROM receipts_graph WHERE room_id = '$ROOMID';
DELETE FROM receipts_linearized WHERE room_id = '$ROOMID';
DELETE FROM event_search_content WHERE c1room_id = '$ROOMID';
DELETE FROM guest_access WHERE room_id = '$ROOMID';
DELETE FROM history_visibility WHERE room_id = '$ROOMID';
DELETE FROM room_tags WHERE room_id = '$ROOMID';
DELETE FROM room_tags_revisions WHERE room_id = '$ROOMID';
DELETE FROM room_account_data WHERE room_id = '$ROOMID';
DELETE FROM event_push_actions WHERE room_id = '$ROOMID';
DELETE FROM local_invites WHERE room_id = '$ROOMID';
DELETE FROM pusher_throttle WHERE room_id = '$ROOMID';
DELETE FROM event_reports WHERE room_id = '$ROOMID';
DELETE FROM public_room_list_stream WHERE room_id = '$ROOMID';
DELETE FROM stream_ordering_to_exterm WHERE room_id = '$ROOMID';
DELETE FROM event_auth WHERE room_id = '$ROOMID';
DELETE FROM appservice_room_list WHERE room_id = '$ROOMID';
VACUUM;
EOF
