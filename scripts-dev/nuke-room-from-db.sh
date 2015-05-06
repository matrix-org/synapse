#!/bin/bash

## CAUTION:
## This script will remove (hopefully) all trace of the given room ID from
## your homeserver.db

## Do not run it lightly.

ROOMID="$1"

sqlite3 homeserver.db <<EOF
DELETE FROM context_depth WHERE context = '$ROOMID';
DELETE FROM current_state WHERE context = '$ROOMID';
DELETE FROM feedback WHERE room_id = '$ROOMID';
DELETE FROM messages WHERE room_id = '$ROOMID';
DELETE FROM pdu_backward_extremities WHERE context = '$ROOMID';
DELETE FROM pdu_edges WHERE context = '$ROOMID';
DELETE FROM pdu_forward_extremities WHERE context = '$ROOMID';
DELETE FROM pdus WHERE context = '$ROOMID';
DELETE FROM room_data WHERE room_id = '$ROOMID';
DELETE FROM room_memberships WHERE room_id = '$ROOMID';
DELETE FROM rooms WHERE room_id = '$ROOMID';
DELETE FROM state_pdus WHERE context = '$ROOMID';
EOF
