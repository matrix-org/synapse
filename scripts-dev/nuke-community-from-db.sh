#!/bin/bash

## CAUTION:
## This script will remove (hopefully) all trace of the given Community ID from
## your homeserver.db

## Do not run it lightly.

set -e

if [ "$1" == "-h" ] || [ "$1" == "" ]; then
  echo "Call with group_id (Community ID e.g. +test:example.com) as first option and then pipe it into the database. So for instance you might run"
  echo " nuke-community-from-db.sh <group_id> | sqlite3 homeserver.db"
  echo "or"
  echo " nuke-community-from-db.sh <group_id> | psql --dbname=synapse"
  exit
fi

GROUPID="$1"

cat <<EOF
DELETE FROM group_users WHERE group_id = '$GROUPID';
DELETE FROM group_invites WHERE group_id = '$GROUPID';
DELETE FROM group_rooms WHERE group_id = '$GROUPID';
DELETE FROM group_summary_rooms WHERE group_id = '$GROUPID';
DELETE FROM group_summary_room_categories WHERE group_id = '$GROUPID';
DELETE FROM group_room_categories WHERE group_id = '$GROUPID';
DELETE FROM group_summary_users WHERE group_id = '$GROUPID';
DELETE FROM group_summary_roles WHERE group_id = '$GROUPID';
DELETE FROM group_roles WHERE group_id = '$GROUPID';
DELETE FROM group_attestations_renewals WHERE group_id = '$GROUPID';
DELETE FROM group_attestations_remote WHERE group_id = '$GROUPID';
DELETE FROM local_group_membership WHERE group_id = '$GROUPID';
DELETE FROM local_group_updates WHERE group_id = '$GROUPID';
DELETE FROM groups WHERE group_id = '$GROUPID';
VACUUM;
EOF
