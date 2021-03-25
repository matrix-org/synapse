# -*- coding: utf-8 -*-
# Copyright 2020 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# We create a new table called `local_current_membership` that stores the latest
# membership state of local users in rooms, which helps track leaves/bans/etc
# even if the server has left the room (and so has deleted the room from
# `current_state_events`). This will also include outstanding invites for local
# users for rooms the server isn't in.
#
# If the server isn't and hasn't been in the room then it will only include
# outsstanding invites, and not e.g. pre-emptive bans of local users.
#
# If the server later rejoins a room `local_current_membership` can simply be
# replaced with the new current state of the room (which results in the
# equivalent behaviour as if the server had remained in the room).


def run_upgrade(cur, database_engine, config, *args, **kwargs):
    # We need to do the insert in `run_upgrade` section as we don't have access
    # to `config` in `run_create`.

    # This upgrade may take a bit of time for large servers (e.g. one minute for
    # matrix.org) but means we avoid a lots of book keeping required to do it as
    # a background update.

    # We check if the `current_state_events.membership` is up to date by
    # checking if the relevant background update has finished. If it has
    # finished we can avoid doing a join against `room_memberships`, which
    # speesd things up.
    cur.execute(
        """SELECT 1 FROM background_updates
            WHERE update_name = 'current_state_events_membership'
        """
    )
    current_state_membership_up_to_date = not bool(cur.fetchone())

    # Cheekily drop and recreate indices, as that is faster.
    cur.execute("DROP INDEX local_current_membership_idx")
    cur.execute("DROP INDEX local_current_membership_room_idx")

    if current_state_membership_up_to_date:
        sql = """
            INSERT INTO local_current_membership (room_id, user_id, event_id, membership)
                SELECT c.room_id, state_key AS user_id, event_id, c.membership
                FROM current_state_events AS c
                WHERE type = 'm.room.member' AND c.membership IS NOT NULL AND state_key LIKE ?
        """
    else:
        # We can't rely on the membership column, so we need to join against
        # `room_memberships`.
        sql = """
            INSERT INTO local_current_membership (room_id, user_id, event_id, membership)
                SELECT c.room_id, state_key AS user_id, event_id, r.membership
                FROM current_state_events AS c
                INNER JOIN room_memberships AS r USING (event_id)
                WHERE type = 'm.room.member' AND state_key LIKE ?
        """
    cur.execute(sql, ("%:" + config.server_name,))

    cur.execute(
        "CREATE UNIQUE INDEX local_current_membership_idx ON local_current_membership(user_id, room_id)"
    )
    cur.execute(
        "CREATE INDEX local_current_membership_room_idx ON local_current_membership(room_id)"
    )


def run_create(cur, database_engine, *args, **kwargs):
    cur.execute(
        """
        CREATE TABLE local_current_membership (
            room_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            membership TEXT NOT NULL
        )"""
    )

    cur.execute(
        "CREATE UNIQUE INDEX local_current_membership_idx ON local_current_membership(user_id, room_id)"
    )
    cur.execute(
        "CREATE INDEX local_current_membership_room_idx ON local_current_membership(room_id)"
    )
