# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from twisted.internet import defer

from sqlite3 import IntegrityError

from synapse.api.errors import StoreError

from ._base import SQLBaseStore, Table

import collections
import logging

logger = logging.getLogger(__name__)


OpsLevel = collections.namedtuple("OpsLevel", ("ban_level", "kick_level"))


class RoomStore(SQLBaseStore):

    @defer.inlineCallbacks
    def store_room(self, room_id, room_creator_user_id, is_public):
        """Stores a room.

        Args:
            room_id (str): The desired room ID, can be None.
            room_creator_user_id (str): The user ID of the room creator.
            is_public (bool): True to indicate that this room should appear in
            public room lists.
        Raises:
            StoreError if the room could not be stored.
        """
        try:
            yield self._simple_insert(RoomsTable.table_name, dict(
                room_id=room_id,
                creator=room_creator_user_id,
                is_public=is_public
            ))
        except IntegrityError:
            raise StoreError(409, "Room ID in use.")
        except Exception as e:
            logger.error("store_room with room_id=%s failed: %s", room_id, e)
            raise StoreError(500, "Problem creating room.")

    def store_room_config(self, room_id, visibility):
        return self._simple_update_one(
            table=RoomsTable.table_name,
            keyvalues={"room_id": room_id},
            updatevalues={"is_public": visibility}
        )

    def get_room(self, room_id):
        """Retrieve a room.

        Args:
            room_id (str): The ID of the room to retrieve.
        Returns:
            A namedtuple containing the room information, or an empty list.
        """
        query = RoomsTable.select_statement("room_id=?")
        return self._execute(
            RoomsTable.decode_single_result, query, room_id,
        )

    @defer.inlineCallbacks
    def get_rooms(self, is_public):
        """Retrieve a list of all public rooms.

        Args:
            is_public (bool): True if the rooms returned should be public.
        Returns:
            A list of room dicts containing at least a "room_id" key, a
            "topic" key if one is set, and a "name" key if one is set
        """

        topic_subquery = (
            "SELECT topics.event_id as event_id, "
            "topics.room_id as room_id, topic "
            "FROM topics "
            "INNER JOIN current_state_events as c "
            "ON c.event_id = topics.event_id "
        )

        name_subquery = (
            "SELECT room_names.event_id as event_id, "
            "room_names.room_id as room_id, name "
            "FROM room_names "
            "INNER JOIN current_state_events as c "
            "ON c.event_id = room_names.event_id "
        )

        # We use non printing ascii character US () as a seperator
        sql = (
            "SELECT r.room_id, n.name, t.topic, "
            "group_concat(a.room_alias, '') "
            "FROM rooms AS r "
            "LEFT JOIN (%(topic)s) AS t ON t.room_id = r.room_id "
            "LEFT JOIN (%(name)s) AS n ON n.room_id = r.room_id "
            "INNER JOIN room_aliases AS a ON a.room_id = r.room_id "
            "WHERE r.is_public = ? "
            "GROUP BY r.room_id "
        ) % {
            "topic": topic_subquery,
            "name": name_subquery,
        }

        rows = yield self._execute(None, sql, is_public)

        ret = [
            {
                "room_id": r[0],
                "name": r[1],
                "topic": r[2],
                "aliases": r[3].split(""),
            }
            for r in rows
        ]

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_room_join_rule(self, room_id):
        sql = (
            "SELECT join_rule FROM room_join_rules as r "
            "INNER JOIN current_state_events as c "
            "ON r.event_id = c.event_id "
            "WHERE c.room_id = ? "
        )

        rows = yield self._execute(None, sql, room_id)

        if len(rows) == 1:
            defer.returnValue(rows[0][0])
        else:
            defer.returnValue(None)

    def get_power_level(self, room_id, user_id):
        return self._db_pool.runInteraction(
            self._get_power_level,
            room_id, user_id,
        )

    def _get_power_level(self, txn, room_id, user_id):
        sql = (
            "SELECT level FROM room_power_levels as r "
            "INNER JOIN current_state_events as c "
            "ON r.event_id = c.event_id "
            "WHERE c.room_id = ? AND r.user_id = ? "
        )

        rows = txn.execute(sql, (room_id, user_id,)).fetchall()

        if len(rows) == 1:
            return rows[0][0]

        sql = (
            "SELECT level FROM room_default_levels as r "
            "INNER JOIN current_state_events as c "
            "ON r.event_id = c.event_id "
            "WHERE c.room_id = ? "
        )

        rows = txn.execute(sql, (room_id,)).fetchall()

        if len(rows) == 1:
            return rows[0][0]
        else:
            return None

    def get_ops_levels(self, room_id):
        return self._db_pool.runInteraction(
            self._get_ops_levels,
            room_id,
        )

    def _get_ops_levels(self, txn, room_id):
        sql = (
            "SELECT ban_level, kick_level FROM room_ops_levels as r "
            "INNER JOIN current_state_events as c "
            "ON r.event_id = c.event_id "
            "WHERE c.room_id = ? "
        )

        rows = txn.execute(sql, (room_id,)).fetchall()

        if len(rows) == 1:
            return OpsLevel(rows[0][0], rows[0][1])
        else:
            return OpsLevel(None, None)

    def get_add_state_level(self, room_id):
        return self._get_level_from_table("room_add_state_levels", room_id)

    def get_send_event_level(self, room_id):
        return self._get_level_from_table("room_send_event_levels", room_id)

    @defer.inlineCallbacks
    def _get_level_from_table(self, table, room_id):
        sql = (
            "SELECT level FROM %(table)s as r "
            "INNER JOIN current_state_events as c "
            "ON r.event_id = c.event_id "
            "WHERE c.room_id = ? "
        ) % {"table": table}

        rows = yield self._execute(None, sql, room_id)

        if len(rows) == 1:
            defer.returnValue(rows[0][0])
        else:
            defer.returnValue(None)

    def _store_room_topic_txn(self, txn, event):
        self._simple_insert_txn(
            txn,
            "topics",
            {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "topic": event.topic,
            }
        )

    def _store_room_name_txn(self, txn, event):
        self._simple_insert_txn(
            txn,
            "room_names",
            {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "name": event.name,
            }
        )

    def _store_join_rule(self, txn, event):
        self._simple_insert_txn(
            txn,
            "room_join_rules",
            {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "join_rule": event.content["join_rule"],
            },
        )

    def _store_power_levels(self, txn, event):
        for user_id, level in event.content.items():
            if user_id == "default":
                self._simple_insert_txn(
                    txn,
                    "room_default_levels",
                    {
                        "event_id": event.event_id,
                        "room_id": event.room_id,
                        "level": level,
                    },
                )
            else:
                self._simple_insert_txn(
                    txn,
                    "room_power_levels",
                    {
                        "event_id": event.event_id,
                        "room_id": event.room_id,
                        "user_id": user_id,
                        "level": level
                    },
                )

    def _store_default_level(self, txn, event):
        self._simple_insert_txn(
            txn,
            "room_default_levels",
            {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "level": event.content["default_level"],
            },
        )

    def _store_add_state_level(self, txn, event):
        self._simple_insert_txn(
            txn,
            "room_add_state_levels",
            {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "level": event.content["level"],
            },
        )

    def _store_send_event_level(self, txn, event):
        self._simple_insert_txn(
            txn,
            "room_send_event_levels",
            {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "level": event.content["level"],
            },
        )

    def _store_ops_level(self, txn, event):
        content = {
            "event_id": event.event_id,
            "room_id": event.room_id,
        }

        if "kick_level" in event.content:
            content["kick_level"] = event.content["kick_level"]

        if "ban_level" in event.content:
            content["ban_level"] = event.content["ban_level"]

        self._simple_insert_txn(
            txn,
            "room_ops_levels",
            content,
        )


class RoomsTable(Table):
    table_name = "rooms"

    fields = [
        "room_id",
        "is_public",
        "creator"
    ]

    EntryType = collections.namedtuple("RoomEntry", fields)
