# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from synapse.api.errors import StoreError
from synapse.util.caches.descriptors import cached

from ._base import SQLBaseStore
from .engines import PostgresEngine, Sqlite3Engine

import collections
import logging
import ujson as json

logger = logging.getLogger(__name__)


OpsLevel = collections.namedtuple(
    "OpsLevel",
    ("ban_level", "kick_level", "redact_level",)
)


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
            def store_room_txn(txn, next_id):
                self._simple_insert_txn(
                    txn,
                    "rooms",
                    {
                        "room_id": room_id,
                        "creator": room_creator_user_id,
                        "is_public": is_public,
                    },
                )
                if is_public:
                    self._simple_insert_txn(
                        txn,
                        table="public_room_list_stream",
                        values={
                            "stream_id": next_id,
                            "room_id": room_id,
                            "visibility": is_public,
                        }
                    )
            with self._public_room_id_gen.get_next() as next_id:
                yield self.runInteraction(
                    "store_room_txn",
                    store_room_txn, next_id,
                )
        except Exception as e:
            logger.error("store_room with room_id=%s failed: %s", room_id, e)
            raise StoreError(500, "Problem creating room.")

    def get_room(self, room_id):
        """Retrieve a room.

        Args:
            room_id (str): The ID of the room to retrieve.
        Returns:
            A namedtuple containing the room information, or an empty list.
        """
        return self._simple_select_one(
            table="rooms",
            keyvalues={"room_id": room_id},
            retcols=("room_id", "is_public", "creator"),
            desc="get_room",
            allow_none=True,
        )

    @defer.inlineCallbacks
    def set_room_is_public(self, room_id, is_public):
        def set_room_is_public_txn(txn, next_id):
            self._simple_update_one_txn(
                txn,
                table="rooms",
                keyvalues={"room_id": room_id},
                updatevalues={"is_public": is_public},
            )

            entries = self._simple_select_list_txn(
                txn,
                table="public_room_list_stream",
                keyvalues={
                    "room_id": room_id,
                    "appservice_id": None,
                    "network_id": None,
                },
                retcols=("stream_id", "visibility"),
            )

            entries.sort(key=lambda r: r["stream_id"])

            add_to_stream = True
            if entries:
                add_to_stream = bool(entries[-1]["visibility"]) != is_public

            if add_to_stream:
                self._simple_insert_txn(
                    txn,
                    table="public_room_list_stream",
                    values={
                        "stream_id": next_id,
                        "room_id": room_id,
                        "visibility": is_public,
                        "appservice_id": None,
                        "network_id": None,
                    }
                )

        with self._public_room_id_gen.get_next() as next_id:
            yield self.runInteraction(
                "set_room_is_public",
                set_room_is_public_txn, next_id,
            )
        self.hs.get_notifier().on_new_replication_data()

    @defer.inlineCallbacks
    def set_room_is_public_appservice(self, room_id, appservice_id, network_id,
                                      is_public):
        """Edit the appservice/network specific public room list.

        Each appservice can have a number of published room lists associated
        with them, keyed off of an appservice defined `network_id`, which
        basically represents a single instance of a bridge to a third party
        network.

        Args:
            room_id (str)
            appservice_id (str)
            network_id (str)
            is_public (bool): Whether to publish or unpublish the room from the
                list.
        """
        def set_room_is_public_appservice_txn(txn, next_id):
            if is_public:
                try:
                    self._simple_insert_txn(
                        txn,
                        table="appservice_room_list",
                        values={
                            "appservice_id": appservice_id,
                            "network_id": network_id,
                            "room_id": room_id
                        },
                    )
                except self.database_engine.module.IntegrityError:
                    # We've already inserted, nothing to do.
                    return
            else:
                self._simple_delete_txn(
                    txn,
                    table="appservice_room_list",
                    keyvalues={
                        "appservice_id": appservice_id,
                        "network_id": network_id,
                        "room_id": room_id
                    },
                )

            entries = self._simple_select_list_txn(
                txn,
                table="public_room_list_stream",
                keyvalues={
                    "room_id": room_id,
                    "appservice_id": appservice_id,
                    "network_id": network_id,
                },
                retcols=("stream_id", "visibility"),
            )

            entries.sort(key=lambda r: r["stream_id"])

            add_to_stream = True
            if entries:
                add_to_stream = bool(entries[-1]["visibility"]) != is_public

            if add_to_stream:
                self._simple_insert_txn(
                    txn,
                    table="public_room_list_stream",
                    values={
                        "stream_id": next_id,
                        "room_id": room_id,
                        "visibility": is_public,
                        "appservice_id": appservice_id,
                        "network_id": network_id,
                    }
                )

        with self._public_room_id_gen.get_next() as next_id:
            yield self.runInteraction(
                "set_room_is_public_appservice",
                set_room_is_public_appservice_txn, next_id,
            )
        self.hs.get_notifier().on_new_replication_data()

    def get_public_room_ids(self):
        return self._simple_select_onecol(
            table="rooms",
            keyvalues={
                "is_public": True,
            },
            retcol="room_id",
            desc="get_public_room_ids",
        )

    def get_room_count(self):
        """Retrieve a list of all rooms
        """

        def f(txn):
            sql = "SELECT count(*)  FROM rooms"
            txn.execute(sql)
            row = txn.fetchone()
            return row[0] or 0

        return self.runInteraction(
            "get_rooms", f
        )

    def _store_room_topic_txn(self, txn, event):
        if hasattr(event, "content") and "topic" in event.content:
            self._simple_insert_txn(
                txn,
                "topics",
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "topic": event.content["topic"],
                },
            )

            self._store_event_search_txn(
                txn, event, "content.topic", event.content["topic"]
            )

    def _store_room_name_txn(self, txn, event):
        if hasattr(event, "content") and "name" in event.content:
            self._simple_insert_txn(
                txn,
                "room_names",
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "name": event.content["name"],
                }
            )

            self._store_event_search_txn(
                txn, event, "content.name", event.content["name"]
            )

    def _store_room_message_txn(self, txn, event):
        if hasattr(event, "content") and "body" in event.content:
            self._store_event_search_txn(
                txn, event, "content.body", event.content["body"]
            )

    def _store_history_visibility_txn(self, txn, event):
        self._store_content_index_txn(txn, event, "history_visibility")

    def _store_guest_access_txn(self, txn, event):
        self._store_content_index_txn(txn, event, "guest_access")

    def _store_content_index_txn(self, txn, event, key):
        if hasattr(event, "content") and key in event.content:
            sql = (
                "INSERT INTO %(key)s"
                " (event_id, room_id, %(key)s)"
                " VALUES (?, ?, ?)" % {"key": key}
            )
            txn.execute(sql, (
                event.event_id,
                event.room_id,
                event.content[key]
            ))

    def _store_event_search_txn(self, txn, event, key, value):
        if isinstance(self.database_engine, PostgresEngine):
            sql = (
                "INSERT INTO event_search"
                " (event_id, room_id, key, vector, stream_ordering, origin_server_ts)"
                " VALUES (?,?,?,to_tsvector('english', ?),?,?)"
            )
            txn.execute(
                sql,
                (
                    event.event_id, event.room_id, key, value,
                    event.internal_metadata.stream_ordering,
                    event.origin_server_ts,
                )
            )
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql = (
                "INSERT INTO event_search (event_id, room_id, key, value)"
                " VALUES (?,?,?,?)"
            )
            txn.execute(sql, (event.event_id, event.room_id, key, value,))
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

    def add_event_report(self, room_id, event_id, user_id, reason, content,
                         received_ts):
        next_id = self._event_reports_id_gen.get_next()
        return self._simple_insert(
            table="event_reports",
            values={
                "id": next_id,
                "received_ts": received_ts,
                "room_id": room_id,
                "event_id": event_id,
                "user_id": user_id,
                "reason": reason,
                "content": json.dumps(content),
            },
            desc="add_event_report"
        )

    def get_current_public_room_stream_id(self):
        return self._public_room_id_gen.get_current_token()

    @cached(num_args=2, max_entries=100)
    def get_public_room_ids_at_stream_id(self, stream_id, network_tuple):
        """Get pulbic rooms for a particular list, or across all lists.

        Args:
            stream_id (int)
            network_tuple (ThirdPartyInstanceID): The list to use (None, None)
                means the main list, None means all lsits.
        """
        return self.runInteraction(
            "get_public_room_ids_at_stream_id",
            self.get_public_room_ids_at_stream_id_txn,
            stream_id, network_tuple=network_tuple
        )

    def get_public_room_ids_at_stream_id_txn(self, txn, stream_id,
                                             network_tuple):
        return {
            rm
            for rm, vis in self.get_published_at_stream_id_txn(
                txn, stream_id, network_tuple=network_tuple
            ).items()
            if vis
        }

    def get_published_at_stream_id_txn(self, txn, stream_id, network_tuple):
        if network_tuple:
            # We want to get from a particular list. No aggregation required.

            sql = ("""
                SELECT room_id, visibility FROM public_room_list_stream
                INNER JOIN (
                    SELECT room_id, max(stream_id) AS stream_id
                    FROM public_room_list_stream
                    WHERE stream_id <= ? %s
                    GROUP BY room_id
                ) grouped USING (room_id, stream_id)
            """)

            if network_tuple.appservice_id is not None:
                txn.execute(
                    sql % ("AND appservice_id = ? AND network_id = ?",),
                    (stream_id, network_tuple.appservice_id, network_tuple.network_id,)
                )
            else:
                txn.execute(
                    sql % ("AND appservice_id IS NULL",),
                    (stream_id,)
                )
            return dict(txn.fetchall())
        else:
            # We want to get from all lists, so we need to aggregate the results

            logger.info("Executing full list")

            sql = ("""
                SELECT room_id, visibility
                FROM public_room_list_stream
                INNER JOIN (
                    SELECT
                        room_id, max(stream_id) AS stream_id, appservice_id,
                        network_id
                    FROM public_room_list_stream
                    WHERE stream_id <= ?
                    GROUP BY room_id, appservice_id, network_id
                ) grouped USING (room_id, stream_id)
            """)

            txn.execute(
                sql,
                (stream_id,)
            )

            results = {}
            # A room is visible if its visible on any list.
            for room_id, visibility in txn.fetchall():
                results[room_id] = bool(visibility) or results.get(room_id, False)

            return results

    def get_public_room_changes(self, prev_stream_id, new_stream_id,
                                network_tuple):
        def get_public_room_changes_txn(txn):
            then_rooms = self.get_public_room_ids_at_stream_id_txn(
                txn, prev_stream_id, network_tuple
            )

            now_rooms_dict = self.get_published_at_stream_id_txn(
                txn, new_stream_id, network_tuple
            )

            now_rooms_visible = set(
                rm for rm, vis in now_rooms_dict.items() if vis
            )
            now_rooms_not_visible = set(
                rm for rm, vis in now_rooms_dict.items() if not vis
            )

            newly_visible = now_rooms_visible - then_rooms
            newly_unpublished = now_rooms_not_visible & then_rooms

            return newly_visible, newly_unpublished

        return self.runInteraction(
            "get_public_room_changes", get_public_room_changes_txn
        )

    def get_all_new_public_rooms(self, prev_id, current_id, limit):
        def get_all_new_public_rooms(txn):
            sql = ("""
                SELECT stream_id, room_id, visibility, appservice_id, network_id
                FROM public_room_list_stream
                WHERE stream_id > ? AND stream_id <= ?
                ORDER BY stream_id ASC
                LIMIT ?
            """)

            txn.execute(sql, (prev_id, current_id, limit,))
            return txn.fetchall()

        if prev_id == current_id:
            return defer.succeed([])

        return self.runInteraction(
            "get_all_new_public_rooms", get_all_new_public_rooms
        )
