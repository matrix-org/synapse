# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import collections
import logging
import re
from typing import Optional, Tuple

from six import integer_types

from canonicaljson import json

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.data_stores.main.search import SearchStore
from synapse.types import ThirdPartyInstanceID
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks

logger = logging.getLogger(__name__)


OpsLevel = collections.namedtuple(
    "OpsLevel", ("ban_level", "kick_level", "redact_level")
)

RatelimitOverride = collections.namedtuple(
    "RatelimitOverride", ("messages_per_second", "burst_count")
)


class RoomWorkerStore(SQLBaseStore):
    def get_room(self, room_id):
        """Retrieve a room.

        Args:
            room_id (str): The ID of the room to retrieve.
        Returns:
            A dict containing the room information, or None if the room is unknown.
        """
        return self._simple_select_one(
            table="rooms",
            keyvalues={"room_id": room_id},
            retcols=("room_id", "is_public", "creator"),
            desc="get_room",
            allow_none=True,
        )

    def get_public_room_ids(self):
        return self._simple_select_onecol(
            table="rooms",
            keyvalues={"is_public": True},
            retcol="room_id",
            desc="get_public_room_ids",
        )

    def count_public_rooms(self, network_tuple, ignore_non_federatable):
        """Counts the number of public rooms as tracked in the room_stats_current
        and room_stats_state table.

        Args:
            network_tuple (ThirdPartyInstanceID|None)
            ignore_non_federatable (bool): If true filters out non-federatable rooms
        """

        def _count_public_rooms_txn(txn):
            query_args = []

            if network_tuple:
                if network_tuple.appservice_id:
                    published_sql = """
                        SELECT room_id from appservice_room_list
                        WHERE appservice_id = ? AND network_id = ?
                    """
                    query_args.append(network_tuple.appservice_id)
                    query_args.append(network_tuple.network_id)
                else:
                    published_sql = """
                        SELECT room_id FROM rooms WHERE is_public
                    """
            else:
                published_sql = """
                    SELECT room_id FROM rooms WHERE is_public
                    UNION SELECT room_id from appservice_room_list
            """

            sql = """
                SELECT
                    COALESCE(COUNT(*), 0)
                FROM (
                    %(published_sql)s
                ) published
                INNER JOIN room_stats_state USING (room_id)
                INNER JOIN room_stats_current USING (room_id)
                WHERE
                    (
                        join_rules = 'public' OR history_visibility = 'world_readable'
                    )
                    AND joined_members > 0
            """ % {
                "published_sql": published_sql
            }

            txn.execute(sql, query_args)
            return txn.fetchone()[0]

        return self.runInteraction("count_public_rooms", _count_public_rooms_txn)

    @defer.inlineCallbacks
    def get_largest_public_rooms(
        self,
        network_tuple: Optional[ThirdPartyInstanceID],
        search_filter: Optional[dict],
        limit: Optional[int],
        bounds: Optional[Tuple[int, str]],
        forwards: bool,
        ignore_non_federatable: bool = False,
    ):
        """Gets the largest public rooms (where largest is in terms of joined
        members, as tracked in the statistics table).

        Args:
            network_tuple
            search_filter
            limit: Maxmimum number of rows to return, unlimited otherwise.
            bounds: An uppoer or lower bound to apply to result set if given,
                consists of a joined member count and room_id (these are
                excluded from result set).
            forwards: true iff going forwards, going backwards otherwise
            ignore_non_federatable: If true filters out non-federatable rooms.

        Returns:
            Rooms in order: biggest number of joined users first.
            We then arbitrarily use the room_id as a tie breaker.

        """

        where_clauses = []
        query_args = []

        if network_tuple:
            if network_tuple.appservice_id:
                published_sql = """
                    SELECT room_id from appservice_room_list
                    WHERE appservice_id = ? AND network_id = ?
                """
                query_args.append(network_tuple.appservice_id)
                query_args.append(network_tuple.network_id)
            else:
                published_sql = """
                    SELECT room_id FROM rooms WHERE is_public
                """
        else:
            published_sql = """
                SELECT room_id FROM rooms WHERE is_public
                UNION SELECT room_id from appservice_room_list
            """

        # Work out the bounds if we're given them, these bounds look slightly
        # odd, but are designed to help query planner use indices by pulling
        # out a common bound.
        if bounds:
            last_joined_members, last_room_id = bounds
            if forwards:
                where_clauses.append(
                    """
                        joined_members <= ? AND (
                            joined_members < ? OR room_id < ?
                        )
                    """
                )
            else:
                where_clauses.append(
                    """
                        joined_members >= ? AND (
                            joined_members > ? OR room_id > ?
                        )
                    """
                )

            query_args += [last_joined_members, last_joined_members, last_room_id]

        if ignore_non_federatable:
            where_clauses.append("is_federatable")

        if search_filter and search_filter.get("generic_search_term", None):
            search_term = "%" + search_filter["generic_search_term"] + "%"

            where_clauses.append(
                """
                    (
                        LOWER(name) LIKE ?
                        OR LOWER(topic) LIKE ?
                        OR LOWER(canonical_alias) LIKE ?
                    )
                """
            )
            query_args += [
                search_term.lower(),
                search_term.lower(),
                search_term.lower(),
            ]

        where_clause = ""
        if where_clauses:
            where_clause = " AND " + " AND ".join(where_clauses)

        sql = """
            SELECT
                room_id, name, topic, canonical_alias, joined_members,
                avatar, history_visibility, joined_members, guest_access
            FROM (
                %(published_sql)s
            ) published
            INNER JOIN room_stats_state USING (room_id)
            INNER JOIN room_stats_current USING (room_id)
            WHERE
                (
                    join_rules = 'public' OR history_visibility = 'world_readable'
                )
                AND joined_members > 0
                %(where_clause)s
            ORDER BY joined_members %(dir)s, room_id %(dir)s
        """ % {
            "published_sql": published_sql,
            "where_clause": where_clause,
            "dir": "DESC" if forwards else "ASC",
        }

        if limit is not None:
            query_args.append(limit)

            sql += """
                LIMIT ?
            """

        def _get_largest_public_rooms_txn(txn):
            txn.execute(sql, query_args)

            results = self.cursor_to_dict(txn)

            if not forwards:
                results.reverse()

            return results

        ret_val = yield self.runInteraction(
            "get_largest_public_rooms", _get_largest_public_rooms_txn
        )
        defer.returnValue(ret_val)

    @cached(max_entries=10000)
    def is_room_blocked(self, room_id):
        return self._simple_select_one_onecol(
            table="blocked_rooms",
            keyvalues={"room_id": room_id},
            retcol="1",
            allow_none=True,
            desc="is_room_blocked",
        )

    @cachedInlineCallbacks(max_entries=10000)
    def get_ratelimit_for_user(self, user_id):
        """Check if there are any overrides for ratelimiting for the given
        user

        Args:
            user_id (str)

        Returns:
            RatelimitOverride if there is an override, else None. If the contents
            of RatelimitOverride are None or 0 then ratelimitng has been
            disabled for that user entirely.
        """
        row = yield self._simple_select_one(
            table="ratelimit_override",
            keyvalues={"user_id": user_id},
            retcols=("messages_per_second", "burst_count"),
            allow_none=True,
            desc="get_ratelimit_for_user",
        )

        if row:
            return RatelimitOverride(
                messages_per_second=row["messages_per_second"],
                burst_count=row["burst_count"],
            )
        else:
            return None


class RoomStore(RoomWorkerStore, SearchStore):
    def __init__(self, db_conn, hs):
        super(RoomStore, self).__init__(db_conn, hs)

        self.config = hs.config

        self.register_background_update_handler(
            "insert_room_retention", self._background_insert_retention,
        )

    @defer.inlineCallbacks
    def _background_insert_retention(self, progress, batch_size):
        """Retrieves a list of all rooms within a range and inserts an entry for each of
        them into the room_retention table.
        NULLs the property's columns if missing from the retention event in the room's
        state (or NULLs all of them if there's no retention event in the room's state),
        so that we fall back to the server's retention policy.
        """

        last_room = progress.get("room_id", "")

        def _background_insert_retention_txn(txn):
            txn.execute(
                """
                SELECT state.room_id, state.event_id, events.json
                FROM current_state_events as state
                LEFT JOIN event_json AS events ON (state.event_id = events.event_id)
                WHERE state.room_id > ? AND state.type = '%s'
                ORDER BY state.room_id ASC
                LIMIT ?;
                """ % EventTypes.Retention,
                (last_room, batch_size)
            )

            rows = self.cursor_to_dict(txn)

            if not rows:
                return True

            for row in rows:
                if not row["json"]:
                    retention_policy = {}
                else:
                    ev = json.loads(row["json"])
                    retention_policy = json.dumps(ev["content"])

                self._simple_insert_txn(
                    txn=txn,
                    table="room_retention",
                    values={
                        "room_id": row["room_id"],
                        "event_id": row["event_id"],
                        "min_lifetime": retention_policy.get("min_lifetime"),
                        "max_lifetime": retention_policy.get("max_lifetime"),
                    }
                )

            logger.info("Inserted %d rows into room_retention", len(rows))

            self._background_update_progress_txn(
                txn, "insert_room_retention", {
                    "room_id": rows[-1]["room_id"],
                }
            )

            if batch_size > len(rows):
                return True
            else:
                return False

        end = yield self.runInteraction(
            "insert_room_retention",
            _background_insert_retention_txn,
        )

        if end:
            yield self._end_background_update("insert_room_retention")

        defer.returnValue(batch_size)

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
                        },
                    )

            with self._public_room_id_gen.get_next() as next_id:
                yield self.runInteraction("store_room_txn", store_room_txn, next_id)
        except Exception as e:
            logger.error("store_room with room_id=%s failed: %s", room_id, e)
            raise StoreError(500, "Problem creating room.")

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
                    },
                )

        with self._public_room_id_gen.get_next() as next_id:
            yield self.runInteraction(
                "set_room_is_public", set_room_is_public_txn, next_id
            )
        self.hs.get_notifier().on_new_replication_data()

    @defer.inlineCallbacks
    def set_room_is_public_appservice(
        self, room_id, appservice_id, network_id, is_public
    ):
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
                            "room_id": room_id,
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
                        "room_id": room_id,
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
                    },
                )

        with self._public_room_id_gen.get_next() as next_id:
            yield self.runInteraction(
                "set_room_is_public_appservice",
                set_room_is_public_appservice_txn,
                next_id,
            )
        self.hs.get_notifier().on_new_replication_data()

    def get_room_count(self):
        """Retrieve a list of all rooms
        """

        def f(txn):
            sql = "SELECT count(*)  FROM rooms"
            txn.execute(sql)
            row = txn.fetchone()
            return row[0] or 0

        return self.runInteraction("get_rooms", f)

    def _store_room_topic_txn(self, txn, event):
        if hasattr(event, "content") and "topic" in event.content:
            self.store_event_search_txn(
                txn, event, "content.topic", event.content["topic"]
            )

    def _store_room_name_txn(self, txn, event):
        if hasattr(event, "content") and "name" in event.content:
            self.store_event_search_txn(
                txn, event, "content.name", event.content["name"]
            )

    def _store_room_message_txn(self, txn, event):
        if hasattr(event, "content") and "body" in event.content:
            self.store_event_search_txn(
                txn, event, "content.body", event.content["body"]
            )

    def _store_retention_policy_for_room_txn(self, txn, event):
        if (
            hasattr(event, "content")
            and ("min_lifetime" in event.content or "max_lifetime" in event.content)
        ):
            if (
                ("min_lifetime" in event.content and not isinstance(
                    event.content.get("min_lifetime"), integer_types
                ))
                or ("max_lifetime" in event.content and not isinstance(
                    event.content.get("max_lifetime"), integer_types
                ))
            ):
                # Ignore the event if one of the value isn't an integer.
                return

            self._simple_insert_txn(
                txn=txn,
                table="room_retention",
                values={
                    "room_id": event.room_id,
                    "event_id": event.event_id,
                    "min_lifetime": event.content.get("min_lifetime"),
                    "max_lifetime": event.content.get("max_lifetime"),
                },
            )

            self._invalidate_cache_and_stream(
                txn, self.get_retention_policy_for_room, (event.room_id,)
            )

    def add_event_report(
        self, room_id, event_id, user_id, reason, content, received_ts
    ):
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
            desc="add_event_report",
        )

    def get_current_public_room_stream_id(self):
        return self._public_room_id_gen.get_current_token()

    def get_all_new_public_rooms(self, prev_id, current_id, limit):
        def get_all_new_public_rooms(txn):
            sql = """
                SELECT stream_id, room_id, visibility, appservice_id, network_id
                FROM public_room_list_stream
                WHERE stream_id > ? AND stream_id <= ?
                ORDER BY stream_id ASC
                LIMIT ?
            """

            txn.execute(sql, (prev_id, current_id, limit))
            return txn.fetchall()

        if prev_id == current_id:
            return defer.succeed([])

        return self.runInteraction("get_all_new_public_rooms", get_all_new_public_rooms)

    @defer.inlineCallbacks
    def block_room(self, room_id, user_id):
        """Marks the room as blocked. Can be called multiple times.

        Args:
            room_id (str): Room to block
            user_id (str): Who blocked it

        Returns:
            Deferred
        """
        yield self._simple_upsert(
            table="blocked_rooms",
            keyvalues={"room_id": room_id},
            values={},
            insertion_values={"user_id": user_id},
            desc="block_room",
        )
        yield self.runInteraction(
            "block_room_invalidation",
            self._invalidate_cache_and_stream,
            self.is_room_blocked,
            (room_id,),
        )

    def get_media_mxcs_in_room(self, room_id):
        """Retrieves all the local and remote media MXC URIs in a given room

        Args:
            room_id (str)

        Returns:
            The local and remote media as a lists of tuples where the key is
            the hostname and the value is the media ID.
        """

        def _get_media_mxcs_in_room_txn(txn):
            local_mxcs, remote_mxcs = self._get_media_mxcs_in_room_txn(txn, room_id)
            local_media_mxcs = []
            remote_media_mxcs = []

            # Convert the IDs to MXC URIs
            for media_id in local_mxcs:
                local_media_mxcs.append("mxc://%s/%s" % (self.hs.hostname, media_id))
            for hostname, media_id in remote_mxcs:
                remote_media_mxcs.append("mxc://%s/%s" % (hostname, media_id))

            return local_media_mxcs, remote_media_mxcs

        return self.runInteraction("get_media_ids_in_room", _get_media_mxcs_in_room_txn)

    def quarantine_media_ids_in_room(self, room_id, quarantined_by):
        """For a room loops through all events with media and quarantines
        the associated media
        """

        def _quarantine_media_in_room_txn(txn):
            local_mxcs, remote_mxcs = self._get_media_mxcs_in_room_txn(txn, room_id)
            total_media_quarantined = 0

            # Now update all the tables to set the quarantined_by flag

            txn.executemany(
                """
                UPDATE local_media_repository
                SET quarantined_by = ?
                WHERE media_id = ?
            """,
                ((quarantined_by, media_id) for media_id in local_mxcs),
            )

            txn.executemany(
                """
                    UPDATE remote_media_cache
                    SET quarantined_by = ?
                    WHERE media_origin = ? AND media_id = ?
                """,
                (
                    (quarantined_by, origin, media_id)
                    for origin, media_id in remote_mxcs
                ),
            )

            total_media_quarantined += len(local_mxcs)
            total_media_quarantined += len(remote_mxcs)

            return total_media_quarantined

        return self.runInteraction(
            "quarantine_media_in_room", _quarantine_media_in_room_txn
        )

    def _get_media_mxcs_in_room_txn(self, txn, room_id):
        """Retrieves all the local and remote media MXC URIs in a given room

        Args:
            txn (cursor)
            room_id (str)

        Returns:
            The local and remote media as a lists of tuples where the key is
            the hostname and the value is the media ID.
        """
        mxc_re = re.compile("^mxc://([^/]+)/([^/#?]+)")

        next_token = self.get_current_events_token() + 1
        local_media_mxcs = []
        remote_media_mxcs = []

        while next_token:
            sql = """
                SELECT stream_ordering, json FROM events
                JOIN event_json USING (room_id, event_id)
                WHERE room_id = ?
                    AND stream_ordering < ?
                    AND contains_url = ? AND outlier = ?
                ORDER BY stream_ordering DESC
                LIMIT ?
            """
            txn.execute(sql, (room_id, next_token, True, False, 100))

            next_token = None
            for stream_ordering, content_json in txn:
                next_token = stream_ordering
                event_json = json.loads(content_json)
                content = event_json["content"]
                content_url = content.get("url")
                thumbnail_url = content.get("info", {}).get("thumbnail_url")

                for url in (content_url, thumbnail_url):
                    if not url:
                        continue
                    matches = mxc_re.match(url)
                    if matches:
                        hostname = matches.group(1)
                        media_id = matches.group(2)
                        if hostname == self.hs.hostname:
                            local_media_mxcs.append(media_id)
                        else:
                            remote_media_mxcs.append((hostname, media_id))

        return local_media_mxcs, remote_media_mxcs

    @defer.inlineCallbacks
    def get_rooms_for_retention_period_in_range(self, min_ms, max_ms, include_null=False):
        """Retrieves all of the rooms within the given retention range.

        Optionally includes the rooms which don't have a retention policy.

        Args:
            min_ms (int|None): Duration in milliseconds that define the lower limit of
                the range to handle (exclusive). If None, doesn't set a lower limit.
            max_ms (int|None): Duration in milliseconds that define the upper limit of
                the range to handle (inclusive). If None, doesn't set an upper limit.
            include_null (bool): Whether to include rooms which retention policy is NULL
                in the returned set.

        Returns:
            dict[str, dict]: The rooms within this range, along with their retention
                policy. The key is "room_id", and maps to a dict describing the retention
                policy associated with this room ID. The keys for this nested dict are
                "min_lifetime" (int|None), and "max_lifetime" (int|None).
        """

        def get_rooms_for_retention_period_in_range_txn(txn):
            range_conditions = []
            args = []

            if min_ms is not None:
                range_conditions.append("max_lifetime > ?")
                args.append(min_ms)

            if max_ms is not None:
                range_conditions.append("max_lifetime <= ?")
                args.append(max_ms)

            # Do a first query which will retrieve the rooms that have a retention policy
            # in their current state.
            sql = """
                SELECT room_id, min_lifetime, max_lifetime FROM room_retention
                INNER JOIN current_state_events USING (event_id, room_id)
                """

            if len(range_conditions):
                sql += " WHERE (" + " AND ".join(range_conditions) + ")"

                if include_null:
                    sql += " OR max_lifetime IS NULL"

            txn.execute(sql, args)

            rows = self.cursor_to_dict(txn)
            rooms_dict = {}

            for row in rows:
                rooms_dict[row["room_id"]] = {
                    "min_lifetime": row["min_lifetime"],
                    "max_lifetime": row["max_lifetime"],
                }

            if include_null:
                # If required, do a second query that retrieves all of the rooms we know
                # of so we can handle rooms with no retention policy.
                sql = "SELECT DISTINCT room_id FROM current_state_events"

                txn.execute(sql)

                rows = self.cursor_to_dict(txn)

                # If a room isn't already in the dict (i.e. it doesn't have a retention
                # policy in its state), add it with a null policy.
                for row in rows:
                    if row["room_id"] not in rooms_dict:
                        rooms_dict[row["room_id"]] = {
                            "min_lifetime": None,
                            "max_lifetime": None,
                        }

            return rooms_dict

        rooms = yield self.runInteraction(
            "get_rooms_for_retention_period_in_range",
            get_rooms_for_retention_period_in_range_txn,
        )

        defer.returnValue(rooms)

    @cachedInlineCallbacks()
    def get_retention_policy_for_room(self, room_id):
        """Get the retention policy for a given room.

        If no retention policy has been found for this room, returns a policy defined
        by the configured default policy (which has None as both the 'min_lifetime' and
        the 'max_lifetime' if no default policy has been defined in the server's
        configuration).

        Args:
            room_id (str): The ID of the room to get the retention policy of.

        Returns:
            dict[int, int]: "min_lifetime" and "max_lifetime" for this room.
        """

        def get_retention_policy_for_room_txn(txn):
            txn.execute(
                """
                SELECT min_lifetime, max_lifetime FROM room_retention
                INNER JOIN current_state_events USING (event_id, room_id)
                WHERE room_id = ?;
                """,
                (room_id,)
            )

            return self.cursor_to_dict(txn)

        ret = yield self.runInteraction(
            "get_retention_policy_for_room",
            get_retention_policy_for_room_txn,
        )

        # If we don't know this room ID, ret will be None, in this case return the default
        # policy.
        if not ret:
            defer.returnValue({
                "min_lifetime": self.config.retention_default_min_lifetime,
                "max_lifetime": self.config.retention_default_max_lifetime,
            })

        row = ret[0]

        # If one of the room's policy's attributes isn't defined, use the matching
        # attribute from the default policy.
        # The default values will be None if no default policy has been defined, or if one
        # of the attributes is missing from the default policy.
        if row["min_lifetime"] is None:
            row["min_lifetime"] = self.config.retention_default_min_lifetime

        if row["max_lifetime"] is None:
            row["max_lifetime"] = self.config.retention_default_max_lifetime

        defer.returnValue(row)
