# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

import logging
import re

from six import iteritems

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules
from synapse.storage.engines import PostgresEngine, Sqlite3Engine
from synapse.types import get_domain_from_id, get_localpart_from_id
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks

from ._base import SQLBaseStore

logger = logging.getLogger(__name__)


class UserDirectoryStore(SQLBaseStore):
    @cachedInlineCallbacks(cache_context=True)
    def is_room_world_readable_or_publicly_joinable(self, room_id, cache_context):
        """Check if the room is either world_readable or publically joinable
        """
        current_state_ids = yield self.get_current_state_ids(
            room_id, on_invalidate=cache_context.invalidate
        )

        join_rules_id = current_state_ids.get((EventTypes.JoinRules, ""))
        if join_rules_id:
            join_rule_ev = yield self.get_event(join_rules_id, allow_none=True)
            if join_rule_ev:
                if join_rule_ev.content.get("join_rule") == JoinRules.PUBLIC:
                    defer.returnValue(True)

        hist_vis_id = current_state_ids.get((EventTypes.RoomHistoryVisibility, ""))
        if hist_vis_id:
            hist_vis_ev = yield self.get_event(hist_vis_id, allow_none=True)
            if hist_vis_ev:
                if hist_vis_ev.content.get("history_visibility") == "world_readable":
                    defer.returnValue(True)

        defer.returnValue(False)

    @defer.inlineCallbacks
    def add_users_to_public_room(self, room_id, user_ids):
        """Add user to the list of users in public rooms

        Args:
            room_id (str): A room_id that all users are in that is world_readable
                or publically joinable
            user_ids (list(str)): Users to add
        """
        yield self._simple_insert_many(
            table="users_in_public_rooms",
            values=[
                {
                    "user_id": user_id,
                    "room_id": room_id,
                }
                for user_id in user_ids
            ],
            desc="add_users_to_public_room"
        )
        for user_id in user_ids:
            self.get_user_in_public_room.invalidate((user_id,))

    def add_profiles_to_user_dir(self, room_id, users_with_profile):
        """Add profiles to the user directory

        Args:
            room_id (str): A room_id that all users are joined to
            users_with_profile (dict): Users to add to directory in the form of
                mapping of user_id -> ProfileInfo
        """
        if isinstance(self.database_engine, PostgresEngine):
            # We weight the loclpart most highly, then display name and finally
            # server name
            sql = """
                INSERT INTO user_directory_search(user_id, vector)
                VALUES (?,
                    setweight(to_tsvector('english', ?), 'A')
                    || setweight(to_tsvector('english', ?), 'D')
                    || setweight(to_tsvector('english', COALESCE(?, '')), 'B')
                )
            """
            args = (
                (
                    user_id, get_localpart_from_id(user_id), get_domain_from_id(user_id),
                    profile.display_name,
                )
                for user_id, profile in iteritems(users_with_profile)
            )
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql = """
                INSERT INTO user_directory_search(user_id, value)
                VALUES (?,?)
            """
            args = (
                (
                    user_id,
                    "%s %s" % (user_id, p.display_name,) if p.display_name else user_id
                )
                for user_id, p in iteritems(users_with_profile)
            )
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

        def _add_profiles_to_user_dir_txn(txn):
            txn.executemany(sql, args)
            self._simple_insert_many_txn(
                txn,
                table="user_directory",
                values=[
                    {
                        "user_id": user_id,
                        "room_id": room_id,
                        "display_name": profile.display_name,
                        "avatar_url": profile.avatar_url,
                    }
                    for user_id, profile in iteritems(users_with_profile)
                ]
            )
            for user_id in users_with_profile:
                txn.call_after(
                    self.get_user_in_directory.invalidate, (user_id,)
                )

        return self.runInteraction(
            "add_profiles_to_user_dir", _add_profiles_to_user_dir_txn
        )

    @defer.inlineCallbacks
    def update_user_in_user_dir(self, user_id, room_id):
        yield self._simple_update_one(
            table="user_directory",
            keyvalues={"user_id": user_id},
            updatevalues={"room_id": room_id},
            desc="update_user_in_user_dir",
        )
        self.get_user_in_directory.invalidate((user_id,))

    def update_profile_in_user_dir(self, user_id, display_name, avatar_url, room_id):
        def _update_profile_in_user_dir_txn(txn):
            new_entry = self._simple_upsert_txn(
                txn,
                table="user_directory",
                keyvalues={"user_id": user_id},
                insertion_values={"room_id": room_id},
                values={"display_name": display_name, "avatar_url": avatar_url},
                lock=False,  # We're only inserter
            )

            if isinstance(self.database_engine, PostgresEngine):
                # We weight the localpart most highly, then display name and finally
                # server name
                if new_entry:
                    sql = """
                        INSERT INTO user_directory_search(user_id, vector)
                        VALUES (?,
                            setweight(to_tsvector('english', ?), 'A')
                            || setweight(to_tsvector('english', ?), 'D')
                            || setweight(to_tsvector('english', COALESCE(?, '')), 'B')
                        )
                    """
                    txn.execute(
                        sql,
                        (
                            user_id, get_localpart_from_id(user_id),
                            get_domain_from_id(user_id), display_name,
                        )
                    )
                else:
                    sql = """
                        UPDATE user_directory_search
                        SET vector = setweight(to_tsvector('english', ?), 'A')
                            || setweight(to_tsvector('english', ?), 'D')
                            || setweight(to_tsvector('english', COALESCE(?, '')), 'B')
                        WHERE user_id = ?
                    """
                    txn.execute(
                        sql,
                        (
                            get_localpart_from_id(user_id), get_domain_from_id(user_id),
                            display_name, user_id,
                        )
                    )
            elif isinstance(self.database_engine, Sqlite3Engine):
                value = "%s %s" % (user_id, display_name,) if display_name else user_id
                self._simple_upsert_txn(
                    txn,
                    table="user_directory_search",
                    keyvalues={"user_id": user_id},
                    values={"value": value},
                    lock=False,  # We're only inserter
                )
            else:
                # This should be unreachable.
                raise Exception("Unrecognized database engine")

            txn.call_after(self.get_user_in_directory.invalidate, (user_id,))

        return self.runInteraction(
            "update_profile_in_user_dir", _update_profile_in_user_dir_txn
        )

    @defer.inlineCallbacks
    def update_user_in_public_user_list(self, user_id, room_id):
        yield self._simple_update_one(
            table="users_in_public_rooms",
            keyvalues={"user_id": user_id},
            updatevalues={"room_id": room_id},
            desc="update_user_in_public_user_list",
        )
        self.get_user_in_public_room.invalidate((user_id,))

    def remove_from_user_dir(self, user_id):
        def _remove_from_user_dir_txn(txn):
            self._simple_delete_txn(
                txn,
                table="user_directory",
                keyvalues={"user_id": user_id},
            )
            self._simple_delete_txn(
                txn,
                table="user_directory_search",
                keyvalues={"user_id": user_id},
            )
            self._simple_delete_txn(
                txn,
                table="users_in_public_rooms",
                keyvalues={"user_id": user_id},
            )
            txn.call_after(
                self.get_user_in_directory.invalidate, (user_id,)
            )
            txn.call_after(
                self.get_user_in_public_room.invalidate, (user_id,)
            )
        return self.runInteraction(
            "remove_from_user_dir", _remove_from_user_dir_txn,
        )

    @defer.inlineCallbacks
    def remove_from_user_in_public_room(self, user_id):
        yield self._simple_delete(
            table="users_in_public_rooms",
            keyvalues={"user_id": user_id},
            desc="remove_from_user_in_public_room",
        )
        self.get_user_in_public_room.invalidate((user_id,))

    def get_users_in_public_due_to_room(self, room_id):
        """Get all user_ids that are in the room directory because they're
        in the given room_id
        """
        return self._simple_select_onecol(
            table="users_in_public_rooms",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            desc="get_users_in_public_due_to_room",
        )

    @defer.inlineCallbacks
    def get_users_in_dir_due_to_room(self, room_id):
        """Get all user_ids that are in the room directory because they're
        in the given room_id
        """
        user_ids_dir = yield self._simple_select_onecol(
            table="user_directory",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            desc="get_users_in_dir_due_to_room",
        )

        user_ids_pub = yield self._simple_select_onecol(
            table="users_in_public_rooms",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            desc="get_users_in_dir_due_to_room",
        )

        user_ids_share = yield self._simple_select_onecol(
            table="users_who_share_rooms",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            desc="get_users_in_dir_due_to_room",
        )

        user_ids = set(user_ids_dir)
        user_ids.update(user_ids_pub)
        user_ids.update(user_ids_share)

        defer.returnValue(user_ids)

    @defer.inlineCallbacks
    def get_all_rooms(self):
        """Get all room_ids we've ever known about, in ascending order of "size"
        """
        sql = """
            SELECT room_id FROM current_state_events
            GROUP BY room_id
            ORDER BY count(*) ASC
        """
        rows = yield self._execute("get_all_rooms", None, sql)
        defer.returnValue([room_id for room_id, in rows])

    @defer.inlineCallbacks
    def get_all_local_users(self):
        """Get all local users
        """
        sql = """
            SELECT name FROM users
        """
        rows = yield self._execute("get_all_local_users", None, sql)
        defer.returnValue([name for name, in rows])

    def add_users_who_share_room(self, room_id, share_private, user_id_tuples):
        """Insert entries into the users_who_share_rooms table. The first
        user should be a local user.

        Args:
            room_id (str)
            share_private (bool): Is the room private
            user_id_tuples([(str, str)]): iterable of 2-tuple of user IDs.
        """
        def _add_users_who_share_room_txn(txn):
            self._simple_insert_many_txn(
                txn,
                table="users_who_share_rooms",
                values=[
                    {
                        "user_id": user_id,
                        "other_user_id": other_user_id,
                        "room_id": room_id,
                        "share_private": share_private,
                    }
                    for user_id, other_user_id in user_id_tuples
                ],
            )
            for user_id, other_user_id in user_id_tuples:
                txn.call_after(
                    self.get_users_who_share_room_from_dir.invalidate,
                    (user_id,),
                )
                txn.call_after(
                    self.get_if_users_share_a_room.invalidate,
                    (user_id, other_user_id),
                )
        return self.runInteraction(
            "add_users_who_share_room", _add_users_who_share_room_txn
        )

    def update_users_who_share_room(self, room_id, share_private, user_id_sets):
        """Updates entries in the users_who_share_rooms table. The first
        user should be a local user.

        Args:
            room_id (str)
            share_private (bool): Is the room private
            user_id_tuples([(str, str)]): iterable of 2-tuple of user IDs.
        """
        def _update_users_who_share_room_txn(txn):
            sql = """
                UPDATE users_who_share_rooms
                SET room_id = ?, share_private = ?
                WHERE user_id = ? AND other_user_id = ?
            """
            txn.executemany(
                sql,
                (
                    (room_id, share_private, uid, oid)
                    for uid, oid in user_id_sets
                )
            )
            for user_id, other_user_id in user_id_sets:
                txn.call_after(
                    self.get_users_who_share_room_from_dir.invalidate,
                    (user_id,),
                )
                txn.call_after(
                    self.get_if_users_share_a_room.invalidate,
                    (user_id, other_user_id),
                )
        return self.runInteraction(
            "update_users_who_share_room", _update_users_who_share_room_txn
        )

    def remove_user_who_share_room(self, user_id, other_user_id):
        """Deletes entries in the users_who_share_rooms table. The first
        user should be a local user.

        Args:
            room_id (str)
            share_private (bool): Is the room private
            user_id_tuples([(str, str)]): iterable of 2-tuple of user IDs.
        """
        def _remove_user_who_share_room_txn(txn):
            self._simple_delete_txn(
                txn,
                table="users_who_share_rooms",
                keyvalues={
                    "user_id": user_id,
                    "other_user_id": other_user_id,
                },
            )
            txn.call_after(
                self.get_users_who_share_room_from_dir.invalidate,
                (user_id,),
            )
            txn.call_after(
                self.get_if_users_share_a_room.invalidate,
                (user_id, other_user_id),
            )

        return self.runInteraction(
            "remove_user_who_share_room", _remove_user_who_share_room_txn
        )

    @cached(max_entries=500000)
    def get_if_users_share_a_room(self, user_id, other_user_id):
        """Gets if users share a room.

        Args:
            user_id (str): Must be a local user_id
            other_user_id (str)

        Returns:
            bool|None: None if they don't share a room, otherwise whether they
            share a private room or not.
        """
        return self._simple_select_one_onecol(
            table="users_who_share_rooms",
            keyvalues={
                "user_id": user_id,
                "other_user_id": other_user_id,
            },
            retcol="share_private",
            allow_none=True,
            desc="get_if_users_share_a_room",
        )

    @cachedInlineCallbacks(max_entries=500000, iterable=True)
    def get_users_who_share_room_from_dir(self, user_id):
        """Returns the set of users who share a room with `user_id`

        Args:
            user_id(str): Must be a local user

        Returns:
            dict: user_id -> share_private mapping
        """
        rows = yield self._simple_select_list(
            table="users_who_share_rooms",
            keyvalues={
                "user_id": user_id,
            },
            retcols=("other_user_id", "share_private",),
            desc="get_users_who_share_room_with_user",
        )

        defer.returnValue({
            row["other_user_id"]: row["share_private"]
            for row in rows
        })

    def get_users_in_share_dir_with_room_id(self, user_id, room_id):
        """Get all user tuples that are in the users_who_share_rooms due to the
        given room_id.

        Returns:
            [(user_id, other_user_id)]: where one of the two will match the given
            user_id.
        """
        sql = """
            SELECT user_id, other_user_id FROM users_who_share_rooms
            WHERE room_id = ? AND (user_id = ? OR other_user_id = ?)
        """
        return self._execute(
            "get_users_in_share_dir_with_room_id", None, sql, room_id, user_id, user_id
        )

    @defer.inlineCallbacks
    def get_rooms_in_common_for_users(self, user_id, other_user_id):
        """Given two user_ids find out the list of rooms they share.
        """
        sql = """
            SELECT room_id FROM (
                SELECT c.room_id FROM current_state_events AS c
                INNER JOIN room_memberships USING (event_id)
                WHERE type = 'm.room.member'
                    AND membership = 'join'
                    AND state_key = ?
            ) AS f1 INNER JOIN (
                SELECT c.room_id FROM current_state_events AS c
                INNER JOIN room_memberships USING (event_id)
                WHERE type = 'm.room.member'
                    AND membership = 'join'
                    AND state_key = ?
            ) f2 USING (room_id)
        """

        rows = yield self._execute(
            "get_rooms_in_common_for_users", None, sql, user_id, other_user_id
        )

        defer.returnValue([room_id for room_id, in rows])

    def delete_all_from_user_dir(self):
        """Delete the entire user directory
        """
        def _delete_all_from_user_dir_txn(txn):
            txn.execute("DELETE FROM user_directory")
            txn.execute("DELETE FROM user_directory_search")
            txn.execute("DELETE FROM users_in_public_rooms")
            txn.execute("DELETE FROM users_who_share_rooms")
            txn.call_after(self.get_user_in_directory.invalidate_all)
            txn.call_after(self.get_user_in_public_room.invalidate_all)
            txn.call_after(self.get_users_who_share_room_from_dir.invalidate_all)
            txn.call_after(self.get_if_users_share_a_room.invalidate_all)
        return self.runInteraction(
            "delete_all_from_user_dir", _delete_all_from_user_dir_txn
        )

    @cached()
    def get_user_in_directory(self, user_id):
        return self._simple_select_one(
            table="user_directory",
            keyvalues={"user_id": user_id},
            retcols=("room_id", "display_name", "avatar_url",),
            allow_none=True,
            desc="get_user_in_directory",
        )

    @cached()
    def get_user_in_public_room(self, user_id):
        return self._simple_select_one(
            table="users_in_public_rooms",
            keyvalues={"user_id": user_id},
            retcols=("room_id",),
            allow_none=True,
            desc="get_user_in_public_room",
        )

    def get_user_directory_stream_pos(self):
        return self._simple_select_one_onecol(
            table="user_directory_stream_pos",
            keyvalues={},
            retcol="stream_id",
            desc="get_user_directory_stream_pos",
        )

    def update_user_directory_stream_pos(self, stream_id):
        return self._simple_update_one(
            table="user_directory_stream_pos",
            keyvalues={},
            updatevalues={"stream_id": stream_id},
            desc="update_user_directory_stream_pos",
        )

    def get_current_state_deltas(self, prev_stream_id):
        prev_stream_id = int(prev_stream_id)
        if not self._curr_state_delta_stream_cache.has_any_entity_changed(prev_stream_id):
            return []

        def get_current_state_deltas_txn(txn):
            # First we calculate the max stream id that will give us less than
            # N results.
            # We arbitarily limit to 100 stream_id entries to ensure we don't
            # select toooo many.
            sql = """
                SELECT stream_id, count(*)
                FROM current_state_delta_stream
                WHERE stream_id > ?
                GROUP BY stream_id
                ORDER BY stream_id ASC
                LIMIT 100
            """
            txn.execute(sql, (prev_stream_id,))

            total = 0
            max_stream_id = prev_stream_id
            for max_stream_id, count in txn:
                total += count
                if total > 100:
                    # We arbitarily limit to 100 entries to ensure we don't
                    # select toooo many.
                    break

            # Now actually get the deltas
            sql = """
                SELECT stream_id, room_id, type, state_key, event_id, prev_event_id
                FROM current_state_delta_stream
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC
            """
            txn.execute(sql, (prev_stream_id, max_stream_id,))
            return self.cursor_to_dict(txn)

        return self.runInteraction(
            "get_current_state_deltas", get_current_state_deltas_txn
        )

    def get_max_stream_id_in_current_state_deltas(self):
        return self._simple_select_one_onecol(
            table="current_state_delta_stream",
            keyvalues={},
            retcol="COALESCE(MAX(stream_id), -1)",
            desc="get_max_stream_id_in_current_state_deltas",
        )

    @defer.inlineCallbacks
    def search_user_dir(self, user_id, search_term, limit):
        """Searches for users in directory

        Returns:
            dict of the form::

                {
                    "limited": <bool>,  # whether there were more results or not
                    "results": [  # Ordered by best match first
                        {
                            "user_id": <user_id>,
                            "display_name": <display_name>,
                            "avatar_url": <avatar_url>
                        }
                    ]
                }
        """

        if self.hs.config.user_directory_search_all_users:
            # make s.user_id null to keep the ordering algorithm happy
            join_clause = """
                CROSS JOIN (SELECT NULL as user_id) AS s
            """
            join_args = ()
            where_clause = "1=1"
        else:
            join_clause = """
                LEFT JOIN users_in_public_rooms AS p USING (user_id)
                LEFT JOIN (
                    SELECT other_user_id AS user_id FROM users_who_share_rooms
                    WHERE user_id = ? AND share_private
                ) AS s USING (user_id)
            """
            join_args = (user_id,)
            where_clause = "(s.user_id IS NOT NULL OR p.user_id IS NOT NULL)"

        if isinstance(self.database_engine, PostgresEngine):
            full_query, exact_query, prefix_query = _parse_query_postgres(search_term)

            # We order by rank and then if they have profile info
            # The ranking algorithm is hand tweaked for "best" results. Broadly
            # the idea is we give a higher weight to exact matches.
            # The array of numbers are the weights for the various part of the
            # search: (domain, _, display name, localpart)
            sql = """
                SELECT d.user_id AS user_id, display_name, avatar_url
                FROM user_directory_search
                INNER JOIN user_directory AS d USING (user_id)
                %s
                WHERE
                    %s
                    AND vector @@ to_tsquery('english', ?)
                ORDER BY
                    (CASE WHEN s.user_id IS NOT NULL THEN 4.0 ELSE 1.0 END)
                    * (CASE WHEN display_name IS NOT NULL THEN 1.2 ELSE 1.0 END)
                    * (CASE WHEN avatar_url IS NOT NULL THEN 1.2 ELSE 1.0 END)
                    * (
                        3 * ts_rank_cd(
                            '{0.1, 0.1, 0.9, 1.0}',
                            vector,
                            to_tsquery('english', ?),
                            8
                        )
                        + ts_rank_cd(
                            '{0.1, 0.1, 0.9, 1.0}',
                            vector,
                            to_tsquery('english', ?),
                            8
                        )
                    )
                    DESC,
                    display_name IS NULL,
                    avatar_url IS NULL
                LIMIT ?
            """ % (join_clause, where_clause)
            args = join_args + (full_query, exact_query, prefix_query, limit + 1,)
        elif isinstance(self.database_engine, Sqlite3Engine):
            search_query = _parse_query_sqlite(search_term)

            sql = """
                SELECT d.user_id AS user_id, display_name, avatar_url
                FROM user_directory_search
                INNER JOIN user_directory AS d USING (user_id)
                %s
                WHERE
                    %s
                    AND value MATCH ?
                ORDER BY
                    rank(matchinfo(user_directory_search)) DESC,
                    display_name IS NULL,
                    avatar_url IS NULL
                LIMIT ?
            """ % (join_clause, where_clause)
            args = join_args + (search_query, limit + 1)
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

        results = yield self._execute(
            "search_user_dir", self.cursor_to_dict, sql, *args
        )

        limited = len(results) > limit

        defer.returnValue({
            "limited": limited,
            "results": results,
        })


def _parse_query_sqlite(search_term):
    """Takes a plain unicode string from the user and converts it into a form
    that can be passed to database.
    We use this so that we can add prefix matching, which isn't something
    that is supported by default.

    We specifically add both a prefix and non prefix matching term so that
    exact matches get ranked higher.
    """

    # Pull out the individual words, discarding any non-word characters.
    results = re.findall(r"([\w\-]+)", search_term, re.UNICODE)
    return " & ".join("(%s* OR %s)" % (result, result,) for result in results)


def _parse_query_postgres(search_term):
    """Takes a plain unicode string from the user and converts it into a form
    that can be passed to database.
    We use this so that we can add prefix matching, which isn't something
    that is supported by default.
    """

    # Pull out the individual words, discarding any non-word characters.
    results = re.findall(r"([\w\-]+)", search_term, re.UNICODE)

    both = " & ".join("(%s:* | %s)" % (result, result,) for result in results)
    exact = " & ".join("%s" % (result,) for result in results)
    prefix = " & ".join("%s:*" % (result,) for result in results)

    return both, exact, prefix
