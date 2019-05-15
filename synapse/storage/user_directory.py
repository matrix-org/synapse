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

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules
from synapse.storage.background_updates import BackgroundUpdateStore
from synapse.storage.engines import PostgresEngine, Sqlite3Engine
from synapse.storage.state import StateFilter
from synapse.storage.state_deltas import StateDeltasStore
from synapse.types import get_domain_from_id, get_localpart_from_id
from synapse.util.caches.descriptors import cached

logger = logging.getLogger(__name__)


TEMP_TABLE = "_temp_populate_user_directory"


class UserDirectoryStore(StateDeltasStore, BackgroundUpdateStore):

    # How many records do we calculate before sending it to
    # add_users_who_share_private_rooms?
    SHARE_PRIVATE_WORKING_SET = 500

    def __init__(self, db_conn, hs):
        super(UserDirectoryStore, self).__init__(db_conn, hs)

        self.server_name = hs.hostname

        self.register_background_update_handler(
            "populate_user_directory_createtables",
            self._populate_user_directory_createtables,
        )
        self.register_background_update_handler(
            "populate_user_directory_process_rooms",
            self._populate_user_directory_process_rooms,
        )
        self.register_background_update_handler(
            "populate_user_directory_process_users",
            self._populate_user_directory_process_users,
        )
        self.register_background_update_handler(
            "populate_user_directory_cleanup", self._populate_user_directory_cleanup
        )

    @defer.inlineCallbacks
    def _populate_user_directory_createtables(self, progress, batch_size):

        # Get all the rooms that we want to process.
        def _make_staging_area(txn):
            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_rooms(room_id TEXT NOT NULL, events BIGINT NOT NULL)"
            )
            txn.execute(sql)

            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_position(position TEXT NOT NULL)"
            )
            txn.execute(sql)

            # Get rooms we want to process from the database
            sql = """
                SELECT room_id, count(*) FROM current_state_events
                GROUP BY room_id
            """
            txn.execute(sql)
            rooms = [{"room_id": x[0], "events": x[1]} for x in txn.fetchall()]
            self._simple_insert_many_txn(txn, TEMP_TABLE + "_rooms", rooms)
            del rooms

            # If search all users is on, get all the users we want to add.
            if self.hs.config.user_directory_search_all_users:
                sql = (
                    "CREATE TABLE IF NOT EXISTS "
                    + TEMP_TABLE
                    + "_users(user_id TEXT NOT NULL)"
                )
                txn.execute(sql)

                txn.execute("SELECT name FROM users")
                users = [{"user_id": x[0]} for x in txn.fetchall()]

                self._simple_insert_many_txn(txn, TEMP_TABLE + "_users", users)

        new_pos = yield self.get_max_stream_id_in_current_state_deltas()
        yield self.runInteraction(
            "populate_user_directory_temp_build", _make_staging_area
        )
        yield self._simple_insert(TEMP_TABLE + "_position", {"position": new_pos})

        yield self._end_background_update("populate_user_directory_createtables")
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _populate_user_directory_cleanup(self, progress, batch_size):
        """
        Update the user directory stream position, then clean up the old tables.
        """
        position = yield self._simple_select_one_onecol(
            TEMP_TABLE + "_position", None, "position"
        )
        yield self.update_user_directory_stream_pos(position)

        def _delete_staging_area(txn):
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_rooms")
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_users")
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_position")

        yield self.runInteraction(
            "populate_user_directory_cleanup", _delete_staging_area
        )

        yield self._end_background_update("populate_user_directory_cleanup")
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _populate_user_directory_process_rooms(self, progress, batch_size):
        """
        Args:
            progress (dict)
            batch_size (int): Maximum number of state events to process
                per cycle.
        """
        state = self.hs.get_state_handler()

        # If we don't have progress filed, delete everything.
        if not progress:
            yield self.delete_all_from_user_dir()

        def _get_next_batch(txn):
            # Only fetch 250 rooms, so we don't fetch too many at once, even
            # if those 250 rooms have less than batch_size state events.
            sql = """
                SELECT room_id, events FROM %s
                ORDER BY events DESC
                LIMIT 250
            """ % (
                TEMP_TABLE + "_rooms",
            )
            txn.execute(sql)
            rooms_to_work_on = txn.fetchall()

            if not rooms_to_work_on:
                return None

            # Get how many are left to process, so we can give status on how
            # far we are in processing
            txn.execute("SELECT COUNT(*) FROM " + TEMP_TABLE + "_rooms")
            progress["remaining"] = txn.fetchone()[0]

            return rooms_to_work_on

        rooms_to_work_on = yield self.runInteraction(
            "populate_user_directory_temp_read", _get_next_batch
        )

        # No more rooms -- complete the transaction.
        if not rooms_to_work_on:
            yield self._end_background_update("populate_user_directory_process_rooms")
            defer.returnValue(1)

        logger.info(
            "Processing the next %d rooms of %d remaining"
            % (len(rooms_to_work_on), progress["remaining"])
        )

        processed_event_count = 0

        for room_id, event_count in rooms_to_work_on:
            is_in_room = yield self.is_host_joined(room_id, self.server_name)

            if is_in_room:
                is_public = yield self.is_room_world_readable_or_publicly_joinable(
                    room_id
                )

                users_with_profile = yield state.get_current_users_in_room(room_id)
                user_ids = set(users_with_profile)

                # Update each user in the user directory.
                for user_id, profile in users_with_profile.items():
                    yield self.update_profile_in_user_dir(
                        user_id, profile.display_name, profile.avatar_url
                    )

                to_insert = set()

                if is_public:
                    for user_id in user_ids:
                        if self.get_if_app_services_interested_in_user(user_id):
                            continue

                        to_insert.add(user_id)

                    if to_insert:
                        yield self.add_users_in_public_rooms(room_id, to_insert)
                        to_insert.clear()
                else:
                    for user_id in user_ids:
                        if not self.hs.is_mine_id(user_id):
                            continue

                        if self.get_if_app_services_interested_in_user(user_id):
                            continue

                        for other_user_id in user_ids:
                            if user_id == other_user_id:
                                continue

                            user_set = (user_id, other_user_id)
                            to_insert.add(user_set)

                            # If it gets too big, stop and write to the database
                            # to prevent storing too much in RAM.
                            if len(to_insert) >= self.SHARE_PRIVATE_WORKING_SET:
                                yield self.add_users_who_share_private_room(
                                    room_id, to_insert
                                )
                                to_insert.clear()

                    if to_insert:
                        yield self.add_users_who_share_private_room(room_id, to_insert)
                        to_insert.clear()

            # We've finished a room. Delete it from the table.
            yield self._simple_delete_one(TEMP_TABLE + "_rooms", {"room_id": room_id})
            # Update the remaining counter.
            progress["remaining"] -= 1
            yield self.runInteraction(
                "populate_user_directory",
                self._background_update_progress_txn,
                "populate_user_directory_process_rooms",
                progress,
            )

            processed_event_count += event_count

            if processed_event_count > batch_size:
                # Don't process any more rooms, we've hit our batch size.
                defer.returnValue(processed_event_count)

        defer.returnValue(processed_event_count)

    @defer.inlineCallbacks
    def _populate_user_directory_process_users(self, progress, batch_size):
        """
        If search_all_users is enabled, add all of the users to the user directory.
        """
        if not self.hs.config.user_directory_search_all_users:
            yield self._end_background_update("populate_user_directory_process_users")
            defer.returnValue(1)

        def _get_next_batch(txn):
            sql = "SELECT user_id FROM %s LIMIT %s" % (
                TEMP_TABLE + "_users",
                str(batch_size),
            )
            txn.execute(sql)
            users_to_work_on = txn.fetchall()

            if not users_to_work_on:
                return None

            users_to_work_on = [x[0] for x in users_to_work_on]

            # Get how many are left to process, so we can give status on how
            # far we are in processing
            sql = "SELECT COUNT(*) FROM " + TEMP_TABLE + "_users"
            txn.execute(sql)
            progress["remaining"] = txn.fetchone()[0]

            return users_to_work_on

        users_to_work_on = yield self.runInteraction(
            "populate_user_directory_temp_read", _get_next_batch
        )

        # No more users -- complete the transaction.
        if not users_to_work_on:
            yield self._end_background_update("populate_user_directory_process_users")
            defer.returnValue(1)

        logger.info(
            "Processing the next %d users of %d remaining"
            % (len(users_to_work_on), progress["remaining"])
        )

        for user_id in users_to_work_on:
            profile = yield self.get_profileinfo(get_localpart_from_id(user_id))
            yield self.update_profile_in_user_dir(
                user_id, profile.display_name, profile.avatar_url
            )

            # We've finished processing a user. Delete it from the table.
            yield self._simple_delete_one(TEMP_TABLE + "_users", {"user_id": user_id})
            # Update the remaining counter.
            progress["remaining"] -= 1
            yield self.runInteraction(
                "populate_user_directory",
                self._background_update_progress_txn,
                "populate_user_directory_process_users",
                progress,
            )

        defer.returnValue(len(users_to_work_on))

    @defer.inlineCallbacks
    def is_room_world_readable_or_publicly_joinable(self, room_id):
        """Check if the room is either world_readable or publically joinable
        """

        # Create a state filter that only queries join and history state event
        types_to_filter = (
            (EventTypes.JoinRules, ""),
            (EventTypes.RoomHistoryVisibility, ""),
        )

        current_state_ids = yield self.get_filtered_current_state_ids(
            room_id, StateFilter.from_types(types_to_filter)
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

    def update_profile_in_user_dir(self, user_id, display_name, avatar_url):
        """
        Update or add a user's profile in the user directory.
        """

        def _update_profile_in_user_dir_txn(txn):
            new_entry = self._simple_upsert_txn(
                txn,
                table="user_directory",
                keyvalues={"user_id": user_id},
                values={"display_name": display_name, "avatar_url": avatar_url},
                lock=False,  # We're only inserter
            )

            if isinstance(self.database_engine, PostgresEngine):
                # We weight the localpart most highly, then display name and finally
                # server name
                if self.database_engine.can_native_upsert:
                    sql = """
                        INSERT INTO user_directory_search(user_id, vector)
                        VALUES (?,
                            setweight(to_tsvector('english', ?), 'A')
                            || setweight(to_tsvector('english', ?), 'D')
                            || setweight(to_tsvector('english', COALESCE(?, '')), 'B')
                        ) ON CONFLICT (user_id) DO UPDATE SET vector=EXCLUDED.vector
                    """
                    txn.execute(
                        sql,
                        (
                            user_id,
                            get_localpart_from_id(user_id),
                            get_domain_from_id(user_id),
                            display_name,
                        ),
                    )
                else:
                    # TODO: Remove this code after we've bumped the minimum version
                    # of postgres to always support upserts, so we can get rid of
                    # `new_entry` usage
                    if new_entry is True:
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
                                user_id,
                                get_localpart_from_id(user_id),
                                get_domain_from_id(user_id),
                                display_name,
                            ),
                        )
                    elif new_entry is False:
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
                                get_localpart_from_id(user_id),
                                get_domain_from_id(user_id),
                                display_name,
                                user_id,
                            ),
                        )
                    else:
                        raise RuntimeError(
                            "upsert returned None when 'can_native_upsert' is False"
                        )
            elif isinstance(self.database_engine, Sqlite3Engine):
                value = "%s %s" % (user_id, display_name) if display_name else user_id
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

    def remove_from_user_dir(self, user_id):
        def _remove_from_user_dir_txn(txn):
            self._simple_delete_txn(
                txn, table="user_directory", keyvalues={"user_id": user_id}
            )
            self._simple_delete_txn(
                txn, table="user_directory_search", keyvalues={"user_id": user_id}
            )
            self._simple_delete_txn(
                txn, table="users_in_public_rooms", keyvalues={"user_id": user_id}
            )
            self._simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"user_id": user_id},
            )
            self._simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"other_user_id": user_id},
            )
            txn.call_after(self.get_user_in_directory.invalidate, (user_id,))

        return self.runInteraction("remove_from_user_dir", _remove_from_user_dir_txn)

    @defer.inlineCallbacks
    def get_users_in_dir_due_to_room(self, room_id):
        """Get all user_ids that are in the room directory because they're
        in the given room_id
        """
        user_ids_share_pub = yield self._simple_select_onecol(
            table="users_in_public_rooms",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            desc="get_users_in_dir_due_to_room",
        )

        user_ids_share_priv = yield self._simple_select_onecol(
            table="users_who_share_private_rooms",
            keyvalues={"room_id": room_id},
            retcol="other_user_id",
            desc="get_users_in_dir_due_to_room",
        )

        user_ids = set(user_ids_share_pub)
        user_ids.update(user_ids_share_priv)

        defer.returnValue(user_ids)

    def add_users_who_share_private_room(self, room_id, user_id_tuples):
        """Insert entries into the users_who_share_private_rooms table. The first
        user should be a local user.

        Args:
            room_id (str)
            user_id_tuples([(str, str)]): iterable of 2-tuple of user IDs.
        """

        def _add_users_who_share_room_txn(txn):
            self._simple_upsert_many_txn(
                txn,
                table="users_who_share_private_rooms",
                key_names=["user_id", "other_user_id", "room_id"],
                key_values=[
                    (user_id, other_user_id, room_id)
                    for user_id, other_user_id in user_id_tuples
                ],
                value_names=(),
                value_values=None,
            )

        return self.runInteraction(
            "add_users_who_share_room", _add_users_who_share_room_txn
        )

    def add_users_in_public_rooms(self, room_id, user_ids):
        """Insert entries into the users_who_share_private_rooms table. The first
        user should be a local user.

        Args:
            room_id (str)
            user_ids (list[str])
        """

        def _add_users_in_public_rooms_txn(txn):

            self._simple_upsert_many_txn(
                txn,
                table="users_in_public_rooms",
                key_names=["user_id", "room_id"],
                key_values=[(user_id, room_id) for user_id in user_ids],
                value_names=(),
                value_values=None,
            )

        return self.runInteraction(
            "add_users_in_public_rooms", _add_users_in_public_rooms_txn
        )

    def remove_user_who_share_room(self, user_id, room_id):
        """
        Deletes entries in the users_who_share_*_rooms table. The first
        user should be a local user.

        Args:
            user_id (str)
            room_id (str)
        """

        def _remove_user_who_share_room_txn(txn):
            self._simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"user_id": user_id, "room_id": room_id},
            )
            self._simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"other_user_id": user_id, "room_id": room_id},
            )
            self._simple_delete_txn(
                txn,
                table="users_in_public_rooms",
                keyvalues={"user_id": user_id, "room_id": room_id},
            )

        return self.runInteraction(
            "remove_user_who_share_room", _remove_user_who_share_room_txn
        )

    @defer.inlineCallbacks
    def get_user_dir_rooms_user_is_in(self, user_id):
        """
        Returns the rooms that a user is in.

        Args:
            user_id(str): Must be a local user

        Returns:
            list: user_id
        """
        rows = yield self._simple_select_onecol(
            table="users_who_share_private_rooms",
            keyvalues={"user_id": user_id},
            retcol="room_id",
            desc="get_rooms_user_is_in",
        )

        pub_rows = yield self._simple_select_onecol(
            table="users_in_public_rooms",
            keyvalues={"user_id": user_id},
            retcol="room_id",
            desc="get_rooms_user_is_in",
        )

        users = set(pub_rows)
        users.update(rows)
        defer.returnValue(list(users))

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
            txn.execute("DELETE FROM users_who_share_private_rooms")
            txn.call_after(self.get_user_in_directory.invalidate_all)

        return self.runInteraction(
            "delete_all_from_user_dir", _delete_all_from_user_dir_txn
        )

    @cached()
    def get_user_in_directory(self, user_id):
        return self._simple_select_one(
            table="user_directory",
            keyvalues={"user_id": user_id},
            retcols=("display_name", "avatar_url"),
            allow_none=True,
            desc="get_user_in_directory",
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
            join_args = (user_id,)
            where_clause = "user_id != ?"
        else:
            join_args = (user_id,)
            where_clause = """
                (
                    EXISTS (select 1 from users_in_public_rooms WHERE user_id = t.user_id)
                    OR EXISTS (
                        SELECT 1 FROM users_who_share_private_rooms
                        WHERE user_id = ? AND other_user_id = t.user_id
                    )
                )
            """

        if isinstance(self.database_engine, PostgresEngine):
            full_query, exact_query, prefix_query = _parse_query_postgres(search_term)

            # We order by rank and then if they have profile info
            # The ranking algorithm is hand tweaked for "best" results. Broadly
            # the idea is we give a higher weight to exact matches.
            # The array of numbers are the weights for the various part of the
            # search: (domain, _, display name, localpart)
            sql = """
                SELECT d.user_id AS user_id, display_name, avatar_url
                FROM user_directory_search as t
                INNER JOIN user_directory AS d USING (user_id)
                WHERE
                    %s
                    AND vector @@ to_tsquery('english', ?)
                ORDER BY
                    (CASE WHEN d.user_id IS NOT NULL THEN 4.0 ELSE 1.0 END)
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
            """ % (
                where_clause,
            )
            args = join_args + (full_query, exact_query, prefix_query, limit + 1)
        elif isinstance(self.database_engine, Sqlite3Engine):
            search_query = _parse_query_sqlite(search_term)

            sql = """
                SELECT d.user_id AS user_id, display_name, avatar_url
                FROM user_directory_search as t
                INNER JOIN user_directory AS d USING (user_id)
                WHERE
                    %s
                    AND value MATCH ?
                ORDER BY
                    rank(matchinfo(user_directory_search)) DESC,
                    display_name IS NULL,
                    avatar_url IS NULL
                LIMIT ?
            """ % (
                where_clause,
            )
            args = join_args + (search_query, limit + 1)
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

        results = yield self._execute(
            "search_user_dir", self.cursor_to_dict, sql, *args
        )

        limited = len(results) > limit

        defer.returnValue({"limited": limited, "results": results})


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
    return " & ".join("(%s* OR %s)" % (result, result) for result in results)


def _parse_query_postgres(search_term):
    """Takes a plain unicode string from the user and converts it into a form
    that can be passed to database.
    We use this so that we can add prefix matching, which isn't something
    that is supported by default.
    """

    # Pull out the individual words, discarding any non-word characters.
    results = re.findall(r"([\w\-]+)", search_term, re.UNICODE)

    both = " & ".join("(%s:* | %s)" % (result, result) for result in results)
    exact = " & ".join("%s" % (result,) for result in results)
    prefix = " & ".join("%s:*" % (result,) for result in results)

    return both, exact, prefix
