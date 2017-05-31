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

from twisted.internet import defer

from ._base import SQLBaseStore
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks
from synapse.api.constants import EventTypes, JoinRules
from synapse.storage.engines import PostgresEngine, Sqlite3Engine
from synapse.types import get_domain_from_id, get_localpart_from_id


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
                if join_rule_ev.content.get("join_rules") == JoinRules.PUBLIC:
                    defer.returnValue(True)

        hist_vis_id = current_state_ids.get((EventTypes.RoomHistoryVisibility, ""))
        if hist_vis_id:
            hist_vis_ev = yield self.get_event(hist_vis_id, allow_none=True)
            if hist_vis_ev:
                if hist_vis_ev.content.get("history_visibility") == "world_readable":
                    defer.returnValue(True)

        defer.returnValue(False)

    def add_profiles_to_user_dir(self, room_id, users_with_profile):
        """Add profiles to the user directory

        Args:
            room_id (str): A room_id that all users are in that is world_readable
                or publically joinable
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
                for user_id, profile in users_with_profile.iteritems()
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
                for user_id, p in users_with_profile.iteritems()
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
                    for user_id, profile in users_with_profile.iteritems()
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

    @defer.inlineCallbacks
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
            txn.call_after(
                self.get_user_in_directory.invalidate, (user_id,)
            )
        return self.runInteraction(
            "remove_from_user_dir", _remove_from_user_dir_txn,
        )

    def get_users_in_dir_due_to_room(self, room_id):
        """Get all user_ids that are in the room directory becuase they're
        in the given room_id
        """
        return self._simple_select_onecol(
            table="user_directory",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            desc="get_users_in_dir_due_to_room",
        )

    def get_all_rooms(self):
        """Get all room_ids we've ever known about
        """
        return self._simple_select_onecol(
            table="current_state_events",
            keyvalues={},
            retcol="DISTINCT room_id",
            desc="get_all_rooms",
        )

    def delete_all_from_user_dir(self):
        """Delete the entire user directory
        """
        def _delete_all_from_user_dir_txn(txn):
            txn.execute("DELETE FROM user_directory")
            txn.execute("DELETE FROM user_directory_search")
            txn.call_after(self.get_user_in_directory.invalidate_all)
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
        if not self._curr_state_delta_stream_cache.has_any_entity_changed(prev_stream_id):
            return []

        def get_current_state_deltas_txn(txn):
            # First we calculate the max stream id that will give us less than
            # N results
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
                if total > 50:
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
    def search_user_dir(self, search_term, limit):
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

        if isinstance(self.database_engine, PostgresEngine):
            sql = """
                SELECT user_id, display_name, avatar_url
                FROM user_directory_search
                INNER JOIN user_directory USING (user_id)
                WHERE vector @@ plainto_tsquery('english', ?)
                ORDER BY ts_rank_cd(vector, plainto_tsquery('english', ?)) DESC
                LIMIT ?
            """
            args = (search_term, search_term, limit + 1,)
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql = """
                SELECT user_id, display_name, avatar_url
                FROM user_directory_search
                INNER JOIN user_directory USING (user_id)
                WHERE value MATCH ?
                ORDER BY rank(matchinfo(user_directory)) DESC
                LIMIT ?
            """
            args = (search_term, limit + 1)
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
