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
        if isinstance(self.database_engine, PostgresEngine):
            sql = """
                INSERT INTO user_directory
                    (user_id, room_id, display_name, avatar_url, vector)
                VALUES (?,?,?,?,
                    setweight(to_tsvector('english', ?), 'A')
                    || to_tsvector('english', ?)
                    || to_tsvector('english', COALESCE(?, ''))
                )
            """
            args = (
                (
                    user_id, room_id, p.display_name, p.avatar_url,
                    get_localpart_from_id(user_id), get_domain_from_id(user_id),
                    p.display_name,
                )
                for user_id, p in users_with_profile.iteritems()
            )
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql = """
                INSERT INTO user_directory
                    (user_id, room_id, display_name, avatar_url, value)
                VALUES (?,?,?,?,?)
            """
            args = (
                (
                    user_id, room_id, p.display_name, p.avatar_url,
                    "%s %s" % (user_id, p.display_name,) if p.display_name else user_id
                )
                for user_id, p in users_with_profile.iteritems()
            )
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

        def _add_profiles_to_user_dir_txn(txn):
            txn.executemany(sql, args)
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
        yield self._simple_delete(
            table="user_directory",
            keyvalues={"user_id": user_id},
            desc="remove_from_user_dir",
        )
        self.get_user_in_directory.invalidate((user_id,))

    def get_all_rooms(self):
        return self._simple_select_onecol(
            table="current_state_events",
            keyvalues={},
            retcol="DISTINCT room_id",
            desc="get_all_rooms",
        )

    def delete_all_from_user_dir(self):
        def _delete_all_from_user_dir_txn(txn):
            txn.execute("DELETE FROM user_directory")
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
        # TODO: Add stream change cache
        # TODO: Add limit
        sql = """
            SELECT stream_id, room_id, type, state_key, event_id, prev_event_id
            FROM current_state_delta_stream
            WHERE stream_id > ?
            ORDER BY stream_id ASC
        """

        return self._execute(
            "get_current_state_deltas", self.cursor_to_dict, sql, prev_stream_id
        )

    @defer.inlineCallbacks
    def search_user_dir(self, search_term, limit):
        if isinstance(self.database_engine, PostgresEngine):
            sql = """
                SELECT user_id, display_name, avatar_url
                FROM user_directory
                WHERE vector @@ plainto_tsquery('english', ?)
                ORDER BY  ts_rank_cd(vector, plainto_tsquery('english', ?)) DESC
                LIMIT ?
            """
            args = (search_term, search_term, limit + 1,)
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql = """
                SELECT user_id, display_name, avatar_url
                FROM user_directory
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
