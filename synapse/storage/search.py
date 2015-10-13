# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from _base import SQLBaseStore
from synapse.api.constants import KnownRoomEventKeys, SearchConstraintTypes
from synapse.storage.engines import PostgresEngine


class SearchStore(SQLBaseStore):
    @defer.inlineCallbacks
    def search_msgs(self, room_ids, constraints):
        clauses = []
        args = []
        fts = None

        clauses.append(
            "room_id IN (%s)" % (",".join(["?"] * len(room_ids)),)
        )
        args.extend(room_ids)

        for c in constraints:
            local_clauses = []
            if c.search_type == SearchConstraintTypes.FTS:
                fts = c.value
                for key in c.keys:
                    local_clauses.append("key = ?")
                    args.append(key)
            elif c.search_type == SearchConstraintTypes.EXACT:
                for key in c.keys:
                    if key == KnownRoomEventKeys.ROOM_ID:
                        for value in c.value:
                            local_clauses.append("room_id = ?")
                            args.append(value)
            clauses.append(
                "(%s)" % (" OR ".join(local_clauses),)
            )

        if isinstance(self.database_engine, PostgresEngine):
            sql = (
                "SELECT ts_rank_cd(vector, query) AS rank, event_id"
                " FROM plainto_tsquery('english', ?) as query, event_search"
                " WHERE vector @@ query"
            )
        else:
            sql = (
                "SELECT 0 as rank, event_id FROM event_search"
                " WHERE value MATCH ?"
            )

        for clause in clauses:
            sql += " AND " + clause

        sql += " ORDER BY rank DESC"

        results = yield self._execute(
            "search_msgs", self.cursor_to_dict, sql, *([fts] + args)
        )

        events = yield self._get_events([r["event_id"] for r in results])

        event_map = {
            ev.event_id: ev
            for ev in events
        }

        defer.returnValue((
            {
                r["event_id"]: r["rank"]
                for r in results
                if r["event_id"] in event_map
            },
            event_map
        ))
