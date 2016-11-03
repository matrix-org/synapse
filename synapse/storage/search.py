# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from .background_updates import BackgroundUpdateStore
from synapse.api.errors import SynapseError
from synapse.storage.engines import PostgresEngine, Sqlite3Engine

import logging
import re
import ujson as json


logger = logging.getLogger(__name__)


class SearchStore(BackgroundUpdateStore):

    EVENT_SEARCH_UPDATE_NAME = "event_search"
    EVENT_SEARCH_ORDER_UPDATE_NAME = "event_search_order"
    EVENT_SEARCH_USE_GIST_POSTGRES_NAME = "event_search_postgres_gist"

    def __init__(self, hs):
        super(SearchStore, self).__init__(hs)
        self.register_background_update_handler(
            self.EVENT_SEARCH_UPDATE_NAME, self._background_reindex_search
        )
        self.register_background_update_handler(
            self.EVENT_SEARCH_ORDER_UPDATE_NAME,
            self._background_reindex_search_order
        )
        self.register_background_update_handler(
            self.EVENT_SEARCH_USE_GIST_POSTGRES_NAME,
            self._background_reindex_gist_search
        )

    @defer.inlineCallbacks
    def _background_reindex_search(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)

        INSERT_CLUMP_SIZE = 1000
        TYPES = ["m.room.name", "m.room.message", "m.room.topic"]

        def reindex_search_txn(txn):
            sql = (
                "SELECT stream_ordering, event_id, room_id, type, content FROM events"
                " WHERE ? <= stream_ordering AND stream_ordering < ?"
                " AND (%s)"
                " ORDER BY stream_ordering DESC"
                " LIMIT ?"
            ) % (" OR ".join("type = '%s'" % (t,) for t in TYPES),)

            txn.execute(sql, (target_min_stream_id, max_stream_id, batch_size))

            rows = self.cursor_to_dict(txn)
            if not rows:
                return 0

            min_stream_id = rows[-1]["stream_ordering"]

            event_search_rows = []
            for row in rows:
                try:
                    event_id = row["event_id"]
                    room_id = row["room_id"]
                    etype = row["type"]
                    try:
                        content = json.loads(row["content"])
                    except:
                        continue

                    if etype == "m.room.message":
                        key = "content.body"
                        value = content["body"]
                    elif etype == "m.room.topic":
                        key = "content.topic"
                        value = content["topic"]
                    elif etype == "m.room.name":
                        key = "content.name"
                        value = content["name"]
                except (KeyError, AttributeError):
                    # If the event is missing a necessary field then
                    # skip over it.
                    continue

                if not isinstance(value, basestring):
                    # If the event body, name or topic isn't a string
                    # then skip over it
                    continue

                event_search_rows.append((event_id, room_id, key, value))

            if isinstance(self.database_engine, PostgresEngine):
                sql = (
                    "INSERT INTO event_search (event_id, room_id, key, vector)"
                    " VALUES (?,?,?,to_tsvector('english', ?))"
                )
            elif isinstance(self.database_engine, Sqlite3Engine):
                sql = (
                    "INSERT INTO event_search (event_id, room_id, key, value)"
                    " VALUES (?,?,?,?)"
                )
            else:
                # This should be unreachable.
                raise Exception("Unrecognized database engine")

            for index in range(0, len(event_search_rows), INSERT_CLUMP_SIZE):
                clump = event_search_rows[index:index + INSERT_CLUMP_SIZE]
                txn.executemany(sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(event_search_rows)
            }

            self._background_update_progress_txn(
                txn, self.EVENT_SEARCH_UPDATE_NAME, progress
            )

            return len(event_search_rows)

        result = yield self.runInteraction(
            self.EVENT_SEARCH_UPDATE_NAME, reindex_search_txn
        )

        if not result:
            yield self._end_background_update(self.EVENT_SEARCH_UPDATE_NAME)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _background_reindex_gist_search(self, progress, batch_size):
        def create_index(conn):
            conn.rollback()
            conn.set_session(autocommit=True)
            c = conn.cursor()

            c.execute(
                "CREATE INDEX CONCURRENTLY event_search_fts_idx_gist"
                " ON event_search USING GIST (vector)"
            )

            c.execute("DROP INDEX event_search_fts_idx")

            conn.set_session(autocommit=False)

        if isinstance(self.database_engine, PostgresEngine):
            yield self.runWithConnection(create_index)

        yield self._end_background_update(self.EVENT_SEARCH_USE_GIST_POSTGRES_NAME)
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _background_reindex_search_order(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)
        have_added_index = progress['have_added_indexes']

        if not have_added_index:
            def create_index(conn):
                conn.rollback()
                conn.set_session(autocommit=True)
                c = conn.cursor()

                # We create with NULLS FIRST so that when we search *backwards*
                # we get the ones with non null origin_server_ts *first*
                c.execute(
                    "CREATE INDEX CONCURRENTLY event_search_room_order ON event_search("
                    "room_id, origin_server_ts NULLS FIRST, stream_ordering NULLS FIRST)"
                )
                c.execute(
                    "CREATE INDEX CONCURRENTLY event_search_order ON event_search("
                    "origin_server_ts NULLS FIRST, stream_ordering NULLS FIRST)"
                )
                conn.set_session(autocommit=False)

            yield self.runWithConnection(create_index)

            pg = dict(progress)
            pg["have_added_indexes"] = True

            yield self.runInteraction(
                self.EVENT_SEARCH_ORDER_UPDATE_NAME,
                self._background_update_progress_txn,
                self.EVENT_SEARCH_ORDER_UPDATE_NAME, pg,
            )

        def reindex_search_txn(txn):
            sql = (
                "UPDATE event_search AS es SET stream_ordering = e.stream_ordering,"
                " origin_server_ts = e.origin_server_ts"
                " FROM events AS e"
                " WHERE e.event_id = es.event_id"
                " AND ? <= e.stream_ordering AND e.stream_ordering < ?"
                " RETURNING es.stream_ordering"
            )

            min_stream_id = max_stream_id - batch_size
            txn.execute(sql, (min_stream_id, max_stream_id))
            rows = txn.fetchall()

            if min_stream_id < target_min_stream_id:
                # We've recached the end.
                return len(rows), False

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows),
                "have_added_indexes": True,
            }

            self._background_update_progress_txn(
                txn, self.EVENT_SEARCH_ORDER_UPDATE_NAME, progress
            )

            return len(rows), True

        num_rows, finished = yield self.runInteraction(
            self.EVENT_SEARCH_ORDER_UPDATE_NAME, reindex_search_txn
        )

        if not finished:
            yield self._end_background_update(self.EVENT_SEARCH_ORDER_UPDATE_NAME)

        defer.returnValue(num_rows)

    @defer.inlineCallbacks
    def search_msgs(self, room_ids, search_term, keys):
        """Performs a full text search over events with given keys.

        Args:
            room_ids (list): List of room ids to search in
            search_term (str): Search term to search for
            keys (list): List of keys to search in, currently supports
                "content.body", "content.name", "content.topic"

        Returns:
            list of dicts
        """
        clauses = []

        search_query = search_query = _parse_query(self.database_engine, search_term)

        args = []

        # Make sure we don't explode because the person is in too many rooms.
        # We filter the results below regardless.
        if len(room_ids) < 500:
            clauses.append(
                "room_id IN (%s)" % (",".join(["?"] * len(room_ids)),)
            )
            args.extend(room_ids)

        local_clauses = []
        for key in keys:
            local_clauses.append("key = ?")
            args.append(key)

        clauses.append(
            "(%s)" % (" OR ".join(local_clauses),)
        )

        count_args = args
        count_clauses = clauses

        if isinstance(self.database_engine, PostgresEngine):
            sql = (
                "SELECT ts_rank_cd(vector, to_tsquery('english', ?)) AS rank,"
                " room_id, event_id"
                " FROM event_search"
                " WHERE vector @@ to_tsquery('english', ?)"
            )
            args = [search_query, search_query] + args

            count_sql = (
                "SELECT room_id, count(*) as count FROM event_search"
                " WHERE vector @@ to_tsquery('english', ?)"
            )
            count_args = [search_query] + count_args
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql = (
                "SELECT rank(matchinfo(event_search)) as rank, room_id, event_id"
                " FROM event_search"
                " WHERE value MATCH ?"
            )
            args = [search_query] + args

            count_sql = (
                "SELECT room_id, count(*) as count FROM event_search"
                " WHERE value MATCH ?"
            )
            count_args = [search_term] + count_args
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

        for clause in clauses:
            sql += " AND " + clause

        for clause in count_clauses:
            count_sql += " AND " + clause

        # We add an arbitrary limit here to ensure we don't try to pull the
        # entire table from the database.
        sql += " ORDER BY rank DESC LIMIT 500"

        results = yield self._execute(
            "search_msgs", self.cursor_to_dict, sql, *args
        )

        results = filter(lambda row: row["room_id"] in room_ids, results)

        events = yield self._get_events([r["event_id"] for r in results])

        event_map = {
            ev.event_id: ev
            for ev in events
        }

        highlights = None
        if isinstance(self.database_engine, PostgresEngine):
            highlights = yield self._find_highlights_in_postgres(search_query, events)

        count_sql += " GROUP BY room_id"

        count_results = yield self._execute(
            "search_rooms_count", self.cursor_to_dict, count_sql, *count_args
        )

        count = sum(row["count"] for row in count_results if row["room_id"] in room_ids)

        defer.returnValue({
            "results": [
                {
                    "event": event_map[r["event_id"]],
                    "rank": r["rank"],
                }
                for r in results
                if r["event_id"] in event_map
            ],
            "highlights": highlights,
            "count": count,
        })

    @defer.inlineCallbacks
    def search_rooms(self, room_ids, search_term, keys, limit, pagination_token=None):
        """Performs a full text search over events with given keys.

        Args:
            room_id (list): The room_ids to search in
            search_term (str): Search term to search for
            keys (list): List of keys to search in, currently supports
                "content.body", "content.name", "content.topic"
            pagination_token (str): A pagination token previously returned

        Returns:
            list of dicts
        """
        clauses = []

        search_query = search_query = _parse_query(self.database_engine, search_term)

        args = []

        # Make sure we don't explode because the person is in too many rooms.
        # We filter the results below regardless.
        if len(room_ids) < 500:
            clauses.append(
                "room_id IN (%s)" % (",".join(["?"] * len(room_ids)),)
            )
            args.extend(room_ids)

        local_clauses = []
        for key in keys:
            local_clauses.append("key = ?")
            args.append(key)

        clauses.append(
            "(%s)" % (" OR ".join(local_clauses),)
        )

        # take copies of the current args and clauses lists, before adding
        # pagination clauses to main query.
        count_args = list(args)
        count_clauses = list(clauses)

        if pagination_token:
            try:
                origin_server_ts, stream = pagination_token.split(",")
                origin_server_ts = int(origin_server_ts)
                stream = int(stream)
            except:
                raise SynapseError(400, "Invalid pagination token")

            clauses.append(
                "(origin_server_ts < ?"
                " OR (origin_server_ts = ? AND stream_ordering < ?))"
            )
            args.extend([origin_server_ts, origin_server_ts, stream])

        if isinstance(self.database_engine, PostgresEngine):
            sql = (
                "SELECT ts_rank_cd(vector, to_tsquery('english', ?)) as rank,"
                " origin_server_ts, stream_ordering, room_id, event_id"
                " FROM event_search"
                " WHERE vector @@ to_tsquery('english', ?) AND "
            )
            args = [search_query, search_query] + args

            count_sql = (
                "SELECT room_id, count(*) as count FROM event_search"
                " WHERE vector @@ to_tsquery('english', ?) AND "
            )
            count_args = [search_query] + count_args
        elif isinstance(self.database_engine, Sqlite3Engine):
            # We use CROSS JOIN here to ensure we use the right indexes.
            # https://sqlite.org/optoverview.html#crossjoin
            #
            # We want to use the full text search index on event_search to
            # extract all possible matches first, then lookup those matches
            # in the events table to get the topological ordering. We need
            # to use the indexes in this order because sqlite refuses to
            # MATCH unless it uses the full text search index
            sql = (
                "SELECT rank(matchinfo) as rank, room_id, event_id,"
                " origin_server_ts, stream_ordering"
                " FROM (SELECT key, event_id, matchinfo(event_search) as matchinfo"
                " FROM event_search"
                " WHERE value MATCH ?"
                " )"
                " CROSS JOIN events USING (event_id)"
                " WHERE "
            )
            args = [search_query] + args

            count_sql = (
                "SELECT room_id, count(*) as count FROM event_search"
                " WHERE value MATCH ? AND "
            )
            count_args = [search_term] + count_args
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

        sql += " AND ".join(clauses)
        count_sql += " AND ".join(count_clauses)

        # We add an arbitrary limit here to ensure we don't try to pull the
        # entire table from the database.
        if isinstance(self.database_engine, PostgresEngine):
            sql += (
                " ORDER BY origin_server_ts DESC NULLS LAST,"
                " stream_ordering DESC NULLS LAST LIMIT ?"
            )
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql += " ORDER BY origin_server_ts DESC, stream_ordering DESC LIMIT ?"
        else:
            raise Exception("Unrecognized database engine")

        args.append(limit)

        results = yield self._execute(
            "search_rooms", self.cursor_to_dict, sql, *args
        )

        results = filter(lambda row: row["room_id"] in room_ids, results)

        events = yield self._get_events([r["event_id"] for r in results])

        event_map = {
            ev.event_id: ev
            for ev in events
        }

        highlights = None
        if isinstance(self.database_engine, PostgresEngine):
            highlights = yield self._find_highlights_in_postgres(search_query, events)

        count_sql += " GROUP BY room_id"

        count_results = yield self._execute(
            "search_rooms_count", self.cursor_to_dict, count_sql, *count_args
        )

        count = sum(row["count"] for row in count_results if row["room_id"] in room_ids)

        defer.returnValue({
            "results": [
                {
                    "event": event_map[r["event_id"]],
                    "rank": r["rank"],
                    "pagination_token": "%s,%s" % (
                        r["origin_server_ts"], r["stream_ordering"]
                    ),
                }
                for r in results
                if r["event_id"] in event_map
            ],
            "highlights": highlights,
            "count": count,
        })

    def _find_highlights_in_postgres(self, search_query, events):
        """Given a list of events and a search term, return a list of words
        that match from the content of the event.

        This is used to give a list of words that clients can match against to
        highlight the matching parts.

        Args:
            search_query (str)
            events (list): A list of events

        Returns:
            deferred : A set of strings.
        """
        def f(txn):
            highlight_words = set()
            for event in events:
                # As a hack we simply join values of all possible keys. This is
                # fine since we're only using them to find possible highlights.
                values = []
                for key in ("body", "name", "topic"):
                    v = event.content.get(key, None)
                    if v:
                        values.append(v)

                if not values:
                    continue

                value = " ".join(values)

                # We need to find some values for StartSel and StopSel that
                # aren't in the value so that we can pick results out.
                start_sel = "<"
                stop_sel = ">"

                while start_sel in value:
                    start_sel += "<"
                while stop_sel in value:
                    stop_sel += ">"

                query = "SELECT ts_headline(?, to_tsquery('english', ?), %s)" % (
                    _to_postgres_options({
                        "StartSel": start_sel,
                        "StopSel": stop_sel,
                        "MaxFragments": "50",
                    })
                )
                txn.execute(query, (value, search_query,))
                headline, = txn.fetchall()[0]

                # Now we need to pick the possible highlights out of the haedline
                # result.
                matcher_regex = "%s(.*?)%s" % (
                    re.escape(start_sel),
                    re.escape(stop_sel),
                )

                res = re.findall(matcher_regex, headline)
                highlight_words.update([r.lower() for r in res])

            return highlight_words

        return self.runInteraction("_find_highlights", f)


def _to_postgres_options(options_dict):
    return "'%s'" % (
        ",".join("%s=%s" % (k, v) for k, v in options_dict.items()),
    )


def _parse_query(database_engine, search_term):
    """Takes a plain unicode string from the user and converts it into a form
    that can be passed to database.
    We use this so that we can add prefix matching, which isn't something
    that is supported by default.
    """

    # Pull out the individual words, discarding any non-word characters.
    results = re.findall(r"([\w\-]+)", search_term, re.UNICODE)

    if isinstance(database_engine, PostgresEngine):
        return " & ".join(result + ":*" for result in results)
    elif isinstance(database_engine, Sqlite3Engine):
        return " & ".join(result + "*" for result in results)
    else:
        # This should be unreachable.
        raise Exception("Unrecognized database engine")
