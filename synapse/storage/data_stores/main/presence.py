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

from synapse.storage._base import SQLBaseStore, make_in_list_sql_clause
from synapse.storage.presence import UserPresenceState
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.iterutils import batch_iter


class PresenceStore(SQLBaseStore):
    @defer.inlineCallbacks
    def update_presence(self, presence_states):
        stream_ordering_manager = self._presence_id_gen.get_next_mult(
            len(presence_states)
        )

        with stream_ordering_manager as stream_orderings:
            yield self.db.runInteraction(
                "update_presence",
                self._update_presence_txn,
                stream_orderings,
                presence_states,
            )

        return stream_orderings[-1], self._presence_id_gen.get_current_token()

    def _update_presence_txn(self, txn, stream_orderings, presence_states):
        for stream_id, state in zip(stream_orderings, presence_states):
            txn.call_after(
                self.presence_stream_cache.entity_has_changed, state.user_id, stream_id
            )
            txn.call_after(self._get_presence_for_user.invalidate, (state.user_id,))

        # Actually insert new rows
        self.db.simple_insert_many_txn(
            txn,
            table="presence_stream",
            values=[
                {
                    "stream_id": stream_id,
                    "user_id": state.user_id,
                    "state": state.state,
                    "last_active_ts": state.last_active_ts,
                    "last_federation_update_ts": state.last_federation_update_ts,
                    "last_user_sync_ts": state.last_user_sync_ts,
                    "status_msg": state.status_msg,
                    "currently_active": state.currently_active,
                }
                for stream_id, state in zip(stream_orderings, presence_states)
            ],
        )

        # Delete old rows to stop database from getting really big
        sql = "DELETE FROM presence_stream WHERE stream_id < ? AND "

        for states in batch_iter(presence_states, 50):
            clause, args = make_in_list_sql_clause(
                self.database_engine, "user_id", [s.user_id for s in states]
            )
            txn.execute(sql + clause, [stream_id] + list(args))

    def get_all_presence_updates(self, last_id, current_id, limit):
        if last_id == current_id:
            return defer.succeed([])

        def get_all_presence_updates_txn(txn):
            sql = """
                SELECT stream_id, user_id, state, last_active_ts,
                    last_federation_update_ts, last_user_sync_ts,
                    status_msg,
                currently_active
                FROM presence_stream
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC
                LIMIT ?
            """
            txn.execute(sql, (last_id, current_id, limit))
            return txn.fetchall()

        return self.db.runInteraction(
            "get_all_presence_updates", get_all_presence_updates_txn
        )

    @cached()
    def _get_presence_for_user(self, user_id):
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_presence_for_user",
        list_name="user_ids",
        num_args=1,
        inlineCallbacks=True,
    )
    def get_presence_for_users(self, user_ids):
        rows = yield self.db.simple_select_many_batch(
            table="presence_stream",
            column="user_id",
            iterable=user_ids,
            keyvalues={},
            retcols=(
                "user_id",
                "state",
                "last_active_ts",
                "last_federation_update_ts",
                "last_user_sync_ts",
                "status_msg",
                "currently_active",
            ),
            desc="get_presence_for_users",
        )

        for row in rows:
            row["currently_active"] = bool(row["currently_active"])

        return {row["user_id"]: UserPresenceState(**row) for row in rows}

    def get_current_presence_token(self):
        return self._presence_id_gen.get_current_token()

    def allow_presence_visible(self, observed_localpart, observer_userid):
        return self.db.simple_insert(
            table="presence_allow_inbound",
            values={
                "observed_user_id": observed_localpart,
                "observer_user_id": observer_userid,
            },
            desc="allow_presence_visible",
            or_ignore=True,
        )

    def disallow_presence_visible(self, observed_localpart, observer_userid):
        return self.db.simple_delete_one(
            table="presence_allow_inbound",
            keyvalues={
                "observed_user_id": observed_localpart,
                "observer_user_id": observer_userid,
            },
            desc="disallow_presence_visible",
        )
