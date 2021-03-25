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

from typing import Dict, List, Tuple

from synapse.api.presence import UserPresenceState
from synapse.storage._base import SQLBaseStore, make_in_list_sql_clause
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.iterutils import batch_iter


class PresenceStore(SQLBaseStore):
    async def update_presence(self, presence_states):
        stream_ordering_manager = self._presence_id_gen.get_next_mult(
            len(presence_states)
        )

        async with stream_ordering_manager as stream_orderings:
            await self.db_pool.runInteraction(
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
        self.db_pool.simple_insert_many_txn(
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

    async def get_all_presence_updates(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, list]], int, bool]:
        """Get updates for presence replication stream.

        Args:
            instance_name: The writer we want to fetch updates from. Unused
                here since there is only ever one writer.
            last_id: The token to fetch updates from. Exclusive.
            current_id: The token to fetch updates up to. Inclusive.
            limit: The requested limit for the number of rows to return. The
                function may return more or fewer rows.

        Returns:
            A tuple consisting of: the updates, a token to use to fetch
            subsequent updates, and whether we returned fewer rows than exists
            between the requested tokens due to the limit.

            The token returned can be used in a subsequent call to this
            function to get further updatees.

            The updates are a list of 2-tuples of stream ID and the row data
        """

        if last_id == current_id:
            return [], current_id, False

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
            updates = [(row[0], row[1:]) for row in txn]

            upper_bound = current_id
            limited = False
            if len(updates) >= limit:
                upper_bound = updates[-1][0]
                limited = True

            return updates, upper_bound, limited

        return await self.db_pool.runInteraction(
            "get_all_presence_updates", get_all_presence_updates_txn
        )

    @cached()
    def _get_presence_for_user(self, user_id):
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_presence_for_user",
        list_name="user_ids",
        num_args=1,
    )
    async def get_presence_for_users(self, user_ids):
        rows = await self.db_pool.simple_select_many_batch(
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

    async def get_presence_for_all_users(
        self,
        include_offline: bool = True,
    ) -> Dict[str, UserPresenceState]:
        """Retrieve the current presence state for all users.

        Note that the presence_stream table is culled frequently, so it should only
        contain the latest presence state for each user.

        Args:
            include_offline: Whether to include offline presence states

        Returns:
            A dict of user IDs to their current UserPresenceState.
        """
        users_to_state = {}

        exclude_keyvalues = None
        if not include_offline:
            # Exclude offline presence state
            exclude_keyvalues = {"state": "offline"}

        # This may be a very heavy database query.
        # We paginate in order to not block a database connection.
        limit = 100
        offset = 0
        while True:
            rows = await self.db_pool.runInteraction(
                "get_presence_for_all_users",
                self.db_pool.simple_select_list_paginate_txn,
                "presence_stream",
                orderby="stream_id",
                start=offset,
                limit=limit,
                exclude_keyvalues=exclude_keyvalues,
                retcols=(
                    "user_id",
                    "state",
                    "last_active_ts",
                    "last_federation_update_ts",
                    "last_user_sync_ts",
                    "status_msg",
                    "currently_active",
                ),
                order_direction="ASC",
            )

            for row in rows:
                users_to_state[row["user_id"]] = UserPresenceState(**row)

            # We've run out of updates to query
            if len(rows) < limit:
                break

            offset += limit

        return users_to_state

    def get_current_presence_token(self):
        return self._presence_id_gen.get_current_token()
