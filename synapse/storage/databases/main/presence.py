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

from typing import TYPE_CHECKING, Dict, Iterable, List, Tuple

from synapse.api.presence import PresenceState, UserPresenceState
from synapse.replication.tcp.streams import PresenceStream
from synapse.storage._base import SQLBaseStore, make_in_list_sql_clause
from synapse.storage.database import DatabasePool
from synapse.storage.engines import PostgresEngine
from synapse.storage.types import Connection
from synapse.storage.util.id_generators import MultiWriterIdGenerator, StreamIdGenerator
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.caches.stream_change_cache import StreamChangeCache
from synapse.util.iterutils import batch_iter

if TYPE_CHECKING:
    from synapse.server import HomeServer


class PresenceStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: Connection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self._can_persist_presence = (
            hs.get_instance_name() in hs.config.worker.writers.presence
        )

        if isinstance(database.engine, PostgresEngine):
            self._presence_id_gen = MultiWriterIdGenerator(
                db_conn=db_conn,
                db=database,
                stream_name="presence_stream",
                instance_name=self._instance_name,
                tables=[("presence_stream", "instance_name", "stream_id")],
                sequence_name="presence_stream_sequence",
                writers=hs.config.worker.writers.to_device,
            )
        else:
            self._presence_id_gen = StreamIdGenerator(
                db_conn, "presence_stream", "stream_id"
            )

        self.hs = hs
        self._presence_on_startup = self._get_active_presence(db_conn)

        presence_cache_prefill, min_presence_val = self.db_pool.get_cache_dict(
            db_conn,
            "presence_stream",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self._presence_id_gen.get_current_token(),
        )
        self.presence_stream_cache = StreamChangeCache(
            "PresenceStreamChangeCache",
            min_presence_val,
            prefilled_cache=presence_cache_prefill,
        )

    async def update_presence(self, presence_states):
        assert self._can_persist_presence

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

        # Delete old rows to stop database from getting really big
        sql = "DELETE FROM presence_stream WHERE stream_id < ? AND "

        for states in batch_iter(presence_states, 50):
            clause, args = make_in_list_sql_clause(
                self.database_engine, "user_id", [s.user_id for s in states]
            )
            txn.execute(sql + clause, [stream_id] + list(args))

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
                    "instance_name": self._instance_name,
                }
                for stream_id, state in zip(stream_orderings, presence_states)
            ],
        )

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

    async def should_user_receive_full_presence_with_token(
        self,
        user_id: str,
        from_token: int,
    ) -> bool:
        """Check whether the given user should receive full presence using the stream token
        they're updating from.

        Args:
            user_id: The ID of the user to check.
            from_token: The stream token included in their /sync token.

        Returns:
            True if the user should have full presence sent to them, False otherwise.
        """

        def _should_user_receive_full_presence_with_token_txn(txn):
            sql = """
                SELECT 1 FROM users_to_send_full_presence_to
                WHERE user_id = ?
                AND presence_stream_id >= ?
            """
            txn.execute(sql, (user_id, from_token))
            return bool(txn.fetchone())

        return await self.db_pool.runInteraction(
            "should_user_receive_full_presence_with_token",
            _should_user_receive_full_presence_with_token_txn,
        )

    async def add_users_to_send_full_presence_to(self, user_ids: Iterable[str]):
        """Adds to the list of users who should receive a full snapshot of presence
        upon their next sync.

        Args:
            user_ids: An iterable of user IDs.
        """
        # Add user entries to the table, updating the presence_stream_id column if the user already
        # exists in the table.
        await self.db_pool.simple_upsert_many(
            table="users_to_send_full_presence_to",
            key_names=("user_id",),
            key_values=[(user_id,) for user_id in user_ids],
            value_names=("presence_stream_id",),
            # We save the current presence stream ID token along with the user ID entry so
            # that when a user /sync's, even if they syncing multiple times across separate
            # devices at different times, each device will receive full presence once - when
            # the presence stream ID in their sync token is less than the one in the table
            # for their user ID.
            value_values=(
                (self._presence_id_gen.get_current_token(),) for _ in user_ids
            ),
            desc="add_users_to_send_full_presence_to",
        )

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

    def _get_active_presence(self, db_conn: Connection):
        """Fetch non-offline presence from the database so that we can register
        the appropriate time outs.
        """

        sql = (
            "SELECT user_id, state, last_active_ts, last_federation_update_ts,"
            " last_user_sync_ts, status_msg, currently_active FROM presence_stream"
            " WHERE state != ?"
        )

        txn = db_conn.cursor()
        txn.execute(sql, (PresenceState.OFFLINE,))
        rows = self.db_pool.cursor_to_dict(txn)
        txn.close()

        for row in rows:
            row["currently_active"] = bool(row["currently_active"])

        return [UserPresenceState(**row) for row in rows]

    def take_presence_startup_info(self):
        active_on_startup = self._presence_on_startup
        self._presence_on_startup = None
        return active_on_startup

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        if stream_name == PresenceStream.NAME:
            self._presence_id_gen.advance(instance_name, token)
            for row in rows:
                self.presence_stream_cache.entity_has_changed(row.user_id, token)
                self._get_presence_for_user.invalidate((row.user_id,))
        return super().process_replication_rows(stream_name, instance_name, token, rows)
