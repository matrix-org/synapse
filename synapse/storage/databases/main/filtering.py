# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import TYPE_CHECKING, Optional, Tuple, Union, cast

from canonicaljson import encode_canonical_json

from synapse.api.errors import Codes, StoreError, SynapseError
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.engines import PostgresEngine
from synapse.types import JsonDict, JsonMapping, UserID
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer


class FilteringWorkerStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)
        self.server_name: str = hs.hostname
        self.database_engine = database.engine
        self.db_pool.updates.register_background_index_update(
            "full_users_filters_unique_idx",
            index_name="full_users_unique_idx",
            table="user_filters",
            columns=["full_user_id, filter_id"],
            unique=True,
        )

        self.db_pool.updates.register_background_update_handler(
            "populate_full_user_id_user_filters",
            self.populate_full_user_id_user_filters,
        )

    async def populate_full_user_id_user_filters(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """
        Background update to populate the column `full_user_id` of the table
        user_filters from entries in the column `user_local_part` of the same table
        """

        lower_bound_id = progress.get("lower_bound_id", "")

        def _get_last_id(txn: LoggingTransaction) -> Optional[str]:
            sql = """
                    SELECT user_id FROM user_filters
                    WHERE user_id > ?
                    ORDER BY user_id
                    LIMIT 1 OFFSET 1000
                  """
            txn.execute(sql, (lower_bound_id,))
            res = txn.fetchone()
            if res:
                upper_bound_id = res[0]
                return upper_bound_id
            else:
                return None

        def _process_batch(
            txn: LoggingTransaction, lower_bound_id: str, upper_bound_id: str
        ) -> None:
            sql = """
                    UPDATE user_filters
                    SET full_user_id = '@' || user_id || ?
                    WHERE ? < user_id AND user_id <= ? AND full_user_id IS NULL
                   """
            txn.execute(sql, (f":{self.server_name}", lower_bound_id, upper_bound_id))

        def _final_batch(txn: LoggingTransaction, lower_bound_id: str) -> None:
            sql = """
                    UPDATE user_filters
                    SET full_user_id = '@' || user_id || ?
                    WHERE ? < user_id AND full_user_id IS NULL
                   """
            txn.execute(
                sql,
                (
                    f":{self.server_name}",
                    lower_bound_id,
                ),
            )

            if isinstance(self.database_engine, PostgresEngine):
                sql = """
                        ALTER TABLE user_filters VALIDATE CONSTRAINT full_user_id_not_null
                      """
                txn.execute(sql)

        upper_bound_id = await self.db_pool.runInteraction(
            "populate_full_user_id_user_filters", _get_last_id
        )

        if upper_bound_id is None:
            await self.db_pool.runInteraction(
                "populate_full_user_id_user_filters", _final_batch, lower_bound_id
            )

            await self.db_pool.updates._end_background_update(
                "populate_full_user_id_user_filters"
            )
            return 1

        await self.db_pool.runInteraction(
            "populate_full_user_id_user_filters",
            _process_batch,
            lower_bound_id,
            upper_bound_id,
        )

        progress["lower_bound_id"] = upper_bound_id

        await self.db_pool.runInteraction(
            "populate_full_user_id_user_filters",
            self.db_pool.updates._background_update_progress_txn,
            "populate_full_user_id_user_filters",
            progress,
        )

        return 50

    @cached(num_args=2)
    async def get_user_filter(
        self, user_id: UserID, filter_id: Union[int, str]
    ) -> JsonMapping:
        # filter_id is BIGINT UNSIGNED, so if it isn't a number, fail
        # with a coherent error message rather than 500 M_UNKNOWN.
        try:
            int(filter_id)
        except ValueError:
            raise SynapseError(400, "Invalid filter ID", Codes.INVALID_PARAM)

        def_json = await self.db_pool.simple_select_one_onecol(
            table="user_filters",
            keyvalues={"full_user_id": user_id.to_string(), "filter_id": filter_id},
            retcol="filter_json",
            allow_none=False,
            desc="get_user_filter",
        )

        return db_to_json(def_json)

    async def add_user_filter(self, user_id: UserID, user_filter: JsonDict) -> int:
        def_json = encode_canonical_json(user_filter)

        # Need an atomic transaction to SELECT the maximal ID so far then
        # INSERT a new one
        def _do_txn(txn: LoggingTransaction) -> int:
            sql = (
                "SELECT filter_id FROM user_filters "
                "WHERE full_user_id = ? AND filter_json = ?"
            )
            txn.execute(sql, (user_id.to_string(), bytearray(def_json)))
            filter_id_response = txn.fetchone()
            if filter_id_response is not None:
                return filter_id_response[0]

            sql = "SELECT MAX(filter_id) FROM user_filters WHERE full_user_id = ?"
            txn.execute(sql, (user_id.to_string(),))
            max_id = cast(Tuple[Optional[int]], txn.fetchone())[0]
            if max_id is None:
                filter_id = 0
            else:
                filter_id = max_id + 1

            sql = (
                "INSERT INTO user_filters (full_user_id, user_id, filter_id, filter_json)"
                "VALUES(?, ?, ?, ?)"
            )
            txn.execute(
                sql,
                (
                    user_id.to_string(),
                    user_id.localpart,
                    filter_id,
                    bytearray(def_json),
                ),
            )

            return filter_id

        attempts = 0
        while True:
            # Try a few times.
            # This is technically needed if a user tries to create two filters at once,
            # leading to two concurrent transactions.
            # The failure case would be:
            # - SELECT filter_id ... filter_json = ? → both transactions return no rows
            # - SELECT MAX(filter_id) ... → both transactions return e.g. 5
            # - INSERT INTO ... → both transactions insert filter_id = 6
            # One of the transactions will commit. The other will get a unique key
            # constraint violation error (IntegrityError). This is not the same as a
            # serialisability violation, which would be automatically retried by
            # `runInteraction`.
            try:
                return await self.db_pool.runInteraction("add_user_filter", _do_txn)
            except self.db_pool.engine.module.IntegrityError:
                attempts += 1

                if attempts >= 5:
                    raise StoreError(500, "Couldn't generate a filter ID.")
