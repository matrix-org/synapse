# Copyright 2019-2021 The Matrix.org Foundation C.I.C.
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

from typing import Optional

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import LoggingTransaction


class OpenIdStore(SQLBaseStore):
    async def insert_open_id_token(
        self, token: str, ts_valid_until_ms: int, user_id: str
    ) -> None:
        await self.db_pool.simple_insert(
            table="open_id_tokens",
            values={
                "token": token,
                "ts_valid_until_ms": ts_valid_until_ms,
                "user_id": user_id,
            },
            desc="insert_open_id_token",
        )

    async def get_user_id_for_open_id_token(
        self, token: str, ts_now_ms: int
    ) -> Optional[str]:
        def get_user_id_for_token_txn(txn: LoggingTransaction) -> Optional[str]:
            sql = (
                "SELECT user_id FROM open_id_tokens"
                " WHERE token = ? AND ? <= ts_valid_until_ms"
            )

            txn.execute(sql, (token, ts_now_ms))

            rows = txn.fetchall()
            if not rows:
                return None
            else:
                return rows[0][0]

        return await self.db_pool.runInteraction(
            "get_user_id_for_token", get_user_id_for_token_txn
        )
