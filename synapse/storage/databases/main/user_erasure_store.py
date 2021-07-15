# Copyright 2018 New Vector Ltd
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

from typing import Dict, Iterable

from synapse.storage._base import SQLBaseStore
from synapse.util.caches.descriptors import cached, cachedList


class UserErasureWorkerStore(SQLBaseStore):
    @cached()
    async def is_user_erased(self, user_id: str) -> bool:
        """
        Check if the given user id has requested erasure

        Args:
            user_id: full user id to check

        Returns:
            True if the user has requested erasure
        """
        result = await self.db_pool.simple_select_onecol(
            table="erased_users",
            keyvalues={"user_id": user_id},
            retcol="1",
            desc="is_user_erased",
        )
        return bool(result)

    @cachedList(cached_method_name="is_user_erased", list_name="user_ids")
    async def are_users_erased(self, user_ids: Iterable[str]) -> Dict[str, bool]:
        """
        Checks which users in a list have requested erasure

        Args:
            user_ids: full user ids to check

        Returns:
            for each user, whether the user has requested erasure.
        """
        rows = await self.db_pool.simple_select_many_batch(
            table="erased_users",
            column="user_id",
            iterable=user_ids,
            retcols=("user_id",),
            desc="are_users_erased",
        )
        erased_users = {row["user_id"] for row in rows}

        return {u: u in erased_users for u in user_ids}


class UserErasureStore(UserErasureWorkerStore):
    async def mark_user_erased(self, user_id: str) -> None:
        """Indicate that user_id wishes their message history to be erased.

        Args:
            user_id: full user_id to be erased
        """

        def f(txn):
            # first check if they are already in the list
            txn.execute("SELECT 1 FROM erased_users WHERE user_id = ?", (user_id,))
            if txn.fetchone():
                return

            # they are not already there: do the insert.
            txn.execute("INSERT INTO erased_users (user_id) VALUES (?)", (user_id,))

            self._invalidate_cache_and_stream(txn, self.is_user_erased, (user_id,))

        await self.db_pool.runInteraction("mark_user_erased", f)

    async def mark_user_not_erased(self, user_id: str) -> None:
        """Indicate that user_id is no longer erased.

        Args:
            user_id: full user_id to be un-erased
        """

        def f(txn):
            # first check if they are already in the list
            txn.execute("SELECT 1 FROM erased_users WHERE user_id = ?", (user_id,))
            if not txn.fetchone():
                return

            # They are there, delete them.
            self.db_pool.simple_delete_one_txn(
                txn, "erased_users", keyvalues={"user_id": user_id}
            )

            self._invalidate_cache_and_stream(txn, self.is_user_erased, (user_id,))

        await self.db_pool.runInteraction("mark_user_not_erased", f)
