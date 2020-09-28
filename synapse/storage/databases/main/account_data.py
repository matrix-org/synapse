# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

import abc
import logging
from typing import Dict, List, Optional, Tuple

from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import DatabasePool
from synapse.storage.util.id_generators import StreamIdGenerator
from synapse.types import JsonDict
from synapse.util import json_encoder
from synapse.util.caches.descriptors import _CacheContext, cached
from synapse.util.caches.stream_change_cache import StreamChangeCache

logger = logging.getLogger(__name__)


# The ABCMeta metaclass ensures that it cannot be instantiated without
# the abstract methods being implemented.
class AccountDataWorkerStore(SQLBaseStore, metaclass=abc.ABCMeta):
    """This is an abstract base class where subclasses must implement
    `get_max_account_data_stream_id` which can be called in the initializer.
    """

    def __init__(self, database: DatabasePool, db_conn, hs):
        account_max = self.get_max_account_data_stream_id()
        self._account_data_stream_cache = StreamChangeCache(
            "AccountDataAndTagsChangeCache", account_max
        )

        super().__init__(database, db_conn, hs)

    @abc.abstractmethod
    def get_max_account_data_stream_id(self):
        """Get the current max stream ID for account data stream

        Returns:
            int
        """
        raise NotImplementedError()

    @cached()
    async def get_account_data_for_user(
        self, user_id: str
    ) -> Tuple[Dict[str, JsonDict], Dict[str, Dict[str, JsonDict]]]:
        """Get all the client account_data for a user.

        Args:
            user_id: The user to get the account_data for.
        Returns:
            A 2-tuple of a dict of global account_data and a dict mapping from
            room_id string to per room account_data dicts.
        """

        def get_account_data_for_user_txn(txn):
            rows = self.db_pool.simple_select_list_txn(
                txn,
                "account_data",
                {"user_id": user_id},
                ["account_data_type", "content"],
            )

            global_account_data = {
                row["account_data_type"]: db_to_json(row["content"]) for row in rows
            }

            rows = self.db_pool.simple_select_list_txn(
                txn,
                "room_account_data",
                {"user_id": user_id},
                ["room_id", "account_data_type", "content"],
            )

            by_room = {}
            for row in rows:
                room_data = by_room.setdefault(row["room_id"], {})
                room_data[row["account_data_type"]] = db_to_json(row["content"])

            return global_account_data, by_room

        return await self.db_pool.runInteraction(
            "get_account_data_for_user", get_account_data_for_user_txn
        )

    @cached(num_args=2, max_entries=5000)
    async def get_global_account_data_by_type_for_user(
        self, data_type: str, user_id: str
    ) -> Optional[JsonDict]:
        """
        Returns:
            The account data.
        """
        result = await self.db_pool.simple_select_one_onecol(
            table="account_data",
            keyvalues={"user_id": user_id, "account_data_type": data_type},
            retcol="content",
            desc="get_global_account_data_by_type_for_user",
            allow_none=True,
        )

        if result:
            return db_to_json(result)
        else:
            return None

    @cached(num_args=2)
    async def get_account_data_for_room(
        self, user_id: str, room_id: str
    ) -> Dict[str, JsonDict]:
        """Get all the client account_data for a user for a room.

        Args:
            user_id: The user to get the account_data for.
            room_id: The room to get the account_data for.
        Returns:
            A dict of the room account_data
        """

        def get_account_data_for_room_txn(txn):
            rows = self.db_pool.simple_select_list_txn(
                txn,
                "room_account_data",
                {"user_id": user_id, "room_id": room_id},
                ["account_data_type", "content"],
            )

            return {
                row["account_data_type"]: db_to_json(row["content"]) for row in rows
            }

        return await self.db_pool.runInteraction(
            "get_account_data_for_room", get_account_data_for_room_txn
        )

    @cached(num_args=3, max_entries=5000)
    async def get_account_data_for_room_and_type(
        self, user_id: str, room_id: str, account_data_type: str
    ) -> Optional[JsonDict]:
        """Get the client account_data of given type for a user for a room.

        Args:
            user_id: The user to get the account_data for.
            room_id: The room to get the account_data for.
            account_data_type: The account data type to get.
        Returns:
            The room account_data for that type, or None if there isn't any set.
        """

        def get_account_data_for_room_and_type_txn(txn):
            content_json = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="room_account_data",
                keyvalues={
                    "user_id": user_id,
                    "room_id": room_id,
                    "account_data_type": account_data_type,
                },
                retcol="content",
                allow_none=True,
            )

            return db_to_json(content_json) if content_json else None

        return await self.db_pool.runInteraction(
            "get_account_data_for_room_and_type", get_account_data_for_room_and_type_txn
        )

    async def get_updated_global_account_data(
        self, last_id: int, current_id: int, limit: int
    ) -> List[Tuple[int, str, str]]:
        """Get the global account_data that has changed, for the account_data stream

        Args:
            last_id: the last stream_id from the previous batch.
            current_id: the maximum stream_id to return up to
            limit: the maximum number of rows to return

        Returns:
            A list of tuples of stream_id int, user_id string,
            and type string.
        """
        if last_id == current_id:
            return []

        def get_updated_global_account_data_txn(txn):
            sql = (
                "SELECT stream_id, user_id, account_data_type"
                " FROM account_data WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            return txn.fetchall()

        return await self.db_pool.runInteraction(
            "get_updated_global_account_data", get_updated_global_account_data_txn
        )

    async def get_updated_room_account_data(
        self, last_id: int, current_id: int, limit: int
    ) -> List[Tuple[int, str, str, str]]:
        """Get the global account_data that has changed, for the account_data stream

        Args:
            last_id: the last stream_id from the previous batch.
            current_id: the maximum stream_id to return up to
            limit: the maximum number of rows to return

        Returns:
            A list of tuples of stream_id int, user_id string,
            room_id string and type string.
        """
        if last_id == current_id:
            return []

        def get_updated_room_account_data_txn(txn):
            sql = (
                "SELECT stream_id, user_id, room_id, account_data_type"
                " FROM room_account_data WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            return txn.fetchall()

        return await self.db_pool.runInteraction(
            "get_updated_room_account_data", get_updated_room_account_data_txn
        )

    async def get_updated_account_data_for_user(
        self, user_id: str, stream_id: int
    ) -> Tuple[Dict[str, JsonDict], Dict[str, Dict[str, JsonDict]]]:
        """Get all the client account_data for a that's changed for a user

        Args:
            user_id: The user to get the account_data for.
            stream_id: The point in the stream since which to get updates
        Returns:
            A deferred pair of a dict of global account_data and a dict
            mapping from room_id string to per room account_data dicts.
        """

        def get_updated_account_data_for_user_txn(txn):
            sql = (
                "SELECT account_data_type, content FROM account_data"
                " WHERE user_id = ? AND stream_id > ?"
            )

            txn.execute(sql, (user_id, stream_id))

            global_account_data = {row[0]: db_to_json(row[1]) for row in txn}

            sql = (
                "SELECT room_id, account_data_type, content FROM room_account_data"
                " WHERE user_id = ? AND stream_id > ?"
            )

            txn.execute(sql, (user_id, stream_id))

            account_data_by_room = {}
            for row in txn:
                room_account_data = account_data_by_room.setdefault(row[0], {})
                room_account_data[row[1]] = db_to_json(row[2])

            return global_account_data, account_data_by_room

        changed = self._account_data_stream_cache.has_entity_changed(
            user_id, int(stream_id)
        )
        if not changed:
            return ({}, {})

        return await self.db_pool.runInteraction(
            "get_updated_account_data_for_user", get_updated_account_data_for_user_txn
        )

    @cached(num_args=2, cache_context=True, max_entries=5000)
    async def is_ignored_by(
        self, ignored_user_id: str, ignorer_user_id: str, cache_context: _CacheContext
    ) -> bool:
        ignored_account_data = await self.get_global_account_data_by_type_for_user(
            "m.ignored_user_list",
            ignorer_user_id,
            on_invalidate=cache_context.invalidate,
        )
        if not ignored_account_data:
            return False

        return ignored_user_id in ignored_account_data.get("ignored_users", {})


class AccountDataStore(AccountDataWorkerStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        self._account_data_id_gen = StreamIdGenerator(
            db_conn,
            "account_data_max_stream_id",
            "stream_id",
            extra_tables=[
                ("room_account_data", "stream_id"),
                ("room_tags_revisions", "stream_id"),
            ],
        )

        super().__init__(database, db_conn, hs)

    def get_max_account_data_stream_id(self) -> int:
        """Get the current max stream id for the private user data stream

        Returns:
            The maximum stream ID.
        """
        return self._account_data_id_gen.get_current_token()

    async def add_account_data_to_room(
        self, user_id: str, room_id: str, account_data_type: str, content: JsonDict
    ) -> int:
        """Add some account_data to a room for a user.

        Args:
            user_id: The user to add a tag for.
            room_id: The room to add a tag for.
            account_data_type: The type of account_data to add.
            content: A json object to associate with the tag.

        Returns:
            The maximum stream ID.
        """
        content_json = json_encoder.encode(content)

        async with self._account_data_id_gen.get_next() as next_id:
            # no need to lock here as room_account_data has a unique constraint
            # on (user_id, room_id, account_data_type) so simple_upsert will
            # retry if there is a conflict.
            await self.db_pool.simple_upsert(
                desc="add_room_account_data",
                table="room_account_data",
                keyvalues={
                    "user_id": user_id,
                    "room_id": room_id,
                    "account_data_type": account_data_type,
                },
                values={"stream_id": next_id, "content": content_json},
                lock=False,
            )

            # it's theoretically possible for the above to succeed and the
            # below to fail - in which case we might reuse a stream id on
            # restart, and the above update might not get propagated. That
            # doesn't sound any worse than the whole update getting lost,
            # which is what would happen if we combined the two into one
            # transaction.
            await self._update_max_stream_id(next_id)

            self._account_data_stream_cache.entity_has_changed(user_id, next_id)
            self.get_account_data_for_user.invalidate((user_id,))
            self.get_account_data_for_room.invalidate((user_id, room_id))
            self.get_account_data_for_room_and_type.prefill(
                (user_id, room_id, account_data_type), content
            )

        return self._account_data_id_gen.get_current_token()

    async def add_account_data_for_user(
        self, user_id: str, account_data_type: str, content: JsonDict
    ) -> int:
        """Add some account_data to a room for a user.

        Args:
            user_id: The user to add a tag for.
            account_data_type: The type of account_data to add.
            content: A json object to associate with the tag.

        Returns:
            The maximum stream ID.
        """
        content_json = json_encoder.encode(content)

        async with self._account_data_id_gen.get_next() as next_id:
            # no need to lock here as account_data has a unique constraint on
            # (user_id, account_data_type) so simple_upsert will retry if
            # there is a conflict.
            await self.db_pool.simple_upsert(
                desc="add_user_account_data",
                table="account_data",
                keyvalues={"user_id": user_id, "account_data_type": account_data_type},
                values={"stream_id": next_id, "content": content_json},
                lock=False,
            )

            # it's theoretically possible for the above to succeed and the
            # below to fail - in which case we might reuse a stream id on
            # restart, and the above update might not get propagated. That
            # doesn't sound any worse than the whole update getting lost,
            # which is what would happen if we combined the two into one
            # transaction.
            #
            # Note: This is only here for backwards compat to allow admins to
            # roll back to a previous Synapse version. Next time we update the
            # database version we can remove this table.
            await self._update_max_stream_id(next_id)

            self._account_data_stream_cache.entity_has_changed(user_id, next_id)
            self.get_account_data_for_user.invalidate((user_id,))
            self.get_global_account_data_by_type_for_user.invalidate(
                (account_data_type, user_id)
            )

        return self._account_data_id_gen.get_current_token()

    async def _update_max_stream_id(self, next_id: int) -> None:
        """Update the max stream_id

        Args:
            next_id: The the revision to advance to.
        """

        # Note: This is only here for backwards compat to allow admins to
        # roll back to a previous Synapse version. Next time we update the
        # database version we can remove this table.

        def _update(txn):
            update_max_id_sql = (
                "UPDATE account_data_max_stream_id"
                " SET stream_id = ?"
                " WHERE stream_id < ?"
            )
            txn.execute(update_max_id_sql, (next_id, next_id))

        await self.db_pool.runInteraction("update_account_data_max_stream_id", _update)
