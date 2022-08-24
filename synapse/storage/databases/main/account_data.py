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

import logging
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Tuple,
    cast,
)

from synapse.api.constants import AccountDataTypes
from synapse.replication.slave.storage._slaved_id_tracker import SlavedIdTracker
from synapse.replication.tcp.streams import AccountDataStream, TagAccountDataStream
from synapse.storage._base import db_to_json
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.databases.main.push_rule import PushRulesWorkerStore
from synapse.storage.engines import PostgresEngine
from synapse.storage.util.id_generators import (
    AbstractStreamIdGenerator,
    AbstractStreamIdTracker,
    MultiWriterIdGenerator,
    StreamIdGenerator,
)
from synapse.types import JsonDict
from synapse.util import json_encoder
from synapse.util.caches.descriptors import cached
from synapse.util.caches.stream_change_cache import StreamChangeCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class AccountDataWorkerStore(PushRulesWorkerStore, CacheInvalidationWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # `_can_write_to_account_data` indicates whether the current worker is allowed
        # to write account data. A value of `True` implies that `_account_data_id_gen`
        # is an `AbstractStreamIdGenerator` and not just a tracker.
        self._account_data_id_gen: AbstractStreamIdTracker

        if isinstance(database.engine, PostgresEngine):
            self._can_write_to_account_data = (
                self._instance_name in hs.config.worker.writers.account_data
            )

            self._account_data_id_gen = MultiWriterIdGenerator(
                db_conn=db_conn,
                db=database,
                stream_name="account_data",
                instance_name=self._instance_name,
                tables=[
                    ("room_account_data", "instance_name", "stream_id"),
                    ("room_tags_revisions", "instance_name", "stream_id"),
                    ("account_data", "instance_name", "stream_id"),
                ],
                sequence_name="account_data_sequence",
                writers=hs.config.worker.writers.account_data,
            )
        else:
            # We shouldn't be running in worker mode with SQLite, but its useful
            # to support it for unit tests.
            #
            # If this process is the writer than we need to use
            # `StreamIdGenerator`, otherwise we use `SlavedIdTracker` which gets
            # updated over replication. (Multiple writers are not supported for
            # SQLite).
            if self._instance_name in hs.config.worker.writers.account_data:
                self._can_write_to_account_data = True
                self._account_data_id_gen = StreamIdGenerator(
                    db_conn,
                    "room_account_data",
                    "stream_id",
                    extra_tables=[("room_tags_revisions", "stream_id")],
                )
            else:
                self._account_data_id_gen = SlavedIdTracker(
                    db_conn,
                    "room_account_data",
                    "stream_id",
                    extra_tables=[("room_tags_revisions", "stream_id")],
                )

        account_max = self.get_max_account_data_stream_id()
        self._account_data_stream_cache = StreamChangeCache(
            "AccountDataAndTagsChangeCache", account_max
        )

        self.db_pool.updates.register_background_update_handler(
            "delete_account_data_for_deactivated_users",
            self._delete_account_data_for_deactivated_users,
        )

    def get_max_account_data_stream_id(self) -> int:
        """Get the current max stream ID for account data stream

        Returns:
            int
        """
        return self._account_data_id_gen.get_current_token()

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

        def get_account_data_for_user_txn(
            txn: LoggingTransaction,
        ) -> Tuple[Dict[str, JsonDict], Dict[str, Dict[str, JsonDict]]]:
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

            by_room: Dict[str, Dict[str, JsonDict]] = {}
            for row in rows:
                room_data = by_room.setdefault(row["room_id"], {})
                room_data[row["account_data_type"]] = db_to_json(row["content"])

            return global_account_data, by_room

        return await self.db_pool.runInteraction(
            "get_account_data_for_user", get_account_data_for_user_txn
        )

    @cached(num_args=2, max_entries=5000, tree=True)
    async def get_global_account_data_by_type_for_user(
        self, user_id: str, data_type: str
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

    @cached(num_args=2, tree=True)
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

        def get_account_data_for_room_txn(
            txn: LoggingTransaction,
        ) -> Dict[str, JsonDict]:
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

    @cached(num_args=3, max_entries=5000, tree=True)
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

        def get_account_data_for_room_and_type_txn(
            txn: LoggingTransaction,
        ) -> Optional[JsonDict]:
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

        def get_updated_global_account_data_txn(
            txn: LoggingTransaction,
        ) -> List[Tuple[int, str, str]]:
            sql = (
                "SELECT stream_id, user_id, account_data_type"
                " FROM account_data WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            return cast(List[Tuple[int, str, str]], txn.fetchall())

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

        def get_updated_room_account_data_txn(
            txn: LoggingTransaction,
        ) -> List[Tuple[int, str, str, str]]:
            sql = (
                "SELECT stream_id, user_id, room_id, account_data_type"
                " FROM room_account_data WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            return cast(List[Tuple[int, str, str, str]], txn.fetchall())

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

        def get_updated_account_data_for_user_txn(
            txn: LoggingTransaction,
        ) -> Tuple[Dict[str, JsonDict], Dict[str, Dict[str, JsonDict]]]:
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

            account_data_by_room: Dict[str, Dict[str, JsonDict]] = {}
            for row in txn:
                room_account_data = account_data_by_room.setdefault(row[0], {})
                room_account_data[row[1]] = db_to_json(row[2])

            return global_account_data, account_data_by_room

        changed = self._account_data_stream_cache.has_entity_changed(
            user_id, int(stream_id)
        )
        if not changed:
            return {}, {}

        return await self.db_pool.runInteraction(
            "get_updated_account_data_for_user", get_updated_account_data_for_user_txn
        )

    @cached(max_entries=5000, iterable=True)
    async def ignored_by(self, user_id: str) -> FrozenSet[str]:
        """
        Get users which ignore the given user.

        Params:
            user_id: The user ID which might be ignored.

        Return:
            The user IDs which ignore the given user.
        """
        return frozenset(
            await self.db_pool.simple_select_onecol(
                table="ignored_users",
                keyvalues={"ignored_user_id": user_id},
                retcol="ignorer_user_id",
                desc="ignored_by",
            )
        )

    @cached(max_entries=5000, iterable=True)
    async def ignored_users(self, user_id: str) -> FrozenSet[str]:
        """
        Get users which the given user ignores.

        Params:
            user_id: The user ID which is making the request.

        Return:
            The user IDs which are ignored by the given user.
        """
        return frozenset(
            await self.db_pool.simple_select_onecol(
                table="ignored_users",
                keyvalues={"ignorer_user_id": user_id},
                retcol="ignored_user_id",
                desc="ignored_users",
            )
        )

    def process_replication_rows(
        self,
        stream_name: str,
        instance_name: str,
        token: int,
        rows: Iterable[Any],
    ) -> None:
        if stream_name == TagAccountDataStream.NAME:
            self._account_data_id_gen.advance(instance_name, token)
        elif stream_name == AccountDataStream.NAME:
            self._account_data_id_gen.advance(instance_name, token)
            for row in rows:
                if not row.room_id:
                    self.get_global_account_data_by_type_for_user.invalidate(
                        (row.user_id, row.data_type)
                    )
                self.get_account_data_for_user.invalidate((row.user_id,))
                self.get_account_data_for_room.invalidate((row.user_id, row.room_id))
                self.get_account_data_for_room_and_type.invalidate(
                    (row.user_id, row.room_id, row.data_type)
                )
                self._account_data_stream_cache.entity_has_changed(row.user_id, token)

        super().process_replication_rows(stream_name, instance_name, token, rows)

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
        assert self._can_write_to_account_data
        assert isinstance(self._account_data_id_gen, AbstractStreamIdGenerator)

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
        """Add some global account_data for a user.

        Args:
            user_id: The user to add a tag for.
            account_data_type: The type of account_data to add.
            content: A json object to associate with the tag.

        Returns:
            The maximum stream ID.
        """
        assert self._can_write_to_account_data
        assert isinstance(self._account_data_id_gen, AbstractStreamIdGenerator)

        async with self._account_data_id_gen.get_next() as next_id:
            await self.db_pool.runInteraction(
                "add_user_account_data",
                self._add_account_data_for_user,
                next_id,
                user_id,
                account_data_type,
                content,
            )

            self._account_data_stream_cache.entity_has_changed(user_id, next_id)
            self.get_account_data_for_user.invalidate((user_id,))
            self.get_global_account_data_by_type_for_user.invalidate(
                (user_id, account_data_type)
            )

        return self._account_data_id_gen.get_current_token()

    def _add_account_data_for_user(
        self,
        txn: LoggingTransaction,
        next_id: int,
        user_id: str,
        account_data_type: str,
        content: JsonDict,
    ) -> None:
        content_json = json_encoder.encode(content)

        # no need to lock here as account_data has a unique constraint on
        # (user_id, account_data_type) so simple_upsert will retry if
        # there is a conflict.
        self.db_pool.simple_upsert_txn(
            txn,
            table="account_data",
            keyvalues={"user_id": user_id, "account_data_type": account_data_type},
            values={"stream_id": next_id, "content": content_json},
            lock=False,
        )

        # Ignored users get denormalized into a separate table as an optimisation.
        if account_data_type != AccountDataTypes.IGNORED_USER_LIST:
            return

        # Insert / delete to sync the list of ignored users.
        previously_ignored_users = set(
            self.db_pool.simple_select_onecol_txn(
                txn,
                table="ignored_users",
                keyvalues={"ignorer_user_id": user_id},
                retcol="ignored_user_id",
            )
        )

        # If the data is invalid, no one is ignored.
        ignored_users_content = content.get("ignored_users", {})
        if isinstance(ignored_users_content, dict):
            currently_ignored_users = set(ignored_users_content)
        else:
            currently_ignored_users = set()

        # If the data has not changed, nothing to do.
        if previously_ignored_users == currently_ignored_users:
            return

        # Delete entries which are no longer ignored.
        self.db_pool.simple_delete_many_txn(
            txn,
            table="ignored_users",
            column="ignored_user_id",
            values=previously_ignored_users - currently_ignored_users,
            keyvalues={"ignorer_user_id": user_id},
        )

        # Add entries which are newly ignored.
        self.db_pool.simple_insert_many_txn(
            txn,
            table="ignored_users",
            keys=("ignorer_user_id", "ignored_user_id"),
            values=[
                (user_id, u) for u in currently_ignored_users - previously_ignored_users
            ],
        )

        # Invalidate the cache for any ignored users which were added or removed.
        for ignored_user_id in previously_ignored_users ^ currently_ignored_users:
            self._invalidate_cache_and_stream(txn, self.ignored_by, (ignored_user_id,))
        self._invalidate_cache_and_stream(txn, self.ignored_users, (user_id,))

    async def purge_account_data_for_user(self, user_id: str) -> None:
        """
        Removes ALL the account data for a user.
        Intended to be used upon user deactivation.

        Also purges the user from the ignored_users cache table
        and the push_rules cache tables.
        """

        await self.db_pool.runInteraction(
            "purge_account_data_for_user_txn",
            self._purge_account_data_for_user_txn,
            user_id,
        )

    def _purge_account_data_for_user_txn(
        self, txn: LoggingTransaction, user_id: str
    ) -> None:
        """
        See `purge_account_data_for_user`.
        """
        # Purge from the primary account_data tables.
        self.db_pool.simple_delete_txn(
            txn, table="account_data", keyvalues={"user_id": user_id}
        )

        self.db_pool.simple_delete_txn(
            txn, table="room_account_data", keyvalues={"user_id": user_id}
        )

        # Purge from ignored_users where this user is the ignorer.
        # N.B. We don't purge where this user is the ignoree, because that
        #      interferes with other users' account data.
        #      It's also not this user's data to delete!
        self.db_pool.simple_delete_txn(
            txn, table="ignored_users", keyvalues={"ignorer_user_id": user_id}
        )

        # Remove the push rules
        self.db_pool.simple_delete_txn(
            txn, table="push_rules", keyvalues={"user_name": user_id}
        )
        self.db_pool.simple_delete_txn(
            txn, table="push_rules_enable", keyvalues={"user_name": user_id}
        )
        self.db_pool.simple_delete_txn(
            txn, table="push_rules_stream", keyvalues={"user_id": user_id}
        )

        # Invalidate caches as appropriate
        self._invalidate_cache_and_stream(
            txn, self.get_account_data_for_room_and_type, (user_id,)
        )
        self._invalidate_cache_and_stream(
            txn, self.get_account_data_for_user, (user_id,)
        )
        self._invalidate_cache_and_stream(
            txn, self.get_global_account_data_by_type_for_user, (user_id,)
        )
        self._invalidate_cache_and_stream(
            txn, self.get_account_data_for_room, (user_id,)
        )
        self._invalidate_cache_and_stream(txn, self.get_push_rules_for_user, (user_id,))
        # This user might be contained in the ignored_by cache for other users,
        # so we have to invalidate it all.
        self._invalidate_all_cache_and_stream(txn, self.ignored_by)

    async def _delete_account_data_for_deactivated_users(
        self, progress: dict, batch_size: int
    ) -> int:
        """
        Retroactively purges account data for users that have already been deactivated.
        Gets run as a background update caused by a schema delta.
        """

        last_user: str = progress.get("last_user", "")

        def _delete_account_data_for_deactivated_users_txn(
            txn: LoggingTransaction,
        ) -> int:
            sql = """
                SELECT name FROM users
                WHERE deactivated = ? and name > ?
                ORDER BY name ASC
                LIMIT ?
            """

            txn.execute(sql, (1, last_user, batch_size))
            users = [row[0] for row in txn]

            for user in users:
                self._purge_account_data_for_user_txn(txn, user_id=user)

            if users:
                self.db_pool.updates._background_update_progress_txn(
                    txn,
                    "delete_account_data_for_deactivated_users",
                    {"last_user": users[-1]},
                )

            return len(users)

        number_deleted = await self.db_pool.runInteraction(
            "_delete_account_data_for_deactivated_users",
            _delete_account_data_for_deactivated_users_txn,
        )

        if number_deleted < batch_size:
            await self.db_pool.updates._end_background_update(
                "delete_account_data_for_deactivated_users"
            )

        return number_deleted


class AccountDataStore(AccountDataWorkerStore):
    pass
