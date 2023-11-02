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
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    cast,
)

from synapse.push import PusherConfig, ThrottleParams
from synapse.replication.tcp.streams import PushersStream
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.util.id_generators import (
    AbstractStreamIdGenerator,
    StreamIdGenerator,
)
from synapse.types import JsonDict
from synapse.util import json_encoder
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# The type of a row in the pushers table.
PusherRow = Tuple[
    int,  # id
    str,  # user_name
    Optional[int],  # access_token
    str,  # profile_tag
    str,  # kind
    str,  # app_id
    str,  # app_display_name
    str,  # device_display_name
    str,  # pushkey
    int,  # ts
    str,  # lang
    str,  # data
    int,  # last_stream_ordering
    int,  # last_success
    int,  # failing_since
    bool,  # enabled
    str,  # device_id
]


class PusherWorkerStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # In the worker store this is an ID tracker which we overwrite in the non-worker
        # class below that is used on the main process.
        self._pushers_id_gen = StreamIdGenerator(
            db_conn,
            hs.get_replication_notifier(),
            "pushers",
            "id",
            extra_tables=[("deleted_pushers", "stream_id")],
            is_writer=hs.config.worker.worker_app is None,
        )

        self.db_pool.updates.register_background_update_handler(
            "remove_deactivated_pushers",
            self._remove_deactivated_pushers,
        )

        self.db_pool.updates.register_background_update_handler(
            "remove_stale_pushers",
            self._remove_stale_pushers,
        )

        self.db_pool.updates.register_background_update_handler(
            "remove_deleted_email_pushers",
            self._remove_deleted_email_pushers,
        )

    def _decode_pushers_rows(
        self,
        rows: Iterable[PusherRow],
    ) -> Iterator[PusherConfig]:
        """JSON-decode the data in the rows returned from the `pushers` table

        Drops any rows whose data cannot be decoded
        """
        for (
            id,
            user_name,
            access_token,
            profile_tag,
            kind,
            app_id,
            app_display_name,
            device_display_name,
            pushkey,
            ts,
            lang,
            data,
            last_stream_ordering,
            last_success,
            failing_since,
            enabled,
            device_id,
        ) in rows:
            try:
                data_json = db_to_json(data)
            except Exception as e:
                logger.warning(
                    "Invalid JSON in data for pusher %d: %s, %s",
                    id,
                    data,
                    e.args[0],
                )
                continue

            yield PusherConfig(
                id=id,
                user_name=user_name,
                profile_tag=profile_tag,
                kind=kind,
                app_id=app_id,
                app_display_name=app_display_name,
                device_display_name=device_display_name,
                pushkey=pushkey,
                ts=ts,
                lang=lang,
                data=data_json,
                last_stream_ordering=last_stream_ordering,
                last_success=last_success,
                failing_since=failing_since,
                # If we're using SQLite, then boolean values are integers. This is
                # troublesome since some code using the return value of this method might
                # expect it to be a boolean, or will expose it to clients (in responses).
                enabled=bool(enabled),
                device_id=device_id,
                access_token=access_token,
            )

    def get_pushers_stream_token(self) -> int:
        return self._pushers_id_gen.get_current_token()

    def process_replication_position(
        self, stream_name: str, instance_name: str, token: int
    ) -> None:
        if stream_name == PushersStream.NAME:
            self._pushers_id_gen.advance(instance_name, token)
        super().process_replication_position(stream_name, instance_name, token)

    async def get_pushers_by_app_id_and_pushkey(
        self, app_id: str, pushkey: str
    ) -> Iterator[PusherConfig]:
        return await self.get_pushers_by({"app_id": app_id, "pushkey": pushkey})

    async def get_pushers_by_user_id(self, user_id: str) -> Iterator[PusherConfig]:
        return await self.get_pushers_by({"user_name": user_id})

    async def get_pushers_by(self, keyvalues: Dict[str, Any]) -> Iterator[PusherConfig]:
        """Retrieve pushers that match the given criteria.

        Args:
            keyvalues: A {column: value} dictionary.

        Returns:
            The pushers for which the given columns have the given values.
        """

        def get_pushers_by_txn(txn: LoggingTransaction) -> List[PusherRow]:
            # We could technically use simple_select_list here, but we need to call
            # COALESCE on the 'enabled' column. While it is technically possible to give
            # simple_select_list the whole `COALESCE(...) AS ...` as a column name, it
            # feels a bit hacky, so it's probably better to just inline the query.
            sql = """
            SELECT
                id, user_name, access_token, profile_tag, kind, app_id,
                app_display_name, device_display_name, pushkey, ts, lang, data,
                last_stream_ordering, last_success, failing_since,
                COALESCE(enabled, TRUE) AS enabled, device_id
            FROM pushers
            """

            sql += "WHERE %s" % (" AND ".join("%s = ?" % (k,) for k in keyvalues),)

            txn.execute(sql, list(keyvalues.values()))

            return cast(List[PusherRow], txn.fetchall())

        ret = await self.db_pool.runInteraction(
            desc="get_pushers_by",
            func=get_pushers_by_txn,
        )

        return self._decode_pushers_rows(ret)

    async def get_enabled_pushers(self) -> Iterator[PusherConfig]:
        def get_enabled_pushers_txn(txn: LoggingTransaction) -> List[PusherRow]:
            txn.execute(
                """
                SELECT id, user_name, access_token, profile_tag, kind, app_id,
                    app_display_name, device_display_name, pushkey, ts, lang, data,
                    last_stream_ordering, last_success, failing_since,
                    enabled, device_id
                FROM pushers WHERE COALESCE(enabled, TRUE)
                """
            )
            return cast(List[PusherRow], txn.fetchall())

        return self._decode_pushers_rows(
            await self.db_pool.runInteraction(
                "get_enabled_pushers", get_enabled_pushers_txn
            )
        )

    async def get_all_updated_pushers_rows(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
        """Get updates for pushers replication stream.

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

        def get_all_updated_pushers_rows_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
            sql = """
                SELECT id, user_name, app_id, pushkey
                FROM pushers
                WHERE ? < id AND id <= ?
                ORDER BY id ASC LIMIT ?
            """
            txn.execute(sql, (last_id, current_id, limit))
            updates = cast(
                List[Tuple[int, tuple]],
                [
                    (stream_id, (user_name, app_id, pushkey, False))
                    for stream_id, user_name, app_id, pushkey in txn
                ],
            )

            sql = """
                SELECT stream_id, user_id, app_id, pushkey
                FROM deleted_pushers
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC LIMIT ?
            """
            txn.execute(sql, (last_id, current_id, limit))
            updates.extend(
                (stream_id, (user_name, app_id, pushkey, True))
                for stream_id, user_name, app_id, pushkey in txn
            )

            updates.sort()  # Sort so that they're ordered by stream id

            limited = False
            upper_bound = current_id
            if len(updates) >= limit:
                limited = True
                upper_bound = updates[-1][0]

            return updates, upper_bound, limited

        return await self.db_pool.runInteraction(
            "get_all_updated_pushers_rows", get_all_updated_pushers_rows_txn
        )

    @cached(num_args=1, max_entries=15000)
    async def get_if_user_has_pusher(self, user_id: str) -> None:
        # This only exists for the cachedList decorator
        raise NotImplementedError()

    async def update_pusher_last_stream_ordering(
        self, app_id: str, pushkey: str, user_id: str, last_stream_ordering: int
    ) -> None:
        await self.db_pool.simple_update_one(
            "pushers",
            {"app_id": app_id, "pushkey": pushkey, "user_name": user_id},
            {"last_stream_ordering": last_stream_ordering},
            desc="update_pusher_last_stream_ordering",
        )

    async def update_pusher_last_stream_ordering_and_success(
        self,
        app_id: str,
        pushkey: str,
        user_id: str,
        last_stream_ordering: int,
        last_success: int,
    ) -> bool:
        """Update the last stream ordering position we've processed up to for
        the given pusher.

        Args:
            app_id
            pushkey
            user_id
            last_stream_ordering
            last_success

        Returns:
            True if the pusher still exists; False if it has been deleted.
        """
        updated = await self.db_pool.simple_update(
            table="pushers",
            keyvalues={"app_id": app_id, "pushkey": pushkey, "user_name": user_id},
            updatevalues={
                "last_stream_ordering": last_stream_ordering,
                "last_success": last_success,
            },
            desc="update_pusher_last_stream_ordering_and_success",
        )

        return bool(updated)

    async def update_pusher_failing_since(
        self, app_id: str, pushkey: str, user_id: str, failing_since: Optional[int]
    ) -> None:
        await self.db_pool.simple_update(
            table="pushers",
            keyvalues={"app_id": app_id, "pushkey": pushkey, "user_name": user_id},
            updatevalues={"failing_since": failing_since},
            desc="update_pusher_failing_since",
        )

    async def get_throttle_params_by_room(
        self, pusher_id: int
    ) -> Dict[str, ThrottleParams]:
        res = cast(
            List[Tuple[str, Optional[int], Optional[int]]],
            await self.db_pool.simple_select_list(
                "pusher_throttle",
                {"pusher": pusher_id},
                ["room_id", "last_sent_ts", "throttle_ms"],
                desc="get_throttle_params_by_room",
            ),
        )

        params_by_room = {}
        for room_id, last_sent_ts, throttle_ms in res:
            params_by_room[room_id] = ThrottleParams(
                last_sent_ts or 0, throttle_ms or 0
            )

        return params_by_room

    async def set_throttle_params(
        self, pusher_id: int, room_id: str, params: ThrottleParams
    ) -> None:
        await self.db_pool.simple_upsert(
            "pusher_throttle",
            {"pusher": pusher_id, "room_id": room_id},
            {"last_sent_ts": params.last_sent_ts, "throttle_ms": params.throttle_ms},
            desc="set_throttle_params",
        )

    async def _remove_deactivated_pushers(self, progress: dict, batch_size: int) -> int:
        """A background update that deletes all pushers for deactivated users.

        Note that we don't proacively tell the pusherpool that we've deleted
        these (just because its a bit off a faff to do from here), but they will
        get cleaned up at the next restart
        """

        last_user = progress.get("last_user", "")

        def _delete_pushers(txn: LoggingTransaction) -> int:
            sql = """
                SELECT name FROM users
                WHERE deactivated = ? and name > ?
                ORDER BY name ASC
                LIMIT ?
            """

            txn.execute(sql, (1, last_user, batch_size))
            users = [row[0] for row in txn]

            self.db_pool.simple_delete_many_txn(
                txn,
                table="pushers",
                column="user_name",
                values=users,
                keyvalues={},
            )

            if users:
                self.db_pool.updates._background_update_progress_txn(
                    txn, "remove_deactivated_pushers", {"last_user": users[-1]}
                )

            return len(users)

        number_deleted = await self.db_pool.runInteraction(
            "_remove_deactivated_pushers", _delete_pushers
        )

        if number_deleted < batch_size:
            await self.db_pool.updates._end_background_update(
                "remove_deactivated_pushers"
            )

        return number_deleted

    async def _remove_stale_pushers(self, progress: dict, batch_size: int) -> int:
        """A background update that deletes all pushers for logged out devices.

        Note that we don't proacively tell the pusherpool that we've deleted
        these (just because its a bit off a faff to do from here), but they will
        get cleaned up at the next restart
        """

        last_pusher = progress.get("last_pusher", 0)

        def _delete_pushers(txn: LoggingTransaction) -> int:
            sql = """
                SELECT p.id, access_token FROM pushers AS p
                LEFT JOIN access_tokens AS a ON (p.access_token = a.id)
                WHERE p.id > ?
                ORDER BY p.id ASC
                LIMIT ?
            """

            txn.execute(sql, (last_pusher, batch_size))
            pushers = [(row[0], row[1]) for row in txn]

            self.db_pool.simple_delete_many_txn(
                txn,
                table="pushers",
                column="id",
                values=[pusher_id for pusher_id, token in pushers if token is None],
                keyvalues={},
            )

            if pushers:
                self.db_pool.updates._background_update_progress_txn(
                    txn, "remove_stale_pushers", {"last_pusher": pushers[-1][0]}
                )

            return len(pushers)

        number_deleted = await self.db_pool.runInteraction(
            "_remove_stale_pushers", _delete_pushers
        )

        if number_deleted < batch_size:
            await self.db_pool.updates._end_background_update("remove_stale_pushers")

        return number_deleted

    async def _remove_deleted_email_pushers(
        self, progress: dict, batch_size: int
    ) -> int:
        """A background update that deletes all pushers for deleted email addresses.

        In previous versions of synapse, when users deleted their email address, it didn't
        also delete all the pushers for that email address. This background update removes
        those to prevent unwanted emails. This should only need to be run once (when users
        upgrade to v1.42.0

        Args:
            progress: dict used to store progress of this background update
            batch_size: the maximum number of rows to retrieve in a single select query

        Returns:
            The number of deleted rows
        """

        last_pusher = progress.get("last_pusher", 0)

        def _delete_pushers(txn: LoggingTransaction) -> int:
            sql = """
                SELECT p.id, p.user_name, p.app_id, p.pushkey
                FROM pushers AS p
                    LEFT JOIN user_threepids AS t
                        ON t.user_id = p.user_name
                        AND t.medium = 'email'
                        AND t.address = p.pushkey
                WHERE t.user_id is NULL
                    AND p.app_id = 'm.email'
                    AND p.id > ?
                ORDER BY p.id ASC
                LIMIT ?
            """

            txn.execute(sql, (last_pusher, batch_size))
            rows = txn.fetchall()

            last = None
            num_deleted = 0
            for row in rows:
                last = row[0]
                num_deleted += 1
                self.db_pool.simple_delete_txn(
                    txn,
                    "pushers",
                    {"user_name": row[1], "app_id": row[2], "pushkey": row[3]},
                )

            if last is not None:
                self.db_pool.updates._background_update_progress_txn(
                    txn, "remove_deleted_email_pushers", {"last_pusher": last}
                )

            return num_deleted

        number_deleted = await self.db_pool.runInteraction(
            "_remove_deleted_email_pushers", _delete_pushers
        )

        if number_deleted < batch_size:
            await self.db_pool.updates._end_background_update(
                "remove_deleted_email_pushers"
            )

        return number_deleted


class PusherBackgroundUpdatesStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_update_handler(
            "set_device_id_for_pushers", self._set_device_id_for_pushers
        )

    async def _set_device_id_for_pushers(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """
        Background update to populate the device_id column and clear the access_token
        column for the pushers table.
        """
        last_pusher_id = progress.get("pusher_id", 0)

        def set_device_id_for_pushers_txn(txn: LoggingTransaction) -> int:
            txn.execute(
                """
                    SELECT
                        p.id AS pusher_id,
                        p.device_id AS pusher_device_id,
                        at.device_id AS token_device_id
                    FROM pushers AS p
                    LEFT JOIN access_tokens AS at
                        ON p.access_token = at.id
                    WHERE
                        p.access_token IS NOT NULL
                        AND p.id > ?
                    ORDER BY p.id
                    LIMIT ?
                """,
                (last_pusher_id, batch_size),
            )

            rows = cast(List[Tuple[int, Optional[str], Optional[str]]], txn.fetchall())
            if len(rows) == 0:
                return 0

            # The reason we're clearing the access_token column here is a bit subtle.
            # When a user logs out, we:
            #  (1) delete the access token
            #  (2) delete the device
            #
            # Ideally, we would delete the pushers only via its link to the device
            # during (2), but since this background update might not have fully run yet,
            # we're still deleting the pushers via the access token during (1).
            self.db_pool.simple_update_many_txn(
                txn=txn,
                table="pushers",
                key_names=("id",),
                key_values=[(row[0],) for row in rows],
                value_names=("device_id", "access_token"),
                # If there was already a device_id on the pusher, we only want to clear
                # the access_token column, so we keep the existing device_id. Otherwise,
                # we set the device_id we got from joining the access_tokens table.
                value_values=[
                    (pusher_device_id or token_device_id, None)
                    for _, pusher_device_id, token_device_id in rows
                ],
            )

            self.db_pool.updates._background_update_progress_txn(
                txn, "set_device_id_for_pushers", {"pusher_id": rows[-1][0]}
            )

            return len(rows)

        nb_processed = await self.db_pool.runInteraction(
            "set_device_id_for_pushers", set_device_id_for_pushers_txn
        )

        if nb_processed < batch_size:
            await self.db_pool.updates._end_background_update(
                "set_device_id_for_pushers"
            )

        return nb_processed


class PusherStore(PusherWorkerStore, PusherBackgroundUpdatesStore):
    # Because we have write access, this will be a StreamIdGenerator
    # (see PusherWorkerStore.__init__)
    _pushers_id_gen: AbstractStreamIdGenerator

    async def add_pusher(
        self,
        user_id: str,
        kind: str,
        app_id: str,
        app_display_name: str,
        device_display_name: str,
        pushkey: str,
        pushkey_ts: int,
        lang: Optional[str],
        data: Optional[JsonDict],
        last_stream_ordering: int,
        profile_tag: str = "",
        enabled: bool = True,
        device_id: Optional[str] = None,
        access_token_id: Optional[int] = None,
    ) -> None:
        async with self._pushers_id_gen.get_next() as stream_id:
            await self.db_pool.simple_upsert(
                table="pushers",
                keyvalues={"app_id": app_id, "pushkey": pushkey, "user_name": user_id},
                values={
                    "kind": kind,
                    "app_display_name": app_display_name,
                    "device_display_name": device_display_name,
                    "ts": pushkey_ts,
                    "lang": lang,
                    "data": json_encoder.encode(data),
                    "last_stream_ordering": last_stream_ordering,
                    "profile_tag": profile_tag,
                    "id": stream_id,
                    "enabled": enabled,
                    "device_id": device_id,
                    # XXX(quenting): We're only really persisting the access token ID
                    # when updating an existing pusher. This is in case the
                    # 'set_device_id_for_pushers' background update hasn't finished yet.
                    "access_token": access_token_id,
                },
                desc="add_pusher",
            )

            user_has_pusher = self.get_if_user_has_pusher.cache.get_immediate(
                (user_id,), None, update_metrics=False
            )

            if user_has_pusher is not True:
                # invalidate, since we the user might not have had a pusher before
                await self.db_pool.runInteraction(
                    "add_pusher",
                    self._invalidate_cache_and_stream,  # type: ignore[attr-defined]
                    self.get_if_user_has_pusher,
                    (user_id,),
                )

    async def delete_pusher_by_app_id_pushkey_user_id(
        self, app_id: str, pushkey: str, user_id: str
    ) -> None:
        def delete_pusher_txn(txn: LoggingTransaction, stream_id: int) -> None:
            self._invalidate_cache_and_stream(  # type: ignore[attr-defined]
                txn, self.get_if_user_has_pusher, (user_id,)
            )

            # It is expected that there is exactly one pusher to delete, but
            # if it isn't there (or there are multiple) delete them all.
            self.db_pool.simple_delete_txn(
                txn,
                "pushers",
                {"app_id": app_id, "pushkey": pushkey, "user_name": user_id},
            )

            # it's possible for us to end up with duplicate rows for
            # (app_id, pushkey, user_id) at different stream_ids, but that
            # doesn't really matter.
            self.db_pool.simple_insert_txn(
                txn,
                table="deleted_pushers",
                values={
                    "stream_id": stream_id,
                    "app_id": app_id,
                    "pushkey": pushkey,
                    "user_id": user_id,
                },
            )

        async with self._pushers_id_gen.get_next() as stream_id:
            await self.db_pool.runInteraction(
                "delete_pusher", delete_pusher_txn, stream_id
            )

    async def delete_all_pushers_for_user(self, user_id: str) -> None:
        """Delete all pushers associated with an account."""

        # We want to generate a row in `deleted_pushers` for each pusher we're
        # deleting, so we fetch the list now so we can generate the appropriate
        # number of stream IDs.
        #
        # Note: technically there could be a race here between adding/deleting
        # pushers, but a) the worst case if we don't stop a pusher until the
        # next restart and b) this is only called when we're deactivating an
        # account.
        pushers = list(await self.get_pushers_by_user_id(user_id))

        def delete_pushers_txn(txn: LoggingTransaction, stream_ids: List[int]) -> None:
            self._invalidate_cache_and_stream(  # type: ignore[attr-defined]
                txn, self.get_if_user_has_pusher, (user_id,)
            )

            self.db_pool.simple_delete_txn(
                txn,
                table="pushers",
                keyvalues={"user_name": user_id},
            )

            self.db_pool.simple_insert_many_txn(
                txn,
                table="deleted_pushers",
                keys=("stream_id", "app_id", "pushkey", "user_id"),
                values=[
                    (stream_id, pusher.app_id, pusher.pushkey, user_id)
                    for stream_id, pusher in zip(stream_ids, pushers)
                ],
            )

        async with self._pushers_id_gen.get_next_mult(len(pushers)) as stream_ids:
            await self.db_pool.runInteraction(
                "delete_all_pushers_for_user", delete_pushers_txn, stream_ids
            )
