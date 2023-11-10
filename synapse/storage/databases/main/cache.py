# Copyright 2019 The Matrix.org Foundation C.I.C.
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


import itertools
import logging
from typing import TYPE_CHECKING, Any, Collection, Iterable, List, Optional, Tuple

from synapse.api.constants import EventTypes
from synapse.config._base import Config
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.replication.tcp.streams import BackfillStream, CachesStream
from synapse.replication.tcp.streams.events import (
    EventsStream,
    EventsStreamAllStateRow,
    EventsStreamCurrentStateRow,
    EventsStreamEventRow,
    EventsStreamRow,
)
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.engines import PostgresEngine
from synapse.storage.util.id_generators import MultiWriterIdGenerator
from synapse.util.caches.descriptors import CachedFunction
from synapse.util.iterutils import batch_iter

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# This is a special cache name we use to batch multiple invalidations of caches
# based on the current state when notifying workers over replication.
CURRENT_STATE_CACHE_NAME = "cs_cache_fake"

# As above, but for invalidating event caches on history deletion
PURGE_HISTORY_CACHE_NAME = "ph_cache_fake"

# As above, but for invalidating room caches on room deletion
DELETE_ROOM_CACHE_NAME = "dr_cache_fake"

# How long between cache invalidation table cleanups, once we have caught up
# with the backlog.
REGULAR_CLEANUP_INTERVAL_MS = Config.parse_duration("1h")

# How long between cache invalidation table cleanups, before we have caught
# up with the backlog.
CATCH_UP_CLEANUP_INTERVAL_MS = Config.parse_duration("1m")

# Maximum number of cache invalidation rows to delete at once.
CLEAN_UP_MAX_BATCH_SIZE = 20_000

# Keep cache invalidations for 7 days
# (This is likely to be quite excessive.)
RETENTION_PERIOD_OF_CACHE_INVALIDATIONS_MS = Config.parse_duration("7d")


class CacheInvalidationWorkerStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self._instance_name = hs.get_instance_name()

        self.db_pool.updates.register_background_index_update(
            update_name="cache_invalidation_index_by_instance",
            index_name="cache_invalidation_stream_by_instance_instance_index",
            table="cache_invalidation_stream_by_instance",
            columns=("instance_name", "stream_id"),
            psql_only=True,  # The table is only on postgres DBs.
        )

        self._cache_id_gen: Optional[MultiWriterIdGenerator]
        if isinstance(self.database_engine, PostgresEngine):
            # We set the `writers` to an empty list here as we don't care about
            # missing updates over restarts, as we'll not have anything in our
            # caches to invalidate. (This reduces the amount of writes to the DB
            # that happen).
            self._cache_id_gen = MultiWriterIdGenerator(
                db_conn,
                database,
                notifier=hs.get_replication_notifier(),
                stream_name="caches",
                instance_name=hs.get_instance_name(),
                tables=[
                    (
                        "cache_invalidation_stream_by_instance",
                        "instance_name",
                        "stream_id",
                    )
                ],
                sequence_name="cache_invalidation_stream_seq",
                writers=[],
            )

        else:
            self._cache_id_gen = None

        # Occasionally clean up the cache invalidations stream table by deleting
        # old rows.
        # This is only applicable when Postgres is in use; this table is unused
        # and not populated at all when SQLite is the active database engine.
        if hs.config.worker.run_background_tasks and isinstance(
            self.database_engine, PostgresEngine
        ):
            self.hs.get_clock().call_later(
                CATCH_UP_CLEANUP_INTERVAL_MS / 1000,
                self._clean_up_cache_invalidation_wrapper,
            )

    async def get_all_updated_caches(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
        """Get updates for caches replication stream.

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

        def get_all_updated_caches_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
            # We purposefully don't bound by the current token, as we want to
            # send across cache invalidations as quickly as possible. Cache
            # invalidations are idempotent, so duplicates are fine.
            sql = """
                SELECT stream_id, cache_func, keys, invalidation_ts
                FROM cache_invalidation_stream_by_instance
                WHERE stream_id > ? AND instance_name = ?
                ORDER BY stream_id ASC
                LIMIT ?
            """
            txn.execute(sql, (last_id, instance_name, limit))
            updates = [(row[0], row[1:]) for row in txn]
            limited = False
            upto_token = current_id
            if len(updates) >= limit:
                upto_token = updates[-1][0]
                limited = True

            return updates, upto_token, limited

        return await self.db_pool.runInteraction(
            "get_all_updated_caches", get_all_updated_caches_txn
        )

    def process_replication_rows(
        self, stream_name: str, instance_name: str, token: int, rows: Iterable[Any]
    ) -> None:
        if stream_name == EventsStream.NAME:
            for row in rows:
                self._process_event_stream_row(token, row)
        elif stream_name == BackfillStream.NAME:
            for row in rows:
                self._invalidate_caches_for_event(
                    -token,
                    row.event_id,
                    row.room_id,
                    row.type,
                    row.state_key,
                    row.redacts,
                    row.relates_to,
                    backfilled=True,
                )
        elif stream_name == CachesStream.NAME:
            for row in rows:
                if row.cache_func == CURRENT_STATE_CACHE_NAME:
                    if row.keys is None:
                        raise Exception(
                            "Can't send an 'invalidate all' for current state cache"
                        )

                    room_id = row.keys[0]
                    members_changed = set(row.keys[1:])
                    self._invalidate_state_caches(room_id, members_changed)
                elif row.cache_func == PURGE_HISTORY_CACHE_NAME:
                    if row.keys is None:
                        raise Exception(
                            "Can't send an 'invalidate all' for 'purge history' cache"
                        )

                    room_id = row.keys[0]
                    self._invalidate_caches_for_room_events(room_id)
                elif row.cache_func == DELETE_ROOM_CACHE_NAME:
                    if row.keys is None:
                        raise Exception(
                            "Can't send an 'invalidate all' for 'delete room' cache"
                        )

                    room_id = row.keys[0]
                    self._invalidate_caches_for_room_events(room_id)
                    self._invalidate_caches_for_room(room_id)
                else:
                    self._attempt_to_invalidate_cache(row.cache_func, row.keys)

        super().process_replication_rows(stream_name, instance_name, token, rows)

    def process_replication_position(
        self, stream_name: str, instance_name: str, token: int
    ) -> None:
        if stream_name == CachesStream.NAME:
            if self._cache_id_gen:
                self._cache_id_gen.advance(instance_name, token)
        super().process_replication_position(stream_name, instance_name, token)

    def _process_event_stream_row(self, token: int, row: EventsStreamRow) -> None:
        data = row.data

        if row.type == EventsStreamEventRow.TypeId:
            assert isinstance(data, EventsStreamEventRow)
            self._invalidate_caches_for_event(
                token,
                data.event_id,
                data.room_id,
                data.type,
                data.state_key,
                data.redacts,
                data.relates_to,
                backfilled=False,
            )
        elif row.type == EventsStreamCurrentStateRow.TypeId:
            assert isinstance(data, EventsStreamCurrentStateRow)
            self._curr_state_delta_stream_cache.entity_has_changed(data.room_id, token)  # type: ignore[attr-defined]

            if data.type == EventTypes.Member:
                self.get_rooms_for_user_with_stream_ordering.invalidate(  # type: ignore[attr-defined]
                    (data.state_key,)
                )
                self.get_rooms_for_user.invalidate((data.state_key,))  # type: ignore[attr-defined]
        elif row.type == EventsStreamAllStateRow.TypeId:
            assert isinstance(data, EventsStreamAllStateRow)
            # Similar to the above, but the entire caches are invalidated. This is
            # unfortunate for the membership caches, but should recover quickly.
            self._curr_state_delta_stream_cache.entity_has_changed(data.room_id, token)  # type: ignore[attr-defined]
            self.get_rooms_for_user_with_stream_ordering.invalidate_all()  # type: ignore[attr-defined]
            self.get_rooms_for_user.invalidate_all()  # type: ignore[attr-defined]
        else:
            raise Exception("Unknown events stream row type %s" % (row.type,))

    def _invalidate_caches_for_event(
        self,
        stream_ordering: int,
        event_id: str,
        room_id: str,
        etype: str,
        state_key: Optional[str],
        redacts: Optional[str],
        relates_to: Optional[str],
        backfilled: bool,
    ) -> None:
        # XXX: If you add something to this function make sure you add it to
        # `_invalidate_caches_for_room_events` as well.

        # This invalidates any local in-memory cached event objects, the original
        # process triggering the invalidation is responsible for clearing any external
        # cached objects.
        self._invalidate_local_get_event_cache(event_id)  # type: ignore[attr-defined]

        self._attempt_to_invalidate_cache("have_seen_event", (room_id, event_id))
        self._attempt_to_invalidate_cache("get_latest_event_ids_in_room", (room_id,))
        self._attempt_to_invalidate_cache(
            "get_unread_event_push_actions_by_room_for_user", (room_id,)
        )

        # The `_get_membership_from_event_id` is immutable, except for the
        # case where we look up an event *before* persisting it.
        self._attempt_to_invalidate_cache("_get_membership_from_event_id", (event_id,))

        if not backfilled:
            self._events_stream_cache.entity_has_changed(room_id, stream_ordering)  # type: ignore[attr-defined]

        if redacts:
            self._invalidate_local_get_event_cache(redacts)  # type: ignore[attr-defined]
            # Caches which might leak edits must be invalidated for the event being
            # redacted.
            self._attempt_to_invalidate_cache("get_relations_for_event", (redacts,))
            self._attempt_to_invalidate_cache("get_applicable_edit", (redacts,))
            self._attempt_to_invalidate_cache("get_thread_id", (redacts,))
            self._attempt_to_invalidate_cache("get_thread_id_for_receipts", (redacts,))

        if etype == EventTypes.Member:
            self._membership_stream_cache.entity_has_changed(state_key, stream_ordering)  # type: ignore[attr-defined]
            self._attempt_to_invalidate_cache(
                "get_invited_rooms_for_local_user", (state_key,)
            )
            self._attempt_to_invalidate_cache(
                "get_rooms_for_user_with_stream_ordering", (state_key,)
            )
            self._attempt_to_invalidate_cache("get_rooms_for_user", (state_key,))

            self._attempt_to_invalidate_cache(
                "did_forget",
                (
                    state_key,
                    room_id,
                ),
            )
            self._attempt_to_invalidate_cache(
                "get_forgotten_rooms_for_user", (state_key,)
            )

        if relates_to:
            self._attempt_to_invalidate_cache("get_relations_for_event", (relates_to,))
            self._attempt_to_invalidate_cache("get_references_for_event", (relates_to,))
            self._attempt_to_invalidate_cache("get_applicable_edit", (relates_to,))
            self._attempt_to_invalidate_cache("get_thread_summary", (relates_to,))
            self._attempt_to_invalidate_cache("get_thread_participated", (relates_to,))
            self._attempt_to_invalidate_cache("get_threads", (room_id,))

    def _invalidate_caches_for_room_events_and_stream(
        self, txn: LoggingTransaction, room_id: str
    ) -> None:
        """Invalidate caches associated with events in a room, and stream to
        replication.

        Used when we delete events a room, but don't know which events we've
        deleted.
        """

        self._send_invalidation_to_replication(txn, PURGE_HISTORY_CACHE_NAME, [room_id])
        txn.call_after(self._invalidate_caches_for_room_events, room_id)

    def _invalidate_caches_for_room_events(self, room_id: str) -> None:
        """Invalidate caches associated with events in a room, and stream to
        replication.

        Used when we delete events in a room, but don't know which events we've
        deleted.
        """

        self._invalidate_local_get_event_cache_all()  # type: ignore[attr-defined]

        self._attempt_to_invalidate_cache("have_seen_event", (room_id,))
        self._attempt_to_invalidate_cache("get_latest_event_ids_in_room", (room_id,))
        self._attempt_to_invalidate_cache(
            "get_unread_event_push_actions_by_room_for_user", (room_id,)
        )

        self._attempt_to_invalidate_cache("_get_membership_from_event_id", None)
        self._attempt_to_invalidate_cache("get_relations_for_event", None)
        self._attempt_to_invalidate_cache("get_applicable_edit", None)
        self._attempt_to_invalidate_cache("get_thread_id", None)
        self._attempt_to_invalidate_cache("get_thread_id_for_receipts", None)
        self._attempt_to_invalidate_cache("get_invited_rooms_for_local_user", None)
        self._attempt_to_invalidate_cache(
            "get_rooms_for_user_with_stream_ordering", None
        )
        self._attempt_to_invalidate_cache("get_rooms_for_user", None)
        self._attempt_to_invalidate_cache("did_forget", None)
        self._attempt_to_invalidate_cache("get_forgotten_rooms_for_user", None)
        self._attempt_to_invalidate_cache("get_references_for_event", None)
        self._attempt_to_invalidate_cache("get_thread_summary", None)
        self._attempt_to_invalidate_cache("get_thread_participated", None)
        self._attempt_to_invalidate_cache("get_threads", (room_id,))

        self._attempt_to_invalidate_cache("_get_state_group_for_event", None)

        self._attempt_to_invalidate_cache("get_event_ordering", None)
        self._attempt_to_invalidate_cache("is_partial_state_event", None)
        self._attempt_to_invalidate_cache("_get_joined_profile_from_event_id", None)

    def _invalidate_caches_for_room_and_stream(
        self, txn: LoggingTransaction, room_id: str
    ) -> None:
        """Invalidate caches associated with rooms, and stream to replication.

        Used when we delete rooms.
        """

        self._send_invalidation_to_replication(txn, DELETE_ROOM_CACHE_NAME, [room_id])
        txn.call_after(self._invalidate_caches_for_room, room_id)

    def _invalidate_caches_for_room(self, room_id: str) -> None:
        """Invalidate caches associated with rooms.

        Used when we delete rooms.
        """

        # If we've deleted the room then we also need to purge all event caches.
        self._invalidate_caches_for_room_events(room_id)

        self._attempt_to_invalidate_cache("get_account_data_for_room", None)
        self._attempt_to_invalidate_cache("get_account_data_for_room_and_type", None)
        self._attempt_to_invalidate_cache("get_aliases_for_room", (room_id,))
        self._attempt_to_invalidate_cache("get_latest_event_ids_in_room", (room_id,))
        self._attempt_to_invalidate_cache("_get_forward_extremeties_for_room", None)
        self._attempt_to_invalidate_cache(
            "get_unread_event_push_actions_by_room_for_user", (room_id,)
        )
        self._attempt_to_invalidate_cache(
            "_get_linearized_receipts_for_room", (room_id,)
        )
        self._attempt_to_invalidate_cache("is_room_blocked", (room_id,))
        self._attempt_to_invalidate_cache("get_retention_policy_for_room", (room_id,))
        self._attempt_to_invalidate_cache(
            "_get_partial_state_servers_at_join", (room_id,)
        )
        self._attempt_to_invalidate_cache("is_partial_state_room", (room_id,))
        self._attempt_to_invalidate_cache("get_invited_rooms_for_local_user", None)
        self._attempt_to_invalidate_cache(
            "get_current_hosts_in_room_ordered", (room_id,)
        )
        self._attempt_to_invalidate_cache("did_forget", None)
        self._attempt_to_invalidate_cache("get_forgotten_rooms_for_user", None)
        self._attempt_to_invalidate_cache("_get_membership_from_event_id", None)
        self._attempt_to_invalidate_cache("get_room_version_id", (room_id,))

        # And delete state caches.

        self._invalidate_state_caches_all(room_id)

    async def invalidate_cache_and_stream(
        self, cache_name: str, keys: Tuple[Any, ...]
    ) -> None:
        """Invalidates the cache and adds it to the cache stream so other workers
        will know to invalidate their caches.

        This should only be used to invalidate caches where other workers won't
        otherwise have known from other replication streams that the cache should
        be invalidated.
        """
        cache_func = getattr(self, cache_name, None)
        if not cache_func:
            return

        cache_func.invalidate(keys)
        await self.send_invalidation_to_replication(
            cache_func.__name__,
            keys,
        )

    def _invalidate_cache_and_stream(
        self,
        txn: LoggingTransaction,
        cache_func: CachedFunction,
        keys: Tuple[Any, ...],
    ) -> None:
        """Invalidates the cache and adds it to the cache stream so other workers
        will know to invalidate their caches.

        This should only be used to invalidate caches where other workers won't
        otherwise have known from other replication streams that the cache should
        be invalidated.
        """
        txn.call_after(cache_func.invalidate, keys)
        self._send_invalidation_to_replication(txn, cache_func.__name__, keys)

    def _invalidate_cache_and_stream_bulk(
        self,
        txn: LoggingTransaction,
        cache_func: CachedFunction,
        key_tuples: Collection[Tuple[Any, ...]],
    ) -> None:
        """A bulk version of _invalidate_cache_and_stream.

        Locally invalidate every key-tuple in `key_tuples`, then emit invalidations
        for each key-tuple over replication.

        This implementation is more efficient than a loop which repeatedly calls the
        non-bulk version.
        """
        if not key_tuples:
            return

        for keys in key_tuples:
            txn.call_after(cache_func.invalidate, keys)

        self._send_invalidation_to_replication_bulk(
            txn, cache_func.__name__, key_tuples
        )

    def _invalidate_all_cache_and_stream(
        self, txn: LoggingTransaction, cache_func: CachedFunction
    ) -> None:
        """Invalidates the entire cache and adds it to the cache stream so other workers
        will know to invalidate their caches.
        """

        txn.call_after(cache_func.invalidate_all)
        self._send_invalidation_to_replication(txn, cache_func.__name__, None)

    def _invalidate_state_caches_and_stream(
        self, txn: LoggingTransaction, room_id: str, members_changed: Collection[str]
    ) -> None:
        """Special case invalidation of caches based on current state.

        We special case this so that we can batch the cache invalidations into a
        single replication poke.

        Args:
            txn
            room_id: Room where state changed
            members_changed: The user_ids of members that have changed
        """
        txn.call_after(self._invalidate_state_caches, room_id, members_changed)

        if members_changed:
            # We need to be careful that the size of the `members_changed` list
            # isn't so large that it causes problems sending over replication, so we
            # send them in chunks.
            # Max line length is 16K, and max user ID length is 255, so 50 should
            # be safe.
            for chunk in batch_iter(members_changed, 50):
                keys = itertools.chain([room_id], chunk)
                self._send_invalidation_to_replication(
                    txn, CURRENT_STATE_CACHE_NAME, keys
                )
        else:
            # if no members changed, we still need to invalidate the other caches.
            self._send_invalidation_to_replication(
                txn, CURRENT_STATE_CACHE_NAME, [room_id]
            )

    async def send_invalidation_to_replication(
        self, cache_name: str, keys: Optional[Collection[Any]]
    ) -> None:
        await self.db_pool.runInteraction(
            "send_invalidation_to_replication",
            self._send_invalidation_to_replication,
            cache_name,
            keys,
        )

    def _send_invalidation_to_replication(
        self, txn: LoggingTransaction, cache_name: str, keys: Optional[Iterable[Any]]
    ) -> None:
        """Notifies replication that given cache has been invalidated.

        Note that this does *not* invalidate the cache locally.

        Args:
            txn
            cache_name
            keys: Entry to invalidate. If None will invalidate all.
        """

        if cache_name == CURRENT_STATE_CACHE_NAME and keys is None:
            raise Exception(
                "Can't stream invalidate all with magic current state cache"
            )

        if cache_name == PURGE_HISTORY_CACHE_NAME and keys is None:
            raise Exception(
                "Can't stream invalidate all with magic purge history cache"
            )

        if cache_name == DELETE_ROOM_CACHE_NAME and keys is None:
            raise Exception("Can't stream invalidate all with magic delete room cache")

        if isinstance(self.database_engine, PostgresEngine):
            assert self._cache_id_gen is not None

            stream_id = self._cache_id_gen.get_next_txn(txn)
            txn.call_after(self.hs.get_notifier().on_new_replication_data)

            if keys is not None:
                keys = list(keys)

            self.db_pool.simple_insert_txn(
                txn,
                table="cache_invalidation_stream_by_instance",
                values={
                    "stream_id": stream_id,
                    "instance_name": self._instance_name,
                    "cache_func": cache_name,
                    "keys": keys,
                    "invalidation_ts": self._clock.time_msec(),
                },
            )

    def _send_invalidation_to_replication_bulk(
        self,
        txn: LoggingTransaction,
        cache_name: str,
        key_tuples: Collection[Tuple[Any, ...]],
    ) -> None:
        """Announce the invalidation of multiple (but not all) cache entries.

        This is more efficient than repeated calls to the non-bulk version. It should
        NOT be used to invalidating the entire cache: use
        `_send_invalidation_to_replication` with keys=None.

        Note that this does *not* invalidate the cache locally.

        Args:
            txn
            cache_name
            key_tuples: Key-tuples to invalidate. Assumed to be non-empty.
        """
        if isinstance(self.database_engine, PostgresEngine):
            assert self._cache_id_gen is not None

            stream_ids = self._cache_id_gen.get_next_mult_txn(txn, len(key_tuples))
            ts = self._clock.time_msec()
            txn.call_after(self.hs.get_notifier().on_new_replication_data)
            self.db_pool.simple_insert_many_txn(
                txn,
                table="cache_invalidation_stream_by_instance",
                keys=(
                    "stream_id",
                    "instance_name",
                    "cache_func",
                    "keys",
                    "invalidation_ts",
                ),
                values=[
                    # We convert key_tuples to a list here because psycopg2 serialises
                    # lists as pq arrrays, but serialises tuples as "composite types".
                    # (We need an array because the `keys` column has type `[]text`.)
                    # See:
                    #     https://www.psycopg.org/docs/usage.html#adapt-list
                    #     https://www.psycopg.org/docs/usage.html#adapt-tuple
                    (stream_id, self._instance_name, cache_name, list(key_tuple), ts)
                    for stream_id, key_tuple in zip(stream_ids, key_tuples)
                ],
            )

    def get_cache_stream_token_for_writer(self, instance_name: str) -> int:
        if self._cache_id_gen:
            return self._cache_id_gen.get_current_token_for_writer(instance_name)
        else:
            return 0

    @wrap_as_background_process("clean_up_old_cache_invalidations")
    async def _clean_up_cache_invalidation_wrapper(self) -> None:
        """
        Clean up cache invalidation stream table entries occasionally.
        If we are behind (i.e. there are entries old enough to
        be deleted but too many of them to be deleted in one go),
        then we run slightly more frequently.
        """
        delete_up_to: int = (
            self.hs.get_clock().time_msec() - RETENTION_PERIOD_OF_CACHE_INVALIDATIONS_MS
        )

        in_backlog = await self._clean_up_batch_of_old_cache_invalidations(delete_up_to)

        # Vary how long we wait before calling again depending on whether we
        # are still sifting through backlog or we have caught up.
        if in_backlog:
            next_interval = CATCH_UP_CLEANUP_INTERVAL_MS
        else:
            next_interval = REGULAR_CLEANUP_INTERVAL_MS

        self.hs.get_clock().call_later(
            next_interval / 1000, self._clean_up_cache_invalidation_wrapper
        )

    async def _clean_up_batch_of_old_cache_invalidations(
        self, delete_up_to_millisec: int
    ) -> bool:
        """
        Remove old rows from the `cache_invalidation_stream_by_instance` table automatically (this table is unused in SQLite).

        Up to `CLEAN_UP_BATCH_SIZE` rows will be deleted at once.

        Returns true if and only if we were limited by batch size (i.e. we are in backlog:
        there are more things to clean up).
        """

        def _clean_up_batch_of_old_cache_invalidations_txn(
            txn: LoggingTransaction,
        ) -> bool:
            # First get the earliest stream ID
            txn.execute(
                """
                SELECT stream_id FROM cache_invalidation_stream_by_instance
                ORDER BY stream_id ASC
                LIMIT 1
                """
            )
            row = txn.fetchone()
            if row is None:
                return False
            earliest_stream_id: int = row[0]

            # Then find the last stream ID of the range we will delete
            txn.execute(
                """
                SELECT stream_id FROM cache_invalidation_stream_by_instance
                WHERE stream_id <= ? AND invalidation_ts <= ?
                ORDER BY stream_id DESC
                LIMIT 1
                """,
                (earliest_stream_id + CLEAN_UP_MAX_BATCH_SIZE, delete_up_to_millisec),
            )
            row = txn.fetchone()
            if row is None:
                return False
            cutoff_stream_id: int = row[0]

            # Determine whether we are caught up or still catching up
            txn.execute(
                """
                SELECT invalidation_ts FROM cache_invalidation_stream_by_instance
                WHERE stream_id > ?
                ORDER BY stream_id ASC
                LIMIT 1
                """,
                (cutoff_stream_id,),
            )
            row = txn.fetchone()
            if row is None:
                in_backlog = False
            else:
                # We are in backlog if the next row could have been deleted
                # if we didn't have such a small batch size
                in_backlog = row[0] <= delete_up_to_millisec

            txn.execute(
                """
                DELETE FROM cache_invalidation_stream_by_instance
                WHERE ? <= stream_id AND stream_id <= ?
                """,
                (earliest_stream_id, cutoff_stream_id),
            )

            return in_backlog

        return await self.db_pool.runInteraction(
            "clean_up_old_cache_invalidations",
            _clean_up_batch_of_old_cache_invalidations_txn,
        )
