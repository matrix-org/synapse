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
import json
from contextlib import contextmanager
from typing import Generator, List, Tuple
from unittest import mock

from twisted.enterprise.adbapi import ConnectionPool
from twisted.internet.defer import CancelledError, Deferred, ensureDeferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.room_versions import EventFormatVersions, RoomVersions
from synapse.events import make_event_from_dict
from synapse.logging.context import LoggingContext
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.storage.databases.main.events_worker import (
    EVENT_QUEUE_THREADS,
    EventsWorkerStore,
)
from synapse.storage.types import Connection
from synapse.util import Clock
from synapse.util.async_helpers import yieldable_gather_results

from tests import unittest
from tests.test_utils.event_injection import create_event, inject_event


class HaveSeenEventsTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.hs = hs
        self.store: EventsWorkerStore = hs.get_datastores().main

        self.user = self.register_user("user", "pass")
        self.token = self.login(self.user, "pass")
        self.room_id = self.helper.create_room_as(self.user, tok=self.token)

        self.event_ids: List[str] = []
        for i in range(3):
            event = self.get_success(
                inject_event(
                    hs,
                    room_version=RoomVersions.V7.identifier,
                    room_id=self.room_id,
                    sender=self.user,
                    type="test_event_type",
                    content={"body": f"foobarbaz{i}"},
                )
            )

            self.event_ids.append(event.event_id)

    def test_simple(self):
        with LoggingContext(name="test") as ctx:
            res = self.get_success(
                self.store.have_seen_events(
                    self.room_id, [self.event_ids[0], "eventdoesnotexist"]
                )
            )
            self.assertEqual(res, {self.event_ids[0]})

            # that should result in a single db query
            self.assertEqual(ctx.get_resource_usage().db_txn_count, 1)

        # a second lookup of the same events should cause no queries
        with LoggingContext(name="test") as ctx:
            res = self.get_success(
                self.store.have_seen_events(
                    self.room_id, [self.event_ids[0], "eventdoesnotexist"]
                )
            )
            self.assertEqual(res, {self.event_ids[0]})
            self.assertEqual(ctx.get_resource_usage().db_txn_count, 0)

    def test_persisting_event_invalidates_cache(self):
        """
        Test to make sure that the `have_seen_event` cache
        is invalidated after we persist an event and returns
        the updated value.
        """
        event, event_context = self.get_success(
            create_event(
                self.hs,
                room_id=self.room_id,
                sender=self.user,
                type="test_event_type",
                content={"body": "garply"},
            )
        )

        with LoggingContext(name="test") as ctx:
            # First, check `have_seen_event` for an event we have not seen yet
            # to prime the cache with a `false` value.
            res = self.get_success(
                self.store.have_seen_events(event.room_id, [event.event_id])
            )
            self.assertEqual(res, set())

            # That should result in a single db query to lookup
            self.assertEqual(ctx.get_resource_usage().db_txn_count, 1)

        # Persist the event which should invalidate or prefill the
        # `have_seen_event` cache so we don't return stale values.
        persistence = self.hs.get_storage_controllers().persistence
        self.get_success(
            persistence.persist_event(
                event,
                event_context,
            )
        )

        with LoggingContext(name="test") as ctx:
            # Check `have_seen_event` again and we should see the updated fact
            # that we have now seen the event after persisting it.
            res = self.get_success(
                self.store.have_seen_events(event.room_id, [event.event_id])
            )
            self.assertEqual(res, {event.event_id})

            # That should result in a single db query to lookup
            self.assertEqual(ctx.get_resource_usage().db_txn_count, 1)

    def test_invalidate_cache_by_room_id(self):
        """
        Test to make sure that all events associated with the given `(room_id,)`
        are invalidated in the `have_seen_event` cache.
        """
        with LoggingContext(name="test") as ctx:
            # Prime the cache with some values
            res = self.get_success(
                self.store.have_seen_events(self.room_id, self.event_ids)
            )
            self.assertEqual(res, set(self.event_ids))

            # That should result in a single db query to lookup
            self.assertEqual(ctx.get_resource_usage().db_txn_count, 1)

        # Clear the cache with any events associated with the `room_id`
        self.store.have_seen_event.invalidate((self.room_id,))

        with LoggingContext(name="test") as ctx:
            res = self.get_success(
                self.store.have_seen_events(self.room_id, self.event_ids)
            )
            self.assertEqual(res, set(self.event_ids))

            # Since we cleared the cache, it should result in another db query to lookup
            self.assertEqual(ctx.get_resource_usage().db_txn_count, 1)


class EventCacheTestCase(unittest.HomeserverTestCase):
    """Test that the various layers of event cache works."""

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store: EventsWorkerStore = hs.get_datastores().main

        self.user = self.register_user("user", "pass")
        self.token = self.login(self.user, "pass")

        self.room = self.helper.create_room_as(self.user, tok=self.token)

        res = self.helper.send(self.room, tok=self.token)
        self.event_id = res["event_id"]

        # Reset the event cache so the tests start with it empty
        self.get_success(self.store._get_event_cache.clear())

    def test_simple(self):
        """Test that we cache events that we pull from the DB."""

        with LoggingContext("test") as ctx:
            self.get_success(self.store.get_event(self.event_id))

            # We should have fetched the event from the DB
            self.assertEqual(ctx.get_resource_usage().evt_db_fetch_count, 1)

    def test_event_ref(self):
        """Test that we reuse events that are still in memory but have fallen
        out of the cache, rather than requesting them from the DB.
        """

        # Reset the event cache
        self.get_success(self.store._get_event_cache.clear())

        with LoggingContext("test") as ctx:
            # We keep hold of the event event though we never use it.
            event = self.get_success(self.store.get_event(self.event_id))  # noqa: F841

            # We should have fetched the event from the DB
            self.assertEqual(ctx.get_resource_usage().evt_db_fetch_count, 1)

        # Reset the event cache
        self.get_success(self.store._get_event_cache.clear())

        with LoggingContext("test") as ctx:
            self.get_success(self.store.get_event(self.event_id))

            # Since the event is still in memory we shouldn't have fetched it
            # from the DB
            self.assertEqual(ctx.get_resource_usage().evt_db_fetch_count, 0)

    def test_dedupe(self):
        """Test that if we request the same event multiple times we only pull it
        out once.
        """

        with LoggingContext("test") as ctx:
            d = yieldable_gather_results(
                self.store.get_event, [self.event_id, self.event_id]
            )
            self.get_success(d)

            # We should have fetched the event from the DB
            self.assertEqual(ctx.get_resource_usage().evt_db_fetch_count, 1)


class DatabaseOutageTestCase(unittest.HomeserverTestCase):
    """Test event fetching during a database outage."""

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        self.store: EventsWorkerStore = hs.get_datastores().main

        self.room_id = f"!room:{hs.hostname}"

        self._populate_events()

    def _populate_events(self) -> None:
        """Ensure that there are test events in the database.

        When testing with the in-memory SQLite database, all the events are lost during
        the simulated outage.

        To ensure consistency between `room_id`s and `event_id`s before and after the
        outage, rows are built and inserted manually.

        Upserts are used to handle the non-SQLite case where events are not lost.
        """
        self.get_success(
            self.store.db_pool.simple_upsert(
                "rooms",
                {"room_id": self.room_id},
                {"room_version": RoomVersions.V4.identifier},
            )
        )

        self.event_ids: List[str] = []
        for idx in range(20):
            event_json = {
                "type": f"test {idx}",
                "room_id": self.room_id,
            }
            event = make_event_from_dict(event_json, room_version=RoomVersions.V4)
            event_id = event.event_id
            self.get_success(
                self.store.db_pool.simple_upsert(
                    "events",
                    {"event_id": event_id},
                    {
                        "event_id": event_id,
                        "room_id": self.room_id,
                        "topological_ordering": idx,
                        "stream_ordering": idx,
                        "type": event.type,
                        "processed": True,
                        "outlier": False,
                    },
                )
            )
            self.get_success(
                self.store.db_pool.simple_upsert(
                    "event_json",
                    {"event_id": event_id},
                    {
                        "room_id": self.room_id,
                        "json": json.dumps(event_json),
                        "internal_metadata": "{}",
                        "format_version": EventFormatVersions.ROOM_V4_PLUS,
                    },
                )
            )
            self.event_ids.append(event_id)

    @contextmanager
    def _outage(self) -> Generator[None, None, None]:
        """Simulate a database outage.

        Returns:
            A context manager. While the context is active, any attempts to connect to
            the database will fail.
        """
        connection_pool = self.store.db_pool._db_pool

        # Close all connections and shut down the database `ThreadPool`.
        connection_pool.close()

        # Restart the database `ThreadPool`.
        connection_pool.start()

        original_connection_factory = connection_pool.connectionFactory

        def connection_factory(_pool: ConnectionPool) -> Connection:
            raise Exception("Could not connect to the database.")

        connection_pool.connectionFactory = connection_factory  # type: ignore[assignment]
        try:
            yield
        finally:
            connection_pool.connectionFactory = original_connection_factory

            # If the in-memory SQLite database is being used, all the events are gone.
            # Restore the test data.
            self._populate_events()

    def test_failure(self) -> None:
        """Test that event fetches do not get stuck during a database outage."""
        with self._outage():
            failure = self.get_failure(
                self.store.get_event(self.event_ids[0]), Exception
            )
            self.assertEqual(str(failure.value), "Could not connect to the database.")

    def test_recovery(self) -> None:
        """Test that event fetchers recover after a database outage."""
        with self._outage():
            # Kick off a bunch of event fetches but do not pump the reactor
            event_deferreds = []
            for event_id in self.event_ids:
                event_deferreds.append(ensureDeferred(self.store.get_event(event_id)))

            # We should have maxed out on event fetcher threads
            self.assertEqual(self.store._event_fetch_ongoing, EVENT_QUEUE_THREADS)

            # All the event fetchers will fail
            self.pump()
            self.assertEqual(self.store._event_fetch_ongoing, 0)

            for event_deferred in event_deferreds:
                failure = self.get_failure(event_deferred, Exception)
                self.assertEqual(
                    str(failure.value), "Could not connect to the database."
                )

        # This next event fetch should succeed
        self.get_success(self.store.get_event(self.event_ids[0]))


class GetEventCancellationTestCase(unittest.HomeserverTestCase):
    """Test cancellation of `get_event` calls."""

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        self.store: EventsWorkerStore = hs.get_datastores().main

        self.user = self.register_user("user", "pass")
        self.token = self.login(self.user, "pass")

        self.room = self.helper.create_room_as(self.user, tok=self.token)

        res = self.helper.send(self.room, tok=self.token)
        self.event_id = res["event_id"]

        # Reset the event cache so the tests start with it empty
        self.get_success(self.store._get_event_cache.clear())

    @contextmanager
    def blocking_get_event_calls(
        self,
    ) -> Generator[
        Tuple["Deferred[None]", "Deferred[None]", "Deferred[None]"], None, None
    ]:
        """Starts two concurrent `get_event` calls for the same event.

        Both `get_event` calls will use the same database fetch, which will be blocked
        at the time this function returns.

        Returns:
            A tuple containing:
             * A `Deferred` that unblocks the database fetch.
             * A cancellable `Deferred` for the first `get_event` call.
             * A cancellable `Deferred` for the second `get_event` call.
        """
        # Patch `DatabasePool.runWithConnection` to block.
        unblock: "Deferred[None]" = Deferred()
        original_runWithConnection = self.store.db_pool.runWithConnection

        async def runWithConnection(*args, **kwargs):
            await unblock
            return await original_runWithConnection(*args, **kwargs)

        with mock.patch.object(
            self.store.db_pool,
            "runWithConnection",
            new=runWithConnection,
        ):
            ctx1 = LoggingContext("get_event1")
            ctx2 = LoggingContext("get_event2")

            async def get_event(ctx: LoggingContext) -> None:
                with ctx:
                    await self.store.get_event(self.event_id)

            get_event1 = ensureDeferred(get_event(ctx1))
            get_event2 = ensureDeferred(get_event(ctx2))

            # Both `get_event` calls ought to be blocked.
            self.assertNoResult(get_event1)
            self.assertNoResult(get_event2)

            yield unblock, get_event1, get_event2

        # Confirm that the two `get_event` calls shared the same database fetch.
        self.assertEqual(ctx1.get_resource_usage().evt_db_fetch_count, 1)
        self.assertEqual(ctx2.get_resource_usage().evt_db_fetch_count, 0)

    def test_first_get_event_cancelled(self):
        """Test cancellation of the first `get_event` call sharing a database fetch.

        The first `get_event` call is the one which initiates the fetch. We expect the
        fetch to complete despite the cancellation. Furthermore, the first `get_event`
        call must not abort before the fetch is complete, otherwise the fetch will be
        using a finished logging context.
        """
        with self.blocking_get_event_calls() as (unblock, get_event1, get_event2):
            # Cancel the first `get_event` call.
            get_event1.cancel()
            # The first `get_event` call must not abort immediately, otherwise its
            # logging context will be finished while it is still in use by the database
            # fetch.
            self.assertNoResult(get_event1)
            # The second `get_event` call must not be cancelled.
            self.assertNoResult(get_event2)

            # Unblock the database fetch.
            unblock.callback(None)
            # A `CancelledError` should be raised out of the first `get_event` call.
            exc = self.get_failure(get_event1, CancelledError).value
            self.assertIsInstance(exc, CancelledError)
            # The second `get_event` call should complete successfully.
            self.get_success(get_event2)

    def test_second_get_event_cancelled(self):
        """Test cancellation of the second `get_event` call sharing a database fetch."""
        with self.blocking_get_event_calls() as (unblock, get_event1, get_event2):
            # Cancel the second `get_event` call.
            get_event2.cancel()
            # The first `get_event` call must not be cancelled.
            self.assertNoResult(get_event1)
            # The second `get_event` call gets cancelled immediately.
            exc = self.get_failure(get_event2, CancelledError).value
            self.assertIsInstance(exc, CancelledError)

            # Unblock the database fetch.
            unblock.callback(None)
            # The first `get_event` call should complete successfully.
            self.get_success(get_event1)
