# Copyright 2016 OpenMarket Ltd
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
from typing import Optional, cast
from unittest.mock import Mock, call

from parameterized import parameterized
from signedjson.key import generate_signing_key

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes, Membership, PresenceState
from synapse.api.presence import UserDevicePresenceState, UserPresenceState
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events.builder import EventBuilder
from synapse.federation.sender import FederationSender
from synapse.handlers.presence import (
    BUSY_ONLINE_TIMEOUT,
    EXTERNAL_PROCESS_EXPIRY,
    FEDERATION_PING_INTERVAL,
    FEDERATION_TIMEOUT,
    IDLE_TIMER,
    LAST_ACTIVE_GRANULARITY,
    SYNC_ONLINE_TIMEOUT,
    PresenceHandler,
    handle_timeout,
    handle_update,
)
from synapse.rest import admin
from synapse.rest.client import room
from synapse.server import HomeServer
from synapse.storage.database import LoggingDatabaseConnection
from synapse.types import JsonDict, UserID, get_domain_from_id
from synapse.util import Clock

from tests import unittest
from tests.replication._base import BaseMultiWorkerStreamTestCase


class PresenceUpdateTestCase(unittest.HomeserverTestCase):
    servlets = [admin.register_servlets]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main

    def test_offline_to_online(self) -> None:
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now
        )

        state, persist_and_notify, federation_ping = handle_update(
            prev_state,
            new_state,
            is_mine=True,
            wheel_timer=wheel_timer,
            now=now,
            persist=False,
        )

        self.assertTrue(persist_and_notify)
        self.assertTrue(state.currently_active)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(new_state.status_msg, state.status_msg)
        self.assertEqual(state.last_federation_update_ts, now)

        self.assertEqual(wheel_timer.insert.call_count, 3)
        wheel_timer.insert.assert_has_calls(
            [
                call(now=now, obj=user_id, then=new_state.last_active_ts + IDLE_TIMER),
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
                ),
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY,
                ),
            ],
            any_order=True,
        )

    def test_online_to_online(self) -> None:
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now, currently_active=True
        )

        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now
        )

        state, persist_and_notify, federation_ping = handle_update(
            prev_state,
            new_state,
            is_mine=True,
            wheel_timer=wheel_timer,
            now=now,
            persist=False,
        )

        self.assertFalse(persist_and_notify)
        self.assertTrue(federation_ping)
        self.assertTrue(state.currently_active)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(new_state.status_msg, state.status_msg)
        self.assertEqual(state.last_federation_update_ts, now)

        self.assertEqual(wheel_timer.insert.call_count, 3)
        wheel_timer.insert.assert_has_calls(
            [
                call(now=now, obj=user_id, then=new_state.last_active_ts + IDLE_TIMER),
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
                ),
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY,
                ),
            ],
            any_order=True,
        )

    def test_online_to_online_last_active_noop(self) -> None:
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - LAST_ACTIVE_GRANULARITY - 10,
            currently_active=True,
        )

        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now
        )

        state, persist_and_notify, federation_ping = handle_update(
            prev_state,
            new_state,
            is_mine=True,
            wheel_timer=wheel_timer,
            now=now,
            persist=False,
        )

        self.assertFalse(persist_and_notify)
        self.assertTrue(federation_ping)
        self.assertTrue(state.currently_active)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(new_state.status_msg, state.status_msg)
        self.assertEqual(state.last_federation_update_ts, now)

        self.assertEqual(wheel_timer.insert.call_count, 3)
        wheel_timer.insert.assert_has_calls(
            [
                call(now=now, obj=user_id, then=new_state.last_active_ts + IDLE_TIMER),
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
                ),
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY,
                ),
            ],
            any_order=True,
        )

    def test_online_to_online_last_active(self) -> None:
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - LAST_ACTIVE_GRANULARITY - 1,
            currently_active=True,
        )

        new_state = prev_state.copy_and_replace(state=PresenceState.ONLINE)

        state, persist_and_notify, federation_ping = handle_update(
            prev_state,
            new_state,
            is_mine=True,
            wheel_timer=wheel_timer,
            now=now,
            persist=False,
        )

        self.assertTrue(persist_and_notify)
        self.assertFalse(state.currently_active)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(new_state.status_msg, state.status_msg)
        self.assertEqual(state.last_federation_update_ts, now)

        self.assertEqual(wheel_timer.insert.call_count, 2)
        wheel_timer.insert.assert_has_calls(
            [
                call(now=now, obj=user_id, then=new_state.last_active_ts + IDLE_TIMER),
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
                ),
            ],
            any_order=True,
        )

    def test_remote_ping_timer(self) -> None:
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now
        )

        new_state = prev_state.copy_and_replace(state=PresenceState.ONLINE)

        state, persist_and_notify, federation_ping = handle_update(
            prev_state,
            new_state,
            is_mine=False,
            wheel_timer=wheel_timer,
            now=now,
            persist=False,
        )

        self.assertFalse(persist_and_notify)
        self.assertFalse(federation_ping)
        self.assertFalse(state.currently_active)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(new_state.status_msg, state.status_msg)

        self.assertEqual(wheel_timer.insert.call_count, 1)
        wheel_timer.insert.assert_has_calls(
            [
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_federation_update_ts + FEDERATION_TIMEOUT,
                )
            ],
            any_order=True,
        )

    def test_online_to_offline(self) -> None:
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now, currently_active=True
        )

        new_state = prev_state.copy_and_replace(state=PresenceState.OFFLINE)

        state, persist_and_notify, federation_ping = handle_update(
            prev_state,
            new_state,
            is_mine=True,
            wheel_timer=wheel_timer,
            now=now,
            persist=False,
        )

        self.assertTrue(persist_and_notify)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(state.last_federation_update_ts, now)

        self.assertEqual(wheel_timer.insert.call_count, 0)

    def test_online_to_idle(self) -> None:
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now, currently_active=True
        )

        new_state = prev_state.copy_and_replace(state=PresenceState.UNAVAILABLE)

        state, persist_and_notify, federation_ping = handle_update(
            prev_state,
            new_state,
            is_mine=True,
            wheel_timer=wheel_timer,
            now=now,
            persist=False,
        )

        self.assertTrue(persist_and_notify)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(state.last_federation_update_ts, now)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(new_state.status_msg, state.status_msg)

        self.assertEqual(wheel_timer.insert.call_count, 1)
        wheel_timer.insert.assert_has_calls(
            [
                call(
                    now=now,
                    obj=user_id,
                    then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
                )
            ],
            any_order=True,
        )

    def test_persisting_presence_updates(self) -> None:
        """Tests that the latest presence state for each user is persisted correctly"""
        # Create some test users and presence states for them
        presence_states = []
        for i in range(5):
            user_id = self.register_user(f"user_{i}", "password")

            presence_state = UserPresenceState(
                user_id=user_id,
                state="online",
                last_active_ts=1,
                last_federation_update_ts=1,
                last_user_sync_ts=1,
                status_msg="I'm online!",
                currently_active=True,
            )
            presence_states.append(presence_state)

        # Persist these presence updates to the database
        self.get_success(self.store.update_presence(presence_states))

        # Check that each update is present in the database
        db_presence_states_raw = self.get_success(
            self.store.get_all_presence_updates(
                instance_name="master",
                last_id=0,
                current_id=len(presence_states) + 1,
                limit=len(presence_states),
            )
        )

        # Extract presence update user ID and state information into lists of tuples
        db_presence_states = [(ps[0], ps[1]) for _, ps in db_presence_states_raw[0]]
        presence_states_compare = [(ps.user_id, ps.state) for ps in presence_states]

        # Compare what we put into the storage with what we got out.
        # They should be identical.
        self.assertEqual(presence_states_compare, db_presence_states)

    @parameterized.expand(
        itertools.permutations(
            (
                PresenceState.BUSY,
                PresenceState.ONLINE,
                PresenceState.UNAVAILABLE,
                PresenceState.OFFLINE,
            ),
            2,
        )
    )
    def test_override(self, initial_state: str, final_state: str) -> None:
        """Overridden statuses should not go into the wheel timer."""
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=initial_state, last_active_ts=now, currently_active=True
        )

        new_state = prev_state.copy_and_replace(state=final_state, last_active_ts=now)

        handle_update(
            prev_state,
            new_state,
            is_mine=True,
            wheel_timer=wheel_timer,
            now=now,
            persist=True,
        )

        wheel_timer.insert.assert_not_called()


class PresenceTimeoutTestCase(unittest.TestCase):
    """Tests different timers and that the timer does not change `status_msg` of user."""

    def test_idle_timer(self) -> None:
        user_id = "@foo:bar"
        device_id = "dev-1"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - IDLE_TIMER - 1,
            last_user_sync_ts=now,
            status_msg=status_msg,
        )
        device_state = UserDevicePresenceState(
            user_id=user_id,
            device_id=device_id,
            state=state.state,
            last_active_ts=state.last_active_ts,
            last_sync_ts=state.last_user_sync_ts,
        )

        new_state = handle_timeout(
            state,
            is_mine=True,
            syncing_device_ids=set(),
            user_devices={device_id: device_state},
            now=now,
        )

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.UNAVAILABLE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_busy_no_idle(self) -> None:
        """
        Tests that a user setting their presence to busy but idling doesn't turn their
        presence state into unavailable.
        """
        user_id = "@foo:bar"
        device_id = "dev-1"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.BUSY,
            last_active_ts=now - IDLE_TIMER - 1,
            last_user_sync_ts=now,
            status_msg=status_msg,
        )
        device_state = UserDevicePresenceState(
            user_id=user_id,
            device_id=device_id,
            state=state.state,
            last_active_ts=state.last_active_ts,
            last_sync_ts=state.last_user_sync_ts,
        )

        new_state = handle_timeout(
            state,
            is_mine=True,
            syncing_device_ids=set(),
            user_devices={device_id: device_state},
            now=now,
        )

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.BUSY)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_sync_timeout(self) -> None:
        user_id = "@foo:bar"
        device_id = "dev-1"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=0,
            last_user_sync_ts=now - SYNC_ONLINE_TIMEOUT - 1,
            status_msg=status_msg,
        )
        device_state = UserDevicePresenceState(
            user_id=user_id,
            device_id=device_id,
            state=state.state,
            last_active_ts=state.last_active_ts,
            last_sync_ts=state.last_user_sync_ts,
        )

        new_state = handle_timeout(
            state,
            is_mine=True,
            syncing_device_ids=set(),
            user_devices={device_id: device_state},
            now=now,
        )

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.OFFLINE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_sync_online(self) -> None:
        user_id = "@foo:bar"
        device_id = "dev-1"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - SYNC_ONLINE_TIMEOUT - 1,
            last_user_sync_ts=now - SYNC_ONLINE_TIMEOUT - 1,
            status_msg=status_msg,
        )
        device_state = UserDevicePresenceState(
            user_id=user_id,
            device_id=device_id,
            state=state.state,
            last_active_ts=state.last_active_ts,
            last_sync_ts=state.last_user_sync_ts,
        )

        new_state = handle_timeout(
            state,
            is_mine=True,
            syncing_device_ids={(user_id, device_id)},
            user_devices={device_id: device_state},
            now=now,
        )

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.ONLINE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_federation_ping(self) -> None:
        user_id = "@foo:bar"
        device_id = "dev-1"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            last_user_sync_ts=now,
            last_federation_update_ts=now - FEDERATION_PING_INTERVAL - 1,
            status_msg=status_msg,
        )
        device_state = UserDevicePresenceState(
            user_id=user_id,
            device_id=device_id,
            state=state.state,
            last_active_ts=state.last_active_ts,
            last_sync_ts=state.last_user_sync_ts,
        )

        new_state = handle_timeout(
            state,
            is_mine=True,
            syncing_device_ids=set(),
            user_devices={device_id: device_state},
            now=now,
        )

        self.assertIsNotNone(new_state)
        self.assertEqual(state, new_state)

    def test_no_timeout(self) -> None:
        user_id = "@foo:bar"
        device_id = "dev-1"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            last_user_sync_ts=now,
            last_federation_update_ts=now,
        )
        device_state = UserDevicePresenceState(
            user_id=user_id,
            device_id=device_id,
            state=state.state,
            last_active_ts=state.last_active_ts,
            last_sync_ts=state.last_user_sync_ts,
        )

        new_state = handle_timeout(
            state,
            is_mine=True,
            syncing_device_ids=set(),
            user_devices={device_id: device_state},
            now=now,
        )

        self.assertIsNone(new_state)

    def test_federation_timeout(self) -> None:
        user_id = "@foo:bar"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            last_user_sync_ts=now,
            last_federation_update_ts=now - FEDERATION_TIMEOUT - 1,
            status_msg=status_msg,
        )

        # Note that this is a remote user so we do not have their device information.
        new_state = handle_timeout(
            state, is_mine=False, syncing_device_ids=set(), user_devices={}, now=now
        )

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.OFFLINE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_last_active(self) -> None:
        user_id = "@foo:bar"
        device_id = "dev-1"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - LAST_ACTIVE_GRANULARITY - 1,
            last_user_sync_ts=now,
            last_federation_update_ts=now,
            status_msg=status_msg,
        )
        device_state = UserDevicePresenceState(
            user_id=user_id,
            device_id=device_id,
            state=state.state,
            last_active_ts=state.last_active_ts,
            last_sync_ts=state.last_user_sync_ts,
        )

        new_state = handle_timeout(
            state,
            is_mine=True,
            syncing_device_ids=set(),
            user_devices={device_id: device_state},
            now=now,
        )

        self.assertIsNotNone(new_state)
        self.assertEqual(state, new_state)


class PresenceHandlerInitTestCase(unittest.HomeserverTestCase):
    def default_config(self) -> JsonDict:
        config = super().default_config()
        # Disable background tasks on this worker so that the PresenceHandler isn't
        # loaded until we request it.
        config["run_background_tasks_on"] = "other"
        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_id = f"@test:{self.hs.config.server.server_name}"
        self.device_id = "dev-1"

        # Move the reactor to the initial time.
        self.reactor.advance(1000)
        now = self.clock.time_msec()

        main_store = hs.get_datastores().main
        self.get_success(
            main_store.update_presence(
                [
                    UserPresenceState(
                        user_id=self.user_id,
                        state=PresenceState.ONLINE,
                        last_active_ts=now,
                        last_federation_update_ts=now,
                        last_user_sync_ts=now,
                        status_msg=None,
                        currently_active=True,
                    )
                ]
            )
        )

        # Regenerate the preloaded presence information on PresenceStore.
        def refill_presence(db_conn: LoggingDatabaseConnection) -> None:
            main_store._presence_on_startup = main_store._get_active_presence(db_conn)

        self.get_success(main_store.db_pool.runWithConnection(refill_presence))

    def test_restored_presence_idles(self) -> None:
        """The presence state restored from the database should not persist forever."""

        # Get the handler (which kicks off a bunch of timers).
        presence_handler = self.hs.get_presence_handler()

        # Assert the user is online.
        state = self.get_success(
            presence_handler.get_state(UserID.from_string(self.user_id))
        )
        self.assertEqual(state.state, PresenceState.ONLINE)

        # Advance such that the user should timeout.
        self.reactor.advance(SYNC_ONLINE_TIMEOUT / 1000)
        self.reactor.pump([5])

        # Check that the user is now offline.
        state = self.get_success(
            presence_handler.get_state(UserID.from_string(self.user_id))
        )
        self.assertEqual(state.state, PresenceState.OFFLINE)

    @parameterized.expand(
        [
            (PresenceState.BUSY, PresenceState.BUSY),
            (PresenceState.ONLINE, PresenceState.ONLINE),
            (PresenceState.UNAVAILABLE, PresenceState.ONLINE),
            # Offline syncs don't update the state.
            (PresenceState.OFFLINE, PresenceState.ONLINE),
        ]
    )
    @unittest.override_config({"experimental_features": {"msc3026_enabled": True}})
    def test_restored_presence_online_after_sync(
        self, sync_state: str, expected_state: str
    ) -> None:
        """
        The presence state restored from the database should be overridden with sync after a timeout.

        Args:
            sync_state: The presence state of the new sync.
            expected_state: The expected presence right after the sync.
        """

        # Get the handler (which kicks off a bunch of timers).
        presence_handler = self.hs.get_presence_handler()

        # Assert the user is online, as restored.
        state = self.get_success(
            presence_handler.get_state(UserID.from_string(self.user_id))
        )
        self.assertEqual(state.state, PresenceState.ONLINE)

        # Advance slightly and sync.
        self.reactor.advance(SYNC_ONLINE_TIMEOUT / 1000 / 2)
        self.get_success(
            presence_handler.user_syncing(
                self.user_id,
                self.device_id,
                sync_state != PresenceState.OFFLINE,
                sync_state,
            )
        )

        # Assert the user is in the expected state.
        state = self.get_success(
            presence_handler.get_state(UserID.from_string(self.user_id))
        )
        self.assertEqual(state.state, expected_state)

        # Advance such that the user's preloaded data times out, but not the new sync.
        self.reactor.advance(SYNC_ONLINE_TIMEOUT / 1000 / 2)
        self.reactor.pump([5])

        # Check that the user is in the sync state (as the client is currently syncing still).
        state = self.get_success(
            presence_handler.get_state(UserID.from_string(self.user_id))
        )
        self.assertEqual(state.state, sync_state)


class PresenceHandlerTestCase(BaseMultiWorkerStreamTestCase):
    user_id = "@test:server"
    user_id_obj = UserID.from_string(user_id)
    device_id = "dev-1"

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.presence_handler = hs.get_presence_handler()

    def test_external_process_timeout(self) -> None:
        """Test that if an external process doesn't update the records for a while
        we time out their syncing users presence.
        """

        # Create a worker and use it to handle /sync traffic instead.
        # This is used to test that presence changes get replicated from workers
        # to the main process correctly.
        worker_to_sync_against = self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "synchrotron"}
        )
        worker_presence_handler = worker_to_sync_against.get_presence_handler()

        self.get_success(
            worker_presence_handler.user_syncing(
                self.user_id, self.device_id, True, PresenceState.ONLINE
            ),
            by=0.1,
        )

        # Check that if we wait a while without telling the handler the user has
        # stopped syncing that their presence state doesn't get timed out.
        self.reactor.advance(EXTERNAL_PROCESS_EXPIRY / 2)

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.ONLINE)

        # Check that if the external process timeout fires, then the syncing
        # user gets timed out
        self.reactor.advance(EXTERNAL_PROCESS_EXPIRY)

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.OFFLINE)

    def test_user_goes_offline_by_timeout_status_msg_remain(self) -> None:
        """Test that if a user doesn't update the records for a while
        users presence goes `OFFLINE` because of timeout and `status_msg` remains.
        """
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(PresenceState.ONLINE, status_msg)

        # Check that if we wait a while without telling the handler the user has
        # stopped syncing that their presence state doesn't get timed out.
        self.reactor.advance(SYNC_ONLINE_TIMEOUT / 2)

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.ONLINE)
        self.assertEqual(state.status_msg, status_msg)

        # Check that if the timeout fires, then the syncing user gets timed out
        self.reactor.advance(SYNC_ONLINE_TIMEOUT)

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        # status_msg should remain even after going offline
        self.assertEqual(state.state, PresenceState.OFFLINE)
        self.assertEqual(state.status_msg, status_msg)

    def test_user_goes_offline_manually_with_no_status_msg(self) -> None:
        """Test that if a user change presence manually to `OFFLINE`
        and no status is set, that `status_msg` is `None`.
        """
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(PresenceState.ONLINE, status_msg)

        # Mark user as offline
        self.get_success(
            self.presence_handler.set_state(
                self.user_id_obj, self.device_id, {"presence": PresenceState.OFFLINE}
            )
        )

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.OFFLINE)
        self.assertEqual(state.status_msg, None)

    def test_user_goes_offline_manually_with_status_msg(self) -> None:
        """Test that if a user change presence manually to `OFFLINE`
        and a status is set, that `status_msg` appears.
        """
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(PresenceState.ONLINE, status_msg)

        # Mark user as offline
        self._set_presencestate_with_status_msg(PresenceState.OFFLINE, "And now here.")

    def test_user_reset_online_with_no_status(self) -> None:
        """Test that if a user set again the presence manually
        and no status is set, that `status_msg` is `None`.
        """
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(PresenceState.ONLINE, status_msg)

        # Mark user as online again
        self.get_success(
            self.presence_handler.set_state(
                self.user_id_obj, self.device_id, {"presence": PresenceState.ONLINE}
            )
        )

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        # status_msg should remain even after going offline
        self.assertEqual(state.state, PresenceState.ONLINE)
        self.assertEqual(state.status_msg, None)

    def test_set_presence_with_status_msg_none(self) -> None:
        """Test that if a user set again the presence manually
        and status is `None`, that `status_msg` is `None`.
        """
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(PresenceState.ONLINE, status_msg)

        # Mark user as online and `status_msg = None`
        self._set_presencestate_with_status_msg(PresenceState.ONLINE, None)

    def test_set_presence_from_syncing_not_set(self) -> None:
        """Test that presence is not set by syncing if affect_presence is false"""
        status_msg = "I'm here!"

        self._set_presencestate_with_status_msg(PresenceState.UNAVAILABLE, status_msg)

        self.get_success(
            self.presence_handler.user_syncing(
                self.user_id, self.device_id, False, PresenceState.ONLINE
            )
        )

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        # we should still be unavailable
        self.assertEqual(state.state, PresenceState.UNAVAILABLE)
        # and status message should still be the same
        self.assertEqual(state.status_msg, status_msg)

    def test_set_presence_from_syncing_is_set(self) -> None:
        """Test that presence is set by syncing if affect_presence is true"""
        status_msg = "I'm here!"

        self._set_presencestate_with_status_msg(PresenceState.UNAVAILABLE, status_msg)

        self.get_success(
            self.presence_handler.user_syncing(
                self.user_id, self.device_id, True, PresenceState.ONLINE
            )
        )

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        # we should now be online
        self.assertEqual(state.state, PresenceState.ONLINE)

    @parameterized.expand(
        # A list of tuples of 4 strings:
        #
        # * The presence state of device 1.
        # * The presence state of device 2.
        # * The expected user presence state after both devices have synced.
        # * The expected user presence state after device 1 has idled.
        # * The expected user presence state after device 2 has idled.
        # * True to use workers, False a monolith.
        [
            (*cases, workers)
            for workers in (False, True)
            for cases in [
                # If both devices have the same state, online should eventually idle.
                # Otherwise, the state doesn't change.
                (
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.OFFLINE,
                    PresenceState.OFFLINE,
                    PresenceState.OFFLINE,
                    PresenceState.OFFLINE,
                ),
                # If the second device has a "lower" state it should fallback to it,
                # except for "busy" which overrides.
                (
                    PresenceState.BUSY,
                    PresenceState.ONLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.BUSY,
                    PresenceState.UNAVAILABLE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.BUSY,
                    PresenceState.OFFLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.ONLINE,
                    PresenceState.OFFLINE,
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.OFFLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                ),
                # If the second device has a "higher" state it should override.
                (
                    PresenceState.ONLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                ),
            ]
        ],
        name_func=lambda testcase_func, param_num, params: f"{testcase_func.__name__}_{param_num}_{'workers' if params.args[5] else 'monolith'}",
    )
    @unittest.override_config({"experimental_features": {"msc3026_enabled": True}})
    def test_set_presence_from_syncing_multi_device(
        self,
        dev_1_state: str,
        dev_2_state: str,
        expected_state_1: str,
        expected_state_2: str,
        expected_state_3: str,
        test_with_workers: bool,
    ) -> None:
        """
        Test the behaviour of multiple devices syncing at the same time.

        Roughly the user's presence state should be set to the "highest" priority
        of all the devices. When a device then goes offline its state should be
        discarded and the next highest should win.

        Note that these tests use the idle timer (and don't close the syncs), it
        is unlikely that a *single* sync would last this long, but is close enough
        to continually syncing with that current state.
        """
        user_id = f"@test:{self.hs.config.server.server_name}"

        # By default, we call /sync against the main process.
        worker_presence_handler = self.presence_handler
        if test_with_workers:
            # Create a worker and use it to handle /sync traffic instead.
            # This is used to test that presence changes get replicated from workers
            # to the main process correctly.
            worker_to_sync_against = self.make_worker_hs(
                "synapse.app.generic_worker", {"worker_name": "synchrotron"}
            )
            worker_presence_handler = worker_to_sync_against.get_presence_handler()

        # 1. Sync with the first device.
        self.get_success(
            worker_presence_handler.user_syncing(
                user_id,
                "dev-1",
                affect_presence=dev_1_state != PresenceState.OFFLINE,
                presence_state=dev_1_state,
            ),
            by=0.01,
        )

        # 2. Wait half the idle timer.
        self.reactor.advance(IDLE_TIMER / 1000 / 2)
        self.reactor.pump([0.1])

        # 3. Sync with the second device.
        self.get_success(
            worker_presence_handler.user_syncing(
                user_id,
                "dev-2",
                affect_presence=dev_2_state != PresenceState.OFFLINE,
                presence_state=dev_2_state,
            ),
            by=0.01,
        )

        # 4. Assert the expected presence state.
        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, expected_state_1)
        if test_with_workers:
            state = self.get_success(
                worker_presence_handler.get_state(UserID.from_string(user_id))
            )
            self.assertEqual(state.state, expected_state_1)

        # When testing with workers, make another random sync (with any *different*
        # user) to keep the process information from expiring.
        #
        # This is due to EXTERNAL_PROCESS_EXPIRY being equivalent to IDLE_TIMER.
        if test_with_workers:
            with self.get_success(
                worker_presence_handler.user_syncing(
                    f"@other-user:{self.hs.config.server.server_name}",
                    "dev-3",
                    affect_presence=True,
                    presence_state=PresenceState.ONLINE,
                ),
                by=0.01,
            ):
                pass

        # 5. Advance such that the first device should be discarded (the idle timer),
        # then pump so _handle_timeouts function to called.
        self.reactor.advance(IDLE_TIMER / 1000 / 2)
        self.reactor.pump([0.01])

        # 6. Assert the expected presence state.
        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, expected_state_2)
        if test_with_workers:
            state = self.get_success(
                worker_presence_handler.get_state(UserID.from_string(user_id))
            )
            self.assertEqual(state.state, expected_state_2)

        # 7. Advance such that the second device should be discarded (half the idle timer),
        # then pump so _handle_timeouts function to called.
        self.reactor.advance(IDLE_TIMER / 1000 / 2)
        self.reactor.pump([0.1])

        # 8. The devices are still "syncing" (the sync context managers were never
        # closed), so might idle.
        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, expected_state_3)
        if test_with_workers:
            state = self.get_success(
                worker_presence_handler.get_state(UserID.from_string(user_id))
            )
            self.assertEqual(state.state, expected_state_3)

    @parameterized.expand(
        # A list of tuples of 4 strings:
        #
        # * The presence state of device 1.
        # * The presence state of device 2.
        # * The expected user presence state after both devices have synced.
        # * The expected user presence state after device 1 has stopped syncing.
        # * True to use workers, False a monolith.
        [
            (*cases, workers)
            for workers in (False, True)
            for cases in [
                # If both devices have the same state, nothing exciting should happen.
                (
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.OFFLINE,
                    PresenceState.OFFLINE,
                    PresenceState.OFFLINE,
                ),
                # If the second device has a "lower" state it should fallback to it,
                # except for "busy" which overrides.
                (
                    PresenceState.BUSY,
                    PresenceState.ONLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.BUSY,
                    PresenceState.UNAVAILABLE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.BUSY,
                    PresenceState.OFFLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.ONLINE,
                    PresenceState.UNAVAILABLE,
                ),
                (
                    PresenceState.ONLINE,
                    PresenceState.OFFLINE,
                    PresenceState.ONLINE,
                    PresenceState.OFFLINE,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.OFFLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.OFFLINE,
                ),
                # If the second device has a "higher" state it should override.
                (
                    PresenceState.ONLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                    PresenceState.BUSY,
                ),
                (
                    PresenceState.UNAVAILABLE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                    PresenceState.ONLINE,
                ),
                (
                    PresenceState.OFFLINE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                    PresenceState.UNAVAILABLE,
                ),
            ]
        ],
        name_func=lambda testcase_func, param_num, params: f"{testcase_func.__name__}_{param_num}_{'workers' if params.args[4] else 'monolith'}",
    )
    @unittest.override_config({"experimental_features": {"msc3026_enabled": True}})
    def test_set_presence_from_non_syncing_multi_device(
        self,
        dev_1_state: str,
        dev_2_state: str,
        expected_state_1: str,
        expected_state_2: str,
        test_with_workers: bool,
    ) -> None:
        """
        Test the behaviour of multiple devices syncing at the same time.

        Roughly the user's presence state should be set to the "highest" priority
        of all the devices. When a device then goes offline its state should be
        discarded and the next highest should win.

        Note that these tests use the idle timer (and don't close the syncs), it
        is unlikely that a *single* sync would last this long, but is close enough
        to continually syncing with that current state.
        """
        user_id = f"@test:{self.hs.config.server.server_name}"

        # By default, we call /sync against the main process.
        worker_presence_handler = self.presence_handler
        if test_with_workers:
            # Create a worker and use it to handle /sync traffic instead.
            # This is used to test that presence changes get replicated from workers
            # to the main process correctly.
            worker_to_sync_against = self.make_worker_hs(
                "synapse.app.generic_worker", {"worker_name": "synchrotron"}
            )
            worker_presence_handler = worker_to_sync_against.get_presence_handler()

        # 1. Sync with the first device.
        sync_1 = self.get_success(
            worker_presence_handler.user_syncing(
                user_id,
                "dev-1",
                affect_presence=dev_1_state != PresenceState.OFFLINE,
                presence_state=dev_1_state,
            ),
            by=0.1,
        )

        # 2. Sync with the second device.
        sync_2 = self.get_success(
            worker_presence_handler.user_syncing(
                user_id,
                "dev-2",
                affect_presence=dev_2_state != PresenceState.OFFLINE,
                presence_state=dev_2_state,
            ),
            by=0.1,
        )

        # 3. Assert the expected presence state.
        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, expected_state_1)
        if test_with_workers:
            state = self.get_success(
                worker_presence_handler.get_state(UserID.from_string(user_id))
            )
            self.assertEqual(state.state, expected_state_1)

        # 4. Disconnect the first device.
        with sync_1:
            pass

        # 5. Advance such that the first device should be discarded (the sync timeout),
        # then pump so _handle_timeouts function to called.
        self.reactor.advance(SYNC_ONLINE_TIMEOUT / 1000)
        self.reactor.pump([5])

        # 6. Assert the expected presence state.
        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, expected_state_2)
        if test_with_workers:
            state = self.get_success(
                worker_presence_handler.get_state(UserID.from_string(user_id))
            )
            self.assertEqual(state.state, expected_state_2)

        # 7. Disconnect the second device.
        with sync_2:
            pass

        # 8. Advance such that the second device should be discarded (the sync timeout),
        # then pump so _handle_timeouts function to called.
        if dev_1_state == PresenceState.BUSY or dev_2_state == PresenceState.BUSY:
            timeout = BUSY_ONLINE_TIMEOUT
        else:
            timeout = SYNC_ONLINE_TIMEOUT
        self.reactor.advance(timeout / 1000)
        self.reactor.pump([5])

        # 9. There are no more devices, should be offline.
        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, PresenceState.OFFLINE)
        if test_with_workers:
            state = self.get_success(
                worker_presence_handler.get_state(UserID.from_string(user_id))
            )
            self.assertEqual(state.state, PresenceState.OFFLINE)

    def test_set_presence_from_syncing_keeps_status(self) -> None:
        """Test that presence set by syncing retains status message"""
        status_msg = "I'm here!"

        self._set_presencestate_with_status_msg(PresenceState.UNAVAILABLE, status_msg)

        self.get_success(
            self.presence_handler.user_syncing(
                self.user_id, self.device_id, True, PresenceState.ONLINE
            )
        )

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        # our status message should be the same as it was before
        self.assertEqual(state.status_msg, status_msg)

    @parameterized.expand([(False,), (True,)])
    @unittest.override_config({"experimental_features": {"msc3026_enabled": True}})
    def test_set_presence_from_syncing_keeps_busy(
        self, test_with_workers: bool
    ) -> None:
        """Test that presence set by syncing doesn't affect busy status

        Args:
            test_with_workers: If True, check the presence state of the user by calling
                /sync against a worker, rather than the main process.
        """
        status_msg = "I'm busy!"

        # By default, we call /sync against the main process.
        worker_to_sync_against = self.hs
        if test_with_workers:
            # Create a worker and use it to handle /sync traffic instead.
            # This is used to test that presence changes get replicated from workers
            # to the main process correctly.
            worker_to_sync_against = self.make_worker_hs(
                "synapse.app.generic_worker", {"worker_name": "synchrotron"}
            )

        # Set presence to BUSY
        self._set_presencestate_with_status_msg(PresenceState.BUSY, status_msg)

        # Perform a sync with a presence state other than busy. This should NOT change
        # our presence status; we only change from busy if we explicitly set it via
        # /presence/*.
        self.get_success(
            worker_to_sync_against.get_presence_handler().user_syncing(
                self.user_id, self.device_id, True, PresenceState.ONLINE
            ),
            by=0.1,
        )

        # Check against the main process that the user's presence did not change.
        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        # we should still be busy
        self.assertEqual(state.state, PresenceState.BUSY)

        # Advance such that the device would be discarded if it was not busy,
        # then pump so _handle_timeouts function to called.
        self.reactor.advance(IDLE_TIMER / 1000)
        self.reactor.pump([5])

        # The account should still be busy.
        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.BUSY)

        # Ensure that a /presence call can set the user *off* busy.
        self._set_presencestate_with_status_msg(PresenceState.ONLINE, status_msg)

        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.ONLINE)

    def _set_presencestate_with_status_msg(
        self, state: str, status_msg: Optional[str]
    ) -> None:
        """Set a PresenceState and status_msg and check the result.

        Args:
            state: The new PresenceState.
            status_msg: Status message that is to be set.
        """
        self.get_success(
            self.presence_handler.set_state(
                self.user_id_obj,
                self.device_id,
                {"presence": state, "status_msg": status_msg},
            )
        )

        new_state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(new_state.state, state)
        self.assertEqual(new_state.status_msg, status_msg)

    @unittest.override_config({"presence": {"enabled": "untracked"}})
    def test_untracked_does_not_idle(self) -> None:
        """Untracked presence should not idle."""

        # Mark user as online, this needs to reach into internals in order to
        # bypass checks.
        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        assert isinstance(self.presence_handler, PresenceHandler)
        self.get_success(
            self.presence_handler._update_states(
                [state.copy_and_replace(state=PresenceState.ONLINE)]
            )
        )

        # Ensure the update took.
        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.ONLINE)

        # The timeout should not fire and the state should be the same.
        self.reactor.advance(SYNC_ONLINE_TIMEOUT)
        state = self.get_success(self.presence_handler.get_state(self.user_id_obj))
        self.assertEqual(state.state, PresenceState.ONLINE)


class PresenceFederationQueueTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.presence_handler = hs.get_presence_handler()
        self.clock = hs.get_clock()
        self.instance_name = hs.get_instance_name()

        self.queue = self.presence_handler.get_federation_queue()

    def test_send_and_get(self) -> None:
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.get_success(
            self.queue.send_presence_to_destinations(
                (state1, state2), ("dest1", "dest2")
            )
        )
        self.get_success(
            self.queue.send_presence_to_destinations((state3,), ("dest3",))
        )

        now_token = self.queue.get_current_token(self.instance_name)

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )

        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)

        expected_rows = [
            (1, ("dest1", "@user1:test")),
            (1, ("dest2", "@user1:test")),
            (1, ("dest1", "@user2:test")),
            (1, ("dest2", "@user2:test")),
            (2, ("dest3", "@user3:test")),
        ]

        self.assertCountEqual(rows, expected_rows)

        now_token = self.queue.get_current_token(self.instance_name)
        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", upto_token, now_token, 10)
        )
        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)
        self.assertCountEqual(rows, [])

    def test_send_and_get_split(self) -> None:
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.get_success(
            self.queue.send_presence_to_destinations(
                (state1, state2), ("dest1", "dest2")
            )
        )

        now_token = self.queue.get_current_token(self.instance_name)

        self.get_success(
            self.queue.send_presence_to_destinations((state3,), ("dest3",))
        )

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )

        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)

        expected_rows = [
            (1, ("dest1", "@user1:test")),
            (1, ("dest2", "@user1:test")),
            (1, ("dest1", "@user2:test")),
            (1, ("dest2", "@user2:test")),
        ]

        self.assertCountEqual(rows, expected_rows)

        now_token = self.queue.get_current_token(self.instance_name)
        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", upto_token, now_token, 10)
        )

        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)

        expected_rows = [
            (2, ("dest3", "@user3:test")),
        ]

        self.assertCountEqual(rows, expected_rows)

    def test_clear_queue_all(self) -> None:
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.get_success(
            self.queue.send_presence_to_destinations(
                (state1, state2), ("dest1", "dest2")
            )
        )
        self.get_success(
            self.queue.send_presence_to_destinations((state3,), ("dest3",))
        )

        self.reactor.advance(10 * 60 * 1000)

        now_token = self.queue.get_current_token(self.instance_name)

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )
        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)
        self.assertCountEqual(rows, [])

        prev_token = self.queue.get_current_token(self.instance_name)

        self.get_success(
            self.queue.send_presence_to_destinations(
                (state1, state2), ("dest1", "dest2")
            )
        )
        self.get_success(
            self.queue.send_presence_to_destinations((state3,), ("dest3",))
        )

        now_token = self.queue.get_current_token(self.instance_name)

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )
        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)

        expected_rows = [
            (3, ("dest1", "@user1:test")),
            (3, ("dest2", "@user1:test")),
            (3, ("dest1", "@user2:test")),
            (3, ("dest2", "@user2:test")),
            (4, ("dest3", "@user3:test")),
        ]

        self.assertCountEqual(rows, expected_rows)

    def test_partially_clear_queue(self) -> None:
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.get_success(
            self.queue.send_presence_to_destinations(
                (state1, state2), ("dest1", "dest2")
            )
        )

        self.reactor.advance(2 * 60 * 1000)

        self.get_success(
            self.queue.send_presence_to_destinations((state3,), ("dest3",))
        )

        self.reactor.advance(4 * 60 * 1000)

        now_token = self.queue.get_current_token(self.instance_name)

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )
        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)

        self.assertCountEqual(rows, [])

        prev_token = self.queue.get_current_token(self.instance_name)

        self.get_success(
            self.queue.send_presence_to_destinations(
                (state1, state2), ("dest1", "dest2")
            )
        )
        self.get_success(
            self.queue.send_presence_to_destinations((state3,), ("dest3",))
        )

        now_token = self.queue.get_current_token(self.instance_name)

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )
        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)

        expected_rows = [
            (3, ("dest1", "@user1:test")),
            (3, ("dest2", "@user1:test")),
            (3, ("dest1", "@user2:test")),
            (3, ("dest2", "@user2:test")),
            (4, ("dest3", "@user3:test")),
        ]

        self.assertCountEqual(rows, expected_rows)


class PresenceJoinTestCase(unittest.HomeserverTestCase):
    """Tests remote servers get told about presence of users in the room when
    they join and when new local users join.
    """

    user_id = "@test:server"

    servlets = [room.register_servlets]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        hs = self.setup_test_homeserver(
            "server",
            federation_sender=Mock(spec=FederationSender),
        )
        return hs

    def default_config(self) -> JsonDict:
        config = super().default_config()
        # Enable federation sending on the main process.
        config["federation_sender_instances"] = None
        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.federation_sender = cast(Mock, hs.get_federation_sender())
        self.event_builder_factory = hs.get_event_builder_factory()
        self.federation_event_handler = hs.get_federation_event_handler()
        self.presence_handler = hs.get_presence_handler()

        # self.event_builder_for_2 = EventBuilderFactory(hs)
        # self.event_builder_for_2.hostname = "test2"

        self.store = hs.get_datastores().main
        self.state = hs.get_state_handler()
        self._event_auth_handler = hs.get_event_auth_handler()

        # We don't actually check signatures in tests, so lets just create a
        # random key to use.
        self.random_signing_key = generate_signing_key("ver")

    def test_remote_joins(self) -> None:
        # We advance time to something that isn't 0, as we use 0 as a special
        # value.
        self.reactor.advance(1000000000000)

        # Create a room with two local users
        room_id = self.helper.create_room_as(self.user_id)
        self.helper.join(room_id, "@test2:server")

        # Mark test2 as online, test will be offline with a last_active of 0
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string("@test2:server"),
                "dev-1",
                {"presence": PresenceState.ONLINE},
            )
        )
        self.reactor.pump([0])  # Wait for presence updates to be handled

        #
        # Test that a new server gets told about existing presence
        #

        self.federation_sender.reset_mock()

        # Add a new remote server to the room
        self._add_new_user(room_id, "@alice:server2")

        # When new server is joined we send it the local users presence states.
        # We expect to only see user @test2:server, as @test:server is offline
        # and has a zero last_active_ts
        expected_state = self.get_success(
            self.presence_handler.current_state_for_user("@test2:server")
        )
        self.assertEqual(expected_state.state, PresenceState.ONLINE)
        self.federation_sender.send_presence_to_destinations.assert_called_once_with(
            destinations={"server2"}, states=[expected_state]
        )

        #
        # Test that only the new server gets sent presence and not existing servers
        #

        self.federation_sender.reset_mock()
        self._add_new_user(room_id, "@bob:server3")

        self.federation_sender.send_presence_to_destinations.assert_called_once_with(
            destinations={"server3"}, states=[expected_state]
        )

    def test_remote_gets_presence_when_local_user_joins(self) -> None:
        # We advance time to something that isn't 0, as we use 0 as a special
        # value.
        self.reactor.advance(1000000000000)

        # Create a room with one local users
        room_id = self.helper.create_room_as(self.user_id)

        # Mark test as online
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string("@test:server"),
                "dev-1",
                {"presence": PresenceState.ONLINE},
            )
        )

        # Mark test2 as online, test will be offline with a last_active of 0.
        # Note we don't join them to the room yet
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string("@test2:server"),
                "dev-1",
                {"presence": PresenceState.ONLINE},
            )
        )

        # Add servers to the room
        self._add_new_user(room_id, "@alice:server2")
        self._add_new_user(room_id, "@bob:server3")

        self.reactor.pump([0])  # Wait for presence updates to be handled

        #
        # Test that when a local join happens remote servers get told about it
        #

        self.federation_sender.reset_mock()

        # Join local user to room
        self.helper.join(room_id, "@test2:server")

        self.reactor.pump([0])  # Wait for presence updates to be handled

        # We expect to only send test2 presence to server2 and server3
        expected_state = self.get_success(
            self.presence_handler.current_state_for_user("@test2:server")
        )
        self.assertEqual(expected_state.state, PresenceState.ONLINE)
        self.federation_sender.send_presence_to_destinations.assert_called_once_with(
            destinations={"server2", "server3"}, states=[expected_state]
        )

    def _add_new_user(self, room_id: str, user_id: str) -> None:
        """Add new user to the room by creating an event and poking the federation API."""

        hostname = get_domain_from_id(user_id)

        room_version = self.get_success(self.store.get_room_version_id(room_id))

        builder = EventBuilder(
            state=self.state,
            event_auth_handler=self._event_auth_handler,
            store=self.store,
            clock=self.clock,
            hostname=hostname,
            signing_key=self.random_signing_key,
            room_version=KNOWN_ROOM_VERSIONS[room_version],
            room_id=room_id,
            type=EventTypes.Member,
            sender=user_id,
            state_key=user_id,
            content={"membership": Membership.JOIN},
        )

        prev_event_ids = self.get_success(
            self.store.get_latest_event_ids_in_room(room_id)
        )

        event = self.get_success(
            builder.build(prev_event_ids=list(prev_event_ids), auth_event_ids=None)
        )

        self.get_success(self.federation_event_handler.on_receive_pdu(hostname, event))

        # Check that it was successfully persisted.
        self.get_success(self.store.get_event(event.event_id))
        self.get_success(self.store.get_event(event.event_id))
