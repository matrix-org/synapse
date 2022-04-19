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

from typing import Optional
from unittest.mock import Mock, call

from signedjson.key import generate_signing_key

from synapse.api.constants import EventTypes, Membership, PresenceState
from synapse.api.presence import UserPresenceState
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events.builder import EventBuilder
from synapse.federation.sender import FederationSender
from synapse.handlers.presence import (
    EXTERNAL_PROCESS_EXPIRY,
    FEDERATION_PING_INTERVAL,
    FEDERATION_TIMEOUT,
    IDLE_TIMER,
    LAST_ACTIVE_GRANULARITY,
    SYNC_ONLINE_TIMEOUT,
    handle_timeout,
    handle_update,
)
from synapse.rest import admin
from synapse.rest.client import room
from synapse.types import UserID, get_domain_from_id

from tests import unittest


class PresenceUpdateTestCase(unittest.HomeserverTestCase):
    servlets = [admin.register_servlets]

    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastores().main

    def test_offline_to_online(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now
        )

        state, persist_and_notify, federation_ping = handle_update(
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
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

    def test_online_to_online(self):
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
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
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

    def test_online_to_online_last_active_noop(self):
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
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
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

    def test_online_to_online_last_active(self):
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
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
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

    def test_remote_ping_timer(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now
        )

        new_state = prev_state.copy_and_replace(state=PresenceState.ONLINE)

        state, persist_and_notify, federation_ping = handle_update(
            prev_state, new_state, is_mine=False, wheel_timer=wheel_timer, now=now
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

    def test_online_to_offline(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now, currently_active=True
        )

        new_state = prev_state.copy_and_replace(state=PresenceState.OFFLINE)

        state, persist_and_notify, federation_ping = handle_update(
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
        )

        self.assertTrue(persist_and_notify)
        self.assertEqual(new_state.state, state.state)
        self.assertEqual(state.last_federation_update_ts, now)

        self.assertEqual(wheel_timer.insert.call_count, 0)

    def test_online_to_idle(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE, last_active_ts=now, currently_active=True
        )

        new_state = prev_state.copy_and_replace(state=PresenceState.UNAVAILABLE)

        state, persist_and_notify, federation_ping = handle_update(
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
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

    def test_persisting_presence_updates(self):
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
        db_presence_states = self.get_success(
            self.store.get_all_presence_updates(
                instance_name="master",
                last_id=0,
                current_id=len(presence_states) + 1,
                limit=len(presence_states),
            )
        )

        # Extract presence update user ID and state information into lists of tuples
        db_presence_states = [(ps[0], ps[1]) for _, ps in db_presence_states[0]]
        presence_states_compare = [(ps.user_id, ps.state) for ps in presence_states]

        # Compare what we put into the storage with what we got out.
        # They should be identical.
        self.assertEqual(presence_states_compare, db_presence_states)


class PresenceTimeoutTestCase(unittest.TestCase):
    """Tests different timers and that the timer does not change `status_msg` of user."""

    def test_idle_timer(self):
        user_id = "@foo:bar"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - IDLE_TIMER - 1,
            last_user_sync_ts=now,
            status_msg=status_msg,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.UNAVAILABLE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_busy_no_idle(self):
        """
        Tests that a user setting their presence to busy but idling doesn't turn their
        presence state into unavailable.
        """
        user_id = "@foo:bar"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.BUSY,
            last_active_ts=now - IDLE_TIMER - 1,
            last_user_sync_ts=now,
            status_msg=status_msg,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.BUSY)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_sync_timeout(self):
        user_id = "@foo:bar"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=0,
            last_user_sync_ts=now - SYNC_ONLINE_TIMEOUT - 1,
            status_msg=status_msg,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.OFFLINE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_sync_online(self):
        user_id = "@foo:bar"
        status_msg = "I'm here!"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - SYNC_ONLINE_TIMEOUT - 1,
            last_user_sync_ts=now - SYNC_ONLINE_TIMEOUT - 1,
            status_msg=status_msg,
        )

        new_state = handle_timeout(
            state, is_mine=True, syncing_user_ids={user_id}, now=now
        )

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.ONLINE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_federation_ping(self):
        user_id = "@foo:bar"
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

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        self.assertEqual(state, new_state)

    def test_no_timeout(self):
        user_id = "@foo:bar"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            last_user_sync_ts=now,
            last_federation_update_ts=now,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNone(new_state)

    def test_federation_timeout(self):
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

        new_state = handle_timeout(
            state, is_mine=False, syncing_user_ids=set(), now=now
        )

        self.assertIsNotNone(new_state)
        assert new_state is not None
        self.assertEqual(new_state.state, PresenceState.OFFLINE)
        self.assertEqual(new_state.status_msg, status_msg)

    def test_last_active(self):
        user_id = "@foo:bar"
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

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        self.assertEqual(state, new_state)


class PresenceHandlerTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.presence_handler = hs.get_presence_handler()
        self.clock = hs.get_clock()

    def test_external_process_timeout(self):
        """Test that if an external process doesn't update the records for a while
        we time out their syncing users presence.
        """
        process_id = 1
        user_id = "@test:server"

        # Notify handler that a user is now syncing.
        self.get_success(
            self.presence_handler.update_external_syncs_row(
                process_id, user_id, True, self.clock.time_msec()
            )
        )

        # Check that if we wait a while without telling the handler the user has
        # stopped syncing that their presence state doesn't get timed out.
        self.reactor.advance(EXTERNAL_PROCESS_EXPIRY / 2)

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, PresenceState.ONLINE)

        # Check that if the external process timeout fires, then the syncing
        # user gets timed out
        self.reactor.advance(EXTERNAL_PROCESS_EXPIRY)

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, PresenceState.OFFLINE)

    def test_user_goes_offline_by_timeout_status_msg_remain(self):
        """Test that if a user doesn't update the records for a while
        users presence goes `OFFLINE` because of timeout and `status_msg` remains.
        """
        user_id = "@test:server"
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(
            user_id, PresenceState.ONLINE, status_msg
        )

        # Check that if we wait a while without telling the handler the user has
        # stopped syncing that their presence state doesn't get timed out.
        self.reactor.advance(SYNC_ONLINE_TIMEOUT / 2)

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, PresenceState.ONLINE)
        self.assertEqual(state.status_msg, status_msg)

        # Check that if the timeout fires, then the syncing user gets timed out
        self.reactor.advance(SYNC_ONLINE_TIMEOUT)

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        # status_msg should remain even after going offline
        self.assertEqual(state.state, PresenceState.OFFLINE)
        self.assertEqual(state.status_msg, status_msg)

    def test_user_goes_offline_manually_with_no_status_msg(self):
        """Test that if a user change presence manually to `OFFLINE`
        and no status is set, that `status_msg` is `None`.
        """
        user_id = "@test:server"
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(
            user_id, PresenceState.ONLINE, status_msg
        )

        # Mark user as offline
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string(user_id), {"presence": PresenceState.OFFLINE}
            )
        )

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(state.state, PresenceState.OFFLINE)
        self.assertEqual(state.status_msg, None)

    def test_user_goes_offline_manually_with_status_msg(self):
        """Test that if a user change presence manually to `OFFLINE`
        and a status is set, that `status_msg` appears.
        """
        user_id = "@test:server"
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(
            user_id, PresenceState.ONLINE, status_msg
        )

        # Mark user as offline
        self._set_presencestate_with_status_msg(
            user_id, PresenceState.OFFLINE, "And now here."
        )

    def test_user_reset_online_with_no_status(self):
        """Test that if a user set again the presence manually
        and no status is set, that `status_msg` is `None`.
        """
        user_id = "@test:server"
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(
            user_id, PresenceState.ONLINE, status_msg
        )

        # Mark user as online again
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string(user_id), {"presence": PresenceState.ONLINE}
            )
        )

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        # status_msg should remain even after going offline
        self.assertEqual(state.state, PresenceState.ONLINE)
        self.assertEqual(state.status_msg, None)

    def test_set_presence_with_status_msg_none(self):
        """Test that if a user set again the presence manually
        and status is `None`, that `status_msg` is `None`.
        """
        user_id = "@test:server"
        status_msg = "I'm here!"

        # Mark user as online
        self._set_presencestate_with_status_msg(
            user_id, PresenceState.ONLINE, status_msg
        )

        # Mark user as online and `status_msg = None`
        self._set_presencestate_with_status_msg(user_id, PresenceState.ONLINE, None)

    def test_set_presence_from_syncing_not_set(self):
        """Test that presence is not set by syncing if affect_presence is false"""
        user_id = "@test:server"
        status_msg = "I'm here!"

        self._set_presencestate_with_status_msg(
            user_id, PresenceState.UNAVAILABLE, status_msg
        )

        self.get_success(
            self.presence_handler.user_syncing(user_id, False, PresenceState.ONLINE)
        )

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        # we should still be unavailable
        self.assertEqual(state.state, PresenceState.UNAVAILABLE)
        # and status message should still be the same
        self.assertEqual(state.status_msg, status_msg)

    def test_set_presence_from_syncing_is_set(self):
        """Test that presence is set by syncing if affect_presence is true"""
        user_id = "@test:server"
        status_msg = "I'm here!"

        self._set_presencestate_with_status_msg(
            user_id, PresenceState.UNAVAILABLE, status_msg
        )

        self.get_success(
            self.presence_handler.user_syncing(user_id, True, PresenceState.ONLINE)
        )

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        # we should now be online
        self.assertEqual(state.state, PresenceState.ONLINE)

    def test_set_presence_from_syncing_keeps_status(self):
        """Test that presence set by syncing retains status message"""
        user_id = "@test:server"
        status_msg = "I'm here!"

        self._set_presencestate_with_status_msg(
            user_id, PresenceState.UNAVAILABLE, status_msg
        )

        self.get_success(
            self.presence_handler.user_syncing(user_id, True, PresenceState.ONLINE)
        )

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        # our status message should be the same as it was before
        self.assertEqual(state.status_msg, status_msg)

    def test_set_presence_from_syncing_keeps_busy(self):
        """Test that presence set by syncing doesn't affect busy status"""
        # while this isn't the default
        self.presence_handler._busy_presence_enabled = True

        user_id = "@test:server"
        status_msg = "I'm busy!"

        self._set_presencestate_with_status_msg(user_id, PresenceState.BUSY, status_msg)

        self.get_success(
            self.presence_handler.user_syncing(user_id, True, PresenceState.ONLINE)
        )

        state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        # we should still be busy
        self.assertEqual(state.state, PresenceState.BUSY)

    def _set_presencestate_with_status_msg(
        self, user_id: str, state: str, status_msg: Optional[str]
    ):
        """Set a PresenceState and status_msg and check the result.

        Args:
            user_id: User for that the status is to be set.
            state: The new PresenceState.
            status_msg: Status message that is to be set.
        """
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string(user_id),
                {"presence": state, "status_msg": status_msg},
            )
        )

        new_state = self.get_success(
            self.presence_handler.get_state(UserID.from_string(user_id))
        )
        self.assertEqual(new_state.state, state)
        self.assertEqual(new_state.status_msg, status_msg)


class PresenceFederationQueueTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.presence_handler = hs.get_presence_handler()
        self.clock = hs.get_clock()
        self.instance_name = hs.get_instance_name()

        self.queue = self.presence_handler.get_federation_queue()

    def test_send_and_get(self):
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.queue.send_presence_to_destinations((state1, state2), ("dest1", "dest2"))
        self.queue.send_presence_to_destinations((state3,), ("dest3",))

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

    def test_send_and_get_split(self):
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.queue.send_presence_to_destinations((state1, state2), ("dest1", "dest2"))

        now_token = self.queue.get_current_token(self.instance_name)

        self.queue.send_presence_to_destinations((state3,), ("dest3",))

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

    def test_clear_queue_all(self):
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.queue.send_presence_to_destinations((state1, state2), ("dest1", "dest2"))
        self.queue.send_presence_to_destinations((state3,), ("dest3",))

        self.reactor.advance(10 * 60 * 1000)

        now_token = self.queue.get_current_token(self.instance_name)

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )
        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)
        self.assertCountEqual(rows, [])

        prev_token = self.queue.get_current_token(self.instance_name)

        self.queue.send_presence_to_destinations((state1, state2), ("dest1", "dest2"))
        self.queue.send_presence_to_destinations((state3,), ("dest3",))

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

    def test_partially_clear_queue(self):
        state1 = UserPresenceState.default("@user1:test")
        state2 = UserPresenceState.default("@user2:test")
        state3 = UserPresenceState.default("@user3:test")

        prev_token = self.queue.get_current_token(self.instance_name)

        self.queue.send_presence_to_destinations((state1, state2), ("dest1", "dest2"))

        self.reactor.advance(2 * 60 * 1000)

        self.queue.send_presence_to_destinations((state3,), ("dest3",))

        self.reactor.advance(4 * 60 * 1000)

        now_token = self.queue.get_current_token(self.instance_name)

        rows, upto_token, limited = self.get_success(
            self.queue.get_replication_rows("master", prev_token, now_token, 10)
        )
        self.assertEqual(upto_token, now_token)
        self.assertFalse(limited)

        expected_rows = [
            (2, ("dest3", "@user3:test")),
        ]
        self.assertCountEqual(rows, [])

        prev_token = self.queue.get_current_token(self.instance_name)

        self.queue.send_presence_to_destinations((state1, state2), ("dest1", "dest2"))
        self.queue.send_presence_to_destinations((state3,), ("dest3",))

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

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(
            "server",
            federation_http_client=None,
            federation_sender=Mock(spec=FederationSender),
        )
        return hs

    def default_config(self):
        config = super().default_config()
        config["send_federation"] = True
        return config

    def prepare(self, reactor, clock, hs):
        self.federation_sender = hs.get_federation_sender()
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

    def test_remote_joins(self):
        # We advance time to something that isn't 0, as we use 0 as a special
        # value.
        self.reactor.advance(1000000000000)

        # Create a room with two local users
        room_id = self.helper.create_room_as(self.user_id)
        self.helper.join(room_id, "@test2:server")

        # Mark test2 as online, test will be offline with a last_active of 0
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string("@test2:server"), {"presence": PresenceState.ONLINE}
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

    def test_remote_gets_presence_when_local_user_joins(self):
        # We advance time to something that isn't 0, as we use 0 as a special
        # value.
        self.reactor.advance(1000000000000)

        # Create a room with one local users
        room_id = self.helper.create_room_as(self.user_id)

        # Mark test as online
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string("@test:server"), {"presence": PresenceState.ONLINE}
            )
        )

        # Mark test2 as online, test will be offline with a last_active of 0.
        # Note we don't join them to the room yet
        self.get_success(
            self.presence_handler.set_state(
                UserID.from_string("@test2:server"), {"presence": PresenceState.ONLINE}
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

    def _add_new_user(self, room_id, user_id):
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
            builder.build(prev_event_ids=prev_event_ids, auth_event_ids=None)
        )

        self.get_success(self.federation_event_handler.on_receive_pdu(hostname, event))

        # Check that it was successfully persisted.
        self.get_success(self.store.get_event(event.event_id))
        self.get_success(self.store.get_event(event.event_id))
