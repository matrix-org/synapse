# -*- coding: utf-8 -*-
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


from mock import Mock, call

from signedjson.key import generate_signing_key

from synapse.api.constants import EventTypes, Membership, PresenceState
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events.builder import EventBuilder
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
from synapse.rest.client.v1 import room
from synapse.storage.presence import UserPresenceState
from synapse.types import UserID, get_domain_from_id

from tests import unittest


class PresenceUpdateTestCase(unittest.TestCase):
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
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)
        self.assertEquals(state.last_federation_update_ts, now)

        self.assertEquals(wheel_timer.insert.call_count, 3)
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
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)
        self.assertEquals(state.last_federation_update_ts, now)

        self.assertEquals(wheel_timer.insert.call_count, 3)
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
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)
        self.assertEquals(state.last_federation_update_ts, now)

        self.assertEquals(wheel_timer.insert.call_count, 3)
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
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)
        self.assertEquals(state.last_federation_update_ts, now)

        self.assertEquals(wheel_timer.insert.call_count, 2)
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
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)

        self.assertEquals(wheel_timer.insert.call_count, 1)
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
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(state.last_federation_update_ts, now)

        self.assertEquals(wheel_timer.insert.call_count, 0)

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
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(state.last_federation_update_ts, now)
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)

        self.assertEquals(wheel_timer.insert.call_count, 1)
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


class PresenceTimeoutTestCase(unittest.TestCase):
    def test_idle_timer(self):
        user_id = "@foo:bar"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - IDLE_TIMER - 1,
            last_user_sync_ts=now,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        self.assertEquals(new_state.state, PresenceState.UNAVAILABLE)

    def test_sync_timeout(self):
        user_id = "@foo:bar"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=0,
            last_user_sync_ts=now - SYNC_ONLINE_TIMEOUT - 1,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        self.assertEquals(new_state.state, PresenceState.OFFLINE)

    def test_sync_online(self):
        user_id = "@foo:bar"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - SYNC_ONLINE_TIMEOUT - 1,
            last_user_sync_ts=now - SYNC_ONLINE_TIMEOUT - 1,
        )

        new_state = handle_timeout(
            state, is_mine=True, syncing_user_ids={user_id}, now=now
        )

        self.assertIsNotNone(new_state)
        self.assertEquals(new_state.state, PresenceState.ONLINE)

    def test_federation_ping(self):
        user_id = "@foo:bar"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            last_user_sync_ts=now,
            last_federation_update_ts=now - FEDERATION_PING_INTERVAL - 1,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        self.assertEquals(new_state, new_state)

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
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            last_user_sync_ts=now,
            last_federation_update_ts=now - FEDERATION_TIMEOUT - 1,
        )

        new_state = handle_timeout(
            state, is_mine=False, syncing_user_ids=set(), now=now
        )

        self.assertIsNotNone(new_state)
        self.assertEquals(new_state.state, PresenceState.OFFLINE)

    def test_last_active(self):
        user_id = "@foo:bar"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now - LAST_ACTIVE_GRANULARITY - 1,
            last_user_sync_ts=now,
            last_federation_update_ts=now,
        )

        new_state = handle_timeout(state, is_mine=True, syncing_user_ids=set(), now=now)

        self.assertIsNotNone(new_state)
        self.assertEquals(state, new_state)


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


class PresenceJoinTestCase(unittest.HomeserverTestCase):
    """Tests remote servers get told about presence of users in the room when
    they join and when new local users join.
    """

    user_id = "@test:server"

    servlets = [room.register_servlets]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(
            "server", http_client=None, federation_sender=Mock()
        )
        return hs

    def prepare(self, reactor, clock, hs):
        self.federation_sender = hs.get_federation_sender()
        self.event_builder_factory = hs.get_event_builder_factory()
        self.federation_handler = hs.get_handlers().federation_handler
        self.presence_handler = hs.get_presence_handler()

        # self.event_builder_for_2 = EventBuilderFactory(hs)
        # self.event_builder_for_2.hostname = "test2"

        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.auth = hs.get_auth()

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

        # We shouldn't have sent out any local presence *updates*
        self.federation_sender.send_presence.assert_not_called()

        # When new server is joined we send it the local users presence states.
        # We expect to only see user @test2:server, as @test:server is offline
        # and has a zero last_active_ts
        expected_state = self.get_success(
            self.presence_handler.current_state_for_user("@test2:server")
        )
        self.assertEqual(expected_state.state, PresenceState.ONLINE)
        self.federation_sender.send_presence_to_destinations.assert_called_once_with(
            destinations=["server2"], states=[expected_state]
        )

        #
        # Test that only the new server gets sent presence and not existing servers
        #

        self.federation_sender.reset_mock()
        self._add_new_user(room_id, "@bob:server3")

        self.federation_sender.send_presence.assert_not_called()
        self.federation_sender.send_presence_to_destinations.assert_called_once_with(
            destinations=["server3"], states=[expected_state]
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

        # We shouldn't have sent out any local presence *updates*
        self.federation_sender.send_presence.assert_not_called()

        # We expect to only send test2 presence to server2 and server3
        expected_state = self.get_success(
            self.presence_handler.current_state_for_user("@test2:server")
        )
        self.assertEqual(expected_state.state, PresenceState.ONLINE)
        self.federation_sender.send_presence_to_destinations.assert_called_once_with(
            destinations={"server2", "server3"}, states=[expected_state]
        )

    def _add_new_user(self, room_id, user_id):
        """Add new user to the room by creating an event and poking the federation API.
        """

        hostname = get_domain_from_id(user_id)

        room_version = self.get_success(self.store.get_room_version_id(room_id))

        builder = EventBuilder(
            state=self.state,
            auth=self.auth,
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

        event = self.get_success(builder.build(prev_event_ids))

        self.get_success(self.federation_handler.on_receive_pdu(hostname, event))

        # Check that it was successfully persisted.
        self.get_success(self.store.get_event(event.event_id))
        self.get_success(self.store.get_event(event.event_id))
