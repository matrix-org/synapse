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


from tests import unittest

from mock import Mock, call

from synapse.api.constants import PresenceState
from synapse.handlers.presence import (
    handle_update, handle_timeout,
    IDLE_TIMER, SYNC_ONLINE_TIMEOUT, LAST_ACTIVE_GRANULARITY, FEDERATION_TIMEOUT,
    FEDERATION_PING_INTERVAL,
)
from synapse.storage.presence import UserPresenceState


class PresenceUpdateTestCase(unittest.TestCase):
    def test_offline_to_online(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
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
        wheel_timer.insert.assert_has_calls([
            call(
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + IDLE_TIMER
            ),
            call(
                now=now,
                obj=user_id,
                then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT
            ),
            call(
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY
            ),
        ], any_order=True)

    def test_online_to_online(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            currently_active=True,
        )

        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
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
        wheel_timer.insert.assert_has_calls([
            call(
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + IDLE_TIMER
            ),
            call(
                now=now,
                obj=user_id,
                then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT
            ),
            call(
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY
            ),
        ], any_order=True)

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
            state=PresenceState.ONLINE,
            last_active_ts=now,
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
        wheel_timer.insert.assert_has_calls([
            call(
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + IDLE_TIMER
            ),
            call(
                now=now,
                obj=user_id,
                then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT
            ),
            call(
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY
            ),
        ], any_order=True)

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

        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
        )

        state, persist_and_notify, federation_ping = handle_update(
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
        )

        self.assertTrue(persist_and_notify)
        self.assertFalse(state.currently_active)
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)
        self.assertEquals(state.last_federation_update_ts, now)

        self.assertEquals(wheel_timer.insert.call_count, 2)
        wheel_timer.insert.assert_has_calls([
            call(
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + IDLE_TIMER
            ),
            call(
                now=now,
                obj=user_id,
                then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT
            )
        ], any_order=True)

    def test_remote_ping_timer(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
        )

        new_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
        )

        state, persist_and_notify, federation_ping = handle_update(
            prev_state, new_state, is_mine=False, wheel_timer=wheel_timer, now=now
        )

        self.assertFalse(persist_and_notify)
        self.assertFalse(federation_ping)
        self.assertFalse(state.currently_active)
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)

        self.assertEquals(wheel_timer.insert.call_count, 1)
        wheel_timer.insert.assert_has_calls([
            call(
                now=now,
                obj=user_id,
                then=new_state.last_federation_update_ts + FEDERATION_TIMEOUT
            ),
        ], any_order=True)

    def test_online_to_offline(self):
        wheel_timer = Mock()
        user_id = "@foo:bar"
        now = 5000000

        prev_state = UserPresenceState.default(user_id)
        prev_state = prev_state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            currently_active=True,
        )

        new_state = prev_state.copy_and_replace(
            state=PresenceState.OFFLINE,
        )

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
            state=PresenceState.ONLINE,
            last_active_ts=now,
            currently_active=True,
        )

        new_state = prev_state.copy_and_replace(
            state=PresenceState.UNAVAILABLE,
        )

        state, persist_and_notify, federation_ping = handle_update(
            prev_state, new_state, is_mine=True, wheel_timer=wheel_timer, now=now
        )

        self.assertTrue(persist_and_notify)
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(state.last_federation_update_ts, now)
        self.assertEquals(new_state.state, state.state)
        self.assertEquals(new_state.status_msg, state.status_msg)

        self.assertEquals(wheel_timer.insert.call_count, 1)
        wheel_timer.insert.assert_has_calls([
            call(
                now=now,
                obj=user_id,
                then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT
            )
        ], any_order=True)


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

        new_state = handle_timeout(
            state, is_mine=True, syncing_user_ids=set(), now=now
        )

        self.assertIsNotNone(new_state)
        self.assertEquals(new_state.state, PresenceState.UNAVAILABLE)

    def test_sync_timeout(self):
        user_id = "@foo:bar"
        now = 5000000

        state = UserPresenceState.default(user_id)
        state = state.copy_and_replace(
            state=PresenceState.ONLINE,
            last_active_ts=now,
            last_user_sync_ts=now - SYNC_ONLINE_TIMEOUT - 1,
        )

        new_state = handle_timeout(
            state, is_mine=True, syncing_user_ids=set(), now=now
        )

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
            state, is_mine=True, syncing_user_ids=set([user_id]), now=now
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

        new_state = handle_timeout(
            state, is_mine=True, syncing_user_ids=set(), now=now
        )

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

        new_state = handle_timeout(
            state, is_mine=True, syncing_user_ids=set(), now=now
        )

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

        new_state = handle_timeout(
            state, is_mine=True, syncing_user_ids=set(), now=now
        )

        self.assertIsNotNone(new_state)
        self.assertEquals(state, new_state)
