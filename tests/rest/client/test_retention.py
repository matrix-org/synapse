# Copyright 2019 New Vector Ltd
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
from typing import Any, Dict
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import JsonDict, create_requester
from synapse.util import Clock
from synapse.visibility import filter_events_for_client

from tests import unittest
from tests.unittest import override_config

one_hour_ms = 3600000
one_day_ms = one_hour_ms * 24


class RetentionTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        # merge this default retention config with anything that was specified in
        # @override_config
        retention_config = {
            "enabled": True,
            "default_policy": {
                "min_lifetime": one_day_ms,
                "max_lifetime": one_day_ms * 3,
            },
            "allowed_lifetime_min": one_day_ms,
            "allowed_lifetime_max": one_day_ms * 3,
        }
        retention_config.update(config.get("retention", {}))
        config["retention"] = retention_config

        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_id = self.register_user("user", "password")
        self.token = self.login("user", "password")

        self.store = self.hs.get_datastores().main
        self.serializer = self.hs.get_event_client_serializer()
        self.clock = self.hs.get_clock()

    def test_retention_event_purged_with_state_event(self) -> None:
        """Tests that expired events are correctly purged when the room's retention policy
        is defined by a state event.
        """
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        # Set the room's retention period to 2 days.
        lifetime = one_day_ms * 2
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.Retention,
            body={"max_lifetime": lifetime},
            tok=self.token,
        )

        self._test_retention_event_purged(room_id, one_day_ms * 1.5)

    def test_retention_event_purged_with_state_event_outside_allowed(self) -> None:
        """Tests that the server configuration can override the policy for a room when
        running the purge jobs.
        """
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        # Set a max_lifetime higher than the maximum allowed value.
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.Retention,
            body={"max_lifetime": one_day_ms * 4},
            tok=self.token,
        )

        # Check that the event is purged after waiting for the maximum allowed duration
        # instead of the one specified in the room's policy.
        self._test_retention_event_purged(room_id, one_day_ms * 1.5)

        # Set a max_lifetime lower than the minimum allowed value.
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.Retention,
            body={"max_lifetime": one_hour_ms},
            tok=self.token,
        )

        # Check that the event is purged after waiting for the minimum allowed duration
        # instead of the one specified in the room's policy.
        self._test_retention_event_purged(room_id, one_day_ms * 0.5)

    def test_retention_event_purged_without_state_event(self) -> None:
        """Tests that expired events are correctly purged when the room's retention policy
        is defined by the server's configuration's default retention policy.
        """
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        self._test_retention_event_purged(room_id, one_day_ms * 2)

    @override_config({"retention": {"purge_jobs": [{"interval": "5d"}]}})
    def test_visibility(self) -> None:
        """Tests that synapse.visibility.filter_events_for_client correctly filters out
        outdated events, even if the purge job hasn't got to them yet.

        We do this by setting a very long time between purge jobs.
        """
        store = self.hs.get_datastores().main
        storage_controllers = self.hs.get_storage_controllers()
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        # Send a first event, which should be filtered out at the end of the test.
        resp = self.helper.send(room_id=room_id, body="1", tok=self.token)
        first_event_id = resp.get("event_id")

        # Advance the time by 2 days. We're using the default retention policy, therefore
        # after this the first event will still be valid.
        self.reactor.advance(one_day_ms * 2 / 1000)

        # Send another event, which shouldn't get filtered out.
        resp = self.helper.send(room_id=room_id, body="2", tok=self.token)
        valid_event_id = resp.get("event_id")

        # Advance the time by another 2 days. After this, the first event should be
        # outdated but not the second one.
        self.reactor.advance(one_day_ms * 2 / 1000)

        # Fetch the events, and run filter_events_for_client on them
        events = self.get_success(
            store.get_events_as_list([first_event_id, valid_event_id])
        )
        self.assertEqual(2, len(events), "events retrieved from database")
        filtered_events = self.get_success(
            filter_events_for_client(storage_controllers, self.user_id, events)
        )

        # We should only get one event back.
        self.assertEqual(len(filtered_events), 1, filtered_events)
        # That event should be the second, not outdated event.
        self.assertEqual(filtered_events[0].event_id, valid_event_id, filtered_events)

    def _test_retention_event_purged(self, room_id: str, increment: float) -> None:
        """Run the following test scenario to test the message retention policy support:

        1. Send event 1
        2. Increment time by `increment`
        3. Send event 2
        4. Increment time by `increment`
        5. Check that event 1 has been purged
        6. Check that event 2 has not been purged
        7. Check that state events that were sent before event 1 aren't purged.
        The main reason for sending a second event is because currently Synapse won't
        purge the latest message in a room because it would otherwise result in a lack of
        forward extremities for this room. It's also a good thing to ensure the purge jobs
        aren't too greedy and purge messages they shouldn't.

        Args:
            room_id: The ID of the room to test retention in.
            increment: The number of milliseconds to advance the clock each time. Must be
                defined so that events in the room aren't purged if they are `increment`
                old but are purged if they are `increment * 2` old.
        """
        # Get the create event to, later, check that we can still access it.
        message_handler = self.hs.get_message_handler()
        create_event = self.get_success(
            message_handler.get_room_data(
                create_requester(self.user_id), room_id, EventTypes.Create, state_key=""
            )
        )

        # Send a first event to the room. This is the event we'll want to be purged at the
        # end of the test.
        resp = self.helper.send(room_id=room_id, body="1", tok=self.token)

        expired_event_id = resp.get("event_id")
        assert expired_event_id is not None

        # Check that we can retrieve the event.
        expired_event = self.get_event(expired_event_id)
        self.assertEqual(
            expired_event.get("content", {}).get("body"), "1", expired_event
        )

        # Advance the time.
        self.reactor.advance(increment / 1000)

        # Send another event. We need this because the purge job won't purge the most
        # recent event in the room.
        resp = self.helper.send(room_id=room_id, body="2", tok=self.token)

        valid_event_id = resp.get("event_id")
        assert valid_event_id is not None

        # Advance the time again. Now our first event should have expired but our second
        # one should still be kept.
        self.reactor.advance(increment / 1000)

        # Check that the first event has been purged from the database, i.e. that we
        # can't retrieve it anymore, because it has expired.
        self.get_event(expired_event_id, expect_none=True)

        # Check that the event that hasn't expired can still be retrieved.
        valid_event = self.get_event(valid_event_id)
        self.assertEqual(valid_event.get("content", {}).get("body"), "2", valid_event)

        # Check that we can still access state events that were sent before the event that
        # has been purged.
        self.get_event(room_id, create_event.event_id)

    def get_event(self, event_id: str, expect_none: bool = False) -> JsonDict:
        event = self.get_success(self.store.get_event(event_id, allow_none=True))

        if expect_none:
            self.assertIsNone(event)
            return {}

        self.assertIsNotNone(event)

        time_now = self.clock.time_msec()
        serialized = self.serializer.serialize_event(event, time_now)

        return serialized


class RetentionNoDefaultPolicyTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()

        retention_config = {
            "enabled": True,
        }

        # Update this config with what's in the default config so that
        # override_config works as expected.
        retention_config.update(config.get("retention", {}))
        config["retention"] = retention_config

        return config

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        mock_federation_client = Mock(spec=["backfill"])

        self.hs = self.setup_test_homeserver(
            federation_client=mock_federation_client,
        )
        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_id = self.register_user("user", "password")
        self.token = self.login("user", "password")

    def test_no_default_policy(self) -> None:
        """Tests that an event doesn't get expired if there is neither a default retention
        policy nor a policy specific to the room.
        """
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        self._test_retention(room_id)

    def test_state_policy(self) -> None:
        """Tests that an event gets correctly expired if there is no default retention
        policy but there's a policy specific to the room.
        """
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        # Set the maximum lifetime to 35 days so that the first event gets expired but not
        # the second one.
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.Retention,
            body={"max_lifetime": one_day_ms * 35},
            tok=self.token,
        )

        self._test_retention(room_id, expected_code_for_first_event=404)

    @unittest.override_config({"retention": {"enabled": False}})
    def test_visibility_when_disabled(self) -> None:
        """Retention policies should be ignored when the retention feature is disabled."""
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.Retention,
            body={"max_lifetime": one_day_ms},
            tok=self.token,
        )

        resp = self.helper.send(room_id=room_id, body="test", tok=self.token)

        self.reactor.advance(one_day_ms * 2 / 1000)

        self.get_event(room_id, resp["event_id"])

    def _test_retention(
        self, room_id: str, expected_code_for_first_event: int = 200
    ) -> None:
        # Send a first event to the room. This is the event we'll want to be purged at the
        # end of the test.
        resp = self.helper.send(room_id=room_id, body="1", tok=self.token)

        first_event_id = resp.get("event_id")
        assert first_event_id is not None

        # Check that we can retrieve the event.
        expired_event = self.get_event(room_id, first_event_id)
        self.assertEqual(
            expired_event.get("content", {}).get("body"), "1", expired_event
        )

        # Advance the time by a month.
        self.reactor.advance(one_day_ms * 30 / 1000)

        # Send another event. We need this because the purge job won't purge the most
        # recent event in the room.
        resp = self.helper.send(room_id=room_id, body="2", tok=self.token)

        second_event_id = resp.get("event_id")
        assert second_event_id is not None

        # Advance the time by another month.
        self.reactor.advance(one_day_ms * 30 / 1000)

        # Check if the event has been purged from the database.
        first_event = self.get_event(
            room_id, first_event_id, expected_code=expected_code_for_first_event
        )

        if expected_code_for_first_event == 200:
            self.assertEqual(
                first_event.get("content", {}).get("body"), "1", first_event
            )

        # Check that the event that hasn't been purged can still be retrieved.
        second_event = self.get_event(room_id, second_event_id)
        self.assertEqual(second_event.get("content", {}).get("body"), "2", second_event)

    def get_event(
        self, room_id: str, event_id: str, expected_code: int = 200
    ) -> JsonDict:
        url = "/_matrix/client/r0/rooms/%s/event/%s" % (room_id, event_id)

        channel = self.make_request("GET", url, access_token=self.token)

        self.assertEqual(channel.code, expected_code, channel.result)

        return channel.json_body
