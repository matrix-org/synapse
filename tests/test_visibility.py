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
from typing import Optional

from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase
from synapse.types import JsonDict
from synapse.visibility import filter_events_for_server

from tests import unittest
from tests.utils import create_room

logger = logging.getLogger(__name__)

TEST_ROOM_ID = "!TEST:ROOM"


class FilterEventsForServerTestCase(unittest.HomeserverTestCase):
    def setUp(self) -> None:
        super(FilterEventsForServerTestCase, self).setUp()
        self.event_creation_handler = self.hs.get_event_creation_handler()
        self.event_builder_factory = self.hs.get_event_builder_factory()
        self.storage = self.hs.get_storage()

        self.get_success(create_room(self.hs, TEST_ROOM_ID, "@someone:ROOM"))

    def test_filtering(self) -> None:
        #
        # The events to be filtered consist of 10 membership events (it doesn't
        # really matter if they are joins or leaves, so let's make them joins).
        # One of those membership events is going to be for a user on the
        # server we are filtering for (so we can check the filtering is doing
        # the right thing).
        #

        # before we do that, we persist some other events to act as state.
        self.get_success(self._inject_visibility("@admin:hs", "joined"))
        for i in range(0, 10):
            self.get_success(self._inject_room_member("@resident%i:hs" % i))

        events_to_filter = []

        for i in range(0, 10):
            user = "@user%i:%s" % (i, "test_server" if i == 5 else "other_server")
            evt = self.get_success(
                self._inject_room_member(user, extra_content={"a": "b"})
            )
            events_to_filter.append(evt)

        filtered = self.get_success(
            filter_events_for_server(self.storage, "test_server", events_to_filter)
        )

        # the result should be 5 redacted events, and 5 unredacted events.
        for i in range(0, 5):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertNotIn("a", filtered[i].content)

        for i in range(5, 10):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertEqual(filtered[i].content["a"], "b")

    def test_erased_user(self) -> None:
        # 4 message events, from erased and unerased users, with a membership
        # change in the middle of them.
        events_to_filter = []

        evt = self.get_success(self._inject_message("@unerased:local_hs"))
        events_to_filter.append(evt)

        evt = self.get_success(self._inject_message("@erased:local_hs"))
        events_to_filter.append(evt)

        evt = self.get_success(self._inject_room_member("@joiner:remote_hs"))
        events_to_filter.append(evt)

        evt = self.get_success(self._inject_message("@unerased:local_hs"))
        events_to_filter.append(evt)

        evt = self.get_success(self._inject_message("@erased:local_hs"))
        events_to_filter.append(evt)

        # the erasey user gets erased
        self.get_success(self.hs.get_datastore().mark_user_erased("@erased:local_hs"))

        # ... and the filtering happens.
        filtered = self.get_success(
            filter_events_for_server(self.storage, "test_server", events_to_filter)
        )

        for i in range(0, len(events_to_filter)):
            self.assertEqual(
                events_to_filter[i].event_id,
                filtered[i].event_id,
                "Unexpected event at result position %i" % (i,),
            )

        for i in (0, 3):
            self.assertEqual(
                events_to_filter[i].content["body"],
                filtered[i].content["body"],
                "Unexpected event content at result position %i" % (i,),
            )

        for i in (1, 4):
            self.assertNotIn("body", filtered[i].content)

    def _inject_visibility(self, user_id: str, visibility: str) -> EventBase:
        content = {"history_visibility": visibility}
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.history_visibility",
                "sender": user_id,
                "state_key": "",
                "room_id": TEST_ROOM_ID,
                "content": content,
            },
        )

        event, context = self.get_success(
            self.event_creation_handler.create_new_client_event(builder)
        )
        self.get_success(self.storage.persistence.persist_event(event, context))
        return event

    def _inject_room_member(
        self,
        user_id: str,
        membership: str = "join",
        extra_content: Optional[JsonDict] = None,
    ) -> EventBase:
        content = {"membership": membership}
        content.update(extra_content or {})
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": TEST_ROOM_ID,
                "content": content,
            },
        )

        event, context = self.get_success(
            self.event_creation_handler.create_new_client_event(builder)
        )

        self.get_success(self.storage.persistence.persist_event(event, context))
        return event

    def _inject_message(
        self, user_id: str, content: Optional[JsonDict] = None
    ) -> EventBase:
        if content is None:
            content = {"body": "testytest", "msgtype": "m.text"}
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.message",
                "sender": user_id,
                "room_id": TEST_ROOM_ID,
                "content": content,
            },
        )

        event, context = self.get_success(
            self.event_creation_handler.create_new_client_event(builder)
        )

        self.get_success(self.storage.persistence.persist_event(event, context))
        return event
