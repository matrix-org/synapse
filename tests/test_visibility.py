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
from unittest.mock import patch

from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase, make_event_from_dict
from synapse.events.snapshot import EventContext
from synapse.types import JsonDict, create_requester
from synapse.visibility import filter_events_for_client, filter_events_for_server

from tests import unittest
from tests.utils import create_room

logger = logging.getLogger(__name__)

TEST_ROOM_ID = "!TEST:ROOM"


class FilterEventsForServerTestCase(unittest.HomeserverTestCase):
    def setUp(self) -> None:
        super(FilterEventsForServerTestCase, self).setUp()
        self.event_creation_handler = self.hs.get_event_creation_handler()
        self.event_builder_factory = self.hs.get_event_builder_factory()
        self._storage_controllers = self.hs.get_storage_controllers()

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
        self._inject_visibility("@admin:hs", "joined")
        for i in range(0, 10):
            self._inject_room_member("@resident%i:hs" % i)

        events_to_filter = []

        for i in range(0, 10):
            user = "@user%i:%s" % (i, "test_server" if i == 5 else "other_server")
            evt = self._inject_room_member(user, extra_content={"a": "b"})
            events_to_filter.append(evt)

        filtered = self.get_success(
            filter_events_for_server(
                self._storage_controllers, "test_server", events_to_filter
            )
        )

        # the result should be 5 redacted events, and 5 unredacted events.
        for i in range(0, 5):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertNotIn("a", filtered[i].content)

        for i in range(5, 10):
            self.assertEqual(events_to_filter[i].event_id, filtered[i].event_id)
            self.assertEqual(filtered[i].content["a"], "b")

    def test_filter_outlier(self) -> None:
        # outlier events must be returned, for the good of the collective federation
        self._inject_room_member("@resident:remote_hs")
        self._inject_visibility("@resident:remote_hs", "joined")

        outlier = self._inject_outlier()
        self.assertEqual(
            self.get_success(
                filter_events_for_server(
                    self._storage_controllers, "remote_hs", [outlier]
                )
            ),
            [outlier],
        )

        # it should also work when there are other events in the list
        evt = self._inject_message("@unerased:local_hs")

        filtered = self.get_success(
            filter_events_for_server(
                self._storage_controllers, "remote_hs", [outlier, evt]
            )
        )
        self.assertEqual(len(filtered), 2, f"expected 2 results, got: {filtered}")
        self.assertEqual(filtered[0], outlier)
        self.assertEqual(filtered[1].event_id, evt.event_id)
        self.assertEqual(filtered[1].content, evt.content)

        # ... but other servers should only be able to see the outlier (the other should
        # be redacted)
        filtered = self.get_success(
            filter_events_for_server(
                self._storage_controllers, "other_server", [outlier, evt]
            )
        )
        self.assertEqual(filtered[0], outlier)
        self.assertEqual(filtered[1].event_id, evt.event_id)
        self.assertNotIn("body", filtered[1].content)

    def test_erased_user(self) -> None:
        # 4 message events, from erased and unerased users, with a membership
        # change in the middle of them.
        events_to_filter = []

        evt = self._inject_message("@unerased:local_hs")
        events_to_filter.append(evt)

        evt = self._inject_message("@erased:local_hs")
        events_to_filter.append(evt)

        evt = self._inject_room_member("@joiner:remote_hs")
        events_to_filter.append(evt)

        evt = self._inject_message("@unerased:local_hs")
        events_to_filter.append(evt)

        evt = self._inject_message("@erased:local_hs")
        events_to_filter.append(evt)

        # the erasey user gets erased
        self.get_success(
            self.hs.get_datastores().main.mark_user_erased("@erased:local_hs")
        )

        # ... and the filtering happens.
        filtered = self.get_success(
            filter_events_for_server(
                self._storage_controllers, "test_server", events_to_filter
            )
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
        self.get_success(
            self._storage_controllers.persistence.persist_event(event, context)
        )
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

        self.get_success(
            self._storage_controllers.persistence.persist_event(event, context)
        )
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

        self.get_success(
            self._storage_controllers.persistence.persist_event(event, context)
        )
        return event

    def _inject_outlier(self) -> EventBase:
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": "m.room.member",
                "sender": "@test:user",
                "state_key": "@test:user",
                "room_id": TEST_ROOM_ID,
                "content": {"membership": "join"},
            },
        )

        event = self.get_success(builder.build(prev_event_ids=[], auth_event_ids=[]))
        event.internal_metadata.outlier = True
        self.get_success(
            self._storage_controllers.persistence.persist_event(
                event, EventContext.for_outlier(self._storage_controllers)
            )
        )
        return event


class FilterEventsForClientTestCase(unittest.FederatingHomeserverTestCase):
    def test_out_of_band_invite_rejection(self):
        # this is where we have received an invite event over federation, and then
        # rejected it.
        invite_pdu = {
            "room_id": "!room:id",
            "depth": 1,
            "auth_events": [],
            "prev_events": [],
            "origin_server_ts": 1,
            "sender": "@someone:" + self.OTHER_SERVER_NAME,
            "type": "m.room.member",
            "state_key": "@user:test",
            "content": {"membership": "invite"},
        }
        self.add_hashes_and_signatures_from_other_server(invite_pdu)
        invite_event_id = make_event_from_dict(invite_pdu, RoomVersions.V9).event_id

        self.get_success(
            self.hs.get_federation_server().on_invite_request(
                self.OTHER_SERVER_NAME,
                invite_pdu,
                "9",
            )
        )

        # stub out do_remotely_reject_invite so that we fall back to a locally-
        # generated rejection
        with patch.object(
            self.hs.get_federation_handler(),
            "do_remotely_reject_invite",
            side_effect=Exception(),
        ):
            reject_event_id, _ = self.get_success(
                self.hs.get_room_member_handler().remote_reject_invite(
                    invite_event_id,
                    txn_id=None,
                    requester=create_requester("@user:test"),
                    content={},
                )
            )

        invite_event, reject_event = self.get_success(
            self.hs.get_datastores().main.get_events_as_list(
                [invite_event_id, reject_event_id]
            )
        )

        # the invited user should be able to see both the invite and the rejection
        self.assertEqual(
            self.get_success(
                filter_events_for_client(
                    self.hs.get_storage_controllers(),
                    "@user:test",
                    [invite_event, reject_event],
                )
            ),
            [invite_event, reject_event],
        )

        # other users should see neither
        self.assertEqual(
            self.get_success(
                filter_events_for_client(
                    self.hs.get_storage_controllers(),
                    "@other:test",
                    [invite_event, reject_event],
                )
            ),
            [],
        )
