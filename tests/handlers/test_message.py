# -*- coding: utf-8 -*-
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
import logging

from synapse.api.constants import EventTypes
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.types import create_requester

from tests import unittest

logger = logging.getLogger(__name__)


class EventCreationTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def test_duplicated_txn_id(self):
        """Test that attempting to handle/persist an event with a transaction ID
        that has already been persisted correctly returns the old event and does
        *not* produce duplicate messages.
        """

        handler = self.hs.get_event_creation_handler()
        persist_event_storage = self.hs.get_storage().persistence

        user_id = self.register_user("tester", "foobar")
        access_token = self.login("tester", "foobar")
        room_id = self.helper.create_room_as(user_id, tok=access_token)

        # We make the IDs up here, which is fine.
        token_id = 4957834
        txn_id = "something_suitably_random"

        requester = create_requester(user_id, access_token_id=token_id)

        def create_duplicate_event():
            return self.get_success(
                handler.create_event(
                    requester,
                    {
                        "type": EventTypes.Message,
                        "room_id": room_id,
                        "sender": requester.user.to_string(),
                        "content": {"msgtype": "m.text", "body": "Hello"},
                    },
                    token_id=4957834,
                    txn_id=txn_id,
                )
            )

        event1, context = create_duplicate_event()

        ret_event1, stream_id1 = self.get_success(
            handler.handle_new_client_event(requester, event1, context)
        )

        self.assertEqual(event1.event_id, ret_event1.event_id)

        event2, context = create_duplicate_event()

        # We want to test that the deduplication at the persit event end works,
        # so we want to make sure we test with different events.
        self.assertNotEqual(event1.event_id, event2.event_id)

        ret_event2, stream_id2 = self.get_success(
            handler.handle_new_client_event(requester, event2, context)
        )

        # Assert that the returned values match those from the initial event
        # rather than the new one.
        self.assertEqual(ret_event1.event_id, ret_event2.event_id)
        self.assertEqual(stream_id1, stream_id2)

        # Let's test that calling `persist_event` directly also does the right
        # thing.
        event3, context = create_duplicate_event()
        self.assertNotEqual(event1.event_id, event3.event_id)

        ret_event3, event_pos3, _ = self.get_success(
            persist_event_storage.persist_event(event3, context)
        )

        # Assert that the returned values match those from the initial event
        # rather than the new one.
        self.assertEqual(ret_event1.event_id, ret_event3.event_id)
        self.assertEqual(stream_id1, event_pos3.stream)

        # Let's test that calling `persist_events` directly also does the right
        # thing.
        event4, context = create_duplicate_event()
        self.assertNotEqual(event1.event_id, event3.event_id)

        events, _ = self.get_success(
            persist_event_storage.persist_events([(event3, context)])
        )
        ret_event4 = events[0]

        # Assert that the returned values match those from the initial event
        # rather than the new one.
        self.assertEqual(ret_event1.event_id, ret_event4.event_id)
