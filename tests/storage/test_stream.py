#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from typing import List

from synapse.api.constants import EventTypes, RelationTypes
from synapse.api.filtering import Filter
from synapse.events import EventBase
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.types import JsonDict

from tests.unittest import HomeserverTestCase


class PaginationTestCase(HomeserverTestCase):
    """
    Test the pre-filtering done in the pagination code.

    This is similar to some of the tests in tests.rest.client.test_rooms but here
    we ensure that the filtering done in the database is applied successfully.
    """

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def default_config(self):
        config = super().default_config()
        config["experimental_features"] = {"msc3440_enabled": True}
        return config

    def prepare(self, reactor, clock, homeserver):
        self.user_id = self.register_user("test", "test")
        self.tok = self.login("test", "test")
        self.room_id = self.helper.create_room_as(self.user_id, tok=self.tok)

        self.second_user_id = self.register_user("second", "test")
        self.second_tok = self.login("second", "test")
        self.helper.join(
            room=self.room_id, user=self.second_user_id, tok=self.second_tok
        )

        self.third_user_id = self.register_user("third", "test")
        self.third_tok = self.login("third", "test")
        self.helper.join(room=self.room_id, user=self.third_user_id, tok=self.third_tok)

        # An initial event with a relation from second user.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "Message 1"},
            tok=self.tok,
        )
        self.event_id_1 = res["event_id"]
        self.helper.send_event(
            room_id=self.room_id,
            type="m.reaction",
            content={
                "m.relates_to": {
                    "rel_type": RelationTypes.ANNOTATION,
                    "event_id": self.event_id_1,
                    "key": "👍",
                }
            },
            tok=self.second_tok,
        )

        # Another event with a relation from third user.
        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "Message 2"},
            tok=self.tok,
        )
        self.event_id_2 = res["event_id"]
        self.helper.send_event(
            room_id=self.room_id,
            type="m.reaction",
            content={
                "m.relates_to": {
                    "rel_type": RelationTypes.REFERENCE,
                    "event_id": self.event_id_2,
                }
            },
            tok=self.third_tok,
        )

        # An event with no relations.
        self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "No relations"},
            tok=self.tok,
        )

    def _filter_messages(self, filter: JsonDict) -> List[EventBase]:
        """Make a request to /messages with a filter, returns the chunk of events."""

        from_token = self.get_success(
            self.hs.get_event_sources().get_current_token_for_pagination(self.room_id)
        )

        events, next_key = self.get_success(
            self.hs.get_datastores().main.paginate_room_events(
                room_id=self.room_id,
                from_key=from_token.room_key,
                to_key=None,
                direction="b",
                limit=10,
                event_filter=Filter(self.hs, filter),
            )
        )

        return events

    def test_filter_relation_senders(self):
        # Messages which second user reacted to.
        filter = {"related_by_senders": [self.second_user_id]}
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 1, chunk)
        self.assertEqual(chunk[0].event_id, self.event_id_1)

        # Messages which third user reacted to.
        filter = {"related_by_senders": [self.third_user_id]}
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 1, chunk)
        self.assertEqual(chunk[0].event_id, self.event_id_2)

        # Messages which either user reacted to.
        filter = {"related_by_senders": [self.second_user_id, self.third_user_id]}
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 2, chunk)
        self.assertCountEqual(
            [c.event_id for c in chunk], [self.event_id_1, self.event_id_2]
        )

    def test_filter_relation_type(self):
        # Messages which have annotations.
        filter = {"related_by_rel_types": [RelationTypes.ANNOTATION]}
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 1, chunk)
        self.assertEqual(chunk[0].event_id, self.event_id_1)

        # Messages which have references.
        filter = {"related_by_rel_types": [RelationTypes.REFERENCE]}
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 1, chunk)
        self.assertEqual(chunk[0].event_id, self.event_id_2)

        # Messages which have either annotations or references.
        filter = {
            "related_by_rel_types": [
                RelationTypes.ANNOTATION,
                RelationTypes.REFERENCE,
            ]
        }
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 2, chunk)
        self.assertCountEqual(
            [c.event_id for c in chunk], [self.event_id_1, self.event_id_2]
        )

    def test_filter_relation_senders_and_type(self):
        # Messages which second user reacted to.
        filter = {
            "related_by_senders": [self.second_user_id],
            "related_by_rel_types": [RelationTypes.ANNOTATION],
        }
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 1, chunk)
        self.assertEqual(chunk[0].event_id, self.event_id_1)

    def test_duplicate_relation(self):
        """An event should only be returned once if there are multiple relations to it."""
        self.helper.send_event(
            room_id=self.room_id,
            type="m.reaction",
            content={
                "m.relates_to": {
                    "rel_type": RelationTypes.ANNOTATION,
                    "event_id": self.event_id_1,
                    "key": "A",
                }
            },
            tok=self.second_tok,
        )

        filter = {"related_by_senders": [self.second_user_id]}
        chunk = self._filter_messages(filter)
        self.assertEqual(len(chunk), 1, chunk)
        self.assertEqual(chunk[0].event_id, self.event_id_1)
