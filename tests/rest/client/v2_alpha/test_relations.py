# -*- coding: utf-8 -*-
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

import six

from synapse.api.constants import EventTypes, RelationTypes
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import relations

from tests import unittest


class RelationsTestCase(unittest.HomeserverTestCase):
    user_id = "@alice:test"
    servlets = [
        relations.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.room = self.helper.create_room_as(self.user_id)
        res = self.helper.send(self.room, body="Hi!")
        self.parent_id = res["event_id"]

    def test_send_relation(self):
        """Tests that sending a relation using the new /send_relation works
        creates the right shape of event.
        """

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="👍")
        self.assertEquals(200, channel.code, channel.json_body)

        event_id = channel.json_body["event_id"]

        request, channel = self.make_request(
            "GET", "/rooms/%s/event/%s" % (self.room, event_id)
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.json_body)

        self.assert_dict(
            {
                "type": "m.reaction",
                "sender": self.user_id,
                "content": {
                    "m.relates_to": {
                        "event_id": self.parent_id,
                        "key": u"👍",
                        "rel_type": RelationTypes.ANNOTATION,
                    }
                },
            },
            channel.json_body,
        )

    def test_deny_membership(self):
        """Test that we deny relations on membership events
        """
        channel = self._send_relation(RelationTypes.ANNOTATION, EventTypes.Member)
        self.assertEquals(400, channel.code, channel.json_body)

    def _send_relation(self, relation_type, event_type, key=None):
        """Helper function to send a relation pointing at `self.parent_id`

        Args:
            relation_type (str): One of `RelationTypes`
            event_type (str): The type of the event to create
            key (str|None): The aggregation key used for m.annotation relation
                type.

        Returns:
            FakeChannel
        """
        query = ""
        if key:
            query = "?key=" + six.moves.urllib.parse.quote_plus(key)

        request, channel = self.make_request(
            "POST",
            "/_matrix/client/unstable/rooms/%s/send_relation/%s/%s/%s%s"
            % (self.room, self.parent_id, relation_type, event_type, query),
            b"{}",
        )
        self.render(request)
        return channel
