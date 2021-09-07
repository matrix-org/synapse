# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import threading
from typing import Dict
from unittest.mock import Mock

from synapse.events import EventBase
from synapse.events.third_party_rules import load_legacy_third_party_event_rules
from synapse.module_api import ModuleApi
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.types import Requester, StateMap
from synapse.util.frozenutils import unfreeze

from tests import unittest

thread_local = threading.local()


class LegacyThirdPartyRulesTestModule:
    def __init__(self, config: Dict, module_api: ModuleApi):
        # keep a record of the "current" rules module, so that the test can patch
        # it if desired.
        thread_local.rules_module = self
        self.module_api = module_api

    async def on_create_room(
        self, requester: Requester, config: dict, is_requester_admin: bool
    ):
        return True

    async def check_event_allowed(self, event: EventBase, state: StateMap[EventBase]):
        return True

    @staticmethod
    def parse_config(config):
        return config


class LegacyDenyNewRooms(LegacyThirdPartyRulesTestModule):
    def __init__(self, config: Dict, module_api: ModuleApi):
        super().__init__(config, module_api)

    def on_create_room(
        self, requester: Requester, config: dict, is_requester_admin: bool
    ):
        return False


class LegacyChangeEvents(LegacyThirdPartyRulesTestModule):
    def __init__(self, config: Dict, module_api: ModuleApi):
        super().__init__(config, module_api)

    async def check_event_allowed(self, event: EventBase, state: StateMap[EventBase]):
        d = event.get_dict()
        content = unfreeze(event.content)
        content["foo"] = "bar"
        d["content"] = content
        return d


class ThirdPartyRulesTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()

        load_legacy_third_party_event_rules(hs)

        return hs

    def prepare(self, reactor, clock, homeserver):
        # Create a user and room to play with during the tests
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        # Some tests might prevent room creation on purpose.
        try:
            self.room_id = self.helper.create_room_as(self.user_id, tok=self.tok)
        except Exception:
            pass

    def test_third_party_rules(self):
        """Tests that a forbidden event is forbidden from being sent, but an allowed one
        can be sent.
        """
        # patch the rules module with a Mock which will return False for some event
        # types
        async def check(ev, state):
            return ev.type != "foo.bar.forbidden", None

        callback = Mock(spec=[], side_effect=check)
        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [
            callback
        ]

        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.allowed/1" % self.room_id,
            {},
            access_token=self.tok,
        )
        self.assertEquals(channel.result["code"], b"200", channel.result)

        callback.assert_called_once()

        # there should be various state events in the state arg: do some basic checks
        state_arg = callback.call_args[0][1]
        for k in (("m.room.create", ""), ("m.room.member", self.user_id)):
            self.assertIn(k, state_arg)
            ev = state_arg[k]
            self.assertEqual(ev.type, k[0])
            self.assertEqual(ev.state_key, k[1])

        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.forbidden/2" % self.room_id,
            {},
            access_token=self.tok,
        )
        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_cannot_modify_event(self):
        """cannot accidentally modify an event before it is persisted"""

        # first patch the event checker so that it will try to modify the event
        async def check(ev: EventBase, state):
            ev.content = {"x": "y"}
            return True, None

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [check]

        # now send the event
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {"x": "x"},
            access_token=self.tok,
        )
        # check_event_allowed has some error handling, so it shouldn't 500 just because a
        # module did something bad.
        self.assertEqual(channel.code, 200, channel.result)
        event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 200, channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["x"], "x")

    def test_modify_event(self):
        """The module can return a modified version of the event"""
        # first patch the event checker so that it will modify the event
        async def check(ev: EventBase, state):
            d = ev.get_dict()
            d["content"] = {"x": "y"}
            return True, d

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [check]

        # now send the event
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {"x": "x"},
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        event_id = channel.json_body["event_id"]

        # ... and check that it got modified
        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["x"], "y")

    def test_message_edit(self):
        """Ensure that the module doesn't cause issues with edited messages."""
        # first patch the event checker so that it will modify the event
        async def check(ev: EventBase, state):
            d = ev.get_dict()
            d["content"] = {
                "msgtype": "m.text",
                "body": d["content"]["body"].upper(),
            }
            return True, d

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [check]

        # Send an event, then edit it.
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {
                "msgtype": "m.text",
                "body": "Original body",
            },
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        orig_event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/m.room.message/2" % self.room_id,
            {
                "m.new_content": {"msgtype": "m.text", "body": "Edited body"},
                "m.relates_to": {
                    "rel_type": "m.replace",
                    "event_id": orig_event_id,
                },
                "msgtype": "m.text",
                "body": "Edited body",
            },
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        edited_event_id = channel.json_body["event_id"]

        # ... and check that they both got modified
        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, orig_event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["body"], "ORIGINAL BODY")

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, edited_event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["body"], "EDITED BODY")

    def test_send_event(self):
        """Tests that a module can send an event into a room via the module api"""
        content = {
            "msgtype": "m.text",
            "body": "Hello!",
        }
        event_dict = {
            "room_id": self.room_id,
            "type": "m.room.message",
            "content": content,
            "sender": self.user_id,
        }
        event: EventBase = self.get_success(
            self.hs.get_module_api().create_and_send_event_into_room(event_dict)
        )

        self.assertEquals(event.sender, self.user_id)
        self.assertEquals(event.room_id, self.room_id)
        self.assertEquals(event.type, "m.room.message")
        self.assertEquals(event.content, content)

    @unittest.override_config(
        {
            "third_party_event_rules": {
                "module": __name__ + ".LegacyChangeEvents",
                "config": {},
            }
        }
    )
    def test_legacy_check_event_allowed(self):
        """Tests that the wrapper for legacy check_event_allowed callbacks works
        correctly.
        """
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/m.room.message/1" % self.room_id,
            {
                "msgtype": "m.text",
                "body": "Original body",
            },
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)

        event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)

        self.assertIn("foo", channel.json_body["content"].keys())
        self.assertEqual(channel.json_body["content"]["foo"], "bar")

    @unittest.override_config(
        {
            "third_party_event_rules": {
                "module": __name__ + ".LegacyDenyNewRooms",
                "config": {},
            }
        }
    )
    def test_legacy_on_create_room(self):
        """Tests that the wrapper for legacy on_create_room callbacks works
        correctly.
        """
        self.helper.create_room_as(self.user_id, tok=self.tok, expect_code=403)
