# -*- coding: utf-8 -*-
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

from mock import Mock

from synapse.events import EventBase
from synapse.module_api import ModuleApi
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.types import Requester, StateMap

from tests import unittest

thread_local = threading.local()


class ThirdPartyRulesTestModule:
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


def current_rules_module() -> ThirdPartyRulesTestModule:
    return thread_local.rules_module


class ThirdPartyRulesTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def default_config(self):
        config = super().default_config()
        config["third_party_event_rules"] = {
            "module": __name__ + ".ThirdPartyRulesTestModule",
            "config": {},
        }
        return config

    def prepare(self, reactor, clock, homeserver):
        # Create a user and room to play with during the tests
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        self.room_id = self.helper.create_room_as(self.user_id, tok=self.tok)

    def test_third_party_rules(self):
        """Tests that a forbidden event is forbidden from being sent, but an allowed one
        can be sent.
        """
        # patch the rules module with a Mock which will return False for some event
        # types
        async def check(ev, state):
            return ev.type != "foo.bar.forbidden"

        callback = Mock(spec=[], side_effect=check)
        current_rules_module().check_event_allowed = callback

        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.allowed/1" % self.room_id,
            {},
            access_token=self.tok,
        )
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        callback.assert_called_once()

        # there should be various state events in the state arg: do some basic checks
        state_arg = callback.call_args[0][1]
        for k in (("m.room.create", ""), ("m.room.member", self.user_id)):
            self.assertIn(k, state_arg)
            ev = state_arg[k]
            self.assertEqual(ev.type, k[0])
            self.assertEqual(ev.state_key, k[1])

        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.forbidden/2" % self.room_id,
            {},
            access_token=self.tok,
        )
        self.render(request)
        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_cannot_modify_event(self):
        """cannot accidentally modify an event before it is persisted"""

        # first patch the event checker so that it will try to modify the event
        async def check(ev: EventBase, state):
            ev.content = {"x": "y"}
            return True

        current_rules_module().check_event_allowed = check

        # now send the event
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {"x": "x"},
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.result["code"], b"500", channel.result)

    def test_modify_event(self):
        """The module can return a modified version of the event"""
        # first patch the event checker so that it will modify the event
        async def check(ev: EventBase, state):
            d = ev.get_dict()
            d["content"] = {"x": "y"}
            return d

        current_rules_module().check_event_allowed = check

        # now send the event
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {"x": "x"},
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.result["code"], b"200", channel.result)
        event_id = channel.json_body["event_id"]

        # ... and check that it got modified
        request, channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.result["code"], b"200", channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["x"], "y")

    def test_send_event(self):
        """Tests that the module can send an event into a room via the module api"""
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
        event = self.get_success(
            current_rules_module().module_api.create_and_send_event_into_room(
                event_dict
            )
        )  # type: EventBase

        self.assertEquals(event.sender, self.user_id)
        self.assertEquals(event.room_id, self.room_id)
        self.assertEquals(event.type, "m.room.message")
        self.assertEquals(event.content, content)
