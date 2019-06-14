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

from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests import unittest


class ThirdPartyRulesTestModule(object):
    def __init__(self, config):
        pass

    def check_event_allowed(self, event, context):
        if event.type == "foo.bar.forbidden":
            return False
        else:
            return True

    @staticmethod
    def parse_config(config):
        return config


class ThirdPartyRulesTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["third_party_event_rules"] = {
            "module": "tests.rest.client.third_party_rules.ThirdPartyRulesTestModule",
            "config": {},
        }

        self.hs = self.setup_test_homeserver(config=config)
        return self.hs

    def test_third_party_rules(self):
        """Tests that a forbidden event is forbidden from being sent, but an allowed one
        can be sent.
        """
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        room_id = self.helper.create_room_as(user_id, tok=tok)

        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.allowed/1" % room_id,
            {},
            access_token=tok,
        )
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.forbidden/1" % room_id,
            {},
            access_token=tok,
        )
        self.render(request)
        self.assertEquals(channel.result["code"], b"403", channel.result)
