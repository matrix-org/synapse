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


import json

import synapse.rest.admin
from synapse.config._base import ConfigError
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.rulecheck.domain_rule_checker import DomainRuleChecker
from synapse.third_party_rules.access_rules import (
    ACCESS_RULE_DIRECT,
    ACCESS_RULE_RESTRICTED,
    ACCESS_RULE_UNRESTRICTED,
    ACCESS_RULES_TYPE,
)

from tests import unittest


class RoomAccessEventTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()

        config["third_party_event_rules"] = {
            "module": "synapse.third_party_rules.access_rules.RoomAccessRules",
            "config": {
                "domains_forbidden_when_restricted": [
                    "forbidden_domain"
                ],
                "id_server": "testis",
            }
        }

        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor, clock, homeserver):
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        self.restricted_room = self.create_room()
        self.unrestricted_room = self.create_room(rule=ACCESS_RULE_UNRESTRICTED)
        self.direct_room = self.create_room(direct=True)

    def test_create_room_no_rule(self):
        """Tests that creating a room with no rule will set the default value."""
        room_id = self.create_room()
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, ACCESS_RULE_RESTRICTED)

    def test_create_room_direct_no_rule(self):
        """Tests that creating a direct room with no rule will set the default value."""
        room_id = self.create_room(direct=True)
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, ACCESS_RULE_DIRECT)

    def test_create_room_valid_rule(self):
        """Tests that creating a room with a valid rule will set the right value."""
        room_id = self.create_room(rule=ACCESS_RULE_UNRESTRICTED)
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, ACCESS_RULE_UNRESTRICTED)

    def test_create_room_invalid_rule(self):
        """Tests that creating a room with an invalid rule will set the default value."""
        self.create_room(rule=ACCESS_RULE_DIRECT, expected_code=400)

    def test_create_room_direct_invalid_rule(self):
        """Tests that creating a direct room with an invalid rule will set the default
        value.
        """
        self.create_room(direct=True, rule=ACCESS_RULE_RESTRICTED, expected_code=400)

    # def test_limited

    def create_room(self, direct=False, rule=None, expected_code=200):
        content = {
            "is_direct": direct,
        }

        if rule:
            content["initial_state"] = [{
                "type": ACCESS_RULES_TYPE,
                "state_key": "",
                "content": {
                    "rule": rule,
                }
            }]

        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/createRoom",
            json.dumps(content),
            access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, expected_code, channel.result)

        if expected_code == 200:
            return channel.json_body["room_id"]

    def current_rule_in_room(self, room_id):
        request, channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/state/%s" % (room_id, ACCESS_RULES_TYPE),
            access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, 200, channel.result)
        return channel.json_body["rule"]
