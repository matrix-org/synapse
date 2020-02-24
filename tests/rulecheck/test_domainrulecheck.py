# -*- coding: utf-8 -*-
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


import json

import synapse.rest.admin
from synapse.config._base import ConfigError
from synapse.rest.client.v1 import login, room
from synapse.rulecheck.domain_rule_checker import DomainRuleChecker

from tests import unittest
from tests.server import make_request, render


class DomainRuleCheckerTestCase(unittest.TestCase):
    def test_allowed(self):
        config = {
            "default": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
            "domains_prevented_from_being_invited_to_published_rooms": ["target_two"],
        }
        check = DomainRuleChecker(config)
        self.assertTrue(
            check.user_may_invite(
                "test:source_one", "test:target_one", None, "room", False
            )
        )
        self.assertTrue(
            check.user_may_invite(
                "test:source_one", "test:target_two", None, "room", False
            )
        )
        self.assertTrue(
            check.user_may_invite(
                "test:source_two", "test:target_two", None, "room", False
            )
        )

        # User can invite internal user to a published room
        self.assertTrue(
            check.user_may_invite(
                "test:source_one", "test1:target_one", None, "room", False, True
            )
        )

        # User can invite external user to a non-published room
        self.assertTrue(
            check.user_may_invite(
                "test:source_one", "test:target_two", None, "room", False, False
            )
        )

    def test_disallowed(self):
        config = {
            "default": True,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
                "source_four": [],
            },
        }
        check = DomainRuleChecker(config)
        self.assertFalse(
            check.user_may_invite(
                "test:source_one", "test:target_three", None, "room", False
            )
        )
        self.assertFalse(
            check.user_may_invite(
                "test:source_two", "test:target_three", None, "room", False
            )
        )
        self.assertFalse(
            check.user_may_invite(
                "test:source_two", "test:target_one", None, "room", False
            )
        )
        self.assertFalse(
            check.user_may_invite(
                "test:source_four", "test:target_one", None, "room", False
            )
        )

        # User cannot invite external user to a published room
        self.assertTrue(
            check.user_may_invite(
                "test:source_one", "test:target_two", None, "room", False, True
            )
        )

    def test_default_allow(self):
        config = {
            "default": True,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        check = DomainRuleChecker(config)
        self.assertTrue(
            check.user_may_invite(
                "test:source_three", "test:target_one", None, "room", False
            )
        )

    def test_default_deny(self):
        config = {
            "default": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        check = DomainRuleChecker(config)
        self.assertFalse(
            check.user_may_invite(
                "test:source_three", "test:target_one", None, "room", False
            )
        )

    def test_config_parse(self):
        config = {
            "default": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        self.assertEquals(config, DomainRuleChecker.parse_config(config))

    def test_config_parse_failure(self):
        config = {
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            }
        }
        self.assertRaises(ConfigError, DomainRuleChecker.parse_config, config)


class DomainRuleCheckerRoomTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    hijack_auth = False

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["trusted_third_party_id_servers"] = ["localhost"]

        config["spam_checker"] = {
            "module": "synapse.rulecheck.domain_rule_checker.DomainRuleChecker",
            "config": {
                "default": True,
                "domain_mapping": {},
                "can_only_join_rooms_with_invite": True,
                "can_only_create_one_to_one_rooms": True,
                "can_only_invite_during_room_creation": True,
                "can_invite_by_third_party_id": False,
            },
        }

        hs = self.setup_test_homeserver(config=config)
        return hs

    def prepare(self, reactor, clock, hs):
        self.admin_user_id = self.register_user("admin_user", "pass", admin=True)
        self.admin_access_token = self.login("admin_user", "pass")

        self.normal_user_id = self.register_user("normal_user", "pass", admin=False)
        self.normal_access_token = self.login("normal_user", "pass")

        self.other_user_id = self.register_user("other_user", "pass", admin=False)

    def test_admin_can_create_room(self):
        channel = self._create_room(self.admin_access_token)
        assert channel.result["code"] == b"200", channel.result

    def test_normal_user_cannot_create_empty_room(self):
        channel = self._create_room(self.normal_access_token)
        assert channel.result["code"] == b"403", channel.result

    def test_normal_user_cannot_create_room_with_multiple_invites(self):
        channel = self._create_room(
            self.normal_access_token,
            content={"invite": [self.other_user_id, self.admin_user_id]},
        )
        assert channel.result["code"] == b"403", channel.result

        # Test that it correctly counts both normal and third party invites
        channel = self._create_room(
            self.normal_access_token,
            content={
                "invite": [self.other_user_id],
                "invite_3pid": [{"medium": "email", "address": "foo@example.com"}],
            },
        )
        assert channel.result["code"] == b"403", channel.result

        # Test that it correctly rejects third party invites
        channel = self._create_room(
            self.normal_access_token,
            content={
                "invite": [],
                "invite_3pid": [{"medium": "email", "address": "foo@example.com"}],
            },
        )
        assert channel.result["code"] == b"403", channel.result

    def test_normal_user_can_room_with_single_invites(self):
        channel = self._create_room(
            self.normal_access_token, content={"invite": [self.other_user_id]}
        )
        assert channel.result["code"] == b"200", channel.result

    def test_cannot_join_public_room(self):
        channel = self._create_room(self.admin_access_token)
        assert channel.result["code"] == b"200", channel.result

        room_id = channel.json_body["room_id"]

        self.helper.join(
            room_id, self.normal_user_id, tok=self.normal_access_token, expect_code=403
        )

    def test_can_join_invited_room(self):
        channel = self._create_room(self.admin_access_token)
        assert channel.result["code"] == b"200", channel.result

        room_id = channel.json_body["room_id"]

        self.helper.invite(
            room_id,
            src=self.admin_user_id,
            targ=self.normal_user_id,
            tok=self.admin_access_token,
        )

        self.helper.join(
            room_id, self.normal_user_id, tok=self.normal_access_token, expect_code=200
        )

    def test_cannot_invite(self):
        channel = self._create_room(self.admin_access_token)
        assert channel.result["code"] == b"200", channel.result

        room_id = channel.json_body["room_id"]

        self.helper.invite(
            room_id,
            src=self.admin_user_id,
            targ=self.normal_user_id,
            tok=self.admin_access_token,
        )

        self.helper.join(
            room_id, self.normal_user_id, tok=self.normal_access_token, expect_code=200
        )

        self.helper.invite(
            room_id,
            src=self.normal_user_id,
            targ=self.other_user_id,
            tok=self.normal_access_token,
            expect_code=403,
        )

    def test_cannot_3pid_invite(self):
        """Test that unbound 3pid invites get rejected.
        """
        channel = self._create_room(self.admin_access_token)
        assert channel.result["code"] == b"200", channel.result

        room_id = channel.json_body["room_id"]

        self.helper.invite(
            room_id,
            src=self.admin_user_id,
            targ=self.normal_user_id,
            tok=self.admin_access_token,
        )

        self.helper.join(
            room_id, self.normal_user_id, tok=self.normal_access_token, expect_code=200
        )

        self.helper.invite(
            room_id,
            src=self.normal_user_id,
            targ=self.other_user_id,
            tok=self.normal_access_token,
            expect_code=403,
        )

        request, channel = self.make_request(
            "POST",
            "rooms/%s/invite" % (room_id),
            {"address": "foo@bar.com", "medium": "email", "id_server": "localhost"},
            access_token=self.normal_access_token,
        )
        self.render(request)
        self.assertEqual(channel.code, 403, channel.result["body"])

    def _create_room(self, token, content={}):
        path = "/_matrix/client/r0/createRoom?access_token=%s" % (token,)

        request, channel = make_request(
            self.hs.get_reactor(),
            "POST",
            path,
            content=json.dumps(content).encode("utf8"),
        )
        render(request, self.resource, self.hs.get_reactor())

        return channel
