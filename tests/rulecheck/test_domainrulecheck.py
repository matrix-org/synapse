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
from typing import Optional

import attr

import synapse.rest.admin
from synapse.api.constants import EventTypes
from synapse.config._base import ConfigError
from synapse.rest.client import login, room
from synapse.rulecheck.domain_rule_checker import DomainRuleChecker

from tests import unittest


@attr.s(auto_attribs=True)
class MockEvent:
    """Mock of an event, only implementing the fields the DomainRuleChecker module will
    use.
    """
    sender: str
    membership: Optional[str] = None


@attr.s(auto_attribs=True)
class MockPublicRoomListManager:
    """Mock of a synapse.module_api.PublicRoomListManager, only implementing the method
    the DomainRuleChecker module will use.
    """
    _published: bool

    async def room_is_in_public_room_list(self, room_id: str) -> bool:
        return self._published


@attr.s(auto_attribs=True)
class MockModuleApi:
    """Mock of a synapse.module_api.ModuleApi, only implementing the methods the
    DomainRuleChecker module will use.
    """
    _new_room: bool
    _published: bool

    def register_spam_checker_callbacks(self, *args, **kwargs):
        """Don't fail when the module tries to register its callbacks."""
        pass

    @property
    def public_room_list_manager(self):
        """Returns a mock public room list manager. We could in theory return a Mock with
        a return value of make_awaitable(self._published), but local testing seems to show
        this doesn't work on all versions of Python.
        """
        return MockPublicRoomListManager(self._published)

    async def get_room_state(self, *args, **kwargs):
        """Mocks the ModuleApi's get_room_state method, by returning mock events. The
        number of events depends on whether we're testing for a new room or not (if the
        room is not new it will have an extra user joined to it).
        """
        state = {
            (EventTypes.Create, ""): MockEvent("room_creator"),
            (EventTypes.Member, "room_creator"): MockEvent("room_creator", "join"),
            (EventTypes.Member, "invitee"): MockEvent("room_creator", "invite"),
        }

        if not self._new_room:
            state[(EventTypes.Member, "joinee")] = MockEvent("joinee", "join")

        return state


# We use a HomeserverTestCase despite not using the homeserver itself because we need a
# reactor to run asynchronous code.
class DomainRuleCheckerTestCase(unittest.HomeserverTestCase):
    def _test_user_may_invite(
        self, config, inviter, invitee, new_room, published,
    ) -> bool:
        check = DomainRuleChecker(config, MockModuleApi(new_room, published))
        return self.get_success(check.user_may_invite(inviter, invitee, "room"))

    def test_allowed(self):
        config = {
            "default": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
            "domains_prevented_from_being_invited_to_published_rooms": ["target_two"],
        }

        self.assertTrue(
            self._test_user_may_invite(
                config, "test:source_one", "test:target_one", False, False,
            ),
        )

        self.assertTrue(
            self._test_user_may_invite(
                config, "test:source_one", "test:target_two", False, False,
            ),
        )

        self.assertTrue(
            self._test_user_may_invite(
                config, "test:source_two", "test:target_two", False, False,
            ),
        )

        # User can invite internal user to a published room
        self.assertTrue(
            self._test_user_may_invite(
                config, "test:source_one", "test1:target_one", False, True,
            ),
        )

        # User can invite external user to a non-published room
        self.assertTrue(
            self._test_user_may_invite(
                config, "test:source_one", "test:target_two", False, False,
            ),
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

        self.assertFalse(
            self._test_user_may_invite(
                config, "test:source_one", "test:target_three", False, False,
            )
        )
        self.assertFalse(
            self._test_user_may_invite(
                config, "test:source_two", "test:target_three", False, False,
            )
        )
        self.assertFalse(
            self._test_user_may_invite(
                config, "test:source_two", "test:target_one", False, False
            )
        )
        self.assertFalse(
            self._test_user_may_invite(
                config, "test:source_four", "test:target_one", False, False
            )
        )

        # User cannot invite external user to a published room
        self.assertTrue(
            self._test_user_may_invite(
                config, "test:source_one", "test:target_two", False, True
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

        self.assertTrue(
            self._test_user_may_invite(
                config, "test:source_three", "test:target_one", False, False,
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

        self.assertFalse(
            self._test_user_may_invite(
                config, "test:source_three", "test:target_one", False, False,
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

        config["modules"] = [
            {
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
        ]

        hs = self.setup_test_homeserver(config=config)

        module_api = hs.get_module_api()
        for module, config in hs.config.modules.loaded_modules:
            module(config=config, api=module_api)

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
        """Test that unbound 3pid invites get rejected."""
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

        channel = self.make_request(
            "POST",
            "rooms/%s/invite" % (room_id),
            {"address": "foo@bar.com", "medium": "email", "id_server": "localhost"},
            access_token=self.normal_access_token,
        )
        self.assertEqual(channel.code, 403, channel.result["body"])

    def _create_room(self, token, content=None):
        path = "/_matrix/client/r0/createRoom?access_token=%s" % (token,)

        channel = self.make_request(
            "POST",
            path,
            content=json.dumps(content or {}).encode("utf8"),
        )

        return channel
