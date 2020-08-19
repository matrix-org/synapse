# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import synapse
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login, push_rule, room

from tests.unittest import HomeserverTestCase


class PushRuleAttributesTestCase(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        push_rule.register_servlets,
    ]
    hijack_auth = False

    def test_enabled_on_creation(self):
        """
        Tests the GET and PUT of push rules' `enabled` endpoints.
        Tests that a rule is enabled upon creation, even though a rule with that
            ruleId existed previously and was disabled.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        body = {
            "conditions": [
                {"kind": "event_match", "key": "sender", "pattern": "@user2:hs"}
            ],
            "actions": ["notify", {"set_tweak": "highlight"}],
        }

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # GET enabled for that new rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["enabled"], True)

    def test_enabled_on_recreation(self):
        """
        Tests the GET and PUT of push rules' `enabled` endpoints.
        Tests that a rule is enabled upon creation, even if a rule with that
            ruleId existed previously and was disabled.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        body = {
            "conditions": [
                {"kind": "event_match", "key": "sender", "pattern": "@user2:hs"}
            ],
            "actions": ["notify", {"set_tweak": "highlight"}],
        }

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # disable the rule
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/best.friend/enabled",
            {"enabled": False},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # check rule disabled
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["enabled"], False)

        # DELETE the rule
        request, channel = self.make_request(
            "DELETE", "/pushrules/global/override/best.friend", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # GET enabled for that new rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["enabled"], True)

    def test_enabled_disable(self):
        """
        Tests the GET and PUT of push rules' `enabled` endpoints.
        Tests that a rule is disabled and enabled when we ask for it.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        body = {
            "conditions": [
                {"kind": "event_match", "key": "sender", "pattern": "@user2:hs"}
            ],
            "actions": ["notify", {"set_tweak": "highlight"}],
        }

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # disable the rule
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/best.friend/enabled",
            {"enabled": False},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # check rule disabled
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["enabled"], False)

        # re-enable the rule
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/best.friend/enabled",
            {"enabled": True},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # check rule enabled
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["enabled"], True)

    def test_enabled_404_when_get_non_existent(self):
        """
        Tests that `enabled` gives 404 when the rule doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        body = {
            "conditions": [
                {"kind": "event_match", "key": "sender", "pattern": "@user2:hs"}
            ],
            "actions": ["notify", {"set_tweak": "highlight"}],
        }

        # check 404 for never-heard-of rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # GET enabled for that new rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # DELETE the rule
        request, channel = self.make_request(
            "DELETE", "/pushrules/global/override/best.friend", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # check 404 for deleted rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_enabled_404_when_get_non_existent_server_rule(self):
        """
        Tests that `enabled` gives 404 when the server-default rule doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        # check 404 for never-heard-of rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/.m.muahahaha/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_enabled_404_when_put_non_existent_rule(self):
        """
        Tests that `enabled` gives 404 when we put to a rule that doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        # enable & check 404 for never-heard-of rule
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/best.friend/enabled",
            {"enabled": True},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_enabled_404_when_put_non_existent_server_rule(self):
        """
        Tests that `enabled` gives 404 when we put to a server-default rule that doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        # enable & check 404 for never-heard-of rule
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/.m.muahahah/enabled",
            {"enabled": True},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_actions_get(self):
        """
        Tests that `actions` gives you what you expect on a fresh rule.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        body = {
            "conditions": [
                {"kind": "event_match", "key": "sender", "pattern": "@user2:hs"}
            ],
            "actions": ["notify", {"set_tweak": "highlight"}],
        }

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # GET actions for that new rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/actions", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body["actions"], ["notify", {"set_tweak": "highlight"}]
        )

    def test_actions_put(self):
        """
        Tests that PUT on actions updates the value you'd get from GET.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        body = {
            "conditions": [
                {"kind": "event_match", "key": "sender", "pattern": "@user2:hs"}
            ],
            "actions": ["notify", {"set_tweak": "highlight"}],
        }

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # change the rule actions
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/best.friend/actions",
            {"actions": ["dont_notify"]},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # GET actions for that new rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/actions", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["actions"], ["dont_notify"])

    def test_actions_404_when_get_non_existent(self):
        """
        Tests that `actions` gives 404 when the rule doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        body = {
            "conditions": [
                {"kind": "event_match", "key": "sender", "pattern": "@user2:hs"}
            ],
            "actions": ["notify", {"set_tweak": "highlight"}],
        }

        # check 404 for never-heard-of rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

        # PUT a new rule
        request, channel = self.make_request(
            "PUT", "/pushrules/global/override/best.friend", body, access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # DELETE the rule
        request, channel = self.make_request(
            "DELETE", "/pushrules/global/override/best.friend", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        # check 404 for deleted rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/best.friend/enabled", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_actions_404_when_get_non_existent_server_rule(self):
        """
        Tests that `actions` gives 404 when the server-default rule doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        # check 404 for never-heard-of rule
        request, channel = self.make_request(
            "GET", "/pushrules/global/override/.m.muahahaha/actions", access_token=token
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_actions_404_when_put_non_existent_rule(self):
        """
        Tests that `actions` gives 404 when putting to a rule that doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        # enable & check 404 for never-heard-of rule
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/best.friend/actions",
            {"actions": ["dont_notify"]},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    def test_actions_404_when_put_non_existent_server_rule(self):
        """
        Tests that `actions` gives 404 when putting to a server-default rule that doesn't exist.
        """
        self.register_user("user", "pass")
        token = self.login("user", "pass")

        # enable & check 404 for never-heard-of rule
        request, channel = self.make_request(
            "PUT",
            "/pushrules/global/override/.m.muahahah/actions",
            {"actions": ["dont_notify"]},
            access_token=token,
        )
        self.render(request)
        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)
