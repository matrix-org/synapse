# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

"""Tests REST events for /profile paths."""
from mock import Mock
from twisted.internet import defer

import synapse.types
from synapse.api.errors import SynapseError, AuthError
from synapse.rest.client.v1 import profile
from tests import unittest
from ....utils import MockHttpResource, setup_test_homeserver

myid = "@1234ABCD:test"
PATH_PREFIX = "/_matrix/client/api/v1"


class ProfileTestCase(unittest.TestCase):
    """ Tests profile management. """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.mock_handler = Mock(spec=[
            "get_displayname",
            "set_displayname",
            "get_avatar_url",
            "set_avatar_url",
        ])

        hs = yield setup_test_homeserver(
            "test",
            http_client=None,
            resource_for_client=self.mock_resource,
            federation=Mock(),
            replication_layer=Mock(),
        )

        def _get_user_by_req(request=None, allow_guest=False):
            return synapse.types.create_requester(myid)

        hs.get_v1auth().get_user_by_req = _get_user_by_req

        hs.get_handlers().profile_handler = self.mock_handler

        profile.register_servlets(hs, self.mock_resource)

    @defer.inlineCallbacks
    def test_get_my_name(self):
        mocked_get = self.mock_handler.get_displayname
        mocked_get.return_value = defer.succeed("Frank")

        (code, response) = yield self.mock_resource.trigger(
            "GET", "/profile/%s/displayname" % (myid), None
        )

        self.assertEquals(200, code)
        self.assertEquals({"displayname": "Frank"}, response)
        self.assertEquals(mocked_get.call_args[0][0].localpart, "1234ABCD")

    @defer.inlineCallbacks
    def test_set_my_name(self):
        mocked_set = self.mock_handler.set_displayname
        mocked_set.return_value = defer.succeed(())

        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            "/profile/%s/displayname" % (myid),
            '{"displayname": "Frank Jr."}'
        )

        self.assertEquals(200, code)
        self.assertEquals(mocked_set.call_args[0][0].localpart, "1234ABCD")
        self.assertEquals(mocked_set.call_args[0][1].user.localpart, "1234ABCD")
        self.assertEquals(mocked_set.call_args[0][2], "Frank Jr.")

    @defer.inlineCallbacks
    def test_set_my_name_noauth(self):
        mocked_set = self.mock_handler.set_displayname
        mocked_set.side_effect = AuthError(400, "message")

        (code, response) = yield self.mock_resource.trigger(
            "PUT", "/profile/%s/displayname" % ("@4567:test"),
            '{"displayname": "Frank Jr."}'
        )

        self.assertTrue(
            400 <= code < 499,
            msg="code %d is in the 4xx range" % (code)
        )

    @defer.inlineCallbacks
    def test_get_other_name(self):
        mocked_get = self.mock_handler.get_displayname
        mocked_get.return_value = defer.succeed("Bob")

        (code, response) = yield self.mock_resource.trigger(
            "GET", "/profile/%s/displayname" % ("@opaque:elsewhere"), None
        )

        self.assertEquals(200, code)
        self.assertEquals({"displayname": "Bob"}, response)

    @defer.inlineCallbacks
    def test_set_other_name(self):
        mocked_set = self.mock_handler.set_displayname
        mocked_set.side_effect = SynapseError(400, "message")

        (code, response) = yield self.mock_resource.trigger(
            "PUT", "/profile/%s/displayname" % ("@opaque:elsewhere"),
            '{"displayname":"bob"}'
        )

        self.assertTrue(
            400 <= code <= 499,
            msg="code %d is in the 4xx range" % (code)
        )

    @defer.inlineCallbacks
    def test_get_my_avatar(self):
        mocked_get = self.mock_handler.get_avatar_url
        mocked_get.return_value = defer.succeed("http://my.server/me.png")

        (code, response) = yield self.mock_resource.trigger(
            "GET", "/profile/%s/avatar_url" % (myid), None
        )

        self.assertEquals(200, code)
        self.assertEquals({"avatar_url": "http://my.server/me.png"}, response)
        self.assertEquals(mocked_get.call_args[0][0].localpart, "1234ABCD")

    @defer.inlineCallbacks
    def test_set_my_avatar(self):
        mocked_set = self.mock_handler.set_avatar_url
        mocked_set.return_value = defer.succeed(())

        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            "/profile/%s/avatar_url" % (myid),
            '{"avatar_url": "http://my.server/pic.gif"}'
        )

        self.assertEquals(200, code)
        self.assertEquals(mocked_set.call_args[0][0].localpart, "1234ABCD")
        self.assertEquals(mocked_set.call_args[0][1].user.localpart, "1234ABCD")
        self.assertEquals(mocked_set.call_args[0][2], "http://my.server/pic.gif")
