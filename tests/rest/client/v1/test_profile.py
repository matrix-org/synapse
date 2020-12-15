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
import json

from mock import Mock

from twisted.internet import defer

import synapse.types
from synapse.api.errors import AuthError, SynapseError
from synapse.rest import admin
from synapse.rest.client.v1 import login, profile, room

from tests import unittest

from ....utils import MockHttpResource, setup_test_homeserver

myid = "@1234ABCD:test"
PATH_PREFIX = "/_matrix/client/r0"


class MockHandlerProfileTestCase(unittest.TestCase):
    """ Tests rest layer of profile management.

    Todo: move these into ProfileTestCase
    """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.mock_handler = Mock(
            spec=[
                "get_displayname",
                "set_displayname",
                "get_avatar_url",
                "set_avatar_url",
                "check_profile_query_allowed",
            ]
        )

        self.mock_handler.get_displayname.return_value = defer.succeed(Mock())
        self.mock_handler.set_displayname.return_value = defer.succeed(Mock())
        self.mock_handler.get_avatar_url.return_value = defer.succeed(Mock())
        self.mock_handler.set_avatar_url.return_value = defer.succeed(Mock())
        self.mock_handler.check_profile_query_allowed.return_value = defer.succeed(
            Mock()
        )

        hs = yield setup_test_homeserver(
            self.addCleanup,
            "test",
            federation_http_client=None,
            resource_for_client=self.mock_resource,
            federation=Mock(),
            federation_client=Mock(),
            profile_handler=self.mock_handler,
        )

        async def _get_user_by_req(request=None, allow_guest=False):
            return synapse.types.create_requester(myid)

        hs.get_auth().get_user_by_req = _get_user_by_req

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
            "PUT", "/profile/%s/displayname" % (myid), b'{"displayname": "Frank Jr."}'
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
            "PUT",
            "/profile/%s/displayname" % ("@4567:test"),
            b'{"displayname": "Frank Jr."}',
        )

        self.assertTrue(400 <= code < 499, msg="code %d is in the 4xx range" % (code))

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
            "PUT",
            "/profile/%s/displayname" % ("@opaque:elsewhere"),
            b'{"displayname":"bob"}',
        )

        self.assertTrue(400 <= code <= 499, msg="code %d is in the 4xx range" % (code))

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
            b'{"avatar_url": "http://my.server/pic.gif"}',
        )

        self.assertEquals(200, code)
        self.assertEquals(mocked_set.call_args[0][0].localpart, "1234ABCD")
        self.assertEquals(mocked_set.call_args[0][1].user.localpart, "1234ABCD")
        self.assertEquals(mocked_set.call_args[0][2], "http://my.server/pic.gif")


class ProfileTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        profile.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        return self.hs

    def prepare(self, reactor, clock, hs):
        self.owner = self.register_user("owner", "pass")
        self.owner_tok = self.login("owner", "pass")

    def test_set_displayname(self):
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content=json.dumps({"displayname": "test"}),
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        res = self.get_displayname()
        self.assertEqual(res, "test")

    def test_set_displayname_too_long(self):
        """Attempts to set a stupid displayname should get a 400"""
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content=json.dumps({"displayname": "test" * 100}),
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

        res = self.get_displayname()
        self.assertEqual(res, "owner")

    def get_displayname(self):
        channel = self.make_request("GET", "/profile/%s/displayname" % (self.owner,))
        self.assertEqual(channel.code, 200, channel.result)
        return channel.json_body["displayname"]


class ProfilesRestrictedTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        profile.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        config = self.default_config()
        config["require_auth_for_profile_requests"] = True
        config["limit_profile_requests_to_users_who_share_rooms"] = True
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor, clock, hs):
        # User owning the requested profile.
        self.owner = self.register_user("owner", "pass")
        self.owner_tok = self.login("owner", "pass")
        self.profile_url = "/profile/%s" % (self.owner)

        # User requesting the profile.
        self.requester = self.register_user("requester", "pass")
        self.requester_tok = self.login("requester", "pass")

        self.room_id = self.helper.create_room_as(self.owner, tok=self.owner_tok)

    def test_no_auth(self):
        self.try_fetch_profile(401)

    def test_not_in_shared_room(self):
        self.ensure_requester_left_room()

        self.try_fetch_profile(403, access_token=self.requester_tok)

    def test_in_shared_room(self):
        self.ensure_requester_left_room()

        self.helper.join(room=self.room_id, user=self.requester, tok=self.requester_tok)

        self.try_fetch_profile(200, self.requester_tok)

    def try_fetch_profile(self, expected_code, access_token=None):
        self.request_profile(expected_code, access_token=access_token)

        self.request_profile(
            expected_code, url_suffix="/displayname", access_token=access_token
        )

        self.request_profile(
            expected_code, url_suffix="/avatar_url", access_token=access_token
        )

    def request_profile(self, expected_code, url_suffix="", access_token=None):
        channel = self.make_request(
            "GET", self.profile_url + url_suffix, access_token=access_token
        )
        self.assertEqual(channel.code, expected_code, channel.result)

    def ensure_requester_left_room(self):
        try:
            self.helper.leave(
                room=self.room_id, user=self.requester, tok=self.requester_tok
            )
        except AssertionError:
            # We don't care whether the leave request didn't return a 200 (e.g.
            # if the user isn't already in the room), because we only want to
            # make sure the user isn't in the room.
            pass


class OwnProfileUnrestrictedTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        profile.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["require_auth_for_profile_requests"] = True
        config["limit_profile_requests_to_users_who_share_rooms"] = True
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor, clock, hs):
        # User requesting the profile.
        self.requester = self.register_user("requester", "pass")
        self.requester_tok = self.login("requester", "pass")

    def test_can_lookup_own_profile(self):
        """Tests that a user can lookup their own profile without having to be in a room
        if 'require_auth_for_profile_requests' is set to true in the server's config.
        """
        channel = self.make_request(
            "GET", "/profile/" + self.requester, access_token=self.requester_tok
        )
        self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            "/profile/" + self.requester + "/displayname",
            access_token=self.requester_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        channel = self.make_request(
            "GET",
            "/profile/" + self.requester + "/avatar_url",
            access_token=self.requester_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)
