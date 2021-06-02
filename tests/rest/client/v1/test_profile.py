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
from synapse.rest import admin
from synapse.rest.client.v1 import login, profile, room

from tests import unittest


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
        self.other = self.register_user("other", "pass", displayname="Bob")

    def test_get_displayname(self):
        res = self._get_displayname()
        self.assertEqual(res, "owner")

    def test_set_displayname(self):
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content={"displayname": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        res = self._get_displayname()
        self.assertEqual(res, "test")

    def test_set_displayname_noauth(self):
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content={"displayname": "test"},
        )
        self.assertEqual(channel.code, 401, channel.result)

    def test_set_displayname_too_long(self):
        """Attempts to set a stupid displayname should get a 400"""
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.owner,),
            content={"displayname": "test" * 100},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

        res = self._get_displayname()
        self.assertEqual(res, "owner")

    def test_get_displayname_other(self):
        res = self._get_displayname(self.other)
        self.assertEquals(res, "Bob")

    def test_set_displayname_other(self):
        channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (self.other,),
            content={"displayname": "test"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

    def test_get_avatar_url(self):
        res = self._get_avatar_url()
        self.assertIsNone(res)

    def test_set_avatar_url(self):
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.owner,),
            content={"avatar_url": "http://my.server/pic.gif"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        res = self._get_avatar_url()
        self.assertEqual(res, "http://my.server/pic.gif")

    def test_set_avatar_url_noauth(self):
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.owner,),
            content={"avatar_url": "http://my.server/pic.gif"},
        )
        self.assertEqual(channel.code, 401, channel.result)

    def test_set_avatar_url_too_long(self):
        """Attempts to set a stupid avatar_url should get a 400"""
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.owner,),
            content={"avatar_url": "http://my.server/pic.gif" * 100},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

        res = self._get_avatar_url()
        self.assertIsNone(res)

    def test_get_avatar_url_other(self):
        res = self._get_avatar_url(self.other)
        self.assertIsNone(res)

    def test_set_avatar_url_other(self):
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.other,),
            content={"avatar_url": "http://my.server/pic.gif"},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

    def _get_displayname(self, name=None):
        channel = self.make_request(
            "GET", "/profile/%s/displayname" % (name or self.owner,)
        )
        self.assertEqual(channel.code, 200, channel.result)
        return channel.json_body["displayname"]

    def _get_avatar_url(self, name=None):
        channel = self.make_request(
            "GET", "/profile/%s/avatar_url" % (name or self.owner,)
        )
        self.assertEqual(channel.code, 200, channel.result)
        return channel.json_body.get("avatar_url")


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
