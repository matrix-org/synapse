# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

"""Tests REST events for /rooms paths."""

import json
from urllib import parse as urlparse

from mock import Mock

import synapse.rest.admin
from synapse.api.constants import EventContentFields, EventTypes, Membership
from synapse.handlers.pagination import PurgeStatus
from synapse.rest.client.v1 import directory, login, profile, room
from synapse.rest.client.v2_alpha import account
from synapse.types import JsonDict, RoomAlias, UserID
from synapse.util.stringutils import random_string

from tests import unittest

PATH_PREFIX = b"/_matrix/client/api/v1"


class RoomBase(unittest.HomeserverTestCase):
    rmcreator_id = None

    servlets = [room.register_servlets, room.register_deprecated_servlets]

    def make_homeserver(self, reactor, clock):

        self.hs = self.setup_test_homeserver(
            "red", http_client=None, federation_client=Mock(),
        )

        self.hs.get_federation_handler = Mock(return_value=Mock())

        async def _insert_client_ip(*args, **kwargs):
            return None

        self.hs.get_datastore().insert_client_ip = _insert_client_ip

        return self.hs


class RoomPermissionsTestCase(RoomBase):
    """ Tests room permissions. """

    user_id = "@sid1:red"
    rmcreator_id = "@notme:red"

    def prepare(self, reactor, clock, hs):

        self.helper.auth_user_id = self.rmcreator_id
        # create some rooms under the name rmcreator_id
        self.uncreated_rmid = "!aa:test"
        self.created_rmid = self.helper.create_room_as(
            self.rmcreator_id, is_public=False
        )
        self.created_public_rmid = self.helper.create_room_as(
            self.rmcreator_id, is_public=True
        )

        # send a message in one of the rooms
        self.created_rmid_msg_path = (
            "rooms/%s/send/m.room.message/a1" % (self.created_rmid)
        ).encode("ascii")
        request, channel = self.make_request(
            "PUT", self.created_rmid_msg_path, b'{"msgtype":"m.text","body":"test msg"}'
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

        # set topic for public room
        request, channel = self.make_request(
            "PUT",
            ("rooms/%s/state/m.room.topic" % self.created_public_rmid).encode("ascii"),
            b'{"topic":"Public Room Topic"}',
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

        # auth as user_id now
        self.helper.auth_user_id = self.user_id

    def test_can_do_action(self):
        msg_content = b'{"msgtype":"m.text","body":"hello"}'

        seq = iter(range(100))

        def send_msg_path():
            return "/rooms/%s/send/m.room.message/mid%s" % (
                self.created_rmid,
                str(next(seq)),
            )

        # send message in uncreated room, expect 403
        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/send/m.room.message/mid2" % (self.uncreated_rmid,),
            msg_content,
        )
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # send message in created room not joined (no state), expect 403
        request, channel = self.make_request("PUT", send_msg_path(), msg_content)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # send message in created room and invited, expect 403
        self.helper.invite(
            room=self.created_rmid, src=self.rmcreator_id, targ=self.user_id
        )
        request, channel = self.make_request("PUT", send_msg_path(), msg_content)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # send message in created room and joined, expect 200
        self.helper.join(room=self.created_rmid, user=self.user_id)
        request, channel = self.make_request("PUT", send_msg_path(), msg_content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        # send message in created room and left, expect 403
        self.helper.leave(room=self.created_rmid, user=self.user_id)
        request, channel = self.make_request("PUT", send_msg_path(), msg_content)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

    def test_topic_perms(self):
        topic_content = b'{"topic":"My Topic Name"}'
        topic_path = "/rooms/%s/state/m.room.topic" % self.created_rmid

        # set/get topic in uncreated room, expect 403
        request, channel = self.make_request(
            "PUT", "/rooms/%s/state/m.room.topic" % self.uncreated_rmid, topic_content
        )
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])
        request, channel = self.make_request(
            "GET", "/rooms/%s/state/m.room.topic" % self.uncreated_rmid
        )
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # set/get topic in created PRIVATE room not joined, expect 403
        request, channel = self.make_request("PUT", topic_path, topic_content)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])
        request, channel = self.make_request("GET", topic_path)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # set topic in created PRIVATE room and invited, expect 403
        self.helper.invite(
            room=self.created_rmid, src=self.rmcreator_id, targ=self.user_id
        )
        request, channel = self.make_request("PUT", topic_path, topic_content)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # get topic in created PRIVATE room and invited, expect 403
        request, channel = self.make_request("GET", topic_path)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # set/get topic in created PRIVATE room and joined, expect 200
        self.helper.join(room=self.created_rmid, user=self.user_id)

        # Only room ops can set topic by default
        self.helper.auth_user_id = self.rmcreator_id
        request, channel = self.make_request("PUT", topic_path, topic_content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])
        self.helper.auth_user_id = self.user_id

        request, channel = self.make_request("GET", topic_path)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])
        self.assert_dict(json.loads(topic_content.decode("utf8")), channel.json_body)

        # set/get topic in created PRIVATE room and left, expect 403
        self.helper.leave(room=self.created_rmid, user=self.user_id)
        request, channel = self.make_request("PUT", topic_path, topic_content)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])
        request, channel = self.make_request("GET", topic_path)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        # get topic in PUBLIC room, not joined, expect 403
        request, channel = self.make_request(
            "GET", "/rooms/%s/state/m.room.topic" % self.created_public_rmid
        )
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        # set topic in PUBLIC room, not joined, expect 403
        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/state/m.room.topic" % self.created_public_rmid,
            topic_content,
        )
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

    def _test_get_membership(self, room=None, members=[], expect_code=None):
        for member in members:
            path = "/rooms/%s/state/m.room.member/%s" % (room, member)
            request, channel = self.make_request("GET", path)
            self.render(request)
            self.assertEquals(expect_code, channel.code)

    def test_membership_basic_room_perms(self):
        # === room does not exist ===
        room = self.uncreated_rmid
        # get membership of self, get membership of other, uncreated room
        # expect all 403s
        self._test_get_membership(
            members=[self.user_id, self.rmcreator_id], room=room, expect_code=403
        )

        # trying to invite people to this room should 403
        self.helper.invite(
            room=room, src=self.user_id, targ=self.rmcreator_id, expect_code=403
        )

        # set [invite/join/left] of self, set [invite/join/left] of other,
        # expect all 404s because room doesn't exist on any server
        for usr in [self.user_id, self.rmcreator_id]:
            self.helper.join(room=room, user=usr, expect_code=404)
            self.helper.leave(room=room, user=usr, expect_code=404)

    def test_membership_private_room_perms(self):
        room = self.created_rmid
        # get membership of self, get membership of other, private room + invite
        # expect all 403s
        self.helper.invite(room=room, src=self.rmcreator_id, targ=self.user_id)
        self._test_get_membership(
            members=[self.user_id, self.rmcreator_id], room=room, expect_code=403
        )

        # get membership of self, get membership of other, private room + joined
        # expect all 200s
        self.helper.join(room=room, user=self.user_id)
        self._test_get_membership(
            members=[self.user_id, self.rmcreator_id], room=room, expect_code=200
        )

        # get membership of self, get membership of other, private room + left
        # expect all 200s
        self.helper.leave(room=room, user=self.user_id)
        self._test_get_membership(
            members=[self.user_id, self.rmcreator_id], room=room, expect_code=200
        )

    def test_membership_public_room_perms(self):
        room = self.created_public_rmid
        # get membership of self, get membership of other, public room + invite
        # expect 403
        self.helper.invite(room=room, src=self.rmcreator_id, targ=self.user_id)
        self._test_get_membership(
            members=[self.user_id, self.rmcreator_id], room=room, expect_code=403
        )

        # get membership of self, get membership of other, public room + joined
        # expect all 200s
        self.helper.join(room=room, user=self.user_id)
        self._test_get_membership(
            members=[self.user_id, self.rmcreator_id], room=room, expect_code=200
        )

        # get membership of self, get membership of other, public room + left
        # expect 200.
        self.helper.leave(room=room, user=self.user_id)
        self._test_get_membership(
            members=[self.user_id, self.rmcreator_id], room=room, expect_code=200
        )

    def test_invited_permissions(self):
        room = self.created_rmid
        self.helper.invite(room=room, src=self.rmcreator_id, targ=self.user_id)

        # set [invite/join/left] of other user, expect 403s
        self.helper.invite(
            room=room, src=self.user_id, targ=self.rmcreator_id, expect_code=403
        )
        self.helper.change_membership(
            room=room,
            src=self.user_id,
            targ=self.rmcreator_id,
            membership=Membership.JOIN,
            expect_code=403,
        )
        self.helper.change_membership(
            room=room,
            src=self.user_id,
            targ=self.rmcreator_id,
            membership=Membership.LEAVE,
            expect_code=403,
        )

    def test_joined_permissions(self):
        room = self.created_rmid
        self.helper.invite(room=room, src=self.rmcreator_id, targ=self.user_id)
        self.helper.join(room=room, user=self.user_id)

        # set invited of self, expect 403
        self.helper.invite(
            room=room, src=self.user_id, targ=self.user_id, expect_code=403
        )

        # set joined of self, expect 200 (NOOP)
        self.helper.join(room=room, user=self.user_id)

        other = "@burgundy:red"
        # set invited of other, expect 200
        self.helper.invite(room=room, src=self.user_id, targ=other, expect_code=200)

        # set joined of other, expect 403
        self.helper.change_membership(
            room=room,
            src=self.user_id,
            targ=other,
            membership=Membership.JOIN,
            expect_code=403,
        )

        # set left of other, expect 403
        self.helper.change_membership(
            room=room,
            src=self.user_id,
            targ=other,
            membership=Membership.LEAVE,
            expect_code=403,
        )

        # set left of self, expect 200
        self.helper.leave(room=room, user=self.user_id)

    def test_leave_permissions(self):
        room = self.created_rmid
        self.helper.invite(room=room, src=self.rmcreator_id, targ=self.user_id)
        self.helper.join(room=room, user=self.user_id)
        self.helper.leave(room=room, user=self.user_id)

        # set [invite/join/left] of self, set [invite/join/left] of other,
        # expect all 403s
        for usr in [self.user_id, self.rmcreator_id]:
            self.helper.change_membership(
                room=room,
                src=self.user_id,
                targ=usr,
                membership=Membership.INVITE,
                expect_code=403,
            )

            self.helper.change_membership(
                room=room,
                src=self.user_id,
                targ=usr,
                membership=Membership.JOIN,
                expect_code=403,
            )

        # It is always valid to LEAVE if you've already left (currently.)
        self.helper.change_membership(
            room=room,
            src=self.user_id,
            targ=self.rmcreator_id,
            membership=Membership.LEAVE,
            expect_code=403,
        )


class RoomsMemberListTestCase(RoomBase):
    """ Tests /rooms/$room_id/members/list REST events."""

    user_id = "@sid1:red"

    def test_get_member_list(self):
        room_id = self.helper.create_room_as(self.user_id)
        request, channel = self.make_request("GET", "/rooms/%s/members" % room_id)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

    def test_get_member_list_no_room(self):
        request, channel = self.make_request("GET", "/rooms/roomdoesnotexist/members")
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

    def test_get_member_list_no_permission(self):
        room_id = self.helper.create_room_as("@some_other_guy:red")
        request, channel = self.make_request("GET", "/rooms/%s/members" % room_id)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

    def test_get_member_list_mixed_memberships(self):
        room_creator = "@some_other_guy:red"
        room_id = self.helper.create_room_as(room_creator)
        room_path = "/rooms/%s/members" % room_id
        self.helper.invite(room=room_id, src=room_creator, targ=self.user_id)
        # can't see list if you're just invited.
        request, channel = self.make_request("GET", room_path)
        self.render(request)
        self.assertEquals(403, channel.code, msg=channel.result["body"])

        self.helper.join(room=room_id, user=self.user_id)
        # can see list now joined
        request, channel = self.make_request("GET", room_path)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        self.helper.leave(room=room_id, user=self.user_id)
        # can see old list once left
        request, channel = self.make_request("GET", room_path)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])


class RoomsCreateTestCase(RoomBase):
    """ Tests /rooms and /rooms/$room_id REST events. """

    user_id = "@sid1:red"

    def test_post_room_no_keys(self):
        # POST with no config keys, expect new room id
        request, channel = self.make_request("POST", "/createRoom", "{}")

        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_visibility_key(self):
        # POST with visibility config key, expect new room id
        request, channel = self.make_request(
            "POST", "/createRoom", b'{"visibility":"private"}'
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_custom_key(self):
        # POST with custom config keys, expect new room id
        request, channel = self.make_request(
            "POST", "/createRoom", b'{"custom":"stuff"}'
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_known_and_unknown_keys(self):
        # POST with custom + known config keys, expect new room id
        request, channel = self.make_request(
            "POST", "/createRoom", b'{"visibility":"private","custom":"things"}'
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_invalid_content(self):
        # POST with invalid content / paths, expect 400
        request, channel = self.make_request("POST", "/createRoom", b'{"visibili')
        self.render(request)
        self.assertEquals(400, channel.code)

        request, channel = self.make_request("POST", "/createRoom", b'["hello"]')
        self.render(request)
        self.assertEquals(400, channel.code)

    def test_post_room_invitees_invalid_mxid(self):
        # POST with invalid invitee, see https://github.com/matrix-org/synapse/issues/4088
        # Note the trailing space in the MXID here!
        request, channel = self.make_request(
            "POST", "/createRoom", b'{"invite":["@alice:example.com "]}'
        )
        self.render(request)
        self.assertEquals(400, channel.code)


class RoomTopicTestCase(RoomBase):
    """ Tests /rooms/$room_id/topic REST events. """

    user_id = "@sid1:red"

    def prepare(self, reactor, clock, hs):
        # create the room
        self.room_id = self.helper.create_room_as(self.user_id)
        self.path = "/rooms/%s/state/m.room.topic" % (self.room_id,)

    def test_invalid_puts(self):
        # missing keys or invalid json
        request, channel = self.make_request("PUT", self.path, "{}")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", self.path, '{"_name":"bo"}')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", self.path, '{"nao')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request(
            "PUT", self.path, '[{"_name":"bo"},{"_name":"jill"}]'
        )
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", self.path, "text only")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", self.path, "")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        # valid key, wrong type
        content = '{"topic":["Topic name"]}'
        request, channel = self.make_request("PUT", self.path, content)
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

    def test_rooms_topic(self):
        # nothing should be there
        request, channel = self.make_request("GET", self.path)
        self.render(request)
        self.assertEquals(404, channel.code, msg=channel.result["body"])

        # valid put
        content = '{"topic":"Topic name"}'
        request, channel = self.make_request("PUT", self.path, content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        # valid get
        request, channel = self.make_request("GET", self.path)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])
        self.assert_dict(json.loads(content), channel.json_body)

    def test_rooms_topic_with_extra_keys(self):
        # valid put with extra keys
        content = '{"topic":"Seasons","subtopic":"Summer"}'
        request, channel = self.make_request("PUT", self.path, content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        # valid get
        request, channel = self.make_request("GET", self.path)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])
        self.assert_dict(json.loads(content), channel.json_body)


class RoomMemberStateTestCase(RoomBase):
    """ Tests /rooms/$room_id/members/$user_id/state REST events. """

    user_id = "@sid1:red"

    def prepare(self, reactor, clock, hs):
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_invalid_puts(self):
        path = "/rooms/%s/state/m.room.member/%s" % (self.room_id, self.user_id)
        # missing keys or invalid json
        request, channel = self.make_request("PUT", path, "{}")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, '{"_name":"bo"}')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, '{"nao')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request(
            "PUT", path, b'[{"_name":"bo"},{"_name":"jill"}]'
        )
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, "text only")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, "")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        # valid keys, wrong types
        content = '{"membership":["%s","%s","%s"]}' % (
            Membership.INVITE,
            Membership.JOIN,
            Membership.LEAVE,
        )
        request, channel = self.make_request("PUT", path, content.encode("ascii"))
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

    def test_rooms_members_self(self):
        path = "/rooms/%s/state/m.room.member/%s" % (
            urlparse.quote(self.room_id),
            self.user_id,
        )

        # valid join message (NOOP since we made the room)
        content = '{"membership":"%s"}' % Membership.JOIN
        request, channel = self.make_request("PUT", path, content.encode("ascii"))
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("GET", path, None)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        expected_response = {"membership": Membership.JOIN}
        self.assertEquals(expected_response, channel.json_body)

    def test_rooms_members_other(self):
        self.other_id = "@zzsid1:red"
        path = "/rooms/%s/state/m.room.member/%s" % (
            urlparse.quote(self.room_id),
            self.other_id,
        )

        # valid invite message
        content = '{"membership":"%s"}' % Membership.INVITE
        request, channel = self.make_request("PUT", path, content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("GET", path, None)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])
        self.assertEquals(json.loads(content), channel.json_body)

    def test_rooms_members_other_custom_keys(self):
        self.other_id = "@zzsid1:red"
        path = "/rooms/%s/state/m.room.member/%s" % (
            urlparse.quote(self.room_id),
            self.other_id,
        )

        # valid invite message with custom key
        content = '{"membership":"%s","invite_text":"%s"}' % (
            Membership.INVITE,
            "Join us!",
        )
        request, channel = self.make_request("PUT", path, content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("GET", path, None)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])
        self.assertEquals(json.loads(content), channel.json_body)


class RoomJoinRatelimitTestCase(RoomBase):
    user_id = "@sid1:red"

    servlets = [
        profile.register_servlets,
        room.register_servlets,
    ]

    @unittest.override_config(
        {"rc_joins": {"local": {"per_second": 0.5, "burst_count": 3}}}
    )
    def test_join_local_ratelimit(self):
        """Tests that local joins are actually rate-limited."""
        for i in range(3):
            self.helper.create_room_as(self.user_id)

        self.helper.create_room_as(self.user_id, expect_code=429)

    @unittest.override_config(
        {"rc_joins": {"local": {"per_second": 0.5, "burst_count": 3}}}
    )
    def test_join_local_ratelimit_profile_change(self):
        """Tests that sending a profile update into all of the user's joined rooms isn't
        rate-limited by the rate-limiter on joins."""

        # Create and join as many rooms as the rate-limiting config allows in a second.
        room_ids = [
            self.helper.create_room_as(self.user_id),
            self.helper.create_room_as(self.user_id),
            self.helper.create_room_as(self.user_id),
        ]
        # Let some time for the rate-limiter to forget about our multi-join.
        self.reactor.advance(2)
        # Add one to make sure we're joined to more rooms than the config allows us to
        # join in a second.
        room_ids.append(self.helper.create_room_as(self.user_id))

        # Create a profile for the user, since it hasn't been done on registration.
        store = self.hs.get_datastore()
        self.get_success(
            store.create_profile(UserID.from_string(self.user_id).localpart)
        )

        # Update the display name for the user.
        path = "/_matrix/client/r0/profile/%s/displayname" % self.user_id
        request, channel = self.make_request("PUT", path, {"displayname": "John Doe"})
        self.render(request)
        self.assertEquals(channel.code, 200, channel.json_body)

        # Check that all the rooms have been sent a profile update into.
        for room_id in room_ids:
            path = "/_matrix/client/r0/rooms/%s/state/m.room.member/%s" % (
                room_id,
                self.user_id,
            )

            request, channel = self.make_request("GET", path)
            self.render(request)
            self.assertEquals(channel.code, 200)

            self.assertIn("displayname", channel.json_body)
            self.assertEquals(channel.json_body["displayname"], "John Doe")

    @unittest.override_config(
        {"rc_joins": {"local": {"per_second": 0.5, "burst_count": 3}}}
    )
    def test_join_local_ratelimit_idempotent(self):
        """Tests that the room join endpoints remain idempotent despite rate-limiting
        on room joins."""
        room_id = self.helper.create_room_as(self.user_id)

        # Let's test both paths to be sure.
        paths_to_test = [
            "/_matrix/client/r0/rooms/%s/join",
            "/_matrix/client/r0/join/%s",
        ]

        for path in paths_to_test:
            # Make sure we send more requests than the rate-limiting config would allow
            # if all of these requests ended up joining the user to a room.
            for i in range(4):
                request, channel = self.make_request("POST", path % room_id, {})
                self.render(request)
                self.assertEquals(channel.code, 200)


class RoomMessagesTestCase(RoomBase):
    """ Tests /rooms/$room_id/messages/$user_id/$msg_id REST events. """

    user_id = "@sid1:red"

    def prepare(self, reactor, clock, hs):
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_invalid_puts(self):
        path = "/rooms/%s/send/m.room.message/mid1" % (urlparse.quote(self.room_id))
        # missing keys or invalid json
        request, channel = self.make_request("PUT", path, b"{}")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, b'{"_name":"bo"}')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, b'{"nao')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request(
            "PUT", path, b'[{"_name":"bo"},{"_name":"jill"}]'
        )
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, b"text only")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, b"")
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

    def test_rooms_messages_sent(self):
        path = "/rooms/%s/send/m.room.message/mid1" % (urlparse.quote(self.room_id))

        content = b'{"body":"test","msgtype":{"type":"a"}}'
        request, channel = self.make_request("PUT", path, content)
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        # custom message types
        content = b'{"body":"test","msgtype":"test.custom.text"}'
        request, channel = self.make_request("PUT", path, content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])

        # m.text message type
        path = "/rooms/%s/send/m.room.message/mid2" % (urlparse.quote(self.room_id))
        content = b'{"body":"test2","msgtype":"m.text"}'
        request, channel = self.make_request("PUT", path, content)
        self.render(request)
        self.assertEquals(200, channel.code, msg=channel.result["body"])


class RoomInitialSyncTestCase(RoomBase):
    """ Tests /rooms/$room_id/initialSync. """

    user_id = "@sid1:red"

    def prepare(self, reactor, clock, hs):
        # create the room
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_initial_sync(self):
        request, channel = self.make_request(
            "GET", "/rooms/%s/initialSync" % self.room_id
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        self.assertEquals(self.room_id, channel.json_body["room_id"])
        self.assertEquals("join", channel.json_body["membership"])

        # Room state is easier to assert on if we unpack it into a dict
        state = {}
        for event in channel.json_body["state"]:
            if "state_key" not in event:
                continue
            t = event["type"]
            if t not in state:
                state[t] = []
            state[t].append(event)

        self.assertTrue("m.room.create" in state)

        self.assertTrue("messages" in channel.json_body)
        self.assertTrue("chunk" in channel.json_body["messages"])
        self.assertTrue("end" in channel.json_body["messages"])

        self.assertTrue("presence" in channel.json_body)

        presence_by_user = {
            e["content"]["user_id"]: e for e in channel.json_body["presence"]
        }
        self.assertTrue(self.user_id in presence_by_user)
        self.assertEquals("m.presence", presence_by_user[self.user_id]["type"])


class RoomMessageListTestCase(RoomBase):
    """ Tests /rooms/$room_id/messages REST events. """

    user_id = "@sid1:red"

    def prepare(self, reactor, clock, hs):
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_topo_token_is_accepted(self):
        token = "t1-0_0_0_0_0_0_0_0_0"
        request, channel = self.make_request(
            "GET", "/rooms/%s/messages?access_token=x&from=%s" % (self.room_id, token)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        self.assertTrue("start" in channel.json_body)
        self.assertEquals(token, channel.json_body["start"])
        self.assertTrue("chunk" in channel.json_body)
        self.assertTrue("end" in channel.json_body)

    def test_stream_token_is_accepted_for_fwd_pagianation(self):
        token = "s0_0_0_0_0_0_0_0_0"
        request, channel = self.make_request(
            "GET", "/rooms/%s/messages?access_token=x&from=%s" % (self.room_id, token)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        self.assertTrue("start" in channel.json_body)
        self.assertEquals(token, channel.json_body["start"])
        self.assertTrue("chunk" in channel.json_body)
        self.assertTrue("end" in channel.json_body)

    def test_room_messages_purge(self):
        store = self.hs.get_datastore()
        pagination_handler = self.hs.get_pagination_handler()

        # Send a first message in the room, which will be removed by the purge.
        first_event_id = self.helper.send(self.room_id, "message 1")["event_id"]
        first_token = self.get_success(
            store.get_topological_token_for_event(first_event_id)
        )
        first_token_str = self.get_success(first_token.to_string(store))

        # Send a second message in the room, which won't be removed, and which we'll
        # use as the marker to purge events before.
        second_event_id = self.helper.send(self.room_id, "message 2")["event_id"]
        second_token = self.get_success(
            store.get_topological_token_for_event(second_event_id)
        )
        second_token_str = self.get_success(second_token.to_string(store))

        # Send a third event in the room to ensure we don't fall under any edge case
        # due to our marker being the latest forward extremity in the room.
        self.helper.send(self.room_id, "message 3")

        # Check that we get the first and second message when querying /messages.
        request, channel = self.make_request(
            "GET",
            "/rooms/%s/messages?access_token=x&from=%s&dir=b&filter=%s"
            % (
                self.room_id,
                second_token_str,
                json.dumps({"types": [EventTypes.Message]}),
            ),
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.json_body)

        chunk = channel.json_body["chunk"]
        self.assertEqual(len(chunk), 2, [event["content"] for event in chunk])

        # Purge every event before the second event.
        purge_id = random_string(16)
        pagination_handler._purges_by_id[purge_id] = PurgeStatus()
        self.get_success(
            pagination_handler._purge_history(
                purge_id=purge_id,
                room_id=self.room_id,
                token=second_token_str,
                delete_local_events=True,
            )
        )

        # Check that we only get the second message through /message now that the first
        # has been purged.
        request, channel = self.make_request(
            "GET",
            "/rooms/%s/messages?access_token=x&from=%s&dir=b&filter=%s"
            % (
                self.room_id,
                second_token_str,
                json.dumps({"types": [EventTypes.Message]}),
            ),
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.json_body)

        chunk = channel.json_body["chunk"]
        self.assertEqual(len(chunk), 1, [event["content"] for event in chunk])

        # Check that we get no event, but also no error, when querying /messages with
        # the token that was pointing at the first event, because we don't have it
        # anymore.
        request, channel = self.make_request(
            "GET",
            "/rooms/%s/messages?access_token=x&from=%s&dir=b&filter=%s"
            % (
                self.room_id,
                first_token_str,
                json.dumps({"types": [EventTypes.Message]}),
            ),
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.json_body)

        chunk = channel.json_body["chunk"]
        self.assertEqual(len(chunk), 0, [event["content"] for event in chunk])


class RoomSearchTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def prepare(self, reactor, clock, hs):

        # Register the user who does the searching
        self.user_id = self.register_user("user", "pass")
        self.access_token = self.login("user", "pass")

        # Register the user who sends the message
        self.other_user_id = self.register_user("otheruser", "pass")
        self.other_access_token = self.login("otheruser", "pass")

        # Create a room
        self.room = self.helper.create_room_as(self.user_id, tok=self.access_token)

        # Invite the other person
        self.helper.invite(
            room=self.room,
            src=self.user_id,
            tok=self.access_token,
            targ=self.other_user_id,
        )

        # The other user joins
        self.helper.join(
            room=self.room, user=self.other_user_id, tok=self.other_access_token
        )

    def test_finds_message(self):
        """
        The search functionality will search for content in messages if asked to
        do so.
        """
        # The other user sends some messages
        self.helper.send(self.room, body="Hi!", tok=self.other_access_token)
        self.helper.send(self.room, body="There!", tok=self.other_access_token)

        request, channel = self.make_request(
            "POST",
            "/search?access_token=%s" % (self.access_token,),
            {
                "search_categories": {
                    "room_events": {"keys": ["content.body"], "search_term": "Hi"}
                }
            },
        )
        self.render(request)

        # Check we get the results we expect -- one search result, of the sent
        # messages
        self.assertEqual(channel.code, 200)
        results = channel.json_body["search_categories"]["room_events"]
        self.assertEqual(results["count"], 1)
        self.assertEqual(results["results"][0]["result"]["content"]["body"], "Hi!")

        # No context was requested, so we should get none.
        self.assertEqual(results["results"][0]["context"], {})

    def test_include_context(self):
        """
        When event_context includes include_profile, profile information will be
        included in the search response.
        """
        # The other user sends some messages
        self.helper.send(self.room, body="Hi!", tok=self.other_access_token)
        self.helper.send(self.room, body="There!", tok=self.other_access_token)

        request, channel = self.make_request(
            "POST",
            "/search?access_token=%s" % (self.access_token,),
            {
                "search_categories": {
                    "room_events": {
                        "keys": ["content.body"],
                        "search_term": "Hi",
                        "event_context": {"include_profile": True},
                    }
                }
            },
        )
        self.render(request)

        # Check we get the results we expect -- one search result, of the sent
        # messages
        self.assertEqual(channel.code, 200)
        results = channel.json_body["search_categories"]["room_events"]
        self.assertEqual(results["count"], 1)
        self.assertEqual(results["results"][0]["result"]["content"]["body"], "Hi!")

        # We should get context info, like the two users, and the display names.
        context = results["results"][0]["context"]
        self.assertEqual(len(context["profile_info"].keys()), 2)
        self.assertEqual(
            context["profile_info"][self.other_user_id]["displayname"], "otheruser"
        )


class PublicRoomsRestrictedTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        self.url = b"/_matrix/client/r0/publicRooms"

        config = self.default_config()
        config["allow_public_rooms_without_auth"] = False
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def test_restricted_no_auth(self):
        request, channel = self.make_request("GET", self.url)
        self.render(request)
        self.assertEqual(channel.code, 401, channel.result)

    def test_restricted_auth(self):
        self.register_user("user", "pass")
        tok = self.login("user", "pass")

        request, channel = self.make_request("GET", self.url, access_token=tok)
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)


class PerRoomProfilesForbiddenTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        profile.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["allow_per_room_profiles"] = False
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor, clock, homeserver):
        self.user_id = self.register_user("test", "test")
        self.tok = self.login("test", "test")

        # Set a profile for the test user
        self.displayname = "test user"
        data = {"displayname": self.displayname}
        request_data = json.dumps(data)
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/profile/%s/displayname" % (self.user_id,),
            request_data,
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self.room_id = self.helper.create_room_as(self.user_id, tok=self.tok)

    def test_per_room_profile_forbidden(self):
        data = {"membership": "join", "displayname": "other test user"}
        request_data = json.dumps(data)
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/state/m.room.member/%s"
            % (self.room_id, self.user_id),
            request_data,
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)
        event_id = channel.json_body["event_id"]

        request, channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        res_displayname = channel.json_body["content"]["displayname"]
        self.assertEqual(res_displayname, self.displayname, channel.result)


class RoomMembershipReasonTestCase(unittest.HomeserverTestCase):
    """Tests that clients can add a "reason" field to membership events and
    that they get correctly added to the generated events and propagated.
    """

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.creator = self.register_user("creator", "test")
        self.creator_tok = self.login("creator", "test")

        self.second_user_id = self.register_user("second", "test")
        self.second_tok = self.login("second", "test")

        self.room_id = self.helper.create_room_as(self.creator, tok=self.creator_tok)

    def test_join_reason(self):
        reason = "hello"
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/{}/join".format(self.room_id),
            content={"reason": reason},
            access_token=self.second_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self._check_for_reason(reason)

    def test_leave_reason(self):
        self.helper.join(self.room_id, user=self.second_user_id, tok=self.second_tok)

        reason = "hello"
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/{}/leave".format(self.room_id),
            content={"reason": reason},
            access_token=self.second_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self._check_for_reason(reason)

    def test_kick_reason(self):
        self.helper.join(self.room_id, user=self.second_user_id, tok=self.second_tok)

        reason = "hello"
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/{}/kick".format(self.room_id),
            content={"reason": reason, "user_id": self.second_user_id},
            access_token=self.second_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self._check_for_reason(reason)

    def test_ban_reason(self):
        self.helper.join(self.room_id, user=self.second_user_id, tok=self.second_tok)

        reason = "hello"
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/{}/ban".format(self.room_id),
            content={"reason": reason, "user_id": self.second_user_id},
            access_token=self.creator_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self._check_for_reason(reason)

    def test_unban_reason(self):
        reason = "hello"
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/{}/unban".format(self.room_id),
            content={"reason": reason, "user_id": self.second_user_id},
            access_token=self.creator_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self._check_for_reason(reason)

    def test_invite_reason(self):
        reason = "hello"
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/{}/invite".format(self.room_id),
            content={"reason": reason, "user_id": self.second_user_id},
            access_token=self.creator_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self._check_for_reason(reason)

    def test_reject_invite_reason(self):
        self.helper.invite(
            self.room_id,
            src=self.creator,
            targ=self.second_user_id,
            tok=self.creator_tok,
        )

        reason = "hello"
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/{}/leave".format(self.room_id),
            content={"reason": reason},
            access_token=self.second_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        self._check_for_reason(reason)

    def _check_for_reason(self, reason):
        request, channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/{}/state/m.room.member/{}".format(
                self.room_id, self.second_user_id
            ),
            access_token=self.creator_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        event_content = channel.json_body

        self.assertEqual(event_content.get("reason"), reason, channel.result)


class LabelsTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        profile.register_servlets,
    ]

    # Filter that should only catch messages with the label "#fun".
    FILTER_LABELS = {
        "types": [EventTypes.Message],
        "org.matrix.labels": ["#fun"],
    }
    # Filter that should only catch messages without the label "#fun".
    FILTER_NOT_LABELS = {
        "types": [EventTypes.Message],
        "org.matrix.not_labels": ["#fun"],
    }
    # Filter that should only catch messages with the label "#work" but without the label
    # "#notfun".
    FILTER_LABELS_NOT_LABELS = {
        "types": [EventTypes.Message],
        "org.matrix.labels": ["#work"],
        "org.matrix.not_labels": ["#notfun"],
    }

    def prepare(self, reactor, clock, homeserver):
        self.user_id = self.register_user("test", "test")
        self.tok = self.login("test", "test")
        self.room_id = self.helper.create_room_as(self.user_id, tok=self.tok)

    def test_context_filter_labels(self):
        """Test that we can filter by a label on a /context request."""
        event_id = self._send_labelled_messages_in_room()

        request, channel = self.make_request(
            "GET",
            "/rooms/%s/context/%s?filter=%s"
            % (self.room_id, event_id, json.dumps(self.FILTER_LABELS)),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        events_before = channel.json_body["events_before"]

        self.assertEqual(
            len(events_before), 1, [event["content"] for event in events_before]
        )
        self.assertEqual(
            events_before[0]["content"]["body"], "with right label", events_before[0]
        )

        events_after = channel.json_body["events_before"]

        self.assertEqual(
            len(events_after), 1, [event["content"] for event in events_after]
        )
        self.assertEqual(
            events_after[0]["content"]["body"], "with right label", events_after[0]
        )

    def test_context_filter_not_labels(self):
        """Test that we can filter by the absence of a label on a /context request."""
        event_id = self._send_labelled_messages_in_room()

        request, channel = self.make_request(
            "GET",
            "/rooms/%s/context/%s?filter=%s"
            % (self.room_id, event_id, json.dumps(self.FILTER_NOT_LABELS)),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        events_before = channel.json_body["events_before"]

        self.assertEqual(
            len(events_before), 1, [event["content"] for event in events_before]
        )
        self.assertEqual(
            events_before[0]["content"]["body"], "without label", events_before[0]
        )

        events_after = channel.json_body["events_after"]

        self.assertEqual(
            len(events_after), 2, [event["content"] for event in events_after]
        )
        self.assertEqual(
            events_after[0]["content"]["body"], "with wrong label", events_after[0]
        )
        self.assertEqual(
            events_after[1]["content"]["body"], "with two wrong labels", events_after[1]
        )

    def test_context_filter_labels_not_labels(self):
        """Test that we can filter by both a label and the absence of another label on a
        /context request.
        """
        event_id = self._send_labelled_messages_in_room()

        request, channel = self.make_request(
            "GET",
            "/rooms/%s/context/%s?filter=%s"
            % (self.room_id, event_id, json.dumps(self.FILTER_LABELS_NOT_LABELS)),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        events_before = channel.json_body["events_before"]

        self.assertEqual(
            len(events_before), 0, [event["content"] for event in events_before]
        )

        events_after = channel.json_body["events_after"]

        self.assertEqual(
            len(events_after), 1, [event["content"] for event in events_after]
        )
        self.assertEqual(
            events_after[0]["content"]["body"], "with wrong label", events_after[0]
        )

    def test_messages_filter_labels(self):
        """Test that we can filter by a label on a /messages request."""
        self._send_labelled_messages_in_room()

        token = "s0_0_0_0_0_0_0_0_0"
        request, channel = self.make_request(
            "GET",
            "/rooms/%s/messages?access_token=%s&from=%s&filter=%s"
            % (self.room_id, self.tok, token, json.dumps(self.FILTER_LABELS)),
        )
        self.render(request)

        events = channel.json_body["chunk"]

        self.assertEqual(len(events), 2, [event["content"] for event in events])
        self.assertEqual(events[0]["content"]["body"], "with right label", events[0])
        self.assertEqual(events[1]["content"]["body"], "with right label", events[1])

    def test_messages_filter_not_labels(self):
        """Test that we can filter by the absence of a label on a /messages request."""
        self._send_labelled_messages_in_room()

        token = "s0_0_0_0_0_0_0_0_0"
        request, channel = self.make_request(
            "GET",
            "/rooms/%s/messages?access_token=%s&from=%s&filter=%s"
            % (self.room_id, self.tok, token, json.dumps(self.FILTER_NOT_LABELS)),
        )
        self.render(request)

        events = channel.json_body["chunk"]

        self.assertEqual(len(events), 4, [event["content"] for event in events])
        self.assertEqual(events[0]["content"]["body"], "without label", events[0])
        self.assertEqual(events[1]["content"]["body"], "without label", events[1])
        self.assertEqual(events[2]["content"]["body"], "with wrong label", events[2])
        self.assertEqual(
            events[3]["content"]["body"], "with two wrong labels", events[3]
        )

    def test_messages_filter_labels_not_labels(self):
        """Test that we can filter by both a label and the absence of another label on a
        /messages request.
        """
        self._send_labelled_messages_in_room()

        token = "s0_0_0_0_0_0_0_0_0"
        request, channel = self.make_request(
            "GET",
            "/rooms/%s/messages?access_token=%s&from=%s&filter=%s"
            % (
                self.room_id,
                self.tok,
                token,
                json.dumps(self.FILTER_LABELS_NOT_LABELS),
            ),
        )
        self.render(request)

        events = channel.json_body["chunk"]

        self.assertEqual(len(events), 1, [event["content"] for event in events])
        self.assertEqual(events[0]["content"]["body"], "with wrong label", events[0])

    def test_search_filter_labels(self):
        """Test that we can filter by a label on a /search request."""
        request_data = json.dumps(
            {
                "search_categories": {
                    "room_events": {
                        "search_term": "label",
                        "filter": self.FILTER_LABELS,
                    }
                }
            }
        )

        self._send_labelled_messages_in_room()

        request, channel = self.make_request(
            "POST", "/search?access_token=%s" % self.tok, request_data
        )
        self.render(request)

        results = channel.json_body["search_categories"]["room_events"]["results"]

        self.assertEqual(
            len(results), 2, [result["result"]["content"] for result in results],
        )
        self.assertEqual(
            results[0]["result"]["content"]["body"],
            "with right label",
            results[0]["result"]["content"]["body"],
        )
        self.assertEqual(
            results[1]["result"]["content"]["body"],
            "with right label",
            results[1]["result"]["content"]["body"],
        )

    def test_search_filter_not_labels(self):
        """Test that we can filter by the absence of a label on a /search request."""
        request_data = json.dumps(
            {
                "search_categories": {
                    "room_events": {
                        "search_term": "label",
                        "filter": self.FILTER_NOT_LABELS,
                    }
                }
            }
        )

        self._send_labelled_messages_in_room()

        request, channel = self.make_request(
            "POST", "/search?access_token=%s" % self.tok, request_data
        )
        self.render(request)

        results = channel.json_body["search_categories"]["room_events"]["results"]

        self.assertEqual(
            len(results), 4, [result["result"]["content"] for result in results],
        )
        self.assertEqual(
            results[0]["result"]["content"]["body"],
            "without label",
            results[0]["result"]["content"]["body"],
        )
        self.assertEqual(
            results[1]["result"]["content"]["body"],
            "without label",
            results[1]["result"]["content"]["body"],
        )
        self.assertEqual(
            results[2]["result"]["content"]["body"],
            "with wrong label",
            results[2]["result"]["content"]["body"],
        )
        self.assertEqual(
            results[3]["result"]["content"]["body"],
            "with two wrong labels",
            results[3]["result"]["content"]["body"],
        )

    def test_search_filter_labels_not_labels(self):
        """Test that we can filter by both a label and the absence of another label on a
        /search request.
        """
        request_data = json.dumps(
            {
                "search_categories": {
                    "room_events": {
                        "search_term": "label",
                        "filter": self.FILTER_LABELS_NOT_LABELS,
                    }
                }
            }
        )

        self._send_labelled_messages_in_room()

        request, channel = self.make_request(
            "POST", "/search?access_token=%s" % self.tok, request_data
        )
        self.render(request)

        results = channel.json_body["search_categories"]["room_events"]["results"]

        self.assertEqual(
            len(results), 1, [result["result"]["content"] for result in results],
        )
        self.assertEqual(
            results[0]["result"]["content"]["body"],
            "with wrong label",
            results[0]["result"]["content"]["body"],
        )

    def _send_labelled_messages_in_room(self):
        """Sends several messages to a room with different labels (or without any) to test
        filtering by label.
        Returns:
            The ID of the event to use if we're testing filtering on /context.
        """
        self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with right label",
                EventContentFields.LABELS: ["#fun"],
            },
            tok=self.tok,
        )

        self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "without label"},
            tok=self.tok,
        )

        res = self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "without label"},
            tok=self.tok,
        )
        # Return this event's ID when we test filtering in /context requests.
        event_id = res["event_id"]

        self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with wrong label",
                EventContentFields.LABELS: ["#work"],
            },
            tok=self.tok,
        )

        self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with two wrong labels",
                EventContentFields.LABELS: ["#work", "#notfun"],
            },
            tok=self.tok,
        )

        self.helper.send_event(
            room_id=self.room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with right label",
                EventContentFields.LABELS: ["#fun"],
            },
            tok=self.tok,
        )

        return event_id


class ContextTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        account.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.user_id = self.register_user("user", "password")
        self.tok = self.login("user", "password")
        self.room_id = self.helper.create_room_as(
            self.user_id, tok=self.tok, is_public=False
        )

        self.other_user_id = self.register_user("user2", "password")
        self.other_tok = self.login("user2", "password")

        self.helper.invite(self.room_id, self.user_id, self.other_user_id, tok=self.tok)
        self.helper.join(self.room_id, self.other_user_id, tok=self.other_tok)

    def test_erased_sender(self):
        """Test that an erasure request results in the requester's events being hidden
        from any new member of the room.
        """

        # Send a bunch of events in the room.

        self.helper.send(self.room_id, "message 1", tok=self.tok)
        self.helper.send(self.room_id, "message 2", tok=self.tok)
        event_id = self.helper.send(self.room_id, "message 3", tok=self.tok)["event_id"]
        self.helper.send(self.room_id, "message 4", tok=self.tok)
        self.helper.send(self.room_id, "message 5", tok=self.tok)

        # Check that we can still see the messages before the erasure request.

        request, channel = self.make_request(
            "GET",
            '/rooms/%s/context/%s?filter={"types":["m.room.message"]}'
            % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        events_before = channel.json_body["events_before"]

        self.assertEqual(len(events_before), 2, events_before)
        self.assertEqual(
            events_before[0].get("content", {}).get("body"),
            "message 2",
            events_before[0],
        )
        self.assertEqual(
            events_before[1].get("content", {}).get("body"),
            "message 1",
            events_before[1],
        )

        self.assertEqual(
            channel.json_body["event"].get("content", {}).get("body"),
            "message 3",
            channel.json_body["event"],
        )

        events_after = channel.json_body["events_after"]

        self.assertEqual(len(events_after), 2, events_after)
        self.assertEqual(
            events_after[0].get("content", {}).get("body"),
            "message 4",
            events_after[0],
        )
        self.assertEqual(
            events_after[1].get("content", {}).get("body"),
            "message 5",
            events_after[1],
        )

        # Deactivate the first account and erase the user's data.

        deactivate_account_handler = self.hs.get_deactivate_account_handler()
        self.get_success(
            deactivate_account_handler.deactivate_account(self.user_id, erase_data=True)
        )

        # Invite another user in the room. This is needed because messages will be
        # pruned only if the user wasn't a member of the room when the messages were
        # sent.

        invited_user_id = self.register_user("user3", "password")
        invited_tok = self.login("user3", "password")

        self.helper.invite(
            self.room_id, self.other_user_id, invited_user_id, tok=self.other_tok
        )
        self.helper.join(self.room_id, invited_user_id, tok=invited_tok)

        # Check that a user that joined the room after the erasure request can't see
        # the messages anymore.

        request, channel = self.make_request(
            "GET",
            '/rooms/%s/context/%s?filter={"types":["m.room.message"]}'
            % (self.room_id, event_id),
            access_token=invited_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        events_before = channel.json_body["events_before"]

        self.assertEqual(len(events_before), 2, events_before)
        self.assertDictEqual(events_before[0].get("content"), {}, events_before[0])
        self.assertDictEqual(events_before[1].get("content"), {}, events_before[1])

        self.assertDictEqual(
            channel.json_body["event"].get("content"), {}, channel.json_body["event"]
        )

        events_after = channel.json_body["events_after"]

        self.assertEqual(len(events_after), 2, events_after)
        self.assertDictEqual(events_after[0].get("content"), {}, events_after[0])
        self.assertEqual(events_after[1].get("content"), {}, events_after[1])


class RoomAliasListTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        directory.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.room_owner = self.register_user("room_owner", "test")
        self.room_owner_tok = self.login("room_owner", "test")

        self.room_id = self.helper.create_room_as(
            self.room_owner, tok=self.room_owner_tok
        )

    def test_no_aliases(self):
        res = self._get_aliases(self.room_owner_tok)
        self.assertEqual(res["aliases"], [])

    def test_not_in_room(self):
        self.register_user("user", "test")
        user_tok = self.login("user", "test")
        res = self._get_aliases(user_tok, expected_code=403)
        self.assertEqual(res["errcode"], "M_FORBIDDEN")

    def test_admin_user(self):
        alias1 = self._random_alias()
        self._set_alias_via_directory(alias1)

        self.register_user("user", "test", admin=True)
        user_tok = self.login("user", "test")

        res = self._get_aliases(user_tok)
        self.assertEqual(res["aliases"], [alias1])

    def test_with_aliases(self):
        alias1 = self._random_alias()
        alias2 = self._random_alias()

        self._set_alias_via_directory(alias1)
        self._set_alias_via_directory(alias2)

        res = self._get_aliases(self.room_owner_tok)
        self.assertEqual(set(res["aliases"]), {alias1, alias2})

    def test_peekable_room(self):
        alias1 = self._random_alias()
        self._set_alias_via_directory(alias1)

        self.helper.send_state(
            self.room_id,
            EventTypes.RoomHistoryVisibility,
            body={"history_visibility": "world_readable"},
            tok=self.room_owner_tok,
        )

        self.register_user("user", "test")
        user_tok = self.login("user", "test")

        res = self._get_aliases(user_tok)
        self.assertEqual(res["aliases"], [alias1])

    def _get_aliases(self, access_token: str, expected_code: int = 200) -> JsonDict:
        """Calls the endpoint under test. returns the json response object."""
        request, channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/org.matrix.msc2432/rooms/%s/aliases"
            % (self.room_id,),
            access_token=access_token,
        )
        self.render(request)
        self.assertEqual(channel.code, expected_code, channel.result)
        res = channel.json_body
        self.assertIsInstance(res, dict)
        if expected_code == 200:
            self.assertIsInstance(res["aliases"], list)
        return res

    def _random_alias(self) -> str:
        return RoomAlias(random_string(5), self.hs.hostname).to_string()

    def _set_alias_via_directory(self, alias: str, expected_code: int = 200):
        url = "/_matrix/client/r0/directory/room/" + alias
        data = {"room_id": self.room_id}
        request_data = json.dumps(data)

        request, channel = self.make_request(
            "PUT", url, request_data, access_token=self.room_owner_tok
        )
        self.render(request)
        self.assertEqual(channel.code, expected_code, channel.result)


class RoomCanonicalAliasTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        directory.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.room_owner = self.register_user("room_owner", "test")
        self.room_owner_tok = self.login("room_owner", "test")

        self.room_id = self.helper.create_room_as(
            self.room_owner, tok=self.room_owner_tok
        )

        self.alias = "#alias:test"
        self._set_alias_via_directory(self.alias)

    def _set_alias_via_directory(self, alias: str, expected_code: int = 200):
        url = "/_matrix/client/r0/directory/room/" + alias
        data = {"room_id": self.room_id}
        request_data = json.dumps(data)

        request, channel = self.make_request(
            "PUT", url, request_data, access_token=self.room_owner_tok
        )
        self.render(request)
        self.assertEqual(channel.code, expected_code, channel.result)

    def _get_canonical_alias(self, expected_code: int = 200) -> JsonDict:
        """Calls the endpoint under test. returns the json response object."""
        request, channel = self.make_request(
            "GET",
            "rooms/%s/state/m.room.canonical_alias" % (self.room_id,),
            access_token=self.room_owner_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, expected_code, channel.result)
        res = channel.json_body
        self.assertIsInstance(res, dict)
        return res

    def _set_canonical_alias(self, content: str, expected_code: int = 200) -> JsonDict:
        """Calls the endpoint under test. returns the json response object."""
        request, channel = self.make_request(
            "PUT",
            "rooms/%s/state/m.room.canonical_alias" % (self.room_id,),
            json.dumps(content),
            access_token=self.room_owner_tok,
        )
        self.render(request)
        self.assertEqual(channel.code, expected_code, channel.result)
        res = channel.json_body
        self.assertIsInstance(res, dict)
        return res

    def test_canonical_alias(self):
        """Test a basic alias message."""
        # There is no canonical alias to start with.
        self._get_canonical_alias(expected_code=404)

        # Create an alias.
        self._set_canonical_alias({"alias": self.alias})

        # Canonical alias now exists!
        res = self._get_canonical_alias()
        self.assertEqual(res, {"alias": self.alias})

        # Now remove the alias.
        self._set_canonical_alias({})

        # There is an alias event, but it is empty.
        res = self._get_canonical_alias()
        self.assertEqual(res, {})

    def test_alt_aliases(self):
        """Test a canonical alias message with alt_aliases."""
        # Create an alias.
        self._set_canonical_alias({"alt_aliases": [self.alias]})

        # Canonical alias now exists!
        res = self._get_canonical_alias()
        self.assertEqual(res, {"alt_aliases": [self.alias]})

        # Now remove the alt_aliases.
        self._set_canonical_alias({})

        # There is an alias event, but it is empty.
        res = self._get_canonical_alias()
        self.assertEqual(res, {})

    def test_alias_alt_aliases(self):
        """Test a canonical alias message with an alias and alt_aliases."""
        # Create an alias.
        self._set_canonical_alias({"alias": self.alias, "alt_aliases": [self.alias]})

        # Canonical alias now exists!
        res = self._get_canonical_alias()
        self.assertEqual(res, {"alias": self.alias, "alt_aliases": [self.alias]})

        # Now remove the alias and alt_aliases.
        self._set_canonical_alias({})

        # There is an alias event, but it is empty.
        res = self._get_canonical_alias()
        self.assertEqual(res, {})

    def test_partial_modify(self):
        """Test removing only the alt_aliases."""
        # Create an alias.
        self._set_canonical_alias({"alias": self.alias, "alt_aliases": [self.alias]})

        # Canonical alias now exists!
        res = self._get_canonical_alias()
        self.assertEqual(res, {"alias": self.alias, "alt_aliases": [self.alias]})

        # Now remove the alt_aliases.
        self._set_canonical_alias({"alias": self.alias})

        # There is an alias event, but it is empty.
        res = self._get_canonical_alias()
        self.assertEqual(res, {"alias": self.alias})

    def test_add_alias(self):
        """Test removing only the alt_aliases."""
        # Create an additional alias.
        second_alias = "#second:test"
        self._set_alias_via_directory(second_alias)

        # Add the canonical alias.
        self._set_canonical_alias({"alias": self.alias, "alt_aliases": [self.alias]})

        # Then add the second alias.
        self._set_canonical_alias(
            {"alias": self.alias, "alt_aliases": [self.alias, second_alias]}
        )

        # Canonical alias now exists!
        res = self._get_canonical_alias()
        self.assertEqual(
            res, {"alias": self.alias, "alt_aliases": [self.alias, second_alias]}
        )

    def test_bad_data(self):
        """Invalid data for alt_aliases should cause errors."""
        self._set_canonical_alias({"alt_aliases": "@bad:test"}, expected_code=400)
        self._set_canonical_alias({"alt_aliases": None}, expected_code=400)
        self._set_canonical_alias({"alt_aliases": 0}, expected_code=400)
        self._set_canonical_alias({"alt_aliases": 1}, expected_code=400)
        self._set_canonical_alias({"alt_aliases": False}, expected_code=400)
        self._set_canonical_alias({"alt_aliases": True}, expected_code=400)
        self._set_canonical_alias({"alt_aliases": {}}, expected_code=400)

    def test_bad_alias(self):
        """An alias which does not point to the room raises a SynapseError."""
        self._set_canonical_alias({"alias": "@unknown:test"}, expected_code=400)
        self._set_canonical_alias({"alt_aliases": ["@unknown:test"]}, expected_code=400)
