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

"""Tests REST events for /rooms paths."""

import json

from mock import Mock, NonCallableMock
from six.moves.urllib import parse as urlparse

from twisted.internet import defer

import synapse.rest.client.v1.room
from synapse.api.constants import Membership
from synapse.http.server import JsonResource
from synapse.types import UserID
from synapse.util import Clock

from tests import unittest
from tests.server import (
    ThreadedMemoryReactorClock,
    make_request,
    render,
    setup_test_homeserver,
)

from .utils import RestHelper

PATH_PREFIX = b"/_matrix/client/api/v1"


class RoomBase(unittest.TestCase):
    rmcreator_id = None

    def setUp(self):

        self.clock = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.clock)

        self.hs = setup_test_homeserver(
            "red",
            http_client=None,
            clock=self.hs_clock,
            reactor=self.clock,
            federation_client=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = self.hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        self.hs.get_federation_handler = Mock(return_value=Mock())

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.helper.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }

        def get_user_by_req(request, allow_guest=False, rights="access"):
            return synapse.types.create_requester(
                UserID.from_string(self.helper.auth_user_id), 1, False, None
            )

        self.hs.get_auth().get_user_by_req = get_user_by_req
        self.hs.get_auth().get_user_by_access_token = get_user_by_access_token
        self.hs.get_auth().get_access_token_from_request = Mock(return_value=b"1234")

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)

        self.hs.get_datastore().insert_client_ip = _insert_client_ip

        self.resource = JsonResource(self.hs)
        synapse.rest.client.v1.room.register_servlets(self.hs, self.resource)
        synapse.rest.client.v1.room.register_deprecated_servlets(self.hs, self.resource)
        self.helper = RestHelper(self.hs, self.resource, self.user_id)


class RoomPermissionsTestCase(RoomBase):
    """ Tests room permissions. """

    user_id = b"@sid1:red"
    rmcreator_id = b"@notme:red"

    def setUp(self):

        super(RoomPermissionsTestCase, self).setUp()

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
        ).encode('ascii')
        request, channel = make_request(
            b"PUT",
            self.created_rmid_msg_path,
            b'{"msgtype":"m.text","body":"test msg"}',
        )
        render(request, self.resource, self.clock)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # set topic for public room
        request, channel = make_request(
            b"PUT",
            ("rooms/%s/state/m.room.topic" % self.created_public_rmid).encode('ascii'),
            b'{"topic":"Public Room Topic"}',
        )
        render(request, self.resource, self.clock)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # auth as user_id now
        self.helper.auth_user_id = self.user_id

    def test_send_message(self):
        msg_content = b'{"msgtype":"m.text","body":"hello"}'

        seq = iter(range(100))

        def send_msg_path():
            return b"/rooms/%s/send/m.room.message/mid%s" % (
                self.created_rmid,
                str(next(seq)).encode('ascii'),
            )

        # send message in uncreated room, expect 403
        request, channel = make_request(
            b"PUT",
            b"/rooms/%s/send/m.room.message/mid2" % (self.uncreated_rmid,),
            msg_content,
        )
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # send message in created room not joined (no state), expect 403
        request, channel = make_request(b"PUT", send_msg_path(), msg_content)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # send message in created room and invited, expect 403
        self.helper.invite(
            room=self.created_rmid, src=self.rmcreator_id, targ=self.user_id
        )
        request, channel = make_request(b"PUT", send_msg_path(), msg_content)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # send message in created room and joined, expect 200
        self.helper.join(room=self.created_rmid, user=self.user_id)
        request, channel = make_request(b"PUT", send_msg_path(), msg_content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        # send message in created room and left, expect 403
        self.helper.leave(room=self.created_rmid, user=self.user_id)
        request, channel = make_request(b"PUT", send_msg_path(), msg_content)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

    def test_topic_perms(self):
        topic_content = b'{"topic":"My Topic Name"}'
        topic_path = b"/rooms/%s/state/m.room.topic" % self.created_rmid

        # set/get topic in uncreated room, expect 403
        request, channel = make_request(
            b"PUT", b"/rooms/%s/state/m.room.topic" % self.uncreated_rmid, topic_content
        )
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])
        request, channel = make_request(
            b"GET", "/rooms/%s/state/m.room.topic" % self.uncreated_rmid
        )
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # set/get topic in created PRIVATE room not joined, expect 403
        request, channel = make_request(b"PUT", topic_path, topic_content)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])
        request, channel = make_request(b"GET", topic_path)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # set topic in created PRIVATE room and invited, expect 403
        self.helper.invite(
            room=self.created_rmid, src=self.rmcreator_id, targ=self.user_id
        )
        request, channel = make_request(b"PUT", topic_path, topic_content)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # get topic in created PRIVATE room and invited, expect 403
        request, channel = make_request(b"GET", topic_path)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # set/get topic in created PRIVATE room and joined, expect 200
        self.helper.join(room=self.created_rmid, user=self.user_id)

        # Only room ops can set topic by default
        self.helper.auth_user_id = self.rmcreator_id
        request, channel = make_request(b"PUT", topic_path, topic_content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
        self.helper.auth_user_id = self.user_id

        request, channel = make_request(b"GET", topic_path)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assert_dict(json.loads(topic_content), channel.json_body)

        # set/get topic in created PRIVATE room and left, expect 403
        self.helper.leave(room=self.created_rmid, user=self.user_id)
        request, channel = make_request(b"PUT", topic_path, topic_content)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])
        request, channel = make_request(b"GET", topic_path)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        # get topic in PUBLIC room, not joined, expect 403
        request, channel = make_request(
            b"GET", b"/rooms/%s/state/m.room.topic" % self.created_public_rmid
        )
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        # set topic in PUBLIC room, not joined, expect 403
        request, channel = make_request(
            b"PUT",
            b"/rooms/%s/state/m.room.topic" % self.created_public_rmid,
            topic_content,
        )
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

    def _test_get_membership(self, room=None, members=[], expect_code=None):
        for member in members:
            path = b"/rooms/%s/state/m.room.member/%s" % (room, member)
            request, channel = make_request(b"GET", path)
            render(request, self.resource, self.clock)
            self.assertEquals(expect_code, int(channel.result["code"]))

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

    user_id = b"@sid1:red"

    def test_get_member_list(self):
        room_id = self.helper.create_room_as(self.user_id)
        request, channel = make_request(b"GET", b"/rooms/%s/members" % room_id)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

    def test_get_member_list_no_room(self):
        request, channel = make_request(b"GET", b"/rooms/roomdoesnotexist/members")
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

    def test_get_member_list_no_permission(self):
        room_id = self.helper.create_room_as(b"@some_other_guy:red")
        request, channel = make_request(b"GET", b"/rooms/%s/members" % room_id)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

    def test_get_member_list_mixed_memberships(self):
        room_creator = b"@some_other_guy:red"
        room_id = self.helper.create_room_as(room_creator)
        room_path = b"/rooms/%s/members" % room_id
        self.helper.invite(room=room_id, src=room_creator, targ=self.user_id)
        # can't see list if you're just invited.
        request, channel = make_request(b"GET", room_path)
        render(request, self.resource, self.clock)
        self.assertEquals(403, int(channel.result["code"]), msg=channel.result["body"])

        self.helper.join(room=room_id, user=self.user_id)
        # can see list now joined
        request, channel = make_request(b"GET", room_path)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        self.helper.leave(room=room_id, user=self.user_id)
        # can see old list once left
        request, channel = make_request(b"GET", room_path)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])


class RoomsCreateTestCase(RoomBase):
    """ Tests /rooms and /rooms/$room_id REST events. """

    user_id = b"@sid1:red"

    def test_post_room_no_keys(self):
        # POST with no config keys, expect new room id
        request, channel = make_request(b"POST", b"/createRoom", b"{}")

        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), channel.result)
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_visibility_key(self):
        # POST with visibility config key, expect new room id
        request, channel = make_request(
            b"POST", b"/createRoom", b'{"visibility":"private"}'
        )
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]))
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_custom_key(self):
        # POST with custom config keys, expect new room id
        request, channel = make_request(b"POST", b"/createRoom", b'{"custom":"stuff"}')
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]))
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_known_and_unknown_keys(self):
        # POST with custom + known config keys, expect new room id
        request, channel = make_request(
            b"POST", b"/createRoom", b'{"visibility":"private","custom":"things"}'
        )
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]))
        self.assertTrue("room_id" in channel.json_body)

    def test_post_room_invalid_content(self):
        # POST with invalid content / paths, expect 400
        request, channel = make_request(b"POST", b"/createRoom", b'{"visibili')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]))

        request, channel = make_request(b"POST", b"/createRoom", b'["hello"]')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]))


class RoomTopicTestCase(RoomBase):
    """ Tests /rooms/$room_id/topic REST events. """

    user_id = b"@sid1:red"

    def setUp(self):

        super(RoomTopicTestCase, self).setUp()

        # create the room
        self.room_id = self.helper.create_room_as(self.user_id)
        self.path = b"/rooms/%s/state/m.room.topic" % (self.room_id,)

    def test_invalid_puts(self):
        # missing keys or invalid json
        request, channel = make_request(b"PUT", self.path, '{}')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", self.path, '{"_name":"bob"}')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", self.path, '{"nao')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(
            b"PUT", self.path, '[{"_name":"bob"},{"_name":"jill"}]'
        )
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", self.path, 'text only')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", self.path, '')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        # valid key, wrong type
        content = '{"topic":["Topic name"]}'
        request, channel = make_request(b"PUT", self.path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

    def test_rooms_topic(self):
        # nothing should be there
        request, channel = make_request(b"GET", self.path)
        render(request, self.resource, self.clock)
        self.assertEquals(404, int(channel.result["code"]), msg=channel.result["body"])

        # valid put
        content = '{"topic":"Topic name"}'
        request, channel = make_request(b"PUT", self.path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        # valid get
        request, channel = make_request(b"GET", self.path)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assert_dict(json.loads(content), channel.json_body)

    def test_rooms_topic_with_extra_keys(self):
        # valid put with extra keys
        content = '{"topic":"Seasons","subtopic":"Summer"}'
        request, channel = make_request(b"PUT", self.path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        # valid get
        request, channel = make_request(b"GET", self.path)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assert_dict(json.loads(content), channel.json_body)


class RoomMemberStateTestCase(RoomBase):
    """ Tests /rooms/$room_id/members/$user_id/state REST events. """

    user_id = b"@sid1:red"

    def setUp(self):

        super(RoomMemberStateTestCase, self).setUp()
        self.room_id = self.helper.create_room_as(self.user_id)

    def tearDown(self):
        pass

    def test_invalid_puts(self):
        path = "/rooms/%s/state/m.room.member/%s" % (self.room_id, self.user_id)
        # missing keys or invalid json
        request, channel = make_request(b"PUT", path, '{}')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, '{"_name":"bob"}')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, '{"nao')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(
            b"PUT", path, b'[{"_name":"bob"},{"_name":"jill"}]'
        )
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, 'text only')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, '')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        # valid keys, wrong types
        content = '{"membership":["%s","%s","%s"]}' % (
            Membership.INVITE,
            Membership.JOIN,
            Membership.LEAVE,
        )
        request, channel = make_request(b"PUT", path, content.encode('ascii'))
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

    def test_rooms_members_self(self):
        path = "/rooms/%s/state/m.room.member/%s" % (
            urlparse.quote(self.room_id),
            self.user_id,
        )

        # valid join message (NOOP since we made the room)
        content = '{"membership":"%s"}' % Membership.JOIN
        request, channel = make_request(b"PUT", path, content.encode('ascii'))
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"GET", path, None)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

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
        request, channel = make_request(b"PUT", path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"GET", path, None)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
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
        request, channel = make_request(b"PUT", path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"GET", path, None)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEquals(json.loads(content), channel.json_body)


class RoomMessagesTestCase(RoomBase):
    """ Tests /rooms/$room_id/messages/$user_id/$msg_id REST events. """

    user_id = "@sid1:red"

    def setUp(self):
        super(RoomMessagesTestCase, self).setUp()

        self.room_id = self.helper.create_room_as(self.user_id)

    def test_invalid_puts(self):
        path = "/rooms/%s/send/m.room.message/mid1" % (urlparse.quote(self.room_id))
        # missing keys or invalid json
        request, channel = make_request(b"PUT", path, '{}')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, '{"_name":"bob"}')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, '{"nao')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(
            b"PUT", path, '[{"_name":"bob"},{"_name":"jill"}]'
        )
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, 'text only')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        request, channel = make_request(b"PUT", path, '')
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

    def test_rooms_messages_sent(self):
        path = "/rooms/%s/send/m.room.message/mid1" % (urlparse.quote(self.room_id))

        content = '{"body":"test","msgtype":{"type":"a"}}'
        request, channel = make_request(b"PUT", path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(400, int(channel.result["code"]), msg=channel.result["body"])

        # custom message types
        content = '{"body":"test","msgtype":"test.custom.text"}'
        request, channel = make_request(b"PUT", path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])

        # m.text message type
        path = "/rooms/%s/send/m.room.message/mid2" % (urlparse.quote(self.room_id))
        content = '{"body":"test2","msgtype":"m.text"}'
        request, channel = make_request(b"PUT", path, content)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])


class RoomInitialSyncTestCase(RoomBase):
    """ Tests /rooms/$room_id/initialSync. """

    user_id = "@sid1:red"

    def setUp(self):
        super(RoomInitialSyncTestCase, self).setUp()

        # create the room
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_initial_sync(self):
        request, channel = make_request(b"GET", "/rooms/%s/initialSync" % self.room_id)
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]))

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

    def setUp(self):
        super(RoomMessageListTestCase, self).setUp()
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_topo_token_is_accepted(self):
        token = "t1-0_0_0_0_0_0_0_0_0"
        request, channel = make_request(
            b"GET", "/rooms/%s/messages?access_token=x&from=%s" % (self.room_id, token)
        )
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]))
        self.assertTrue("start" in channel.json_body)
        self.assertEquals(token, channel.json_body['start'])
        self.assertTrue("chunk" in channel.json_body)
        self.assertTrue("end" in channel.json_body)

    def test_stream_token_is_accepted_for_fwd_pagianation(self):
        token = "s0_0_0_0_0_0_0_0_0"
        request, channel = make_request(
            b"GET", "/rooms/%s/messages?access_token=x&from=%s" % (self.room_id, token)
        )
        render(request, self.resource, self.clock)
        self.assertEquals(200, int(channel.result["code"]))
        self.assertTrue("start" in channel.json_body)
        self.assertEquals(token, channel.json_body['start'])
        self.assertTrue("chunk" in channel.json_body)
        self.assertTrue("end" in channel.json_body)
