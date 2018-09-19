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

from synapse.api.constants import Membership
from synapse.rest.client.v1 import room

from tests import unittest

PATH_PREFIX = b"/_matrix/client/api/v1"


class RoomBase(unittest.HomeserverTestCase):
    rmcreator_id = None

    servlets = [room.register_servlets, room.register_deprecated_servlets]

    def make_homeserver(self, reactor, clock):

        self.hs = self.setup_test_homeserver(
            "red",
            http_client=None,
            federation_client=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = self.hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        self.hs.get_federation_handler = Mock(return_value=Mock())

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)

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
        ).encode('ascii')
        request, channel = self.make_request(
            "PUT", self.created_rmid_msg_path, b'{"msgtype":"m.text","body":"test msg"}'
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

        # set topic for public room
        request, channel = self.make_request(
            "PUT",
            ("rooms/%s/state/m.room.topic" % self.created_public_rmid).encode('ascii'),
            b'{"topic":"Public Room Topic"}',
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

        # auth as user_id now
        self.helper.auth_user_id = self.user_id

    def test_send_message(self):
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
        self.assert_dict(json.loads(topic_content.decode('utf8')), channel.json_body)

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


class RoomTopicTestCase(RoomBase):
    """ Tests /rooms/$room_id/topic REST events. """

    user_id = "@sid1:red"

    def prepare(self, reactor, clock, hs):
        # create the room
        self.room_id = self.helper.create_room_as(self.user_id)
        self.path = "/rooms/%s/state/m.room.topic" % (self.room_id,)

    def test_invalid_puts(self):
        # missing keys or invalid json
        request, channel = self.make_request("PUT", self.path, '{}')
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

        request, channel = self.make_request("PUT", self.path, 'text only')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", self.path, '')
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
        request, channel = self.make_request("PUT", path, '{}')
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

        request, channel = self.make_request("PUT", path, 'text only')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, '')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        # valid keys, wrong types
        content = '{"membership":["%s","%s","%s"]}' % (
            Membership.INVITE,
            Membership.JOIN,
            Membership.LEAVE,
        )
        request, channel = self.make_request("PUT", path, content.encode('ascii'))
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

    def test_rooms_members_self(self):
        path = "/rooms/%s/state/m.room.member/%s" % (
            urlparse.quote(self.room_id),
            self.user_id,
        )

        # valid join message (NOOP since we made the room)
        content = '{"membership":"%s"}' % Membership.JOIN
        request, channel = self.make_request("PUT", path, content.encode('ascii'))
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


class RoomMessagesTestCase(RoomBase):
    """ Tests /rooms/$room_id/messages/$user_id/$msg_id REST events. """

    user_id = "@sid1:red"

    def prepare(self, reactor, clock, hs):
        self.room_id = self.helper.create_room_as(self.user_id)

    def test_invalid_puts(self):
        path = "/rooms/%s/send/m.room.message/mid1" % (urlparse.quote(self.room_id))
        # missing keys or invalid json
        request, channel = self.make_request("PUT", path, b'{}')
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

        request, channel = self.make_request("PUT", path, b'text only')
        self.render(request)
        self.assertEquals(400, channel.code, msg=channel.result["body"])

        request, channel = self.make_request("PUT", path, b'')
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
        self.assertEquals(token, channel.json_body['start'])
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
        self.assertEquals(token, channel.json_body['start'])
        self.assertTrue("chunk" in channel.json_body)
        self.assertTrue("end" in channel.json_body)
