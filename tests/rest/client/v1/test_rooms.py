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

# twisted imports
from twisted.internet import defer

import synapse.rest.client.v1.room
from synapse.api.constants import Membership

from synapse.types import UserID

import json
import urllib

from ....utils import MockHttpResource, setup_test_homeserver
from .utils import RestTestCase

from mock import Mock, NonCallableMock

PATH_PREFIX = "/_matrix/client/api/v1"


class RoomPermissionsTestCase(RestTestCase):
    """ Tests room permissions. """
    user_id = "@sid1:red"
    rmcreator_id = "@notme:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        self.auth_user_id = self.rmcreator_id

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        self.auth = hs.get_v1auth()

        # create some rooms under the name rmcreator_id
        self.uncreated_rmid = "!aa:test"

        self.created_rmid = yield self.create_room_as(self.rmcreator_id,
                                                      is_public=False)

        self.created_public_rmid = yield self.create_room_as(self.rmcreator_id,
                                                             is_public=True)

        # send a message in one of the rooms
        self.created_rmid_msg_path = (
            "/rooms/%s/send/m.room.message/a1" % (self.created_rmid)
        )
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            self.created_rmid_msg_path,
            '{"msgtype":"m.text","body":"test msg"}'
        )
        self.assertEquals(200, code, msg=str(response))

        # set topic for public room
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            "/rooms/%s/state/m.room.topic" % self.created_public_rmid,
            '{"topic":"Public Room Topic"}'
        )
        self.assertEquals(200, code, msg=str(response))

        # auth as user_id now
        self.auth_user_id = self.user_id

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_send_message(self):
        msg_content = '{"msgtype":"m.text","body":"hello"}'
        send_msg_path = (
            "/rooms/%s/send/m.room.message/mid1" % (self.created_rmid,)
        )

        # send message in uncreated room, expect 403
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            "/rooms/%s/send/m.room.message/mid2" % (self.uncreated_rmid,),
            msg_content
        )
        self.assertEquals(403, code, msg=str(response))

        # send message in created room not joined (no state), expect 403
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            send_msg_path,
            msg_content
        )
        self.assertEquals(403, code, msg=str(response))

        # send message in created room and invited, expect 403
        yield self.invite(
            room=self.created_rmid,
            src=self.rmcreator_id,
            targ=self.user_id
        )
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            send_msg_path,
            msg_content
        )
        self.assertEquals(403, code, msg=str(response))

        # send message in created room and joined, expect 200
        yield self.join(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            send_msg_path,
            msg_content
        )
        self.assertEquals(200, code, msg=str(response))

        # send message in created room and left, expect 403
        yield self.leave(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            send_msg_path,
            msg_content
        )
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def test_topic_perms(self):
        topic_content = '{"topic":"My Topic Name"}'
        topic_path = "/rooms/%s/state/m.room.topic" % self.created_rmid

        # set/get topic in uncreated room, expect 403
        (code, response) = yield self.mock_resource.trigger(
            "PUT", "/rooms/%s/state/m.room.topic" % self.uncreated_rmid,
            topic_content
        )
        self.assertEquals(403, code, msg=str(response))
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/%s/state/m.room.topic" % self.uncreated_rmid
        )
        self.assertEquals(403, code, msg=str(response))

        # set/get topic in created PRIVATE room not joined, expect 403
        (code, response) = yield self.mock_resource.trigger(
            "PUT", topic_path, topic_content
        )
        self.assertEquals(403, code, msg=str(response))
        (code, response) = yield self.mock_resource.trigger_get(topic_path)
        self.assertEquals(403, code, msg=str(response))

        # set topic in created PRIVATE room and invited, expect 403
        yield self.invite(
            room=self.created_rmid, src=self.rmcreator_id, targ=self.user_id
        )
        (code, response) = yield self.mock_resource.trigger(
            "PUT", topic_path, topic_content
        )
        self.assertEquals(403, code, msg=str(response))

        # get topic in created PRIVATE room and invited, expect 403
        (code, response) = yield self.mock_resource.trigger_get(topic_path)
        self.assertEquals(403, code, msg=str(response))

        # set/get topic in created PRIVATE room and joined, expect 200
        yield self.join(room=self.created_rmid, user=self.user_id)

        # Only room ops can set topic by default
        self.auth_user_id = self.rmcreator_id
        (code, response) = yield self.mock_resource.trigger(
            "PUT", topic_path, topic_content
        )
        self.assertEquals(200, code, msg=str(response))
        self.auth_user_id = self.user_id

        (code, response) = yield self.mock_resource.trigger_get(topic_path)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(topic_content), response)

        # set/get topic in created PRIVATE room and left, expect 403
        yield self.leave(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_resource.trigger(
            "PUT", topic_path, topic_content
        )
        self.assertEquals(403, code, msg=str(response))
        (code, response) = yield self.mock_resource.trigger_get(topic_path)
        self.assertEquals(200, code, msg=str(response))

        # get topic in PUBLIC room, not joined, expect 403
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/%s/state/m.room.topic" % self.created_public_rmid
        )
        self.assertEquals(403, code, msg=str(response))

        # set topic in PUBLIC room, not joined, expect 403
        (code, response) = yield self.mock_resource.trigger(
            "PUT",
            "/rooms/%s/state/m.room.topic" % self.created_public_rmid,
            topic_content
        )
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def _test_get_membership(self, room=None, members=[], expect_code=None):
        for member in members:
            path = "/rooms/%s/state/m.room.member/%s" % (room, member)
            (code, response) = yield self.mock_resource.trigger_get(path)
            self.assertEquals(expect_code, code)

    @defer.inlineCallbacks
    def test_membership_basic_room_perms(self):
        # === room does not exist ===
        room = self.uncreated_rmid
        # get membership of self, get membership of other, uncreated room
        # expect all 403s
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=403)

        # trying to invite people to this room should 403
        yield self.invite(room=room, src=self.user_id, targ=self.rmcreator_id,
                          expect_code=403)

        # set [invite/join/left] of self, set [invite/join/left] of other,
        # expect all 404s because room doesn't exist on any server
        for usr in [self.user_id, self.rmcreator_id]:
            yield self.join(room=room, user=usr, expect_code=404)
            yield self.leave(room=room, user=usr, expect_code=404)

    @defer.inlineCallbacks
    def test_membership_private_room_perms(self):
        room = self.created_rmid
        # get membership of self, get membership of other, private room + invite
        # expect all 403s
        yield self.invite(room=room, src=self.rmcreator_id,
                          targ=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=403)

        # get membership of self, get membership of other, private room + joined
        # expect all 200s
        yield self.join(room=room, user=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=200)

        # get membership of self, get membership of other, private room + left
        # expect all 200s
        yield self.leave(room=room, user=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=200)

    @defer.inlineCallbacks
    def test_membership_public_room_perms(self):
        room = self.created_public_rmid
        # get membership of self, get membership of other, public room + invite
        # expect 403
        yield self.invite(room=room, src=self.rmcreator_id,
                          targ=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=403)

        # get membership of self, get membership of other, public room + joined
        # expect all 200s
        yield self.join(room=room, user=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=200)

        # get membership of self, get membership of other, public room + left
        # expect 200.
        yield self.leave(room=room, user=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=200)

    @defer.inlineCallbacks
    def test_invited_permissions(self):
        room = self.created_rmid
        yield self.invite(room=room, src=self.rmcreator_id, targ=self.user_id)

        # set [invite/join/left] of other user, expect 403s
        yield self.invite(room=room, src=self.user_id, targ=self.rmcreator_id,
                          expect_code=403)
        yield self.change_membership(room=room, src=self.user_id,
                                     targ=self.rmcreator_id,
                                     membership=Membership.JOIN,
                                     expect_code=403)
        yield self.change_membership(room=room, src=self.user_id,
                                     targ=self.rmcreator_id,
                                     membership=Membership.LEAVE,
                                     expect_code=403)

    @defer.inlineCallbacks
    def test_joined_permissions(self):
        room = self.created_rmid
        yield self.invite(room=room, src=self.rmcreator_id, targ=self.user_id)
        yield self.join(room=room, user=self.user_id)

        # set invited of self, expect 403
        yield self.invite(room=room, src=self.user_id, targ=self.user_id,
                          expect_code=403)

        # set joined of self, expect 200 (NOOP)
        yield self.join(room=room, user=self.user_id)

        other = "@burgundy:red"
        # set invited of other, expect 200
        yield self.invite(room=room, src=self.user_id, targ=other,
                          expect_code=200)

        # set joined of other, expect 403
        yield self.change_membership(room=room, src=self.user_id,
                                     targ=other,
                                     membership=Membership.JOIN,
                                     expect_code=403)

        # set left of other, expect 403
        yield self.change_membership(room=room, src=self.user_id,
                                     targ=other,
                                     membership=Membership.LEAVE,
                                     expect_code=403)

        # set left of self, expect 200
        yield self.leave(room=room, user=self.user_id)

    @defer.inlineCallbacks
    def test_leave_permissions(self):
        room = self.created_rmid
        yield self.invite(room=room, src=self.rmcreator_id, targ=self.user_id)
        yield self.join(room=room, user=self.user_id)
        yield self.leave(room=room, user=self.user_id)

        # set [invite/join/left] of self, set [invite/join/left] of other,
        # expect all 403s
        for usr in [self.user_id, self.rmcreator_id]:
            yield self.change_membership(
                room=room,
                src=self.user_id,
                targ=usr,
                membership=Membership.INVITE,
                expect_code=403
            )

            yield self.change_membership(
                room=room,
                src=self.user_id,
                targ=usr,
                membership=Membership.JOIN,
                expect_code=403
            )

        # It is always valid to LEAVE if you've already left (currently.)
        yield self.change_membership(
            room=room,
            src=self.user_id,
            targ=self.rmcreator_id,
            membership=Membership.LEAVE,
            expect_code=403
        )


class RoomsMemberListTestCase(RestTestCase):
    """ Tests /rooms/$room_id/members/list REST events."""
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        self.auth_user_id = self.user_id

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_get_member_list(self):
        room_id = yield self.create_room_as(self.user_id)
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/%s/members" % room_id
        )
        self.assertEquals(200, code, msg=str(response))

    @defer.inlineCallbacks
    def test_get_member_list_no_room(self):
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/roomdoesnotexist/members"
        )
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def test_get_member_list_no_permission(self):
        room_id = yield self.create_room_as("@some_other_guy:red")
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/%s/members" % room_id
        )
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def test_get_member_list_mixed_memberships(self):
        room_creator = "@some_other_guy:red"
        room_id = yield self.create_room_as(room_creator)
        room_path = "/rooms/%s/members" % room_id
        yield self.invite(room=room_id, src=room_creator,
                          targ=self.user_id)
        # can't see list if you're just invited.
        (code, response) = yield self.mock_resource.trigger_get(room_path)
        self.assertEquals(403, code, msg=str(response))

        yield self.join(room=room_id, user=self.user_id)
        # can see list now joined
        (code, response) = yield self.mock_resource.trigger_get(room_path)
        self.assertEquals(200, code, msg=str(response))

        yield self.leave(room=room_id, user=self.user_id)
        # can see old list once left
        (code, response) = yield self.mock_resource.trigger_get(room_path)
        self.assertEquals(200, code, msg=str(response))


class RoomsCreateTestCase(RestTestCase):
    """ Tests /rooms and /rooms/$room_id REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_post_room_no_keys(self):
        # POST with no config keys, expect new room id
        (code, response) = yield self.mock_resource.trigger("POST",
                                                            "/createRoom",
                                                            "{}")
        self.assertEquals(200, code, response)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_visibility_key(self):
        # POST with visibility config key, expect new room id
        (code, response) = yield self.mock_resource.trigger(
            "POST",
            "/createRoom",
            '{"visibility":"private"}')
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_custom_key(self):
        # POST with custom config keys, expect new room id
        (code, response) = yield self.mock_resource.trigger(
            "POST",
            "/createRoom",
            '{"custom":"stuff"}')
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_known_and_unknown_keys(self):
        # POST with custom + known config keys, expect new room id
        (code, response) = yield self.mock_resource.trigger(
            "POST",
            "/createRoom",
            '{"visibility":"private","custom":"things"}')
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_invalid_content(self):
        # POST with invalid content / paths, expect 400
        (code, response) = yield self.mock_resource.trigger(
            "POST",
            "/createRoom",
            '{"visibili')
        self.assertEquals(400, code)

        (code, response) = yield self.mock_resource.trigger(
            "POST",
            "/createRoom",
            '["hello"]')
        self.assertEquals(400, code)


class RoomTopicTestCase(RestTestCase):
    """ Tests /rooms/$room_id/topic REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }

        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        # create the room
        self.room_id = yield self.create_room_as(self.user_id)
        self.path = "/rooms/%s/state/m.room.topic" % (self.room_id,)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_invalid_puts(self):
        # missing keys or invalid json
        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, '{}'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, '{"_name":"bob"}'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, '{"nao'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, '[{"_name":"bob"},{"_name":"jill"}]'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, 'text only'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, ''
        )
        self.assertEquals(400, code, msg=str(response))

        # valid key, wrong type
        content = '{"topic":["Topic name"]}'
        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, content
        )
        self.assertEquals(400, code, msg=str(response))

    @defer.inlineCallbacks
    def test_rooms_topic(self):
        # nothing should be there
        (code, response) = yield self.mock_resource.trigger_get(self.path)
        self.assertEquals(404, code, msg=str(response))

        # valid put
        content = '{"topic":"Topic name"}'
        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, content
        )
        self.assertEquals(200, code, msg=str(response))

        # valid get
        (code, response) = yield self.mock_resource.trigger_get(self.path)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(content), response)

    @defer.inlineCallbacks
    def test_rooms_topic_with_extra_keys(self):
        # valid put with extra keys
        content = '{"topic":"Seasons","subtopic":"Summer"}'
        (code, response) = yield self.mock_resource.trigger(
            "PUT", self.path, content
        )
        self.assertEquals(200, code, msg=str(response))

        # valid get
        (code, response) = yield self.mock_resource.trigger_get(self.path)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(content), response)


class RoomMemberStateTestCase(RestTestCase):
    """ Tests /rooms/$room_id/members/$user_id/state REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        self.room_id = yield self.create_room_as(self.user_id)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_invalid_puts(self):
        path = "/rooms/%s/state/m.room.member/%s" % (self.room_id, self.user_id)
        # missing keys or invalid json
        (code, response) = yield self.mock_resource.trigger("PUT", path, '{}')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, '{"_name":"bob"}'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, '{"nao'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, '[{"_name":"bob"},{"_name":"jill"}]'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, 'text only'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, ''
        )
        self.assertEquals(400, code, msg=str(response))

        # valid keys, wrong types
        content = ('{"membership":["%s","%s","%s"]}' % (
            Membership.INVITE, Membership.JOIN, Membership.LEAVE
        ))
        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(400, code, msg=str(response))

    @defer.inlineCallbacks
    def test_rooms_members_self(self):
        path = "/rooms/%s/state/m.room.member/%s" % (
            urllib.quote(self.room_id), self.user_id
        )

        # valid join message (NOOP since we made the room)
        content = '{"membership":"%s"}' % Membership.JOIN
        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))

        expected_response = {
            "membership": Membership.JOIN,
        }
        self.assertEquals(expected_response, response)

    @defer.inlineCallbacks
    def test_rooms_members_other(self):
        self.other_id = "@zzsid1:red"
        path = "/rooms/%s/state/m.room.member/%s" % (
            urllib.quote(self.room_id), self.other_id
        )

        # valid invite message
        content = '{"membership":"%s"}' % Membership.INVITE
        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))
        self.assertEquals(json.loads(content), response)

    @defer.inlineCallbacks
    def test_rooms_members_other_custom_keys(self):
        self.other_id = "@zzsid1:red"
        path = "/rooms/%s/state/m.room.member/%s" % (
            urllib.quote(self.room_id), self.other_id
        )

        # valid invite message with custom key
        content = ('{"membership":"%s","invite_text":"%s"}' % (
            Membership.INVITE, "Join us!"
        ))
        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))
        self.assertEquals(json.loads(content), response)


class RoomMessagesTestCase(RestTestCase):
    """ Tests /rooms/$room_id/messages/$user_id/$msg_id REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        self.room_id = yield self.create_room_as(self.user_id)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_invalid_puts(self):
        path = "/rooms/%s/send/m.room.message/mid1" % (
            urllib.quote(self.room_id))
        # missing keys or invalid json
        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, '{}'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, '{"_name":"bob"}'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, '{"nao'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, '[{"_name":"bob"},{"_name":"jill"}]'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, 'text only'
        )
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, ''
        )
        self.assertEquals(400, code, msg=str(response))

    @defer.inlineCallbacks
    def test_rooms_messages_sent(self):
        path = "/rooms/%s/send/m.room.message/mid1" % (
            urllib.quote(self.room_id))

        content = '{"body":"test","msgtype":{"type":"a"}}'
        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(400, code, msg=str(response))

        # custom message types
        content = '{"body":"test","msgtype":"test.custom.text"}'
        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

#        (code, response) = yield self.mock_resource.trigger("GET", path, None)
#        self.assertEquals(200, code, msg=str(response))
#        self.assert_dict(json.loads(content), response)

        # m.text message type
        path = "/rooms/%s/send/m.room.message/mid2" % (
            urllib.quote(self.room_id))
        content = '{"body":"test2","msgtype":"m.text"}'
        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))


class RoomInitialSyncTestCase(RestTestCase):
    """ Tests /rooms/$room_id/initialSync. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        # create the room
        self.room_id = yield self.create_room_as(self.user_id)

    @defer.inlineCallbacks
    def test_initial_sync(self):
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/%s/initialSync" % self.room_id
        )
        self.assertEquals(200, code)

        self.assertEquals(self.room_id, response["room_id"])
        self.assertEquals("join", response["membership"])

        # Room state is easier to assert on if we unpack it into a dict
        state = {}
        for event in response["state"]:
            if "state_key" not in event:
                continue
            t = event["type"]
            if t not in state:
                state[t] = []
            state[t].append(event)

        self.assertTrue("m.room.create" in state)

        self.assertTrue("messages" in response)
        self.assertTrue("chunk" in response["messages"])
        self.assertTrue("end" in response["messages"])

        self.assertTrue("presence" in response)

        presence_by_user = {
            e["content"]["user_id"]: e for e in response["presence"]
        }
        self.assertTrue(self.user_id in presence_by_user)
        self.assertEquals("m.presence", presence_by_user[self.user_id]["type"])


class RoomMessageListTestCase(RestTestCase):
    """ Tests /rooms/$room_id/messages REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        hs = yield setup_test_homeserver(
            "red",
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)

        hs.get_handlers().federation_handler = Mock()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.auth_user_id),
                "token_id": 1,
                "is_guest": False,
            }
        hs.get_v1auth().get_user_by_access_token = get_user_by_access_token

        def _insert_client_ip(*args, **kwargs):
            return defer.succeed(None)
        hs.get_datastore().insert_client_ip = _insert_client_ip

        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        self.room_id = yield self.create_room_as(self.user_id)

    @defer.inlineCallbacks
    def test_topo_token_is_accepted(self):
        token = "t1-0_0_0_0_0_0_0_0"
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/%s/messages?access_token=x&from=%s" %
            (self.room_id, token))
        self.assertEquals(200, code)
        self.assertTrue("start" in response)
        self.assertEquals(token, response['start'])
        self.assertTrue("chunk" in response)
        self.assertTrue("end" in response)

    @defer.inlineCallbacks
    def test_stream_token_is_accepted_for_fwd_pagianation(self):
        token = "s0_0_0_0_0_0_0_0"
        (code, response) = yield self.mock_resource.trigger_get(
            "/rooms/%s/messages?access_token=x&from=%s" %
            (self.room_id, token))
        self.assertEquals(200, code)
        self.assertTrue("start" in response)
        self.assertEquals(token, response['start'])
        self.assertTrue("chunk" in response)
        self.assertTrue("end" in response)
