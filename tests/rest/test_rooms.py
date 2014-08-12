# -*- coding: utf-8 -*-
"""Tests REST events for /rooms paths."""

# twisted imports
from twisted.internet import defer

import synapse.rest.room
from synapse.api.constants import Membership

from synapse.server import HomeServer

# python imports
import json
import urllib

from ..utils import MockHttpServer, MemoryDataStore
from .utils import RestTestCase

from mock import Mock

PATH_PREFIX = "/matrix/client/api/v1"


class RoomPermissionsTestCase(RestTestCase):
    """ Tests room permissions. """
    user_id = "@sid1:red"
    rmcreator_id = "@notme:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)

        state_handler = Mock(spec=["handle_new_event"])
        state_handler.handle_new_event.return_value = True

        persistence_service = Mock(spec=["get_latest_pdus_in_context"])
        persistence_service.get_latest_pdus_in_context.return_value = []

        hs = HomeServer(
            "test",
            db_pool=None,
            http_client=None,
            federation=Mock(),
            datastore=MemoryDataStore(),
            replication_layer=Mock(),
            state_handler=state_handler,
            persistence_service=persistence_service,
        )

        def _get_user_by_token(token=None):
            return hs.parse_userid(self.auth_user_id)
        hs.get_auth().get_user_by_token = _get_user_by_token

        self.auth_user_id = self.rmcreator_id

        synapse.rest.room.register_servlets(hs, self.mock_server)

        self.auth = hs.get_auth()

        # create some rooms under the name rmcreator_id
        self.uncreated_rmid = "!aa:test"

        self.created_rmid = "!abc:test"
        yield self.create_room_as(self.created_rmid, self.rmcreator_id,
                                  is_public=False)

        self.created_public_rmid = "!def1234ghi:test"
        yield self.create_room_as(self.created_public_rmid, self.rmcreator_id,
                                  is_public=True)

        # send a message in one of the rooms
        self.created_rmid_msg_path = ("/rooms/%s/messages/%s/midaaa1" %
                                (self.created_rmid, self.rmcreator_id))
        (code, response) = yield self.mock_server.trigger(
                           "PUT",
                           self.created_rmid_msg_path,
                           '{"msgtype":"m.text","body":"test msg"}')
        self.assertEquals(200, code, msg=str(response))

        # set topic for public room
        (code, response) = yield self.mock_server.trigger(
                           "PUT",
                           "/rooms/%s/topic" % self.created_public_rmid,
                           '{"topic":"Public Room Topic"}')
        self.assertEquals(200, code, msg=str(response))

        # auth as user_id now
        self.auth_user_id = self.user_id

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_get_message(self):
        # get message in uncreated room, expect 403
        (code, response) = yield self.mock_server.trigger_get(
                           "/rooms/noroom/messages/someid/m1")
        self.assertEquals(403, code, msg=str(response))

        # get message in created room not joined (no state), expect 403
        (code, response) = yield self.mock_server.trigger_get(
                           self.created_rmid_msg_path)
        self.assertEquals(403, code, msg=str(response))

        # get message in created room and invited, expect 403
        yield self.invite(room=self.created_rmid, src=self.rmcreator_id,
                          targ=self.user_id)
        (code, response) = yield self.mock_server.trigger_get(
                           self.created_rmid_msg_path)
        self.assertEquals(403, code, msg=str(response))

        # get message in created room and joined, expect 200
        yield self.join(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_server.trigger_get(
                           self.created_rmid_msg_path)
        self.assertEquals(200, code, msg=str(response))

        # get message in created room and left, expect 403
        yield self.leave(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_server.trigger_get(
                           self.created_rmid_msg_path)
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def test_send_message(self):
        msg_content = '{"msgtype":"m.text","body":"hello"}'
        send_msg_path = ("/rooms/%s/messages/%s/mid1" %
                        (self.created_rmid, self.user_id))

        # send message in uncreated room, expect 403
        (code, response) = yield self.mock_server.trigger(
                           "PUT",
                           "/rooms/%s/messages/%s/mid1" %
                           (self.uncreated_rmid, self.user_id), msg_content)
        self.assertEquals(403, code, msg=str(response))

        # send message in created room not joined (no state), expect 403
        (code, response) = yield self.mock_server.trigger(
                           "PUT", send_msg_path, msg_content)
        self.assertEquals(403, code, msg=str(response))

        # send message in created room and invited, expect 403
        yield self.invite(room=self.created_rmid, src=self.rmcreator_id,
                          targ=self.user_id)
        (code, response) = yield self.mock_server.trigger(
                           "PUT", send_msg_path, msg_content)
        self.assertEquals(403, code, msg=str(response))

        # send message in created room and joined, expect 200
        yield self.join(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_server.trigger(
                           "PUT", send_msg_path, msg_content)
        self.assertEquals(200, code, msg=str(response))

        # send message in created room and left, expect 403
        yield self.leave(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_server.trigger(
                           "PUT", send_msg_path, msg_content)
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def test_topic_perms(self):
        topic_content = '{"topic":"My Topic Name"}'
        topic_path = "/rooms/%s/topic" % self.created_rmid

        # set/get topic in uncreated room, expect 403
        (code, response) = yield self.mock_server.trigger(
                           "PUT", "/rooms/%s/topic" % self.uncreated_rmid,
                           topic_content)
        self.assertEquals(403, code, msg=str(response))
        (code, response) = yield self.mock_server.trigger_get(
                           "/rooms/%s/topic" % self.uncreated_rmid)
        self.assertEquals(403, code, msg=str(response))

        # set/get topic in created PRIVATE room not joined, expect 403
        (code, response) = yield self.mock_server.trigger(
                           "PUT", topic_path, topic_content)
        self.assertEquals(403, code, msg=str(response))
        (code, response) = yield self.mock_server.trigger_get(topic_path)
        self.assertEquals(403, code, msg=str(response))

        # set topic in created PRIVATE room and invited, expect 403
        yield self.invite(room=self.created_rmid, src=self.rmcreator_id,
                          targ=self.user_id)
        (code, response) = yield self.mock_server.trigger(
                           "PUT", topic_path, topic_content)
        self.assertEquals(403, code, msg=str(response))

        # get topic in created PRIVATE room and invited, expect 200 (or 404)
        (code, response) = yield self.mock_server.trigger_get(topic_path)
        self.assertEquals(404, code, msg=str(response))

        # set/get topic in created PRIVATE room and joined, expect 200
        yield self.join(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_server.trigger(
                           "PUT", topic_path, topic_content)
        self.assertEquals(200, code, msg=str(response))
        (code, response) = yield self.mock_server.trigger_get(topic_path)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(topic_content), response)

        # set/get topic in created PRIVATE room and left, expect 403
        yield self.leave(room=self.created_rmid, user=self.user_id)
        (code, response) = yield self.mock_server.trigger(
                           "PUT", topic_path, topic_content)
        self.assertEquals(403, code, msg=str(response))
        (code, response) = yield self.mock_server.trigger_get(topic_path)
        self.assertEquals(403, code, msg=str(response))

        # get topic in PUBLIC room, not joined, expect 200 (or 404)
        (code, response) = yield self.mock_server.trigger_get(
                           "/rooms/%s/topic" % self.created_public_rmid)
        self.assertEquals(200, code, msg=str(response))

        # set topic in PUBLIC room, not joined, expect 403
        (code, response) = yield self.mock_server.trigger(
                           "PUT",
                           "/rooms/%s/topic" % self.created_public_rmid,
                           topic_content)
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def _test_get_membership(self, room=None, members=[], expect_code=None):
        path = "/rooms/%s/members/%s/state"
        for member in members:
            (code, response) = yield self.mock_server.trigger_get(
                               path %
                               (room, member))
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
        # expect all 403s
        for usr in [self.user_id, self.rmcreator_id]:
            yield self.join(room=room, user=usr, expect_code=403)
            yield self.leave(room=room, user=usr, expect_code=403)

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
        # expect all 403s
        yield self.leave(room=room, user=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=403)

    @defer.inlineCallbacks
    def test_membership_public_room_perms(self):
        room = self.created_public_rmid
        # get membership of self, get membership of other, public room + invite
        # expect all 403s
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
        # expect all 403s
        yield self.leave(room=room, user=self.user_id)
        yield self._test_get_membership(
            members=[self.user_id, self.rmcreator_id],
            room=room, expect_code=403)

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
            yield self.change_membership(room=room, src=self.user_id,
                                     targ=usr,
                                     membership=Membership.INVITE,
                                     expect_code=403)
            yield self.change_membership(room=room, src=self.user_id,
                                     targ=usr,
                                     membership=Membership.JOIN,
                                     expect_code=403)
            yield self.change_membership(room=room, src=self.user_id,
                                     targ=usr,
                                     membership=Membership.LEAVE,
                                     expect_code=403)


class RoomsMemberListTestCase(RestTestCase):
    """ Tests /rooms/$room_id/members/list REST events."""
    user_id = "@sid1:red"

    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)

        state_handler = Mock(spec=["handle_new_event"])
        state_handler.handle_new_event.return_value = True

        persistence_service = Mock(spec=["get_latest_pdus_in_context"])
        persistence_service.get_latest_pdus_in_context.return_value = []

        hs = HomeServer(
            "test",
            db_pool=None,
            http_client=None,
            federation=Mock(),
            datastore=MemoryDataStore(),
            replication_layer=Mock(),
            state_handler=state_handler,
            persistence_service=persistence_service,
        )

        self.auth_user_id = self.user_id

        def _get_user_by_token(token=None):
            return hs.parse_userid(self.auth_user_id)
        hs.get_auth().get_user_by_token = _get_user_by_token

        synapse.rest.room.register_servlets(hs, self.mock_server)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_get_member_list(self):
        room_id = "!aa:test"
        yield self.create_room_as(room_id, self.user_id)
        (code, response) = yield self.mock_server.trigger_get(
                           "/rooms/%s/members/list" % room_id)
        self.assertEquals(200, code, msg=str(response))

    @defer.inlineCallbacks
    def test_get_member_list_no_room(self):
        (code, response) = yield self.mock_server.trigger_get(
                           "/rooms/roomdoesnotexist/members/list")
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def test_get_member_list_no_permission(self):
        room_id = "!bb:test"
        yield self.create_room_as(room_id, "@some_other_guy:red")
        (code, response) = yield self.mock_server.trigger_get(
                           "/rooms/%s/members/list" % room_id)
        self.assertEquals(403, code, msg=str(response))

    @defer.inlineCallbacks
    def test_get_member_list_mixed_memberships(self):
        room_id = "!bb:test"
        room_creator = "@some_other_guy:blue"
        room_path = "/rooms/%s/members/list" % room_id
        yield self.create_room_as(room_id, room_creator)
        yield self.invite(room=room_id, src=room_creator,
                          targ=self.user_id)
        # can't see list if you're just invited.
        (code, response) = yield self.mock_server.trigger_get(room_path)
        self.assertEquals(403, code, msg=str(response))

        yield self.join(room=room_id, user=self.user_id)
        # can see list now joined
        (code, response) = yield self.mock_server.trigger_get(room_path)
        self.assertEquals(200, code, msg=str(response))

        yield self.leave(room=room_id, user=self.user_id)
        # can no longer see list, you've left.
        (code, response) = yield self.mock_server.trigger_get(room_path)
        self.assertEquals(403, code, msg=str(response))


class RoomsCreateTestCase(RestTestCase):
    """ Tests /rooms and /rooms/$room_id REST events. """
    user_id = "@sid1:red"

    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id

        state_handler = Mock(spec=["handle_new_event"])
        state_handler.handle_new_event.return_value = True

        persistence_service = Mock(spec=["get_latest_pdus_in_context"])
        persistence_service.get_latest_pdus_in_context.return_value = []

        hs = HomeServer(
            "test",
            db_pool=None,
            http_client=None,
            federation=Mock(),
            datastore=MemoryDataStore(),
            replication_layer=Mock(),
            state_handler=state_handler,
            persistence_service=persistence_service,
        )

        def _get_user_by_token(token=None):
            return hs.parse_userid(self.auth_user_id)
        hs.get_auth().get_user_by_token = _get_user_by_token

        synapse.rest.room.register_servlets(hs, self.mock_server)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_post_room_no_keys(self):
        # POST with no config keys, expect new room id
        (code, response) = yield self.mock_server.trigger("POST", "/rooms",
                                                          "{}")
        self.assertEquals(200, code, response)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_visibility_key(self):
        # POST with visibility config key, expect new room id
        (code, response) = yield self.mock_server.trigger("POST", "/rooms",
                                                '{"visibility":"private"}')
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_custom_key(self):
        # POST with custom config keys, expect new room id
        (code, response) = yield self.mock_server.trigger("POST", "/rooms",
                                                '{"custom":"stuff"}')
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_known_and_unknown_keys(self):
        # POST with custom + known config keys, expect new room id
        (code, response) = yield self.mock_server.trigger("POST", "/rooms",
                                 '{"visibility":"private","custom":"things"}')
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_post_room_invalid_content(self):
        # POST with invalid content / paths, expect 400
        (code, response) = yield self.mock_server.trigger("POST", "/rooms",
                                                          '{"visibili')
        self.assertEquals(400, code)

        (code, response) = yield self.mock_server.trigger("POST", "/rooms",
                                                          '["hello"]')
        self.assertEquals(400, code)

    @defer.inlineCallbacks
    def test_put_room_no_keys(self):
        # PUT with no config keys, expect new room id
        (code, response) = yield self.mock_server.trigger(
            "PUT", "/rooms/%21aa%3Atest", "{}"
        )
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_put_room_visibility_key(self):
        # PUT with known config keys, expect new room id
        (code, response) = yield self.mock_server.trigger(
            "PUT", "/rooms/%21bb%3Atest", '{"visibility":"private"}'
        )
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_put_room_custom_key(self):
        # PUT with custom config keys, expect new room id
        (code, response) = yield self.mock_server.trigger(
            "PUT", "/rooms/%21cc%3Atest", '{"custom":"stuff"}'
        )
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_put_room_known_and_unknown_keys(self):
        # PUT with custom + known config keys, expect new room id
        (code, response) = yield self.mock_server.trigger(
            "PUT", "/rooms/%21dd%3Atest",
            '{"visibility":"private","custom":"things"}'
        )
        self.assertEquals(200, code)
        self.assertTrue("room_id" in response)

    @defer.inlineCallbacks
    def test_put_room_invalid_content(self):
        # PUT with invalid content / room names, expect 400

        (code, response) = yield self.mock_server.trigger(
            "PUT", "/rooms/ee", '{"sdf"'
        )
        self.assertEquals(400, code)

        (code, response) = yield self.mock_server.trigger(
            "PUT", "/rooms/ee", '["hello"]'
        )
        self.assertEquals(400, code)

    @defer.inlineCallbacks
    def test_put_room_conflict(self):
        yield self.create_room_as("!aa:test", self.user_id)

        # PUT with conflicting room ID, expect 409
        (code, response) = yield self.mock_server.trigger(
            "PUT", "/rooms/%21aa%3Atest", "{}"
        )
        self.assertEquals(409, code)


class RoomTopicTestCase(RestTestCase):
    """ Tests /rooms/$room_id/topic REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id
        self.room_id = "!rid1:test"
        self.path = "/rooms/%s/topic" % self.room_id

        state_handler = Mock(spec=["handle_new_event"])
        state_handler.handle_new_event.return_value = True

        persistence_service = Mock(spec=["get_latest_pdus_in_context"])
        persistence_service.get_latest_pdus_in_context.return_value = []

        hs = HomeServer(
            "test",
            db_pool=None,
            http_client=None,
            federation=Mock(),
            datastore=MemoryDataStore(),
            replication_layer=Mock(),
            state_handler=state_handler,
            persistence_service=persistence_service,
        )

        def _get_user_by_token(token=None):
            return hs.parse_userid(self.auth_user_id)
        hs.get_auth().get_user_by_token = _get_user_by_token

        synapse.rest.room.register_servlets(hs, self.mock_server)

        # create the room
        yield self.create_room_as(self.room_id, self.user_id)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_invalid_puts(self):
        # missing keys or invalid json
        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, '{}')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, '{"_name":"bob"}')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, '{"nao')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, '[{"_name":"bob"},{"_name":"jill"}]')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, 'text only')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, '')
        self.assertEquals(400, code, msg=str(response))

        # valid key, wrong type
        content = '{"topic":["Topic name"]}'
        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, content)
        self.assertEquals(400, code, msg=str(response))

    @defer.inlineCallbacks
    def test_rooms_topic(self):
        # nothing should be there
        (code, response) = yield self.mock_server.trigger_get(self.path)
        self.assertEquals(404, code, msg=str(response))

        # valid put
        content = '{"topic":"Topic name"}'
        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, content)
        self.assertEquals(200, code, msg=str(response))

        # valid get
        (code, response) = yield self.mock_server.trigger_get(self.path)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(content), response)

    @defer.inlineCallbacks
    def test_rooms_topic_with_extra_keys(self):
        # valid put with extra keys
        content = '{"topic":"Seasons","subtopic":"Summer"}'
        (code, response) = yield self.mock_server.trigger("PUT",
                           self.path, content)
        self.assertEquals(200, code, msg=str(response))

        # valid get
        (code, response) = yield self.mock_server.trigger_get(self.path)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(content), response)


class RoomMemberStateTestCase(RestTestCase):
    """ Tests /rooms/$room_id/members/$user_id/state REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id
        self.room_id = "!rid1:test"

        state_handler = Mock(spec=["handle_new_event"])
        state_handler.handle_new_event.return_value = True

        persistence_service = Mock(spec=["get_latest_pdus_in_context"])
        persistence_service.get_latest_pdus_in_context.return_value = []

        hs = HomeServer(
            "test",
            db_pool=None,
            http_client=None,
            federation=Mock(),
            datastore=MemoryDataStore(),
            replication_layer=Mock(),
            state_handler=state_handler,
            persistence_service=persistence_service,
        )

        def _get_user_by_token(token=None):
            return hs.parse_userid(self.auth_user_id)
        hs.get_auth().get_user_by_token = _get_user_by_token

        synapse.rest.room.register_servlets(hs, self.mock_server)

        yield self.create_room_as(self.room_id, self.user_id)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_invalid_puts(self):
        path = "/rooms/%s/members/%s/state" % (self.room_id, self.user_id)
        # missing keys or invalid json
        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '{}')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '{"_name":"bob"}')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '{"nao')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '[{"_name":"bob"},{"_name":"jill"}]')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, 'text only')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '')
        self.assertEquals(400, code, msg=str(response))

        # valid keys, wrong types
        content = ('{"membership":["%s","%s","%s"]}' %
                  (Membership.INVITE, Membership.JOIN, Membership.LEAVE))
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(400, code, msg=str(response))

    @defer.inlineCallbacks
    def test_rooms_members_self(self):
        path = "/rooms/%s/members/%s/state" % (
            urllib.quote(self.room_id), self.user_id
        )

        # valid join message (NOOP since we made the room)
        content = '{"membership":"%s"}' % Membership.JOIN
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))
        self.assertEquals(json.loads(content), response)

    @defer.inlineCallbacks
    def test_rooms_members_other(self):
        self.other_id = "@zzsid1:red"
        path = "/rooms/%s/members/%s/state" % (
            urllib.quote(self.room_id), self.other_id
        )

        # valid invite message
        content = '{"membership":"%s"}' % Membership.INVITE
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))
        self.assertEquals(json.loads(content), response)

    @defer.inlineCallbacks
    def test_rooms_members_other_custom_keys(self):
        self.other_id = "@zzsid1:red"
        path = "/rooms/%s/members/%s/state" % (
            urllib.quote(self.room_id), self.other_id
        )

        # valid invite message with custom key
        content = ('{"membership":"%s","invite_text":"%s"}' %
                    (Membership.INVITE, "Join us!"))
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))
        self.assertEquals(json.loads(content), response)


class RoomMessagesTestCase(RestTestCase):
    """ Tests /rooms/$room_id/messages/$user_id/$msg_id REST events. """
    user_id = "@sid1:red"

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_server = MockHttpServer(prefix=PATH_PREFIX)
        self.auth_user_id = self.user_id
        self.room_id = "!rid1:test"

        state_handler = Mock(spec=["handle_new_event"])
        state_handler.handle_new_event.return_value = True

        persistence_service = Mock(spec=["get_latest_pdus_in_context"])
        persistence_service.get_latest_pdus_in_context.return_value = []

        hs = HomeServer(
            "test",
            db_pool=None,
            http_client=None,
            federation=Mock(),
            datastore=MemoryDataStore(),
            replication_layer=Mock(),
            state_handler=state_handler,
            persistence_service=persistence_service,
        )

        def _get_user_by_token(token=None):
            return hs.parse_userid(self.auth_user_id)
        hs.get_auth().get_user_by_token = _get_user_by_token

        synapse.rest.room.register_servlets(hs, self.mock_server)

        yield self.create_room_as(self.room_id, self.user_id)

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_invalid_puts(self):
        path = "/rooms/%s/messages/%s/mid1" % (
            urllib.quote(self.room_id), self.user_id
        )
        # missing keys or invalid json
        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '{}')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '{"_name":"bob"}')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '{"nao')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '[{"_name":"bob"},{"_name":"jill"}]')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, 'text only')
        self.assertEquals(400, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("PUT",
                           path, '')
        self.assertEquals(400, code, msg=str(response))

    @defer.inlineCallbacks
    def test_rooms_messages_sent(self):
        path = "/rooms/%s/messages/%s/mid1" % (
            urllib.quote(self.room_id), self.user_id
        )

        content = '{"body":"test","msgtype":{"type":"a"}}'
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(400, code, msg=str(response))

        # custom message types
        content = '{"body":"test","msgtype":"test.custom.text"}'
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(content), response)

        # m.text message type
        path = "/rooms/%s/messages/%s/mid2" % (
            urllib.quote(self.room_id), self.user_id
        )
        content = '{"body":"test2","msgtype":"m.text"}'
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(200, code, msg=str(response))

        (code, response) = yield self.mock_server.trigger("GET", path, None)
        self.assertEquals(200, code, msg=str(response))
        self.assert_dict(json.loads(content), response)

        # trying to send message in different user path
        path = "/rooms/%s/messages/%s/mid2" % (
            urllib.quote(self.room_id), "invalid" + self.user_id
        )
        content = '{"body":"test2","msgtype":"m.text"}'
        (code, response) = yield self.mock_server.trigger("PUT", path, content)
        self.assertEquals(403, code, msg=str(response))
