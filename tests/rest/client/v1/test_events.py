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

""" Tests REST events for /events paths."""

from mock import Mock, NonCallableMock
from six import PY3

from twisted.internet import defer

from ....utils import MockHttpResource, setup_test_homeserver
from .utils import RestTestCase

PATH_PREFIX = "/_matrix/client/api/v1"


class EventStreamPermissionsTestCase(RestTestCase):
    """ Tests event streaming (GET /events). """

    if PY3:
        skip = "Skip on Py3 until ported to use not V1 only register."

    @defer.inlineCallbacks
    def setUp(self):
        import synapse.rest.client.v1.events
        import synapse.rest.client.v1_only.register
        import synapse.rest.client.v1.room

        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = yield setup_test_homeserver(
            self.addCleanup,
            http_client=None,
            federation_client=Mock(),
            ratelimiter=NonCallableMock(spec_set=["send_message"]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)
        hs.config.enable_registration_captcha = False
        hs.config.enable_registration = True
        hs.config.auto_join_rooms = []

        hs.get_handlers().federation_handler = Mock()

        synapse.rest.client.v1_only.register.register_servlets(hs, self.mock_resource)
        synapse.rest.client.v1.events.register_servlets(hs, self.mock_resource)
        synapse.rest.client.v1.room.register_servlets(hs, self.mock_resource)

        # register an account
        self.user_id = "sid1"
        response = yield self.register(self.user_id)
        self.token = response["access_token"]
        self.user_id = response["user_id"]

        # register a 2nd account
        self.other_user = "other1"
        response = yield self.register(self.other_user)
        self.other_token = response["access_token"]
        self.other_user = response["user_id"]

    def tearDown(self):
        pass

    @defer.inlineCallbacks
    def test_stream_basic_permissions(self):
        # invalid token, expect 401
        # note: this is in violation of the original v1 spec, which expected
        # 403. However, since the v1 spec no longer exists and the v1
        # implementation is now part of the r0 implementation, the newer
        # behaviour is used instead to be consistent with the r0 spec.
        # see issue #2602
        (code, response) = yield self.mock_resource.trigger_get(
            "/events?access_token=%s" % ("invalid" + self.token,)
        )
        self.assertEquals(401, code, msg=str(response))

        # valid token, expect content
        (code, response) = yield self.mock_resource.trigger_get(
            "/events?access_token=%s&timeout=0" % (self.token,)
        )
        self.assertEquals(200, code, msg=str(response))
        self.assertTrue("chunk" in response)
        self.assertTrue("start" in response)
        self.assertTrue("end" in response)

    @defer.inlineCallbacks
    def test_stream_room_permissions(self):
        room_id = yield self.create_room_as(self.other_user, tok=self.other_token)
        yield self.send(room_id, tok=self.other_token)

        # invited to room (expect no content for room)
        yield self.invite(
            room_id, src=self.other_user, targ=self.user_id, tok=self.other_token
        )

        (code, response) = yield self.mock_resource.trigger_get(
            "/events?access_token=%s&timeout=0" % (self.token,)
        )
        self.assertEquals(200, code, msg=str(response))

        # We may get a presence event for ourselves down
        self.assertEquals(
            0,
            len(
                [
                    c
                    for c in response["chunk"]
                    if not (
                        c.get("type") == "m.presence"
                        and c["content"].get("user_id") == self.user_id
                    )
                ]
            ),
        )

        # joined room (expect all content for room)
        yield self.join(room=room_id, user=self.user_id, tok=self.token)

        # left to room (expect no content for room)

    def TODO_test_stream_items(self):
        # new user, no content

        # join room, expect 1 item (join)

        # send message, expect 2 items (join,send)

        # set topic, expect 3 items (join,send,topic)

        # someone else join room, expect 4 (join,send,topic,join)

        # someone else send message, expect 5 (join,send.topic,join,send)

        # someone else set topic, expect 6 (join,send,topic,join,send,topic)
        pass
