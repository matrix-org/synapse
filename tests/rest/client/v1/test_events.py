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
from tests import unittest

# twisted imports
from twisted.internet import defer

import synapse.rest.client.v1.events
import synapse.rest.client.v1.register
import synapse.rest.client.v1.room


from ....utils import MockHttpResource, setup_test_homeserver
from .utils import RestTestCase

from mock import Mock, NonCallableMock


PATH_PREFIX = "/_matrix/client/api/v1"


class EventStreamPaginationApiTestCase(unittest.TestCase):
    """ Tests event streaming query parameters and start/end keys used in the
    Pagination stream API. """
    user_id = "sid1"

    def setUp(self):
        # configure stream and inject items
        pass

    def tearDown(self):
        pass

    def TODO_test_long_poll(self):
        # stream from 'end' key, send (self+other) message, expect message.

        # stream from 'END', send (self+other) message, expect message.

        # stream from 'end' key, send (self+other) topic, expect topic.

        # stream from 'END', send (self+other) topic, expect topic.

        # stream from 'end' key, send (self+other) invite, expect invite.

        # stream from 'END', send (self+other) invite, expect invite.

        pass

    def TODO_test_stream_forward(self):
        # stream from START, expect injected items

        # stream from 'start' key, expect same content

        # stream from 'end' key, expect nothing

        # stream from 'END', expect nothing

        # The following is needed for cases where content is removed e.g. you
        # left a room, so the token you're streaming from is > the one that
        # would be returned naturally from START>END.
        # stream from very new token (higher than end key), expect same token
        # returned as end key
        pass

    def TODO_test_limits(self):
        # stream from a key, expect limit_num items

        # stream from START, expect limit_num items

        pass

    def TODO_test_range(self):
        # stream from key to key, expect X items

        # stream from key to END, expect X items

        # stream from START to key, expect X items

        # stream from START to END, expect all items
        pass

    def TODO_test_direction(self):
        # stream from END to START and fwds, expect newest first

        # stream from END to START and bwds, expect oldest first

        # stream from START to END and fwds, expect oldest first

        # stream from START to END and bwds, expect newest first

        pass


class EventStreamPermissionsTestCase(RestTestCase):
    """ Tests event streaming (GET /events). """

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        hs = yield setup_test_homeserver(
            http_client=None,
            replication_layer=Mock(),
            ratelimiter=NonCallableMock(spec_set=[
                "send_message",
            ]),
        )
        self.ratelimiter = hs.get_ratelimiter()
        self.ratelimiter.send_message.return_value = (True, 0)
        hs.config.enable_registration_captcha = False
        hs.config.enable_registration = True

        hs.get_handlers().federation_handler = Mock()

        synapse.rest.client.v1.register.register_servlets(hs, self.mock_resource)
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
        # invalid token, expect 403
        (code, response) = yield self.mock_resource.trigger_get(
            "/events?access_token=%s" % ("invalid" + self.token, )
        )
        self.assertEquals(403, code, msg=str(response))

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
        room_id = yield self.create_room_as(
            self.other_user,
            tok=self.other_token
        )
        yield self.send(room_id, tok=self.other_token)

        # invited to room (expect no content for room)
        yield self.invite(
            room_id,
            src=self.other_user,
            targ=self.user_id,
            tok=self.other_token
        )

        (code, response) = yield self.mock_resource.trigger_get(
            "/events?access_token=%s&timeout=0" % (self.token,)
        )
        self.assertEquals(200, code, msg=str(response))

        # We may get a presence event for ourselves down
        self.assertEquals(
            0,
            len([
                c for c in response["chunk"]
                if not (
                    c.get("type") == "m.presence"
                    and c["content"].get("user_id") == self.user_id
                )
            ])
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
