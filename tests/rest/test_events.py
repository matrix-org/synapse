# -*- coding: utf-8 -*-
""" Tests REST events for /events paths."""
from twisted.trial import unittest

# twisted imports
from twisted.internet import defer

import synapse.rest.events
import synapse.rest.register
import synapse.rest.room

from synapse.server import HomeServer

# python imports
import json
import logging

from ..utils import MockHttpServer, MemoryDataStore
from .utils import RestTestCase

from mock import Mock

logging.getLogger().addHandler(logging.NullHandler())

PATH_PREFIX = "/matrix/client/api/v1"


class EventStreamPaginationApiTestCase(unittest.TestCase):
    """ Tests event streaming query parameters and start/end keys used in the
    Pagination stream API. """
    user_id = "sid1"

    def setUp(self):
        # configure stream and inject items
        pass

    def tearDown(self):
        pass

    def test_long_poll(self):
        # stream from 'end' key, send (self+other) message, expect message.

        # stream from 'END', send (self+other) message, expect message.

        # stream from 'end' key, send (self+other) topic, expect topic.

        # stream from 'END', send (self+other) topic, expect topic.

        # stream from 'end' key, send (self+other) invite, expect invite.

        # stream from 'END', send (self+other) invite, expect invite.

        pass

    def test_stream_forward(self):
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

    def test_limits(self):
        # stream from a key, expect limit_num items

        # stream from START, expect limit_num items

        pass

    def test_range(self):
        # stream from key to key, expect X items

        # stream from key to END, expect X items

        # stream from START to key, expect X items

        # stream from START to END, expect all items
        pass

    def test_direction(self):
        # stream from END to START and fwds, expect newest first

        # stream from END to START and bwds, expect oldest first

        # stream from START to END and fwds, expect oldest first

        # stream from START to END and bwds, expect newest first

        pass


class EventStreamPermissionsTestCase(RestTestCase):
    """ Tests event streaming (GET /events). """

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
            replication_layer=Mock(),
            state_handler=state_handler,
            persistence_service=persistence_service,
            clock=Mock(spec=[
                "call_later",
                "cancel_call_later",
                "time_msec",
            ]),
        )

        hs.get_clock().time_msec.return_value = 1000000

        hs.datastore = MemoryDataStore()
        synapse.rest.register.register_servlets(hs, self.mock_server)
        synapse.rest.events.register_servlets(hs, self.mock_server)
        synapse.rest.room.register_servlets(hs, self.mock_server)

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
        (code, response) = yield self.mock_server.trigger_get(
                           "/events?access_token=%s" % ("invalid" + self.token))
        self.assertEquals(403, code, msg=str(response))

        # valid token, expect content
        (code, response) = yield self.mock_server.trigger_get(
                           "/events?access_token=%s&timeout=0" % (self.token))
        self.assertEquals(200, code, msg=str(response))
        self.assertTrue("chunk" in response)
        self.assertTrue("start" in response)
        self.assertTrue("end" in response)

    @defer.inlineCallbacks
    def test_stream_room_permissions(self):
        room_id = "!rid1:test"
        yield self.create_room_as(room_id, self.other_user,
                                  tok=self.other_token)
        yield self.send(room_id, self.other_user, tok=self.other_token)

        # invited to room (expect no content for room)
        yield self.invite(room_id, src=self.other_user, targ=self.user_id,
                          tok=self.other_token)
        (code, response) = yield self.mock_server.trigger_get(
                           "/events?access_token=%s&timeout=0" % (self.token))
        self.assertEquals(200, code, msg=str(response))

        # First message is a reflection of my own presence status change
        self.assertEquals(1, len(response["chunk"]))
        self.assertEquals("m.presence", response["chunk"][0]["type"])

        # joined room (expect all content for room)
        yield self.join(room=room_id, user=self.user_id, tok=self.token)

        # left to room (expect no content for room)

    def test_stream_items(self):
        # new user, no content

        # join room, expect 1 item (join)

        # send message, expect 2 items (join,send)

        # set topic, expect 3 items (join,send,topic)

        # someone else join room, expect 4 (join,send,topic,join)

        # someone else send message, expect 5 (join,send.topic,join,send)

        # someone else set topic, expect 6 (join,send,topic,join,send,topic)
        pass
