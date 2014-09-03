# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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


from twisted.trial import unittest
from twisted.internet import defer

from mock import Mock
import logging

from synapse.api.errors import AuthError
from synapse.server import HomeServer
from synapse.handlers.profile import ProfileHandler


logging.getLogger().addHandler(logging.NullHandler())


class ProfileHandlers(object):
    def __init__(self, hs):
        self.profile_handler = ProfileHandler(hs)


class ProfileTestCase(unittest.TestCase):
    """ Tests profile management. """

    def setUp(self):
        self.mock_federation = Mock(spec=[
            "make_query",
        ])

        self.query_handlers = {}
        def register_query_handler(query_type, handler):
            self.query_handlers[query_type] = handler
        self.mock_federation.register_query_handler = register_query_handler

        hs = HomeServer("test",
                db_pool=None,
                http_client=None,
                datastore=Mock(spec=[
                    "get_profile_displayname",
                    "set_profile_displayname",
                    "get_profile_avatar_url",
                    "set_profile_avatar_url",
                ]),
                handlers=None,
                resource_for_federation=Mock(),
                replication_layer=self.mock_federation,
            )
        hs.handlers = ProfileHandlers(hs)

        self.datastore = hs.get_datastore()

        self.frank = hs.parse_userid("@1234ABCD:test")
        self.bob   = hs.parse_userid("@4567:test")
        self.alice = hs.parse_userid("@alice:remote")

        self.handler = hs.get_handlers().profile_handler

        # TODO(paul): Icky signal declarings.. booo
        hs.get_distributor().declare("changed_presencelike_data")

    @defer.inlineCallbacks
    def test_get_my_name(self):
        mocked_get = self.datastore.get_profile_displayname
        mocked_get.return_value = defer.succeed("Frank")

        displayname = yield self.handler.get_displayname(self.frank)

        self.assertEquals("Frank", displayname)
        mocked_get.assert_called_with("1234ABCD")

    @defer.inlineCallbacks
    def test_set_my_name(self):
        mocked_set = self.datastore.set_profile_displayname
        mocked_set.return_value = defer.succeed(())

        yield self.handler.set_displayname(self.frank, self.frank, "Frank Jr.")

        mocked_set.assert_called_with("1234ABCD", "Frank Jr.")

    @defer.inlineCallbacks
    def test_set_my_name_noauth(self):
        d = self.handler.set_displayname(self.frank, self.bob, "Frank Jr.")

        yield self.assertFailure(d, AuthError)

    @defer.inlineCallbacks
    def test_get_other_name(self):
        self.mock_federation.make_query.return_value = defer.succeed(
            {"displayname": "Alice"}
        )

        displayname = yield self.handler.get_displayname(self.alice)

        self.assertEquals(displayname, "Alice")
        self.mock_federation.make_query.assert_called_with(
            destination="remote",
            query_type="profile",
            args={"user_id": "@alice:remote", "field": "displayname"}
        )

    @defer.inlineCallbacks
    def test_incoming_fed_query(self):
        mocked_get = self.datastore.get_profile_displayname
        mocked_get.return_value = defer.succeed("Caroline")

        response = yield self.query_handlers["profile"](
            {"user_id": "@caroline:test", "field": "displayname"}
        )

        self.assertEquals({"displayname": "Caroline"}, response)
        mocked_get.assert_called_with("caroline")

    @defer.inlineCallbacks
    def test_get_my_avatar(self):
        mocked_get = self.datastore.get_profile_avatar_url
        mocked_get.return_value = defer.succeed("http://my.server/me.png")

        avatar_url = yield self.handler.get_avatar_url(self.frank)

        self.assertEquals("http://my.server/me.png", avatar_url)
        mocked_get.assert_called_with("1234ABCD")

    @defer.inlineCallbacks
    def test_set_my_avatar(self):
        mocked_set = self.datastore.set_profile_avatar_url
        mocked_set.return_value = defer.succeed(())

        yield self.handler.set_avatar_url(self.frank, self.frank,
                "http://my.server/pic.gif")

        mocked_set.assert_called_with("1234ABCD", "http://my.server/pic.gif")
