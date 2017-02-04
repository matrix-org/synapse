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

# twisted imports
from twisted.internet import defer

# trial imports
from tests import unittest

from synapse.api.constants import Membership

import json
import time


class RestTestCase(unittest.TestCase):
    """Contains extra helper functions to quickly and clearly perform a given
    REST action, which isn't the focus of the test.

    This subclass assumes there are mock_resource and auth_user_id attributes.
    """

    def __init__(self, *args, **kwargs):
        super(RestTestCase, self).__init__(*args, **kwargs)
        self.mock_resource = None
        self.auth_user_id = None

    @defer.inlineCallbacks
    def create_room_as(self, room_creator, is_public=True, tok=None):
        temp_id = self.auth_user_id
        self.auth_user_id = room_creator
        path = "/createRoom"
        content = "{}"
        if not is_public:
            content = '{"visibility":"private"}'
        if tok:
            path = path + "?access_token=%s" % tok
        (code, response) = yield self.mock_resource.trigger("POST", path, content)
        self.assertEquals(200, code, msg=str(response))
        self.auth_user_id = temp_id
        defer.returnValue(response["room_id"])

    @defer.inlineCallbacks
    def invite(self, room=None, src=None, targ=None, expect_code=200, tok=None):
        yield self.change_membership(room=room, src=src, targ=targ, tok=tok,
                                     membership=Membership.INVITE,
                                     expect_code=expect_code)

    @defer.inlineCallbacks
    def join(self, room=None, user=None, expect_code=200, tok=None):
        yield self.change_membership(room=room, src=user, targ=user, tok=tok,
                                     membership=Membership.JOIN,
                                     expect_code=expect_code)

    @defer.inlineCallbacks
    def leave(self, room=None, user=None, expect_code=200, tok=None):
        yield self.change_membership(room=room, src=user, targ=user, tok=tok,
                                     membership=Membership.LEAVE,
                                     expect_code=expect_code)

    @defer.inlineCallbacks
    def change_membership(self, room, src, targ, membership, tok=None,
                          expect_code=200):
        temp_id = self.auth_user_id
        self.auth_user_id = src

        path = "/rooms/%s/state/m.room.member/%s" % (room, targ)
        if tok:
            path = path + "?access_token=%s" % tok

        data = {
            "membership": membership
        }

        (code, response) = yield self.mock_resource.trigger(
            "PUT", path, json.dumps(data)
        )
        self.assertEquals(
            expect_code, code,
            msg="Expected: %d, got: %d, resp: %r" % (expect_code, code, response)
        )

        self.auth_user_id = temp_id

    @defer.inlineCallbacks
    def register(self, user_id):
        (code, response) = yield self.mock_resource.trigger(
            "POST",
            "/register",
            json.dumps({
                "user": user_id,
                "password": "test",
                "type": "m.login.password"
            }))
        self.assertEquals(200, code)
        defer.returnValue(response)

    @defer.inlineCallbacks
    def send(self, room_id, body=None, txn_id=None, tok=None,
             expect_code=200):
        if txn_id is None:
            txn_id = "m%s" % (str(time.time()))
        if body is None:
            body = "body_text_here"

        path = "/rooms/%s/send/m.room.message/%s" % (room_id, txn_id)
        content = '{"msgtype":"m.text","body":"%s"}' % body
        if tok:
            path = path + "?access_token=%s" % tok

        (code, response) = yield self.mock_resource.trigger("PUT", path, content)
        self.assertEquals(expect_code, code, msg=str(response))

    def assert_dict(self, required, actual):
        """Does a partial assert of a dict.

        Args:
            required (dict): The keys and value which MUST be in 'actual'.
            actual (dict): The test result. Extra keys will not be checked.
        """
        for key in required:
            self.assertEquals(required[key], actual[key],
                              msg="%s mismatch. %s" % (key, actual))
