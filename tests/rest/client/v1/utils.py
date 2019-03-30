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

import json
import time

import attr

from synapse.api.constants import Membership

from tests.server import make_request, render


@attr.s
class RestHelper(object):
    """Contains extra helper functions to quickly and clearly perform a given
    REST action, which isn't the focus of the test.
    """

    hs = attr.ib()
    resource = attr.ib()
    auth_user_id = attr.ib()

    def create_room_as(self, room_creator, is_public=True, tok=None):
        temp_id = self.auth_user_id
        self.auth_user_id = room_creator
        path = "/_matrix/client/r0/createRoom"
        content = {}
        if not is_public:
            content["visibility"] = "private"
        if tok:
            path = path + "?access_token=%s" % tok

        request, channel = make_request(
            self.hs.get_reactor(), "POST", path, json.dumps(content).encode('utf8')
        )
        render(request, self.resource, self.hs.get_reactor())

        assert channel.result["code"] == b"200", channel.result
        self.auth_user_id = temp_id
        return channel.json_body["room_id"]

    def invite(self, room=None, src=None, targ=None, expect_code=200, tok=None):
        self.change_membership(
            room=room,
            src=src,
            targ=targ,
            tok=tok,
            membership=Membership.INVITE,
            expect_code=expect_code,
        )

    def join(self, room=None, user=None, expect_code=200, tok=None):
        self.change_membership(
            room=room,
            src=user,
            targ=user,
            tok=tok,
            membership=Membership.JOIN,
            expect_code=expect_code,
        )

    def leave(self, room=None, user=None, expect_code=200, tok=None):
        self.change_membership(
            room=room,
            src=user,
            targ=user,
            tok=tok,
            membership=Membership.LEAVE,
            expect_code=expect_code,
        )

    def change_membership(self, room, src, targ, membership, tok=None, expect_code=200):
        temp_id = self.auth_user_id
        self.auth_user_id = src

        path = "/_matrix/client/r0/rooms/%s/state/m.room.member/%s" % (room, targ)
        if tok:
            path = path + "?access_token=%s" % tok

        data = {"membership": membership}

        request, channel = make_request(
            self.hs.get_reactor(), "PUT", path, json.dumps(data).encode('utf8')
        )

        render(request, self.resource, self.hs.get_reactor())

        assert int(channel.result["code"]) == expect_code, (
            "Expected: %d, got: %d, resp: %r"
            % (expect_code, int(channel.result["code"]), channel.result["body"])
        )

        self.auth_user_id = temp_id

    def send(self, room_id, body=None, txn_id=None, tok=None, expect_code=200):
        if txn_id is None:
            txn_id = "m%s" % (str(time.time()))
        if body is None:
            body = "body_text_here"

        path = "/_matrix/client/r0/rooms/%s/send/m.room.message/%s" % (room_id, txn_id)
        content = {"msgtype": "m.text", "body": body}
        if tok:
            path = path + "?access_token=%s" % tok

        request, channel = make_request(
            self.hs.get_reactor(), "PUT", path, json.dumps(content).encode('utf8')
        )
        render(request, self.resource, self.hs.get_reactor())

        assert int(channel.result["code"]) == expect_code, (
            "Expected: %d, got: %d, resp: %r"
            % (expect_code, int(channel.result["code"]), channel.result["body"])
        )

        return channel.json_body
