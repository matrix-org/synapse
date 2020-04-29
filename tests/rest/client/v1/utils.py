# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from typing import Any, Dict, Optional

import attr

from twisted.web.resource import Resource

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

    def create_room_as(self, room_creator=None, is_public=True, tok=None):
        temp_id = self.auth_user_id
        self.auth_user_id = room_creator
        path = "/_matrix/client/r0/createRoom"
        content = {}
        if not is_public:
            content["visibility"] = "private"
        if tok:
            path = path + "?access_token=%s" % tok

        request, channel = make_request(
            self.hs.get_reactor(), "POST", path, json.dumps(content).encode("utf8")
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
            self.hs.get_reactor(), "PUT", path, json.dumps(data).encode("utf8")
        )

        render(request, self.resource, self.hs.get_reactor())

        assert int(channel.result["code"]) == expect_code, (
            "Expected: %d, got: %d, resp: %r"
            % (expect_code, int(channel.result["code"]), channel.result["body"])
        )

        self.auth_user_id = temp_id

    def send(self, room_id, body=None, txn_id=None, tok=None, expect_code=200):
        if body is None:
            body = "body_text_here"

        content = {"msgtype": "m.text", "body": body}

        return self.send_event(
            room_id, "m.room.message", content, txn_id, tok, expect_code
        )

    def send_event(
        self, room_id, type, content={}, txn_id=None, tok=None, expect_code=200
    ):
        if txn_id is None:
            txn_id = "m%s" % (str(time.time()))

        path = "/_matrix/client/r0/rooms/%s/send/%s/%s" % (room_id, type, txn_id)
        if tok:
            path = path + "?access_token=%s" % tok

        request, channel = make_request(
            self.hs.get_reactor(), "PUT", path, json.dumps(content).encode("utf8")
        )
        render(request, self.resource, self.hs.get_reactor())

        assert int(channel.result["code"]) == expect_code, (
            "Expected: %d, got: %d, resp: %r"
            % (expect_code, int(channel.result["code"]), channel.result["body"])
        )

        return channel.json_body

    def _read_write_state(
        self,
        room_id: str,
        event_type: str,
        body: Optional[Dict[str, Any]],
        tok: str,
        expect_code: int = 200,
        state_key: str = "",
        method: str = "GET",
    ) -> Dict:
        """Read or write some state from a given room

        Args:
            room_id:
            event_type: The type of state event
            body: Body that is sent when making the request. The content of the state event.
                If None, the request to the server will have an empty body
            tok: The access token to use
            expect_code: The HTTP code to expect in the response
            state_key:
            method: "GET" or "PUT" for reading or writing state, respectively

        Returns:
            The response body from the server

        Raises:
            AssertionError: if expect_code doesn't match the HTTP code we received
        """
        path = "/_matrix/client/r0/rooms/%s/state/%s/%s" % (
            room_id,
            event_type,
            state_key,
        )
        if tok:
            path = path + "?access_token=%s" % tok

        # Set request body if provided
        content = b""
        if body is not None:
            content = json.dumps(body).encode("utf8")

        request, channel = make_request(self.hs.get_reactor(), method, path, content)

        render(request, self.resource, self.hs.get_reactor())

        assert int(channel.result["code"]) == expect_code, (
            "Expected: %d, got: %d, resp: %r"
            % (expect_code, int(channel.result["code"]), channel.result["body"])
        )

        return channel.json_body

    def get_state(
        self,
        room_id: str,
        event_type: str,
        tok: str,
        expect_code: int = 200,
        state_key: str = "",
    ):
        """Gets some state from a room

        Args:
            room_id:
            event_type: The type of state event
            tok: The access token to use
            expect_code: The HTTP code to expect in the response
            state_key:

        Returns:
            The response body from the server

        Raises:
            AssertionError: if expect_code doesn't match the HTTP code we received
        """
        return self._read_write_state(
            room_id, event_type, None, tok, expect_code, state_key, method="GET"
        )

    def send_state(
        self,
        room_id: str,
        event_type: str,
        body: Dict[str, Any],
        tok: str,
        expect_code: int = 200,
        state_key: str = "",
    ):
        """Set some state in a room

        Args:
            room_id:
            event_type: The type of state event
            body: Body that is sent when making the request. The content of the state event.
            tok: The access token to use
            expect_code: The HTTP code to expect in the response
            state_key:

        Returns:
            The response body from the server

        Raises:
            AssertionError: if expect_code doesn't match the HTTP code we received
        """
        return self._read_write_state(
            room_id, event_type, body, tok, expect_code, state_key, method="PUT"
        )

    def upload_media(
        self,
        resource: Resource,
        image_data: bytes,
        tok: str,
        filename: str = "test.png",
        expect_code: int = 200,
    ) -> dict:
        """Upload a piece of test media to the media repo
        Args:
            resource: The resource that will handle the upload request
            image_data: The image data to upload
            tok: The user token to use during the upload
            filename: The filename of the media to be uploaded
            expect_code: The return code to expect from attempting to upload the media
        """
        image_length = len(image_data)
        path = "/_matrix/media/r0/upload?filename=%s" % (filename,)
        request, channel = make_request(
            self.hs.get_reactor(), "POST", path, content=image_data, access_token=tok
        )
        request.requestHeaders.addRawHeader(
            b"Content-Length", str(image_length).encode("UTF-8")
        )
        request.render(resource)
        self.hs.get_reactor().pump([100])

        assert channel.code == expect_code, "Expected: %d, got: %d, resp: %r" % (
            expect_code,
            int(channel.result["code"]),
            channel.result["body"],
        )

        return channel.json_body
