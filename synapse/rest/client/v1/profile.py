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

""" This module contains REST servlets to do with profile: /profile/<paths> """
from twisted.internet import defer

from .base import ClientV1RestServlet, client_path_patterns
from synapse.types import UserID
from synapse.http.servlet import parse_json_object_from_request


class ProfileDisplaynameRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/profile/(?P<user_id>[^/]*)/displayname")

    def __init__(self, hs):
        super(ProfileDisplaynameRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        user = UserID.from_string(user_id)

        displayname = yield self.handlers.profile_handler.get_displayname(
            user,
        )

        ret = {}
        if displayname is not None:
            ret["displayname"] = displayname

        defer.returnValue((200, ret))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        user = UserID.from_string(user_id)

        content = parse_json_object_from_request(request)

        try:
            new_name = content["displayname"]
        except:
            defer.returnValue((400, "Unable to parse name"))

        yield self.handlers.profile_handler.set_displayname(
            user, requester, new_name)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, request, user_id):
        return (200, {})


class ProfileAvatarURLRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/profile/(?P<user_id>[^/]*)/avatar_url")

    def __init__(self, hs):
        super(ProfileAvatarURLRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        user = UserID.from_string(user_id)

        avatar_url = yield self.handlers.profile_handler.get_avatar_url(
            user,
        )

        ret = {}
        if avatar_url is not None:
            ret["avatar_url"] = avatar_url

        defer.returnValue((200, ret))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)

        content = parse_json_object_from_request(request)
        try:
            new_name = content["avatar_url"]
        except:
            defer.returnValue((400, "Unable to parse name"))

        yield self.handlers.profile_handler.set_avatar_url(
            user, requester, new_name)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, request, user_id):
        return (200, {})


class ProfileRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/profile/(?P<user_id>[^/]*)")

    def __init__(self, hs):
        super(ProfileRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        user = UserID.from_string(user_id)

        displayname = yield self.handlers.profile_handler.get_displayname(
            user,
        )
        avatar_url = yield self.handlers.profile_handler.get_avatar_url(
            user,
        )

        ret = {}
        if displayname is not None:
            ret["displayname"] = displayname
        if avatar_url is not None:
            ret["avatar_url"] = avatar_url

        defer.returnValue((200, ret))


def register_servlets(hs, http_server):
    ProfileDisplaynameRestServlet(hs).register(http_server)
    ProfileAvatarURLRestServlet(hs).register(http_server)
    ProfileRestServlet(hs).register(http_server)
