# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from base import RestServlet, client_path_pattern

import json


class ProfileDisplaynameRestServlet(RestServlet):
    PATTERN = client_path_pattern("/profile/(?P<user_id>[^/]*)/displayname")

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        user = self.hs.parse_userid(user_id)

        displayname = yield self.handlers.profile_handler.get_displayname(
            user,
            local_only="local_only" in request.args
        )

        defer.returnValue((200, {"displayname": displayname}))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        auth_user = yield self.auth.get_user_by_req(request)
        user = self.hs.parse_userid(user_id)

        try:
            content = json.loads(request.content.read())
            new_name = content["displayname"]
        except:
            defer.returnValue((400, "Unable to parse name"))

        yield self.handlers.profile_handler.set_displayname(
            user, auth_user, new_name)

        defer.returnValue((200, ""))

    def on_OPTIONS(self, request, user_id):
        return (200, {})


class ProfileAvatarURLRestServlet(RestServlet):
    PATTERN = client_path_pattern("/profile/(?P<user_id>[^/]*)/avatar_url")

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        user = self.hs.parse_userid(user_id)

        avatar_url = yield self.handlers.profile_handler.get_avatar_url(
            user,
            local_only="local_only" in request.args
        )

        defer.returnValue((200, {"avatar_url": avatar_url}))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        auth_user = yield self.auth.get_user_by_req(request)
        user = self.hs.parse_userid(user_id)

        try:
            content = json.loads(request.content.read())
            new_name = content["avatar_url"]
        except:
            defer.returnValue((400, "Unable to parse name"))

        yield self.handlers.profile_handler.set_avatar_url(
            user, auth_user, new_name)

        defer.returnValue((200, ""))

    def on_OPTIONS(self, request, user_id):
        return (200, {})


def register_servlets(hs, http_server):
    ProfileDisplaynameRestServlet(hs).register(http_server)
    ProfileAvatarURLRestServlet(hs).register(http_server)
