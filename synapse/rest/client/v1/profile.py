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
import logging

from twisted.internet import defer

from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.types import UserID

logger = logging.getLogger(__name__)


class ProfileDisplaynameRestServlet(RestServlet):
    PATTERNS = client_patterns("/profile/(?P<user_id>[^/]*)/displayname", v1=True)

    def __init__(self, hs):
        super(ProfileDisplaynameRestServlet, self).__init__()
        self.hs = hs
        self.profile_handler = hs.get_profile_handler()
        self.http_client = hs.get_simple_http_client()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        requester_user = None

        if self.hs.config.require_auth_for_profile_requests:
            requester = yield self.auth.get_user_by_req(request)
            requester_user = requester.user

        user = UserID.from_string(user_id)

        yield self.profile_handler.check_profile_query_allowed(user, requester_user)

        displayname = yield self.profile_handler.get_displayname(user)

        ret = {}
        if displayname is not None:
            ret["displayname"] = displayname

        defer.returnValue((200, ret))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        user = UserID.from_string(user_id)
        is_admin = yield self.auth.is_server_admin(requester.user)

        content = parse_json_object_from_request(request)

        try:
            new_name = content["displayname"]
        except Exception:
            defer.returnValue((400, "Unable to parse name"))

        yield self.profile_handler.set_displayname(
            user, requester, new_name, is_admin)

        if self.hs.config.shadow_server:
            shadow_user = UserID(
                user.localpart, self.hs.config.shadow_server.get("hs")
            )
            self.shadow_displayname(shadow_user.to_string(), content)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, request, user_id):
        return (200, {})

    @defer.inlineCallbacks
    def shadow_displayname(self, user_id, body):
        # TODO: retries
        shadow_hs_url = self.hs.config.shadow_server.get("hs_url")
        as_token = self.hs.config.shadow_server.get("as_token")

        yield self.http_client.put_json(
            "%s/_matrix/client/r0/profile/%s/displayname?access_token=%s&user_id=%s" % (
                shadow_hs_url, user_id, as_token, user_id
            ),
            body
        )


class ProfileAvatarURLRestServlet(RestServlet):
    PATTERNS = client_patterns("/profile/(?P<user_id>[^/]*)/avatar_url", v1=True)

    def __init__(self, hs):
        super(ProfileAvatarURLRestServlet, self).__init__()
        self.hs = hs
        self.profile_handler = hs.get_profile_handler()
        self.http_client = hs.get_simple_http_client()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        requester_user = None

        if self.hs.config.require_auth_for_profile_requests:
            requester = yield self.auth.get_user_by_req(request)
            requester_user = requester.user

        user = UserID.from_string(user_id)

        yield self.profile_handler.check_profile_query_allowed(user, requester_user)

        avatar_url = yield self.profile_handler.get_avatar_url(user)

        ret = {}
        if avatar_url is not None:
            ret["avatar_url"] = avatar_url

        defer.returnValue((200, ret))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)
        is_admin = yield self.auth.is_server_admin(requester.user)

        content = parse_json_object_from_request(request)
        try:
            new_name = content["avatar_url"]
        except Exception:
            defer.returnValue((400, "Unable to parse name"))

        yield self.profile_handler.set_avatar_url(
            user, requester, new_name, is_admin)

        if self.hs.config.shadow_server:
            shadow_user = UserID(
                user.localpart, self.hs.config.shadow_server.get("hs")
            )
            self.shadow_avatar_url(shadow_user.to_string(), content)

        defer.returnValue((200, {}))

    def on_OPTIONS(self, request, user_id):
        return (200, {})

    @defer.inlineCallbacks
    def shadow_avatar_url(self, user_id, body):
        # TODO: retries
        shadow_hs_url = self.hs.config.shadow_server.get("hs_url")
        as_token = self.hs.config.shadow_server.get("as_token")

        yield self.http_client.put_json(
            "%s/_matrix/client/r0/profile/%s/avatar_url?access_token=%s&user_id=%s" % (
                shadow_hs_url, user_id, as_token, user_id
            ),
            body
        )


class ProfileRestServlet(RestServlet):
    PATTERNS = client_patterns("/profile/(?P<user_id>[^/]*)", v1=True)

    def __init__(self, hs):
        super(ProfileRestServlet, self).__init__()
        self.hs = hs
        self.profile_handler = hs.get_profile_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        requester_user = None

        if self.hs.config.require_auth_for_profile_requests:
            requester = yield self.auth.get_user_by_req(request)
            requester_user = requester.user

        user = UserID.from_string(user_id)

        yield self.profile_handler.check_profile_query_allowed(user, requester_user)

        displayname = yield self.profile_handler.get_displayname(user)
        avatar_url = yield self.profile_handler.get_avatar_url(user)

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
