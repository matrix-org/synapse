# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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


from ._base import client_v2_patterns

from synapse.api.errors import NotFoundError
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class FullProfileServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/profile_extended/(?P<user_id>[^/]+)/$"
    )

    EXPIRES_MS = 3600 * 1000

    def __init__(self, hs):
        super(FullProfileServlet, self).__init__()
        self.auth = hs.get_auth()
        self.profile_handler = hs.get_handlers().profile_handler

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        yield self.auth.get_user_by_req(request)

        profile = yield self.profile_handler.get_full_profile_for_user(user_id)

        defer.returnValue((200, profile))


class ProfilePersonaServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/profile_extended/(?P<user_id>[^/]+)/(?P<persona>[^/]+)/$"
    )

    EXPIRES_MS = 3600 * 1000

    def __init__(self, hs):
        super(ProfilePersonaServlet, self).__init__()
        self.auth = hs.get_auth()
        self.profile_handler = hs.get_handlers().profile_handler

    @defer.inlineCallbacks
    def on_GET(self, request, user_id, persona):
        yield self.auth.get_user_by_req(request)

        profile = yield self.profile_handler.get_persona_profile_for_user(
            user_id, persona
        )

        if profile:
            defer.returnValue((200, profile))
        else:
            raise NotFoundError()


class ProfileTupleServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/profile_extended/(?P<user_id>[^/]+)/(?P<persona>[^/]+)/(?P<key>[^/]+)$"
    )

    EXPIRES_MS = 3600 * 1000

    def __init__(self, hs):
        super(ProfileTupleServlet, self).__init__()
        self.auth = hs.get_auth()
        self.profile_handler = hs.get_handlers().profile_handler

    @defer.inlineCallbacks
    def on_GET(self, request, user_id, persona, key):
        yield self.auth.get_user_by_req(request)

        profile = yield self.profile_handler.get_profile_key_for_user(
            user_id, persona, key
        )

        if profile is not None:
            defer.returnValue((200, profile))
        else:
            raise NotFoundError()

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id, persona, key):
        yield self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)

        yield self.profile_handler.update_profile_key(user_id, persona, key, content)

        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    FullProfileServlet(hs).register(http_server)
    ProfileTupleServlet(hs).register(http_server)
    ProfilePersonaServlet(hs).register(http_server)
