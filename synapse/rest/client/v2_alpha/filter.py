# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.api.errors import AuthError, SynapseError
from synapse.http.servlet import RestServlet
from synapse.types import UserID

from ._base import client_v2_pattern

import json
import logging


logger = logging.getLogger(__name__)


# TODO(paul)
_filters_for_user = {}


class GetFilterRestServlet(RestServlet):
    PATTERN = client_v2_pattern("/user/(?P<user_id>[^/]*)/filter/(?P<filter_id>[^/]*)")

    def __init__(self, hs):
        super(GetFilterRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id, filter_id):
        target_user = UserID.from_string(user_id)
        auth_user = yield self.auth.get_user_by_req(request)

        if target_user != auth_user:
            raise AuthError(403, "Cannot get filters for other users")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only get filters for local users")

        try:
            filter_id = int(filter_id)
        except:
            raise SynapseError(400, "Invalid filter_id")

        filters = _filters_for_user.get(target_user.localpart, None)

        if not filters or filter_id >= len(filters):
            raise SynapseError(400, "No such filter")

        defer.returnValue((200, filters[filter_id]))


class CreateFilterRestServlet(RestServlet):
    PATTERN = client_v2_pattern("/user/(?P<user_id>[^/]*)/filter")

    def __init__(self, hs):
        super(CreateFilterRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request, user_id):
        target_user = UserID.from_string(user_id)
        auth_user = yield self.auth.get_user_by_req(request)

        if target_user != auth_user:
            raise AuthError(403, "Cannot create filters for other users")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only create filters for local users")

        try:
            content = json.loads(request.content.read())

            # TODO(paul): check for required keys and invalid keys
        except:
            raise SynapseError(400, "Invalid filter definition")

        filters = _filters_for_user.setdefault(target_user.localpart, [])

        filter_id = len(filters)
        filters.append(content)

        defer.returnValue((200, {"filter_id": str(filter_id)}))


def register_servlets(hs, http_server):
    GetFilterRestServlet(hs).register(http_server)
    CreateFilterRestServlet(hs).register(http_server)
