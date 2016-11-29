# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

import logging

from twisted.internet import defer

from synapse.api import constants, errors
from synapse.http import servlet
from ._base import client_v2_patterns

logger = logging.getLogger(__name__)


class DevicesRestServlet(servlet.RestServlet):
    PATTERNS = client_v2_patterns("/devices$", releases=[], v2_alpha=False)

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(DevicesRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        devices = yield self.device_handler.get_devices_by_user(
            requester.user.to_string()
        )
        defer.returnValue((200, {"devices": devices}))


class DeviceRestServlet(servlet.RestServlet):
    PATTERNS = client_v2_patterns("/devices/(?P<device_id>[^/]*)$",
                                  releases=[], v2_alpha=False)

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(DeviceRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self.auth_handler = hs.get_auth_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, device_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        device = yield self.device_handler.get_device(
            requester.user.to_string(),
            device_id,
        )
        defer.returnValue((200, device))

    @defer.inlineCallbacks
    def on_DELETE(self, request, device_id):
        try:
            body = servlet.parse_json_object_from_request(request)

        except errors.SynapseError as e:
            if e.errcode == errors.Codes.NOT_JSON:
                # deal with older clients which didn't pass a JSON dict
                # the same as those that pass an empty dict
                body = {}
            else:
                raise

        authed, result, params, _ = yield self.auth_handler.check_auth([
            [constants.LoginType.PASSWORD],
        ], body, self.hs.get_ip_from_request(request))

        if not authed:
            defer.returnValue((401, result))

        requester = yield self.auth.get_user_by_req(request)
        yield self.device_handler.delete_device(
            requester.user.to_string(),
            device_id,
        )
        defer.returnValue((200, {}))

    @defer.inlineCallbacks
    def on_PUT(self, request, device_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)

        body = servlet.parse_json_object_from_request(request)
        yield self.device_handler.update_device(
            requester.user.to_string(),
            device_id,
            body
        )
        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    DevicesRestServlet(hs).register(http_server)
    DeviceRestServlet(hs).register(http_server)
