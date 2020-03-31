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

from synapse.api import errors
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)

from ._base import client_patterns, interactive_auth_handler

logger = logging.getLogger(__name__)


class DevicesRestServlet(RestServlet):
    PATTERNS = client_patterns("/devices$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(DevicesRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        devices = await self.device_handler.get_devices_by_user(
            requester.user.to_string()
        )
        return 200, {"devices": devices}


class DeleteDevicesRestServlet(RestServlet):
    """
    API for bulk deletion of devices. Accepts a JSON object with a devices
    key which lists the device_ids to delete. Requires user interactive auth.
    """

    PATTERNS = client_patterns("/delete_devices")

    def __init__(self, hs):
        super(DeleteDevicesRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self.auth_handler = hs.get_auth_handler()

    @interactive_auth_handler
    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request)

        try:
            body = parse_json_object_from_request(request)
        except errors.SynapseError as e:
            if e.errcode == errors.Codes.NOT_JSON:
                # DELETE
                # deal with older clients which didn't pass a JSON dict
                # the same as those that pass an empty dict
                body = {}
            else:
                raise e

        assert_params_in_dict(body, ["devices"])

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body,
            self.hs.get_ip_from_request(request),
            "remove device(s) from your account",
        )

        await self.device_handler.delete_devices(
            requester.user.to_string(), body["devices"]
        )
        return 200, {}


class DeviceRestServlet(RestServlet):
    PATTERNS = client_patterns("/devices/(?P<device_id>[^/]*)$")

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

    async def on_GET(self, request, device_id):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        device = await self.device_handler.get_device(
            requester.user.to_string(), device_id
        )
        return 200, device

    @interactive_auth_handler
    async def on_DELETE(self, request, device_id):
        requester = await self.auth.get_user_by_req(request)

        try:
            body = parse_json_object_from_request(request)

        except errors.SynapseError as e:
            if e.errcode == errors.Codes.NOT_JSON:
                # deal with older clients which didn't pass a JSON dict
                # the same as those that pass an empty dict
                body = {}
            else:
                raise

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body,
            self.hs.get_ip_from_request(request),
            "remove a device from your account",
        )

        await self.device_handler.delete_device(requester.user.to_string(), device_id)
        return 200, {}

    async def on_PUT(self, request, device_id):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        body = parse_json_object_from_request(request)
        await self.device_handler.update_device(
            requester.user.to_string(), device_id, body
        )
        return 200, {}


def register_servlets(hs, http_server):
    DeleteDevicesRestServlet(hs).register(http_server)
    DevicesRestServlet(hs).register(http_server)
    DeviceRestServlet(hs).register(http_server)
