# Copyright 2020 Dirk Klimpel
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
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import NotFoundError, SynapseError
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import admin_patterns, assert_requester_is_admin
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class DeviceRestServlet(RestServlet):
    """
    Get, update or delete the given user's device
    """

    PATTERNS = admin_patterns(
        "/users/(?P<user_id>[^/]*)/devices/(?P<device_id>[^/]*)$", "v2"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self.store = hs.get_datastore()

    async def on_GET(
        self, request: SynapseRequest, user_id, device_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        device = await self.device_handler.get_device(
            target_user.to_string(), device_id
        )
        return 200, device

    async def on_DELETE(
        self, request: SynapseRequest, user_id: str, device_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        await self.device_handler.delete_device(target_user.to_string(), device_id)
        return 200, {}

    async def on_PUT(
        self, request: SynapseRequest, user_id: str, device_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        body = parse_json_object_from_request(request, allow_empty_body=True)
        await self.device_handler.update_device(
            target_user.to_string(), device_id, body
        )
        return 200, {}


class DevicesRestServlet(RestServlet):
    """
    Retrieve the given user's devices
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/devices$", "v2")

    def __init__(self, hs: "HomeServer"):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self.store = hs.get_datastore()

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        devices = await self.device_handler.get_devices_by_user(target_user.to_string())
        return 200, {"devices": devices, "total": len(devices)}


class DeleteDevicesRestServlet(RestServlet):
    """
    API for bulk deletion of devices. Accepts a JSON object with a devices
    key which lists the device_ids to delete.
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/delete_devices$", "v2")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self.store = hs.get_datastore()

    async def on_POST(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        body = parse_json_object_from_request(request, allow_empty_body=False)
        assert_params_in_dict(body, ["devices"])

        await self.device_handler.delete_devices(
            target_user.to_string(), body["devices"]
        )
        return 200, {}
