# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import TYPE_CHECKING, List, Optional, Tuple

from synapse._pydantic_compat import HAS_PYDANTIC_V2

if TYPE_CHECKING or HAS_PYDANTIC_V2:
    from pydantic.v1 import Extra, StrictStr
else:
    from pydantic import Extra, StrictStr

from synapse.api import errors
from synapse.api.errors import NotFoundError, SynapseError, UnrecognizedRequestError
from synapse.handlers.device import DeviceHandler
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    parse_and_validate_json_object_from_request,
    parse_integer,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns, interactive_auth_handler
from synapse.rest.client.models import AuthenticationData
from synapse.rest.models import RequestBodyModel
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class DevicesRestServlet(RestServlet):
    PATTERNS = client_patterns("/devices$")
    CATEGORY = "Client API requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self._msc3852_enabled = hs.config.experimental.msc3852_enabled

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        devices = await self.device_handler.get_devices_by_user(
            requester.user.to_string()
        )

        # If MSC3852 is disabled, then the "last_seen_user_agent" field will be
        # removed from each device. If it is enabled, then the field name will
        # be replaced by the unstable identifier.
        #
        # When MSC3852 is accepted, this block of code can just be removed to
        # expose "last_seen_user_agent" to clients.
        for device in devices:
            last_seen_user_agent = device["last_seen_user_agent"]
            del device["last_seen_user_agent"]
            if self._msc3852_enabled:
                device["org.matrix.msc3852.last_seen_user_agent"] = last_seen_user_agent

        return 200, {"devices": devices}


class DeleteDevicesRestServlet(RestServlet):
    """
    API for bulk deletion of devices. Accepts a JSON object with a devices
    key which lists the device_ids to delete. Requires user interactive auth.
    """

    PATTERNS = client_patterns("/delete_devices")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.device_handler = handler
        self.auth_handler = hs.get_auth_handler()

    class PostBody(RequestBodyModel):
        auth: Optional[AuthenticationData]
        devices: List[StrictStr]

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        try:
            body = parse_and_validate_json_object_from_request(request, self.PostBody)
        except errors.SynapseError as e:
            if e.errcode == errors.Codes.NOT_JSON:
                # TODO: Can/should we remove this fallback now?
                # deal with older clients which didn't pass a JSON dict
                # the same as those that pass an empty dict
                body = self.PostBody.parse_obj({})
            else:
                raise e

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body.dict(exclude_unset=True),
            "remove device(s) from your account",
            # Users might call this multiple times in a row while cleaning up
            # devices, allow a single UI auth session to be re-used.
            can_skip_ui_auth=True,
        )

        await self.device_handler.delete_devices(
            requester.user.to_string(), body.devices
        )
        return 200, {}


class DeviceRestServlet(RestServlet):
    PATTERNS = client_patterns("/devices/(?P<device_id>[^/]*)$")
    CATEGORY = "Client API requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.device_handler = handler
        self.auth_handler = hs.get_auth_handler()
        self._msc3852_enabled = hs.config.experimental.msc3852_enabled
        self._msc3861_oauth_delegation_enabled = hs.config.experimental.msc3861.enabled

    async def on_GET(
        self, request: SynapseRequest, device_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        device = await self.device_handler.get_device(
            requester.user.to_string(), device_id
        )
        if device is None:
            raise NotFoundError("No device found")

        # If MSC3852 is disabled, then the "last_seen_user_agent" field will be
        # removed from each device. If it is enabled, then the field name will
        # be replaced by the unstable identifier.
        #
        # When MSC3852 is accepted, this block of code can just be removed to
        # expose "last_seen_user_agent" to clients.
        last_seen_user_agent = device["last_seen_user_agent"]
        del device["last_seen_user_agent"]
        if self._msc3852_enabled:
            device["org.matrix.msc3852.last_seen_user_agent"] = last_seen_user_agent

        return 200, device

    class DeleteBody(RequestBodyModel):
        auth: Optional[AuthenticationData]

    @interactive_auth_handler
    async def on_DELETE(
        self, request: SynapseRequest, device_id: str
    ) -> Tuple[int, JsonDict]:
        if self._msc3861_oauth_delegation_enabled:
            raise UnrecognizedRequestError(code=404)

        requester = await self.auth.get_user_by_req(request)

        try:
            body = parse_and_validate_json_object_from_request(request, self.DeleteBody)

        except errors.SynapseError as e:
            if e.errcode == errors.Codes.NOT_JSON:
                # TODO: can/should we remove this fallback now?
                # deal with older clients which didn't pass a JSON dict
                # the same as those that pass an empty dict
                body = self.DeleteBody.parse_obj({})
            else:
                raise

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body.dict(exclude_unset=True),
            "remove a device from your account",
            # Users might call this multiple times in a row while cleaning up
            # devices, allow a single UI auth session to be re-used.
            can_skip_ui_auth=True,
        )

        await self.device_handler.delete_devices(
            requester.user.to_string(), [device_id]
        )
        return 200, {}

    class PutBody(RequestBodyModel):
        display_name: Optional[StrictStr]

    async def on_PUT(
        self, request: SynapseRequest, device_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        body = parse_and_validate_json_object_from_request(request, self.PutBody)
        await self.device_handler.update_device(
            requester.user.to_string(), device_id, body.dict()
        )
        return 200, {}


class DehydratedDeviceDataModel(RequestBodyModel):
    """JSON blob describing a dehydrated device to be stored.

    Expects other freeform fields. Use .dict() to access them.
    """

    class Config:
        extra = Extra.allow

    algorithm: StrictStr


class DehydratedDeviceServlet(RestServlet):
    """Retrieve or store a dehydrated device.

    Implements MSC2697.

    GET /org.matrix.msc2697.v2/dehydrated_device

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "device_id": "dehydrated_device_id",
      "device_data": {
        "algorithm": "org.matrix.msc2697.v1.dehydration.v1.olm",
        "account": "dehydrated_device"
      }
    }

    PUT /org.matrix.msc2697.v2/dehydrated_device
    Content-Type: application/json

    {
      "device_data": {
        "algorithm": "org.matrix.msc2697.v1.dehydration.v1.olm",
        "account": "dehydrated_device"
      }
    }

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "device_id": "dehydrated_device_id"
    }

    """

    PATTERNS = client_patterns(
        "/org.matrix.msc2697.v2/dehydrated_device$",
        releases=(),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.device_handler = handler

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        dehydrated_device = await self.device_handler.get_dehydrated_device(
            requester.user.to_string()
        )
        if dehydrated_device is not None:
            (device_id, device_data) = dehydrated_device
            result = {"device_id": device_id, "device_data": device_data}
            return 200, result
        else:
            raise errors.NotFoundError("No dehydrated device available")

    class PutBody(RequestBodyModel):
        device_data: DehydratedDeviceDataModel
        initial_device_display_name: Optional[StrictStr]

    async def on_PUT(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        submission = parse_and_validate_json_object_from_request(request, self.PutBody)
        requester = await self.auth.get_user_by_req(request)

        device_id = await self.device_handler.store_dehydrated_device(
            requester.user.to_string(),
            None,
            submission.device_data.dict(),
            submission.initial_device_display_name,
        )
        return 200, {"device_id": device_id}


class ClaimDehydratedDeviceServlet(RestServlet):
    """Claim a dehydrated device.

    POST /org.matrix.msc2697.v2/dehydrated_device/claim
    Content-Type: application/json

    {
      "device_id": "dehydrated_device_id"
    }

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "success": true,
    }

    """

    PATTERNS = client_patterns(
        "/org.matrix.msc2697.v2/dehydrated_device/claim", releases=()
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.device_handler = handler

    class PostBody(RequestBodyModel):
        device_id: StrictStr

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        submission = parse_and_validate_json_object_from_request(request, self.PostBody)

        result = await self.device_handler.rehydrate_device(
            requester.user.to_string(),
            self.auth.get_access_token_from_request(request),
            submission.device_id,
        )

        return 200, result


class DehydratedDeviceEventsServlet(RestServlet):
    PATTERNS = client_patterns(
        "/org.matrix.msc3814.v1/dehydrated_device/(?P<device_id>[^/]*)/events$",
        releases=(),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.message_handler = hs.get_device_message_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    class PostBody(RequestBodyModel):
        next_batch: Optional[StrictStr]

    async def on_POST(
        self, request: SynapseRequest, device_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        next_batch = parse_and_validate_json_object_from_request(
            request, self.PostBody
        ).next_batch
        limit = parse_integer(request, "limit", 100)

        msgs = await self.message_handler.get_events_for_dehydrated_device(
            requester=requester,
            device_id=device_id,
            since_token=next_batch,
            limit=limit,
        )

        return 200, msgs


class DehydratedDeviceV2Servlet(RestServlet):
    """Upload, retrieve, or delete a dehydrated device.

    GET /org.matrix.msc3814.v1/dehydrated_device

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "device_id": "dehydrated_device_id",
      "device_data": {
        "algorithm": "org.matrix.msc2697.v1.dehydration.v1.olm",
        "account": "dehydrated_device"
      }
    }

    PUT /org.matrix.msc3814.v1/dehydrated_device
    Content-Type: application/json

    {
        "device_id": "dehydrated_device_id",
        "device_data": {
            "algorithm": "org.matrix.msc2697.v1.dehydration.v1.olm",
            "account": "dehydrated_device"
        },
        "device_keys": {
            "user_id": "<user_id>",
            "device_id": "<device_id>",
            "valid_until_ts": <millisecond_timestamp>,
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
            ]
            "keys": {
                "<algorithm>:<device_id>": "<key_base64>",
            },
            "signatures:" {
                "<user_id>" {
                    "<algorithm>:<device_id>": "<signature_base64>"
                }
            }
        },
        "fallback_keys": {
            "<algorithm>:<device_id>": "<key_base64>",
            "signed_<algorithm>:<device_id>": {
                "fallback": true,
                "key": "<key_base64>",
                "signatures": {
                    "<user_id>": {
                        "<algorithm>:<device_id>": "<key_base64>"
                    }
                }
            }
        }
        "one_time_keys": {
            "<algorithm>:<key_id>": "<key_base64>"
        },

    }

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "device_id": "dehydrated_device_id"
    }

    DELETE /org.matrix.msc3814.v1/dehydrated_device

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "device_id": "dehydrated_device_id",
    }
    """

    PATTERNS = [
        *client_patterns("/org.matrix.msc3814.v1/dehydrated_device$", releases=()),
    ]

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.e2e_keys_handler = hs.get_e2e_keys_handler()
        self.device_handler = handler

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        dehydrated_device = await self.device_handler.get_dehydrated_device(
            requester.user.to_string()
        )

        if dehydrated_device is not None:
            (device_id, device_data) = dehydrated_device
            result = {"device_id": device_id, "device_data": device_data}
            return 200, result
        else:
            raise errors.NotFoundError("No dehydrated device available")

    async def on_DELETE(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        dehydrated_device = await self.device_handler.get_dehydrated_device(
            requester.user.to_string()
        )

        if dehydrated_device is not None:
            (device_id, device_data) = dehydrated_device

            await self.device_handler.delete_dehydrated_device(
                requester.user.to_string(), device_id
            )

            result = {"device_id": device_id}

            return 200, result
        else:
            raise errors.NotFoundError("No dehydrated device available")

    class PutBody(RequestBodyModel):
        device_data: DehydratedDeviceDataModel
        device_id: StrictStr
        initial_device_display_name: Optional[StrictStr]

        class Config:
            extra = Extra.allow

    async def on_PUT(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        submission = parse_and_validate_json_object_from_request(request, self.PutBody)
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        old_dehydrated_device = await self.device_handler.get_dehydrated_device(user_id)

        # if an old device exists, delete it before creating a new one
        if old_dehydrated_device:
            await self.device_handler.delete_dehydrated_device(
                user_id, old_dehydrated_device[0]
            )

        device_info = submission.dict()
        if "device_keys" not in device_info.keys():
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Device key(s) not found, these must be provided.",
            )

        device_id = await self.device_handler.store_dehydrated_device(
            requester.user.to_string(),
            submission.device_id,
            submission.device_data.dict(),
            submission.initial_device_display_name,
            device_info,
        )

        return 200, {"device_id": device_id}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if (
        hs.config.worker.worker_app is None
        and not hs.config.experimental.msc3861.enabled
    ):
        DeleteDevicesRestServlet(hs).register(http_server)
    DevicesRestServlet(hs).register(http_server)

    if hs.config.worker.worker_app is None:
        DeviceRestServlet(hs).register(http_server)
        if hs.config.experimental.msc2697_enabled:
            DehydratedDeviceServlet(hs).register(http_server)
            ClaimDehydratedDeviceServlet(hs).register(http_server)
        if hs.config.experimental.msc3814_enabled:
            DehydratedDeviceV2Servlet(hs).register(http_server)
            DehydratedDeviceEventsServlet(hs).register(http_server)
